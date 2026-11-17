//! The Server facade: build a Server from typed values or from a configuration
//! file, serve it on the caller's runtime or on a thread of its own, and hand
//! admitted streams to an application handler or to one fixed TCP target.

use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use tokio::task::JoinSet;

use super::runtime::{self, Ready, Running};
use super::text::{Network, Text};
use super::{AllowList, PeerKey, SdkError};
use crate::config::{Fallback, PublishAddress, ServerConfig, ServerOverrides, load_server};
use crate::identity::Identity;
use crate::network::{
    Endpoint, ForwardError, Limits, NetworkError, ServeReport, ServiceStream, Session,
};
use crate::startup::{RoleOptions, ServerRole, StreamHandler};

/// Most sessions a Server serves at once (the same bound as the binary).
const MAX_SESSIONS: usize = 32;

/// Application code that serves the streams of admitted clients.
///
/// Implemented for every `Fn(PeerKey, ServiceStream) -> impl Future<Output = ()>`.
/// A handler runs once per stream, at most 16 per client session at a time,
/// and sees only clients that passed the allowlist. A panic ends that stream
/// only. The `ServiceStream` is reset when dropped without `shutdown`.
pub trait Handler: Send + Sync + 'static {
    /// Serves one stream of `peer`.
    fn handle(
        &self,
        peer: PeerKey,
        stream: ServiceStream,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

impl<F, Fut> Handler for F
where
    F: Fn(PeerKey, ServiceStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    fn handle(
        &self,
        peer: PeerKey,
        stream: ServiceStream,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(self(peer, stream))
    }
}

/// What the Server does with an admitted stream.
#[derive(Clone)]
pub enum Service {
    /// Connect to one fixed loopback TCP service and copy bytes both ways.
    Target(SocketAddr),
    /// Hand the stream to application code.
    Handler(Arc<dyn Handler>),
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Target(target) => f.debug_tuple("Target").field(target).finish(),
            Self::Handler(_) => f.write_str("Handler(..)"),
        }
    }
}

/// Collects the settings of a [`Server`]; every value is validated by
/// [`ServerBuilder::build`] with the same rules as a configuration file.
#[derive(Debug)]
pub struct ServerBuilder {
    identity: Identity,
    allow: AllowList,
    service: Option<Service>,
    network: Network,
    fallback: Fallback,
    publish_address: PublishAddress,
    address_key_file: Option<PathBuf>,
    bind: Option<SocketAddr>,
}

impl ServerBuilder {
    fn new(identity: Identity) -> Self {
        Self {
            identity,
            allow: AllowList::empty(),
            service: None,
            network: Network::Direct,
            fallback: Fallback::default(),
            publish_address: PublishAddress::default(),
            address_key_file: None,
            bind: None,
        }
    }

    /// The clients to admit; the default list is empty and admits nobody.
    pub fn allow(mut self, allow: AllowList) -> Self {
        self.allow = allow;
        self
    }

    /// Forwards admitted streams to a loopback TCP service (required unless a
    /// handler is set).
    pub fn forward_to(mut self, target: SocketAddr) -> Self {
        self.service = Some(Service::Target(target));
        self
    }

    /// Serves admitted streams with application code.
    pub fn handler(mut self, handler: impl Handler) -> Self {
        self.service = Some(Service::Handler(Arc::new(handler)));
        self
    }

    /// The network shape: [`Network::Direct`] (the default) listens on one
    /// socket and publishes nothing; the others join the Mainline DHT and
    /// Yggdrasil as the configuration file's `network` object does.
    pub fn network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    /// Fallback mode of the composed shape (default `standby`).
    pub fn fallback(mut self, fallback: Fallback) -> Self {
        self.fallback = fallback;
        self
    }

    /// Whether the DHT record carries the NAT-observed public address; `Encrypted`
    /// needs [`ServerBuilder::address_key_file`].
    pub fn publish_address(mut self, publish: PublishAddress) -> Self {
        self.publish_address = publish;
        self
    }

    /// File with the key that seals an encrypted address record.
    pub fn address_key_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.address_key_file = Some(path.into());
        self
    }

    /// Listen address of the direct shape (default `0.0.0.0:0`); refused in the composed shape.
    pub fn bind(mut self, bind: SocketAddr) -> Self {
        self.bind = Some(bind);
        self
    }

    /// Validates everything and builds the Server; nothing is bound or contacted yet.
    pub fn build(self) -> Result<Server, SdkError> {
        let service = self
            .service
            .ok_or(SdkError::Setup("a Server needs forward_to or handler"))?;
        let mut text = Text::new();
        // A handler needs no TCP target; the placeholder satisfies the schema and is never dialed.
        let target = match &service {
            Service::Target(target) => *target,
            Service::Handler(_) => SocketAddr::from(([127, 0, 0, 1], 1)),
        };
        text.value("target", &target.to_string())?;
        if let Some(bind) = self.bind {
            text.value("bind", &bind.to_string())?;
        }
        text.value(
            "fallback",
            match self.fallback {
                Fallback::Standby => "standby",
                Fallback::Signal => "signal",
            },
        )?;
        text.value(
            "publish_address",
            match self.publish_address {
                PublishAddress::Off => "off",
                PublishAddress::Plain => "plain",
                PublishAddress::Encrypted => "encrypted",
            },
        )?;
        if let Some(path) = &self.address_key_file {
            text.path("address_key_file", path)?;
        }
        text.network(&self.network)?;
        let config = ServerConfig::from_text(text.finish(), &ServerOverrides::default())
            .map_err(SdkError::Config)?;
        Ok(Server {
            config,
            identity: self.identity,
            allow: self.allow,
            service,
        })
    }
}

/// A configured Server. Nothing runs until [`Server::run`] or [`Server::start`].
#[derive(Debug)]
pub struct Server {
    config: ServerConfig,
    identity: Identity,
    allow: AllowList,
    service: Service,
}

impl Server {
    /// Starts collecting settings for a Server with this identity.
    pub fn builder(identity: Identity) -> ServerBuilder {
        ServerBuilder::new(identity)
    }

    /// Loads a Server from a configuration file: the identity from `key_file`,
    /// the clients from `allowlist_path`, the TCP service from `target`.
    pub async fn from_config_file(path: impl AsRef<Path>) -> Result<Self, SdkError> {
        let config = load_server(path.as_ref(), &ServerOverrides::default())
            .await
            .map_err(SdkError::Config)?;
        let identity = Identity::load(config.key_file())
            .await
            .map_err(SdkError::Identity)?;
        let allow = AllowList::read(config.allowlist_path())
            .await
            .map_err(SdkError::AllowList)?;
        Ok(Self::from_config(config, identity, allow))
    }

    /// A Server over an already validated configuration; the service is its
    /// fixed `target`.
    pub fn from_config(config: ServerConfig, identity: Identity, allow: AllowList) -> Self {
        let service = Service::Target(config.target());
        Self {
            config,
            identity,
            allow,
            service,
        }
    }

    /// Replaces the service, for example to serve a configuration file's
    /// Server with a handler.
    pub fn with_service(mut self, service: Service) -> Self {
        self.service = service;
        self
    }

    /// The address clients use to find this Server.
    pub fn address(&self) -> PeerKey {
        PeerKey::of(&self.identity)
    }

    /// The validated configuration.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Serves on the caller's runtime until `shutdown` completes or a terminal
    /// error occurs, then shuts down in order. The future is not `Send`; use
    /// [`Server::start`] to serve from a spawned task.
    /// cancel-safe: NO — dropping it leaves the shutdown to a best-effort drop.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> Result<(), SdkError> {
        let mut shutdown = std::pin::pin!(shutdown);
        self.drive(&mut shutdown, |_| {}).await
    }

    /// Serves on a thread of its own and returns once the Server is up; the
    /// handle is `Send`.
    /// cancel-safe: YES — until the Server is up nothing outlives the future.
    pub async fn start(self) -> Result<RunningServer, SdkError> {
        let address = self.address();
        let running = runtime::spawn(
            "shaar-server",
            move |stop, mut ready: Ready<Option<SocketAddr>>| async move {
                let mut stop = std::pin::pin!(stop.wait());
                let outcome = self
                    .drive(&mut stop, |bound| ready.announce(Ok(bound)))
                    .await;
                match outcome {
                    // A start failure goes to the waiting `start` call.
                    Err(error) if !ready.announced() => {
                        ready.announce(Err(error));
                        Ok(())
                    }
                    other => other,
                }
            },
        )
        .await?;
        Ok(RunningServer { address, running })
    }

    /// Start, serve and close; `ready` receives the bound native address once the Server is up.
    async fn drive(
        self,
        shutdown: &mut Pin<&mut impl Future<Output = ()>>,
        ready: impl FnOnce(Option<SocketAddr>),
    ) -> Result<(), SdkError> {
        let Server {
            mut config,
            identity,
            allow,
            service,
        } = self;
        if config.network().is_some() {
            composed(&mut config, &identity, &allow, service, shutdown, ready).await
        } else {
            direct(&config, &identity, &allow, service, shutdown, ready).await
        }
    }
}

/// The composed shape: the shared role owns DHT publication, signaling and fallback.
async fn composed(
    config: &mut ServerConfig,
    identity: &Identity,
    allow: &AllowList,
    service: Service,
    shutdown: &mut Pin<&mut impl Future<Output = ()>>,
    ready: impl FnOnce(Option<SocketAddr>),
) -> Result<(), SdkError> {
    let limits = Limits::new(MAX_SESSIONS).map_err(SdkError::Network)?;
    let mut role = ServerRole::new(
        config.clone(),
        identity,
        allow.to_network(),
        limits,
        RoleOptions::default(),
    )
    .map_err(SdkError::Startup)?;
    if let Service::Handler(handler) = service {
        role = role.with_handler(stream_handler(handler));
    }
    let started = tokio::select! {
        biased;
        () = shutdown.as_mut() => None,
        result = role.start() => Some(result),
    };
    let mut primary = match started {
        Some(Ok(())) => {
            ready(role.native_addr());
            role.run(shutdown).await.err()
        }
        Some(Err(error)) => Some(error),
        None => None,
    };
    let secondary = role.shutdown().await.err();
    match (primary.take(), secondary) {
        (Some(error), _) | (None, Some(error)) => Err(SdkError::Startup(error)),
        (None, None) => Ok(()),
    }
}

fn stream_handler(handler: Arc<dyn Handler>) -> StreamHandler {
    Arc::new(move |peer, stream| handler.handle(PeerKey::from_iroh(peer), stream))
}

/// The direct shape: one native socket, no DHT, no fallback.
async fn direct(
    config: &ServerConfig,
    identity: &Identity,
    allow: &AllowList,
    service: Service,
    shutdown: &mut Pin<&mut impl Future<Output = ()>>,
    ready: impl FnOnce(Option<SocketAddr>),
) -> Result<(), SdkError> {
    let limits = Limits::new(MAX_SESSIONS).map_err(SdkError::Network)?;
    let mut endpoint = Endpoint::bind(identity, config.bind(), allow.to_network(), limits)
        .await
        .map_err(SdkError::Network)?;
    ready(Some(endpoint.local_addr()));
    let outcome = accept_loop(&mut endpoint, service, shutdown).await;
    endpoint.close().await;
    outcome
}

/// What a session task returns.
type SessionResult = Result<ServeReport, ForwardError>;

async fn accept_loop(
    endpoint: &mut Endpoint,
    service: Service,
    shutdown: &mut Pin<&mut impl Future<Output = ()>>,
) -> Result<(), SdkError> {
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let mut sessions: JoinSet<SessionResult> = JoinSet::new();
    let outcome = 'serve: loop {
        while let Some(joined) = sessions.try_join_next() {
            if let Err(error) = reaped(joined) {
                break 'serve Err(error);
            }
        }
        tokio::select! {
            biased;
            () = shutdown.as_mut() => break Ok(()),
            joined = sessions.join_next(), if sessions.len() >= MAX_SESSIONS => {
                if let Some(Err(error)) = joined.map(reaped) {
                    break Err(error);
                }
            }
            accepted = endpoint.accept(), if sessions.len() < MAX_SESSIONS => match accepted {
                Ok(session) => spawn_session(&mut sessions, session, &service, &stop_rx),
                Err(NetworkError::Closed) => break Err(SdkError::Network(NetworkError::Closed)),
                // A rejected or failed admission never ends the Server.
                Err(_) => {}
            },
        }
    };
    let _ = stop_tx.send(true);
    let mut drained = Ok(());
    while let Some(joined) = sessions.join_next().await {
        if let Err(error) = reaped(joined) {
            drained = Err(error);
        }
    }
    outcome.and(drained)
}

/// A finished session task: only a broken worker ends the Server.
fn reaped(joined: Result<SessionResult, tokio::task::JoinError>) -> Result<(), SdkError> {
    match joined {
        Ok(Err(ForwardError::TaskFailure)) | Err(_) => {
            Err(SdkError::Forward(ForwardError::TaskFailure))
        }
        Ok(_) => Ok(()),
    }
}

fn spawn_session(
    sessions: &mut JoinSet<SessionResult>,
    mut session: Session,
    service: &Service,
    stop_rx: &tokio::sync::watch::Receiver<bool>,
) {
    let service = service.clone();
    let mut stop = stop_rx.clone();
    sessions.spawn(async move {
        let stop = async move {
            if !*stop.borrow() {
                let _ = stop.changed().await;
            }
        };
        match service {
            Service::Target(target) => session.serve(target, stop).await,
            Service::Handler(handler) => {
                session
                    .serve_streams(
                        move |peer, stream| handler.handle(PeerKey::from_iroh(peer), stream),
                        stop,
                    )
                    .await
            }
        }
    });
}

/// A Server running on its own thread.
#[derive(Debug)]
pub struct RunningServer {
    address: PeerKey,
    running: Running<Option<SocketAddr>>,
}

impl RunningServer {
    /// The address clients use to find this Server.
    pub fn address(&self) -> PeerKey {
        self.address
    }

    /// The native (QUIC) socket address; a wildcard IP means all interfaces.
    /// Clients of the direct shape dial a reachable host address with this port.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.running.ready
    }

    /// Stops the Server and waits for its ordered shutdown.
    /// cancel-safe: YES — the stop is requested once; a later call only waits.
    pub async fn shutdown(mut self) -> Result<(), SdkError> {
        self.running.shutdown().await
    }

    /// Resolves when the Server ends on its own, with its outcome.
    /// cancel-safe: YES — the outcome is kept until it is received.
    pub async fn wait(&mut self) -> Result<(), SdkError> {
        self.running.wait().await
    }
}
