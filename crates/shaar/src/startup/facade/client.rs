//! The Client facade: build a Client from typed values or from a configuration
//! file, run it on a thread of its own and open streams to the Server.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;

use super::runtime::{self, Ready, Running};
use super::text::{Network, Text};
use super::{PeerKey, SdkError};
use crate::config::{ClientConfig, ClientOverrides, Fallback, load_client};
use crate::identity::Identity;
use crate::network::{
    Allowlist, Endpoint, ForwardError, Limits, NetworkError, ServiceStream, Session,
};
use crate::startup::{ClientRole, RoleOptions};

/// Most local TCP connections forwarded at once (the same bound as the binary).
const MAX_FORWARDS: usize = 16;
const MAX_ATTEMPTS: u32 = 3;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(12);
const BACKOFF: Duration = Duration::from_millis(250);
/// Queued `connect` calls waiting for the role thread.
const OPEN_QUEUE: usize = 8;

/// Collects the settings of a [`Client`]; every value is validated by
/// [`ClientBuilder::build`] with the same rules as a configuration file.
#[derive(Debug)]
pub struct ClientBuilder {
    identity: Identity,
    server: PeerKey,
    server_address: Option<SocketAddr>,
    network: Network,
    fallback: Fallback,
    listen: Option<SocketAddr>,
    address_key_file: Option<PathBuf>,
}

impl ClientBuilder {
    fn new(identity: Identity, server: PeerKey) -> Self {
        Self {
            identity,
            server,
            server_address: None,
            network: Network::Direct,
            fallback: Fallback::default(),
            listen: None,
            address_key_file: None,
        }
    }

    /// The Server's reachable `ip:port`: required for [`Network::Direct`], an
    /// optional first candidate otherwise.
    pub fn server_address(mut self, address: SocketAddr) -> Self {
        self.server_address = Some(address);
        self
    }

    /// The network shape; see [`Network`].
    pub fn network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    /// Fallback mode of the composed shape (default `standby`).
    pub fn fallback(mut self, fallback: Fallback) -> Self {
        self.fallback = fallback;
        self
    }

    /// Also listens on this loopback address and forwards every accepted TCP
    /// connection to the Server. The composed shape always listens (port 0
    /// when this is not set); the direct shape listens only when this is set.
    pub fn listen(mut self, listen: SocketAddr) -> Self {
        self.listen = Some(listen);
        self
    }

    /// File with the key that opens an encrypted address record of the Server.
    pub fn address_key_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.address_key_file = Some(path.into());
        self
    }

    /// Validates everything and builds the Client; nothing is bound or contacted yet.
    pub fn build(self) -> Result<Client, SdkError> {
        if self.network == Network::Direct && self.server_address.is_none() {
            return Err(SdkError::Setup(
                "the direct shape needs the Server's address (server_address)",
            ));
        }
        let mut text = Text::new();
        text.value("server", &self.server.to_string())?;
        if let Some(address) = self.server_address {
            text.value("server_address", &address.to_string())?;
        }
        let listen = self
            .listen
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));
        text.value("listen", &listen.to_string())?;
        text.value(
            "fallback",
            match self.fallback {
                Fallback::Standby => "standby",
                Fallback::Signal => "signal",
            },
        )?;
        if let Some(path) = &self.address_key_file {
            text.path("address_key_file", path)?;
        }
        text.network(&self.network)?;
        let config = ClientConfig::from_text(text.finish(), &ClientOverrides::default())
            .map_err(SdkError::Config)?;
        Ok(Client {
            config,
            identity: self.identity,
            listener: self.listen.is_some(),
        })
    }
}

/// A configured Client. Nothing runs until [`Client::start`].
#[derive(Debug)]
pub struct Client {
    config: ClientConfig,
    identity: Identity,
    /// Whether the direct shape also listens for local TCP connections.
    listener: bool,
}

impl Client {
    /// Starts collecting settings for a Client with this identity that reaches `server`.
    pub fn builder(identity: Identity, server: PeerKey) -> ClientBuilder {
        ClientBuilder::new(identity, server)
    }

    /// Loads a Client from a configuration file: the identity from `key_file`,
    /// the Server from `server`. As with the binary, a loopback listener is bound.
    pub async fn from_config_file(path: impl AsRef<Path>) -> Result<Self, SdkError> {
        let config = load_client(path.as_ref(), &ClientOverrides::default())
            .await
            .map_err(SdkError::Config)?;
        let identity = Identity::load(config.key_file())
            .await
            .map_err(SdkError::Identity)?;
        Ok(Self::from_config(config, identity))
    }

    /// [`Self::from_config_file`] for a key file that `key encrypt` made: `password` opens it.
    pub async fn from_config_file_with_password(
        path: impl AsRef<Path>,
        password: &str,
    ) -> Result<Self, SdkError> {
        let config = load_client(path.as_ref(), &ClientOverrides::default())
            .await
            .map_err(SdkError::Config)?;
        let identity = Identity::load_with_password(config.key_file(), password)
            .await
            .map_err(SdkError::Identity)?;
        Ok(Self::from_config(config, identity))
    }

    /// A Client over an already validated configuration; it listens locally.
    pub fn from_config(config: ClientConfig, identity: Identity) -> Self {
        Self {
            config,
            identity,
            listener: true,
        }
    }

    /// The Server this Client reaches.
    pub fn server(&self) -> PeerKey {
        PeerKey::from_bytes(*self.config.server_key_bytes())
            .expect("a validated configuration holds a valid server key")
    }

    /// This Client's own key: what the Server must have in its allowlist.
    pub fn key(&self) -> PeerKey {
        PeerKey::of(&self.identity)
    }

    /// The validated configuration.
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Runs the Client on a thread of its own and returns once it is up.
    /// cancel-safe: YES — until the Client is up nothing outlives the future.
    pub async fn start(self) -> Result<RunningClient, SdkError> {
        let server = self.server();
        let running = runtime::spawn(
            "shaar-client",
            move |stop, mut ready: Ready<Up>| async move {
                let mut stop = std::pin::pin!(stop.wait());
                let outcome = self.drive(&mut stop, &mut ready).await;
                match outcome {
                    Ok(()) => Ok(()),
                    // A start failure goes to the waiting `start` call.
                    Err(error) if !ready.announced() => {
                        ready.announce(Err(error));
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            },
        )
        .await?;
        Ok(RunningClient { server, running })
    }

    async fn drive(
        self,
        shutdown: &mut std::pin::Pin<&mut impl std::future::Future<Output = ()>>,
        ready: &mut Ready<Up>,
    ) -> Result<(), SdkError> {
        let Client {
            mut config,
            identity,
            listener,
        } = self;
        if config.network().is_some() {
            composed(&mut config, &identity, shutdown, ready).await
        } else {
            direct(&config, &identity, listener, shutdown, ready).await
        }
    }
}

/// What a started Client offers to `connect`.
#[derive(Debug)]
struct Up {
    /// The loopback listener, when there is one.
    listen: Option<SocketAddr>,
    /// Direct shape: requests to the role thread, which owns the session.
    opener: Option<mpsc::Sender<Open>>,
}

struct Open {
    reply: oneshot::Sender<Result<ServiceStream, ForwardError>>,
}

impl std::fmt::Debug for Open {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Open")
    }
}

/// The composed shape: the shared role dials, falls back and listens on loopback.
async fn composed(
    config: &mut ClientConfig,
    identity: &Identity,
    shutdown: &mut std::pin::Pin<&mut impl std::future::Future<Output = ()>>,
    ready: &mut Ready<Up>,
) -> Result<(), SdkError> {
    let limits = Limits::new(1).map_err(SdkError::Network)?;
    let mut role = ClientRole::new(config.clone(), identity, limits, RoleOptions::default())
        .map_err(SdkError::Startup)?;
    let started = tokio::select! {
        biased;
        () = shutdown.as_mut() => None,
        result = role.start() => Some(result),
    };
    let mut primary = match started {
        Some(Ok(())) => {
            let mut listening = std::pin::pin!(role.listening());
            let mut announced = false;
            let mut run = std::pin::pin!(role.run(shutdown));
            loop {
                tokio::select! {
                    result = &mut run => break result.err(),
                    address = &mut listening, if !announced => {
                        announced = true;
                        if let Some(address) = address {
                            ready.announce(Ok(Up { listen: Some(address), opener: None }));
                        }
                    }
                }
            }
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

/// Dials with a few paced attempts; a refusal by the Server is final.
async fn dial(
    endpoint: &Endpoint,
    key: PeerKey,
    address: SocketAddr,
) -> Result<Session, NetworkError> {
    let mut retry = 0u32;
    loop {
        match tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(key.to_iroh(), address)).await
        {
            Ok(Ok(session)) => return Ok(session),
            Ok(Err(error @ (NetworkError::AccessDenied | NetworkError::PeerMismatch))) => {
                return Err(error);
            }
            Ok(Err(error)) if retry + 1 >= MAX_ATTEMPTS => return Err(error),
            Err(_) if retry + 1 >= MAX_ATTEMPTS => return Err(NetworkError::Deadline),
            _ => {
                retry += 1;
                tokio::time::sleep(BACKOFF * retry).await;
            }
        }
    }
}

/// The direct shape: one native socket, one session, streams opened on demand.
async fn direct(
    config: &ClientConfig,
    identity: &Identity,
    listener: bool,
    shutdown: &mut std::pin::Pin<&mut impl std::future::Future<Output = ()>>,
    ready: &mut Ready<Up>,
) -> Result<(), SdkError> {
    let address = config
        .server_address()
        .ok_or(SdkError::Setup("the direct shape needs server_address"))?;
    let bind: SocketAddr = if address.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        "[::]:0".parse().expect("static wildcard literal parses")
    };
    let limits = Limits::new(1).map_err(SdkError::Network)?;
    let endpoint = Endpoint::bind(identity, bind, Allowlist::default(), limits)
        .await
        .map_err(SdkError::Network)?;
    let server = PeerKey::from_bytes(*config.server_key_bytes())
        .expect("a validated configuration holds a valid server key");
    let session = tokio::select! {
        biased;
        () = shutdown.as_mut() => {
            endpoint.close().await;
            return Ok(());
        }
        result = dial(&endpoint, server, address) => match result {
            Ok(session) => Arc::new(session),
            Err(error) => {
                endpoint.close().await;
                return Err(SdkError::Network(error));
            }
        },
    };
    let listener = if listener {
        Some(
            TcpListener::bind(config.listen())
                .await
                .map_err(SdkError::Io)?,
        )
    } else {
        None
    };
    let (open_tx, mut open_rx) = mpsc::channel::<Open>(OPEN_QUEUE);
    ready.announce(Ok(Up {
        listen: listener.as_ref().and_then(|l| l.local_addr().ok()),
        opener: Some(open_tx),
    }));
    let mut workers: JoinSet<()> = JoinSet::new();
    let outcome = loop {
        tokio::select! {
            biased;
            () = shutdown.as_mut() => break Ok(()),
            closed = session.closed() => break Err(SdkError::Network(closed)),
            request = open_rx.recv(), if workers.len() < MAX_FORWARDS => {
                if let Some(Open { reply }) = request {
                    let session = Arc::clone(&session);
                    workers.spawn(async move {
                        let _ = reply.send(session.open_stream().await);
                    });
                }
            }
            accepted = async { listener.as_ref().expect("guarded").accept().await },
                if listener.is_some() && workers.len() < MAX_FORWARDS => {
                if let Ok((stream, _)) = accepted {
                    let session = Arc::clone(&session);
                    workers.spawn(async move {
                        let _ = session.forward(stream).await;
                    });
                }
            }
            _ = workers.join_next(), if !workers.is_empty() => {}
        }
    };
    workers.abort_all();
    while workers.join_next().await.is_some() {}
    drop(session);
    endpoint.close().await;
    outcome
}

/// A Client running on its own thread.
#[derive(Debug)]
pub struct RunningClient {
    server: PeerKey,
    running: Running<Up>,
}

impl RunningClient {
    /// The Server this Client reaches.
    pub fn server(&self) -> PeerKey {
        self.server
    }

    /// The loopback address that forwards local TCP connections to the Server,
    /// when the Client listens.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.running.ready.listen
    }

    /// Opens one stream to the Server's service.
    ///
    /// The direct shape opens a QUIC stream on the Client's session. The composed
    /// shape connects to the loopback listener of the role, which forwards it over
    /// the active path (direct QUIC or Yggdrasil). An error means the Server
    /// refused the stream, is unreachable or the Client has ended.
    /// cancel-safe: NO — cancellation resets the stream being set up.
    pub async fn connect(&self) -> Result<ServiceStream, SdkError> {
        let up = &self.running.ready;
        if let Some(opener) = &up.opener {
            let (reply, answer) = oneshot::channel();
            opener
                .send(Open { reply })
                .await
                .map_err(|_| SdkError::Closed)?;
            return answer
                .await
                .map_err(|_| SdkError::Closed)?
                .map_err(SdkError::Forward);
        }
        let address = up.listen.ok_or(SdkError::Closed)?;
        let stream = TcpStream::connect(address).await.map_err(SdkError::Io)?;
        Ok(ServiceStream::from_tcp(stream))
    }

    /// Stops the Client and waits for its ordered shutdown.
    /// cancel-safe: YES — the stop is requested once; a later call only waits.
    pub async fn shutdown(mut self) -> Result<(), SdkError> {
        self.running.shutdown().await
    }

    /// Resolves when the Client ends on its own, with its outcome.
    /// cancel-safe: YES — the outcome is kept until it is received.
    pub async fn wait(&mut self) -> Result<(), SdkError> {
        self.running.wait().await
    }
}
