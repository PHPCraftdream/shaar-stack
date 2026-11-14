use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc, time::Duration};

use futures::{StreamExt, stream::FuturesUnordered};
use iroh::endpoint::{
    BindOpts, NetReportConfig, PortmapperConfig, QuicTransportConfig, VarInt, presets,
};
use iroh::{EndpointAddr, TransportAddr, endpoint::IncomingAddr};
use iroh_base::PublicKey;
use shaar_p2p::SignalingTransport;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::identity::Identity;

use super::{ALPN, NetworkError, STREAM_LIMIT, Session, session::ACCESS_DENIED};

mod policy;
pub(super) use policy::native_ip;
pub use policy::{Allowlist, Limits};
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "P10 4c path-owner wiring is pending")
)]
pub(crate) mod ygg;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg(test)]
mod native_path_tests;
#[cfg(test)]
pub(crate) mod negotiation_frames;
#[cfg(test)]
mod negotiation_tests;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
// First post-RX eliciting send can reset idle within the 2 s keepalive.
// 5 s idle + 2 s keepalive + default 2 s grace leaves payload headroom.
// The SDK handshake limit stays 10 s; backend idle timeout can expire first.
const NATIVE_IDLE_TIMEOUT_MS: u32 = 5_000;
// Retire a silent path before connection idle can kill a usable backup.
const NATIVE_PATH_IDLE_TIMEOUT: Duration = Duration::from_secs(4);
const NATIVE_PATH_KEEPALIVE: Duration = Duration::from_secs(2);
const _: () = assert!(
    NATIVE_PATH_IDLE_TIMEOUT.as_millis() < NATIVE_IDLE_TIMEOUT_MS as u128,
    "path idle must precede connection idle"
);

/// A failed inbound handshake parked in the pending set.
enum HandshakeFailure {
    Deadline,
    Handshake(iroh::endpoint::ConnectingError),
}

/// Outcome of one parked inbound handshake.
struct HandshakeOutcome {
    source: IncomingAddr,
    connection: Result<iroh::endpoint::Connection, HandshakeFailure>,
}

/// One concurrently driven inbound handshake, bounded by the endpoint's pending cap.
type PendingHandshake = Pin<Box<dyn Future<Output = HandshakeOutcome> + Send>>;

/// Parked inbound handshakes. The `Mutex` is only a `Sync` adapter for the boxed
/// futures: every access goes through `&mut self` and `get_mut`, so it is never
/// locked, never contended and never held across an await.
struct Pending(std::sync::Mutex<FuturesUnordered<PendingHandshake>>);

impl Pending {
    fn new() -> Self {
        Self(std::sync::Mutex::new(FuturesUnordered::new()))
    }

    fn set(&mut self) -> &mut FuturesUnordered<PendingHandshake> {
        self.0
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn len(&mut self) -> usize {
        self.set().len()
    }

    fn is_empty(&mut self) -> bool {
        self.set().is_empty()
    }

    fn push(&mut self, handshake: PendingHandshake) {
        self.set().push(handshake);
    }

    /// cancel-safe: yes — a completed handshake is taken only in the poll that returns it.
    async fn next(&mut self) -> Option<HandshakeOutcome> {
        self.set().next().await
    }
}

/// Parks one accepted transport attempt; its 10 s deadline starts at insertion.
/// Dropping the parked future abandons only that one handshake.
fn park_handshake(incoming: iroh::endpoint::Incoming) -> PendingHandshake {
    let source = incoming.remote_addr();
    Box::pin(async move {
        let connection =
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, async { incoming.await }).await {
                Ok(connection) => connection.map_err(HandshakeFailure::Handshake),
                Err(_elapsed) => Err(HandshakeFailure::Deadline),
            };
        HandshakeOutcome { source, connection }
    })
}

/// Native sockets and immutable admission policy. Not Clone.
/// No SDK task is spawned: callers own/poll handshakes and shutdown themselves.
pub struct Endpoint {
    inner: iroh::Endpoint,
    address: SocketAddr,
    allowlist: Allowlist,
    slots: Arc<Semaphore>,
    custom: Option<Arc<SignalingTransport>>,
    /// Concurrent inbound handshakes allowed before authentication.
    pending_cap: usize,
    pending: Pending,
}

impl Endpoint {
    /// Binds without n0, relays, port mapping or external address lookup.
    /// cancel-safe: NO — a cancelled bind must not be treated as successful startup.
    pub async fn bind(
        identity: &Identity,
        address: SocketAddr,
        allowlist: Allowlist,
        limits: Limits,
    ) -> Result<Self, NetworkError> {
        Self::bind_custom(identity, address, allowlist, limits, None).await
    }

    pub(in crate::network) fn validate_bind(address: SocketAddr) -> Result<(), NetworkError> {
        if !policy::native_ip(address.ip()) || address.ip().is_multicast() {
            return Err(NetworkError::InvalidAddress);
        }
        Ok(())
    }

    /// cancel-safe: NO — cancellation does not prove completed backend startup or drain.
    pub(in crate::network) async fn bind_custom(
        identity: &Identity,
        address: SocketAddr,
        allowlist: Allowlist,
        limits: Limits,
        custom: Option<Arc<SignalingTransport>>,
    ) -> Result<Self, NetworkError> {
        // Fresh per-endpoint admission pool; a shared pool opts in explicitly.
        Self::bind_custom_shared(
            identity,
            address,
            allowlist,
            limits,
            custom,
            Arc::new(Semaphore::new(limits.sessions)),
            false,
        )
        .await
    }

    /// Binds over a caller-provided admission pool. The shared pool bounds LIVE
    /// admission (outbound handshakes, authenticated sessions and live handles)
    /// across every endpoint built over it; the numeric iroh incoming/connection
    /// limits stay per endpoint as transport-level guards.
    /// Inbound handshakes are bounded per endpoint by the pending cap before authentication.
    /// cancel-safe: NO — cancellation does not prove completed backend startup or drain.
    pub(in crate::network) async fn bind_custom_shared(
        identity: &Identity,
        address: SocketAddr,
        allowlist: Allowlist,
        limits: Limits,
        custom: Option<Arc<SignalingTransport>>,
        slots: Arc<Semaphore>,
        dual_stack: bool,
    ) -> Result<Self, NetworkError> {
        Self::validate_bind(address)?;
        if dual_stack && address != SocketAddr::from(([0, 0, 0, 0], 0)) {
            return Err(NetworkError::InvalidAddress);
        }
        let transport = QuicTransportConfig::builder()
            .application_data_filter(|path| policy::native_ip(path.remote().ip()))
            .max_idle_timeout(Some(VarInt::from_u32(NATIVE_IDLE_TIMEOUT_MS).into()))
            .default_path_max_idle_timeout(NATIVE_PATH_IDLE_TIMEOUT)
            .default_path_keep_alive_interval(NATIVE_PATH_KEEPALIVE)
            .max_concurrent_bidi_streams(VarInt::from_u32(u32::from(STREAM_LIMIT)))
            .max_concurrent_uni_streams(VarInt::from_u32(0))
            .stream_receive_window(VarInt::from_u32(256 * 1024))
            .receive_window(VarInt::from_u32(1024 * 1024))
            .send_window(1024 * 1024)
            .datagram_receive_buffer_size(None)
            .datagram_send_buffer_size(0)
            .build();
        let builder = iroh::Endpoint::builder(presets::Minimal)
            .secret_key(identity.transport_key())
            .alpns(vec![ALPN.to_vec()])
            .clear_ip_transports()
            .bind_addr(address)
            .map_err(|_| NetworkError::InvalidAddress)?;
        let builder = if dual_stack {
            builder
                .bind_addr_with_opts(
                    SocketAddr::from(([0_u16; 8], 0)),
                    BindOpts::default().set_is_required(false),
                )
                .map_err(|_| NetworkError::InvalidAddress)?
        } else {
            builder
        };
        let builder = builder
            .portmapper_config(PortmapperConfig::Disabled)
            .net_report_config(NetReportConfig::minimal())
            .incoming_limits(limits.sessions, 16 * 1024, 512 * 1024)
            .connection_limit(limits.sessions * 2)
            .transport_config(transport);
        let builder = match &custom {
            Some(factory) => builder.add_custom_transport(factory.clone()),
            None => builder,
        };
        let inner = builder
            .bind()
            .await
            .map_err(|error| NetworkError::Bind(Box::new(error)))?;
        let address = match inner
            .bound_sockets()
            .into_iter()
            .find(|bound| !dual_stack || bound.is_ipv4())
        {
            Some(address) => address,
            None => {
                inner.close().await;
                return Err(NetworkError::InvalidAddress);
            }
        };
        Ok(Self {
            inner,
            address,
            allowlist,
            slots,
            custom,
            pending_cap: limits.sessions,
            pending: Pending::new(),
        })
    }

    pub fn id(&self) -> PublicKey {
        self.inner.id()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    #[cfg(test)]
    pub(crate) fn bound_native_sockets(&self) -> Vec<SocketAddr> {
        self.inner.bound_sockets()
    }

    #[cfg(test)]
    pub(crate) fn native_packet_gate(&self) -> Arc<iroh::endpoint::NativePacketGate> {
        self.inner.native_packet_gate()
    }

    pub(crate) fn native_addr_watcher(&self) -> impl iroh::Watcher<Value = EndpointAddr> + use<> {
        self.inner.watch_addr()
    }

    fn admit(&self) -> Result<OwnedSemaphorePermit, NetworkError> {
        if self.inner.is_closed() {
            return Err(NetworkError::Closed);
        }
        // Non-queued acquisition: callers cannot create an unbounded waiter queue.
        self.slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| NetworkError::Capacity)
    }

    /// Pins the exact TLS identity at a native address; does not enable early data.
    /// This authenticates the server, not its acceptance of a later TCP request.
    /// cancel-safe: NO — dropping the future abandons the attempt, releases its SDK
    /// slot and drops its connection handles; protocol metadata may remain until drain.
    pub async fn connect(
        &self,
        peer: PublicKey,
        address: SocketAddr,
    ) -> Result<Session, NetworkError> {
        if !policy::dial_address(address) {
            return Err(NetworkError::InvalidAddress);
        }
        self.connect_route(peer, TransportAddr::Ip(address)).await
    }

    /// cancel-safe: NO — a cancelled handshake is abandoned, not replayed.
    pub(in crate::network) async fn connect_custom(
        &self,
        peer: PublicKey,
        address: iroh_base::CustomAddr,
    ) -> Result<Session, NetworkError> {
        self.connect_route(peer, TransportAddr::Custom(address))
            .await
    }

    /// cancel-safe: NO — a completed handshake may retain bounded metadata until drain.
    async fn connect_route(
        &self,
        peer: PublicKey,
        address: TransportAddr,
    ) -> Result<Session, NetworkError> {
        let source = match &address {
            TransportAddr::Ip(address) => IncomingAddr::Ip(*address),
            TransportAddr::Custom(address) => IncomingAddr::Custom(address.clone()),
            _ => return Err(NetworkError::InvalidAddress),
        };
        let admission = self.admit()?;
        let remote = EndpointAddr::from_parts(peer, [address]);
        let connect = async {
            let connection = self
                .inner
                .connect(remote, ALPN)
                .await
                .map_err(NetworkError::from_connect)?;
            self.finish_connect(connection, admission, peer, source)
                .await
        };
        tokio::time::timeout(HANDSHAKE_TIMEOUT, connect)
            .await
            .map_err(|_| NetworkError::Deadline)?
    }

    /// cancel-safe: NO — an unpublished session closes on failure or cancellation, not drain.
    async fn finish_connect(
        &self,
        connection: iroh::endpoint::Connection,
        admission: OwnedSemaphorePermit,
        peer: PublicKey,
        source: IncomingAddr,
    ) -> Result<Session, NetworkError> {
        if connection.remote_id() != peer || !self.source_matches(&source, &peer) {
            connection.close(VarInt::from_u32(2), b"");
            return Err(NetworkError::PeerMismatch);
        }
        // An unpublished Session closes the new connection if path setup fails or is cancelled.
        let session = Self::session(connection, admission)?;
        if let IncomingAddr::Ip(address) = source
            && self.custom.is_some()
        {
            // Reused paths need the same pruning retention as newly admitted paths.
            session
                .connection
                .ensure_native_path(address)
                .await
                .map_err(NetworkError::NativePath)?;
        }
        Ok(session)
    }

    /// Accepts one fully handshaken, allowlisted peer.
    ///
    /// Inbound handshakes are driven concurrently and bounded by their own cap
    /// (`pending_cap`, the configured session limit kept separate from the slot
    /// pool): a silent or unauthenticated Initial parks without a session slot,
    /// so it never delays or displaces another peer's admission and cannot
    /// exhaust the authenticated session pool. An attempt beyond the cap is
    /// refused immediately, and so is one that arrives while the session pool is
    /// saturated ([`NetworkError::Capacity`], before any handshake work); a peer
    /// that authenticates after the pool filled up meanwhile is closed with the
    /// same error. Initials that arrive while no
    /// accept poll is pending queue inside the transport under its own limits.
    /// Parked handshakes progress only while this future is polled; the
    /// endpoint retains them across calls, and `pending + live` stays within
    /// the transport's `connection_limit` headroom.
    ///
    /// cancel-safe: YES — dropping or losing the select race on this future
    /// parks the polled attempt in the pending set (or leaves it queued in the
    /// transport), and a later call completes the same handshake; an attempt is
    /// always either parked or refused, never silently consumed. Each failed
    /// handshake is returned as its own error as soon as it completes
    /// ([`NetworkError::Deadline`] for the 10 s handshake deadline) while the
    /// other parked handshakes stay in place; after [`Self::close`] the call
    /// answers [`NetworkError::Closed`].
    pub async fn accept(&mut self) -> Result<Session, NetworkError> {
        loop {
            if self.inner.is_closed() {
                return Err(NetworkError::Closed);
            }
            tokio::select! {
                biased;
                completed = self.pending.next(), if !self.pending.is_empty() => {
                    // The arm is disabled while the set is empty, so `None` cannot occur.
                    let Some(outcome) = completed else { continue };
                    return self.finish_inbound(outcome);
                }
                incoming = self.inner.accept() => match incoming {
                    Some(incoming) => {
                        // A saturated pool refuses before any handshake work, as before;
                        // the check takes no slot, so parked handshakes still hold none.
                        if let Err(error) = self.admit() {
                            incoming.refuse();
                            return Err(error);
                        }
                        if self.pending.len() >= self.pending_cap {
                            incoming.refuse();
                            continue;
                        }
                        self.pending.push(park_handshake(incoming));
                    }
                    None => return Err(NetworkError::Closed),
                },
            }
        }
    }

    /// Authenticates one completed handshake and charges the session slot only now.
    fn finish_inbound(&self, outcome: HandshakeOutcome) -> Result<Session, NetworkError> {
        let connection = match outcome.connection {
            Ok(connection) => connection,
            Err(HandshakeFailure::Deadline) => return Err(NetworkError::Deadline),
            Err(HandshakeFailure::Handshake(error)) => {
                return Err(NetworkError::from_handshake(error));
            }
        };
        if !self.allowlist.contains(&connection.remote_id()) {
            connection.close(VarInt::from_u32(ACCESS_DENIED), b"");
            return Err(NetworkError::AccessDenied);
        }
        if !self.source_matches(&outcome.source, &connection.remote_id()) {
            connection.close(VarInt::from_u32(2), b"");
            return Err(NetworkError::PeerMismatch);
        }
        let admission = match self.admit() {
            Ok(admission) => admission,
            Err(error) => {
                connection.close(VarInt::from_u32(2), b"");
                return Err(error);
            }
        };
        Self::session(connection, admission)
    }

    fn source_matches(&self, source: &IncomingAddr, peer: &PublicKey) -> bool {
        match source {
            IncomingAddr::Ip(address) => policy::native_ip(address.ip()),
            IncomingAddr::Custom(address) => self.custom.as_ref().is_some_and(|factory| {
                let Ok(peer) = super::signaling::peer_id(peer) else {
                    return false;
                };
                factory
                    .authenticated_link(address)
                    .is_ok_and(|link| link.peer == peer)
            }),
            _ => false,
        }
    }

    fn session(
        connection: iroh::endpoint::Connection,
        admission: OwnedSemaphorePermit,
    ) -> Result<Session, NetworkError> {
        if connection.alpn() != ALPN {
            connection.close(VarInt::from_u32(2), b"");
            return Err(NetworkError::Protocol);
        }
        Ok(Session {
            connection,
            streams: Semaphore::new(usize::from(STREAM_LIMIT)),
            _admission: admission,
        })
    }

    /// Closes all connections, waits for the backend drain boundary and drops the
    /// only SDK endpoint owner. Sessions do not hold endpoint clones.
    /// cancel-safe: NO — cancellation drops the owner but does not finish async drain.
    pub async fn close(self) {
        self.slots.close();
        self.inner.close().await;
    }
}
