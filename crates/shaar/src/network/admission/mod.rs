use std::{net::SocketAddr, sync::Arc, time::Duration};

use iroh::endpoint::{NetReportConfig, PortmapperConfig, QuicTransportConfig, VarInt, presets};
use iroh::{EndpointAddr, TransportAddr, endpoint::IncomingAddr};
use iroh_base::PublicKey;
use shaar_p2p::SignalingTransport;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::identity::Identity;

use super::{ALPN, NetworkError, STREAM_LIMIT, Session, session::ACCESS_DENIED};

mod policy;
pub use policy::{Allowlist, Limits};

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A single native socket and immutable admission policy. Not Clone.
/// No SDK task is spawned: callers own/poll handshakes and shutdown themselves.
pub struct Endpoint {
    inner: iroh::Endpoint,
    address: SocketAddr,
    allowlist: Allowlist,
    slots: Arc<Semaphore>,
    custom: Option<Arc<SignalingTransport>>,
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
        Self::validate_bind(address)?;
        let transport = QuicTransportConfig::builder()
            .application_data_filter(|path| policy::native_ip(path.remote().ip()))
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
            .map_err(|_| NetworkError::InvalidAddress)?
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
        let address = match inner.bound_sockets().into_iter().next() {
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
            slots: Arc::new(Semaphore::new(limits.sessions)),
            custom,
        })
    }

    pub fn id(&self) -> PublicKey {
        self.inner.id()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.address
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
            if connection.remote_id() != peer || !self.source_matches(&source, &peer) {
                connection.close(VarInt::from_u32(2), b"");
                return Err(NetworkError::PeerMismatch);
            }
            // An unpublished Session closes the new connection if path setup fails or is cancelled.
            let session = Self::session(connection, admission)?;
            if let IncomingAddr::Ip(address) = source
                && self.custom.is_some()
            {
                let established = session.connection.paths().iter().any(|path|
                    matches!(path.remote_addr(), TransportAddr::Ip(remote) if *remote == address));
                if !established {
                    session
                        .connection
                        .ensure_native_path(address)
                        .await
                        .map_err(NetworkError::NativePath)?;
                }
            }
            Ok(session)
        };
        tokio::time::timeout(HANDSHAKE_TIMEOUT, connect)
            .await
            .map_err(|_| NetworkError::Deadline)?
    }

    /// Accepts one fully handshaken, allowlisted peer. Mutable access serializes
    /// inbound handshakes; a rejected peer never produces an application session.
    /// cancel-safe: NO — a received Initial/handshake is consumed, not replayed;
    /// SDK slots are returned on cancellation, protocol metadata drains separately.
    pub async fn accept(&mut self) -> Result<Session, NetworkError> {
        let incoming = self.inner.accept().await.ok_or(NetworkError::Closed)?;
        let source = incoming.remote_addr();
        let admission = match self.admit() {
            Ok(admission) => admission,
            Err(error) => {
                incoming.refuse();
                return Err(error);
            }
        };
        let connection = tokio::time::timeout(HANDSHAKE_TIMEOUT, async { incoming.await })
            .await
            .map_err(|_| NetworkError::Deadline)?
            .map_err(|error| NetworkError::Handshake(Box::new(error)))?;
        if !self.allowlist.contains(&connection.remote_id()) {
            connection.close(VarInt::from_u32(ACCESS_DENIED), b"");
            return Err(NetworkError::AccessDenied);
        }
        if !self.source_matches(&source, &connection.remote_id()) {
            connection.close(VarInt::from_u32(2), b"");
            return Err(NetworkError::PeerMismatch);
        }
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
