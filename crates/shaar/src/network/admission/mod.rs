use std::{net::SocketAddr, sync::Arc, time::Duration};

use iroh::endpoint::{NetReportConfig, PortmapperConfig, QuicTransportConfig, VarInt, presets};
use iroh::{EndpointAddr, TransportAddr};
use iroh_base::PublicKey;
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
        if !policy::native_ip(address.ip()) || address.ip().is_multicast() {
            return Err(NetworkError::InvalidAddress);
        }
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
        let inner = iroh::Endpoint::builder(presets::Minimal)
            .secret_key(identity.transport_key())
            .alpns(vec![ALPN.to_vec()])
            .clear_ip_transports()
            .bind_addr(address)
            .map_err(|_| NetworkError::InvalidAddress)?
            .portmapper_config(PortmapperConfig::Disabled)
            .net_report_config(NetReportConfig::minimal())
            .incoming_limits(limits.sessions, 16 * 1024, 512 * 1024)
            .connection_limit(limits.sessions * 2)
            .transport_config(transport)
            .bind()
            .await
            .map_err(|error| NetworkError::Bind(Box::new(error)))?;
        let address = inner
            .bound_sockets()
            .into_iter()
            .next()
            .ok_or(NetworkError::InvalidAddress)?;
        Ok(Self {
            inner,
            address,
            allowlist,
            slots: Arc::new(Semaphore::new(limits.sessions)),
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
        let admission = self.admit()?;
        let remote = EndpointAddr::from_parts(peer, [TransportAddr::Ip(address)]);
        let connection = tokio::time::timeout(HANDSHAKE_TIMEOUT, self.inner.connect(remote, ALPN))
            .await
            .map_err(|_| NetworkError::Deadline)?
            .map_err(NetworkError::from_connect)?;
        if connection.remote_id() != peer {
            connection.close(VarInt::from_u32(2), b"");
            return Err(NetworkError::PeerMismatch);
        }
        Self::session(connection, admission)
    }

    /// Accepts one fully handshaken, allowlisted peer. Mutable access serializes
    /// inbound handshakes; a rejected peer never produces an application session.
    /// cancel-safe: NO — a received Initial/handshake is consumed, not replayed;
    /// SDK slots are returned on cancellation, protocol metadata drains separately.
    pub async fn accept(&mut self) -> Result<Session, NetworkError> {
        let incoming = self.inner.accept().await.ok_or(NetworkError::Closed)?;
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
        Self::session(connection, admission)
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
