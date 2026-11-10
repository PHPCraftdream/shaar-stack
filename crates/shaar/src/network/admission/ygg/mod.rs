use std::{net::IpAddr, sync::Arc, time::Duration};

use crate::identity::Identity;
use iroh::endpoint::{NetReportConfig, PortmapperConfig, QuicTransportConfig, VarInt, presets};
use iroh::{EndpointAddr, TransportAddr, endpoint::IncomingAddr};
use iroh_base::{CustomAddr, PublicKey};
use shaar_ygg::{YggBridge, YggCarrier, YggPump};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::network::{
    ALPN, Allowlist, Limits, NetworkError, STREAM_LIMIT, Session, session::ACCESS_DENIED,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Private custom-only endpoint; native and signaling endpoint construction is unchanged.
pub(crate) struct YggEndpoint {
    inner: iroh::Endpoint,
    carrier: Arc<YggCarrier>,
    allowlist: Allowlist,
    slots: Arc<Semaphore>,
    closed: bool,
}

impl YggEndpoint {
    /// cancel-safe: NO — cancellation does not prove capability revocation and bind completion.
    pub(crate) async fn bind(
        identity: &Identity,
        bridge: &YggBridge,
        allowlist: Allowlist,
        limits: Limits,
    ) -> Result<(Self, YggPump), NetworkError> {
        // Fresh per-endpoint admission pool; a shared pool opts in explicitly.
        Self::bind_shared_slots(
            identity,
            bridge,
            allowlist,
            limits,
            Arc::new(Semaphore::new(limits.sessions)),
        )
        .await
    }

    /// Binds over a caller-provided admission pool shared with the native and
    /// signaling endpoint, so live admission is bounded across both paths.
    /// Identity/bridge guard and all validation are identical to `bind`.
    /// cancel-safe: NO — cancellation does not prove capability revocation and bind completion.
    pub(crate) async fn bind_shared_slots(
        identity: &Identity,
        bridge: &YggBridge,
        allowlist: Allowlist,
        limits: Limits,
        slots: Arc<Semaphore>,
    ) -> Result<(Self, YggPump), NetworkError> {
        let local_key = identity.public_key_bytes();
        if bridge.public_key() != local_key {
            return Err(NetworkError::PeerMismatch);
        }
        let peer_keys: Vec<PublicKey> = allowlist.keys().collect();
        if peer_keys.len() > shaar_ygg::MAX_DATAGRAM_PEERS {
            return Err(NetworkError::Capacity);
        }
        let peers: Vec<[u8; 32]> = peer_keys.iter().map(|key| *key.as_bytes()).collect();
        let (carrier, pump) = YggCarrier::attach(bridge, local_key, &peers, HANDSHAKE_TIMEOUT)
            .await
            .map_err(NetworkError::SignalingOperation)?;
        let transport = QuicTransportConfig::builder()
            .application_data_filter(|path| custom_mapped(path.remote()))
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
            .portmapper_config(PortmapperConfig::Disabled)
            .net_report_config(NetReportConfig::minimal())
            .incoming_limits(limits.sessions, 16 * 1024, 512 * 1024)
            .connection_limit(limits.sessions * 2)
            .transport_config(transport)
            .add_custom_transport(carrier.clone());
        let inner = builder
            .bind()
            .await
            .map_err(|error| NetworkError::Bind(Box::new(error)))?;
        if !inner.bound_sockets().is_empty() {
            inner.close().await;
            return Err(NetworkError::InvalidAddress);
        }
        Ok((
            Self {
                inner,
                carrier,
                allowlist,
                slots,
                closed: false,
            },
            pump,
        ))
    }

    pub(crate) fn id(&self) -> PublicKey {
        self.inner.id()
    }

    pub(crate) fn peer_address(&self, peer: &PublicKey) -> Result<CustomAddr, NetworkError> {
        self.carrier
            .peer_address(peer.as_bytes())
            .map_err(NetworkError::SignalingOperation)
    }

    fn admit(&self) -> Result<OwnedSemaphorePermit, NetworkError> {
        if self.closed || self.inner.is_closed() {
            return Err(NetworkError::Closed);
        }
        self.slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| NetworkError::Capacity)
    }

    /// cancel-safe: NO — connection attempts may be completed remotely after cancellation.
    pub(crate) async fn connect(&self, peer: PublicKey) -> Result<Session, NetworkError> {
        if !self.allowlist.contains(&peer) {
            return Err(NetworkError::AccessDenied);
        }
        let address = self.peer_address(&peer)?;
        let source = IncomingAddr::Custom(address.clone());
        let admission = self.admit()?;
        let remote = EndpointAddr::from_parts(peer, [TransportAddr::Custom(address)]);
        let handshake = async {
            let connection = self
                .inner
                .connect(remote, ALPN)
                .await
                .map_err(NetworkError::from_connect)?;
            if connection.remote_id() != peer
                || !self.source_matches(&source, &connection.remote_id())
            {
                connection.close(VarInt::from_u32(2), b"");
                return Err(NetworkError::PeerMismatch);
            }
            super::Endpoint::session(connection, admission)
        };
        tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
            .await
            .map_err(|_| NetworkError::Deadline)?
    }

    /// cancel-safe: NO — a received Initial/handshake may be consumed before cancellation;
    /// it is not replayed.
    pub(crate) async fn accept(&self) -> Result<Session, NetworkError> {
        let incoming = self.inner.accept().await.ok_or(NetworkError::Closed)?;
        let source = incoming.remote_addr();
        let admission = match self.admit() {
            Ok(admission) => admission,
            Err(error) => {
                incoming.refuse();
                return Err(error);
            }
        };
        let connection = tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming)
            .await
            .map_err(|_| NetworkError::Deadline)?
            .map_err(|error| NetworkError::Handshake(Box::new(error)))?;
        let peer = connection.remote_id();
        if !self.allowlist.contains(&peer) {
            connection.close(VarInt::from_u32(ACCESS_DENIED), b"");
            return Err(NetworkError::AccessDenied);
        }
        if !self.source_matches(&source, &peer) {
            connection.close(VarInt::from_u32(2), b"");
            return Err(NetworkError::PeerMismatch);
        }
        super::Endpoint::session(connection, admission)
    }

    fn source_matches(&self, source: &IncomingAddr, peer: &PublicKey) -> bool {
        let IncomingAddr::Custom(address) = source else {
            return false;
        };
        self.carrier.authenticated_peer(address).ok().as_ref() == Some(peer.as_bytes())
    }

    /// cancel-safe: yes — both owners retain shutdown progress across cancellation.
    /// The returned pump must be the pump returned with this endpoint by the same bind.
    /// Keep both owners alive across close cancellation; retries resume in each owner.
    pub(crate) async fn close(&mut self, pump: &mut YggPump) -> Result<(), NetworkError> {
        self.closed = true;
        self.slots.close();
        self.inner.close().await;
        pump.close().await.map_err(NetworkError::SignalingOperation)
    }
}

fn custom_mapped(address: std::net::SocketAddr) -> bool {
    match address.ip() {
        IpAddr::V6(ip) => ip.octets()[..8] == [0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, 0, 3],
        IpAddr::V4(_) => false,
    }
}

mod fallback;
#[cfg(test)]
mod standby_tests;
#[cfg(test)]
pub(in crate::network) use standby_tests::block::NativeGate;
#[cfg(test)]
mod tests;
