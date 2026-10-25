use std::{fmt, net::SocketAddr};

use iroh_base::PublicKey;
use shaar_p2p::{RelayAddr, RelayLease};
use tokio::sync::watch;

use crate::{
    identity::Identity,
    network::{Allowlist, Endpoint, Limits, NetworkError, Session},
};

use super::{check_peers, owner::Owned, peer_id};

#[cfg(test)]
#[path = "owned_tests.rs"]
mod tests;

/// Native QUIC endpoint with one retained signaling coordinator and shared identity.
/// Explicit close joins both backends. Drop/cancel is abort-only, not a joined shutdown promise.
pub struct SignaledEndpoint {
    endpoint: Endpoint,
    signaling: Owned,
    signaling_address: SocketAddr,
}

impl fmt::Debug for SignaledEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignaledEndpoint(..)")
    }
}

impl SignaledEndpoint {
    /// Binds native UDP plus signaling TCP, with at most 16 configured peer keys before deduplication.
    /// One coordinator task is retained and joined, never hidden behind submission handles.
    /// cancel-safe: NO — dropping startup aborts ownership but does not await native destruction.
    pub async fn bind(
        identity: &Identity,
        native: SocketAddr,
        signaling: SocketAddr,
        peers: &[PublicKey],
        limits: Limits,
    ) -> Result<Self, NetworkError> {
        Endpoint::validate_bind(native)?;
        check_peers(peers)?;
        let allowlist = Allowlist::new(peers)?;
        let owner = Owned::start(identity, signaling, peers)?;
        let signaling_address = match owner.ready().await {
            Ok(address) => address,
            Err(error) => {
                owner.close().await?;
                return Err(error);
            }
        };
        let endpoint = match Endpoint::bind_custom(
            identity,
            native,
            allowlist,
            limits,
            Some(owner.factory.clone()),
        )
        .await
        {
            Ok(endpoint) => endpoint,
            Err(error) => {
                owner.close().await?;
                return Err(error);
            }
        };
        Ok(Self {
            endpoint,
            signaling: owner,
            signaling_address,
        })
    }

    pub fn id(&self) -> PublicKey {
        self.endpoint.id()
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.endpoint.local_addr()
    }
    pub fn signaling_addr(&self) -> SocketAddr {
        self.signaling_address
    }

    /// cancel-safe: NO — abandoned handshakes release SDK slots, not protocol drain metadata.
    pub async fn connect(
        &self,
        peer: PublicKey,
        native: SocketAddr,
    ) -> Result<Session, NetworkError> {
        self.endpoint.connect(peer, native).await
    }

    /// Negotiates through a pinned direct signaling peer; APP still requires a native QUIC path.
    /// cancel-safe: NO — carrier and QUIC handshakes may complete after waiter cancellation.
    pub async fn connect_signaling(
        &self,
        peer: PublicKey,
        address: SocketAddr,
    ) -> Result<Session, NetworkError> {
        let remote = peer_id(&peer).map_err(NetworkError::SignalingOperation)?;
        self.signaling
            .handle
            .connect(remote, address)
            .await
            .map_err(NetworkError::SignalingOperation)?;
        let address = self
            .signaling
            .factory
            .peer_address(remote)
            .map_err(NetworkError::SignalingOperation)?;
        self.endpoint.connect_custom(peer, address).await
    }

    /// Negotiates via the pinned relay; this never grants application-data fallback on a circuit.
    /// cancel-safe: NO — admitted circuit/QUIC work is not undone by dropping the waiter.
    pub async fn connect_via(
        &self,
        peer: PublicKey,
        relay: RelayAddr,
    ) -> Result<Session, NetworkError> {
        let remote = peer_id(&peer).map_err(NetworkError::SignalingOperation)?;
        self.signaling
            .handle
            .connect_via(remote, relay)
            .await
            .map_err(NetworkError::SignalingOperation)?;
        let address = self
            .signaling
            .factory
            .peer_address(remote)
            .map_err(NetworkError::SignalingOperation)?;
        self.endpoint.connect_custom(peer, address).await
    }

    /// cancel-safe: NO — an admitted reservation may briefly exist before cancellation cleanup.
    pub async fn reserve_relay(&self, relay: RelayAddr) -> Result<RelayLease, NetworkError> {
        self.signaling
            .handle
            .reserve(relay)
            .await
            .map_err(NetworkError::SignalingOperation)
    }

    pub fn relay_leases(&self) -> watch::Receiver<Vec<RelayLease>> {
        self.signaling.handle.relay_leases()
    }

    /// cancel-safe: NO — cancellation cannot undo an admitted release.
    pub async fn release_relay(&self, relay: RelayAddr) -> Result<(), NetworkError> {
        self.signaling
            .handle
            .release_relay(relay.peer_id())
            .await
            .map_err(NetworkError::SignalingOperation)
    }

    /// Checks allowlist and authenticated custom-source/TLS-key correspondence before Session creation.
    /// cancel-safe: NO — a consumed incoming handshake is not replayed.
    pub async fn accept(&mut self) -> Result<Session, NetworkError> {
        self.endpoint.accept().await
    }

    /// Keeps signaling available during QUIC drain, then stops and joins carrier plus pump.
    /// Retained Session/factory/sender handles do not own the native sockets.
    /// cancel-safe: NO — only successful return proves both joined shutdown barriers.
    pub async fn close(self) -> Result<(), NetworkError> {
        let Self {
            endpoint,
            signaling,
            ..
        } = self;
        endpoint.close().await;
        signaling.close().await
    }
}
