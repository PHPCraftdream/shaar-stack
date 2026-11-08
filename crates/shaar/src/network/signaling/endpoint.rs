use std::{fmt, net::SocketAddr};

use iroh_base::PublicKey;
use shaar_p2p::{RelayAddr, RelayLease};
use tokio::sync::watch;

use crate::{
    identity::Identity,
    network::{Allowlist, Endpoint, Limits, NetworkError, Session},
};

use super::{DiscoveredRelay, DiscoveryConfig, check_peers, owner::Owned, peer_id};

#[cfg(test)]
#[path = "discovery_tests.rs"]
mod discovery_tests;
#[cfg(test)]
#[path = "owned_tests.rs"]
mod tests;

#[cfg(test)]
pub(crate) use tests::relay_fixture::RelayFixture;

/// Native QUIC endpoint with one retained signaling coordinator and shared identity.
/// Explicit close joins both backends. Drop/cancel is abort-only.
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

/// Cloneable signaling command capability that owns no sockets.
#[derive(Clone)]
pub(crate) struct RelayOperations {
    handle: super::CarrierHandle,
}

impl RelayOperations {
    pub(crate) async fn reserve(&self, relay: RelayAddr) -> Result<RelayLease, NetworkError> {
        self.handle
            .reserve(relay)
            .await
            .map_err(NetworkError::SignalingOperation)
    }

    pub(crate) fn has_reservation(&self, relay: RelayAddr) -> bool {
        self.handle
            .relay_leases()
            .borrow()
            .iter()
            .any(|lease| lease.relay() == relay)
    }

    pub(crate) async fn release(&self, relay: RelayAddr) -> Result<(), NetworkError> {
        self.handle
            .release_relay(relay.peer_id())
            .await
            .map_err(NetworkError::SignalingOperation)
    }
}

impl SignaledEndpoint {
    /// Binds native UDP plus signaling TCP and retains their joined owner.
    /// cancel-safe: NO — cancellation does not prove joined destruction.
    pub async fn bind(
        identity: &Identity,
        native: SocketAddr,
        signaling: SocketAddr,
        peers: &[PublicKey],
        limits: Limits,
    ) -> Result<Self, NetworkError> {
        Self::bind_configured(identity, native, signaling, peers, limits, None).await
    }

    /// Starts with validated in-memory discovery settings.
    /// cancel-safe: NO — cancellation does not prove joined destruction.
    pub async fn bind_with_discovery(
        identity: &Identity,
        native: SocketAddr,
        signaling: SocketAddr,
        peers: &[PublicKey],
        limits: Limits,
        discovery: DiscoveryConfig,
    ) -> Result<Self, NetworkError> {
        Self::bind_configured(identity, native, signaling, peers, limits, Some(discovery)).await
    }

    /// cancel-safe: NO — cancellation does not prove completed backend startup.
    async fn bind_configured(
        identity: &Identity,
        native: SocketAddr,
        signaling: SocketAddr,
        peers: &[PublicKey],
        limits: Limits,
        discovery: Option<DiscoveryConfig>,
    ) -> Result<Self, NetworkError> {
        Endpoint::validate_bind(native)?;
        check_peers(peers)?;
        let allowlist = Allowlist::new(peers)?;
        let owner = Owned::start(identity, signaling, peers, discovery)?;
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

    pub async fn discover_relays(&self) -> Result<Vec<DiscoveredRelay>, NetworkError> {
        self.signaling
            .handle
            .discover_relays()
            .await
            .map_err(NetworkError::SignalingOperation)
    }

    pub async fn reserve_discovered_relay(
        &self,
        candidate: DiscoveredRelay,
    ) -> Result<RelayLease, NetworkError> {
        self.signaling
            .handle
            .reserve_discovered_relay(candidate)
            .await
            .map_err(NetworkError::SignalingOperation)
    }

    pub fn id(&self) -> PublicKey {
        self.endpoint.id()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.endpoint.local_addr()
    }

    pub(crate) fn native_addr_watcher(
        &self,
    ) -> impl iroh::Watcher<Value = iroh::EndpointAddr> + use<> {
        self.endpoint.native_addr_watcher()
    }

    pub(crate) fn relay_operations(&self) -> RelayOperations {
        RelayOperations {
            handle: self.signaling.handle.clone(),
        }
    }

    pub fn signaling_addr(&self) -> SocketAddr {
        self.signaling_address
    }

    pub async fn connect(
        &self,
        peer: PublicKey,
        native: SocketAddr,
    ) -> Result<Session, NetworkError> {
        self.endpoint.connect(peer, native).await
    }

    /// Negotiates through direct signaling; payload remains native QUIC.
    /// cancel-safe: NO — handshakes may complete after waiter cancellation.
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

    /// Negotiates via the pinned relay without enabling circuit payload fallback.
    /// cancel-safe: NO — admitted circuit work may continue after cancellation.
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

    /// cancel-safe: NO — admitted reservation is reconciled by the carrier.
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

    /// cancel-safe: NO — cancellation does not undo an admitted release.
    pub async fn release_relay(&self, relay: RelayAddr) -> Result<(), NetworkError> {
        self.signaling
            .handle
            .release_relay(relay.peer_id())
            .await
            .map_err(NetworkError::SignalingOperation)
    }

    pub async fn accept(&mut self) -> Result<Session, NetworkError> {
        self.endpoint.accept().await
    }

    /// Keeps signaling alive during QUIC drain, then joins carrier and pump.
    /// cancel-safe: NO — only successful return proves both shutdown barriers.
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
