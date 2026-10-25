mod endpoint;
mod owner;
pub use endpoint::SignaledEndpoint;

use std::{io, net::SocketAddr};

use iroh_base::PublicKey;
use libp2p_identity::{PeerId, PublicKey as SignalingKey, ed25519};
use shaar_p2p::{Carrier, CarrierHandle, Received};
use tokio::sync::mpsc;

use crate::identity::Identity;

use super::NetworkError;

/// Constructs a caller-driven signaling carrier using the same identity as native QUIC.
/// Accepts at most 16 public-key entries, before deduplication, and requires a Tokio runtime.
/// No root task is spawned. The caller must drive and await `Carrier::run` for joined cleanup.
/// This does not install an Iroh custom transport or make Endpoint::close own this carrier.
pub fn bind_signaling(
    identity: &Identity,
    address: SocketAddr,
    peers: &[PublicKey],
) -> Result<(Carrier, CarrierHandle, mpsc::Receiver<Received>), NetworkError> {
    check_peers(peers)?;
    let peers = peers
        .iter()
        .map(peer_id)
        .collect::<io::Result<Vec<_>>>()
        .map_err(NetworkError::Signaling)?;
    let key = identity.signaling_key().map_err(NetworkError::Signaling)?;
    Carrier::bind(key, address, peers).map_err(NetworkError::Signaling)
}

fn check_peers(peers: &[PublicKey]) -> Result<(), NetworkError> {
    if peers.len() > 16 {
        return Err(NetworkError::Signaling(io::Error::new(
            io::ErrorKind::WouldBlock,
            "signaling allowlist exceeds 16 entries",
        )));
    }
    Ok(())
}

pub(super) fn peer_id(key: &PublicKey) -> io::Result<PeerId> {
    let key = ed25519::PublicKey::try_from_bytes(key.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid signaling peer key"))?;
    Ok(SignalingKey::from(key).to_peer_id())
}

#[cfg(test)]
mod tests;
