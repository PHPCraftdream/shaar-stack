//! Composed-startup preflight: pure validation before any network I/O.
//!
//! Requires the shared network object (no silent direct-only fallback),
//! bounds the raw application-peer input like signaling admission, and
//! rejects identity-role conflicts by exact PeerId-bytes equality — no
//! prefix or address heuristics. For the client role the configured service
//! key is part of the role boundary, independent of the caller-supplied
//! peer slice. The plan carries validated borrows only; resource
//! composition belongs to later leaves.

use iroh_base::PublicKey;
use libp2p_identity::PeerId;

use crate::config::{ClientConfig, Fallback, NetworkSettings, ServerConfig};
use crate::identity::Identity;

use super::StartupError;

/// Matches the signaling admission bound (`crate::network::signaling::check_peers`).
pub const MAX_STARTUP_APP_PEERS: usize = 16;

/// Validated composed-startup inputs; borrows the caller's data.
#[derive(Debug)]
pub(crate) struct ComposedStartupPlan<'a> {
    network: &'a NetworkSettings,
    app_peers: &'a [PublicKey],
    /// Configured fallback transport selection, captured verbatim from the
    /// role config; decides whether the Yggdrasil payload endpoint is built
    /// (`Standby`) or the bridge stays control-only (`Signal`).
    mode: Fallback,
}

impl ComposedStartupPlan<'_> {
    /// Validated shared infrastructure settings.
    pub(crate) fn network(&self) -> &NetworkSettings {
        self.network
    }

    /// Raw application peers in input order; duplicates included.
    pub(crate) fn app_peers(&self) -> &[PublicKey] {
        self.app_peers
    }

    /// The configured fallback transport selection.
    pub(crate) fn fallback(&self) -> Fallback {
        self.mode
    }
}

/// Preflight for the composed server role (no configured remote service key).
pub(crate) fn preflight_server<'a>(
    config: &'a ServerConfig,
    identity: &Identity,
    app_peers: &'a [PublicKey],
) -> Result<ComposedStartupPlan<'a>, StartupError> {
    preflight_shared(
        config.network(),
        &[],
        config.fallback(),
        identity,
        app_peers,
    )
}

/// Preflight for the composed client role; the pinned server key is a
/// configured service identity even when the peer slice omits it.
pub(crate) fn preflight_client<'a>(
    config: &'a ClientConfig,
    identity: &Identity,
    app_peers: &'a [PublicKey],
) -> Result<ComposedStartupPlan<'a>, StartupError> {
    // The configured key already passed Ed25519 point decompression at config
    // parse (client.rs FromStr path), so this rebuild cannot fail.
    let service_key = PublicKey::from_bytes(config.server_key_bytes())
        .expect("configured service key is a valid Ed25519 public key");
    preflight_shared(
        config.network(),
        &[service_key],
        config.fallback(),
        identity,
        app_peers,
    )
}

fn preflight_shared<'a>(
    network: Option<&'a NetworkSettings>,
    service_keys: &[PublicKey],
    mode: Fallback,
    identity: &Identity,
    app_peers: &'a [PublicKey],
) -> Result<ComposedStartupPlan<'a>, StartupError> {
    let network = network.ok_or(StartupError::NetworkRequired)?;
    // Raw-entry bound before any identity work; duplicates are counted so
    // deduplication can never evade the cap (dedup happens later, inside
    // signaling admission).
    if app_peers.len() > MAX_STARTUP_APP_PEERS {
        return Err(StartupError::TooManyAppPeers {
            count: app_peers.len(),
        });
    }
    let signaling = network.signaling().ok_or(StartupError::NetworkRequired)?;
    let relay_peer_id = *signaling.relay_peer_id();
    let local_peer_id = PeerId::from_bytes(&identity.peer_id_bytes())
        .expect("local identity multihash is a valid PeerId");
    // A node cannot pin itself as its own relay, and it cannot pin itself
    // as its own service either.
    if relay_peer_id == local_peer_id {
        return Err(StartupError::IdentityConflict { role: "relay" });
    }
    for key in service_keys {
        if peer_id_of(key) == relay_peer_id {
            return Err(StartupError::IdentityConflict { role: "relay" });
        }
        if peer_id_of(key) == local_peer_id {
            return Err(StartupError::IdentityConflict { role: "service" });
        }
    }
    // Exact role boundary: an application peer is never the local identity
    // and never pinned infrastructure; the configured service key IS a
    // legitimate application peer.
    for key in app_peers {
        let peer = peer_id_of(key);
        if peer == local_peer_id || peer == relay_peer_id {
            return Err(StartupError::IdentityConflict {
                role: "application",
            });
        }
    }
    Ok(ComposedStartupPlan {
        network,
        app_peers,
        mode,
    })
}

/// The helper only fails on non-Ed25519 keys, which the typed
/// `iroh_base::PublicKey` structurally excludes.
fn peer_id_of(key: &PublicKey) -> PeerId {
    crate::network::signaling::peer_id(key).expect("Ed25519 public keys always derive a PeerId")
}
