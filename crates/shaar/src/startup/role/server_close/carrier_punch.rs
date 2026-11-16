//! The leaf L4b punch responder over the libp2p carrier: a Server with a pinned relay answers
//! authenticated punch offers that arrive on the carrier link's side channel, through the same
//! rate-limited workers and probe bursts as the Yggdrasil responder. The relay carries signaling
//! only; the probes and the session stay direct QUIC.

use libp2p_identity::PeerId;

use super::punch::{candidate_provider, drive_links};
use crate::network::signaling::{peer_id, punch};
use crate::startup::role::server::ServerParts;

/// Spawns the carrier responder when the composition pins a relay; a no-op without an
/// allowlisted peer or when the port was already taken. Joined by the same abort-and-join close
/// as the Yggdrasil responder.
pub(in crate::startup::role) fn spawn_carrier_responder(
    parts: &mut ServerParts,
    allowlist: &crate::network::Allowlist,
) {
    let Some(endpoint) = parts.endpoint.as_ref() else {
        return;
    };
    let peers: Vec<([u8; 32], PeerId)> = allowlist
        .keys()
        .filter_map(|key| Some((*key.as_bytes(), peer_id(&key).ok()?)))
        .collect();
    // Empty allowlist: no authenticated peer can ever offer.
    if peers.is_empty() {
        return;
    }
    let Some(port) = endpoint.punch_port() else {
        return;
    };
    let provider = candidate_provider(endpoint.local_addr(), parts.resources.clone());
    let probes = endpoint.probe_handle();
    let (links, router) = punch::route(port, &peers);
    parts.punch_task = Some(tokio::spawn(async move {
        // The router ends with the transport; the workers end once every link closed.
        tokio::select! {
            () = router => {}
            () = drive_links(links, provider, probes) => {}
        }
    }));
}
