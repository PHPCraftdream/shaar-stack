//! Watching the configured links of a started node (leaf YGG-4a).

use std::sync::Arc;

use yggdrasil::core::Core;

use crate::phases::{LinksUp, Phases};

/// A read-only view of the links of one node. It keeps the core alive while it exists, so drop it
/// before the transport is closed and dropped.
pub struct LinkWatch {
    core: Arc<Core>,
    peers: Arc<[String]>,
    phases: Arc<Phases>,
}

impl LinkWatch {
    pub(super) fn new(core: Arc<Core>, peers: Arc<[String]>, phases: Arc<Phases>) -> Self {
        Self {
            core,
            peers,
            phases,
        }
    }

    /// The configured links that are up now. An inbound link is not a configured one.
    pub async fn up(&self) -> LinksUp {
        let mut up = LinksUp::default();
        for info in self.core.get_peers().await {
            if !info.up || info.inbound {
                continue;
            }
            if let Some(index) = self.peers.iter().position(|uri| *uri == info.uri) {
                up.set(index);
            }
        }
        up
    }

    /// Resolves with the set of links that are up as soon as it differs from `seen`. Cancel-safe:
    /// it keeps no state across a cancelled poll, and the next call takes a fresh snapshot.
    pub async fn next(&self, seen: LinksUp) -> LinksUp {
        loop {
            // Subscribe before the snapshot: a change after it wakes the receiver below.
            let mut events = self.core.subscribe_peer_events();
            let now = self.up().await;
            if now != seen {
                return now;
            }
            // Any event, a lagged receiver included, only asks for a fresh snapshot. The sender
            // lives in the core this watch holds, so the receiver is never closed.
            let _ = events.recv().await;
        }
    }

    /// Prints one line per change of the configured links until the share of the line budget
    /// that belongs to the links is spent. Cancel-safe.
    pub async fn trace(&self) {
        let mut seen = LinksUp::default();
        while !self.phases.links_exhausted() {
            let now = self.next(seen).await;
            self.phases.report(seen, now);
            seen = now;
        }
    }
}
