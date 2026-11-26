// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

//! Best-effort mirror of the Server's signed record to public pkarr relays (leaf PKARR-1).
//!
//! A relay verifies the packet and does the BEP 44 put from a well-connected host, which is what
//! a lossy phone socket lacks. The mirror is independent of the DHT publication: the publisher
//! only hands over the bytes it already holds (`offer`, never blocks), and no answer of a relay
//! sets any state of the publisher. One task per relay, one request in flight per relay, only the
//! latest packet is kept.

mod client;
#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::Duration;

use iroh_base::EndpointId;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;

pub(crate) use self::client::RelayUrl;
use self::client::{Class, RelayClient, http_client};
use crate::network::observe::emit;

/// Bytes of the public key at the head of a signed packet; a relay takes the packet without them.
const KEY_BYTES: usize = 32;
/// Largest signed packet: key, signature, timestamp and at most 1000 bytes of DNS.
const MAX_PACKET_BYTES: usize = 1104;
/// Most relays one mirror serves; the surplus of a longer list is ignored.
pub(crate) const MAX_RELAYS: usize = 4;

/// The two bounds of the mirror. A refresh is sent at most once per `interval` per relay (a
/// replacement at once), so a relay's copy is never much older than the freshness of the record;
/// `request_bound` caps one request, connect included.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MirrorTiming {
    pub(crate) interval: Duration,
    pub(crate) request_bound: Duration,
}

impl MirrorTiming {
    pub(crate) const PRODUCT: Self = Self {
        interval: Duration::from_secs(120),
        request_bound: Duration::from_secs(10),
    };
}

/// What a mirror is started with: the relays (empty means no mirror) and the two bounds.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MirrorSpec<'a> {
    pub(crate) relays: &'a [RelayUrl],
    pub(crate) timing: MirrorTiming,
}

impl MirrorSpec<'_> {
    pub(crate) const NONE: MirrorSpec<'static> = MirrorSpec {
        relays: &[],
        timing: MirrorTiming::PRODUCT,
    };
}

#[derive(Clone)]
struct Offer {
    packet: Arc<[u8]>,
    initial: bool,
}

pub(in crate::native_discovery::runtime) struct RelayMirror {
    offers: watch::Sender<Option<Offer>>,
    tasks: Vec<JoinHandle<()>>,
}

impl RelayMirror {
    /// `None` when there is no relay or no client could be built: nothing is spawned.
    pub(in crate::native_discovery::runtime) fn start(
        key: EndpointId,
        spec: MirrorSpec<'_>,
    ) -> Option<Self> {
        let MirrorSpec { relays, timing } = spec;
        if relays.is_empty() {
            return None;
        }
        let Some(http) = http_client(timing.request_bound) else {
            emit("shaar-server: pkarr relay mirror off reason=client".to_owned());
            return None;
        };
        let (offers, receiver) = watch::channel(None);
        let tasks = relays
            .iter()
            .take(MAX_RELAYS)
            .enumerate()
            .map(|(index, relay)| {
                tokio::spawn(relay_task(
                    index,
                    RelayClient::new(http.clone(), relay, key),
                    receiver.clone(),
                    timing.interval,
                ))
            })
            .collect();
        Some(Self { offers, tasks })
    }

    /// Hands over a signed packet (with its key); `initial` marks a publication of new content,
    /// which is sent at once, against a refresh of the same content, which waits for the
    /// interval. Never blocks and never fails: a malformed size is ignored.
    pub(in crate::native_discovery::runtime) fn offer(&self, packet: &[u8], initial: bool) {
        if packet.len() <= KEY_BYTES || packet.len() > MAX_PACKET_BYTES {
            return;
        }
        self.offers.send_replace(Some(Offer {
            packet: Arc::from(packet),
            initial,
        }));
    }
}

impl std::fmt::Debug for RelayMirror {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayMirror")
            .field("relays", &self.tasks.len())
            .finish_non_exhaustive()
    }
}

impl Drop for RelayMirror {
    /// Closing the owner ends the mirror: an in-flight request is dropped with its task.
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// The payload-free trace line of one answer: the relay's position in the list, the class, the
/// stored-nodes count when the relay named one, and the time.
fn trace_line(index: usize, class: Class, elapsed: Duration) -> String {
    let stored = class
        .stored_nodes()
        .map_or_else(|| "?".to_owned(), |count| count.to_string());
    format!(
        "shaar-server: pkarr relay={index} result={} stored={stored} elapsed_ms={}",
        class.token(),
        elapsed.as_millis()
    )
}

async fn relay_task(
    index: usize,
    client: RelayClient,
    mut offers: watch::Receiver<Option<Offer>>,
    interval: Duration,
) {
    let mut last_sent: Option<Instant> = None;
    let mut paused_until: Option<Instant> = None;
    while offers.changed().await.is_ok() {
        let Some(offer) = offers.borrow_and_update().clone() else {
            continue;
        };
        let now = Instant::now();
        let waiting = paused_until.is_some_and(|until| now < until)
            || (!offer.initial
                && last_sent.is_some_and(|sent| now.duration_since(sent) < interval));
        if waiting {
            continue;
        }
        last_sent = Some(now);
        let class = client.put(&offer.packet[KEY_BYTES..]).await;
        emit(trace_line(index, class, now.elapsed()));
        if class == Class::RateLimited {
            paused_until = Some(Instant::now() + interval);
        }
    }
}
