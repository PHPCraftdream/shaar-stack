//! The leaf L4 punch responder: answers authenticated punch offers from
//! allowlisted peers over the retained Yggdrasil bridge and runs the bounded,
//! rate-limited probe bursts itself (Finding 1): bursts live inside the
//! responder task, capped by [`punch::BURST_CONCURRENCY_CAP`] and rate-limited
//! per peer by [`punch::BURST_MIN_INTERVAL`], so the accept loop never runs
//! one. Present only for relay-less compositions; with relay fields the
//! server behavior is unchanged.

use std::net::SocketAddr;
use std::pin::Pin;

use futures::{StreamExt, future::select_all, stream::FuturesUnordered};
use iroh_base::PublicKey;
use tokio::sync::mpsc;

use crate::network::signaling::punch::{
    self, Kind, OfferBatch, PunchChannel, PunchLink, PunchMessage, SendError,
};
use crate::startup::role::server::ServerParts;

/// Bounded batch backlog; a full channel skips the batch, never queues
/// without bound.
const BATCH_CHANNEL_CAPACITY: usize = 4;

/// Injected candidates per server native port, so concurrent role tests never share a seam.
#[cfg(test)]
static PUNCH_CANDIDATES_FOR_TESTS: std::sync::Mutex<Vec<(u16, Vec<SocketAddr>)>> =
    std::sync::Mutex::new(Vec::new());

/// Test seam: injects the externally mapped candidates an Answer should
/// carry for the server bound to `port`; the exchange and probes stay production code.
#[cfg(test)]
pub(crate) fn set_punch_candidates_for_tests(port: u16, candidates: Vec<SocketAddr>) {
    let mut seams = PUNCH_CANDIDATES_FOR_TESTS
        .lock()
        .expect("punch test candidates lock");
    seams.retain(|(bound, _)| *bound != port);
    seams.push((port, candidates));
}

#[cfg(test)]
fn punch_candidates_for_tests(port: u16) -> Option<Vec<SocketAddr>> {
    PUNCH_CANDIDATES_FOR_TESTS
        .lock()
        .expect("punch test candidates lock")
        .iter()
        .find(|(bound, _)| *bound == port)
        .map(|(_, candidates)| candidates.clone())
}

/// Builds the per-call candidate provider for the spawned responder.
pub(super) fn candidate_provider(
    local: SocketAddr,
    resources: crate::startup::resources::SharedResources,
) -> impl Fn() -> Vec<SocketAddr> + Clone + Send + 'static {
    move || {
        #[cfg(test)]
        if let Some(candidates) = punch_candidates_for_tests(local.port()) {
            return candidates;
        }
        punch::answer_candidates(
            local,
            resources.punch_address(),
            resources.punch_rewritten_port(),
        )
    }
}

/// Spawns the punch responder when the composition is relay-less but
/// retained a Yggdrasil bridge; otherwise a no-op (server behavior with
/// relay fields present is byte-identical to before leaf L4).
pub(in crate::startup::role) fn spawn_responder(
    parts: &mut ServerParts,
    allowlist: &crate::network::Allowlist,
) {
    // No bridge: nothing to answer offers over.
    let Some(bridge) = parts.resources.ygg_bridge() else {
        return;
    };
    let peers: Vec<[u8; 32]> = allowlist.keys().map(|key| *key.as_bytes()).collect();
    // Empty allowlist: no authenticated peer can ever offer.
    if peers.is_empty() {
        return;
    }
    let local = parts
        .endpoint
        .as_ref()
        .expect("server holds the native endpoint while live")
        .local_addr();
    let provider = candidate_provider(local, parts.resources.clone());
    // Slotless probe capability (Finding 3): a cloneable handle over the same
    // native socket — no admission slot, no allowlist, no `Session` built;
    // the accept loop keeps exclusive `&mut` ownership of the endpoint.
    let probes = parts
        .endpoint
        .as_ref()
        .expect("server holds the native endpoint while live")
        .probe_handle();
    let task = tokio::spawn(async move {
        // One bounded channel open per allowlisted peer; a failed open
        // silently disables that peer's punching.
        let mut channels = Vec::with_capacity(peers.len());
        let mut failed = 0usize;
        for peer in peers {
            match PunchChannel::open(&bridge, peer).await {
                Ok(channel) => channels.push((peer, channel)),
                Err(_) => failed += 1,
            }
        }
        if failed > 0 {
            eprintln!("shaar: punch registration unavailable");
        }
        drive_links(channels, provider, probes).await;
    });
    parts.punch_task = Some(task);
}

/// Drives one punch worker per link together with the burst loop: the future ends when EVERY
/// worker has ended AND the burst loop has ended. Shared by the Yggdrasil and the carrier
/// responders, which differ only in the links they hand over.
pub(super) async fn drive_links<L, P>(
    channels: Vec<([u8; 32], L)>,
    provider: P,
    probes: crate::network::ProbeHandle,
) where
    L: PunchLink + Send + 'static,
    P: Fn() -> Vec<SocketAddr> + Clone + Send + 'static,
{
    let (batches, batch_rx) = mpsc::channel::<OfferBatch>(BATCH_CHANNEL_CAPACITY);
    // Production burst: runs the sequential probe burst through the
    // cloned probe handle (cloning keeps the socket alive; the responder
    // is aborted and joined before the composition closes the endpoint).
    let burst = move |batch: OfferBatch| {
        let probes = probes.clone();
        async move {
            let Ok(peer) = PublicKey::from_bytes(&batch.peer) else {
                return;
            };
            punch::probe_burst(&probes, peer, &batch.candidates, batch.burst, "server").await;
        }
    };
    // One owned worker per channel, driven concurrently together with the
    // burst loop; the task ends when EVERY worker has ended AND the burst
    // loop has ended (the burst loop ends once every worker dropped its
    // batch sender).
    let mut items: Vec<Pin<Box<dyn std::future::Future<Output = ()> + Send>>> = channels
        .into_iter()
        .map(|(peer, channel)| {
            let provider = provider.clone();
            Box::pin(serve_peer(peer, provider, batches.clone(), channel))
                as Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        })
        .collect();
    items.push(Box::pin(run_batches(batch_rx, burst)));
    loop {
        if items.len() == 1 {
            // Only the burst loop remains: every worker ended, so drop
            // the last batch sender; the loop drains the channel and
            // ends (channel end also drops in-flight bursts).
            drop(batches);
            items.pop().expect("burst loop present").await;
            return;
        }
        let (_, _, rest) = select_all(items).await;
        items = rest;
    }
}

/// Serves one peer channel: decodes offers, answers with the provider's
/// candidates, and forwards at most one batch per peer per
/// [`punch::BURST_MIN_INTERVAL`] (Finding 1a). Offer candidates are
/// probe-gated (`peer_claimed_probe_allowed`, Finding 2) before the batch
/// decision; the Answer still carries the provider's own candidates
/// regardless of what the peer offered. Offers INSIDE the interval are
/// STILL ANSWERED — only the burst handover is suppressed. Malformed or
/// hostile input is silently discarded; a closed link ends the worker (peer
/// punching disabled), while a refused Answer is left to the peer's next Offer
/// copy.
async fn serve_peer<L, P>(
    peer: [u8; 32],
    provider: P,
    batches: mpsc::Sender<OfferBatch>,
    mut channel: L,
) where
    L: PunchLink + Send,
    P: Fn() -> Vec<SocketAddr> + Send,
{
    let mut last_epoch: Option<u32> = None;
    // Per-peer burst rate limit (Finding 1a), on the tokio (pausable)
    // monotonic clock.
    let mut last_batch: Option<tokio::time::Instant> = None;
    // Bursts handed over for this peer: each one walks the next slice of the peer's port set.
    let mut bursts: u32 = 0;
    loop {
        let Some(raw) = channel.recv_raw().await else {
            // Link died: this peer's punching is disabled.
            return;
        };
        // Malformed, hostile or Answer-kind datagrams: silently discarded.
        let Some(offer) = punch::decode(&raw) else {
            continue;
        };
        if offer.kind != Kind::Offer {
            continue;
        }
        let candidates = provider();
        // Nothing to answer: skip without touching the epoch state.
        if candidates.is_empty() {
            punch::trace_offer(offer.candidates.len(), "none");
            continue;
        }
        punch::trace_ports("server", &candidates, &offer.candidates);
        let answer = PunchMessage {
            kind: Kind::Answer,
            epoch: offer.epoch,
            candidates: candidates.clone(),
        };
        // Probe-gate the peer-claimed candidates (Finding 2); the Answer
        // always carries the provider's own candidates unfiltered.
        let batch_candidates: Vec<SocketAddr> = offer
            .candidates
            .iter()
            .copied()
            .filter(|candidate| punch::peer_claimed_probe_allowed(*candidate))
            .collect();
        match channel.send(&answer, punch::EXCHANGE_BUDGET).await {
            Ok(()) => punch::trace_offer(offer.candidates.len(), "sent"),
            // Transient: epoch and burst state stay untouched for the retry.
            Err(SendError::Refused) => {
                punch::trace_offer(offer.candidates.len(), "refused");
                continue;
            }
            Err(SendError::Closed) => return,
        }
        // One burst per peer per `punch::BURST_MIN_INTERVAL`; a full channel
        // skips the batch. Special-range offers start no batch (nothing safe
        // to probe), but they still reset the epoch tracking via the guard
        // above.
        if last_epoch != Some(offer.epoch)
            && !batch_candidates.is_empty()
            && last_batch.is_none_or(|started| started.elapsed() >= punch::BURST_MIN_INTERVAL)
        {
            // Stamp BEFORE the handover: at most one burst per interval per
            // peer, even when the channel is full and the batch is skipped.
            last_batch = Some(tokio::time::Instant::now());
            last_epoch = Some(offer.epoch);
            bursts = bursts.saturating_add(1);
            let _ = batches.try_send(OfferBatch {
                peer,
                candidates: batch_candidates,
                burst: bursts,
            });
        } else if last_epoch != Some(offer.epoch) {
            // Suppressed burst: still track the epoch so retries of the same
            // epoch stay suppressed.
            last_epoch = Some(offer.epoch);
        }
    }
}

/// Consumes bounded probe batches and runs at most
/// [`punch::BURST_CONCURRENCY_CAP`] bursts concurrently (Finding 1c). The
/// receiver end lives inside the responder task, so the accept loop never
/// runs a burst; the recv-arm select guard gives backpressure (at cap, only
/// completions are reaped). When the channel ends (every worker dropped its
/// sender) the loop breaks and the `FuturesUnordered` is DROPPED: dropping
/// cancels in-flight burst futures, which is safe because production bursts
/// are self-bounded by the per-candidate `punch::PROBE_SLICE` slices anyway
/// and close aborts the whole responder task with a bounded join (Finding
/// 1c).
async fn run_batches<F, Fut>(mut batches: mpsc::Receiver<OfferBatch>, burst: F)
where
    F: Fn(OfferBatch) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let mut running: FuturesUnordered<Pin<Box<dyn std::future::Future<Output = ()> + Send>>> =
        FuturesUnordered::new();
    loop {
        tokio::select! {
            batch = batches.recv(), if running.len() < punch::BURST_CONCURRENCY_CAP => {
                match batch {
                    Some(batch) => running.push(Box::pin(burst(batch))),
                    None => break,
                }
            }
            _ = running.next(), if !running.is_empty() => {}
        }
    }
}

#[cfg(test)]
#[path = "punch_tests.rs"]
mod tests;
