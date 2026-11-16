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

#[cfg(test)]
static PUNCH_CANDIDATES_FOR_TESTS: std::sync::Mutex<Option<Vec<SocketAddr>>> =
    std::sync::Mutex::new(None);

/// Test seam: injects the externally mapped candidates an Answer should
/// carry; the exchange and probes stay production code.
#[cfg(test)]
pub(crate) fn set_punch_candidates_for_tests(candidates: Vec<SocketAddr>) {
    *PUNCH_CANDIDATES_FOR_TESTS
        .lock()
        .expect("punch test candidates lock") = Some(candidates);
}

#[cfg(test)]
fn punch_candidates_for_tests() -> Option<Vec<SocketAddr>> {
    PUNCH_CANDIDATES_FOR_TESTS
        .lock()
        .expect("punch test candidates lock")
        .clone()
}

/// Builds the per-call candidate provider for the spawned responder.
fn candidate_provider(
    local: SocketAddr,
    resources: crate::startup::resources::SharedResources,
) -> impl Fn() -> Vec<SocketAddr> + Clone + Send + 'static {
    move || {
        #[cfg(test)]
        if let Some(candidates) = punch_candidates_for_tests() {
            return candidates;
        }
        punch::local_candidates(local, resources.public_address())
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
    let (batches, batch_rx) = mpsc::channel::<OfferBatch>(BATCH_CHANNEL_CAPACITY);
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
        // Production burst: runs the sequential probe burst through the
        // cloned probe handle (cloning keeps the socket alive; the responder
        // is aborted and joined before the composition closes the endpoint).
        let burst = move |batch: OfferBatch| {
            let probes = probes.clone();
            async move {
                let Ok(peer) = PublicKey::from_bytes(&batch.peer) else {
                    return;
                };
                punch::probe_burst_sequential(&probes, peer, &batch.candidates, "server").await;
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
    });
    parts.punch_task = Some(task);
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
            let _ = batches.try_send(OfferBatch {
                peer,
                candidates: batch_candidates,
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
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::time::timeout;

    use crate::network::signaling::punch::{Kind, encode};

    /// Fake link over bounded mpsc channels: `tx` carries datagrams the
    /// server sends, `rx` carries datagrams the test feeds the server.
    struct FakeLink {
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    }

    impl PunchLink for FakeLink {
        async fn send(&self, message: &PunchMessage, _budget: Duration) -> Result<(), SendError> {
            let bytes = encode(message).ok_or(SendError::Closed)?;
            self.tx.send(bytes).await.map_err(|_| SendError::Closed)
        }

        async fn recv_raw(&mut self) -> Option<Vec<u8>> {
            self.rx.recv().await
        }
    }

    const PEER: [u8; 32] = [7u8; 32];

    /// The candidates every `offer` claims: private LAN, because the probe
    /// gate admits it. A batch carries THESE (the peer's
    /// claimed addresses), never the provider's own candidates.
    fn offered() -> Vec<SocketAddr> {
        vec!["10.0.0.1:4433".parse().unwrap()]
    }

    fn offer(epoch: u32) -> Vec<u8> {
        encode(&PunchMessage {
            kind: Kind::Offer,
            epoch,
            candidates: offered(),
        })
        .unwrap()
    }

    fn answer(raw: Option<Vec<u8>>) -> PunchMessage {
        let raw = raw.expect("answer datagram");
        let message = punch::decode(&raw).expect("decoded answer");
        assert_eq!(message.kind, Kind::Answer);
        message
    }

    async fn no_batch(batches: &mut mpsc::Receiver<OfferBatch>) {
        assert!(
            timeout(Duration::from_millis(50), batches.recv())
                .await
                .is_err()
        );
    }

    async fn no_answer(rx: &mut mpsc::Receiver<Vec<u8>>) {
        assert!(timeout(Duration::from_millis(50), rx.recv()).await.is_err());
    }

    /// Starts `serve_peer` over a fake link; returns the handles the test
    /// drives: feeding datagrams in, reading answers out, reading batches.
    async fn serve_with(
        candidates: Vec<SocketAddr>,
        capacity: usize,
    ) -> (
        mpsc::Sender<Vec<u8>>,
        mpsc::Receiver<Vec<u8>>,
        mpsc::Receiver<OfferBatch>,
    ) {
        let (in_tx, in_rx) = mpsc::channel(16);
        // Room for every answer of the longest test: a full answer queue would
        // block the responder in `send` and starve later offers.
        let (out_tx, out_rx) = mpsc::channel(16);
        let (batch_tx, batch_rx) = mpsc::channel(capacity);
        let link = FakeLink {
            tx: out_tx,
            rx: in_rx,
        };
        tokio::spawn(serve_peer(PEER, move || candidates.clone(), batch_tx, link));
        (in_tx, out_rx, batch_rx)
    }

    #[tokio::test]
    async fn valid_offer_yields_answer_and_batch() {
        let candidates = vec!["198.51.100.9:4433".parse().unwrap()];
        let (in_tx, mut out_rx, mut batches) = serve_with(candidates.clone(), 4).await;
        in_tx.send(offer(1)).await.unwrap();
        let answer = answer(
            timeout(Duration::from_secs(1), out_rx.recv())
                .await
                .unwrap(),
        );
        assert_eq!(answer.epoch, 1);
        assert_eq!(answer.candidates, candidates);
        let batch = timeout(Duration::from_secs(1), batches.recv())
            .await
            .unwrap()
            .expect("batch");
        assert_eq!(batch.peer, PEER);
        assert_eq!(batch.candidates, offered());
        // Exactly one batch for one offer (the same-LAN path stays open).
        no_batch(&mut batches).await;
    }

    fn offer_with(epoch: u32, candidates: Vec<SocketAddr>) -> Vec<u8> {
        encode(&PunchMessage {
            kind: Kind::Offer,
            epoch,
            candidates,
        })
        .unwrap()
    }

    /// Finding 2: an offer whose candidates are all special-range (v4 and v6
    /// link-local) is still ANSWERED with the provider's candidates but
    /// starts NO probe batch. Fails on the code that forwarded every offered
    /// candidate.
    #[tokio::test]
    async fn link_local_offers_are_answered_but_start_no_batch() {
        let provider: Vec<SocketAddr> = vec!["10.0.0.9:4433".parse().unwrap()];
        let (in_tx, mut out_rx, mut batches) = serve_with(provider.clone(), 4).await;
        let claimed = vec![
            "169.254.9.9:4433".parse().unwrap(),
            "[fe80::1]:4433".parse().unwrap(),
        ];
        in_tx.send(offer_with(1, claimed)).await.unwrap();
        let reply = answer(
            timeout(Duration::from_secs(1), out_rx.recv())
                .await
                .unwrap(),
        );
        assert_eq!(reply.epoch, 1);
        assert_eq!(reply.candidates, provider);
        no_batch(&mut batches).await;
    }

    #[tokio::test(start_paused = true)]
    async fn same_epoch_forwards_one_batch_new_epoch_a_second() {
        let candidates = vec!["198.51.100.9:4433".parse().unwrap()];
        let (in_tx, _out_rx, mut batches) = serve_with(candidates.clone(), 4).await;
        in_tx.send(offer(1)).await.unwrap();
        let first = timeout(Duration::from_secs(1), batches.recv())
            .await
            .unwrap()
            .expect("batch");
        assert_eq!(first.candidates, offered());
        // Same epoch again: answered, but no second batch.
        in_tx.send(offer(1)).await.unwrap();
        no_batch(&mut batches).await;
        // A new epoch AFTER the burst interval forwards exactly one more
        // batch (Finding 1a rate limit).
        tokio::time::advance(punch::BURST_MIN_INTERVAL).await;
        in_tx.send(offer(2)).await.unwrap();
        let second = timeout(Duration::from_secs(1), batches.recv())
            .await
            .unwrap()
            .expect("batch");
        assert_eq!(second.peer, PEER);
    }

    /// Finding 1a: a flood of fresh epochs yields at most one batch per
    /// `punch::BURST_MIN_INTERVAL`, even though every epoch is new. Pre-fix
    /// code produced a batch per fresh epoch, so the `no_batch` assertions
    /// fail there.
    #[tokio::test(start_paused = true)]
    async fn fresh_epoch_flood_yields_at_most_one_batch_per_interval() {
        let candidates = vec!["198.51.100.9:4433".parse().unwrap()];
        let (in_tx, _out_rx, mut batches) = serve_with(candidates, 4).await;
        for epoch in 1..=3u32 {
            in_tx.send(offer(epoch)).await.unwrap();
        }
        let first = timeout(Duration::from_secs(1), batches.recv())
            .await
            .unwrap()
            .expect("batch");
        assert_eq!(first.peer, PEER);
        no_batch(&mut batches).await;
        // Just inside the interval: still suppressed.
        tokio::time::advance(Duration::from_millis(4_900)).await;
        in_tx.send(offer(4)).await.unwrap();
        no_batch(&mut batches).await;
        // Past the interval: exactly one more batch.
        tokio::time::advance(Duration::from_millis(200)).await;
        in_tx.send(offer(5)).await.unwrap();
        let second = timeout(Duration::from_secs(1), batches.recv())
            .await
            .unwrap()
            .expect("batch");
        assert_eq!(second.peer, PEER);
        // Immediately after: suppressed again.
        in_tx.send(offer(6)).await.unwrap();
        no_batch(&mut batches).await;
    }

    /// Finding 1a: offers inside the suppressed interval are STILL ANSWERED —
    /// only the burst handover is throttled. Pre-fix code answered too, but
    /// also batched per epoch, which the `no_batch` assertion rejects.
    #[tokio::test(start_paused = true)]
    async fn offers_inside_the_interval_are_still_answered() {
        let candidates = vec!["198.51.100.9:4433".parse().unwrap()];
        let (in_tx, mut out_rx, mut batches) = serve_with(candidates.clone(), 4).await;
        for epoch in 1..=3u32 {
            in_tx.send(offer(epoch)).await.unwrap();
            let reply = answer(
                timeout(Duration::from_secs(1), out_rx.recv())
                    .await
                    .unwrap(),
            );
            assert_eq!(reply.epoch, epoch);
            assert_eq!(reply.candidates, candidates);
        }
        // Only the epoch-1 batch was handed over; the other epochs were
        // answered without a burst.
        let batch = timeout(Duration::from_secs(1), batches.recv())
            .await
            .unwrap()
            .expect("batch");
        assert_eq!(batch.peer, PEER);
        no_batch(&mut batches).await;
    }

    /// Finding 1c: `run_batches` never runs more than
    /// `punch::BURST_CONCURRENCY_CAP` bursts concurrently, drains the channel
    /// (backpressure), and on channel end joins shutdown by cancelling the
    /// in-flight bursts cleanly (counter back to 0). Fails pre-fix:
    /// `run_batches` does not exist.
    #[tokio::test(start_paused = true)]
    async fn run_batches_caps_concurrent_bursts_and_drains_the_channel() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// Decrements the running counter when (and only when) the burst
        /// future is dropped, including cancellation-by-drop.
        struct Guard(std::sync::Arc<AtomicUsize>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }

        let running = std::sync::Arc::new(AtomicUsize::new(0));
        let started = std::sync::Arc::new(AtomicUsize::new(0));
        let (tx, rx) = mpsc::channel::<OfferBatch>(8);
        let burst_running = std::sync::Arc::clone(&running);
        let burst_started = std::sync::Arc::clone(&started);
        let handle = tokio::spawn(run_batches(rx, move |batch: OfferBatch| {
            let running = std::sync::Arc::clone(&burst_running);
            let started = std::sync::Arc::clone(&burst_started);
            async move {
                let _peer = &batch.peer;
                started.fetch_add(1, Ordering::SeqCst);
                let _guard = Guard(std::sync::Arc::clone(&running));
                running.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }));
        for _ in 0..5u32 {
            tx.send(OfferBatch {
                peer: PEER,
                candidates: Vec::new(),
            })
            .await
            .unwrap();
        }
        // Bounded polling on the paused clock: every batch is consumed off
        // the channel while no more than the cap runs concurrently.
        for _ in 0..200u32 {
            tokio::time::advance(Duration::from_millis(10)).await;
            tokio::task::yield_now().await;
            assert!(running.load(Ordering::SeqCst) <= punch::BURST_CONCURRENCY_CAP);
            if started.load(Ordering::SeqCst) == 5 {
                break;
            }
        }
        assert_eq!(started.load(Ordering::SeqCst), 5);
        assert!(running.load(Ordering::SeqCst) > 0);
        // Dropping the sender ends the loop; in-flight bursts are dropped
        // (decrementing the counter) and the join completes.
        drop(tx);
        timeout(Duration::from_secs(60), handle)
            .await
            .expect("run_batches joins after channel end")
            .unwrap();
        assert_eq!(running.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn garbage_bytes_yield_neither_and_never_panic() {
        let candidates = vec!["198.51.100.9:4433".parse().unwrap()];
        let (in_tx, mut out_rx, mut batches) = serve_with(candidates, 4).await;
        in_tx.send(vec![0xde, 0xad, 0xbe, 0xef]).await.unwrap();
        in_tx.send(vec![b'p'; 4096]).await.unwrap();
        no_answer(&mut out_rx).await;
        no_batch(&mut batches).await;
    }

    #[tokio::test]
    async fn empty_provider_yields_neither() {
        let (in_tx, mut out_rx, mut batches) = serve_with(Vec::new(), 4).await;
        in_tx.send(offer(1)).await.unwrap();
        no_answer(&mut out_rx).await;
        no_batch(&mut batches).await;
    }

    #[tokio::test(start_paused = true)]
    async fn full_batches_channel_skips_without_panic() {
        let candidates = vec!["198.51.100.9:4433".parse().unwrap()];
        // Capacity 1, never drained while sending: the batch is skipped, the
        // answers are still sent, the worker stays alive.
        let (in_tx, mut out_rx, mut batches) = serve_with(candidates.clone(), 1).await;
        in_tx.send(offer(1)).await.unwrap();
        let first = answer(
            timeout(Duration::from_secs(1), out_rx.recv())
                .await
                .unwrap(),
        );
        assert_eq!(first.epoch, 1);
        // Cross the burst interval so the new epoch is burst-eligible; the
        // full (undrained) channel still skips the batch, no panic.
        tokio::time::advance(punch::BURST_MIN_INTERVAL).await;
        in_tx.send(offer(2)).await.unwrap();
        let second = answer(
            timeout(Duration::from_secs(1), out_rx.recv())
                .await
                .unwrap(),
        );
        assert_eq!(second.epoch, 2);
        // Exactly one batch was queued (the first); the second was skipped.
        let queued = timeout(Duration::from_secs(1), batches.recv())
            .await
            .unwrap()
            .expect("batch");
        assert_eq!(queued.peer, PEER);
        no_batch(&mut batches).await;
    }

    #[tokio::test]
    async fn answer_kind_datagram_is_ignored() {
        let candidates = vec!["198.51.100.9:4433".parse().unwrap()];
        let (in_tx, mut out_rx, mut batches) = serve_with(candidates, 4).await;
        let datagram = encode(&PunchMessage {
            kind: Kind::Answer,
            epoch: 9,
            candidates: vec!["203.0.113.7:4433".parse().unwrap()],
        })
        .unwrap();
        in_tx.send(datagram).await.unwrap();
        no_answer(&mut out_rx).await;
        no_batch(&mut batches).await;
    }

    /// Refuses the first `refusals` sends (cold Yggdrasil path), then delivers.
    struct RefusingLink {
        inner: FakeLink,
        refusals: usize,
        sent: AtomicUsize,
    }

    impl PunchLink for RefusingLink {
        async fn send(&self, message: &PunchMessage, budget: Duration) -> Result<(), SendError> {
            if self.sent.fetch_add(1, Ordering::SeqCst) < self.refusals {
                return Err(SendError::Refused);
            }
            self.inner.send(message, budget).await
        }

        async fn recv_raw(&mut self) -> Option<Vec<u8>> {
            self.inner.recv_raw().await
        }
    }

    /// A refused Answer must not end the worker: the peer's next Offer copy is
    /// answered and starts the one burst of that epoch.
    #[tokio::test]
    async fn refused_answer_is_retried_by_the_next_offer_copy() {
        let (in_tx, in_rx) = mpsc::channel(16);
        let (out_tx, mut out_rx) = mpsc::channel(16);
        let (batch_tx, mut batches) = mpsc::channel(4);
        let link = RefusingLink {
            inner: FakeLink {
                tx: out_tx,
                rx: in_rx,
            },
            refusals: 1,
            sent: AtomicUsize::new(0),
        };
        let provider: Vec<SocketAddr> = vec!["198.51.100.9:4433".parse().unwrap()];
        tokio::spawn(serve_peer(PEER, move || provider.clone(), batch_tx, link));
        in_tx.send(offer(1)).await.unwrap();
        no_answer(&mut out_rx).await;
        no_batch(&mut batches).await;
        in_tx.send(offer(1)).await.unwrap();
        let answer = answer(
            timeout(Duration::from_secs(1), out_rx.recv())
                .await
                .unwrap(),
        );
        assert_eq!(answer.epoch, 1);
        let batch = timeout(Duration::from_secs(1), batches.recv())
            .await
            .unwrap()
            .expect("batch");
        assert_eq!(batch.candidates, offered());
        no_batch(&mut batches).await;
    }

    /// A closed link still ends the worker (peer punching disabled).
    #[tokio::test]
    async fn closed_answer_link_ends_the_worker() {
        let (in_tx, in_rx) = mpsc::channel(16);
        let (out_tx, out_rx) = mpsc::channel(16);
        let (batch_tx, _batches) = mpsc::channel(4);
        // Answers can no longer be delivered once the receiving half is gone.
        drop(out_rx);
        let link = FakeLink {
            tx: out_tx,
            rx: in_rx,
        };
        let provider: Vec<SocketAddr> = vec!["198.51.100.9:4433".parse().unwrap()];
        let worker = tokio::spawn(serve_peer(PEER, move || provider.clone(), batch_tx, link));
        in_tx.send(offer(1)).await.unwrap();
        timeout(Duration::from_secs(1), worker)
            .await
            .expect("the worker ends")
            .expect("no panic");
    }
}
