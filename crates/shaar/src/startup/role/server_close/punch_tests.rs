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

/// Leaf SET-1d: the batches of one peer carry rising burst numbers, which pick the slice of the
/// peer's port set that each burst walks; an offer suppressed inside the interval takes no number.
#[tokio::test(start_paused = true)]
async fn the_batches_of_one_peer_carry_rising_burst_numbers() {
    let candidates = vec!["198.51.100.9:4433".parse().unwrap()];
    let (in_tx, _out_rx, mut batches) = serve_with(candidates, 4).await;
    let mut numbers = Vec::new();
    for epoch in 1..=3u32 {
        in_tx.send(offer(epoch)).await.unwrap();
        let batch = timeout(Duration::from_secs(1), batches.recv())
            .await
            .unwrap()
            .expect("batch");
        numbers.push(batch.burst);
        in_tx.send(offer(epoch + 100)).await.unwrap();
        no_batch(&mut batches).await;
        tokio::time::advance(punch::BURST_MIN_INTERVAL).await;
    }
    assert_eq!(numbers, [1, 2, 3]);
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
            burst: 1,
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
