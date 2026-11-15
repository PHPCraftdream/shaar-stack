//! Offer retransmission inside one exchange window (leaf L4): a lost first
//! datagram is repeated, and the repetition is bounded by the window. Owns a
//! tiny fake `PunchLink`; time is paused, so every oracle is exact.

use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::sync::mpsc;
use tokio::time::Instant;

use super::{
    EXCHANGE_BUDGET, Kind, NetworkError, OFFER_RESEND, PROBE_WINDOW, PunchLink, PunchMessage,
    SendError, client_attempt, decode, encode,
};

const BOUND: Duration = EXCHANGE_BUDGET.saturating_add(PROBE_WINDOW);

struct FakeLink {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
}

impl PunchLink for FakeLink {
    async fn send(&self, message: &PunchMessage, _budget: Duration) -> Result<(), SendError> {
        self.tx
            .send(encode(message).ok_or(SendError::Closed)?)
            .await
            .map_err(|_| SendError::Closed)
    }

    async fn recv_raw(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }
}

/// Refuses the first `refusals` sends (cold path), then delivers like `FakeLink`.
struct FlakyLink {
    inner: FakeLink,
    refusals: AtomicUsize,
}

impl PunchLink for FlakyLink {
    async fn send(&self, message: &PunchMessage, budget: Duration) -> Result<(), SendError> {
        let refused = self
            .refusals
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok();
        if refused {
            return Err(SendError::Refused);
        }
        self.inner.send(message, budget).await
    }

    async fn recv_raw(&mut self) -> Option<Vec<u8>> {
        self.inner.recv_raw().await
    }
}

fn link_pair() -> (FakeLink, FakeLink) {
    let (a_tx, b_rx) = mpsc::channel(16);
    let (b_tx, a_rx) = mpsc::channel(16);
    (
        FakeLink { tx: a_tx, rx: a_rx },
        FakeLink { tx: b_tx, rx: b_rx },
    )
}

/// Connect seam that records the probed address and fails at once.
fn recording(
    calls: Arc<Mutex<Vec<SocketAddr>>>,
) -> impl Fn(SocketAddr) -> std::future::Ready<Result<crate::network::Session, NetworkError>> {
    move |address| {
        calls.lock().expect("calls lock").push(address);
        std::future::ready(Err(NetworkError::InvalidAddress))
    }
}

/// The first Offer copy is lost (cold Yggdrasil path, peer not registered
/// yet); the retransmitted copy is answered and the answered candidate is
/// probed, inside the one exchange window.
#[tokio::test(start_paused = true)]
async fn lost_first_offer_is_retransmitted_and_answered() {
    let (mut client_link, mut peer_link) = link_pair();
    let answered: SocketAddr = "10.0.0.2:1".parse().unwrap();
    let server = tokio::spawn(async move {
        let _lost = peer_link.recv_raw().await.expect("first offer");
        let raw = peer_link.recv_raw().await.expect("retransmitted offer");
        let offer = decode(&raw).expect("valid offer");
        assert_eq!(offer.kind, Kind::Offer);
        let answer = PunchMessage {
            kind: Kind::Answer,
            epoch: offer.epoch,
            candidates: vec![answered],
        };
        peer_link
            .send(&answer, EXCHANGE_BUDGET)
            .await
            .expect("answer sent");
    });
    let calls = Arc::new(Mutex::new(Vec::new()));
    let started = Instant::now();
    let result = client_attempt(
        &mut client_link,
        recording(Arc::clone(&calls)),
        vec![],
        8,
        started + BOUND,
        "client",
    )
    .await;
    server.await.expect("server task");
    assert!(
        result.is_none(),
        "the recording seam never completes a session"
    );
    assert_eq!(*calls.lock().expect("calls lock"), vec![answered]);
    assert!(
        started.elapsed() >= OFFER_RESEND && started.elapsed() < EXCHANGE_BUDGET,
        "answered on the second copy, inside the window: {:?}",
        started.elapsed()
    );
}

/// Without any answer the peer sees one copy per resend interval and the
/// attempt ends exactly at the end of the exchange window.
#[tokio::test(start_paused = true)]
async fn retransmission_is_bounded_by_the_exchange_window() {
    let (mut client_link, mut peer_link) = link_pair();
    let started = Instant::now();
    let result = client_attempt(
        &mut client_link,
        recording(Arc::new(Mutex::new(Vec::new()))),
        vec![],
        9,
        started + BOUND,
        "client",
    )
    .await;
    assert!(result.is_none());
    assert_eq!(started.elapsed(), EXCHANGE_BUDGET, "exact virtual time");
    let mut copies = 0u128;
    while let Ok(raw) = peer_link.rx.try_recv() {
        let offer = decode(&raw).expect("every copy is the same valid offer");
        assert_eq!((offer.kind, offer.epoch), (Kind::Offer, 9));
        copies += 1;
    }
    assert_eq!(
        copies,
        EXCHANGE_BUDGET.as_millis() / OFFER_RESEND.as_millis(),
        "one copy per resend interval"
    );
}

/// A refused first copy is not a closed link: the next copy follows after one
/// resend interval, is answered, and the answered candidate is probed.
#[tokio::test(start_paused = true)]
async fn refused_first_offer_is_retried_inside_the_window() {
    let (client_half, mut peer_link) = link_pair();
    let mut client_link = FlakyLink {
        inner: client_half,
        refusals: AtomicUsize::new(1),
    };
    let answered: SocketAddr = "10.0.0.3:1".parse().unwrap();
    let server = tokio::spawn(async move {
        let raw = peer_link
            .recv_raw()
            .await
            .expect("the first delivered offer");
        let offer = decode(&raw).expect("valid offer");
        let answer = PunchMessage {
            kind: Kind::Answer,
            epoch: offer.epoch,
            candidates: vec![answered],
        };
        peer_link
            .send(&answer, EXCHANGE_BUDGET)
            .await
            .expect("answer sent");
    });
    let calls = Arc::new(Mutex::new(Vec::new()));
    let started = Instant::now();
    let result = client_attempt(
        &mut client_link,
        recording(Arc::clone(&calls)),
        vec![],
        10,
        started + BOUND,
        "client",
    )
    .await;
    server.await.expect("server task");
    assert!(result.is_none());
    assert_eq!(*calls.lock().expect("calls lock"), vec![answered]);
    assert_eq!(
        started.elapsed(),
        OFFER_RESEND,
        "the delivered copy is the second one"
    );
}

/// Every copy refused: nothing reaches the peer and the attempt still ends
/// exactly at the end of the exchange window (bounded, not an instant return).
#[tokio::test(start_paused = true)]
async fn all_copies_refused_end_at_the_window_without_delivery() {
    let (client_half, mut peer_link) = link_pair();
    let mut client_link = FlakyLink {
        inner: client_half,
        refusals: AtomicUsize::new(usize::MAX),
    };
    let started = Instant::now();
    let result = client_attempt(
        &mut client_link,
        recording(Arc::new(Mutex::new(Vec::new()))),
        vec![],
        11,
        started + BOUND,
        "client",
    )
    .await;
    assert!(result.is_none());
    assert_eq!(started.elapsed(), EXCHANGE_BUDGET, "exact virtual time");
    assert!(peer_link.rx.try_recv().is_err(), "no copy was delivered");
}
