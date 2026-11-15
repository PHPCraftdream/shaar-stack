//! Offer retransmission inside one exchange window (leaf L4): a lost first
//! datagram is repeated, and the repetition is bounded by the window. Owns a
//! tiny fake `PunchLink`; time is paused, so every oracle is exact.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::sync::mpsc;
use tokio::time::Instant;

use super::{
    EXCHANGE_BUDGET, Kind, NetworkError, OFFER_RESEND, PROBE_WINDOW, PunchLink, PunchMessage,
    client_attempt, decode, encode,
};

const BOUND: Duration = EXCHANGE_BUDGET.saturating_add(PROBE_WINDOW);

struct FakeLink {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
}

impl PunchLink for FakeLink {
    async fn send(&self, message: &PunchMessage, _budget: Duration) -> Result<(), ()> {
        self.tx
            .send(encode(message).ok_or(())?)
            .await
            .map_err(|_| ())
    }

    async fn recv_raw(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
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
