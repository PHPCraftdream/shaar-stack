//! The end reason of one client punch attempt (leaf NAT-L4e step 1): every exit
//! of the state machine names why it ended, so a live run can tell a spent
//! deadline from a silent peer, a closed link or failed probes. Time is paused,
//! so every oracle is exact.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::sync::mpsc;
use tokio::time::Instant;

use super::punch_tests::direct_session;
use super::{
    EXCHANGE_BUDGET, EndReason, Kind, NetworkError, PROBE_WINDOW, PunchLink, PunchMessage,
    SendError, client_attempt_reasoned, client_exchange, decode, encode, trace_line,
};

const BOUND: Duration = EXCHANGE_BUDGET.saturating_add(PROBE_WINDOW);

struct Link {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
}

impl PunchLink for Link {
    async fn send(&self, message: &PunchMessage, _budget: Duration) -> Result<(), SendError> {
        let bytes = encode(message).ok_or(SendError::Closed)?;
        self.tx.send(bytes).await.map_err(|_| SendError::Closed)
    }

    async fn recv_raw(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }
}

fn pair() -> (Link, Link) {
    let (a_tx, b_rx) = mpsc::channel(16);
    let (b_tx, a_rx) = mpsc::channel(16);
    (Link { tx: a_tx, rx: a_rx }, Link { tx: b_tx, rx: b_rx })
}

type Seam = std::future::Ready<Result<crate::network::Session, NetworkError>>;

/// Connect seam that fails at once.
fn failing(_: SocketAddr) -> Seam {
    std::future::ready(Err(NetworkError::InvalidAddress))
}

/// Answers the first Offer with one public candidate.
fn answering(mut peer: Link) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let raw = peer.recv_raw().await.expect("offer");
        let offer = decode(&raw).expect("valid offer");
        let answer = PunchMessage {
            kind: Kind::Answer,
            epoch: offer.epoch,
            candidates: vec!["198.51.100.7:4433".parse().unwrap()],
        };
        peer.send(&answer, EXCHANGE_BUDGET).await.expect("answer");
    })
}

#[tokio::test(start_paused = true)]
async fn an_attempt_without_time_ends_on_the_deadline_at_once() {
    let (mut client, _peer) = pair();
    let started = Instant::now();
    let (session, reason) = client_exchange(&mut client, failing, vec![], 1, started).await;
    assert!(session.is_none());
    assert_eq!(reason, EndReason::Deadline);
    assert_eq!(started.elapsed(), Duration::ZERO);
}

#[tokio::test(start_paused = true)]
async fn a_deadline_inside_the_window_is_reported_as_the_deadline() {
    let (mut client, _peer) = pair();
    let started = Instant::now();
    let cut = Duration::from_millis(600);
    let (session, reason) = client_exchange(&mut client, failing, vec![], 2, started + cut).await;
    assert!(session.is_none());
    assert_eq!(reason, EndReason::Deadline);
    assert_eq!(started.elapsed(), cut);
}

#[tokio::test(start_paused = true)]
async fn a_silent_peer_ends_on_no_answer_at_the_window() {
    let (mut client, _peer) = pair();
    let started = Instant::now();
    let (session, reason) = client_exchange(&mut client, failing, vec![], 3, started + BOUND).await;
    assert!(session.is_none());
    assert_eq!(reason, EndReason::NoAnswer);
    assert_eq!(started.elapsed(), EXCHANGE_BUDGET);
}

#[tokio::test(start_paused = true)]
async fn a_closed_link_ends_on_closed() {
    let (mut client, peer) = pair();
    drop(peer);
    let started = Instant::now();
    let (session, reason) = client_exchange(&mut client, failing, vec![], 4, started + BOUND).await;
    assert!(session.is_none());
    assert_eq!(reason, EndReason::Closed);
    assert_eq!(started.elapsed(), Duration::ZERO);
}

#[tokio::test(start_paused = true)]
async fn an_answer_with_only_failing_probes_ends_on_probe() {
    let (mut client, peer) = pair();
    let server = answering(peer);
    let started = Instant::now();
    let (session, reason) = client_exchange(&mut client, failing, vec![], 5, started + BOUND).await;
    server.await.expect("server task");
    assert!(session.is_none());
    assert_eq!(reason, EndReason::Probe);
}

#[tokio::test(start_paused = true)]
async fn a_completed_probe_ends_on_direct_with_the_session() {
    let (mut client, peer) = pair();
    let server = answering(peer);
    let stored = Arc::new(Mutex::new(Some(direct_session().await)));
    let seam = move |_: SocketAddr| {
        let taken = stored.lock().expect("session lock").take();
        std::future::ready(taken.ok_or(NetworkError::InvalidAddress))
    };
    let started = Instant::now();
    let (session, reason) = client_exchange(&mut client, seam, vec![], 6, started + BOUND).await;
    server.await.expect("server task");
    assert!(session.is_some());
    assert_eq!(reason, EndReason::Direct);
}

#[test]
fn the_trace_line_carries_counts_reason_and_timing_only() {
    for (reason, outcome, token) in [
        (EndReason::Direct, "direct", "direct"),
        (EndReason::Deadline, "fallback", "deadline"),
        (EndReason::NoAnswer, "fallback", "no-answer"),
        (EndReason::Closed, "fallback", "closed"),
        (EndReason::Probe, "fallback", "probe"),
    ] {
        assert_eq!(
            trace_line("client", 2, reason, 17),
            format!(
                "shaar: client punch candidates=2 outcome={outcome} reason={token} elapsed_ms=17"
            )
        );
    }
}

#[test]
fn the_offer_line_carries_counts_and_the_answer_fate_only() {
    for answer in ["sent", "none", "refused"] {
        assert_eq!(
            super::offer_line(3, answer),
            format!("shaar: server punch offer candidates=3 answer={answer}")
        );
    }
}

#[test]
fn the_ports_line_carries_ports_only_never_addresses() {
    let own: Vec<SocketAddr> = vec![
        "203.0.113.5:40001".parse().expect("own public"),
        "10.0.0.2:40001".parse().expect("own private"),
    ];
    let peer: Vec<SocketAddr> = vec!["198.51.100.7:51234".parse().expect("peer public")];
    let line = super::ports_line("client", &own, &peer);
    assert_eq!(line, "shaar: client punch ports own=40001,40001 peer=51234");
    for fragment in ["203.0.113", "10.0.0.2", "198.51.100"] {
        assert!(!line.contains(fragment), "no address in {line}");
    }
    assert_eq!(
        super::ports_line("server", &[], &[]),
        "shaar: server punch ports own=- peer=-"
    );
}

#[test]
fn the_ports_line_is_bounded_by_the_candidate_limit() {
    let many: Vec<SocketAddr> = (1..=20_u16)
        .map(|port| SocketAddr::from(([192, 0, 2, 1], 40_000 + port)))
        .collect();
    let line = super::ports_line("server", &many, &many);
    let listed = line.matches(',').count() + 2;
    assert!(
        listed <= 2 * super::MAX_CANDIDATES,
        "at most MAX_CANDIDATES ports per side: {line}"
    );
}

#[tokio::test(start_paused = true)]
async fn the_reasoned_attempt_returns_the_reason_its_exchange_named() {
    // An Answer comes back and the probe fails: Probe.
    let (mut client, peer) = pair();
    let _answerer = answering(peer);
    let (session, reason) = client_attempt_reasoned(
        &mut client,
        failing,
        vec![],
        1,
        Instant::now() + BOUND,
        "client",
    )
    .await;
    assert!(session.is_none());
    assert_eq!(reason, EndReason::Probe);
    // Nobody answers: NoAnswer when the exchange window ends.
    let (mut client, _silent) = pair();
    let (session, reason) = client_attempt_reasoned(
        &mut client,
        failing,
        vec![],
        2,
        Instant::now() + BOUND,
        "client",
    )
    .await;
    assert!(session.is_none());
    assert_eq!(reason, EndReason::NoAnswer);
    // No time left: Deadline.
    let (mut client, _silent) = pair();
    let (_, reason) =
        client_attempt_reasoned(&mut client, failing, vec![], 3, Instant::now(), "client").await;
    assert_eq!(reason, EndReason::Deadline);
}
