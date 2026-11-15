//! Unit tests for the punch subsystem: wire codec, candidate builder and the
//! client state machine over fake `PunchLink`s under paused Tokio time, so
//! every timing oracle is exact virtual time. Success paths need one real
//! loopback QUIC session (see `direct_session`); no relay is involved.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::sync::mpsc;

use super::*;

fn v4(a: [u8; 4], port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(a)), port)
}

fn loopback_addr() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn public(identity: &crate::identity::Identity) -> PublicKey {
    identity.transport_key().public()
}

/// One real handshaken loopback session; the server endpoint is closed, the
/// session is dropped by the caller's seam when the attempt consumes it.
async fn direct_session() -> Session {
    let a = crate::identity::Identity::generate();
    let b = crate::identity::Identity::generate();
    let mut server = crate::network::SignaledEndpoint::bind(
        &b,
        loopback_addr(),
        loopback_addr(),
        &[public(&a)],
        crate::network::Limits::default(),
    )
    .await
    .unwrap();
    let client = crate::network::SignaledEndpoint::bind(
        &a,
        loopback_addr(),
        loopback_addr(),
        &[public(&b)],
        crate::network::Limits::default(),
    )
    .await
    .unwrap();
    let target = server.local_addr();
    let (session, accepted) = tokio::join!(client.connect(public(&b), target), server.accept());
    let session = session.expect("loopback client session");
    accepted.expect("loopback server session");
    server.close().await.expect("server close");
    drop(client);
    session
}

// ---------------------------------------------------------------- codec ----

fn offer(epoch: u32, candidates: Vec<SocketAddr>) -> PunchMessage {
    PunchMessage {
        kind: Kind::Offer,
        epoch,
        candidates,
    }
}

#[test]
fn roundtrip_matches_golden_wire_prefix() {
    let message = offer(7, vec![v4([203, 0, 113, 10], 1), v4([127, 0, 0, 1], 4242)]);
    let bytes = encode(&message).expect("encodable");
    assert_eq!(&bytes[..5], b"pnc1\x01");
    assert_eq!(bytes[5], 1);
    assert_eq!(bytes[6..10], 7u32.to_le_bytes());
    assert_eq!(bytes[10], 2);
    // family 4 + 4 address bytes + big-endian port per candidate.
    assert_eq!(&bytes[11..15], &[4, 203, 0, 113, 10]);
    assert_eq!(&bytes[15..17], &1u16.to_be_bytes());
    assert_eq!(&bytes[17..22], &[4, 127, 0, 0, 1]);
    assert_eq!(&bytes[22..24], &4242u16.to_be_bytes());
    assert_eq!(decode(&bytes), Some(message));
}

#[test]
fn answer_kind_roundtrips_with_epoch() {
    let message = PunchMessage {
        kind: Kind::Answer,
        epoch: u32::MAX,
        candidates: vec![],
    };
    let bytes = encode(&message).expect("encodable");
    assert_eq!(bytes[5], 2);
    assert_eq!(decode(&bytes), Some(message));
}

#[test]
fn empty_candidate_list_decodes() {
    let bytes = encode(&offer(1, vec![])).expect("encodable");
    assert_eq!(bytes.len(), 11);
    assert_eq!(decode(&bytes), Some(offer(1, vec![])));
}

#[test]
fn five_candidates_are_rejected() {
    let candidates = (0u8..5)
        .map(|i| v4([203, 0, 113, 10 + i], 1))
        .collect::<Vec<_>>();
    assert_eq!(encode(&offer(1, candidates)), None);
    // A hostile count byte with matching padding still fails the cap.
    let mut bytes = encode(&offer(1, vec![])).unwrap();
    bytes[10] = 5;
    bytes.resize(11 + 5 * 18, 0);
    assert_eq!(decode(&bytes), None);
}

#[test]
fn malformed_lengths_decode_none() {
    let good = encode(&offer(1, vec![v4([203, 0, 113, 10], 1)])).unwrap();
    assert_eq!(decode(&good[..good.len() - 1]), None, "truncated");
    let mut long = good.clone();
    long.push(0);
    assert_eq!(decode(&long), None, "trailing byte");
    let mut lie = good.clone();
    lie[10] = 2;
    assert_eq!(decode(&lie), None, "count lie");
    assert_eq!(decode(&[]), None, "empty");
    let mut magic = good.clone();
    magic[0] = b'x';
    assert_eq!(decode(&magic), None, "wrong magic");
    let mut version = good;
    version[4] = 2;
    assert_eq!(decode(&version), None, "wrong version");
}

#[test]
fn unknown_kind_bytes_decode_none() {
    for kind in [0u8, 3] {
        let mut bytes = encode(&offer(1, vec![])).unwrap();
        bytes[5] = kind;
        assert_eq!(decode(&bytes), None, "kind {kind}");
    }
}

#[test]
fn oversized_and_over_cap_payloads_are_rejected() {
    // Six candidates exceed the candidate cap before any size check.
    let six = (0u8..6)
        .map(|i| v4([203, 0, 113, 10 + i], 1))
        .collect::<Vec<_>>();
    assert_eq!(encode(&offer(1, six)), None, "over candidate cap");
    // With at most 4 candidates an encode always fits the byte cap (88 max),
    // so the 96-byte cap is only exercised through hostile decode input.
    let mut bytes = encode(&offer(1, vec![])).unwrap();
    bytes.resize(MAX_MESSAGE_BYTES + 1, 0);
    assert_eq!(bytes.len(), MAX_MESSAGE_BYTES + 1);
    assert_eq!(decode(&bytes), None, "oversized buffer not a message");
}

/// Builds one candidate item by hand for hostile-wire rejection checks.
fn craft(family: u8, octets: &[u8], port: u16) -> Vec<u8> {
    let mut bytes = b"pnc1\x01".to_vec();
    bytes.push(1); // kind byte: Offer
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.push(1); // count
    bytes.push(family);
    bytes.extend_from_slice(octets);
    bytes.extend_from_slice(&port.to_be_bytes());
    bytes
}

#[test]
fn policy_denied_candidates_decode_none() {
    let denied_v4 = [
        ([0u8, 0, 0, 0], "unspecified v4"),
        ([224, 0, 0, 1], "multicast v4"),
        ([255, 255, 255, 255], "v4 broadcast"),
    ];
    for (octets, label) in denied_v4 {
        assert_eq!(decode(&craft(4, &octets, 1)), None, "{label}");
    }
    let denied_v6 = [
        ([0u8; 16], "unspecified v6"),
        (
            [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            "multicast v6",
        ),
        (
            [
                0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ],
            "fabric prefix",
        ),
    ];
    for (octets, label) in denied_v6 {
        assert_eq!(decode(&craft(6, &octets, 1)), None, "{label}");
    }
    assert_eq!(decode(&craft(4, &[1, 2, 3, 4], 0)), None, "port zero");
    assert_eq!(decode(&craft(7, &[1, 2, 3, 4], 1)), None, "bad family");
    // encode also refuses denied candidates outright.
    assert_eq!(encode(&offer(1, vec![v4([0, 0, 0, 0], 1)])), None);
    assert_eq!(encode(&offer(1, vec![v4([1, 2, 3, 4], 0)])), None);
}

/// Dial parity with the dialer: loopback and the CI namespace documentation
/// range (203.0.113.0/24) are allowed punch candidates.
#[test]
fn loopback_and_documentation_candidates_are_accepted() {
    for address in [v4([127, 0, 0, 1], 4242), v4([203, 0, 113, 10], 1)] {
        let bytes = encode(&offer(1, vec![address])).expect("allowed by dial parity");
        assert_eq!(decode(&bytes), Some(offer(1, vec![address])));
    }
}

#[test]
fn duplicate_and_v4_mapped_duplicates_decode_none() {
    let a = v4([203, 0, 113, 10], 1);
    let mapped = SocketAddr::new(IpAddr::V6("::ffff:203.0.113.10".parse().unwrap()), 1);
    assert_eq!(candidate_allowed(mapped), true, "mapped passes predicate");
    let bytes = encode(&offer(1, vec![a, a])).expect("encode does not dedupe");
    assert_eq!(decode(&bytes), None, "exact duplicate");
    let bytes = encode(&offer(1, vec![a, mapped])).expect("encode does not canonicalize");
    assert_eq!(decode(&bytes), None, "v4-mapped duplicate");
}

// ---------------------------------------------------- candidate builder ----

#[test]
fn reflexive_guess_leads_and_local_follows() {
    let local = v4([10, 0, 0, 1], 7777);
    let reflexive = Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(
        local_candidates(local, reflexive),
        vec![v4([8, 8, 8, 8], 7777), local]
    );
}

/// Acceptance 4: without a reflexive source only the local bound address is
/// offered, exactly today's record behavior.
#[test]
fn reflexive_none_offers_local_only() {
    let local = v4([192, 168, 1, 1], 7777);
    assert_eq!(local_candidates(local, None), vec![local]);
}

#[test]
fn wildcard_local_is_never_offered() {
    assert!(local_candidates(v4([0, 0, 0, 0], 7777), None).is_empty());
    assert!(
        local_candidates(
            v4([0, 0, 0, 0], 7777),
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
        )
        .is_empty()
    );
}

#[test]
fn zero_port_local_is_never_offered() {
    assert!(local_candidates(v4([10, 0, 0, 1], 0), None).is_empty());
    assert!(
        local_candidates(
            v4([10, 0, 0, 1], 0),
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
        )
        .is_empty()
    );
}

#[test]
fn reflexive_equal_to_local_dedupes() {
    let local = v4([203, 0, 113, 10], 7777);
    let reflexive = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)));
    assert_eq!(local_candidates(local, reflexive), vec![local]);
}

#[test]
fn candidates_cap_at_four() {
    // The builder only ever composes two entries today; the cap is asserted
    // through the encode path that shares the constant.
    let four = (0u16..4)
        .map(|i| v4([203, 0, 113, 10], 1000 + i))
        .collect::<Vec<_>>();
    assert!(encode(&offer(1, four)).is_some());
    assert_eq!(MAX_CANDIDATES, 4);
}

#[test]
fn candidate_allowed_mirrors_dial_predicate() {
    assert!(candidate_allowed(v4([127, 0, 0, 1], 4242)));
    assert!(candidate_allowed(v4([203, 0, 113, 10], 1)));
    assert!(!candidate_allowed(v4([0, 0, 0, 0], 1)));
    assert!(!candidate_allowed(v4([224, 0, 0, 1], 1)));
    assert!(!candidate_allowed(v4([255, 255, 255, 255], 1)));
    assert!(!candidate_allowed(SocketAddr::new(
        IpAddr::V6("fd15:70a:510b::1".parse().unwrap()),
        1
    )));
}

// ------------------------------------------------------ state machine ----

/// Fake `PunchLink` over paired mpsc channels; the peer half plays the server.
struct FakeLink {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
}

impl PunchLink for FakeLink {
    async fn send(&self, message: &PunchMessage, budget: Duration) -> Result<(), ()> {
        let bytes = encode(message).ok_or(())?;
        tokio::time::timeout(budget, self.tx.send(bytes))
            .await
            .map_err(|_| ())?
            .map_err(|_| ())
    }

    async fn recv_raw(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }
}

fn link_pair() -> (FakeLink, FakeLink) {
    let (a_tx, b_rx) = mpsc::channel(8);
    let (b_tx, a_rx) = mpsc::channel(8);
    (
        FakeLink { tx: a_tx, rx: a_rx },
        FakeLink { tx: b_tx, rx: b_rx },
    )
}

/// Connect seam type: records dialed addresses, yields stored sessions.
type ConnectFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Session, NetworkError>>>>;

/// Connect seam: records every dialed address, resolves after one scheduler
/// yield with the stored session for non-silent addresses, hangs for silent
/// ones. The yield makes completion observable (a hanging probe never polls
/// past its first yield, so it is never recorded as completed).
fn seam(
    calls: Arc<Mutex<Vec<SocketAddr>>>,
    completions: Arc<Mutex<Vec<SocketAddr>>>,
    session: Arc<Mutex<Option<Session>>>,
    silent: Vec<SocketAddr>,
) -> impl Fn(SocketAddr) -> ConnectFuture {
    move |address: SocketAddr| {
        calls.lock().expect("calls lock").push(address);
        if silent.contains(&address) {
            Box::pin(std::future::pending::<Result<Session, NetworkError>>()) as ConnectFuture
        } else {
            let taken = session.lock().expect("session lock").take();
            let completions = Arc::clone(&completions);
            Box::pin(async move {
                tokio::task::yield_now().await;
                completions.lock().expect("completions lock").push(address);
                Ok(taken.expect("one stored loopback session"))
            }) as ConnectFuture
        }
    }
}

fn empty_seam() -> impl Fn(SocketAddr) -> ConnectFuture {
    |_| Box::pin(std::future::pending::<Result<Session, NetworkError>>()) as ConnectFuture
}

const ATTEMPT_BOUND: Duration = EXCHANGE_BUDGET.saturating_add(PROBE_WINDOW);

#[tokio::test(start_paused = true)]
async fn both_sides_probe_within_the_bound() {
    let (mut client_link, peer_link) = link_pair();
    let epoch = 5;
    let client_candidates = vec![v4([10, 0, 0, 1], 7777)];
    let answer_candidates = vec![v4([10, 0, 0, 2], 1)];
    let events = Arc::new(Mutex::new(Vec::<(&'static str, u128)>::new()));
    let started = Instant::now();

    // Server task: records offer arrival, answers, starts its own probe seam.
    let server_events = Arc::clone(&events);
    let server_candidates = client_candidates.clone();
    let server_answer = answer_candidates.clone();
    let server = tokio::spawn(async move {
        let mut peer_link = peer_link;
        let raw = peer_link.recv_raw().await.expect("offer received");
        server_events
            .lock()
            .expect("events lock")
            .push(("offer", started.elapsed().as_millis()));
        let offer = decode(&raw).expect("valid offer");
        assert_eq!(offer.kind, Kind::Offer);
        assert_eq!(offer.epoch, epoch);
        assert_eq!(offer.candidates, server_candidates);
        let answer = PunchMessage {
            kind: Kind::Answer,
            epoch,
            candidates: server_answer,
        };
        peer_link
            .send(&answer, EXCHANGE_BUDGET)
            .await
            .expect("answer sent");
        // Server probe seam: records the burst start (real burst is chunk 3).
        server_events
            .lock()
            .expect("events lock")
            .push(("server_probe", started.elapsed().as_millis()));
    });

    let session = Arc::new(Mutex::new(Some(direct_session().await)));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let successes = Arc::new(Mutex::new(Vec::new()));
    let result = client_attempt(
        &mut client_link,
        seam(Arc::clone(&calls), successes, session, vec![]),
        client_candidates.clone(),
        epoch,
        started + ATTEMPT_BOUND,
        "client",
    )
    .await;
    server.await.expect("server task");

    let events = events.lock().expect("events lock").clone();
    assert_eq!(events.len(), 2, "offer arrival and server probe recorded");
    assert_eq!(events[0].0, "offer");
    assert_eq!(events[1].0, "server_probe");
    for (_, at) in &events {
        assert!(*at <= PROBE_WINDOW.as_millis(), "within the burst window");
    }
    let dialed = calls.lock().expect("calls lock").clone();
    assert_eq!(dialed, answer_candidates, "client probed the answer");
    assert!(result.is_some(), "direct session won");
    let elapsed = started.elapsed();
    assert!(
        elapsed <= ATTEMPT_BOUND,
        "total elapsed {elapsed:?} within documented bound"
    );
}

#[tokio::test(start_paused = true)]
async fn burst_stops_on_first_success() {
    let (mut client_link, peer_link) = link_pair();
    let first = v4([10, 0, 0, 2], 1);
    let second = v4([10, 0, 0, 3], 1);
    let server = tokio::spawn(async move {
        let mut peer_link = peer_link;
        let raw = peer_link.recv_raw().await.expect("offer received");
        let offer = decode(&raw).expect("valid offer");
        peer_link
            .send(
                &PunchMessage {
                    kind: Kind::Answer,
                    epoch: offer.epoch,
                    candidates: vec![first, second],
                },
                EXCHANGE_BUDGET,
            )
            .await
            .expect("answer sent");
    });

    let session = Arc::new(Mutex::new(Some(direct_session().await)));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let successes = Arc::new(Mutex::new(Vec::new()));
    let result = client_attempt(
        &mut client_link,
        seam(calls, Arc::clone(&successes), session, vec![second]),
        vec![],
        9,
        Instant::now() + ATTEMPT_BOUND,
        "client",
    )
    .await;
    server.await.expect("server task");

    // Probe futures are built eagerly, but only the first candidate completes;
    // the hanging second is dropped without ever completing.
    let completed = successes.lock().expect("successes lock").clone();
    assert_eq!(completed, vec![first], "exactly one connect completed");
    assert!(result.is_some());
}

#[tokio::test(start_paused = true)]
async fn budget_exhaustion_without_answer_is_exact() {
    let (mut client_link, _peer_link) = link_pair();
    let started = Instant::now();
    let result = client_attempt(
        &mut client_link,
        empty_seam(),
        vec![v4([10, 0, 0, 1], 7777)],
        1,
        started + ATTEMPT_BOUND,
        "client",
    )
    .await;
    assert!(result.is_none());
    assert_eq!(started.elapsed(), EXCHANGE_BUDGET, "exact virtual time");
}

#[tokio::test(start_paused = true)]
async fn burst_window_bounds_hanging_probes() {
    let (mut client_link, peer_link) = link_pair();
    let server = tokio::spawn(async move {
        let mut peer_link = peer_link;
        let raw = peer_link.recv_raw().await.expect("offer received");
        let offer = decode(&raw).expect("valid offer");
        peer_link
            .send(
                &PunchMessage {
                    kind: Kind::Answer,
                    epoch: offer.epoch,
                    candidates: vec![v4([10, 0, 0, 2], 1)],
                },
                EXCHANGE_BUDGET,
            )
            .await
            .expect("answer sent");
    });
    let started = Instant::now();
    let result = client_attempt(
        &mut client_link,
        empty_seam(),
        vec![],
        2,
        started + ATTEMPT_BOUND,
        "client",
    )
    .await;
    server.await.expect("server task");
    assert!(result.is_none());
    assert_eq!(started.elapsed(), PROBE_WINDOW, "bounded by the window");
}

#[tokio::test(start_paused = true)]
async fn link_closed_returns_immediately() {
    let (mut client_link, peer_link) = link_pair();
    // The peer drops its whole half: the client's receive end closes at once.
    let FakeLink { tx, rx } = peer_link;
    drop((tx, rx));
    let started = Instant::now();
    let result = client_attempt(
        &mut client_link,
        empty_seam(),
        vec![],
        3,
        started + ATTEMPT_BOUND,
        "client",
    )
    .await;
    assert!(result.is_none());
    assert_eq!(started.elapsed(), Duration::ZERO, "no wait at all");
}

#[tokio::test(start_paused = true)]
async fn malformed_datagram_is_discarded_and_attempt_succeeds() {
    let (mut client_link, peer_link) = link_pair();
    let server = tokio::spawn(async move {
        let mut peer_link = peer_link;
        let raw = peer_link.recv_raw().await.expect("offer received");
        let offer = decode(&raw).expect("valid offer");
        peer_link.tx.send(vec![0u8; 7]).await.expect("garbage sent");
        peer_link
            .send(
                &PunchMessage {
                    kind: Kind::Answer,
                    epoch: offer.epoch,
                    candidates: vec![v4([10, 0, 0, 2], 1)],
                },
                EXCHANGE_BUDGET,
            )
            .await
            .expect("answer sent");
    });
    let session = Arc::new(Mutex::new(Some(direct_session().await)));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let successes = Arc::new(Mutex::new(Vec::new()));
    let result = client_attempt(
        &mut client_link,
        seam(calls, successes, session, vec![]),
        vec![],
        4,
        Instant::now() + ATTEMPT_BOUND,
        "client",
    )
    .await;
    server.await.expect("server task");
    assert!(result.is_some(), "malformed input never aborts the attempt");
}

#[tokio::test(start_paused = true)]
async fn stale_epoch_answer_is_discarded_to_the_budget_path() {
    let (mut client_link, peer_link) = link_pair();
    let server = tokio::spawn(async move {
        let mut peer_link = peer_link;
        let raw = peer_link.recv_raw().await.expect("offer received");
        let offer = decode(&raw).expect("valid offer");
        peer_link
            .send(
                &PunchMessage {
                    kind: Kind::Answer,
                    epoch: offer.epoch + 1,
                    candidates: vec![v4([203, 0, 113, 10], 1)],
                },
                EXCHANGE_BUDGET,
            )
            .await
            .expect("stale answer sent");
        // Nothing further: the client must fall to budget exhaustion.
        std::future::pending::<()>().await;
    });
    let started = Instant::now();
    let result = client_attempt(
        &mut client_link,
        empty_seam(),
        vec![],
        6,
        started + ATTEMPT_BOUND,
        "client",
    )
    .await;
    server.abort();
    assert!(result.is_none());
    assert_eq!(started.elapsed(), EXCHANGE_BUDGET, "budget path");
}
