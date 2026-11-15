//! Unit tests for the peer-claimed probe gate (leaf L4 review Finding 2):
//! the pure denial predicate and the client probe gate (the responder-side
//! gate tests live next to `serve_peer`). Owns a small fake `PunchLink`
//! over tokio mpsc channels; `punch_tests.rs` items are private to that
//! module and are NOT reused.
//! The success path needs one real loopback QUIC session (see
//! `direct_session`, replicated from `punch_tests.rs` as written there).

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use iroh_base::PublicKey;
use tokio::sync::mpsc;
use tokio::time::Instant;

use super::{
    EXCHANGE_BUDGET, Kind, NetworkError, PROBE_WINDOW, PunchLink, PunchMessage, Session,
    client_attempt, decode, encode, peer_claimed_probe_allowed, peer_claimed_probe_denied,
};

fn v4(a: [u8; 4], port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(a)), port)
}

fn v6(s: &str, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(s.parse().unwrap()), port)
}

fn loopback_addr() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn public(identity: &crate::identity::Identity) -> PublicKey {
    identity.transport_key().public()
}

/// One real handshaken loopback session; replicated from `punch_tests.rs`
/// (its items are private to that module).
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

// ------------------------------------------------------------- predicate ----

/// The production denial set: special-use ranges a peer merely CLAIMS must
/// never become server probe targets; private LAN stays allowed.
#[test]
fn production_filter_denies_special_ranges_and_allows_private_lan() {
    let denied = [
        "127.0.0.1:1",
        "[::1]:1",
        "0.0.0.0:1",
        "[::]:1",
        "224.0.0.1:1",
        "[ff02::1]:1",
        "255.255.255.255:1",
        "169.254.9.9:1",
        "[fe80::1]:1",
        "203.0.113.10:1",
        "198.51.100.9:1",
        "192.0.2.9:1",
        "[2001:db8::1]:1",
        "[fd15:70a:51b::1]:1",
    ];
    for raw in denied {
        let address: SocketAddr = raw.parse().unwrap();
        assert!(
            peer_claimed_probe_denied(address.ip().to_canonical()),
            "denied: {raw}"
        );
    }
    let allowed = [
        "10.1.2.3:1",
        "192.168.1.1:1",
        "172.16.5.5:1",
        "100.64.0.1:1",
        "8.8.8.8:53",
        "[2001:db7::1]:1",
    ];
    for raw in allowed {
        let address: SocketAddr = raw.parse().unwrap();
        assert!(
            !peer_claimed_probe_denied(address.ip().to_canonical()),
            "allowed: {raw}"
        );
    }
}

// ------------------------------------------------------------ serve_peer ----

/// Fake link over bounded mpsc channels: `tx` carries the datagrams this side
/// sends, `rx` the datagrams fed to it.
struct FakeLink {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
}

impl PunchLink for FakeLink {
    async fn send(&self, message: &PunchMessage, _budget: Duration) -> Result<(), ()> {
        let bytes = encode(message).ok_or(())?;
        self.tx.send(bytes).await.map_err(|_| ())
    }

    async fn recv_raw(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }
}

// ---------------------------------------------------------- client gate ----

/// Connect seam type: records dialed addresses, yields stored sessions.
type ConnectFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Session, NetworkError>>>>;

/// The client gate mirrors the server gate on ANSWERED candidates: the
/// link-local candidate is never probed, while loopback (allowed only in
/// test builds) and private LAN are both probed. Probe futures are created
/// eagerly for every gated-in candidate, so both allowed addresses are
/// recorded even though only the loopback connect ever completes.
#[tokio::test(start_paused = true)]
async fn client_probes_skip_link_local_but_keep_loopback_and_private_lan_under_test_gate() {
    let (a_tx, b_rx) = mpsc::channel(8);
    let (b_tx, a_rx) = mpsc::channel(8);
    let mut client_link = FakeLink { tx: a_tx, rx: a_rx };
    let mut peer_link = FakeLink { tx: b_tx, rx: b_rx };
    let answer_candidates = vec![
        v4([169, 254, 9, 9], 4433),
        v4([127, 0, 0, 1], 4433),
        v4([10, 0, 0, 1], 4433),
    ];
    // Peer half: answer the offer with the mixed candidate set.
    let answer = PunchMessage {
        kind: Kind::Answer,
        epoch: 3,
        candidates: answer_candidates,
    };
    tokio::spawn(async move {
        let raw = peer_link.recv_raw().await.expect("offer received");
        let offer = decode(&raw).expect("valid offer");
        peer_link
            .send(
                &PunchMessage {
                    kind: Kind::Answer,
                    epoch: offer.epoch,
                    candidates: answer.candidates,
                },
                EXCHANGE_BUDGET,
            )
            .await
            .expect("answer sent");
    });

    let calls = Arc::new(Mutex::new(Vec::<SocketAddr>::new()));
    let loopback = v4([127, 0, 0, 1], 4433);
    let private = v4([10, 0, 0, 1], 4433);
    let silent = vec![private];
    let calls_for_seam = Arc::clone(&calls);
    let session = Arc::new(Mutex::new(Some(direct_session().await)));
    let connect = move |address: SocketAddr| {
        calls_for_seam.lock().expect("calls lock").push(address);
        if silent.contains(&address) {
            Box::pin(std::future::pending::<Result<Session, NetworkError>>()) as ConnectFuture
        } else {
            let taken = session.lock().expect("session lock").take();
            Box::pin(async move {
                tokio::task::yield_now().await;
                Ok(taken.expect("one stored loopback session"))
            }) as ConnectFuture
        }
    };
    let started = Instant::now();
    let result = client_attempt(
        &mut client_link,
        connect,
        vec![],
        3,
        started + EXCHANGE_BUDGET + PROBE_WINDOW,
        "client",
    )
    .await;
    let dialed = calls.lock().expect("calls lock").clone();
    let mut sorted = dialed.clone();
    sorted.sort();
    assert_eq!(
        sorted,
        vec![loopback, private],
        "exactly the gated-in candidates were probed (eagerly), link-local never"
    );
    assert!(result.is_some(), "loopback connect completed the burst");
}

// Port zero is never a probe target, even for loopback under the test gate.
#[test]
fn loopback_port_zero_is_denied_even_under_test_gate() {
    assert!(!peer_claimed_probe_allowed(v6("::1", 0)));
    assert!(peer_claimed_probe_allowed(v6("::1", 1)));
}
