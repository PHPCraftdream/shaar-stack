#![forbid(unsafe_code)]
//! Leaf 53.3 exchange tests: two transports on loopback exchange datagrams by
//! peer key. Datagrams are unreliable by contract, so the load is paced.

use std::collections::HashSet;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use shaar_ygg_core::{YggConfig, YggError, YggTransport, address_for_key};

const POLL_STEP: Duration = Duration::from_millis(20);
const POLL_BUDGET: Duration = Duration::from_secs(5);

/// Each test uses its own key pair: the process-wide key registry refuses two
/// live transports on one key and the tests run in parallel threads.
fn seed(role: u8, tag: u8) -> [u8; 32] {
    [(role << 4) | tag; 32]
}
const PROBE: &[u8] = b"probe";
const PATH_BUDGET: Duration = Duration::from_secs(10);
const RECV_BUDGET: Duration = Duration::from_secs(5);
const LOAD_BUDGET: Duration = Duration::from_secs(20);
const CLOSE_BUDGET: Duration = Duration::from_secs(10);
const QUIET: Duration = Duration::from_millis(300);
const PACE: Duration = Duration::from_millis(2);
const PER_SENDER: usize = 25;
const RACE_ROUNDS: u8 = 20;
const INTRUDER_WINDOW: Duration = Duration::from_secs(3);

fn config(seed: [u8; 32], listen: Vec<String>, peers: Vec<String>) -> YggConfig {
    YggConfig {
        seed,
        listen,
        peers,
        allowed_public_keys: Vec::new(),
        group_password: None,
    }
}

struct Pair {
    listener: Arc<YggTransport>,
    dialer: Arc<YggTransport>,
    port: u16,
}

/// Start a listening and a dialing transport and wait until a datagram flows
/// in both directions (path discovery takes time; early writes are accepted
/// but not delivered).
async fn start_pair(tag: u8) -> Pair {
    start_pair_with(tag, false).await
}

fn public_key_of(seed: [u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(&seed).verifying_key().to_bytes()
}

/// With `restrict`, the listener only accepts the dialer's key.
async fn start_pair_with(tag: u8, restrict: bool) -> Pair {
    let mut started = None;
    for _ in 0..50 {
        let port = reserve_port();
        let uri = format!("tcp://127.0.0.1:{port}");
        let mut listener_config = config(seed(1, tag), vec![uri], vec![]);
        if restrict {
            listener_config.allowed_public_keys = vec![public_key_of(seed(2, tag))];
        }
        match YggTransport::start(listener_config).await {
            Ok(listener) => {
                started = Some((listener, port));
                break;
            }
            Err(YggError::Start { .. }) => tokio::time::sleep(POLL_STEP).await,
            Err(other) => panic!("listener start failed: {other}"),
        }
    }
    let (listener, port) = started.expect("listener bound a reserved port");
    let peer_uri = format!("tcp://127.0.0.1:{port}");
    let dialer = YggTransport::start(config(seed(2, tag), vec![], vec![peer_uri]))
        .await
        .expect("dialer starts");
    let pair = Pair {
        listener: Arc::new(listener),
        dialer: Arc::new(dialer),
        port,
    };
    wait_for_path(&pair.dialer, &pair.listener).await;
    wait_for_path(&pair.listener, &pair.dialer).await;
    pair
}

async fn wait_for_path(sender: &YggTransport, receiver: &YggTransport) {
    let key = receiver.public_key();
    let mut buffer = vec![0u8; receiver.mtu() + 1];
    let deadline = tokio::time::Instant::now() + PATH_BUDGET;
    loop {
        let _ = tokio::time::timeout(Duration::from_secs(1), sender.send_to(&key, PROBE)).await;
        let read = tokio::time::timeout(Duration::from_secs(1), receiver.recv(&mut buffer)).await;
        if matches!(read, Ok(Ok(_))) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no datagram reached the receiver within {PATH_BUDGET:?}"
        );
    }
}

/// Next datagram that is not a path-discovery probe.
async fn recv_data(transport: &YggTransport) -> (Vec<u8>, [u8; 32]) {
    let mut buffer = vec![0u8; transport.mtu() + 1];
    loop {
        let (len, from) = transport.recv(&mut buffer).await.expect("recv succeeds");
        if &buffer[..len] != PROBE {
            return (buffer[..len].to_vec(), from);
        }
    }
}

async fn recv_data_within(
    transport: &YggTransport,
    budget: Duration,
) -> Option<(Vec<u8>, [u8; 32])> {
    tokio::time::timeout(budget, recv_data(transport))
        .await
        .ok()
}

/// Close both transports and require quiescence: no core reference, no task, free port.
async fn finish(pair: Pair) {
    let Pair {
        listener,
        dialer,
        port,
    } = pair;
    for (who, transport) in [("listener", &listener), ("dialer", &dialer)] {
        let closed = tokio::time::timeout(CLOSE_BUDGET, transport.close()).await;
        assert!(
            closed.is_ok(),
            "{who} close() did not finish within {CLOSE_BUDGET:?}"
        );
        let outcome = closed.expect("timeout checked above");
        assert!(outcome.is_ok(), "{who} close() failed: {:?}", outcome.err());
    }
    assert_eq!(
        Arc::strong_count(&listener),
        1,
        "listener transport still shared"
    );
    assert_eq!(
        Arc::strong_count(&dialer),
        1,
        "dialer transport still shared"
    );
    drop(listener);
    drop(dialer);
    assert_no_alive_tasks("transport pair").await;
    assert_port_rebinds(port).await;
}

#[tokio::test]
async fn datagrams_flow_both_ways_addressed_by_key() {
    let pair = start_pair(1).await;
    let (listener_key, dialer_key) = (pair.listener.public_key(), pair.dialer.public_key());
    assert_ne!(
        listener_key, dialer_key,
        "fixed seeds give distinct identities"
    );

    pair.dialer
        .send_to(&listener_key, b"ping")
        .await
        .expect("dialer sends");
    let (payload, from) = recv_data_within(&pair.listener, RECV_BUDGET)
        .await
        .expect("listener receives the ping");
    assert_eq!(payload, b"ping");
    assert_eq!(from, dialer_key, "recv reports the sender key");

    pair.listener
        .send_to(&dialer_key, b"pong")
        .await
        .expect("listener replies");
    let (payload, from) = recv_data_within(&pair.dialer, RECV_BUDGET)
        .await
        .expect("dialer receives the pong");
    assert_eq!(payload, b"pong");
    assert_eq!(from, listener_key, "recv reports the sender key");
    finish(pair).await;
}

#[tokio::test]
async fn payloads_up_to_the_mtu_arrive_intact() {
    let pair = start_pair(2).await;
    let listener_key = pair.listener.public_key();
    let mtu = pair.dialer.mtu();
    assert!(mtu >= 1000, "mtu {mtu} must fit the 1000-byte case");
    for len in [1usize, 1000, mtu] {
        let payload: Vec<u8> = (0..len).map(|index| (index % 251) as u8).collect();
        pair.dialer
            .send_to(&listener_key, &payload)
            .await
            .expect("send within mtu");
        let (received, _) = recv_data_within(&pair.listener, RECV_BUDGET)
            .await
            .unwrap_or_else(|| panic!("a {len}-byte datagram was not delivered"));
        assert_eq!(received, payload, "a {len}-byte datagram changed in flight");
    }
    finish(pair).await;
}

#[tokio::test]
async fn payload_above_the_mtu_is_rejected_before_sending() {
    let pair = start_pair(3).await;
    let listener_key = pair.listener.public_key();
    let mtu = pair.dialer.mtu();
    let oversize = vec![0x5au8; mtu + 1];
    let outcome = pair.dialer.send_to(&listener_key, &oversize).await;
    assert_eq!(outcome, Err(YggError::Oversize { len: mtu + 1, mtu }));
    assert!(
        recv_data_within(&pair.listener, QUIET).await.is_none(),
        "an oversize payload must not reach the receiver"
    );
    finish(pair).await;
}

#[tokio::test]
async fn receive_buffer_below_mtu_plus_one_is_rejected() {
    let pair = start_pair(4).await;
    let mtu = pair.listener.mtu();
    let mut small = vec![0u8; mtu];
    let outcome = pair.listener.recv(&mut small).await;
    assert_eq!(
        outcome,
        Err(YggError::BufferTooSmall {
            len: mtu,
            needed: mtu + 1
        })
    );
    finish(pair).await;
}

async fn send_paced(from: Arc<YggTransport>, to: [u8; 32], tag: u8) {
    for sequence in 0..PER_SENDER {
        from.send_to(&to, &[tag, sequence as u8])
            .await
            .expect("paced send");
        tokio::time::sleep(PACE).await;
    }
}

async fn collect(at: Arc<YggTransport>, from_key: [u8; 32], expected: usize) -> HashSet<(u8, u8)> {
    let mut seen = HashSet::new();
    while seen.len() < expected {
        let (payload, from) = recv_data(&at).await;
        assert_eq!(from, from_key, "datagram attributed to the wrong key");
        assert_eq!(payload.len(), 2, "datagram length changed in flight");
        seen.insert((payload[0], payload[1]));
    }
    seen
}

fn expected_set(senders: u8) -> HashSet<(u8, u8)> {
    (0..senders)
        .flat_map(|tag| (0..PER_SENDER).map(move |sequence| (tag, sequence as u8)))
        .collect()
}

#[tokio::test]
async fn concurrent_senders_and_receivers_deliver_every_paced_datagram() {
    let pair = start_pair(5).await;
    let (listener_key, dialer_key) = (pair.listener.public_key(), pair.dialer.public_key());
    let mut senders = Vec::new();
    for tag in 0..4u8 {
        senders.push(tokio::spawn(send_paced(
            pair.dialer.clone(),
            listener_key,
            tag,
        )));
    }
    for tag in 0..2u8 {
        senders.push(tokio::spawn(send_paced(
            pair.listener.clone(),
            dialer_key,
            tag,
        )));
    }
    let at_listener = tokio::spawn(collect(pair.listener.clone(), dialer_key, 4 * PER_SENDER));
    let at_dialer = tokio::spawn(collect(pair.dialer.clone(), listener_key, 2 * PER_SENDER));

    let listener_got = tokio::time::timeout(LOAD_BUDGET, at_listener)
        .await
        .expect("listener collected every datagram in time")
        .expect("listener collector finished");
    let dialer_got = tokio::time::timeout(LOAD_BUDGET, at_dialer)
        .await
        .expect("dialer collected every datagram in time")
        .expect("dialer collector finished");
    for sender in senders {
        sender.await.expect("sender task finished");
    }
    assert_eq!(listener_got, expected_set(4));
    assert_eq!(dialer_got, expected_set(2));
    finish(pair).await;
}

#[tokio::test]
async fn a_dropped_recv_future_loses_no_datagram() {
    let pair = start_pair(6).await;
    let listener_key = pair.listener.public_key();
    while recv_data_within(&pair.listener, QUIET).await.is_some() {}

    let mut buffer = vec![0u8; pair.listener.mtu() + 1];
    let idle =
        tokio::time::timeout(Duration::from_millis(100), pair.listener.recv(&mut buffer)).await;
    assert!(
        idle.is_err(),
        "nothing was sent, so the receive must stay pending"
    );

    pair.dialer
        .send_to(&listener_key, b"after-cancel")
        .await
        .expect("send");
    let (payload, _) = recv_data_within(&pair.listener, RECV_BUDGET)
        .await
        .expect("a datagram sent after a cancelled recv is delivered");
    assert_eq!(payload, b"after-cancel");
    finish(pair).await;
}

#[tokio::test]
async fn cancelling_receives_with_datagrams_in_flight_loses_none() {
    let pair = start_pair(7).await;
    let listener_key = pair.listener.public_key();
    while recv_data_within(&pair.listener, QUIET).await.is_some() {}

    let mut received = HashSet::new();
    for index in 0..RACE_ROUNDS {
        pair.dialer
            .send_to(&listener_key, &[index])
            .await
            .expect("send");
        // Race a receive against an immediate cancellation while the datagram travels.
        tokio::select! {
            biased;
            (payload, _) = recv_data(&pair.listener) => {
                received.insert(payload[0]);
            }
            _ = tokio::task::yield_now() => {}
        }
    }
    while received.len() < usize::from(RACE_ROUNDS) {
        let (payload, _) = recv_data_within(&pair.listener, RECV_BUDGET)
            .await
            .expect("an in-flight datagram was lost by a cancelled receive");
        received.insert(payload[0]);
    }
    assert_eq!(received, (0..RACE_ROUNDS).collect::<HashSet<u8>>());
    finish(pair).await;
}

/// Reserve an ephemeral loopback port and release it; `listen` does not report the port.
fn reserve_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("reserve probe listener");
    let port = listener.local_addr().expect("probe local addr").port();
    drop(listener);
    port
}

/// Poll `made` until it holds before `POLL_BUDGET` elapses.
async fn poll_until(observation: &str, mut made: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + POLL_BUDGET;
    while tokio::time::Instant::now() < deadline {
        if made() {
            return;
        }
        tokio::time::sleep(POLL_STEP).await;
    }
    panic!("observation not reached within {POLL_BUDGET:?}: {observation}");
}

/// No task may outlive `close()` and the final drop (the test body is not a counted task).
async fn assert_no_alive_tasks(context: &str) {
    poll_until(
        &format!("{context}: runtime still reports alive tasks"),
        || {
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks()
                == 0
        },
    )
    .await;
}

/// Bounded retry for rebinding a just-released port.
async fn assert_port_rebinds(port: u16) {
    let mut last: Option<std::io::Error> = None;
    for _ in 0..250 {
        match TcpListener::bind(("127.0.0.1", port)) {
            Ok(listener) => {
                drop(listener);
                return;
            }
            Err(error) => last = Some(error),
        }
        tokio::time::sleep(POLL_STEP).await;
    }
    panic!("loopback port {port} did not bind again within the poll budget: {last:?}");
}

#[tokio::test]
async fn start_rejects_invalid_settings_naming_only_the_field() {
    let mut bad_listen = config(seed(3, 1), vec!["http://127.0.0.1:1".to_string()], vec![]);
    assert_eq!(
        YggTransport::start(bad_listen.clone()).await.err(),
        Some(YggError::InvalidConfig { field: "listen" })
    );
    bad_listen.listen.clear();
    bad_listen.peers = vec!["tcp://secret host:1?password=hunter2".to_string()];
    let error = YggTransport::start(bad_listen.clone())
        .await
        .err()
        .expect("a peer URI with whitespace is rejected");
    assert_eq!(error, YggError::InvalidConfig { field: "peers" });
    let text = format!("{error} {error:?} {bad_listen:?}");
    assert!(!text.contains("hunter2"), "a secret leaked: {text}");

    let mut open = config(seed(3, 1), vec![], vec![]);
    open.group_password = Some(String::new());
    assert_eq!(
        YggTransport::start(open).await.err(),
        Some(YggError::InvalidConfig {
            field: "group_password"
        })
    );
}

#[tokio::test]
async fn a_live_key_cannot_be_started_twice_and_is_free_after_close() {
    let settings = config(seed(3, 2), vec![], vec![]);
    let first = YggTransport::start(settings.clone())
        .await
        .expect("first start");
    assert_eq!(
        YggTransport::start(settings.clone()).await.err(),
        Some(YggError::KeyInUse)
    );
    first.close().await.expect("close");
    let second = YggTransport::start(settings.clone())
        .await
        .expect("the key is free after close");
    first.close().await.expect("a repeated close is harmless");
    assert_eq!(
        YggTransport::start(settings).await.err(),
        Some(YggError::KeyInUse),
        "a repeated close of the old handle must not free the new owner's key"
    );
    second.close().await.expect("close");
}

#[tokio::test]
async fn a_failed_start_releases_its_key() {
    let occupied = TcpListener::bind(("127.0.0.1", 0)).expect("occupy a port");
    let port = occupied.local_addr().expect("local addr").port();
    let taken = config(seed(3, 3), vec![format!("tcp://127.0.0.1:{port}")], vec![]);
    assert_eq!(
        YggTransport::start(taken).await.err(),
        Some(YggError::Start { stage: "listen" })
    );
    let retry = YggTransport::start(config(seed(3, 3), vec![], vec![]))
        .await
        .expect("the key was released by the failed start");
    retry.close().await.expect("close");
    drop(occupied);
}

#[tokio::test]
async fn operations_after_close_report_closed() {
    let transport = YggTransport::start(config(seed(3, 4), vec![], vec![]))
        .await
        .expect("start");
    transport.close().await.expect("close");
    let key = transport.public_key();
    assert_eq!(
        transport.send_to(&key, b"late").await,
        Err(YggError::Closed)
    );
    let mut buffer = vec![0u8; transport.mtu() + 1];
    assert_eq!(transport.recv(&mut buffer).await, Err(YggError::Closed));
    transport.close().await.expect("close stays idempotent");
}

/// The receiver allowlists the dialer only. A third node that dials the same
/// listener must not get a datagram through, while the allowed key still does.
/// The test observes non-delivery within a bounded window, not the mechanism.
#[tokio::test]
async fn a_key_outside_the_allowlist_gets_no_datagram_through() {
    let pair = start_pair_with(3, true).await;
    let listener_key = pair.listener.public_key();
    let intruder_seed = seed(4, 3);
    let intruder_key = public_key_of(intruder_seed);
    let peer_uri = format!("tcp://127.0.0.1:{}", pair.port);
    let intruder = YggTransport::start(config(intruder_seed, vec![], vec![peer_uri]))
        .await
        .expect("intruder starts");

    let deadline = tokio::time::Instant::now() + INTRUDER_WINDOW;
    while tokio::time::Instant::now() < deadline {
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            intruder.send_to(&listener_key, b"intruder"),
        )
        .await;
        if let Some((payload, from)) = recv_data_within(&pair.listener, POLL_STEP * 5).await {
            assert_ne!(
                from, intruder_key,
                "a datagram of the intruder was delivered"
            );
            assert_ne!(payload, b"intruder", "intruder payload was delivered");
        }
    }

    pair.dialer
        .send_to(&listener_key, b"legit")
        .await
        .expect("allowed key sends");
    let (payload, from) = recv_data_within(&pair.listener, RECV_BUDGET)
        .await
        .expect("the allowed key is still delivered");
    assert_eq!(payload, b"legit");
    assert_eq!(from, pair.dialer.public_key());
    intruder.close().await.expect("intruder closes");
    finish(pair).await;
}

#[test]
fn transport_keys_map_to_distinct_stable_addresses() {
    let a = address_for_key(&public_key_of(seed(1, 1)));
    let b = address_for_key(&public_key_of(seed(2, 1)));
    assert_ne!(a, b);
    assert_eq!(a, address_for_key(&public_key_of(seed(1, 1))));
    assert_eq!(a[0], 0x02, "addresses carry the Yggdrasil prefix");
}
