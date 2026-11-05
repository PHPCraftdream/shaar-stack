#![forbid(unsafe_code)]
//! Leaf 53.3 exchange tests: two transports on loopback exchange datagrams by
//! peer key. Datagrams are unreliable by contract, so the load is paced.

use std::collections::HashSet;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use shaar_ygg_core::{YggConfig, YggError, YggTransport};

const POLL_STEP: Duration = Duration::from_millis(20);
const POLL_BUDGET: Duration = Duration::from_secs(5);
const SEED_LISTENER: [u8; 32] = [0x61; 32];
const SEED_DIALER: [u8; 32] = [0x62; 32];
const PROBE: &[u8] = b"probe";
const PATH_BUDGET: Duration = Duration::from_secs(10);
const RECV_BUDGET: Duration = Duration::from_secs(5);
const LOAD_BUDGET: Duration = Duration::from_secs(20);
const CLOSE_BUDGET: Duration = Duration::from_secs(10);
const QUIET: Duration = Duration::from_millis(300);
const PACE: Duration = Duration::from_millis(2);
const PER_SENDER: usize = 25;
const RACE_ROUNDS: u8 = 20;

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
async fn start_pair() -> Pair {
    let mut started = None;
    for _ in 0..50 {
        let port = reserve_port();
        let uri = format!("tcp://127.0.0.1:{port}");
        match YggTransport::start(config(SEED_LISTENER, vec![uri], vec![])).await {
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
    let dialer = YggTransport::start(config(SEED_DIALER, vec![], vec![peer_uri]))
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
    let pair = start_pair().await;
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
    let pair = start_pair().await;
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
    let pair = start_pair().await;
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
    let pair = start_pair().await;
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
    let pair = start_pair().await;
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
    let pair = start_pair().await;
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
    let pair = start_pair().await;
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
