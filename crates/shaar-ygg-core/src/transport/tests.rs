//! Core release observations that need private access to the transport.

use std::net::TcpListener;
use std::sync::{Arc, Weak};
use std::time::Duration;

use super::{YggConfig, YggError, YggTransport};

const STEP: Duration = Duration::from_millis(20);
const BUDGET: Duration = Duration::from_secs(10);
const PROBE: &[u8] = b"probe";

fn config(seed: [u8; 32], listen: Vec<String>, peers: Vec<String>) -> YggConfig {
    YggConfig {
        seed,
        listen,
        peers,
        allowed_public_keys: Vec::new(),
        group_password: None,
    }
}

fn reserve_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("reserve probe listener");
    let port = listener.local_addr().expect("probe local addr").port();
    drop(listener);
    port
}

async fn start_listener(seed: [u8; 32]) -> (YggTransport, u16) {
    for _ in 0..50 {
        let port = reserve_port();
        let uri = format!("tcp://127.0.0.1:{port}");
        match YggTransport::start(config(seed, vec![uri], vec![])).await {
            Ok(transport) => return (transport, port),
            Err(YggError::Start { .. }) => tokio::time::sleep(STEP).await,
            Err(other) => panic!("listener start failed: {other}"),
        }
    }
    panic!("no reserved loopback port could be bound");
}

/// A probe datagram must flow before the pair counts as connected.
async fn wait_for_path(sender: &YggTransport, receiver: &YggTransport) {
    let key = receiver.public_key();
    let mut buffer = vec![0u8; receiver.mtu() + 1];
    let deadline = tokio::time::Instant::now() + BUDGET;
    loop {
        let _ = tokio::time::timeout(Duration::from_secs(1), sender.send_to(&key, PROBE)).await;
        let read = tokio::time::timeout(Duration::from_secs(1), receiver.recv(&mut buffer)).await;
        if matches!(read, Ok(Ok(_))) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no datagram reached the receiver within {BUDGET:?}"
        );
    }
}

async fn assert_core_released(name: &str, weak: Weak<yggdrasil::core::Core>) {
    let deadline = tokio::time::Instant::now() + BUDGET;
    while weak.upgrade().is_some() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{name}: the core is still referenced after close and drop"
        );
        tokio::time::sleep(STEP).await;
    }
}

/// `close()` must break the internal Core/Links cycle on a live connection:
/// after the transport is dropped no strong reference to either core remains.
#[tokio::test]
async fn closing_a_connected_pair_releases_both_cores() {
    let (listener, port) = start_listener([0x71; 32]).await;
    let peer_uri = format!("tcp://127.0.0.1:{port}");
    let dialer = YggTransport::start(config([0x72; 32], vec![], vec![peer_uri]))
        .await
        .expect("dialer starts");
    wait_for_path(&dialer, &listener).await;
    wait_for_path(&listener, &dialer).await;

    let weak_listener = Arc::downgrade(&listener.core);
    let weak_dialer = Arc::downgrade(&dialer.core);
    for (who, transport) in [("listener", &listener), ("dialer", &dialer)] {
        let closed = tokio::time::timeout(BUDGET, transport.close()).await;
        assert!(
            closed.is_ok(),
            "{who} close() did not finish within {BUDGET:?}"
        );
        assert!(
            closed.expect("checked above").is_ok(),
            "{who} close() failed"
        );
    }
    drop(listener);
    drop(dialer);
    assert_core_released("listener", weak_listener).await;
    assert_core_released("dialer", weak_dialer).await;
}
