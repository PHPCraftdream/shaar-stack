//! Loopback fixtures shared by the product-crate tests.

use std::net::TcpListener;
use std::time::Duration;

use crate::{YggConfig, YggError, YggTransport};

pub(crate) const STEP: Duration = Duration::from_millis(20);
pub(crate) const BUDGET: Duration = Duration::from_secs(10);

pub(crate) fn config(seed: u8, listen: Vec<String>, peers: Vec<String>) -> YggConfig {
    YggConfig {
        seed: [seed; 32],
        listen,
        peers,
        allowed_public_keys: Vec::new(),
        group_password: None,
    }
}

fn reserve_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("reserve a loopback port");
    let port = listener.local_addr().expect("local address").port();
    drop(listener);
    port
}

/// Start a listening transport on a free loopback port, retrying on a lost race.
pub(crate) async fn start_listener(seed: u8) -> (YggTransport, u16) {
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

/// Start a transport that dials the listener on `port`.
pub(crate) async fn start_dialer(seed: u8, port: u16) -> YggTransport {
    let uri = format!("tcp://127.0.0.1:{port}");
    YggTransport::start(config(seed, vec![], vec![uri]))
        .await
        .expect("dialer starts")
}

pub(crate) async fn close_within(transport: &YggTransport, who: &str) {
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

pub(crate) async fn poll_until(observation: &str, mut made: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + BUDGET;
    while tokio::time::Instant::now() < deadline {
        if made() {
            return;
        }
        tokio::time::sleep(STEP).await;
    }
    panic!("observation not reached within {BUDGET:?}: {observation}");
}
