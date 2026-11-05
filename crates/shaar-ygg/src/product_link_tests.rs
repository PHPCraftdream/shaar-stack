//! The product crate exports a working transport: two instances on loopback
//! exchange a datagram by key and close without leaving a task or a socket.

use std::net::TcpListener;
use std::time::Duration;

use crate::YggTransport;
use crate::test_support::{BUDGET, close_within, poll_until, start_dialer, start_listener};

const PROBE: &[u8] = b"probe";

/// Path discovery takes time: wait until a probe datagram is really delivered.
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

async fn recv_data(receiver: &YggTransport) -> (Vec<u8>, [u8; 32]) {
    let mut buffer = vec![0u8; receiver.mtu() + 1];
    loop {
        let (len, from) = receiver.recv(&mut buffer).await.expect("recv succeeds");
        if &buffer[..len] != PROBE {
            return (buffer[..len].to_vec(), from);
        }
    }
}

#[tokio::test]
async fn product_exports_exchange_a_datagram_by_key_and_release_everything() {
    let (listener, port) = start_listener(0x91).await;
    let dialer = start_dialer(0x92, port).await;
    wait_for_path(&dialer, &listener).await;
    wait_for_path(&listener, &dialer).await;

    let listener_key = listener.public_key();
    dialer
        .send_to(&listener_key, b"product-link")
        .await
        .expect("send by key");
    let received = tokio::time::timeout(BUDGET, recv_data(&listener)).await;
    let (payload, from) = received.expect("the datagram arrives in time");
    assert_eq!(payload, b"product-link");
    assert_eq!(from, dialer.public_key(), "recv reports the sender key");

    close_within(&dialer, "dialer").await;
    close_within(&listener, "listener").await;
    drop(dialer);
    drop(listener);
    poll_until("a task of the transport is still alive", || {
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
            == 0
    })
    .await;
    TcpListener::bind(("127.0.0.1", port)).expect("the listening port is free again");
}
