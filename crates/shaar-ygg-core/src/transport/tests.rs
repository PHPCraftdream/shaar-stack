//! Core release observations that need private access to the transport.

use std::net::TcpListener;
use std::sync::{Arc, Weak};
use std::time::Duration;

use super::{YggConfig, YggError, YggTransport};
use crate::LinksUp;
use crate::phases::Phase;

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

/// The one-shot phases fire at the real boundaries: the core ready at the start, the first datagram
/// handed to the core by the sender, the first one received by the receiver.
#[tokio::test]
async fn one_shot_phases_fire_at_the_start_the_first_send_and_the_first_receive() {
    let (listener, port) = start_listener([0x75; 32]).await;
    let dialer = YggTransport::start(config(
        [0x76; 32],
        vec![],
        vec![format!("tcp://127.0.0.1:{port}")],
    ))
    .await
    .expect("dialer starts");
    for transport in [&listener, &dialer] {
        assert!(transport.phases.has_fired(Phase::CoreReady));
        assert!(!transport.phases.has_fired(Phase::FirstSend));
        assert!(!transport.phases.has_fired(Phase::FirstRecv));
    }
    wait_for_path(&dialer, &listener).await;
    assert!(dialer.phases.has_fired(Phase::FirstSend));
    assert!(listener.phases.has_fired(Phase::FirstRecv));
    for transport in [&listener, &dialer] {
        transport.close().await.expect("close");
    }
}

/// A configured link is reported up by its index once the dial succeeds, a dead peer never
/// counts, and the link is reported down once its peer is gone.
#[tokio::test]
async fn the_link_watch_follows_a_configured_link_up_and_down() {
    let (listener, port) = start_listener([0x73; 32]).await;
    let dead = reserve_port();
    let peers = vec![
        format!("tcp://127.0.0.1:{dead}"),
        format!("tcp://127.0.0.1:{port}"),
    ];
    let dialer = YggTransport::start(config([0x74; 32], vec![], peers))
        .await
        .expect("dialer starts");
    let watch = dialer.link_watch();
    let up = tokio::time::timeout(BUDGET, watch.next(LinksUp::default()))
        .await
        .expect("the live link comes up");
    assert!(
        up.contains(1) && !up.contains(0),
        "the live peer is index 1"
    );
    assert_eq!(up.count(), 1);
    assert_eq!(watch.up().await, up);
    let quiet = tokio::time::timeout(Duration::from_millis(300), watch.next(up)).await;
    assert!(quiet.is_err(), "nothing changed, so nothing is reported");
    listener.close().await.expect("listener closes");
    let down = tokio::time::timeout(BUDGET, watch.next(up))
        .await
        .expect("the link goes down with its peer");
    assert_eq!(down, LinksUp::default());
    drop(watch);
    dialer.close().await.expect("dialer closes");
}

/// A node whose only peer does not answer has no link up, and asking again reports no change.
#[tokio::test]
async fn a_dead_peer_never_counts_as_a_link() {
    let dead = reserve_port();
    let dialer = YggTransport::start(config(
        [0x77; 32],
        vec![],
        vec![format!("tcp://127.0.0.1:{dead}")],
    ))
    .await
    .expect("dialer starts");
    let watch = dialer.link_watch();
    assert_eq!(watch.up().await, LinksUp::default());
    let quiet = tokio::time::timeout(Duration::from_millis(300), watch.next(LinksUp::default()));
    assert!(quiet.await.is_err());
    drop(watch);
    dialer.close().await.expect("dialer closes");
}
