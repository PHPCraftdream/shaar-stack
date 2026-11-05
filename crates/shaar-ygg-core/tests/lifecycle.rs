#![forbid(unsafe_code)]
//! Leaf 53.2 quiescence tests: repeated create/listen/close must cancel and
//! join every library-spawned task and release the core and its port.
//!
//! Observation contract (docs/plans/v1-focus.md, leaf 53.2): `close()` finishes
//! under a timeout, the runtime's alive-task count returns to zero (the test
//! body runs under `block_on`, so it is not a counted task), a retained
//! `Weak<Core>` stops upgrading after the caller drops its `Arc`, and the same
//! loopback port binds again.

use std::net::TcpListener;
use std::sync::{Arc, Weak};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use yggdrasil::config::Config;
use yggdrasil::core::Core;
use yggdrasil::links::PeerEvent;

const POLL_STEP: Duration = Duration::from_millis(20);
const POLL_BUDGET: Duration = Duration::from_secs(5);
const CLOSE_BUDGET: Duration = Duration::from_secs(10);
const CONNECT_BUDGET: Duration = Duration::from_secs(10);
/// Datagrams sent at a receiver that never reads (queue capacity is 512).
const FLOOD_MESSAGES: usize = 4096;
const FLOOD_STALL: Duration = Duration::from_millis(100);
const FLOOD_SETTLE: Duration = Duration::from_millis(300);
/// Fixed in-repo test seeds; never production keys.
const CORE_SEED: [u8; 32] = [0x53; 32];
const PEER_SEED: [u8; 32] = [0x54; 32];

fn test_core(seed: &[u8; 32]) -> Arc<Core> {
    Core::new(SigningKey::from_bytes(seed), Config::default())
}

/// Reserve an ephemeral loopback port and release it. Upstream `listen` does
/// not report the bound port, so the test reserves one first.
fn reserve_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("reserve probe listener on loopback");
    let port = listener.local_addr().expect("probe local addr").port();
    drop(listener);
    port
}

async fn listen_on_reserved_port(core: &Core) -> u16 {
    for _ in 0..50 {
        let port = reserve_port();
        if core
            .listen(&format!("tcp://127.0.0.1:{port}"))
            .await
            .is_ok()
        {
            return port;
        }
        tokio::time::sleep(POLL_STEP).await;
    }
    panic!("could not listen on a freshly reserved loopback port after retries");
}

/// Poll `made` until it holds true before `POLL_BUDGET` elapses.
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

/// No task spawned by the core stack may outlive `close()` and the final drop.
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

/// Bounded retry for rebinding a just-released port (rare TIME_WAIT overlap).
async fn assert_port_rebinds(port: u16) {
    let mut last: Option<std::io::Error> = None;
    for _ in 0..250 {
        match TcpListener::bind(("127.0.0.1", port)) {
            Ok(listener) => {
                drop(listener);
                return;
            }
            Err(err) => last = Some(err),
        }
        tokio::time::sleep(POLL_STEP).await;
    }
    panic!("loopback port {port} did not bind again within the poll budget: {last:?}");
}

/// Three create/listen/close cycles in one process: quiescence after each close.
#[tokio::test]
async fn repeated_create_listen_close_releases_core_and_port() {
    for cycle in 1..=3 {
        let core = test_core(&CORE_SEED);
        core.init_links().await;
        let weak: Weak<Core> = Arc::downgrade(&core);
        let port = listen_on_reserved_port(&core).await;

        let closed = tokio::time::timeout(CLOSE_BUDGET, core.close()).await;
        assert!(
            closed.is_ok(),
            "cycle {cycle}: close() did not finish within {CLOSE_BUDGET:?}"
        );
        let outcome = closed.expect("timeout checked above");
        assert!(
            outcome.is_ok(),
            "cycle {cycle}: close() failed: {:?}",
            outcome.err()
        );

        assert_eq!(
            Arc::strong_count(&core),
            1,
            "cycle {cycle}: a strong reference to the core outlived close()"
        );
        drop(core);
        poll_until(
            &format!("cycle {cycle}: Weak<Core> still upgrades after close and drop; a strong reference to the core leaked"),
            || weak.upgrade().is_none(),
        )
        .await;
        assert_no_alive_tasks(&format!("cycle {cycle}")).await;
        assert_port_rebinds(port).await;
    }
}

/// A second close must return promptly without panicking or failing.
#[tokio::test]
async fn second_close_returns_promptly_and_succeeds() {
    let core = test_core(&CORE_SEED);
    core.init_links().await;
    close_within(&core, "first").await;
    close_within(&core, "second").await;
}

/// Concurrent closes are serialized: both return only after shutdown finished.
#[tokio::test]
async fn concurrent_close_calls_both_observe_completed_shutdown() {
    let core = test_core(&CORE_SEED);
    core.init_links().await;
    let port = listen_on_reserved_port(&core).await;

    let both = tokio::time::timeout(CLOSE_BUDGET, async {
        tokio::join!(core.close(), core.close())
    })
    .await;
    assert!(
        both.is_ok(),
        "concurrent close() calls did not finish within {CLOSE_BUDGET:?}"
    );
    let (first, second) = both.expect("timeout checked above");
    assert!(
        first.is_ok(),
        "first concurrent close() failed: {:?}",
        first.err()
    );
    assert!(
        second.is_ok(),
        "second concurrent close() failed: {:?}",
        second.err()
    );
    assert_eq!(
        Arc::strong_count(&core),
        1,
        "a strong reference to the core outlived close()"
    );
    assert_port_rebinds(port).await;
}

/// Close one core under a timeout and require success.
async fn close_within(core: &Core, who: &str) {
    let closed = tokio::time::timeout(CLOSE_BUDGET, core.close()).await;
    assert!(
        closed.is_ok(),
        "{who} close() did not finish within {CLOSE_BUDGET:?}"
    );
    let outcome = closed.expect("timeout checked above");
    assert!(outcome.is_ok(), "{who} close() failed: {:?}", outcome.err());
}

/// Start a listening core and a dialing core and wait until they are connected.
async fn connected_pair() -> (Arc<Core>, Arc<Core>, u16) {
    let listener = test_core(&CORE_SEED);
    listener.init_links().await;
    let port = listen_on_reserved_port(&listener).await;

    let dialer = test_core(&PEER_SEED);
    dialer.init_links().await;

    // Subscribe before dialing so the Connected event cannot be missed.
    let mut events = listener.subscribe_peer_events();
    dialer
        .add_peer(&format!("tcp://127.0.0.1:{port}"))
        .await
        .expect("add loopback peer");
    let connected = tokio::time::timeout(CONNECT_BUDGET, async {
        loop {
            let event = events.recv().await.expect("peer event stream stays open");
            if matches!(event, PeerEvent::Connected { .. }) {
                break;
            }
        }
    })
    .await;
    assert!(
        connected.is_ok(),
        "loopback peering did not connect within {CONNECT_BUDGET:?}"
    );
    (listener, dialer, port)
}

/// A receiver that never reads must still close: the reader blocked delivering
/// into a full receive queue is cancelled by `close()` (leaf 53.2b regression).
#[tokio::test]
async fn close_returns_while_the_receive_queue_is_full() {
    let (listener, dialer, port) = connected_pair().await;
    let destination = ironwood::Addr(*listener.public_key());
    let payload = [0xA5u8; 64];

    // Flood the listener, which never calls `read_from`; a write that stalls
    // means backpressure reached the sender, so stop there. The queue holds 512.
    for _ in 0..FLOOD_MESSAGES {
        let write =
            tokio::time::timeout(FLOOD_STALL, dialer.write_to(&payload, &destination)).await;
        if write.is_err() {
            break;
        }
    }
    tokio::time::sleep(FLOOD_SETTLE).await;

    close_within(&listener, "full-queue listener").await;
    close_within(&dialer, "dialer").await;
    drop(listener);
    drop(dialer);
    assert_no_alive_tasks("full queue").await;
    assert_port_rebinds(port).await;
}

/// Join two cores over loopback, close them in the requested order and require
/// that both are released, no task survives and the listening port binds again.
async fn two_cores_release_after_both_close(listener_first: bool) {
    let (listener, dialer, port) = connected_pair().await;
    let weak_listener: Weak<Core> = Arc::downgrade(&listener);
    let weak_dialer: Weak<Core> = Arc::downgrade(&dialer);

    if listener_first {
        close_within(&listener, "listener").await;
        close_within(&dialer, "dialer").await;
    } else {
        close_within(&dialer, "dialer").await;
        close_within(&listener, "listener").await;
    }
    assert_eq!(
        Arc::strong_count(&listener),
        1,
        "a strong reference to the listener core outlived close()"
    );
    assert_eq!(
        Arc::strong_count(&dialer),
        1,
        "a strong reference to the dialer core outlived close()"
    );
    drop(listener);
    drop(dialer);
    poll_until(
        "listener Weak<Core> still upgrades after close and drop",
        || weak_listener.upgrade().is_none(),
    )
    .await;
    poll_until(
        "dialer Weak<Core> still upgrades after close and drop",
        || weak_dialer.upgrade().is_none(),
    )
    .await;
    assert_no_alive_tasks("two cores").await;
    assert_port_rebinds(port).await;
}

#[tokio::test]
async fn two_cores_release_when_listener_closes_first() {
    two_cores_release_after_both_close(true).await;
}

/// The dialer's reconnect task sits inside a live connection; close must abort it.
#[tokio::test]
async fn two_cores_release_when_dialer_closes_first() {
    two_cores_release_after_both_close(false).await;
}
