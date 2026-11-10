//! Retained same-identity start oracles on real loopback cores and on
//! deterministic test-only fault seams: identity equality, retained terminal
//! statuses without subscribed waiters, REAL cancellation of borrowed
//! wait/shutdown futures (pinned storage destroyed by an inner scope, not a
//! dropped pin reference), cached success AND error shutdown results,
//! closed-after-failure lifecycle, exact-once transport extraction, real
//! `YggBridge` transfer with ordered cleanup, and key/port reuse.
//!
//! Scheduling facts are observed, not assumed: on `#[tokio::test(flavor =
//! "current_thread")]` a spawned owner provably has NOT run until the test
//! task itself awaits, so a first no-op-waker poll asserting `Pending` is an
//! observed fact, not folklore. Owner completion is observed through real
//! production state (`wait`, the owner join route, the key registry), never
//! through sleep/yield busyloops. The bounded observations are the detached
//! real-owner join and the post-close key-reuse probe, whose subjects (the
//! dropped handle's signal path and asynchronous socket teardown) have no
//! earlier observable.
//!
//! `YggTransport` key claims are process-wide. This test module owns the
//! disjoint 0x81..=0x8D cohort: joined start 0x81/listener 0x82; intentional
//! KeyInUse holder+start 0x83; no-waiter holder+start 0x84; cancelled wait
//! 0x85; cancelled shutdown 0x86; close-fault listener 0x87/start 0x88;
//! post-admission cleanup 0x89; pre-admission owner 0x8A; bridge listener
//! 0x8B/client 0x8C; invalid-peer start 0x8D. Reuse probes mirror owner seeds.
//! The two equal holder/start pairs preserve their intentional KeyInUse oracle.
//!

use std::net::TcpListener;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use shaar_ygg::{YggBridge, YggConfig, YggError, YggTransport};

use crate::identity::Identity;
use crate::startup::{RetainedYggStart, SameIdentityYgg, StartupError, start_ygg_same_identity};

const STEP: Duration = Duration::from_millis(20);
const BUDGET: Duration = Duration::from_secs(10);
const PROBE: Duration = Duration::from_secs(5);

fn local_identity(seed_byte: u8) -> Identity {
    Identity::from_seed([seed_byte; 32])
}

fn infra_config(seed_byte: u8, listen: Vec<String>, peers: Vec<String>) -> YggConfig {
    YggConfig {
        seed: [seed_byte; 32],
        listen,
        peers,
        allowed_public_keys: Vec::new(),
        group_password: None,
    }
}

/// A direct transport on the test's own identity seed: the deterministic
/// key-claim holder for the KeyInUse oracle.
fn local_config(seed_byte: u8) -> YggConfig {
    infra_config(seed_byte, Vec::new(), Vec::new())
}

fn reserve_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("reserve a loopback port");
    listener.local_addr().expect("local address").port()
}

/// Start a listening transport on a free loopback port, retrying on a lost race.
async fn start_listener(seed_byte: u8) -> (YggTransport, u16) {
    for _ in 0..50 {
        let port = reserve_port();
        let uri = format!("tcp://127.0.0.1:{port}");
        match YggTransport::start(infra_config(seed_byte, vec![uri], vec![])).await {
            Ok(transport) => return (transport, port),
            Err(YggError::Start { .. }) => tokio::time::sleep(STEP).await,
            Err(other) => panic!("listener start failed: {other}"),
        }
    }
    panic!("no reserved loopback port could be bound");
}

async fn close_within(transport: &YggTransport, who: &str) {
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

/// Try a direct transport start on `seed` until the process-wide key claim
/// is free again; close the probe immediately. This is the bounded cleanup
/// observation for asynchronous socket teardown, which has no earlier
/// production observable; an interleaving may transiently hold the claim,
/// and both orders converge to the same released-claim contract.
async fn probe_claim_free(seed_byte: u8, who: &str) {
    let deadline = tokio::time::Instant::now() + BUDGET;
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{who}: key claim not released within {BUDGET:?}"
        );
        match YggTransport::start(local_config(seed_byte)).await {
            Ok(probe) => {
                close_within(&probe, who).await;
                return;
            }
            Err(YggError::KeyInUse) => tokio::time::sleep(STEP).await,
            Err(other) => panic!("{who}: probe start failed: {other}"),
        }
    }
}

/// One no-op-waker poll of an already-pinned future. `Pin<&mut F>` is the
/// receiver `Future::poll` actually requires, so the helper compiles for
/// every future without `Unpin` bounds.
fn poll_once<F: std::future::Future>(fut: Pin<&mut F>) -> Poll<F::Output> {
    let mut cx = Context::from_waker(Waker::noop());
    fut.poll(&mut cx)
}

#[tokio::test]
async fn same_identity_start_admits_identity_and_shutdown_closes_and_caches() {
    let (listener, port) = start_listener(0x82).await;
    let identity = local_identity(0x81);
    let peer_uri = format!("tcp://127.0.0.1:{port}");
    let mut retained = start_ygg_same_identity(&identity, &[peer_uri]);
    // wait() returning IS the deterministic admission barrier: the owner has
    // published its terminal status before this resolves.
    let ygg: SameIdentityYgg = retained.wait().await.expect("retained start admits");
    assert_eq!(
        ygg.public_key().expect("admitted transport is present"),
        identity.public_key_bytes(),
        "started core uses the SAME Ed25519 identity"
    );
    retained
        .shutdown()
        .await
        .expect("joined shutdown closes cleanly");
    retained
        .shutdown()
        .await
        .expect("repeated shutdown reports the cached success");
    let error = retained
        .wait()
        .await
        .expect_err("closed start is not admitted");
    assert!(
        matches!(error, StartupError::Ygg(YggError::Closed)),
        "wrong closed error: {error:?}"
    );
    close_within(&listener, "infra listener").await;
    let rebound = TcpListener::bind(("127.0.0.1", port)).expect("listener port binds again");
    drop(rebound);
    probe_claim_free(0x81, "claim released by joined shutdown").await;
}

#[tokio::test(flavor = "current_thread")]
async fn failed_start_error_is_retained_until_shutdown_then_closed() {
    let seed_byte = 0x83;
    let identity = local_identity(seed_byte);
    let holder = YggTransport::start(local_config(seed_byte))
        .await
        .expect("holder transport starts");
    let mut retained = start_ygg_same_identity(&identity, &[]);
    // Real production barrier: wait resolves only after the owner published
    // its terminal failure status.
    let error = retained
        .wait()
        .await
        .expect_err("the startup failure must be reported");
    assert!(
        matches!(error, StartupError::Ygg(YggError::KeyInUse)),
        "wrong retained error: {error:?}"
    );
    let text = format!("{error} {error:?}");
    assert!(!text.contains("0x83"), "seed marker leaked: {text}");
    // The ORIGINAL error stays observable before shutdown completes.
    let error_again = retained
        .wait()
        .await
        .expect_err("failure stays observable before shutdown");
    assert!(matches!(error_again, StartupError::Ygg(YggError::KeyInUse)));
    retained
        .shutdown()
        .await
        .expect("shutdown after a failed start is Ok");
    // A completed shutdown is terminal Closed, not a repeat of the failure.
    let closed = retained
        .wait()
        .await
        .expect_err("closed start is not admitted");
    assert!(
        matches!(closed, StartupError::Ygg(YggError::Closed)),
        "wait after shutdown must be Closed: {closed:?}"
    );
    drop(retained);
    close_within(&holder, "key holder").await;
    probe_claim_free(seed_byte, "key reusable after holder close").await;
}

#[tokio::test]
async fn failure_is_published_without_any_subscribed_waiter() {
    let seed_byte = 0x84;
    let identity = local_identity(seed_byte);
    let holder = YggTransport::start(local_config(seed_byte))
        .await
        .expect("holder transport starts");
    let mut retained = start_ygg_same_identity(&identity, &[]);
    // NO watch waiter is ever subscribed before the owner completes: the
    // owner join route is the deterministic completion barrier, independent
    // of scheduler order.
    retained
        .await_owner_without_waiter_for_tests()
        .await
        .expect("failed owner joins cleanly");
    // The outcome recorded through the permanent receiver survives for the
    // first-ever subscriber.
    let error = retained
        .wait()
        .await
        .expect_err("retained failure must survive without waiters");
    assert!(
        matches!(error, StartupError::Ygg(YggError::KeyInUse)),
        "wrong retained error: {error:?}"
    );
    retained
        .shutdown()
        .await
        .expect("shutdown after the joined owner reports Ok");
    let closed = retained
        .wait()
        .await
        .expect_err("closed start is not admitted");
    assert!(matches!(closed, StartupError::Ygg(YggError::Closed)));
    drop(retained);
    close_within(&holder, "key holder").await;
    probe_claim_free(seed_byte, "key reusable after holder close").await;
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_wait_is_resumable_and_keeps_the_admitted_status() {
    let identity = local_identity(0x85);
    let mut retained = start_ygg_same_identity(&identity, &[]);
    // Inner scope: the pinned wait future is polled exactly once and its
    // STORAGE is destroyed when the scope ends — a real cancellation, not a
    // dropped pin reference. On this single-thread runtime the owner has not
    // run yet, so `Pending` is an observed scheduling fact.
    {
        let mut wait_future = std::pin::pin!(retained.wait());
        assert!(
            matches!(poll_once(wait_future.as_mut()), Poll::Pending),
            "wait must be pending before the owner runs"
        );
    }
    let ygg = retained
        .wait()
        .await
        .expect("admitted status survives a cancelled wait");
    assert_eq!(
        ygg.public_key()
            .expect("transport present after resumption"),
        identity.public_key_bytes()
    );
    retained
        .shutdown()
        .await
        .expect("joined shutdown after resumption");
    probe_claim_free(0x85, "claim released after resumed wait and shutdown").await;
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_shutdown_is_resumable_and_still_joins() {
    let identity = local_identity(0x86);
    let mut retained = start_ygg_same_identity(&identity, &[]);
    let ygg = retained.wait().await.expect("retained start admits");
    assert_eq!(
        ygg.public_key().expect("admitted transport is present"),
        identity.public_key_bytes()
    );
    // Poll the borrowed shutdown once: the signal is sent synchronously, the
    // owner has not run on this thread, so the join is deterministically
    // Pending; the inner scope then destroys the future storage (real
    // cancellation) while the handle stays owned by `retained`.
    {
        let mut shutdown_future = std::pin::pin!(retained.shutdown());
        assert!(
            matches!(poll_once(shutdown_future.as_mut()), Poll::Pending),
            "shutdown must be pending before the owner runs"
        );
    }
    retained
        .shutdown()
        .await
        .expect("resumed shutdown joins and closes");
    drop(ygg);
    probe_claim_free(0x86, "claim released by resumed shutdown").await;
}

#[tokio::test]
async fn shutdown_propagates_and_caches_the_production_close_result() {
    // Real admitted transport, REAL owned close at the production boundary:
    // the fault seam only replaces the reported close result after the real
    // close has run, so this regression fails if the production close error
    // is discarded, if the cached result is not repeated, or if cleanup is
    // skipped.
    let (listener, port) = start_listener(0x87).await;
    let identity = local_identity(0x88);
    let peer_uri = format!("tcp://127.0.0.1:{port}");
    let mut retained = start_ygg_same_identity(&identity, &[peer_uri]);
    let ygg = retained.wait().await.expect("retained start admits");
    assert_eq!(
        ygg.public_key().expect("admitted transport is present"),
        identity.public_key_bytes()
    );
    // Arm AFTER admission and BEFORE the signal: the owner reads the flag
    // only after its real transport close has completed.
    retained.arm_close_fault_for_tests();
    let first = retained
        .shutdown()
        .await
        .expect_err("the production close failure must propagate");
    assert!(
        matches!(
            &first,
            StartupError::Ygg(YggError::Io(text)) if text.contains("synthetic close failure")
        ),
        "wrong close failure: {first:?}"
    );
    let second = retained
        .shutdown()
        .await
        .expect_err("the cached close failure must persist");
    assert_eq!(
        first, second,
        "repeated shutdown must return the same cached close result"
    );
    // Terminal lifecycle: a completed shutdown reports Closed, not the close
    // failure, and never a false admission.
    let closed = retained
        .wait()
        .await
        .expect_err("closed start is not admitted");
    assert!(
        matches!(closed, StartupError::Ygg(YggError::Closed)),
        "wait after shutdown must be Closed: {closed:?}"
    );
    // Real cleanup happened although the close REPORTED failure: the port
    // binds again and the key claim is reusable.
    close_within(&listener, "infra listener").await;
    let rebound = TcpListener::bind(("127.0.0.1", port)).expect("listener port binds again");
    drop(rebound);
    probe_claim_free(0x88, "claim released although the close reported failure").await;
}

#[tokio::test]
async fn join_failure_is_reported_and_cached() {
    let task = tokio::spawn(async {
        panic!("synthetic owner join failure");
        #[allow(unreachable_code)]
        Err::<(), StartupError>(StartupError::Ygg(YggError::Closed))
    });
    let mut retained = RetainedYggStart::assemble_for_tests(task);
    let first = retained
        .shutdown()
        .await
        .expect_err("join failure must propagate");
    let second = retained
        .shutdown()
        .await
        .expect_err("cached join failure must persist");
    assert_eq!(first, second);
    assert!(
        matches!(first, StartupError::Ygg(YggError::Io(_))),
        "wrong join failure mapping: {first:?}"
    );
}

#[tokio::test]
async fn cancellation_after_admission_closes_the_retained_transport() {
    let identity = local_identity(0x89);
    let mut retained = start_ygg_same_identity(&identity, &[]);
    let ygg = retained.wait().await.expect("retained start admits");
    assert_eq!(
        ygg.public_key()
            .expect("owner-retained transport is present"),
        identity.public_key_bytes()
    );
    drop(retained);
    drop(ygg);
    probe_claim_free(0x89, "claim released by post-admission cleanup").await;
}

#[tokio::test(flavor = "current_thread")]
async fn pre_admission_drop_does_not_strand_the_key_claim() {
    let identity = local_identity(0x8A);
    let mut retained = start_ygg_same_identity(&identity, &[]);
    // Observed, not assumed: on this single-thread runtime the owner has not
    // run when the first no-op-waker poll reports Pending, so the handle is
    // dropped before the owner ever started (real storage destruction in the
    // inner scope).
    {
        let mut wait_future = std::pin::pin!(retained.wait());
        assert!(
            matches!(poll_once(wait_future.as_mut()), Poll::Pending),
            "owner must not have run before the drop"
        );
    }
    // Split the REAL owner's join route off before dropping: the drop only
    // sends the production close signal, and the bounded join below awaits
    // THE OWNER ITSELF, so the later probe cannot win the key race by
    // starting first and can no longer pass while the owner never ran.
    let owner = retained
        .detach_owner_join_for_tests()
        .expect("owner task is present before the drop");
    drop(retained);
    // The owner admits, runs its OWNED transport close, and returns the real
    // close result. A lost signal or a leaking owner fails this bounded
    // timeout instead of passing; no sleep/yield polling is used.
    let joined = tokio::time::timeout(BUDGET, owner)
        .await
        .expect("the dropped handle's close signal must still let the owner finish");
    joined
        .expect("the owner task must not panic")
        .expect("the owner's own transport close must succeed");
    // Only now is the claim provably released by the owner itself.
    probe_claim_free(0x8A, "claim released by the owner's own close").await;
}

#[tokio::test]
async fn transport_transfer_is_exact_once_into_a_real_bridge() {
    // Production-path ownership: the transferred transport constructs the
    // existing YggBridge, proves an authenticated probe round trip, and the
    // ordered cleanup (bridges first, then the joined startup shutdown)
    // releases key claims and ports.
    let (listener_transport, port) = start_listener(0x8B).await;
    let client_identity = local_identity(0x8C);
    let listener_identity = local_identity(0x8B);
    let client_public = client_identity.public_key_bytes();
    let listener_public = listener_identity.public_key_bytes();
    let listener_bridge = YggBridge::new(listener_transport, [client_public]);
    let peer_uri = format!("tcp://127.0.0.1:{port}");
    let mut retained = start_ygg_same_identity(&client_identity, &[peer_uri]);
    let ygg = retained.wait().await.expect("retained start admits");
    assert_eq!(
        ygg.public_key().expect("admitted transport is present"),
        client_public,
        "started core uses the SAME Ed25519 identity"
    );
    let client_transport = ygg
        .take_transport()
        .expect("first synchronous transfer succeeds");
    // A second guard (the status stays Admitted until shutdown) must observe
    // an already-transferred slot: extraction is exact-once.
    let second = retained
        .wait()
        .await
        .expect("status stays admitted until shutdown");
    assert!(
        second.public_key().is_none(),
        "transferred slot must be empty"
    );
    assert!(
        second.take_transport().is_none(),
        "second transfer must not extract"
    );
    let client_bridge = YggBridge::new(client_transport, []);
    let duration = tokio::time::timeout(PROBE, client_bridge.probe(listener_public, PROBE))
        .await
        .expect("probe round trip inside the test budget")
        .expect("authenticated probe over the transferred transport");
    assert!(duration <= PROBE, "probe answered within its deadline");
    client_bridge
        .close()
        .await
        .expect("client bridge close joins and releases");
    listener_bridge
        .close()
        .await
        .expect("listener bridge close joins and releases");
    retained
        .shutdown()
        .await
        .expect("startup shutdown joins after the transfer");
    let rebound = TcpListener::bind(("127.0.0.1", port)).expect("listener port binds again");
    drop(rebound);
    probe_claim_free(0x8C, "claim released after bridge-owned cleanup").await;
}

#[tokio::test]
async fn invalid_peer_uri_is_reported_with_redacted_diagnostic() {
    let identity = local_identity(0x8D);
    let mut retained = start_ygg_same_identity(&identity, &["http://127.0.0.1:9".to_string()]);
    let error = retained
        .wait()
        .await
        .expect_err("unsupported scheme refused");
    assert!(
        matches!(
            error,
            StartupError::Ygg(YggError::InvalidConfig { field: "peers" })
        ),
        "wrong error: {error:?}"
    );
    let text = format!("{error} {error:?}");
    assert!(!text.contains("http://127.0.0.1:9"), "URI leaked: {text}");
    drop(retained);
    probe_claim_free(0x8D, "failed start released the claim").await;
}
