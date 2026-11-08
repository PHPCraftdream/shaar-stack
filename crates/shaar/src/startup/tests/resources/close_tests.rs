//! Close lifecycle of the retained composition (`SharedResourcesStart`):
//! cached results, real late-close barriers, and retained-Mainline retry.

use std::net::{SocketAddrV4, TcpListener, UdpSocket};
use std::time::Duration;

use shaar_ygg::{YggConfig, YggError, YggTransport};

use crate::native_discovery::runtime::owner::LoopbackPeer;
use crate::network::Limits;
use crate::startup::SharedResourcesStart;
use crate::startup::StartupError;
use crate::startup::resources::{SharedResources, StageControls};

use super::{
    BUDGET, identity, parse_server_config, probe_claim_free, reserve_tcp_port, reserve_udp_port,
    server_config_text, start_composition, start_listener, wait_admitted,
};

pub(super) struct Fixture {
    pub(super) start: SharedResourcesStart,
    pub(super) resources: SharedResources,
    pub(super) transit: shaar_ygg::YggTransport,
    pub(super) signaling_port: u16,
    pub(super) mainline_port: u16,
}

pub(super) type PausedStart = fn(
    &crate::identity::Identity,
    &crate::startup::preflight::ComposedStartupPlan<'_>,
    Limits,
) -> (SharedResourcesStart, Option<StageControls>);
pub(super) type PeerComposition = (
    SharedResourcesStart,
    Option<StageControls>,
    crate::identity::Identity,
    shaar_ygg::YggTransport,
    u16,
    u16,
);
pub(super) type CapturedPut = (
    std::net::SocketAddr,
    Vec<u8>,
    iroh_dns::pkarr::SignedPacket,
    n0_mainline::MutableItem,
);

/// Retains admission and the actual initial Mainline PUT concurrently.
pub(super) async fn admit_and_capture_initial_put(
    start: &mut SharedResourcesStart,
    peer: &mut crate::native_discovery::runtime::owner::LoopbackPeer,
) -> (SharedResources, CapturedPut) {
    let mut admission = Box::pin(start.wait());
    let mut capture = Box::pin(peer.capture_put_record());
    let mut admitted = None;
    let mut captured_put = None;
    tokio::time::timeout(BUDGET, async {
        while admitted.is_none() || captured_put.is_none() {
            tokio::select! {
                result = &mut admission, if admitted.is_none() => admitted = Some(result),
                result = &mut capture, if captured_put.is_none() => captured_put = Some(result),
            }
        }
    })
    .await
    .expect("admission and actual initial Mainline PUT complete within the budget");
    drop(admission);
    drop(capture);
    let resources = admitted
        .expect("admission result retained")
        .expect("composition admitted");
    let captured = captured_put.expect("actual initial PUT retained");
    (resources, captured)
}

/// Shared loopback-peer composition setup; the constructor is caller-chosen.
pub(super) async fn peer_composition(
    peer: &mut crate::native_discovery::runtime::owner::LoopbackPeer,
    seed: u8,
    transit_seed: u8,
    start_of: PausedStart,
) -> PeerComposition {
    let signaling_port = reserve_tcp_port();
    let mainline_port = reserve_udp_port();
    let (transit, transit_port) = start_listener(transit_seed).await;
    let bootstrap = match peer.address {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => panic!("loopback Mainline peer must bind IPv4"),
    };
    let text = server_config_text(
        SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, mainline_port),
        &[bootstrap],
        format!("127.0.0.1:{signaling_port}")
            .parse()
            .expect("signaling bind"),
        &[format!("tcp://127.0.0.1:{transit_port}")],
        None,
    );
    let config = parse_server_config(&text);
    let identity = identity(seed);
    let plan = super::plan_for(&config, &identity, &[]);
    let (start, controls) = start_of(&identity, &plan, Limits::default());
    (
        start,
        controls,
        identity,
        transit,
        signaling_port,
        mainline_port,
    )
}

async fn start_paused_with_reserved_ports(
    seed: u8,
    transit_seed: u8,
    pause_after_bridge: bool,
    pause_after_native_close: bool,
) -> (
    SharedResourcesStart,
    StageControls,
    shaar_ygg::YggTransport,
    u16,
    u16,
) {
    let signaling_port = reserve_tcp_port();
    let mainline_port = reserve_udp_port();
    let (transit, transit_port) = start_listener(transit_seed).await;
    let text = server_config_text(
        SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, mainline_port),
        &[SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 9)],
        format!("127.0.0.1:{signaling_port}")
            .parse()
            .expect("signaling bind"),
        &[format!("tcp://127.0.0.1:{transit_port}")],
        None,
    );
    let config = parse_server_config(&text);
    let identity = identity(seed);
    let plan = super::plan_for(&config, &identity, &[]);
    let (start, controls) = SharedResourcesStart::start_paused_for_tests(
        &identity,
        &plan,
        Limits::default(),
        pause_after_bridge,
        pause_after_native_close,
    );
    (start, controls, transit, signaling_port, mainline_port)
}

async fn compose_paused_with_reserved_ports(
    seed: u8,
    transit_seed: u8,
    pause_after_native_close: bool,
) -> (Fixture, StageControls) {
    let (mut start, controls, transit, signaling_port, mainline_port) =
        start_paused_with_reserved_ports(seed, transit_seed, false, pause_after_native_close).await;
    let resources = wait_admitted(&mut start).await;
    (
        Fixture {
            start,
            resources,
            transit,
            signaling_port,
            mainline_port,
        },
        controls,
    )
}

/// Compose with a RESERVED signaling TCP port and a RESERVED Mainline UDP
/// port so post-close rebinding proves the joined teardown of both backends.
async fn compose_with_reserved_ports(seed: u8, transit_seed: u8) -> Fixture {
    let signaling_port = reserve_tcp_port();
    let mainline_port = reserve_udp_port();
    let (transit, transit_port) = start_listener(transit_seed).await;
    let text = server_config_text(
        SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, mainline_port),
        &[SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 9)],
        format!("127.0.0.1:{signaling_port}")
            .parse()
            .expect("signaling bind"),
        &[format!("tcp://127.0.0.1:{transit_port}")],
        None,
    );
    let config = parse_server_config(&text);
    let identity = identity(seed);
    let mut start = start_composition(&identity, &config, &[]);
    let resources = wait_admitted(&mut start).await;
    Fixture {
        start,
        resources,
        transit,
        signaling_port,
        mainline_port,
    }
}

fn assert_ports_released(fixture: &Fixture) {
    TcpListener::bind(("127.0.0.1", fixture.signaling_port))
        .expect("signaling TCP port rebinds after close");
    // Bind+drop proves the mainline UDP port is free again.
    let rebound = std::net::UdpSocket::bind(("127.0.0.1", fixture.mainline_port))
        .expect("mainline UDP port rebinds after close");
    drop(rebound);
}

pub(super) async fn close_transit_and_release_claims(fixture: Fixture, seed: u8, transit_seed: u8) {
    let Fixture {
        transit,
        signaling_port,
        mainline_port,
        ..
    } = fixture;
    let closed = tokio::time::timeout(Duration::from_secs(10), transit.close()).await;
    assert!(
        closed.is_ok() && closed.expect("checked").is_ok(),
        "transit close"
    );
    let rebound_signaling =
        TcpListener::bind(("127.0.0.1", signaling_port)).expect("signaling port rebinds");
    drop(rebound_signaling);
    let rebound_mainline =
        std::net::UdpSocket::bind(("127.0.0.1", mainline_port)).expect("mainline port rebinds");
    drop(rebound_mainline);
    probe_claim_free(seed, "identity claim released").await;
    probe_claim_free(transit_seed, "transit claim released").await;
}

#[tokio::test]
async fn cancelled_shutdown_waits_at_native_close_then_preserves_first_error_and_releases_owners() {
    let (mut fixture, controls) = compose_paused_with_reserved_ports(0xD6, 0xD7, true).await;
    let native_addr = fixture
        .resources
        .endpoint_for_tests(|endpoint| endpoint.local_addr())
        .expect("admitted native endpoint");
    let (entered, release) = controls
        .after_native_close
        .expect("native close gate requested");
    fixture.resources.arm_native_close_fault_for_tests();
    fixture.resources.arm_ygg_close_fault_for_tests();

    {
        let mut shutdown = std::pin::pin!(fixture.start.shutdown());
        tokio::time::timeout(BUDGET, async {
            tokio::select! {
                biased;
                result = &mut shutdown => panic!("shutdown cannot finish before Ygg close: {result:?}"),
                result = entered => result,
            }
        })
        .await
        .expect("native close gate enters within the budget")
        .expect("native close gate entered");
    }

    let rebound_native = UdpSocket::bind(native_addr).expect("real native UDP address is released");
    drop(rebound_native);
    let rebound_signaling = TcpListener::bind(("127.0.0.1", fixture.signaling_port))
        .expect("signaling TCP is released before Ygg close");
    drop(rebound_signaling);
    assert_ygg_key_claimed(0xD6, "Ygg key remains claimed until its close phase").await;

    release.send(()).expect("release native-close stage");
    let error = tokio::time::timeout(BUDGET, fixture.start.shutdown())
        .await
        .expect("shutdown completes after release")
        .expect_err("native close fault is retained");
    assert_eq!(
        error,
        StartupError::Close {
            stage: "native-signaling"
        },
        "the native close error precedes the later Ygg close fault"
    );
    assert_eq!(
        fixture
            .start
            .shutdown()
            .await
            .expect_err("cached first error"),
        error
    );
    probe_claim_free(0xD6, "composition Ygg key released after close").await;
    assert_ports_released(&fixture);
    close_transit_and_release_claims(fixture, 0xD6, 0xD7).await;
}

fn empty_transport_config(seed: u8) -> YggConfig {
    YggConfig {
        seed: [seed; 32],
        listen: Vec::new(),
        peers: Vec::new(),
        allowed_public_keys: Vec::new(),
        group_password: None,
    }
}

async fn assert_ygg_key_claimed(seed: u8, context: &str) {
    match YggTransport::start(empty_transport_config(seed)).await {
        Err(YggError::KeyInUse) => {}
        Ok(transport) => {
            tokio::time::timeout(BUDGET, transport.close())
                .await
                .expect("unexpected Ygg transport closes within the budget")
                .expect("unexpected Ygg transport closes cleanly");
            panic!("{context}: key was unexpectedly available");
        }
        Err(error) => panic!("{context}: unexpected Ygg start error: {error}"),
    }
}

#[tokio::test]
async fn repeated_shutdown_is_idempotent_and_caches_the_terminal_result() {
    let mut fixture = compose_with_reserved_ports(0xD4, 0xD5).await;
    let readiness = fixture.resources.readiness().await;
    assert!(readiness.native_bound && readiness.publication.is_some());
    // First shutdown runs the ordered close inside the owner task.
    let first = tokio::time::timeout(BUDGET, fixture.start.shutdown())
        .await
        .expect("first shutdown finishes within the budget")
        .expect("first shutdown is clean");
    // The terminal result is cached WITHOUT repolling consumed handles.
    let second = fixture.start.shutdown().await.expect("second shutdown");
    let third = fixture.start.shutdown().await.expect("third shutdown");
    assert_eq!(first, second, "repeated shutdown repeats the cached result");
    assert_eq!(second, third);
    // Truthful readiness after the close.
    let readiness = fixture.resources.readiness().await;
    assert!(readiness.publication.is_none() && !readiness.native_bound);
    assert_ports_released(&fixture);
    close_transit_and_release_claims(fixture, 0xD4, 0xD5).await;
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_wait_keeps_acquired_bridge_owned_until_resumed_shutdown() {
    let (mut start, controls, transit, signaling_port, mainline_port) =
        start_paused_with_reserved_ports(0xF1, 0xF2, true, false).await;
    let (entered, release) = controls.after_bridge.expect("bridge gate requested");
    {
        let mut wait = std::pin::pin!(start.wait());
        tokio::time::timeout(BUDGET, async {
            tokio::select! {
                biased;
                result = &mut wait => panic!("wait cannot finish before the bridge gate: {result:?}"),
                result = entered => result,
            }
        })
        .await
        .expect("bridge gate enters within the budget")
        .expect("bridge stage entered");
    }
    assert_ygg_key_claimed(
        0xF1,
        "dropping the waiter does not abandon the acquired bridge's key claim",
    )
    .await;
    release.send(()).expect("release bridge stage");
    let resources = tokio::time::timeout(BUDGET, start.wait())
        .await
        .expect("wait resumes after bridge release")
        .expect("startup admits after bridge release");
    assert!(resources.readiness().await.native_bound);
    tokio::time::timeout(BUDGET, start.shutdown())
        .await
        .expect("explicit shutdown joins acquired resources")
        .expect("shutdown is clean");
    probe_claim_free(0xF1, "cancelled wait's Ygg claim released by shutdown").await;
    let rebound_signaling =
        TcpListener::bind(("127.0.0.1", signaling_port)).expect("signaling port released");
    drop(rebound_signaling);
    let rebound_mainline =
        UdpSocket::bind(("127.0.0.1", mainline_port)).expect("Mainline port released");
    drop(rebound_mainline);
    close_transit_and_release_claims(
        Fixture {
            start,
            resources,
            transit,
            signaling_port,
            mainline_port,
        },
        0xF1,
        0xF2,
    )
    .await;
}

#[tokio::test]
async fn incomplete_mainline_close_retains_owner_for_retry_and_caches_terminal_error() {
    let mut peer = LoopbackPeer::bind().await;
    let (mut start, _controls, _identity, transit, signaling_port, mainline_port) =
        peer_composition(&mut peer, 0xF3, 0xF9, |identity, plan, limits| {
            (SharedResourcesStart::start(identity, plan, limits), None)
        })
        .await;

    let (resources, (source, transaction, _signed, _item)) =
        admit_and_capture_initial_put(&mut start, &mut peer).await;
    peer.acknowledge(source, &transaction).await;
    let publication = super::published_on_watch(&resources).await;
    assert!(
        matches!(
            publication,
            crate::native_discovery::runtime::publisher::PublicationStatus::Published { .. }
        ),
        "the retained Mainline owner has actually published before close: {publication:?}"
    );
    let mut fixture = Fixture {
        start,
        resources,
        transit,
        signaling_port,
        mainline_port,
    };
    let native_addr = fixture
        .resources
        .endpoint_for_tests(|endpoint| endpoint.local_addr())
        .expect("admitted native endpoint");
    fixture.resources.arm_mainline_close_skip_for_tests();
    let first = tokio::time::timeout(BUDGET, fixture.start.shutdown())
        .await
        .expect("first incomplete close attempt returns")
        .expect_err("skipped Mainline close is nonterminal");
    assert_eq!(first, StartupError::Close { stage: "mainline" });
    let readiness = fixture.resources.readiness().await;
    assert!(readiness.publication.is_none());
    assert!(!readiness.native_bound);
    assert_eq!(
        fixture.resources.ygg_phase(),
        crate::startup::YggPhase::None
    );
    let rebound_native = UdpSocket::bind(native_addr).expect("native UDP owner closes");
    drop(rebound_native);
    let rebound_signaling = TcpListener::bind(("127.0.0.1", fixture.signaling_port))
        .expect("signaling closes despite incomplete Mainline");
    drop(rebound_signaling);
    probe_claim_free(0xF3, "Ygg owner closes despite incomplete Mainline").await;

    let occupied = UdpSocket::bind(("127.0.0.1", fixture.mainline_port))
        .expect_err("incomplete Mainline owner still holds its UDP port");
    assert_eq!(occupied.kind(), std::io::ErrorKind::AddrInUse);
    let terminal = tokio::time::timeout(BUDGET, fixture.start.shutdown())
        .await
        .expect("retry closes retained Mainline owner")
        .expect_err("first error remains cached after terminal cleanup");
    assert_eq!(terminal, first);
    let rebound = UdpSocket::bind(("127.0.0.1", fixture.mainline_port))
        .expect("terminal retry releases Mainline port");
    drop(rebound);
    assert_eq!(
        fixture
            .start
            .shutdown()
            .await
            .expect_err("terminal cached error"),
        first
    );
    close_transit_and_release_claims(fixture, 0xF3, 0xF9).await;
}

#[tokio::test]
async fn one_backend_close_error_via_the_real_boundary_still_closes_every_other_owner() {
    let mut fixture = compose_with_reserved_ports(0xD8, 0xD9).await;
    // Arm the REAL-boundary bridge-close fault seam: the REAL bridge close
    // still releases the transport (claim + sockets); only the REPORTED
    // result is replaced, so close.rs records "ygg-bridge".
    fixture.resources.arm_ygg_close_fault_for_tests();
    let error = tokio::time::timeout(BUDGET, fixture.start.shutdown())
        .await
        .expect("shutdown with a backend fault finishes within the budget")
        .expect_err("the first close error must surface");
    assert!(
        matches!(
            error,
            StartupError::Close {
                stage: "ygg-bridge"
            }
        ),
        "wrong first error: {error:?}"
    );
    // The FIRST error is persisted and repeated by the cached terminal.
    let again = fixture.start.shutdown().await.expect_err("cached error");
    assert_eq!(error, again);
    // The REAL close ran: claim released, readiness truthful, ports rebind.
    let readiness = fixture.resources.readiness().await;
    assert!(readiness.publication.is_none(), "maintenance was joined");
    assert!(!readiness.native_bound, "endpoint owner was closed");
    assert_eq!(
        readiness.ygg,
        crate::startup::YggPhase::None,
        "ygg owners were cleared"
    );
    assert_ports_released(&fixture);
    probe_claim_free(0xD8, "identity claim released despite the reported fault").await;
    close_transit_and_release_claims(fixture, 0xD8, 0xD9).await;
}

/// A shutdown waiter cancelled at the gated native-close stage does not
/// abandon the owner task: the owner records the terminal close, `wait()`
/// then reports `Closed`, and an explicit shutdown joins cleanly.
#[tokio::test]
async fn cancelled_shutdown_owner_records_closed_and_wait_reports_closed() {
    let mut peer = LoopbackPeer::bind().await;
    let (mut start, controls, _identity, transit, signaling_port, mainline_port) =
        peer_composition(&mut peer, 0xF7, 0xFA, |identity, plan, limits| {
            let (start, controls) =
                SharedResourcesStart::start_paused_for_tests(identity, plan, limits, false, true);
            (start, Some(controls))
        })
        .await;
    let resources = wait_admitted(&mut start).await;
    let (entered, release) = controls
        .expect("paused start requested controls")
        .after_native_close
        .expect("native close gate requested");
    // Subscribe BEFORE the shutdown future is pinned; no change is missed.
    let mut completion = start.completion_observer_for_tests();

    {
        let mut shutdown = std::pin::pin!(start.shutdown());
        tokio::time::timeout(BUDGET, async {
            tokio::select! {
                biased;
                result = &mut shutdown => panic!("shutdown cannot finish while the close stage is gated: {result:?}"),
                result = entered => result,
            }
        })
        .await
        .expect("native close gate enters within the budget")
        .expect("native close stage entered");
    } // The scope end IS the cancellation: the pin!'s hidden future storage (and its &mut start borrow) dies with the block.
    release.send(()).expect("release native close stage");
    // The owner task records the terminal result despite the cancelled waiter.
    tokio::time::timeout(BUDGET, completion.changed())
        .await
        .expect("completion is recorded within the budget")
        .expect("completion channel stays open");
    let terminal = completion.borrow().clone();
    assert_eq!(
        terminal,
        Some(Ok(())),
        "the owner records a clean terminal close on its own"
    );

    // Without another shutdown call: the stale Admitted status is gone.
    let wait_error = tokio::time::timeout(BUDGET, start.wait())
        .await
        .expect("wait resolves within the budget")
        .expect_err("stale Admitted status must not be reported after close");
    assert_eq!(wait_error, StartupError::Ygg(YggError::Closed));

    // The explicit shutdown joins and reports the clean terminal result.
    tokio::time::timeout(BUDGET, start.shutdown())
        .await
        .expect("shutdown joins within the budget")
        .expect("shutdown is clean after the owner-recorded close");

    let fixture = Fixture {
        start,
        resources,
        transit,
        signaling_port,
        mainline_port,
    };
    assert_ports_released(&fixture);
    close_transit_and_release_claims(fixture, 0xF7, 0xFA).await;
}
