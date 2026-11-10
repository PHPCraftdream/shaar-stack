use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::AtomicBool;

use libp2p_identity::PeerId;
use shaar_p2p::RelayAddr;
use tokio::sync::watch;

use super::super::Status;
use super::*;
use crate::network::RelayFixture;
use crate::startup::resources::maintain::Maintenance;

fn loopback_relay() -> RelayAddr {
    // RFC 8032 style identity multihash prefix plus a fixture key; the
    // value only fills SharedState and is never dialed in these tests.
    let mut multihash = vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
    multihash.extend_from_slice(&[0xC4; 32]);
    let peer = PeerId::from_bytes(&multihash).expect("fixture relay peer id");
    RelayAddr::new(peer, "192.0.2.20:7000".parse().unwrap()).expect("fixture relay address")
}

fn shared_with(resources: StartupResources) -> Arc<SharedState> {
    let (status_tx, status_rx) = watch::channel(Status::Pending);
    let (completion_tx, _) = watch::channel(None);
    Arc::new(SharedState {
        configured_relay: loopback_relay(),
        slot: std::sync::Mutex::new(super::super::CompositionSlot {
            resources: Some(resources),
            closing: None,
            orphan_native: Vec::new(),
            orphan_ygg: Vec::new(),
        }),
        status_tx,
        status_rx,
        first_close_error: std::sync::Mutex::new(None),
        completion_tx,
        close_fault_for_tests: AtomicBool::new(false),
        native_close_fault_for_tests: AtomicBool::new(false),
        mainline_close_skip_for_tests: AtomicBool::new(false),
        payload_fault_for_tests: AtomicBool::new(false),
        cleanup_hold_armed_for_tests: AtomicBool::new(false),
        cleanup_hold_observer_for_tests: std::sync::Mutex::new(None),
        mainline_actor_id_for_tests: std::sync::Mutex::new(None),
        publication_watch_for_tests: std::sync::Mutex::new(None),
    })
}

/// Real Mainline owner withdrawn through a dead command channel proves
/// shutdown converges instead of blocking native transfer forever.
#[tokio::test]
async fn closed_owner_withdrawal_drives_shutdown_then_permits_quiescence() {
    let peer = LoopbackPeer::bind().await; // kept alive as the DHT bootstrap
    let bootstrap = match peer.address {
        SocketAddr::V4(address) => address,
        _ => panic!("loopback peer must be IPv4"),
    };
    let identity = Identity::from_seed([0xC5; 32]);
    let owner = RuntimeOwner::start(
        identity.clone(),
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        &[bootstrap],
    )
    .expect("mainline owner starts");
    let endpoint = SignaledEndpoint::bind(
        &identity,
        SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &[],
        Limits::default(),
    )
    .await
    .expect("native endpoint binds");
    let shared = shared_with(StartupResources {
        endpoint: Some(endpoint),
        native_transferred: false,
        native_quiesced: false,
        maintenance: None,
        owner: Some(owner),
        withdrawal_done: false,
        ygg: None,
    });

    // Terminate the publisher first so withdrawal answers Closed through
    // the same dead command channel a terminal publication failure
    // produces.
    let mut owner = {
        let mut slot = slot_lock(&shared.slot);
        slot.resources
            .as_mut()
            .expect("slot installed")
            .owner
            .take()
            .expect("owner installed")
    };
    owner.close().await.expect("mainline closes");
    slot_lock(&shared.slot)
        .resources
        .as_mut()
        .expect("slot installed")
        .owner = Some(owner);

    let quiescence = quiesce_native(&shared);
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&quiescence);
    let complete = quiescence.await;
    assert!(complete, "a joined closed owner proves publication stopped");
    let slot = slot_lock(&shared.slot);
    let resources = slot.resources.as_ref().expect("slot retained");
    assert!(resources.withdrawal_done && resources.native_quiesced);
    assert!(resources.owner.is_none(), "closed owner is not retained");
    let endpoint = resources
        .endpoint
        .as_ref()
        .expect("native endpoint stays owned");
    assert_ne!(
        endpoint.signaling_addr().port(),
        0,
        "usable signaling endpoint survives quiesce"
    );
    assert!(shared.first_error().is_none(), "no fabricated close error");
}

/// The fault seam drives the REAL maintenance loop; the wrapper recovers
/// the owner and hands it back, and the joins happen through the
/// production `RuntimeOwner::close` — abort-only Drop never claims
/// completion.
#[tokio::test]
async fn faulted_maintenance_retains_owner_and_joined_close_releases_resources() {
    let peer = LoopbackPeer::bind().await; // kept alive as the DHT bootstrap
    let bootstrap = match peer.address {
        SocketAddr::V4(address) => address,
        _ => panic!("loopback peer must be IPv4"),
    };
    let identity = Identity::from_seed([0xC6; 32]);
    // A reserved explicit Mainline bind: rebinding this exact socket is
    // the independent backend-release oracle for the joined close.
    let reserved_mainline =
        std::net::UdpSocket::bind(("127.0.0.1", 0)).expect("reserve a loopback Mainline port");
    let mainline_port = reserved_mainline
        .local_addr()
        .expect("reserved Mainline address")
        .port();
    drop(reserved_mainline);
    let owner = RuntimeOwner::start(
        identity.clone(),
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, mainline_port),
        &[bootstrap],
    )
    .expect("mainline owner starts");
    let endpoint = SignaledEndpoint::bind(
        &identity,
        SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &[],
        Limits::default(),
    )
    .await
    .expect("native endpoint binds");
    let native_addr = endpoint.local_addr();
    let watcher = endpoint.native_addr_watcher();
    let maintenance = Maintenance::spawn(owner, watcher);
    let commands = maintenance.commands.clone();
    let shared = shared_with(StartupResources {
        endpoint: Some(endpoint),
        native_transferred: false,
        native_quiesced: false,
        maintenance: Some(maintenance),
        owner: None,
        withdrawal_done: false,
        ygg: None,
    });

    // Fault the REAL maintenance loop; the wrapper recovers the owner.
    Maintenance::fault_for_tests(&commands).await;
    // The configured Mainline socket is really held before close, so the
    // rebind assertion below cannot pass vacuously.
    let occupied = std::net::UdpSocket::bind(("127.0.0.1", mainline_port))
        .expect_err("retained Mainline owner holds its configured socket");
    assert_eq!(occupied.kind(), std::io::ErrorKind::AddrInUse);

    let first = run_ordered_close(&shared, None, None).await;
    assert!(
        first,
        "faulted exit hands the owner back and the joined close completes"
    );
    assert_eq!(
        shared.first_error(),
        Some(StartupError::Close {
            stage: "address-maintenance",
        })
    );
    {
        let slot = slot_lock(&shared.slot);
        let resources = slot.resources.as_ref().expect("slot retained");
        assert!(
            resources.owner.is_none(),
            "owner dropped only AFTER its close() joined publisher and dht"
        );
        assert!(
            resources.maintenance.is_none()
                && resources.endpoint.is_none()
                && resources.ygg.is_none(),
            "joined close releases every retained resource"
        );
        assert!(
            slot.closing.is_none(),
            "no closing claims leak past restore"
        );
    }
    // Independent release oracles after the actual joins: BOTH the
    // explicitly configured Mainline actor socket and the native
    // endpoint socket rebind. The Mainline rebind is the backend proof;
    // the native rebind alone proves nothing about Mainline.
    let rebound_mainline = std::net::UdpSocket::bind(("127.0.0.1", mainline_port))
        .expect("joined close released the Mainline actor socket");
    drop(rebound_mainline);
    std::net::UdpSocket::bind(native_addr).expect("native UDP owner closed");

    let second = run_ordered_close(&shared, None, None).await;
    assert!(
        second,
        "repeat close converges without repolling consumed handles"
    );
    assert_eq!(
        shared.first_error(),
        Some(StartupError::Close {
            stage: "address-maintenance",
        })
    );
}

/// A close that joins every resource but retains its terminal error no
/// longer blocks native transfer: the join is the cleanup proof.
/// Post-failure usability is proven by an actual relay reservation round
/// trip through the real signaling route, not a cached address.
#[tokio::test]
async fn joined_close_error_after_terminal_withdrawal_permits_quiescence() {
    let peer = LoopbackPeer::bind().await; // kept alive as the DHT bootstrap
    let bootstrap = match peer.address {
        SocketAddr::V4(address) => address,
        _ => panic!("loopback peer must be IPv4"),
    };
    let identity = Identity::from_seed([0xC7; 32]);
    let owner = RuntimeOwner::start(
        identity.clone(),
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        &[bootstrap],
    )
    .expect("mainline owner starts");
    let endpoint = SignaledEndpoint::bind(
        &identity,
        SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &[],
        Limits::default(),
    )
    .await
    .expect("native endpoint binds");
    let shared = shared_with(StartupResources {
        endpoint: Some(endpoint),
        native_transferred: false,
        native_quiesced: false,
        maintenance: None,
        owner: Some(owner),
        withdrawal_done: false,
        ygg: None,
    });

    // The aborted publisher makes `close_inner` retain `RuntimeError::Closed`
    // after clearing both handles.
    let mut owner = {
        let mut slot = slot_lock(&shared.slot);
        slot.resources
            .as_mut()
            .expect("slot installed")
            .owner
            .take()
            .expect("owner installed")
    };
    owner.abort_publisher_for_tests();
    owner
        .close()
        .await
        .expect_err("aborted publisher retains a terminal close error");
    slot_lock(&shared.slot)
        .resources
        .as_mut()
        .expect("slot installed")
        .owner = Some(owner);

    let complete = quiesce_native(&shared).await;
    assert!(
        complete,
        "a finished join proves publication stopped despite its retained error"
    );
    {
        let slot = slot_lock(&shared.slot);
        let resources = slot.resources.as_ref().expect("slot retained");
        assert!(resources.withdrawal_done && resources.native_quiesced);
        assert!(resources.owner.is_none(), "closed owner is not retained");
        let endpoint = resources
            .endpoint
            .as_ref()
            .expect("native endpoint stays owned");
        assert_ne!(
            endpoint.signaling_addr().port(),
            0,
            "usable signaling endpoint survives the retained close error"
        );
    }
    // Post-failure usability: an actual relay reservation round trip
    // through the still-owned signaling endpoint. The slot guard is
    // dropped before the awaits; the endpoint stays in the slot.
    let fixture = RelayFixture::start().await;
    let fixture_relay = fixture.address;
    let operations = {
        let slot = slot_lock(&shared.slot);
        slot.resources
            .as_ref()
            .expect("slot retained")
            .endpoint
            .as_ref()
            .expect("native endpoint stays owned")
            .relay_operations()
    };
    let lease = tokio::time::timeout(MAINTENANCE_BOUND, operations.reserve(fixture_relay))
        .await
        .expect("relay reserve completes")
        .expect("the endpoint still operates its signaling after the terminal failure");
    assert_eq!(lease.relay(), fixture_relay);
    operations
        .release(fixture_relay)
        .await
        .expect("relay release");
    fixture.close().await;
    assert_eq!(
        shared.first_error(),
        Some(StartupError::Close { stage: "mainline" }),
        "the retained close error stays recorded"
    );
}
