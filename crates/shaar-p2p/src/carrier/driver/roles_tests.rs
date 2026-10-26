//! Carrier role-integration wiring proofs: the real `Owner` ledger, the real
//! composed guarded transport and the gate factory the patched relay transport
//! installs — not simulated registry calls. Registry and guard micro-semantics
//! have their own suites; these tests pin the wiring layer.

use super::*;
use crate::discovery::roles::{Owner, Role};
use libp2p::{Multiaddr, relay::client::OperationKind};
use std::{num::NonZeroU64, sync::atomic::Ordering as AtomicOrdering};
use tokio::{
    net::TcpListener,
    sync::oneshot,
    task::JoinSet,
    time::{Instant, timeout},
};

use super::relay::gate::{Gate, Slot, Ticket};

/// Mirrors `gate::RECORDS` (2 * (RESERVATIONS + PENDING_LIMIT)): the bounded
/// total of live records plus retained tombstones; the constant itself is
/// private to the gate module.
const RECORD_BUDGET: usize = 20;

fn peer() -> PeerId {
    Keypair::generate_ed25519().public().to_peer_id()
}

fn endpoint() -> SocketAddr {
    "127.0.0.1:4001".parse().unwrap()
}

fn other_endpoint() -> SocketAddr {
    "127.0.0.1:4002".parse().unwrap()
}

fn plain(endpoint: SocketAddr) -> Multiaddr {
    let host = match endpoint.ip() {
        std::net::IpAddr::V4(ip) => Protocol::Ip4(ip),
        std::net::IpAddr::V6(ip) => Protocol::Ip6(ip),
    };
    Multiaddr::empty()
        .with(host)
        .with(Protocol::Tcp(endpoint.port()))
}

/// A ledger configured exactly like `bind_with_discovery`: the allowlist as
/// applications, then an explicit relay identity granted by the policy layer.
fn configured(
    relay: PeerId,
    application: PeerId,
    endpoint: SocketAddr,
) -> (Owner, crate::discovery::roles::View) {
    let mut owner = Owner::new(&[application], &[]).unwrap();
    owner
        .admit_identity(relay, Role::ExplicitRelay(endpoint))
        .unwrap();
    let view = owner.view();
    (owner, view)
}

fn deadline(seconds: u64) -> Instant {
    Instant::now() + Duration::from_secs(seconds)
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_destination_shutdown_revokes_all_and_joins_release() {
    use futures::task::{ArcWake, waker};
    use std::{
        future::Future,
        sync::atomic::{AtomicUsize, Ordering},
    };

    struct WakeCounter(AtomicUsize);
    impl ArcWake for WakeCounter {
        fn wake_by_ref(counter: &Arc<Self>) {
            counter.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let relay = peer();
    let application = peer();
    let (_owner, view) = configured(relay, application, endpoint());
    let gate = Gate::new();
    let generation = gate.stage_reserve(relay, endpoint(), deadline(60)).unwrap();
    let factory = gate.factory_unbound(view);
    let capability = factory(relay, &plain(endpoint()), OperationKind::Reserve).unwrap();
    gate.revoke_all();
    gate.terminal_reservation(relay, generation);
    let released = gate
        .released_flag(relay, Slot::Reserve, generation)
        .unwrap();
    let mut join = Box::pin(gate.join_release());
    let counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
    let waker = waker(counter.clone());
    let mut cx = std::task::Context::from_waker(&waker);
    assert!(join.as_mut().poll(&mut cx).is_pending());
    let wakes = counter.0.load(Ordering::SeqCst);
    drop(capability);
    assert!(counter.0.load(Ordering::SeqCst) > wakes);
    assert!(released.load(AtomicOrdering::Acquire));
    assert!(matches!(
        join.as_mut().poll(&mut cx),
        std::task::Poll::Ready(Ok(()))
    ));
    drop(factory);
    gate.prune_released();
    assert_eq!(gate.record_count(), 0);

    // Full carrier run: revoke_all → drop(core) → executor join → release join.
    let seed = peer();
    let (carrier, _handle, _incoming) = Carrier::bind_with_discovery(
        Keypair::generate_ed25519(),
        "127.0.0.1:0".parse().unwrap(),
        vec![application],
        discovery_config(seed),
    )
    .unwrap();
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(carrier.run(async {
        let _ = stopped.await;
    }));
    stop.send(()).unwrap();
    timeout(Duration::from_secs(15), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_destination_positive_dial_completes_real_noise_over_guarded_transport() {
    let seed = peer();
    let ka = Keypair::generate_ed25519();
    let kb = Keypair::generate_ed25519();
    let pa = ka.public().to_peer_id();
    let pb = kb.public().to_peer_id();
    let (a, ah, mut a_in) = Carrier::bind_with_discovery(
        ka,
        "127.0.0.1:0".parse().unwrap(),
        vec![pb],
        discovery_config(seed),
    )
    .unwrap();
    let (b, bh, mut b_in) = Carrier::bind_with_discovery(
        kb,
        "127.0.0.1:0".parse().unwrap(),
        vec![pa],
        discovery_config(seed),
    )
    .unwrap();
    let mut tasks = JoinSet::new();
    let mut stops = Vec::with_capacity(2);
    for carrier in [a, b] {
        let (stop, stopped) = oneshot::channel();
        stops.push(stop);
        tasks.spawn(carrier.run(async {
            let _ = stopped.await;
        }));
    }
    let b_addr = bh.local_addr().await.unwrap();
    let connection = timeout(Duration::from_secs(15), ah.connect(pb, b_addr))
        .await
        .unwrap()
        .unwrap();
    ah.send_on(
        Link {
            peer: pb,
            connection,
            route: Route::Direct,
        },
        Datagram::new(b"ping").unwrap(),
    )
    .await
    .unwrap();
    let received = timeout(Duration::from_secs(15), b_in.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.peer, pa);
    assert_eq!(received.route, Route::Direct);
    assert_eq!(received.packet.as_bytes(), b"ping");
    bh.send_on(
        Link {
            peer: pa,
            connection: received.connection,
            route: Route::Direct,
        },
        Datagram::new(b"pong").unwrap(),
    )
    .await
    .unwrap();
    let received = timeout(Duration::from_secs(15), a_in.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.packet.as_bytes(), b"pong");
    for stop in stops {
        stop.send(()).unwrap();
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap().unwrap();
    }
    assert!(ah.local_addr().await.is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_destination_hostile_dial_rejects_without_fallback() {
    let seed = peer();
    let stranger = peer();
    let (a, ah, _a_in) = Carrier::bind_with_discovery(
        Keypair::generate_ed25519(),
        "127.0.0.1:0".parse().unwrap(),
        vec![],
        discovery_config(seed),
    )
    .unwrap();
    let (stop, stopped) = oneshot::channel();
    let mut tasks = JoinSet::new();
    tasks.spawn(a.run(async {
        let _ = stopped.await;
    }));
    let _listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_addr = _listener.local_addr().unwrap();
    // A peer outside the admission allowlist: denied outright, never dialed.
    let denied = timeout(Duration::from_secs(15), ah.connect(stranger, listener_addr))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
    // A seed peer holds an infrastructure reservation only: it is never dial
    // authority, so the composed command path denies it without fallback.
    let denied = timeout(Duration::from_secs(15), ah.connect(seed, listener_addr))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
    assert!(ah.links().borrow().is_empty());
    stop.send(()).unwrap();
    while let Some(result) = tasks.join_next().await {
        result.unwrap().unwrap();
    }
}

fn discovery_config(seed: PeerId) -> DiscoveryConfig {
    let address = Multiaddr::empty()
        .with(Protocol::Dns("seed.example.".to_string()))
        .with(Protocol::Tcp(443))
        .with(Protocol::P2p(seed));
    DiscoveryConfig::new(vec![(seed, address)], vec!["8.8.8.8:53".parse().unwrap()]).unwrap()
}

#[test]
fn carrier_destination_transport_capture_consumes_precharged_once() {
    let relay = peer();
    let application = peer();
    let (_owner, view) = configured(relay, application, endpoint());
    let gate = Gate::new();
    let generation = gate.stage_reserve(relay, endpoint(), deadline(60)).unwrap();
    let key = Keypair::generate_ed25519();
    let (mut transport, behaviour) = libp2p::relay::client::new_with_operation_factory(
        key.public().to_peer_id(),
        gate.factory_unbound(view),
    );
    let address = plain(endpoint())
        .with(Protocol::P2p(relay))
        .with(Protocol::P2pCircuit);
    assert!(
        transport
            .listen_on(ListenerId::next(), address.clone())
            .is_ok()
    );
    assert!(transport.listen_on(ListenerId::next(), address).is_err());
    gate.revoke(relay, Slot::Reserve);
    gate.terminal_reservation(relay, generation);
    drop(transport);
    drop(behaviour);
}

#[test]
fn carrier_destination_release_before_terminal_keeps_charge() {
    let relay = peer();
    let gate = Gate::new();
    let generation = gate.stage_reserve(relay, endpoint(), deadline(60)).unwrap();
    let (_owner, view) = configured(relay, peer(), endpoint());
    let capability =
        gate.factory_unbound(view)(relay, &plain(endpoint()), OperationKind::Reserve).unwrap();
    gate.revoke(relay, Slot::Reserve);
    drop(capability);
    let flag = gate
        .released_flag(relay, Slot::Reserve, generation)
        .unwrap();
    assert!(flag.load(AtomicOrdering::Acquire));
    gate.prune_released();
    assert_eq!(gate.record_count(), 1);
    gate.terminal_reservation(relay, generation);
    gate.prune_released();
    assert_eq!(gate.record_count(), 0);
}

#[test]
fn carrier_destination_double_factory_take_is_refused_once_claimed() {
    let relay = peer();
    let application = peer();
    let (_owner, view) = configured(relay, application, endpoint());
    let gate = Gate::new();
    gate.stage_reserve(relay, endpoint(), deadline(60)).unwrap();
    let factory = gate.factory_unbound(view);
    assert!(factory(relay, &plain(endpoint()), OperationKind::Reserve).is_ok());
    // Take-once semantics: a second capture of the same staged generation is
    // refused with backpressure, never silently regranted.
    assert_eq!(
        factory(relay, &plain(endpoint()), OperationKind::Reserve)
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn carrier_destination_capability_does_not_retain_owner_cycle() {
    let relay = peer();
    let application = peer();
    let (_owner, view) = configured(relay, application, endpoint());
    let gate = Gate::new();
    gate.stage_reserve(relay, endpoint(), deadline(60)).unwrap();
    let observer = gate.lifetime_observer();
    let factory = gate.factory_unbound(view);
    let capability = factory(relay, &plain(endpoint()), OperationKind::Reserve).unwrap();
    drop(gate);
    assert!(!observer());
    assert!(factory(relay, &plain(endpoint()), OperationKind::Reserve).is_err());
    drop(capability);
}
