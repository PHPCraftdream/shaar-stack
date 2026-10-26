use super::*;
use crate::carrier::{Command, driver::Carrier};
use libp2p::swarm::NetworkBehaviour;

fn peer() -> PeerId {
    Keypair::generate_ed25519().public().to_peer_id()
}
fn address(peer: PeerId) -> RelayAddr {
    RelayAddr::new(peer, "127.0.0.1:4001".parse().unwrap()).unwrap()
}

/// Owner-issued reserve capability mirroring what the patched relay transport
/// captures at the listen boundary; the controller under test does not inspect it.
fn reserve_operation(
    relay: &RelayAddr,
) -> (
    protocol::client::OperationOwner,
    protocol::client::OperationCapability,
) {
    protocol::client::OperationCapability::owned(
        protocol::client::OperationDescriptor::new(
            relay.peer,
            multiaddr(relay.address),
            protocol::client::OperationKind::Reserve,
            std::num::NonZeroU64::new(1).unwrap(),
        ),
        |_, _| true,
        || {},
    )
}

#[test]
fn infrastructure_admission_is_distinct_bounded_and_reclaimable() {
    let app = peer();
    let mut admission = super::super::Admission::new(vec![app]).unwrap();
    assert_eq!(
        admission.authorize_relay(app).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    let peers: Vec<_> = (0..RELAY_LIMIT).map(|_| peer()).collect();
    for peer in &peers {
        admission.authorize_relay(*peer).unwrap();
        assert!(!admission.allows(peer));
    }
    let next = peer();
    assert_eq!(
        admission.authorize_relay(next).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    admission.forget_relay(peers[0]);
    admission.authorize_relay(next).unwrap();
    assert!(RelayAddr::new(next, "0.0.0.0:1".parse().unwrap()).is_err());
    assert!(RelayAddr::new(next, "127.0.0.1:0".parse().unwrap()).is_err());
    assert!(RelayAddr::new(next, "224.0.0.1:1".parse().unwrap()).is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn reservation_cardinality_is_capped_before_transport_submission() {
    let (mut owner, _handle, _incoming) = Carrier::bind(
        Keypair::generate_ed25519(),
        "127.0.0.1:0".parse().unwrap(),
        vec![],
    )
    .unwrap();
    let mut results = Vec::with_capacity(RESERVATIONS);
    for _ in 0..RESERVATIONS {
        let (reply, result) = oneshot::channel();
        owner.core.command(Command::Reserve(address(peer()), reply));
        results.push(result);
    }
    assert_eq!(owner.core.relay.records.len(), RESERVATIONS);
    let (reply, rejected) = oneshot::channel();
    owner.core.command(Command::Reserve(address(peer()), reply));
    assert_eq!(
        rejected.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(owner.core.relay.records.len(), RESERVATIONS);
    drop(results);
    owner.run(async {}).await.unwrap();
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn failed_reservations_wait_for_demand_without_a_ready_timer_loop() {
    let (mut owner, _handle, _incoming) = Carrier::bind(
        Keypair::generate_ed25519(),
        "127.0.0.1:0".parse().unwrap(),
        vec![],
    )
    .unwrap();
    let relay = address(peer());
    let (reply, result) = oneshot::channel();
    owner.core.reserve_relay(relay, reply);
    let listener = owner.core.relay.records[&relay.peer].listener.unwrap();
    owner
        .core
        .relay_listener_failed(listener, io::ErrorKind::ConnectionRefused.into());
    // Model the transport's terminal listener acknowledgement, not merely remove_listener.
    owner
        .core
        .relay
        .records
        .get_mut(&relay.peer)
        .unwrap()
        .listener = None;
    owner.core.relay_tick(Instant::now()).unwrap();
    assert_eq!(
        result.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::ConnectionRefused
    );
    let (reply, rejected) = oneshot::channel();
    owner.core.reserve_relay(relay, reply);
    assert_eq!(
        rejected.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    owner.core.relay_tick(Instant::now()).unwrap();
    assert!(owner.core.relay.next_deadline().unwrap() > Instant::now());
    assert!(owner.core.relay.records[&relay.peer].phase == Phase::Failed);
    let (reply, _retry) = oneshot::channel();
    owner.core.reserve_relay(relay, reply);
    assert_eq!(owner.core.relay.records[&relay.peer].attempts, 2);
    assert!(owner.core.relay.records[&relay.peer].phase == Phase::Pending);
    owner.run(async {}).await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn advertisements_are_validated_and_bounded_before_retention() {
    for malformed in 0..4 {
        let (mut owner, _handle, _incoming) = Carrier::bind(
            Keypair::generate_ed25519(),
            "127.0.0.1:0".parse().unwrap(),
            vec![],
        )
        .unwrap();
        let relay = address(peer());
        let local = *owner.core.swarm.local_peer_id();
        let (reply, _result) = oneshot::channel();
        owner.core.reserve_relay(relay, reply);
        let listener = owner.core.relay.records[&relay.peer].listener.unwrap();
        let advertised = match malformed {
            0 => relay.prefix().with(Protocol::P2p(peer())),
            1 => address(peer()).prefix().with(Protocol::P2p(local)),
            2 => multiaddr(relay.address).with(Protocol::P2p(local)),
            _ => Multiaddr::empty()
                .with(Protocol::Dns("a".repeat(ADDRESS_BYTES + 1).into()))
                .with(Protocol::P2p(relay.peer))
                .with(Protocol::P2pCircuit)
                .with(Protocol::P2p(local)),
        };
        owner.core.relay_listen_address(listener, advertised);
        let record = &owner.core.relay.records[&relay.peer];
        assert!(record.addresses.is_empty());
        assert!(record.phase == Phase::Stopping);
        assert!(owner.core.relay.snapshots.borrow().is_empty());
        owner.run(async {}).await.unwrap();
    }
    let (mut owner, _handle, _incoming) = Carrier::bind(
        Keypair::generate_ed25519(),
        "127.0.0.1:0".parse().unwrap(),
        vec![],
    )
    .unwrap();
    let relay = address(peer());
    let local = *owner.core.swarm.local_peer_id();
    let (reply, _result) = oneshot::channel();
    owner.core.reserve_relay(relay, reply);
    let listener = owner.core.relay.records[&relay.peer].listener.unwrap();
    for port in 1..=ADDRESSES {
        let advertised = format!("/ip4/127.0.0.1/tcp/{port}")
            .parse::<Multiaddr>()
            .unwrap()
            .with(Protocol::P2p(relay.peer))
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(local));
        owner
            .core
            .relay_listen_address(listener, advertised.clone());
        owner.core.relay_listen_address(listener, advertised);
        assert_eq!(owner.core.relay.records[&relay.peer].addresses.len(), port);
        assert!(owner.core.relay.snapshots.borrow().is_empty());
    }
    let extra = relay.prefix().with(Protocol::P2p(local));
    owner.core.relay_listen_address(listener, extra);
    let record = &owner.core.relay.records[&relay.peer];
    assert_eq!(record.addresses.len(), ADDRESSES);
    assert!(record.phase == Phase::Stopping);
    owner.run(async {}).await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_reservation_waiter_stops_before_the_admission_deadline() {
    let (mut owner, _handle, _incoming) = Carrier::bind(
        Keypair::generate_ed25519(),
        "127.0.0.1:0".parse().unwrap(),
        vec![],
    )
    .unwrap();
    let relay = address(peer());
    let (reply, result) = oneshot::channel();
    owner.core.reserve_relay(relay, reply);
    assert!(owner.core.relay.records[&relay.peer].phase == Phase::Pending);
    drop(result);
    owner.core.relay_tick(Instant::now()).unwrap();
    let record = &owner.core.relay.records[&relay.peer];
    assert!(record.phase == Phase::Stopping);
    assert!(record.expiry.is_none());
    assert!(owner.core.relay.snapshots.borrow().is_empty());
    owner.run(async {}).await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn a_closing_circuit_cannot_be_reused() {
    let app = peer();
    let (mut owner, _handle, _incoming) = Carrier::bind(
        Keypair::generate_ed25519(),
        "127.0.0.1:0".parse().unwrap(),
        vec![app],
    )
    .unwrap();
    let relay = address(peer());
    let current = ConnectionId::new_unchecked(802);
    let endpoint = libp2p::core::ConnectedPoint::Dialer {
        address: relay.prefix().with(Protocol::P2p(app)),
        role_override: libp2p::core::Endpoint::Dialer,
        port_use: libp2p::core::transport::PortUse::New,
    };
    owner.core.swarm.behaviour_mut().admission.on_swarm_event(
        libp2p::swarm::behaviour::FromSwarm::ConnectionEstablished(
            libp2p::swarm::behaviour::ConnectionEstablished {
                peer_id: app,
                connection_id: current,
                endpoint: &endpoint,
                failed_addresses: &[],
                other_established: 0,
            },
        ),
    );
    owner.core.relay.routes.insert(
        current,
        Route::Relayed {
            relay: Some(relay.peer),
            generation: 1,
        },
    );
    let (reply, reused) = oneshot::channel();
    owner.core.connect_via(app, relay, reply);
    assert_eq!(reused.await.unwrap().unwrap(), current);
    owner.core.closing.insert(
        app,
        Closing {
            deadline: Instant::now() + DEADLINE,
            reply: None,
        },
    );
    let (reply, rejected) = oneshot::channel();
    owner.core.connect_via(app, relay, reply);
    assert_eq!(
        rejected.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    owner.run(async {}).await.unwrap();
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn local_expiry_revokes_a_published_lease_and_rejects_late_renewal() {
    let (mut owner, _handle, _incoming) = Carrier::bind(
        Keypair::generate_ed25519(),
        "127.0.0.1:0".parse().unwrap(),
        vec![],
    )
    .unwrap();
    let relay = address(peer());
    let (_operation_owner, operation) = reserve_operation(&relay);
    let (reply, result) = oneshot::channel();
    owner.core.reserve_relay(relay, reply);
    let current = ConnectionId::new_unchecked(803);
    let endpoint = libp2p::core::ConnectedPoint::Listener {
        local_addr: multiaddr(relay.address),
        send_back_addr: multiaddr(relay.address),
    };
    owner.core.swarm.behaviour_mut().admission.on_swarm_event(
        libp2p::swarm::behaviour::FromSwarm::ConnectionEstablished(
            libp2p::swarm::behaviour::ConnectionEstablished {
                peer_id: relay.peer,
                connection_id: current,
                endpoint: &endpoint,
                failed_addresses: &[],
                other_established: 0,
            },
        ),
    );
    let listener = owner.core.relay.records[&relay.peer].listener.unwrap();
    let advertised = relay
        .prefix()
        .with(Protocol::P2p(*owner.core.swarm.local_peer_id()));
    owner.core.relay_listen_address(listener, advertised);
    let expires = Instant::now() + Duration::from_secs(1);
    owner
        .core
        .relay_event(protocol::client::Event::ReservationReqAccepted {
            relay_peer_id: relay.peer,
            connection_id: current,
            renewal: false,
            limit: None,
            expires_at: expires.into_std(),
            operation: operation.clone(),
        });
    let lease = result.await.unwrap().unwrap();
    assert_eq!(owner.core.relay.snapshots.borrow().as_slice(), &[lease]);
    assert_eq!(owner.core.relay.next_deadline(), Some(expires));
    tokio::time::advance(Duration::from_secs(1)).await;
    owner.core.relay_tick(Instant::now()).unwrap();
    assert!(owner.core.relay.snapshots.borrow().is_empty());
    assert!(owner.core.relay.records[&relay.peer].phase == Phase::Stopping);
    owner
        .core
        .relay_event(protocol::client::Event::ReservationReqAccepted {
            relay_peer_id: relay.peer,
            connection_id: current,
            renewal: true,
            limit: None,
            expires_at: (Instant::now() + Duration::from_secs(60)).into_std(),
            operation: operation.clone(),
        });
    assert!(owner.core.relay.snapshots.borrow().is_empty());
    assert_eq!(lease.expires_at(), expires);
    owner.run(async {}).await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn stale_or_stopping_acceptances_never_publish_a_lease() {
    let (mut owner, _handle, _incoming) = Carrier::bind(
        Keypair::generate_ed25519(),
        "127.0.0.1:0".parse().unwrap(),
        vec![],
    )
    .unwrap();
    let relay = address(peer());
    let (_operation_owner, operation) = reserve_operation(&relay);
    let (reply, mut pending) = oneshot::channel();
    owner.core.command(Command::Reserve(relay, reply));
    let stale = ConnectionId::new_unchecked(800);
    let current = ConnectionId::new_unchecked(801);
    let endpoint = libp2p::core::ConnectedPoint::Listener {
        local_addr: multiaddr(relay.address),
        send_back_addr: multiaddr(relay.address),
    };
    owner.core.swarm.behaviour_mut().admission.on_swarm_event(
        libp2p::swarm::behaviour::FromSwarm::ConnectionEstablished(
            libp2p::swarm::behaviour::ConnectionEstablished {
                peer_id: relay.peer,
                connection_id: current,
                endpoint: &endpoint,
                failed_addresses: &[],
                other_established: 0,
            },
        ),
    );
    owner
        .core
        .relay_event(protocol::client::Event::ReservationReqAccepted {
            relay_peer_id: relay.peer,
            connection_id: stale,
            renewal: false,
            limit: None,
            expires_at: (Instant::now() + Duration::from_secs(60)).into_std(),
            operation: operation.clone(),
        });
    assert!(owner.core.relay.snapshots.borrow().is_empty());
    assert!(pending.try_recv().is_err());
    assert!(owner.core.relay.records[&relay.peer].control.is_none());
    let (release, _released) = oneshot::channel();
    owner.core.release_relay(relay.peer, release);
    owner
        .core
        .relay_event(protocol::client::Event::ReservationReqAccepted {
            relay_peer_id: relay.peer,
            connection_id: current,
            renewal: false,
            limit: None,
            expires_at: (Instant::now() + Duration::from_secs(60)).into_std(),
            operation: operation.clone(),
        });
    assert!(owner.core.relay.snapshots.borrow().is_empty());
    assert!(owner.core.relay.records[&relay.peer].control.is_none());
    owner.run(async {}).await.unwrap();
}
