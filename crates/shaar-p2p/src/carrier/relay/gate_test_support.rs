use super::*;

fn authenticate_infrastructure(
    owner: &mut roles::Owner,
    peer: PeerId,
    connection: ConnectionId,
    endpoint: SocketAddr,
) -> (roles::AttemptKey, roles::InfrastructurePermit) {
    let now = Instant::now();
    let address = multiaddr(endpoint).with(Protocol::P2p(peer));
    let (key, permit) = owner
        .stage_infrastructure(
            peer,
            connection,
            now + Duration::from_secs(10),
            now,
            roles::Root::new(address.as_ref(), peer).unwrap(),
        )
        .unwrap();
    let view = owner.view();
    let root = view.lease(key, roles::LeaseKind::Root, now).unwrap();
    let numeric = view.lease(key, roles::LeaseKind::Numeric, now).unwrap();
    numeric.record_numeric(endpoint, now).unwrap();
    assert_eq!(owner.terminal(key, Some(peer), now), Some(endpoint));
    drop((numeric, root));
    (key, permit)
}

#[test]
fn discovery_reservation_factory_requires_owned_provenance_and_exact_live_control() {
    let peer = Keypair::generate_ed25519().public().to_peer_id();
    let endpoint = "8.8.8.8:4001".parse().unwrap();
    let mut owner = roles::Owner::new(&[], &[peer]).unwrap();
    let (key, _permit) =
        authenticate_infrastructure(&mut owner, peer, ConnectionId::new_unchecked(1), endpoint);
    let view = owner.view();
    let gate = Gate::new();
    let factory = gate.factory(view.clone());
    let deadline = Instant::now() + Duration::from_secs(10);
    let explicit = gate.stage_reserve(peer, endpoint, deadline).unwrap();
    assert!(factory(peer, &multiaddr(endpoint), OperationKind::Reserve).is_err());
    gate.revoke_generation(peer, Slot::Reserve, explicit);
    gate.terminal_reservation(peer, explicit);
    let wrong = "8.8.4.4:4001".parse().unwrap();
    assert!(gate.stage_discovered_reserve(key, wrong, deadline).is_err());
    let generation = gate
        .stage_discovered_reserve(key, endpoint, deadline)
        .unwrap();
    let capability = factory(peer, &multiaddr(endpoint), OperationKind::Reserve).unwrap();
    assert_eq!(view.role(peer), Some(Role::Infrastructure));
    assert!(gate.test_admit(
        peer,
        generation,
        multiaddr(endpoint),
        OperationKind::Reserve,
        None
    ));
    assert!(!gate.test_admit(
        peer,
        generation,
        multiaddr(endpoint),
        OperationKind::Reserve,
        Some(ConnectionId::new_unchecked(2))
    ));
    assert!(gate.test_admit(
        peer,
        generation,
        multiaddr(endpoint),
        OperationKind::Reserve,
        Some(key.connection)
    ));
    assert!(gate.reservation_permit(peer, generation, key.connection));
    assert!(gate.native_permit(peer, &multiaddr(endpoint).with(Protocol::P2p(peer))));
    owner.infrastructure_withdraw(key);
    assert_eq!(
        factory(peer, &multiaddr(endpoint), OperationKind::Reserve)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(!gate.test_admit(
        peer,
        generation,
        multiaddr(endpoint),
        OperationKind::Reserve,
        Some(key.connection)
    ));
    assert!(!gate.reservation_permit(peer, generation, key.connection));
    assert!(!gate.native_permit(peer, &multiaddr(endpoint).with(Protocol::P2p(peer))));
    gate.revoke_generation(peer, Slot::Reserve, generation);
    gate.terminal_reservation(peer, generation);
    assert!(
        !gate
            .released_flag(peer, Slot::Reserve, generation)
            .unwrap()
            .load(Ordering::Acquire)
    );
    drop(capability);
    gate.prune_released();
    assert_eq!(gate.record_count(), 0);
}

#[test]
fn discovery_reservation_factory_cannot_rebind_successor_or_foreign_owner_key() {
    let peer = Keypair::generate_ed25519().public().to_peer_id();
    let endpoint = "8.8.8.8:4001".parse().unwrap();
    let mut owner = roles::Owner::new(&[], &[peer]).unwrap();
    let (old, permit) =
        authenticate_infrastructure(&mut owner, peer, ConnectionId::new_unchecked(1), endpoint);
    let gate = Gate::new();
    let factory = gate.factory(owner.view());
    let deadline = Instant::now() + Duration::from_secs(10);
    let generation = gate
        .stage_discovered_reserve(old, endpoint, deadline)
        .unwrap();
    let capability = factory(peer, &multiaddr(endpoint), OperationKind::Reserve).unwrap();
    owner.infrastructure_withdraw(old);
    owner.infrastructure_terminal(old);
    drop(permit);
    let (current, _permit) =
        authenticate_infrastructure(&mut owner, peer, ConnectionId::new_unchecked(2), endpoint);
    assert!(!gate.test_admit(
        peer,
        generation,
        multiaddr(endpoint),
        OperationKind::Reserve,
        Some(current.connection)
    ));
    assert!(
        gate.stage_discovered_reserve(old, endpoint, deadline)
            .is_err()
    );
    let mut foreign = roles::Owner::new(&[], &[peer]).unwrap();
    let (foreign_key, _foreign_permit) =
        authenticate_infrastructure(&mut foreign, peer, current.connection, endpoint);
    assert!(
        gate.stage_discovered_reserve(foreign_key, endpoint, deadline)
            .is_err()
    );
    gate.revoke_generation(peer, Slot::Reserve, generation);
    gate.terminal_reservation(peer, generation);
    let successor = gate
        .stage_discovered_reserve(current, endpoint, deadline)
        .unwrap();
    assert!(successor > generation);
    let next = factory(peer, &multiaddr(endpoint), OperationKind::Reserve).unwrap();
    assert!(gate.test_admit(
        peer,
        successor,
        multiaddr(endpoint),
        OperationKind::Reserve,
        Some(current.connection)
    ));
    assert!(!gate.test_admit(
        peer,
        successor,
        multiaddr(endpoint),
        OperationKind::Reserve,
        Some(old.connection)
    ));
    gate.revoke_generation(peer, Slot::Reserve, successor);
    gate.terminal_reservation(peer, successor);
    drop((capability, next));
    gate.prune_released();
    assert_eq!(gate.record_count(), 0);
}

#[test]
fn discovery_connect_inherits_control_and_reservation_deadline_but_not_destination_authority() {
    let peer = Keypair::generate_ed25519().public().to_peer_id();
    let app = Keypair::generate_ed25519().public().to_peer_id();
    let unlisted = Keypair::generate_ed25519().public().to_peer_id();
    let endpoint = "8.8.8.8:4001".parse().unwrap();
    let mut owner = roles::Owner::new(&[app], &[peer]).unwrap();
    let (key, _permit) =
        authenticate_infrastructure(&mut owner, peer, ConnectionId::new_unchecked(1), endpoint);
    let view = owner.view();
    let gate = Gate::new();
    let factory = gate.factory_unbound(view.clone());
    let now = Instant::now();
    let expiry = now + Duration::from_secs(2);
    let generation = gate
        .stage_discovered_reserve(key, endpoint, expiry)
        .unwrap();
    let reservation = factory(peer, &multiaddr(endpoint), OperationKind::Reserve).unwrap();
    assert!(gate.test_admit(
        peer,
        generation,
        multiaddr(endpoint),
        OperationKind::Reserve,
        Some(key.connection)
    ));
    gate.accepted(peer, generation, expiry, key.connection);
    let ticket = gate
        .stage_connect(peer, endpoint, app, now + Duration::from_secs(10))
        .unwrap();
    let connect = factory(
        peer,
        &multiaddr(endpoint),
        OperationKind::Connect { destination: app },
    )
    .unwrap();
    assert!(!gate.test_admit(
        peer,
        ticket.generation,
        multiaddr(endpoint),
        OperationKind::Connect { destination: app },
        Some(ConnectionId::new_unchecked(2))
    ));
    assert!(gate.test_admit(
        peer,
        ticket.generation,
        multiaddr(endpoint),
        OperationKind::Connect { destination: app },
        Some(key.connection)
    ));
    assert!(gate.connection_permit(ticket, app));
    let denied = gate
        .stage_connect(peer, endpoint, unlisted, now + Duration::from_secs(10))
        .unwrap();
    assert!(
        factory(
            peer,
            &multiaddr(endpoint),
            OperationKind::Connect {
                destination: unlisted
            }
        )
        .is_err()
    );
    gate.expire(now + Duration::from_secs(3));
    assert!(
        !gate.connection_permit(ticket, app),
        "CONNECT_OUTLIVED_RESERVATION_ADMISSION_DEADLINE"
    );
    assert_eq!(view.role(peer), Some(Role::Infrastructure));
    assert!(view.infrastructure_live(key).is_some());
    gate.revoke_all();
    gate.terminal_reservation(peer, generation);
    gate.terminal(ticket);
    gate.terminal(denied);
    drop((reservation, connect));
    gate.prune_released();
    assert_eq!(gate.record_count(), 0);
}

impl Gate {
    pub(crate) fn test_admit(
        &self,
        peer: PeerId,
        generation: u64,
        address: Multiaddr,
        kind: OperationKind,
        control: Option<ConnectionId>,
    ) -> bool {
        let Some(g) = NonZeroU64::new(generation) else {
            return false;
        };
        self.core
            .admit(&OperationDescriptor::new(peer, address, kind, g), control)
    }

    pub(crate) fn lifetime_observer(&self) -> impl Fn() -> bool + use<> {
        let weak = Arc::downgrade(&self.core);
        move || weak.upgrade().is_some()
    }

    pub(crate) fn record_count(&self) -> usize {
        lock(&self.core.records).len()
    }

    /// Test handle to a record's release flag: true only after the owner AND
    /// every capability clone were dropped.
    pub(crate) fn released_flag(
        &self,
        peer: PeerId,
        slot: Slot,
        generation: u64,
    ) -> Option<Arc<AtomicBool>> {
        lock(&self.core.records)
            .get(&(peer, slot, generation))
            .map(|record| record.released.clone())
    }
}
