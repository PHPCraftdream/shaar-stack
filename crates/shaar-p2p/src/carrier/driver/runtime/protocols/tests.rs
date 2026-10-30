use super::guard::Guard;
use crate::discovery::roles::{AttemptKey, InfrastructurePermit, LeaseKind, Owner, Role, Root};
use libp2p::{
    Multiaddr, PeerId,
    core::{Endpoint, transport::PortUse},
    swarm::{
        ConnectionDenied, ConnectionId, DialError, NetworkBehaviour, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm,
        behaviour::{DialFailure, FromSwarm},
        dummy,
    },
};
use std::{
    collections::VecDeque,
    convert::Infallible,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;

#[test]
fn carrier_destination_discovery_capabilities_require_exact_dht_and_hop_names() {
    use libp2p::StreamProtocol;
    assert_eq!(super::capabilities(&[]), 0);
    for name in [
        "/libp2p/circuit/relay/0.2.0/stop",
        "/other/ipfs/kad/1.0.0",
        "/libp2p/circuit/relay/0.2.0/hop/extra",
    ] {
        assert_eq!(super::capabilities(&[StreamProtocol::new(name)]), 0);
    }
    assert_eq!(
        super::capabilities(&[StreamProtocol::new("/ipfs/kad/1.0.0")]),
        super::DHT
    );
    assert_eq!(
        super::capabilities(&[StreamProtocol::new("/libp2p/circuit/relay/0.2.0/hop")]),
        super::HOP
    );
    assert_eq!(
        super::capabilities(&[
            StreamProtocol::new("/ipfs/kad/1.0.0"),
            StreamProtocol::new("/libp2p/circuit/relay/0.2.0/hop"),
        ]),
        super::DHT | super::HOP
    );
}

#[derive(Debug, PartialEq, Eq)]
enum Event {
    RejectedAddress,
}

#[derive(Default)]
struct Probe {
    pending: usize,
    established: usize,
    failures: usize,
    peer_addresses: usize,
    actions: VecDeque<ToSwarm<Event, Infallible>>,
}

impl NetworkBehaviour for Probe {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Event;

    fn handle_pending_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: Option<PeerId>,
        _: &[Multiaddr],
        _: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        self.pending += 1;
        Ok(Vec::new())
    }

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.established += 1;
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.established += 1;
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::DialFailure(_) => self.failures += 1,
            FromSwarm::NewExternalAddrOfPeer(_) => self.peer_addresses += 1,
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        self.actions.pop_front().map_or(Poll::Pending, Poll::Ready)
    }
}

fn peer(value: u8) -> PeerId {
    let mut bytes = [value; 34];
    bytes[0] = 0x12;
    bytes[1] = 32;
    PeerId::from_bytes(&bytes).unwrap()
}

fn address(peer: PeerId) -> Multiaddr {
    format!("/ip4/8.8.8.8/tcp/4001/p2p/{peer}").parse().unwrap()
}

fn stage(owner: &mut Owner, peer: PeerId, id: ConnectionId) -> (AttemptKey, InfrastructurePermit) {
    let now = Instant::now();
    owner
        .stage_infrastructure(
            peer,
            id,
            now + Duration::from_secs(10),
            now,
            Root::new(address(peer).as_ref(), peer).unwrap(),
        )
        .unwrap()
}

fn authenticate(owner: &mut Owner, key: AttemptKey) {
    let view = owner.view();
    let root = view.lease(key, LeaseKind::Root, Instant::now()).unwrap();
    let numeric = view.lease(key, LeaseKind::Numeric, Instant::now()).unwrap();
    let endpoint = "8.8.8.8:4001".parse().unwrap();
    numeric.record_numeric(endpoint, Instant::now()).unwrap();
    assert_eq!(
        owner.terminal(key, Some(key.peer), Instant::now()),
        Some(endpoint)
    );
    drop(numeric);
    drop(root);
    assert!(view.attempt_for_connection(key.connection).is_none());
}

fn guard(owner: &Owner) -> Guard<Probe> {
    Guard::new(Some(Probe::default()), Some(owner.view()), || {
        Event::RejectedAddress
    })
}

#[test]
fn carrier_destination_discovery_handler_keeps_exact_key_across_admission_terminal() {
    let infra = peer(1);
    let app = peer(2);
    let explicit = peer(3);
    let mut owner = Owner::new(&[app], &[infra]).unwrap();
    owner
        .admit_identity(
            explicit,
            Role::ExplicitRelay("8.8.8.8:4001".parse().unwrap()),
        )
        .unwrap();
    let mut guard = guard(&owner);
    for (index, peer) in [(1, app), (2, explicit)] {
        let id = ConnectionId::new_unchecked(index);
        let now = Instant::now();
        let key = owner
            .admit(peer, id, now + Duration::from_secs(10), now)
            .unwrap();
        owner
            .pin_root(key, Root::new(address(peer).as_ref(), peer).unwrap(), now)
            .unwrap();
        guard
            .handle_pending_outbound_connection(id, Some(peer), &[address(peer)], Endpoint::Dialer)
            .unwrap();
        authenticate(&mut owner, key);
        guard
            .handle_established_outbound_connection(
                id,
                peer,
                &address(peer),
                Endpoint::Dialer,
                PortUse::New,
            )
            .unwrap();
    }
    assert_eq!(guard.as_mut().unwrap().pending, 0);
    assert_eq!(guard.as_mut().unwrap().established, 0);
    let id = ConnectionId::new_unchecked(3);
    let (key, _permit) = stage(&mut owner, infra, id);
    guard
        .handle_pending_outbound_connection(id, Some(infra), &[address(infra)], Endpoint::Dialer)
        .unwrap();
    assert_eq!(guard.as_mut().unwrap().pending, 1);
    authenticate(&mut owner, key);
    assert!(owner.view().infrastructure_live(key).is_some());
    guard
        .handle_established_outbound_connection(
            id,
            infra,
            &address(infra),
            Endpoint::Dialer,
            PortUse::New,
        )
        .unwrap();
    assert_eq!(guard.as_mut().unwrap().established, 1);
}

#[test]
fn carrier_destination_discovery_handler_denies_unstaged_inbound_and_revoked_controls() {
    let infra = peer(1);
    let mut owner = Owner::new(&[], &[infra]).unwrap();
    let mut guard = guard(&owner);
    let id = ConnectionId::new_unchecked(1);
    guard
        .handle_established_outbound_connection(
            id,
            infra,
            &address(infra),
            Endpoint::Dialer,
            PortUse::New,
        )
        .unwrap();
    guard
        .handle_established_inbound_connection(id, infra, &address(infra), &address(infra))
        .unwrap();
    let (key, _permit) = stage(&mut owner, infra, id);
    guard
        .handle_pending_outbound_connection(id, Some(infra), &[address(infra)], Endpoint::Dialer)
        .unwrap();
    authenticate(&mut owner, key);
    owner.infrastructure_withdraw(key);
    guard
        .handle_established_outbound_connection(
            id,
            infra,
            &address(infra),
            Endpoint::Dialer,
            PortUse::New,
        )
        .unwrap();
    assert_eq!(guard.as_mut().unwrap().established, 0);
}

#[test]
fn carrier_destination_discovery_same_peer_control_waits_for_its_original_terminal_event() {
    let infra = peer(1);
    let mut owner = Owner::new(&[], &[infra]).unwrap();
    let mut guard = guard(&owner);
    let first = ConnectionId::new_unchecked(1);
    let (key, permit) = stage(&mut owner, infra, first);
    guard
        .handle_pending_outbound_connection(first, Some(infra), &[address(infra)], Endpoint::Dialer)
        .unwrap();
    owner.terminal(key, None, Instant::now());
    owner.infrastructure_terminal(key);
    drop(permit);
    let second = ConnectionId::new_unchecked(2);
    let (_key, _permit) = stage(&mut owner, infra, second);
    assert!(
        guard
            .handle_pending_outbound_connection(
                second,
                Some(infra),
                &[address(infra)],
                Endpoint::Dialer
            )
            .is_err()
    );
    let error = DialError::Aborted;
    guard.on_swarm_event(FromSwarm::DialFailure(DialFailure {
        peer_id: Some(infra),
        error: &error,
        connection_id: first,
    }));
    guard
        .handle_pending_outbound_connection(
            second,
            Some(infra),
            &[address(infra)],
            Endpoint::Dialer,
        )
        .unwrap();
    assert_eq!(guard.as_mut().unwrap().pending, 2);
}

#[tokio::test(start_paused = true)]
async fn carrier_destination_discovery_pending_deadline_cannot_enable_a_handler() {
    let infra = peer(1);
    let mut owner = Owner::new(&[], &[infra]).unwrap();
    let mut guard = guard(&owner);
    let id = ConnectionId::new_unchecked(1);
    let (key, _permit) = stage(&mut owner, infra, id);
    guard
        .handle_pending_outbound_connection(id, Some(infra), &[address(infra)], Endpoint::Dialer)
        .unwrap();
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(owner.terminal(key, Some(infra), Instant::now()).is_none());
    guard
        .handle_established_outbound_connection(
            id,
            infra,
            &address(infra),
            Endpoint::Dialer,
            PortUse::New,
        )
        .unwrap();
    assert_eq!(guard.as_mut().unwrap().established, 0);
}

#[test]
fn carrier_destination_discovery_pending_handler_slots_release_only_on_terminal_notification() {
    let seeds = [peer(1), peer(2), peer(3), peer(4)];
    let app = peer(100);
    let mut owner = Owner::new(&[app], &seeds).unwrap();
    let mut guard = guard(&owner);
    for (index, peer) in seeds.into_iter().enumerate() {
        let id = ConnectionId::new_unchecked(index);
        let (key, permit) = stage(&mut owner, peer, id);
        guard
            .handle_pending_outbound_connection(id, Some(peer), &[address(peer)], Endpoint::Dialer)
            .unwrap();
        owner.terminal(key, None, Instant::now());
        owner.infrastructure_terminal(key);
        drop(permit);
    }
    let extra = peer(5);
    owner.admit_identity(extra, Role::Infrastructure).unwrap();
    let id = ConnectionId::new_unchecked(4);
    let (_key, _permit) = stage(&mut owner, extra, id);
    assert!(
        guard
            .handle_pending_outbound_connection(
                id,
                Some(extra),
                &[address(extra)],
                Endpoint::Dialer
            )
            .is_err()
    );
    guard
        .handle_established_outbound_connection(
            ConnectionId::new_unchecked(9),
            app,
            &address(app),
            Endpoint::Dialer,
            PortUse::New,
        )
        .unwrap();
    let error = DialError::Aborted;
    guard.on_swarm_event(FromSwarm::DialFailure(DialFailure {
        peer_id: Some(seeds[0]),
        error: &error,
        connection_id: ConnectionId::new_unchecked(0),
    }));
    guard
        .handle_pending_outbound_connection(id, Some(extra), &[address(extra)], Endpoint::Dialer)
        .unwrap();
    assert_eq!(guard.as_mut().unwrap().failures, 1);
    assert_eq!(guard.as_mut().unwrap().established, 0);
}

#[test]
fn carrier_destination_discovery_protocols_ignore_foreign_peer_address_announcements() {
    let claimed = address(peer(1));
    let mut control = Probe::default();
    control.on_swarm_event(FromSwarm::NewExternalAddrOfPeer(
        libp2p::swarm::behaviour::NewExternalAddrOfPeer {
            peer_id: peer(1),
            addr: &claimed,
        },
    ));
    assert_eq!(control.peer_addresses, 1);
    let owner = Owner::new(&[], &[]).unwrap();
    let mut guard = guard(&owner);
    guard.on_swarm_event(FromSwarm::NewExternalAddrOfPeer(
        libp2p::swarm::behaviour::NewExternalAddrOfPeer {
            peer_id: peer(1),
            addr: &claimed,
        },
    ));
    assert_eq!(guard.as_mut().unwrap().peer_addresses, 0);
}

#[test]
fn carrier_destination_discovery_protocols_do_not_publish_observed_peer_addresses() {
    let owner = Owner::new(&[], &[]).unwrap();
    let mut guard = guard(&owner);
    guard.as_mut().unwrap().actions.extend([
        ToSwarm::NewExternalAddrCandidate(address(peer(1))),
        ToSwarm::NewExternalAddrOfPeer {
            peer_id: peer(2),
            address: address(peer(2)),
        },
    ]);
    let mut context = Context::from_waker(std::task::Waker::noop());
    for _ in 0..2 {
        assert!(matches!(
            guard.poll(&mut context),
            Poll::Ready(ToSwarm::GenerateEvent(Event::RejectedAddress))
        ));
    }
    assert!(guard.poll(&mut context).is_pending());
}
