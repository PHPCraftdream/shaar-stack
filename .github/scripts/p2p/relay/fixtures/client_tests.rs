#![forbid(unsafe_code)]

use super::*;
use crate::operation_gate::{OperationDescriptor, OperationKind, OperationOwner};
use libp2p_core::Transport as _;
use std::{
    num::NonZeroU64,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Waker,
    time::Duration,
};

fn operation(peer: PeerId, address: Multiaddr, generation: u64) -> (OperationOwner, Operation) {
    Operation::owned(
        OperationDescriptor::new(
            peer,
            address,
            OperationKind::Reserve,
            NonZeroU64::new(generation).unwrap(),
        ),
        |_, _| true,
        || {},
    )
}

fn accepted(operation: Operation) -> handler::Event {
    handler::Event::ReservationReqAccepted {
        operation,
        renewal: false,
        limit: None,
        expires_at: web_time::Instant::now() + Duration::from_secs(60),
    }
}

#[test]
fn operation_late_legacy_acceptance_after_listener_removal_does_not_panic() {
    let peer = PeerId::random();
    let address: Multiaddr = "/memory/121".parse().unwrap();
    let operation = Operation::capture(None, peer, &address, OperationKind::Reserve).unwrap();
    let (_transport, mut behaviour) = new(PeerId::random());
    let connection = ConnectionId::new_unchecked(1);
    assert!(operation.bind(connection));
    // The listener mapping has already been removed; this used to reach expect().
    behaviour.on_connection_handler_event(peer, connection, Either::Left(accepted(operation)));
    assert!(
        behaviour.queued_actions.is_empty(),
        "late acceptance published without listener"
    );
}

#[test]
fn operation_stale_acceptance_cannot_confirm_successor_mapping() {
    let peer = PeerId::random();
    let address: Multiaddr = "/memory/121".parse().unwrap();
    let (_old_owner, old) = operation(peer, address.clone(), 1);
    let (_new_owner, new) = operation(peer, address.clone(), 2);
    let (_transport, mut behaviour) = new_client();
    let connection = ConnectionId::new_unchecked(1);
    behaviour
        .reservation_addresses
        .insert(connection, (address, ReservationStatus::Pending, new));
    behaviour.on_connection_handler_event(peer, connection, Either::Left(accepted(old)));
    assert!(behaviour.queued_actions.is_empty());
    assert_eq!(
        behaviour.reservation_addresses[&connection].1,
        ReservationStatus::Pending
    );
}

fn new_client() -> (Transport, Behaviour) {
    new(PeerId::random())
}

#[test]
fn operation_queued_acceptance_is_rechecked_at_publication() {
    let peer = PeerId::random();
    let address: Multiaddr = "/memory/121".parse().unwrap();
    let (owner, operation) = operation(peer, address.clone(), 1);
    let (_transport, mut behaviour) = new_client();
    let connection = ConnectionId::new_unchecked(1);
    behaviour.reservation_addresses.insert(
        connection,
        (address, ReservationStatus::Pending, operation.clone()),
    );
    behaviour.on_connection_handler_event(peer, connection, Either::Left(accepted(operation)));
    assert_eq!(
        behaviour.queued_actions.len(),
        2,
        "positive acceptance was not queued"
    );
    owner.cancel();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(
        behaviour.poll(&mut cx).is_pending(),
        "revoked external address published"
    );
    assert!(
        behaviour.poll(&mut cx).is_pending(),
        "revoked acceptance published"
    );
    assert!(behaviour.queued_actions.is_empty());
}

#[test]
fn operation_factory_runs_at_listen_call_and_stale_connected_reuse_is_denied() {
    let peer = PeerId::random();
    let address: Multiaddr = "/memory/121".parse().unwrap();
    let (owner, operation) = operation(peer, address.clone(), 1);
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let factory: OperationFactory = Arc::new(move |_, _, _| {
        count.fetch_add(1, Ordering::SeqCst);
        Ok(operation.clone())
    });
    let (mut transport, mut behaviour) = new_with_operation_factory(PeerId::random(), factory);
    let connection = ConnectionId::new_unchecked(1);
    behaviour
        .directly_connected_peers
        .insert(peer, vec![connection]);
    let listener = ListenerId::next();
    transport
        .listen_on(
            listener,
            address.with(Protocol::P2p(peer)).with(Protocol::P2pCircuit),
        )
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "factory deferred beyond listen call"
    );
    let mut cx = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut transport).poll(&mut cx).is_pending());
    owner.cancel();
    assert!(
        behaviour.poll(&mut cx).is_pending(),
        "stale connected reuse emitted NotifyHandler"
    );
    assert!(behaviour.pending_handler_commands.is_empty());
    assert!(behaviour.reservation_addresses.is_empty());
}

#[test]
fn operation_factory_runs_at_dial_call_even_if_future_is_never_polled() {
    let peer = PeerId::random();
    let destination = PeerId::random();
    let address: Multiaddr = "/memory/121".parse().unwrap();
    let kind = OperationKind::Connect { destination };
    let (owner, operation) = Operation::owned(
        OperationDescriptor::new(peer, address.clone(), kind, NonZeroU64::new(1).unwrap()),
        |_, _| true,
        || {},
    );
    let retained = operation.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let factory: OperationFactory = Arc::new(move |_, _, _| {
        count.fetch_add(1, Ordering::SeqCst);
        Ok(operation.clone())
    });
    let (mut transport, _behaviour) = new_with_operation_factory(PeerId::random(), factory);
    let future = transport
        .dial(
            address
                .with(Protocol::P2p(peer))
                .with(Protocol::P2pCircuit)
                .with(Protocol::P2p(destination)),
            libp2p_core::transport::DialOpts {
                role: Endpoint::Dialer,
                port_use: PortUse::New,
            },
        )
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "factory deferred beyond dial call"
    );
    assert!(retained.live());
    drop(future);
    assert!(
        !retained.live(),
        "unpolled dial drop did not cancel operation"
    );
    drop(owner);
}
