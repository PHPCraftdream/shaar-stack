#![forbid(unsafe_code)]
//! Deterministic cancellation controls against the actual relay transport/behaviour.

use std::{pin::Pin, task::Context};

use libp2p::{
    Multiaddr, PeerId, Transport,
    core::{
        Endpoint,
        transport::{DialOpts, ListenerId, PortUse, TransportEvent},
    },
    identity::Keypair,
    multiaddr::Protocol,
    relay,
    swarm::{NetworkBehaviour, ToSwarm},
};

fn peer() -> PeerId {
    Keypair::generate_ed25519().public().to_peer_id()
}

fn route(relay_id: PeerId) -> Multiaddr {
    "/ip4/127.0.0.1/tcp/4001"
        .parse::<Multiaddr>()
        .unwrap()
        .with(Protocol::P2p(relay_id))
        .with(Protocol::P2pCircuit)
}

#[test]
fn an_uncancelled_reservation_reaches_the_real_dial_admission() {
    let (mut transport, mut behaviour) = relay::client::new(peer());
    let id = ListenerId::next();
    transport.listen_on(id, route(peer())).unwrap();
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(Pin::new(&mut transport).poll(&mut cx).is_pending());
    assert!(matches!(
        behaviour.poll(&mut cx),
        std::task::Poll::Ready(ToSwarm::Dial { .. })
    ));
}

#[test]
fn an_uncancelled_circuit_reaches_the_real_dial_admission() {
    let (mut transport, mut behaviour) = relay::client::new(peer());
    let address = route(peer()).with(Protocol::P2p(peer()));
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    let mut dial = transport
        .dial(
            address,
            DialOpts {
                role: Endpoint::Dialer,
                port_use: PortUse::New,
            },
        )
        .unwrap();
    assert!(dial.as_mut().poll(&mut cx).is_pending());
    assert!(matches!(
        behaviour.poll(&mut cx),
        std::task::Poll::Ready(ToSwarm::Dial { .. })
    ));
}

#[test]
fn closing_a_listener_before_transport_dispatch_never_allocates_a_dial() {
    let (mut transport, mut behaviour) = relay::client::new(peer());
    let relay_id = peer();
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    for _ in 0..64 {
        let id = ListenerId::next();
        transport.listen_on(id, route(relay_id)).unwrap();
        assert!(transport.remove_listener(id));
        // The receiver must be closed before reporting ListenerClosed, not on later Drop.
        assert!(matches!(Pin::new(&mut transport).poll(&mut cx),
            std::task::Poll::Ready(TransportEvent::ListenerClosed { listener_id, .. }) if listener_id == id));
        assert!(behaviour.poll(&mut cx).is_pending());
        assert!(behaviour.poll(&mut cx).is_pending());
        assert!(Pin::new(&mut transport).poll(&mut cx).is_pending());
    }
}

#[test]
fn a_cancelled_circuit_future_never_allocates_a_dial_or_handler_request() {
    let (mut transport, mut behaviour) = relay::client::new(peer());
    let address = route(peer()).with(Protocol::P2p(peer()));
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    for _ in 0..64 {
        let mut dial = transport
            .dial(
                address.clone(),
                DialOpts {
                    role: Endpoint::Dialer,
                    port_use: PortUse::New,
                },
            )
            .unwrap();
        assert!(dial.as_mut().poll(&mut cx).is_pending());
        drop(dial);
        assert!(behaviour.poll(&mut cx).is_pending());
        assert!(behaviour.poll(&mut cx).is_pending());
    }
}
