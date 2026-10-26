#![forbid(unsafe_code)]

use super::*;
use crate::operation_gate::{OperationDescriptor, OperationKind, OperationOwner};
use std::num::NonZeroU64;

fn listener() -> (
    OperationOwner,
    Pin<Box<Listener>>,
    mpsc::Sender<ToListenerMsg>,
) {
    let peer = PeerId::random();
    let address: Multiaddr = "/memory/123".parse().unwrap();
    let (owner, operation) = Operation::owned(
        OperationDescriptor::new(
            peer,
            address,
            OperationKind::Reserve,
            NonZeroU64::new(1).unwrap(),
        ),
        |_, _| true,
        || {},
    );
    // Capacity matches the production listener channel exactly.
    let (to_listener, from_behaviour) = mpsc::channel(0);
    let listener = Listener {
        operation,
        listener_id: ListenerId::next(),
        queued_events: VecDeque::new(),
        from_behaviour,
        is_closed: false,
        waker: None,
    };
    (owner, Box::pin(listener), to_listener)
}

fn poll_event(listener: &mut Pin<Box<Listener>>) -> Poll<Option<<Listener as Stream>::Item>> {
    listener
        .as_mut()
        .poll_next(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn cancelled_operation_delivers_a_queued_typed_rejection_before_closing() {
    let (owner, mut listener, mut to_listener) = listener();
    assert!(
        to_listener
            .try_send(ToListenerMsg::Reservation(Err(ReserveError::Io(
                std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
            ))))
            .is_ok(),
        "queued rejection was not admitted to the listener channel"
    );
    owner.cancel();
    match poll_event(&mut listener) {
        Poll::Ready(Some(TransportEvent::ListenerClosed {
            reason: Err(Error::Reservation(ReserveError::Io(error))),
            ..
        })) => assert_eq!(
            error.kind(),
            std::io::ErrorKind::ConnectionRefused,
            "typed rejection lost its concrete error kind"
        ),
        _ => panic!("cancel did not deliver the concrete typed rejection"),
    }
    assert!(
        matches!(poll_event(&mut listener), Poll::Ready(None)),
        "listener stream did not terminate after the typed close"
    );
}

#[test]
fn cancelled_operation_without_a_queued_message_closes_untyped() {
    let (owner, mut listener, _to_listener) = listener();
    owner.cancel();
    assert!(
        matches!(
            poll_event(&mut listener),
            Poll::Ready(Some(TransportEvent::ListenerClosed { reason: Ok(()), .. }))
        ),
        "cancel without a queued message fabricated a typed rejection"
    );
    assert!(matches!(poll_event(&mut listener), Poll::Ready(None)));
}

#[test]
fn cancelled_operation_never_accepts_a_queued_reservation_success() {
    let (owner, mut listener, mut to_listener) = listener();
    let addresses: Vec<Multiaddr> = vec![
        "/memory/124".parse().unwrap(),
        "/memory/125".parse().unwrap(),
    ];
    assert!(
        to_listener
            .try_send(ToListenerMsg::Reservation(Ok(Reservation {
                addrs: addresses
            })))
            .is_ok()
    );
    owner.cancel();
    assert!(
        matches!(
            poll_event(&mut listener),
            Poll::Ready(Some(TransportEvent::ListenerClosed { reason: Ok(()), .. }))
        ),
        "cancel accepted a queued reservation success"
    );
    assert!(matches!(poll_event(&mut listener), Poll::Ready(None)));
}

#[test]
fn revoked_operation_stops_publishing_already_buffered_addresses() {
    let (owner, mut listener, mut to_listener) = listener();
    let first: Multiaddr = "/memory/124".parse().unwrap();
    let second: Multiaddr = "/memory/125".parse().unwrap();
    assert!(
        to_listener
            .try_send(ToListenerMsg::Reservation(Ok(Reservation {
                addrs: vec![first.clone(), second.clone()],
            })))
            .is_ok()
    );
    match poll_event(&mut listener) {
        Poll::Ready(Some(TransportEvent::NewAddress { listen_addr, .. })) => {
            assert_eq!(
                listen_addr, first,
                "live publication was not the queued head"
            )
        }
        _ => panic!("live operation did not publish the first queued address"),
    }
    owner.cancel();
    assert!(
        matches!(
            poll_event(&mut listener),
            Poll::Ready(Some(TransportEvent::ListenerClosed { reason: Ok(()), .. }))
        ),
        "revoked operation published a buffered address or fabricated a rejection"
    );
    assert!(matches!(poll_event(&mut listener), Poll::Ready(None)));
}

#[test]
fn revoked_buffered_publication_still_delivers_a_queued_typed_rejection() {
    let (owner, mut listener, mut to_listener) = listener();
    let first: Multiaddr = "/memory/124".parse().unwrap();
    let second: Multiaddr = "/memory/125".parse().unwrap();
    assert!(
        to_listener
            .try_send(ToListenerMsg::Reservation(Ok(Reservation {
                addrs: vec![first.clone(), second.clone()],
            })))
            .is_ok()
    );
    match poll_event(&mut listener) {
        Poll::Ready(Some(TransportEvent::NewAddress { listen_addr, .. })) => {
            assert_eq!(
                listen_addr, first,
                "live publication was not the queued head"
            )
        }
        _ => panic!("live operation did not publish the first queued address"),
    }
    // Production order: the rejection is enqueued before the operation is revoked.
    assert!(
        to_listener
            .try_send(ToListenerMsg::Reservation(Err(ReserveError::Io(
                std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
            ))))
            .is_ok(),
        "queued rejection was not admitted to the listener channel"
    );
    owner.cancel();
    match poll_event(&mut listener) {
        Poll::Ready(Some(TransportEvent::ListenerClosed {
            reason: Err(Error::Reservation(ReserveError::Io(error))),
            ..
        })) => assert_eq!(
            error.kind(),
            std::io::ErrorKind::ConnectionRefused,
            "typed rejection lost its concrete error kind"
        ),
        _ => panic!("revocation lost the queued typed rejection or published a buffered address"),
    }
    assert!(matches!(poll_event(&mut listener), Poll::Ready(None)));
}
