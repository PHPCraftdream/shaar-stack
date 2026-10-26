#![forbid(unsafe_code)]

use super::*;
use crate::operation_gate::{OperationDescriptor, OperationOwner};
use std::{num::NonZeroU64, task::Waker};

fn handler() -> Handler {
    Handler::new(
        PeerId::random(),
        PeerId::random(),
        "/memory/121".parse().unwrap(),
    )
}

fn operation(
    handler: &Handler,
    generation: u64,
    kind: OperationKind,
) -> (OperationOwner, Operation) {
    Operation::owned(
        OperationDescriptor::new(
            handler.remote_peer_id,
            handler.remote_addr.clone(),
            kind,
            NonZeroU64::new(generation).unwrap(),
        ),
        |_, _| true,
        || {},
    )
}

fn accepted(handler: &mut Handler, operation: &Operation) -> mpsc::Receiver<ToListenerMsg> {
    let (sender, receiver) = mpsc::channel(0);
    handler.reservation_operation = Some(operation.clone());
    handler.reservation = Reservation::Accepted {
        renewal_timeout: Delay::new(Duration::from_secs(60)),
        pending_msgs: VecDeque::new(),
        to_listener: sender,
    };
    receiver
}

#[test]
fn operation_stale_reset_cannot_clear_a_successor() {
    let mut handler = handler();
    let (_old_owner, old) = operation(&handler, 1, OperationKind::Reserve);
    let (_new_owner, new) = operation(&handler, 2, OperationKind::Reserve);
    let _listener = accepted(&mut handler, &new);
    handler.on_behaviour_event(In::ResetReservation { operation: old });
    assert!(handler.current(&new));
    assert!(
        handler.reservation.is_some(),
        "stale reset cleared successor"
    );
}

#[test]
fn operation_stale_error_cannot_clear_a_successor() {
    let mut handler = handler();
    let (_old_owner, old) = operation(&handler, 1, OperationKind::Reserve);
    let (_new_owner, new) = operation(&handler, 2, OperationKind::Reserve);
    let _listener = accepted(&mut handler, &new);
    let (sender, _receiver) = mpsc::channel(0);
    assert!(
        handler
            .inflight_reserve_requests
            .try_push(
                async {
                    Err(outbound_hop::ReserveError::Io(
                        io::ErrorKind::BrokenPipe.into(),
                    ))
                },
                (sender, old)
            )
            .is_ok()
    );
    assert!(
        handler
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert!(handler.current(&new));
    assert!(
        handler.reservation.is_some(),
        "stale error cleared successor"
    );
}

fn response() -> outbound_hop::Reservation {
    outbound_hop::Reservation {
        renewal_timeout: Delay::new(Duration::from_secs(60)),
        expires_at: web_time::Instant::now() + Duration::from_secs(80),
        addrs: vec!["/memory/121".parse().unwrap()],
        limit: None,
    }
}

#[test]
fn operation_acceptance_has_a_positive_path_and_rejects_revoked_completion() {
    let mut handler = handler();
    let (owner, operation) = operation(&handler, 1, OperationKind::Reserve);
    let (sender, _receiver) = mpsc::channel(0);
    handler.reservation_operation = Some(operation.clone());
    assert!(
        handler
            .inflight_reserve_requests
            .try_push(
                async { Ok(response()) },
                (sender.clone(), operation.clone())
            )
            .is_ok()
    );
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        handler.poll(&mut cx),
        Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
            Event::ReservationReqAccepted { renewal: false, .. }
        ))
    ));
    owner.cancel();
    assert!(
        handler
            .inflight_reserve_requests
            .try_push(async { Ok(response()) }, (sender, operation))
            .is_ok()
    );
    assert!(
        handler.poll(&mut cx).is_pending(),
        "revoked response published acceptance"
    );
    assert!(
        !handler.reservation.is_some(),
        "revoked response reactivated renewal"
    );
}

#[test]
fn operation_cancelled_first_negotiation_does_not_shift_second_completion() {
    let mut handler = handler();
    let (first_owner, first) = operation(&handler, 1, OperationKind::Reserve);
    let (_second_owner, second) = operation(&handler, 2, OperationKind::Reserve);
    let mut first_receiver = handler.request_stream(&first).unwrap();
    let second_receiver = handler.request_stream(&second).unwrap();
    let first_id = handler.pending_streams[0].0;
    let second_id = handler.pending_streams[1].0;
    first_owner.cancel();
    handler.finish_stream(second_id, Err(StreamUpgradeError::Timeout));
    assert!(matches!(
        futures::executor::block_on(second_receiver),
        Ok(Err(StreamUpgradeError::Timeout))
    ));
    assert!(first_receiver.try_recv().unwrap().is_none());
    assert_eq!(
        handler.pending_streams.len(),
        1,
        "cancelled placeholder disappeared before terminal"
    );
    handler.finish_stream(first_id, Err(StreamUpgradeError::Timeout));
    assert!(futures::executor::block_on(first_receiver).is_err());
    assert!(handler.pending_streams.is_empty());
}

#[test]
fn operation_pending_negotiation_budget_includes_cancelled_placeholders() {
    let mut handler = handler();
    let (owner, operation) = operation(&handler, 1, OperationKind::Reserve);
    let mut receivers = Vec::new();
    for _ in 0..MAX_CONCURRENT_STREAMS_PER_CONNECTION {
        receivers.push(handler.request_stream(&operation).unwrap());
    }
    assert!(handler.request_stream(&operation).is_none());
    owner.cancel();
    let (_next_owner, next) = operation_for_next(&handler);
    assert!(handler.request_stream(&next).is_none());
    assert_eq!(
        handler.pending_streams.len(),
        MAX_CONCURRENT_STREAMS_PER_CONNECTION
    );
}

fn operation_for_next(handler: &Handler) -> (OperationOwner, Operation) {
    operation(handler, 2, OperationKind::Reserve)
}

#[test]
fn operation_receipt_checks_destination_and_relay_identity() {
    let mut handler = handler();
    let destination = PeerId::random();
    let (_owner, operation) = operation(&handler, 1, OperationKind::Connect { destination });
    let (sender, _receiver) = oneshot::channel();
    handler.on_behaviour_event(In::EstablishCircuit {
        operation,
        dst_peer_id: PeerId::random(),
        to_dial: sender,
    });
    assert!(
        handler.pending_streams.is_empty(),
        "mismatched destination admitted"
    );
    let other = self::handler();
    let (_owner, operation) = self::operation(&other, 2, OperationKind::Reserve);
    let (sender, _receiver) = mpsc::channel(0);
    handler.on_behaviour_event(In::Reserve {
        operation,
        to_listener: sender,
    });
    assert!(
        handler.pending_streams.is_empty(),
        "mismatched relay admitted"
    );
}

#[test]
fn operation_revocation_clears_idle_renewal_without_behaviour_polling() {
    let mut handler = handler();
    let (owner, operation) = operation(&handler, 1, OperationKind::Reserve);
    let _listener = accepted(&mut handler, &operation);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(handler.poll(&mut cx).is_pending());
    assert!(handler.connection_keep_alive());
    owner.cancel();
    assert!(handler.poll(&mut cx).is_pending());
    assert!(
        !handler.connection_keep_alive(),
        "revoked idle reservation kept renewing"
    );
    assert!(handler.pending_streams.is_empty());
}
