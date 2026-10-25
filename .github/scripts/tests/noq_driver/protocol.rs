#![forbid(unsafe_code)]

use super::util::ConnPair;
use crate::{ConnectionError, Event, Side};
use std::io::ErrorKind;

#[test]
fn local_abort_is_terminal_ordered_and_idempotent() {
    let mut pair = ConnPair::default();
    let connection = pair.conn_mut(Side::Client);
    while connection.poll_endpoint_events().is_some() {}
    while connection.poll().is_some() {}
    connection.abort_local(ConnectionError::LocalIo(ErrorKind::BrokenPipe));
    assert!(connection.is_closed());
    assert!(connection.is_drained());
    assert!(connection.poll_timeout().is_none());
    assert!(connection.poll_endpoint_events().unwrap().is_draining());
    assert!(connection.poll_endpoint_events().unwrap().is_drained());
    assert!(connection.poll_endpoint_events().is_none());
    assert!(matches!(
        connection.poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::LocalIo(ErrorKind::BrokenPipe),
        })
    ));
    connection.abort_local(ConnectionError::LocallyClosed);
    assert!(connection.poll_endpoint_events().is_none());
    assert!(connection.poll().is_none());
}

#[test]
fn local_abort_finishes_local_close_without_a_second_error() {
    let mut pair = ConnPair::default();
    let now = pair.time;
    let connection = pair.conn_mut(Side::Client);
    while connection.poll_endpoint_events().is_some() {}
    while connection.poll().is_some() {}
    connection.close(now, 41u32.into(), b"already closed".as_slice().into());
    assert!(!connection.is_drained());
    connection.abort_local(ConnectionError::LocalIo(ErrorKind::BrokenPipe));
    assert!(connection.is_drained());
    assert!(connection.poll_timeout().is_none());
    assert!(connection.poll_endpoint_events().unwrap().is_draining());
    assert!(connection.poll_endpoint_events().unwrap().is_drained());
    assert!(connection.poll_endpoint_events().is_none());
    assert!(connection.poll().is_none());
}

fn unread_terminal_error(draining: bool) {
    let mut pair = ConnPair::default();
    let now = pair.time;
    let connection = pair.conn_mut(Side::Client);
    while connection.poll_endpoint_events().is_some() {}
    while connection.poll().is_some() {}
    let original = crate::TransportError::new(
        crate::TransportErrorCode::INTERNAL_ERROR,
        "original terminal error before abort".to_owned(),
    );
    connection.driver_test_terminal(now, original.clone(), draining);
    assert!(connection.is_closed());
    assert!(!connection.is_drained());
    // Do not poll ConnectionLost before the local abort.
    connection.abort_local(ConnectionError::LocalIo(ErrorKind::BrokenPipe));
    connection.abort_local(ConnectionError::LocallyClosed);
    assert!(connection.is_drained());
    assert!(connection.poll_timeout().is_none());
    assert!(connection.poll_endpoint_events().unwrap().is_draining());
    assert!(connection.poll_endpoint_events().unwrap().is_drained());
    assert!(connection.poll_endpoint_events().is_none());
    assert!(
        matches!(connection.poll(), Some(Event::ConnectionLost { reason })
        if reason == ConnectionError::TransportError(original))
    );
    assert!(connection.poll().is_none());
}

#[test]
fn local_abort_preserves_unread_closed_error() {
    unread_terminal_error(false);
}

#[test]
fn local_abort_preserves_unread_draining_error() {
    unread_terminal_error(true);
}
