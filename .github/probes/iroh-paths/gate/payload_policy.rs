#![forbid(unsafe_code)]
//! Initial sans-I/O calibration only; not a per-egress P03 acceptance test.

use bytes::Bytes;

use super::util::{ConnPair, ConnPairBuilder};
use crate::{Dir, FourTuple, Side};

fn deny(_: FourTuple) -> bool {
    false
}

fn allow(_: FourTuple) -> bool {
    true
}

fn enqueue(pair: &mut ConnPair, side: Side) {
    let stream = pair.streams(side).open(Dir::Uni).expect("stream allowance");
    assert_eq!(pair.send_stream(side, stream).write(b"payload").unwrap(), 7);
    pair.send_stream(side, stream).finish().unwrap();
    pair.conn_mut(side)
        .datagrams()
        .send(Bytes::from_static(b"payload-datagram"), false)
        .unwrap();
}

fn assert_no_payload(pair: &mut ConnPair, side: Side) {
    let stats = pair.conn_mut(side).stats();
    assert_eq!(stats.frame_tx.stream, 0, "STREAM serialization forbidden");
    assert_eq!(
        stats.frame_tx.datagram, 0,
        "DATAGRAM serialization forbidden"
    );
    assert!(stats.frame_tx.crypto > 0, "real crypto handshake completed");
}

#[test]
fn payload_policy_all_denied_bootstraps_and_becomes_quiescent() {
    let mut builder = ConnPairBuilder::default().disable_mtud_discovery();
    builder.client_transport_cfg.application_data_filter(deny);
    builder.server_transport_cfg.application_data_filter(deny);
    let mut pair = builder.connect();
    assert_no_payload(&mut pair, Side::Client);
    assert_no_payload(&mut pair, Side::Server);
    enqueue(&mut pair, Side::Client);
    enqueue(&mut pair, Side::Server);
    // Force packet construction while payload is queued: readiness alone is insufficient.
    pair.conn_mut(Side::Client).ping();
    pair.conn_mut(Side::Server).ping();
    assert!(!pair.drive_bounded(100), "denied payload must not spin");
    assert!(pair.conn_mut(Side::Client).stats().frame_tx.ping > 0);
    assert!(pair.conn_mut(Side::Server).stats().frame_tx.ping > 0);
    assert_no_payload(&mut pair, Side::Client);
    assert_no_payload(&mut pair, Side::Server);
    assert_eq!(pair.conn_mut(Side::Client).stats().frame_rx.stream, 0);
    assert_eq!(pair.conn_mut(Side::Server).stats().frame_rx.stream, 0);
}

#[test]
fn payload_policy_allow_positive_calibration() {
    let mut builder = ConnPairBuilder::default().disable_mtud_discovery();
    builder.client_transport_cfg.application_data_filter(allow);
    builder.server_transport_cfg.application_data_filter(allow);
    let mut pair = builder.connect();
    enqueue(&mut pair, Side::Client);
    enqueue(&mut pair, Side::Server);
    assert!(!pair.drive_bounded(100), "positive calibration settles");
    for side in [Side::Client, Side::Server] {
        let stats = pair.conn_mut(side).stats();
        assert!(stats.frame_tx.stream > 0);
        assert!(stats.frame_tx.datagram > 0);
        assert!(stats.frame_rx.stream > 0);
        assert!(stats.frame_rx.datagram > 0);
    }
}

#[test]
fn payload_policy_is_independent_in_each_direction() {
    let mut builder = ConnPairBuilder::default().disable_mtud_discovery();
    builder.client_transport_cfg.application_data_filter(deny);
    let mut pair = builder.connect();
    enqueue(&mut pair, Side::Client);
    enqueue(&mut pair, Side::Server);
    assert!(!pair.drive_bounded(100));
    assert_no_payload(&mut pair, Side::Client);
    assert_eq!(pair.conn_mut(Side::Server).stats().frame_rx.stream, 0);
    assert_eq!(pair.conn_mut(Side::Server).stats().frame_rx.datagram, 0);
    assert!(pair.conn_mut(Side::Client).stats().frame_rx.stream > 0);
    assert!(pair.conn_mut(Side::Client).stats().frame_rx.datagram > 0);
}

#[test]
fn payload_policy_denial_preserves_send_backpressure() {
    let mut builder = ConnPairBuilder::default().disable_mtud_discovery();
    builder.client_transport_cfg.application_data_filter(deny);
    builder.client_transport_cfg.send_window(4);
    let mut pair = builder.connect();
    let stream = pair.streams(Side::Client).open(Dir::Uni).unwrap();
    assert_eq!(
        pair.send_stream(Side::Client, stream)
            .write(b"pending")
            .unwrap(),
        4
    );
    assert!(matches!(
        pair.send_stream(Side::Client, stream).write(b"more"),
        Err(crate::WriteError::Blocked)
    ));
    assert!(!pair.drive_bounded(100));
    assert!(matches!(
        pair.send_stream(Side::Client, stream).write(b"more"),
        Err(crate::WriteError::Blocked)
    ));
    assert_no_payload(&mut pair, Side::Client);
}
