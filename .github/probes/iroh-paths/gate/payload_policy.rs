#![forbid(unsafe_code)]
//! Initial sans-I/O calibration only; not a per-egress P03 acceptance test.

use bytes::Bytes;

use std::net::IpAddr;

use super::util::{ConnPair, ConnPairBuilder, ManyToManyRouting, Pair};
use crate::{Dir, FourTuple, PathId, PathStatus, Side};

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

// Synthetic route classification only; production needs authenticated transport mapping.
fn allow_secondary_tuple(path: FourTuple) -> bool {
    matches!(path.remote.ip(), IpAddr::V6(ip) if ip.segments()[7] > 1)
}

fn open_backup(pair: &mut ConnPair, tuple: FourTuple) -> PathId {
    let id = pair
        .open_path(Side::Client, tuple, PathStatus::Backup)
        .unwrap();
    assert!(!pair.drive_bounded(100), "path validation settles");
    pair.set_path_status(Side::Server, id, PathStatus::Backup)
        .unwrap();
    assert!(!pair.drive_bounded(100), "path status exchange settles");
    for side in [Side::Client, Side::Server] {
        assert_eq!(
            pair.path_status(side, PathId::ZERO).unwrap(),
            PathStatus::Available
        );
        assert_eq!(pair.path_status(side, id).unwrap(), PathStatus::Backup);
    }
    id
}

fn assert_control_only(pair: &mut ConnPair) {
    for side in [Side::Client, Side::Server] {
        let control = pair.path_stats(side, PathId::ZERO).unwrap();
        assert_eq!(control.frame_tx.stream, 0, "no STREAM on control path");
        assert_eq!(control.frame_tx.datagram, 0, "no DATAGRAM on control path");
    }
}

fn assert_backup_payload(pair: &mut ConnPair, id: PathId) {
    for side in [Side::Client, Side::Server] {
        let data = pair.path_stats(side, id).unwrap();
        assert!(data.frame_tx.stream > 0, "eligible Backup carries STREAM");
        assert!(
            data.frame_tx.datagram > 0,
            "eligible Backup carries DATAGRAM"
        );
    }
    assert_control_only(pair);
}

#[test]
fn payload_policy_backup_preference_and_path_recovery() {
    let clients = [
        Pair::CLIENT_ADDR,
        "[::1:2]:1".parse().unwrap(),
        "[::1:3]:1".parse().unwrap(),
    ];
    let servers = [
        Pair::SERVER_ADDR,
        "[::2:2]:1".parse().unwrap(),
        "[::2:3]:1".parse().unwrap(),
    ];
    let mut builder = ConnPair::builder()
        .enable_multipath()
        .disable_mtud_discovery()
        .with_routes(ManyToManyRouting::simple_symmetric(clients, servers));
    builder
        .client_transport_cfg
        .application_data_filter(allow_secondary_tuple);
    builder
        .server_transport_cfg
        .application_data_filter(allow_secondary_tuple);
    let mut pair = builder.connect();

    // Queued payload cannot bootstrap over the only existing, denied path.
    enqueue(&mut pair, Side::Client);
    enqueue(&mut pair, Side::Server);
    assert!(!pair.drive_bounded(100));
    assert_no_payload(&mut pair, Side::Client);
    assert_no_payload(&mut pair, Side::Server);

    let first = open_backup(
        &mut pair,
        FourTuple {
            remote: servers[1],
            local_ip: Some(clients[1].ip()),
        },
    );
    // No requeue: appearance of an eligible path must release pending data.
    assert_backup_payload(&mut pair, first);
    let before = pair
        .path_stats(Side::Server, first)
        .unwrap()
        .frame_tx
        .stream;
    enqueue(&mut pair, Side::Client);
    enqueue(&mut pair, Side::Server);
    assert!(!pair.drive_bounded(100));
    assert!(
        pair.path_stats(Side::Server, first)
            .unwrap()
            .frame_tx
            .stream
            > before
    );
    assert_backup_payload(&mut pair, first);

    // Explicit abandonment, not a claim about detecting physical packet loss.
    pair.close_path(Side::Client, first, 0u8.into()).unwrap();
    assert!(!pair.drive_bounded(100));
    assert!(pair.path_status(Side::Client, first).is_err());
    enqueue(&mut pair, Side::Client);
    enqueue(&mut pair, Side::Server);
    pair.ping_path(Side::Client, PathId::ZERO).unwrap();
    pair.ping_path(Side::Server, PathId::ZERO).unwrap();
    assert!(!pair.drive_bounded(100));
    assert_control_only(&mut pair);

    let recovered = open_backup(
        &mut pair,
        FourTuple {
            remote: servers[2],
            local_ip: Some(clients[2].ip()),
        },
    );
    assert_ne!(first, recovered);
    assert_backup_payload(&mut pair, recovered);
    assert!(!pair.is_closed(Side::Client));
    assert!(!pair.is_closed(Side::Server));
}
