#![forbid(unsafe_code)]
//! Initial sans-I/O calibration only; not a per-egress P03 acceptance test.

use bytes::Bytes;

use std::{net::IpAddr, time::Duration};

use super::util::{ConnPair, ConnPairBuilder, ManyToManyRouting, Pair};
use crate::{Dir, FourTuple, PathId, PathStatus, Side};

fn deny(_: FourTuple) -> bool {
    false
}

fn allow(_: FourTuple) -> bool {
    true
}

fn enqueue(pair: &mut ConnPair, side: Side) {
    enqueue_connection(pair.conn_mut(side));
}

fn enqueue_connection(connection: &mut crate::Connection) {
    let stream = connection
        .streams()
        .open(Dir::Uni)
        .expect("stream allowance");
    assert_eq!(connection.send_stream(stream).write(b"payload").unwrap(), 7);
    connection.send_stream(stream).finish().unwrap();
    connection
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

#[test]
fn payload_policy_resumed_client_zero_rtt() {
    let cases: [(bool, fn(FourTuple) -> bool); 2] = [(true, allow), (false, deny)];
    for (permitted, filter) in cases {
        let mut builder = ConnPairBuilder::default()
            .disable_mtud_discovery()
            .with_latency(Duration::ZERO);
        builder.client_transport_cfg.application_data_filter(filter);
        builder.server_transport_cfg.application_data_filter(filter);
        let (mut pair, config) = builder.build_pair();
        let first = pair.begin_connect(config.clone());
        assert!(!pair.drive_bounded(100));
        pair.server.assert_accept();
        assert!(!pair.client_conn_mut(first).is_handshaking());
        let now = pair.time;
        pair.client_conn_mut(first)
            .close(now, 0u8.into(), Bytes::new());
        assert!(!pair.drive_bounded(100));

        let resumed = pair.begin_connect(config);
        assert!(
            pair.client_conn_mut(resumed).has_0rtt(),
            "cached early keys required"
        );
        enqueue_connection(pair.client_conn_mut(resumed));
        // No server processing yet: any payload sent now really is early data.
        pair.drive_client();
        assert!(pair.client_conn_mut(resumed).is_handshaking());
        let early = pair.client_conn_mut(resumed).stats();
        assert_eq!(early.frame_tx.stream > 0, permitted, "0-RTT STREAM policy");
        assert_eq!(
            early.frame_tx.datagram > 0,
            permitted,
            "0-RTT DATAGRAM policy"
        );
        assert!(
            early.frame_tx.crypto > 0,
            "ClientHello must still be transmitted"
        );

        assert!(!pair.drive_bounded(100));
        assert!(!pair.client_conn_mut(resumed).is_handshaking());
        assert!(pair.client_conn_mut(resumed).accepted_0rtt());
        let server = pair.server.assert_accept();
        let received = pair.server_conn_mut(server).stats();
        assert_eq!(received.frame_rx.stream > 0, permitted);
        assert_eq!(received.frame_rx.datagram > 0, permitted);
    }
}

#[test]
fn payload_policy_server_half_rtt_before_client_finished() {
    let cases: [(bool, fn(FourTuple) -> bool); 2] = [(true, allow), (false, deny)];
    for (permitted, filter) in cases {
        let mut builder = ConnPairBuilder::default()
            .disable_mtud_discovery()
            .with_latency(Duration::ZERO);
        builder.server_transport_cfg.application_data_filter(filter);
        let (mut pair, config) = builder.build_pair();
        let client = pair.begin_connect(config);
        pair.drive_client();
        pair.drive_server();
        let server = pair.server.assert_accept();
        assert!(pair.client_conn_mut(client).is_handshaking());
        assert!(pair.server_conn_mut(server).is_handshaking());
        enqueue_connection(pair.server_conn_mut(server));
        pair.server_conn_mut(server).ping();
        // Client has not consumed the server flight or sent Finished.
        pair.drive_server();
        assert!(pair.server_conn_mut(server).is_handshaking());
        let early = pair.server_conn_mut(server).stats();
        assert_eq!(
            early.frame_tx.stream > 0,
            permitted,
            "server early STREAM policy"
        );
        assert_eq!(
            early.frame_tx.datagram > 0,
            permitted,
            "server early DATAGRAM policy"
        );
        assert!(early.frame_tx.crypto > 0);

        assert!(!pair.drive_bounded(100));
        assert!(!pair.server_conn_mut(server).is_handshaking());
        assert!(!pair.client_conn_mut(client).is_handshaking());
        let received = pair.client_conn_mut(client).stats();
        assert_eq!(received.frame_rx.stream > 0, permitted);
        assert_eq!(received.frame_rx.datagram > 0, permitted);
    }
}

#[test]
fn payload_policy_lost_stream_retransmission_survives_path_change() {
    const MESSAGE: &[u8] = b"lost-before-ack-payload";
    for sender in [Side::Client, Side::Server] {
        let receiver = match sender {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        };
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
        let lost = open_backup(
            &mut pair,
            FourTuple {
                remote: servers[1],
                local_ip: Some(clients[1].ip()),
            },
        );

        // Only the control route remains reachable; data packets are actually dropped.
        pair.routes = ManyToManyRouting::simple_symmetric([clients[0]], [servers[0]]).into();
        let stream = pair.streams(sender).open(Dir::Uni).unwrap();
        assert_eq!(
            pair.send_stream(sender, stream).write(MESSAGE).unwrap(),
            MESSAGE.len()
        );
        pair.send_stream(sender, stream).finish().unwrap();
        pair.drive_client();
        pair.drive_server();
        assert!(pair.path_stats(sender, lost).unwrap().frame_tx.stream > 0);
        assert_eq!(pair.conn_mut(receiver).stats().frame_rx.stream, 0);

        // No additional writes: a second STREAM serialization must come from loss recovery.
        for _ in 0..100 {
            if pair.path_stats(sender, lost).unwrap().frame_tx.stream > 1 {
                break;
            }
            if !pair.step() {
                break;
            }
        }
        assert!(
            pair.path_stats(sender, lost).unwrap().frame_tx.stream > 1,
            "PTO must retransmit the unacknowledged STREAM on the failed route"
        );
        assert_eq!(pair.conn_mut(receiver).stats().frame_rx.stream, 0);
        assert_control_only(&mut pair);

        pair.close_path(sender, lost, 0u8.into()).unwrap();
        assert!(!pair.drive_bounded(100));
        pair.ping_path(sender, PathId::ZERO).unwrap();
        assert!(!pair.drive_bounded(100));
        assert_control_only(&mut pair);
        assert!(pair.streams(receiver).accept(Dir::Uni).is_none());

        pair.routes =
            ManyToManyRouting::simple_symmetric([clients[0], clients[2]], [servers[0], servers[2]])
                .into();
        let recovered = open_backup(
            &mut pair,
            FourTuple {
                remote: servers[2],
                local_ip: Some(clients[2].ip()),
            },
        );
        assert!(pair.path_stats(sender, recovered).unwrap().frame_tx.stream > 0);
        assert_control_only(&mut pair);
        assert_eq!(pair.streams(receiver).accept(Dir::Uni), Some(stream));
        {
            let mut recv = pair.recv_stream(receiver, stream);
            let mut chunks = recv.read(false).unwrap();
            let chunk = chunks.next(usize::MAX).unwrap().expect("original payload");
            assert_eq!(chunk.offset, 0);
            assert_eq!(chunk.bytes.as_ref(), MESSAGE);
            assert!(chunks.next(usize::MAX).unwrap().is_none(), "FIN preserved");
            let _ = chunks.finalize();
        }
        assert!(!pair.is_closed(sender));
        assert!(!pair.is_closed(receiver));
    }
}
