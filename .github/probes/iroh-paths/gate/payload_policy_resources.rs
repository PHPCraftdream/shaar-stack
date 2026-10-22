#![forbid(unsafe_code)]
//! Public-API queue and cancellation contracts through the real Noq harness.

use super::util::{ConnPair, ConnPairBuilder};
use crate::{Dir, FourTuple, SendDatagramError, Side, WriteError};
use bytes::Bytes;

fn deny(_: FourTuple) -> bool {
    false
}
fn allow(_: FourTuple) -> bool {
    true
}

fn pair(send: usize, receive: usize, filter: fn(FourTuple) -> bool) -> ConnPair {
    let mut builder = ConnPairBuilder::default().disable_mtud_discovery();
    for config in [
        &mut builder.client_transport_cfg,
        &mut builder.server_transport_cfg,
    ] {
        config.datagram_send_buffer_size(send);
        config.datagram_receive_buffer_size(Some(receive));
        config.application_data_filter(filter);
    }
    builder.connect()
}

#[test]
fn blocked_datagram_budget_counts_empty_and_nonempty_records() {
    let cases: [(&'static [u8], usize); 2] = [(b"", 4), (b"full", 1)];
    for (payload, admitted) in cases {
        for sender in [Side::Client, Side::Server] {
            let mut pair = pair(4, 64, deny);
            for _ in 0..admitted {
                pair.conn_mut(sender)
                    .datagrams()
                    .send(Bytes::from_static(payload), false)
                    .unwrap();
            }
            assert_eq!(pair.conn_mut(sender).datagrams().send_buffer_space(), 0);
            match pair
                .conn_mut(sender)
                .datagrams()
                .send(Bytes::from_static(payload), false)
            {
                Err(SendDatagramError::Blocked(returned)) => assert_eq!(returned.as_ref(), payload),
                other => panic!("expected send backpressure, got {other:?}"),
            }
            let batch = [Bytes::from_static(payload), Bytes::from_static(payload)];
            assert_eq!(
                pair.conn_mut(sender)
                    .datagrams()
                    .send_many(&batch, false)
                    .unwrap(),
                0
            );
            for _ in 0..8 {
                assert_eq!(
                    pair.conn_mut(sender)
                        .datagrams()
                        .send_many(&batch, true)
                        .unwrap(),
                    2
                );
                assert_eq!(pair.conn_mut(sender).datagrams().send_buffer_space(), 0);
            }
            pair.conn_mut(sender).ping();
            assert!(!pair.drive_bounded(100));
            assert_eq!(pair.conn_mut(sender).stats().frame_tx.datagram, 0);
            assert_eq!(pair.conn_mut(sender).datagrams().send_buffer_space(), 0);
        }
    }
}

#[test]
fn empty_datagram_serialization_and_batch_receive_release_budget() {
    for sender in [Side::Client, Side::Server] {
        let receiver = match sender {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        };
        let mut pair = pair(4, 64, allow);
        let data = [Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new()];
        assert_eq!(
            pair.conn_mut(sender)
                .datagrams()
                .send_many(&data, false)
                .unwrap(),
            4
        );
        assert_eq!(pair.conn_mut(sender).datagrams().send_buffer_space(), 0);
        assert!(!pair.drive_bounded(100));
        assert_eq!(pair.conn_mut(sender).datagrams().send_buffer_space(), 4);
        assert_eq!(pair.conn_mut(sender).stats().frame_tx.datagram, 4);
        assert_eq!(pair.conn_mut(receiver).stats().frame_rx.datagram, 4);
        let mut out = [Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new()];
        assert_eq!(pair.conn_mut(receiver).datagrams().recv_many(&mut out), 4);
        assert!(out.iter().all(Bytes::is_empty));
        assert!(pair.conn_mut(receiver).datagrams().recv().is_none());
    }
}

#[test]
fn zero_send_budget_rejects_empty_single_and_batch() {
    let mut pair = pair(0, 64, allow);
    for sender in [Side::Client, Side::Server] {
        for drop_old in [false, true] {
            assert!(matches!(
                pair.conn_mut(sender)
                    .datagrams()
                    .send(Bytes::new(), drop_old),
                Err(SendDatagramError::TooLarge)
            ));
            assert!(matches!(
                pair.conn_mut(sender)
                    .datagrams()
                    .send_many(&[Bytes::new()], drop_old),
                Err(SendDatagramError::TooLarge)
            ));
        }
        assert_eq!(pair.conn_mut(sender).datagrams().send_buffer_space(), 0);
    }
    assert!(!pair.drive_bounded(100));
    for side in [Side::Client, Side::Server] {
        assert_eq!(pair.conn_mut(side).stats().frame_tx.datagram, 0);
    }
}

#[test]
fn cancelling_queued_stream_restores_window_without_stream_egress() {
    for sender in [Side::Client, Side::Server] {
        let mut builder = ConnPairBuilder::default().disable_mtud_discovery();
        builder
            .client_transport_cfg
            .application_data_filter(deny)
            .send_window(4);
        builder
            .server_transport_cfg
            .application_data_filter(deny)
            .send_window(4);
        let mut pair = builder.connect();
        let first = pair.streams(sender).open(Dir::Uni).unwrap();
        assert_eq!(pair.send_stream(sender, first).write(b"held").unwrap(), 4);
        assert!(matches!(
            pair.send_stream(sender, first).write(b"x"),
            Err(WriteError::Blocked)
        ));
        pair.send_stream(sender, first).reset(0u8.into()).unwrap();
        let next = pair.streams(sender).open(Dir::Uni).unwrap();
        assert_eq!(pair.send_stream(sender, next).write(b"next").unwrap(), 4);
        assert!(!pair.drive_bounded(100));
        assert_eq!(pair.conn_mut(sender).stats().frame_tx.stream, 0);
        assert!(pair.conn_mut(sender).stats().frame_tx.reset_stream > 0);
        assert!(matches!(
            pair.send_stream(sender, next).write(b"x"),
            Err(WriteError::Blocked)
        ));
    }
}
