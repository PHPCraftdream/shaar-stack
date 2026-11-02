// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use super::KrpcSocket;
use crate::common::{
    ErrorSpecific, Id, Message, MessageType, RequestSpecific, RequestTypeSpecific,
};
use crate::resource::{OperationId, ResourceError};
use tokio::sync::oneshot;

fn capture() -> (UdpSocket, SocketAddrV4) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("loopback capture");
    let address = match socket.local_addr().expect("capture address") {
        std::net::SocketAddr::V4(address) => address,
        _ => unreachable!("IPv4 socket"),
    };
    socket.set_nonblocking(true).expect("nonblocking capture");
    (socket, address)
}

fn ping() -> RequestSpecific {
    RequestSpecific {
        requester_id: Id::from([1_u8; 20]),
        request_type: RequestTypeSpecific::Ping,
    }
}

fn owned_socket() -> KrpcSocket {
    let mut socket = KrpcSocket::client().expect("KRPC socket");
    socket.enable_owned_resources();
    socket
}

fn new_operation(socket: &mut KrpcSocket) -> OperationId {
    socket.allocate_operation().expect("operation")
}

#[tokio::test]
async fn past_deadline_request_is_rejected_without_resource_growth() {
    let (_, destination) = capture();
    let mut socket = owned_socket();
    let operation = new_operation(&mut socket);
    socket
        .register_owned_deadline(operation, tokio::time::Instant::now())
        .unwrap();
    assert_eq!(
        socket.request_owned(destination, ping(), operation),
        Err(ResourceError::DeadlineExceeded)
    );
    assert_eq!(socket.owned_test_state(), Some((0, 0, 0, 0)));
}

#[tokio::test(start_paused = true)]
async fn queued_packet_with_tightened_expired_deadline_is_not_transmitted() {
    let (peer, destination) = capture();
    let mut socket = owned_socket();
    let operation = new_operation(&mut socket);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    socket.register_owned_deadline(operation, deadline).unwrap();
    socket
        .request_owned(destination, ping(), operation)
        .unwrap();
    socket
        .register_owned_deadline(operation, deadline - Duration::from_secs(1))
        .unwrap();
    tokio::time::advance(Duration::from_secs(9)).await;
    socket.flush_owned().await;
    let state = socket.owned_test_state().unwrap();
    assert_eq!((state.0, state.2, state.3), (0, 0, 0));
    assert_eq!(
        peer.recv_from(&mut [0; 2048]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn expired_request_does_not_block_a_later_valid_packet() {
    let (peer, destination) = capture();
    let mut socket = owned_socket();
    let expired = new_operation(&mut socket);
    let valid = new_operation(&mut socket);
    let future = tokio::time::Instant::now() + Duration::from_secs(30);
    socket.register_owned_deadline(expired, future).unwrap();
    socket.register_owned_deadline(valid, future).unwrap();
    let expired_tid = socket.request_owned(destination, ping(), expired).unwrap();
    let valid_tid = socket.request_owned(destination, ping(), valid).unwrap();
    socket
        .register_owned_deadline(expired, tokio::time::Instant::now())
        .unwrap();
    socket.flush_owned().await;
    let mut bytes = [0; 2048];
    let (length, _) = peer.recv_from(&mut bytes).unwrap();
    assert_eq!(
        Message::from_bytes(&bytes[..length])
            .unwrap()
            .transaction_id,
        valid_tid
    );
    assert!(!socket.owned_inflight(expired_tid));
    assert!(socket.owned_inflight(valid_tid));
    assert_eq!(socket.owned_test_state(), Some((0, 0, 1, 1)));
    assert_eq!(socket.owned_failure(), None);
}

#[tokio::test]
async fn owned_deadline_registration_is_bounded_and_never_extended() {
    let mut socket = owned_socket();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let first = new_operation(&mut socket);
    socket.register_owned_deadline(first, deadline).unwrap();
    socket
        .register_owned_deadline(first, deadline + Duration::from_secs(10))
        .unwrap();
    assert_eq!(socket.owned_deadline(first), Some(deadline));
    let earlier = deadline - Duration::from_secs(1);
    socket.register_owned_deadline(first, earlier).unwrap();
    assert_eq!(socket.owned_deadline(first), Some(earlier));
    for _ in 0..7 {
        let operation = new_operation(&mut socket);
        socket.register_owned_deadline(operation, deadline).unwrap();
    }
    let ninth = new_operation(&mut socket);
    assert_eq!(
        socket.register_owned_deadline(ninth, deadline),
        Err(ResourceError::OperationLimit)
    );
}

#[tokio::test]
async fn operation_and_aggregate_caps_apply_to_actual_transactions() {
    let (_, destination) = capture();
    let mut socket = owned_socket();
    let first = new_operation(&mut socket);
    for _ in 0..16 {
        socket.request_owned(destination, ping(), first).unwrap();
    }
    assert_eq!(
        socket.request_owned(destination, ping(), first),
        Err(ResourceError::RpcLimit)
    );
    assert_eq!(socket.operation_rpc_len(first), 16);
    for _ in 1..8 {
        let operation = new_operation(&mut socket);
        for _ in 0..16 {
            socket
                .request_owned(destination, ping(), operation)
                .unwrap();
        }
    }
    let full_state = socket.owned_test_state().unwrap();
    assert_eq!((full_state.0, full_state.2, full_state.3), (128, 128, 128));
    let ninth = new_operation(&mut socket);
    assert_eq!(
        socket.request_owned(destination, ping(), ninth),
        Err(ResourceError::RpcLimit)
    );
    assert_eq!(socket.owned_test_state(), Some(full_state));
}

#[tokio::test]
async fn encode_and_enqueue_failures_rollback_all_real_reservations() {
    let (_, destination) = capture();
    let mut socket = owned_socket();
    let operation = new_operation(&mut socket);
    socket.fail_next_encode_for_test();
    assert_eq!(
        socket.request_owned(destination, ping(), operation),
        Err(ResourceError::Encode)
    );
    assert_eq!(socket.owned_test_state(), Some((0, 0, 0, 0)));
    socket.fail_next_enqueue_for_test();
    assert_eq!(
        socket.request_owned(destination, ping(), operation),
        Err(ResourceError::Enqueue)
    );
    assert_eq!(socket.owned_test_state(), Some((0, 0, 0, 0)));
    assert!(socket.request_owned(destination, ping(), operation).is_ok());
}

#[tokio::test]
async fn outbox_count_and_size_bounds_charge_real_queue() {
    let (peer, destination) = capture();
    let mut socket = owned_socket();
    socket
        .send_datagram_owned(vec![0; 2048], destination)
        .unwrap();
    assert_eq!(socket.owned_test_state(), Some((1, 2048, 0, 0)));
    socket.flush_owned().await;
    let mut received = [0; 2048];
    let (length, _) = peer.recv_from(&mut received).unwrap();
    assert_eq!(length, 2048);
    assert_eq!(socket.owned_test_state(), Some((0, 0, 0, 0)));

    let (peer, destination) = capture();
    let mut socket = owned_socket();
    for _ in 0..128 {
        socket
            .send_datagram_owned(vec![0; 2048], destination)
            .unwrap();
    }
    let state = socket.owned_test_state().unwrap();
    assert_eq!((state.0, state.2, state.3), (128, 0, 0));
    assert_eq!(state.1, 128 * 2048);
    assert_eq!(
        socket.send_datagram_owned(vec![0], destination),
        Err(ResourceError::OutboxFull)
    );
    assert_eq!(socket.owned_test_state(), Some(state));
    socket.flush_owned().await;
    let mut received = [0; 2048];
    let (length, _) = peer.recv_from(&mut received).unwrap();
    assert_eq!(length, 2048);
    assert_eq!(socket.owned_test_state(), Some((0, 0, 0, 0)));
    let mut other = owned_socket();
    assert_eq!(
        other.send_datagram_owned(vec![0; 2049], destination),
        Err(ResourceError::DatagramTooLarge)
    );
    assert_eq!(other.owned_test_state(), Some((0, 0, 0, 0)));
}

#[tokio::test]
async fn cancellation_at_real_send_gate_retains_rpc_and_datagram_charges() {
    let (_, destination) = capture();
    let mut socket = owned_socket();
    let operation = new_operation(&mut socket);
    let tid = socket
        .request_owned(destination, ping(), operation)
        .unwrap();
    for _ in 0..127 {
        socket
            .send_datagram_owned(vec![0; 2048], destination)
            .unwrap();
    }
    let (entered, entered_rx) = oneshot::channel();
    let (release, release_rx) = oneshot::channel();
    socket.hold_next_send_for_test(entered, release_rx);
    let mut flush = Box::pin(socket.flush_owned());
    tokio::select! { result = entered_rx => result.unwrap(), _ = &mut flush => panic!("send was not held") }
    drop(flush);
    let state = socket.owned_test_state().unwrap();
    assert_eq!((state.0, state.2, state.3), (128, 1, 1));
    assert!(state.1 > 127 * 2048);
    assert!(release.send(()).is_err());
    socket.expire_owned_requests(Duration::ZERO);
    assert_eq!(socket.owned_test_state(), Some(state));
    assert_eq!(
        socket.send_datagram_owned(vec![0], destination),
        Err(ResourceError::OutboxFull)
    );
    socket.flush_owned().await;
    let state = socket.owned_test_state().unwrap();
    assert_eq!((state.0, state.2, state.3), (0, 1, 1));
    assert_eq!(state.1, 0);
    assert!(socket.owned_inflight(tid));
    socket.cancel_owned_operation(operation);
    assert_eq!(socket.owned_test_state(), Some((0, 0, 0, 0)));
}

#[tokio::test]
async fn send_failure_and_timeout_release_actual_owned_transactions() {
    let (_, destination) = capture();
    let mut failed = owned_socket();
    let operation = new_operation(&mut failed);
    failed
        .request_owned(destination, ping(), operation)
        .unwrap();
    failed.fail_next_send_for_test();
    failed.flush_owned().await;
    assert_eq!(failed.owned_failure(), None);
    assert_eq!(
        failed.take_owned_operation_errors(),
        vec![(operation, ResourceError::Send)]
    );
    assert_eq!(failed.owned_test_state(), Some((0, 0, 0, 0)));
    let (peer, destination) = capture();
    let mut socket = owned_socket();
    let operation = new_operation(&mut socket);
    let tid = socket
        .request_owned(destination, ping(), operation)
        .unwrap();
    socket.flush_owned().await;
    let mut bytes = [0; 2048];
    let (length, _) = peer.recv_from(&mut bytes).unwrap();
    assert_eq!(
        Message::from_bytes(&bytes[..length])
            .unwrap()
            .transaction_id,
        tid
    );
    assert!(socket.owned_inflight(tid));
    assert_eq!(socket.owned_test_state(), Some((0, 0, 1, 1)));
    socket.expire_owned_requests(Duration::ZERO);
    assert_eq!(socket.owned_test_state(), Some((0, 0, 0, 0)));
    assert_eq!(socket.owned_failure(), None);
}

#[tokio::test]
async fn cancellation_releases_only_selected_operation() {
    let (_, destination) = capture();
    let mut socket = owned_socket();
    let first = new_operation(&mut socket);
    let second = new_operation(&mut socket);
    let first_tid = socket.request_owned(destination, ping(), first).unwrap();
    let second_tid = socket.request_owned(destination, ping(), second).unwrap();
    socket.cancel_owned_operation(first);
    assert!(!socket.owned_inflight(first_tid));
    assert!(socket.owned_inflight(second_tid));
    assert_eq!(socket.operation_rpc_len(first), 0);
    assert_eq!(socket.operation_rpc_len(second), 1);
    socket.cancel_owned_operation(second);
    assert_eq!(socket.owned_test_state(), Some((0, 0, 0, 0)));
}

#[tokio::test]
async fn actual_udp_wrong_source_cannot_complete_transaction() {
    let (peer, destination) = capture();
    let (wrong_peer, _) = capture();
    let mut socket = owned_socket();
    let operation = new_operation(&mut socket);
    let tid = socket
        .request_owned(destination, ping(), operation)
        .unwrap();
    socket.flush_owned().await;

    let mut bytes = [0; 2048];
    let (length, local) = peer.recv_from(&mut bytes).unwrap();
    let request = Message::from_bytes(&bytes[..length]).unwrap();
    assert_eq!(request.transaction_id, tid);
    let reply = Message {
        transaction_id: request.transaction_id,
        message_type: MessageType::Error(ErrorSpecific {
            code: 201,
            description: "fixture version".to_owned(),
        }),
        version: request.version,
        read_only: false,
        requester_ip: None,
    }
    .to_bytes()
    .unwrap();

    wrong_peer.send_to(&reply, local).unwrap();
    assert!(socket.recv_from().await.is_none());
    assert!(socket.owned_inflight(tid));
    assert_eq!(socket.owned_test_state().unwrap().2, 1);

    peer.send_to(&reply, local).unwrap();
    assert!(socket.recv_from().await.is_some());
    assert!(!socket.owned_inflight(tid));
    assert_eq!(socket.owned_test_state(), Some((0, 0, 0, 0)));
}

#[tokio::test]
async fn owned_transaction_id_space_exhausts_without_reusing_or_leaking_state() {
    let (_, destination) = capture();
    let mut socket = owned_socket();
    socket.inflight_requests.next_tid = u32::MAX - 1;
    let operation = new_operation(&mut socket);
    assert_eq!(
        socket
            .request_owned(destination, ping(), operation)
            .unwrap(),
        u32::MAX - 1
    );
    assert_eq!(
        socket
            .request_owned(destination, ping(), operation)
            .unwrap(),
        u32::MAX
    );
    let retained = socket.owned_test_state().unwrap();
    assert_eq!((retained.0, retained.2, retained.3), (2, 2, 2));
    assert!(retained.1 > 0);
    assert_eq!(socket.operation_rpc_len(operation), 2);
    assert_eq!(
        socket.request_owned(destination, ping(), operation),
        Err(ResourceError::TransactionSpaceExhausted)
    );
    assert_eq!(socket.owned_test_state(), Some(retained));
    socket.cancel_owned_operation(operation);
    assert_eq!(socket.owned_test_state(), Some((0, 0, 0, 0)));
}

#[tokio::test]
async fn unowned_legacy_socket_keeps_unbounded_request_path() {
    let (_, destination) = capture();
    let mut socket = KrpcSocket::client().unwrap();
    for _ in 0..129 {
        let tid = socket.request(destination, ping());
        assert!(socket.inflight(&tid));
        assert_eq!(socket.owned_test_state(), None);
    }
    assert!(!socket.is_owned_profile());
}

#[tokio::test(start_paused = true)]
async fn original_deadline_is_enforced_at_real_send_after_flush_cancellation() {
    for expired in [false, true] {
        let (peer, destination) = capture();
        let mut socket = owned_socket();
        let operation = new_operation(&mut socket);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        socket.register_owned_deadline(operation, deadline).unwrap();
        let tid = socket
            .request_owned(destination, ping(), operation)
            .unwrap();
        let (entered, entered_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        socket.hold_next_persistent_send_for_test(entered, release_rx);
        let mut flush = Box::pin(socket.flush_owned());
        tokio::select! { result = entered_rx => result.unwrap(), _ = &mut flush => panic!("persistent send was not held") }
        drop(flush);
        let state = socket.owned_test_state().unwrap();
        assert_eq!((state.0, state.2, state.3), (1, 1, 1));
        assert!(state.1 > 0);

        tokio::time::advance(if expired {
            Duration::from_secs(10)
        } else {
            Duration::from_millis(9_999)
        })
        .await;
        assert!(release.send(()).is_ok());
        socket.flush_owned().await;

        if expired {
            assert_eq!(
                peer.recv_from(&mut [0; 2048]).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            let state = socket.owned_test_state().unwrap();
            assert_eq!((state.0, state.2, state.3), (0, 0, 0));
            assert_eq!(state.1, 0);
            assert_eq!(socket.owned_failure(), None);
        } else {
            let mut bytes = [0; 2048];
            let (length, _) = peer.recv_from(&mut bytes).unwrap();
            assert_eq!(
                Message::from_bytes(&bytes[..length])
                    .unwrap()
                    .transaction_id,
                tid
            );
            let state = socket.owned_test_state().unwrap();
            assert_eq!((state.0, state.2, state.3), (0, 1, 1));
            assert_eq!(state.1, 0);
            assert_eq!(socket.owned_failure(), None);
            socket.cancel_owned_operation(operation);
        }
        assert_eq!(socket.owned_test_state(), Some((0, 0, 0, 0)));
    }
}
