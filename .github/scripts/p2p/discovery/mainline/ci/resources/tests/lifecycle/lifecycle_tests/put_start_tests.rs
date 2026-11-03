// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::*;

#[tokio::test]
async fn actual_put_start_deadline_fails_coalesced_put_and_get_waiters() {
    use crate::common::{Message, MessageType};

    let (peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let request = put_request();
    let put_target = *request.target();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    actor
        .owned_put_until(request, None, deadline)
        .expect("owned PUT operation");
    let operation = actor.owned_resources.as_ref().unwrap().operations[&put_target];

    let (put_sender_a, mut put_receiver_a) = oneshot::channel();
    let (put_sender_b, mut put_receiver_b) = oneshot::channel();
    actor
        .put_senders
        .entry(put_target)
        .or_default()
        .push(put_sender_a);
    actor
        .put_senders
        .entry(put_target)
        .or_default()
        .push(put_sender_b);
    let (get_sender_a, mut get_receiver_a) = oneshot::channel();
    let (get_sender_b, mut get_receiver_b) = oneshot::channel();
    actor
        .owned_mutable_until(put_target, get_sender_a, deadline)
        .expect("first coalesced GET waiter");
    actor
        .owned_mutable_until(put_target, get_sender_b, deadline)
        .expect("second coalesced GET waiter");

    actor.socket.flush_owned().await;
    let mut bytes = [0_u8; 4096];
    let (length, source) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut bytes))
        .await
        .expect("GET receipt timeout")
        .expect("receive actual GET");
    let outgoing = Message::from_bytes(&bytes[..length]).expect("decode actual GET");
    assert!(matches!(outgoing.message_type, MessageType::Request(_)));
    let response = Message {
        transaction_id: outgoing.transaction_id,
        version: Some([82, 83, 0, 6]),
        requester_ip: None,
        message_type: MessageType::Error(crate::common::ErrorSpecific {
            code: 201,
            description: "test".to_owned(),
        }),
        read_only: false,
    };
    peer.send_to(
        &response.to_bytes().expect("encode actual error response"),
        source,
    )
    .await
    .expect("send actual error response");
    let (response, from) = actor
        .socket
        .recv_from()
        .await
        .expect("receive actual error response");
    actor.process_message(response, from);
    actor.owned_note_response(outgoing.transaction_id);

    let unrelated_target = target(211);
    let unrelated_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let (unrelated_sender, mut unrelated_receiver) = oneshot::channel();
    actor
        .owned_mutable_until(unrelated_target, unrelated_sender, unrelated_deadline)
        .expect("unrelated live GET");
    let unrelated_operation = actor.owned_resources.as_ref().unwrap().operations[&unrelated_target];
    let (maintenance_peer, maintenance_address) = captured_peer();
    actor
        .owned_ping(maintenance_address)
        .expect("live maintenance ping");
    let maintenance_operation = actor.owned_resources.as_ref().unwrap().maintenance.unwrap();
    assert_eq!(actor.socket.operation_rpc_len(maintenance_operation), 1);

    actor
        .owned_resources
        .as_mut()
        .unwrap()
        .put_start_deadline_operation = Some(operation);
    actor.tick_owned();

    assert!(matches!(
        put_receiver_a.try_recv(),
        Ok(Err(crate::core::PutError::Query(
            crate::core::PutQueryError::Resource(ResourceError::DeadlineExceeded)
        )))
    ));
    assert!(matches!(
        put_receiver_b.try_recv(),
        Ok(Err(crate::core::PutError::Query(
            crate::core::PutQueryError::Resource(ResourceError::DeadlineExceeded)
        )))
    ));
    assert!(matches!(
        get_receiver_a.try_recv(),
        Ok(Err(ResourceError::DeadlineExceeded))
    ));
    assert!(matches!(
        get_receiver_b.try_recv(),
        Ok(Err(ResourceError::DeadlineExceeded))
    ));
    assert_eq!(actor.owned_error(), None);
    assert_eq!(actor.socket.owned_deadline(operation), None);
    assert_eq!(actor.socket.operation_rpc_len(operation), 0);
    assert!(!actor.core.put_queries.contains_key(&put_target));
    assert!(!actor.core.iterative_queries.contains_key(&put_target));
    assert_eq!(
        actor
            .owned_resources
            .as_ref()
            .unwrap()
            .put_start_deadline_operation,
        None
    );

    assert_eq!(
        actor.socket.owned_deadline(unrelated_operation),
        Some(unrelated_deadline)
    );
    assert!(actor.socket.operation_rpc_len(unrelated_operation) > 0);
    assert!(matches!(
        unrelated_receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert_eq!(
        actor.owned_resources.as_ref().unwrap().maintenance,
        Some(maintenance_operation)
    );
    assert!(actor.socket.operation_rpc_len(maintenance_operation) > 0);
    drop(maintenance_peer);
}

#[tokio::test(start_paused = true)]
async fn shared_socket_put_deadline_preserves_get_packet_deadline() {
    use crate::common::{
        GetValueRequestArguments, Id, Message, MessageType, MutableItem, PutMutableRequestArguments,
        PutRequest, PutRequestSpecific, RequestSpecific, RequestTypeSpecific,
    };
    use ed25519_dalek::SigningKey;

    let (peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let operation = actor.socket.allocate_operation().expect("operation");
    let address = bootstrap;
    let original_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    actor
        .socket
        .register_owned_deadline(operation, original_deadline)
        .expect("operation deadline");
    let signing_key = SigningKey::from_bytes(&[3; 32]);
    let item = MutableItem::new(&signing_key, b"value", 1, None);
    let target = *item.target();
    let put_deadline = tokio::time::Instant::now() + Duration::from_millis(100);
    actor
        .socket
        .register_owned_put_deadline(target, put_deadline)
        .expect("PUT deadline");

    let get_tid = actor
        .socket
        .request_owned(
            address,
            RequestSpecific {
                requester_id: Id::random(),
                request_type: RequestTypeSpecific::GetValue(GetValueRequestArguments {
                    target,
                    seq: None,
                    salt: None,
                }),
            },
            operation,
        )
        .expect("enqueue actual GET");
    let put_tid = actor
        .socket
        .request_owned(
            address,
            RequestSpecific {
                requester_id: Id::random(),
                request_type: RequestTypeSpecific::Put(PutRequest {
                    token: Box::new([7]),
                    put_request_type: PutRequestSpecific::PutMutable(
                        PutMutableRequestArguments::from(item, None),
                    ),
                }),
            },
            operation,
        )
        .expect("enqueue actual PUT");

    tokio::time::advance(Duration::from_millis(100)).await;
    tokio::time::resume();
    actor.socket.flush_owned().await;
    let mut bytes = [0_u8; 4096];
    let (length, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut bytes))
        .await
        .expect("GET receipt timeout")
        .expect("receive actual GET");
    let message = Message::from_bytes(&bytes[..length]).expect("decode GET");
    assert_eq!(message.transaction_id, get_tid);
    assert!(matches!(
        message.message_type,
        MessageType::Request(RequestSpecific {
            request_type: RequestTypeSpecific::GetValue(GetValueRequestArguments { target: actual, .. }),
            ..
        }) if actual == target
    ));
    assert!(actor.socket.inflight(&get_tid));
    assert!(!actor.socket.inflight(&put_tid));
    assert_eq!(actor.socket.operation_rpc_len(operation), 1);
    assert_eq!(actor.socket.owned_deadline(operation), Some(original_deadline));
    assert_eq!(
        peer.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "expired PUT must not be transmitted"
    );
}
