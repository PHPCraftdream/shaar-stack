// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::*;

#[path = "lifecycle_tests/put_start_tests.rs"]
mod put_start;

#[path = "lifecycle_tests/retry_tests.rs"]
mod retries;

#[tokio::test]
async fn maintenance_epoch_does_not_renew_deadline_or_rounds_before_expiry() {
    use crate::common::{Message, MessageType};

    let (peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let target = *actor.core.routing_table.id();
    let base = tokio::time::Instant::now();
    let deadline = base + Duration::from_secs(10);
    actor
        .owned_get_until(
            GetRequestSpecific::FindNode(FindNodeRequestArguments { target }),
            None,
            deadline,
        )
        .expect("maintenance operation");
    let operation = actor.owned_resources.as_ref().unwrap().maintenance.unwrap();
    let mut bytes = [0_u8; 4096];
    actor.socket.flush_owned().await;
    let (length, source) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut bytes))
        .await
        .expect("GET receipt timeout")
        .expect("receive maintenance GET");
    let request = Message::from_bytes(&bytes[..length]).expect("decode maintenance GET");
    assert!(matches!(request.message_type, MessageType::Request(_)));
    peer.send_to(
        &Message {
            transaction_id: request.transaction_id,
            version: Some([82, 83, 0, 6]),
            requester_ip: None,
            message_type: MessageType::Error(crate::common::ErrorSpecific {
                code: 201,
                description: "test".to_owned(),
            }),
            read_only: false,
        }
        .to_bytes()
        .expect("encode error response"),
        source,
    )
    .await
    .expect("send maintenance response");
    let (response, from) = actor
        .socket
        .recv_from()
        .await
        .expect("receive maintenance response");
    actor.process_message(response, from);
    actor.owned_note_response(request.transaction_id);
    actor.tick_owned();
    assert_eq!(
        actor.owned_resources.as_ref().unwrap().maintenance,
        Some(operation)
    );
    assert_eq!(actor.socket.owned_deadline(operation), Some(deadline));
    assert!(!actor.core.iterative_queries.contains_key(&target));

    actor.periodic_node_maintaenance();
    assert_eq!(
        actor.owned_resources.as_ref().unwrap().maintenance,
        Some(operation)
    );
    assert_eq!(actor.socket.owned_deadline(operation), Some(deadline));
    assert!(!actor.core.iterative_queries.contains_key(&target));
    assert_eq!(actor.socket.operation_rpc_len(operation), 0);
    assert_eq!(
        peer.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );

    actor.expire_owned_operations_at(deadline);
    assert_eq!(actor.owned_resources.as_ref().unwrap().maintenance, None);
    assert_eq!(actor.socket.owned_deadline(operation), None);
    assert_eq!(actor.owned_error(), None);
}

#[tokio::test]
async fn maintenance_owned_operation_is_expired_locally_and_releases_its_slot() {
    let (_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let maintenance_target = *actor.core.routing_table.id();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    actor
        .owned_get_until(
            GetRequestSpecific::FindNode(FindNodeRequestArguments {
                target: maintenance_target,
            }),
            None,
            deadline,
        )
        .expect("maintenance operation");
    let operation = actor.owned_resources.as_ref().unwrap().maintenance.unwrap();
    let charged = actor.socket.operation_rpc_len(operation);
    actor.expire_owned_operations_at(deadline);
    assert_eq!(actor.socket.operation_rpc_len(operation), 0);
    assert_eq!(actor.socket.owned_deadline(operation), None);
    assert_eq!(actor.owned_resources.as_ref().unwrap().maintenance, None);
    assert!(
        !actor
            .core
            .iterative_queries
            .contains_key(&maintenance_target)
    );
    assert_eq!(charged, 1);
    assert_eq!(actor.owned_error(), None);
}

#[tokio::test]
async fn owned_operation_keeps_its_original_deadline_when_get_coalesces() {
    let (_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let target = target(75);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    actor
        .owned_get_until(get(target), None, deadline)
        .expect("first deadline-bound GET");
    let operation = actor.owned_resources.as_ref().unwrap().operations[&target];
    actor
        .owned_get_until(
            get(target),
            None,
            tokio::time::Instant::now() + Duration::from_secs(40),
        )
        .expect("coalesced GET");
    assert_eq!(actor.socket.owned_deadline(operation), Some(deadline));
    assert_eq!(
        actor.owned_resources.as_ref().unwrap().operations[&target],
        operation
    );
}

#[tokio::test]
async fn partial_put_deadline_expires_only_put_rpc_and_preserves_unrelated_get() {
    let (_bootstrap_peer, bootstrap) = captured_peer();
    let (peer_a, address_a) = captured_peer();
    let (peer_b, address_b) = captured_peer();
    let mut actor = actor(bootstrap);
    let unrelated_target = target(90);
    let (unrelated_sender, mut unrelated_receiver) = oneshot::channel();
    let base = tokio::time::Instant::now();
    actor
        .owned_mutable_until(
            unrelated_target,
            unrelated_sender,
            base + Duration::from_secs(30),
        )
        .expect("unrelated live GET");
    let unrelated_operation = actor.owned_resources.as_ref().unwrap().operations[&unrelated_target];

    let request = put_request();
    let put_target = *request.target();
    let deadline = base + Duration::from_secs(5);
    actor
        .owned_put_until(request.clone(), None, deadline)
        .expect("owned PUT operation");
    let operation = actor.owned_resources.as_ref().unwrap().operations[&put_target];
    let budget = Arc::clone(&actor.owned_resources.as_ref().unwrap().budget);
    let nodes = [
        Node::new_with_token(Id::from([0x61; 20]), address_a, vec![1].into_boxed_slice()),
        Node::new_with_token(Id::from([0x62; 20]), address_b, vec![2].into_boxed_slice()),
    ];
    let mut put = PutQuery::new_owned(request, None, operation, budget)
        .expect("actual owner-backed PUT query");
    put.start(&mut actor.socket, &nodes)
        .expect("start two owned PUT RPCs");
    *actor
        .core
        .put_queries
        .get_mut(&put_target)
        .expect("actor-owned pending PUT") = put;
    let (typed_sender, mut typed_receiver) = oneshot::channel();
    actor
        .put_senders
        .entry(put_target)
        .or_default()
        .push(typed_sender);
    actor.socket.flush_owned().await;

    let mut buffer = [0_u8; 4096];
    let (length, source) =
        tokio::time::timeout(Duration::from_secs(2), peer_a.recv_from(&mut buffer))
            .await
            .expect("first PUT receipt timeout")
            .expect("receive first PUT");
    let outgoing =
        crate::common::Message::from_bytes(&buffer[..length]).expect("decode outgoing PUT");
    let tid = outgoing.transaction_id;
    assert!(matches!(
        outgoing.message_type,
        crate::common::MessageType::Request(crate::common::RequestSpecific {
            request_type: crate::common::RequestTypeSpecific::Put(_),
            ..
        })
    ));
    let reply = crate::common::Message {
        transaction_id: tid,
        version: Some([82, 83, 0, 6]),
        requester_ip: None,
        message_type: crate::common::MessageType::Response(crate::common::ResponseSpecific::Ping(
            crate::common::PingResponseArguments {
                responder_id: Id::from([0x63; 20]),
            },
        )),
        read_only: false,
    };
    peer_a
        .send_to(
            &reply.to_bytes().expect("encode actual PUT success reply"),
            source,
        )
        .await
        .expect("send PUT success response");
    let (response, from) = actor
        .socket
        .recv_from()
        .await
        .expect("receive actual PUT response");
    actor.process_message(response, from);
    actor.owned_note_response(tid);
    assert_eq!(
        actor
            .core
            .put_queries
            .get(&put_target)
            .expect("partial PUT remains")
            .check(&actor.socket),
        Ok(false)
    );

    actor.expire_owned_operations_at(deadline);
    assert!(matches!(
        typed_receiver.try_recv(),
        Ok(Err(crate::core::PutError::Query(
            crate::core::PutQueryError::Resource(ResourceError::DeadlineExceeded)
        )))
    ));
    assert_eq!(actor.socket.owned_deadline(operation), None);
    assert_eq!(actor.socket.operation_rpc_len(operation), 0);
    assert!(!actor.core.put_queries.contains_key(&put_target));
    assert!(!actor.core.iterative_queries.contains_key(&put_target));
    assert!(!actor.owned_has_response_operation(operation));
    assert!(actor.core.iterative_queries.contains_key(&unrelated_target));
    assert!(actor.socket.operation_rpc_len(unrelated_operation) > 0);
    assert!(matches!(
        unrelated_receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert_eq!(actor.socket.operation_rpc_len(operation), 0);
    drop(peer_b);
}

#[tokio::test]
async fn held_send_gate_deadline_cleanup_is_deterministic_actor_cleanup_not_wall_clock_stall() {
    use crate::common::{GetValueRequestArguments, Id, Message, MessageType, RequestTypeSpecific};
    use crate::resource::{RequestReply, ResourceError};
    use tokio::sync::oneshot;

    let (peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let base = tokio::time::Instant::now();
    let deadline = base + Duration::from_secs(10);
    let expired_target = target(121);
    let unrelated_target = target(122);
    let request_budget = actor.owned_request_budget();
    let (expired_sender, expired_receiver) = oneshot::channel();
    actor.owned_admission_until(
        expired_target,
        expired_sender,
        deadline,
        request_budget.acquire().expect("expired request budget"),
    );
    let RequestReply::Ready(mut result_receiver) = expired_receiver.await.expect("admission reply")
    else {
        panic!("request admitted");
    };
    let expired_operation = actor
        .owned_resources
        .as_ref()
        .expect("owned actor")
        .operations[&expired_target];
    assert_eq!(
        actor.socket.owned_deadline(expired_operation),
        Some(deadline)
    );

    let unrelated_deadline = base + Duration::from_secs(30);
    let (unrelated_sender, unrelated_receiver) = oneshot::channel();
    actor.owned_admission_until(
        unrelated_target,
        unrelated_sender,
        unrelated_deadline,
        request_budget.acquire().expect("unrelated request budget"),
    );
    let RequestReply::Ready(_unrelated_result) =
        unrelated_receiver.await.expect("unrelated admission reply")
    else {
        panic!("unrelated request admitted");
    };
    let unrelated_operation = actor
        .owned_resources
        .as_ref()
        .expect("owned actor")
        .operations[&unrelated_target];

    let (entered, entered_rx) = oneshot::channel();
    let (release, release_rx) = oneshot::channel();
    actor.socket.hold_next_send_for_test(entered, release_rx);
    let mut flush = Box::pin(actor.socket.flush_owned());
    tokio::select! {
        result = entered_rx => result.expect("real send gate entered"),
        _ = &mut flush => panic!("held send unexpectedly completed"),
    }
    drop(flush);
    let held = actor.socket.owned_test_state().expect("held socket state");
    assert_eq!((held.0, held.2, held.3), (2, 2, 2));
    assert_eq!(actor.socket.operation_rpc_len(expired_operation), 1);
    assert_eq!(actor.socket.operation_rpc_len(unrelated_operation), 1);

    actor.expire_owned_operations_at(deadline);
    assert!(matches!(
        result_receiver.try_recv(),
        Ok(Err(ResourceError::DeadlineExceeded))
    ));
    assert_eq!(actor.socket.owned_deadline(expired_operation), None);
    assert_eq!(actor.socket.operation_rpc_len(expired_operation), 0);
    assert!(!actor.core.iterative_queries.contains_key(&expired_target));
    assert!(actor.core.iterative_queries.contains_key(&unrelated_target));
    assert_eq!(actor.socket.operation_rpc_len(unrelated_operation), 1);
    let cleaned = actor
        .socket
        .owned_test_state()
        .expect("cleaned socket state");
    assert_eq!(
        (cleaned.0, cleaned.2, cleaned.3),
        (1, 1, 1),
        "unrelated queued datagram remains charged"
    );
    assert!(
        release.send(()).is_err(),
        "cancelled flush released its gate receiver"
    );
    actor.socket.flush_owned().await;

    let mut bytes = [0_u8; 4096];
    let (length, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut bytes))
        .await
        .expect("unrelated packet receipt timeout")
        .expect("receive unrelated packet");
    let message = Message::from_bytes(&bytes[..length]).expect("decode unrelated request");
    assert!(
        matches!(message.message_type, MessageType::Request(crate::common::RequestSpecific { request_type: RequestTypeSpecific::GetValue(GetValueRequestArguments { target, .. }), .. }) if target == unrelated_target)
    );
    assert!(
        matches!(peer.try_recv_from(&mut bytes), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "expired packet was not transmitted"
    );
}

#[tokio::test]
async fn promoted_admission_preserves_original_deadline_across_coalesced_waiters() {
    use crate::resource::{RequestReply, ResourceError};

    let (peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let base = tokio::time::Instant::now();
    let budget = actor.owned_request_budget();
    let mut occupied = Vec::new();
    for _ in 0..8 {
        let (sender, receiver) = oneshot::channel();
        actor.owned_admission_until(
            target(1),
            sender,
            base + Duration::from_secs(30),
            budget.acquire().unwrap(),
        );
        let RequestReply::Ready(receiver) = receiver.await.unwrap() else {
            panic!("request admitted")
        };
        occupied.push(receiver);
    }

    let promoted_target = target(20);
    let origin_deadline = base + Duration::from_secs(10);
    let (queued_sender, queued_receiver) = oneshot::channel();
    actor.owned_admission_until(
        promoted_target,
        queued_sender,
        origin_deadline,
        budget.acquire().unwrap(),
    );
    for _ in 0..3 {
        drop(occupied.pop());
    }
    actor.maintain_owned_admissions_at(base + Duration::from_secs(6));
    let RequestReply::Ready(mut original_result) = queued_receiver.await.unwrap() else {
        panic!("queued admission promoted")
    };
    let operation = actor.owned_resources.as_ref().unwrap().operations[&promoted_target];
    assert_eq!(
        actor.socket.owned_deadline(operation),
        Some(origin_deadline)
    );
    assert!(actor.core.iterative_queries.contains_key(&promoted_target));
    assert_eq!(actor.socket.operation_rpc_len(operation), 1);

    let (later_sender, later_receiver) = oneshot::channel();
    actor.owned_admission_until(
        promoted_target,
        later_sender,
        base + Duration::from_secs(20),
        budget.acquire().unwrap(),
    );
    let RequestReply::Ready(mut later_result) = later_receiver.await.unwrap() else {
        panic!("coalesced admission ready")
    };
    assert_eq!(
        actor.owned_resources.as_ref().unwrap().operations[&promoted_target],
        operation
    );
    assert_eq!(
        actor.socket.owned_deadline(operation),
        Some(origin_deadline)
    );
    assert_eq!(actor.socket.operation_rpc_len(operation), 1);

    let (short_sender, short_receiver) = oneshot::channel();
    actor.owned_admission_until(
        promoted_target,
        short_sender,
        base + Duration::from_secs(8),
        budget.acquire().unwrap(),
    );
    let RequestReply::Ready(mut short_result) = short_receiver.await.unwrap() else {
        panic!("short coalesced admission ready")
    };
    actor.maintain_owned_admissions_at(base + Duration::from_secs(8));
    assert!(matches!(
        short_result.try_recv(),
        Ok(Err(ResourceError::DeadlineExceeded))
    ));
    assert!(actor.core.iterative_queries.contains_key(&promoted_target));
    assert_eq!(actor.socket.operation_rpc_len(operation), 1);
    assert_eq!(
        actor.socket.owned_deadline(operation),
        Some(origin_deadline)
    );

    actor.expire_owned_operations_at(origin_deadline);
    assert!(matches!(
        original_result.try_recv(),
        Ok(Err(ResourceError::DeadlineExceeded))
    ));
    assert!(matches!(
        later_result.try_recv(),
        Ok(Err(ResourceError::DeadlineExceeded))
    ));
    assert_eq!(actor.socket.owned_deadline(operation), None);
    assert_eq!(actor.socket.operation_rpc_len(operation), 0);
    assert!(!actor.core.iterative_queries.contains_key(&promoted_target));
    assert!(occupied.iter_mut().all(|receiver| matches!(
        receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    )));
    assert_eq!(
        peer.try_recv_from(&mut [0_u8; 4096]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(occupied);
}

#[tokio::test]
async fn retained_put_get_recreation_keeps_operation_round_budget() {
    use crate::common::{Message, MessageType};

    let (bootstrap_peer, bootstrap) = captured_peer();
    let (put_peer, put_address) = captured_peer();
    let mut actor = actor(bootstrap);
    let (maintenance_reached, _maintenance_reached_rx) = oneshot::channel();
    actor.owned_maintenance_after_operations = Some((8, maintenance_reached));
    let request = put_request();
    let get_request = GetRequestSpecific::from(&request);
    let put_target = *request.target();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    actor
        .owned_put_until(request.clone(), None, deadline)
        .expect("admit retained PUT");
    let operation = actor.owned_resources.as_ref().unwrap().operations[&put_target];
    let budget = Arc::clone(&actor.owned_resources.as_ref().unwrap().budget);
    let node = Node::new_with_token(
        Id::from([0x71; 20]),
        put_address,
        vec![9].into_boxed_slice(),
    );
    let mut put =
        PutQuery::new_owned(request, None, operation, budget).expect("actual retained PUT");
    put.start(&mut actor.socket, &[node])
        .expect("start retained PUT");
    *actor
        .core
        .put_queries
        .get_mut(&put_target)
        .expect("pending PUT slot") = put;
    actor
        .owned_get_until(get_request.clone(), None, deadline)
        .expect("live GET coalesces");
    assert_eq!(actor.socket.operation_rpc_len(operation), 2);
    actor.socket.flush_owned().await;
    let mut bytes = [0_u8; 4096];
    let (length, _) = tokio::time::timeout(Duration::from_secs(2), put_peer.recv_from(&mut bytes))
        .await
        .expect("PUT receipt timeout")
        .expect("receive retained PUT");
    let put_packet = Message::from_bytes(&bytes[..length]).expect("decode actual PUT");
    assert!(matches!(
        put_packet.message_type,
        MessageType::Request(crate::common::RequestSpecific {
            request_type: crate::common::RequestTypeSpecific::Put(_),
            ..
        })
    ));

    for round in 1..=3 {
        actor
            .owned_get_until(get_request.clone(), None, deadline)
            .expect("live GET coalesces without consuming another round");
        assert_eq!(actor.socket.operation_rpc_len(operation), 2);
        actor.socket.flush_owned().await;
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(2), bootstrap_peer.recv_from(&mut bytes))
                .await
                .expect("GET receipt timeout")
                .expect("receive actual GET");
        let packet = Message::from_bytes(&bytes[..length]).expect("decode actual GET");
        assert!(matches!(packet.message_type, MessageType::Request(_)));
        let response = Message {
            transaction_id: packet.transaction_id,
            version: Some([82, 83, 0, 6]),
            requester_ip: None,
            message_type: MessageType::Error(crate::common::ErrorSpecific {
                code: 201,
                description: "test".to_owned(),
            }),
            read_only: false,
        };
        bootstrap_peer
            .send_to(&response.to_bytes().expect("encode GET error"), source)
            .await
            .expect("send GET error");
        let (response, from) = actor
            .socket
            .recv_from()
            .await
            .expect("receive GET response");
        actor.process_message(response, from);
        actor.owned_note_response(packet.transaction_id);
        actor.tick_owned();
        assert!(
            !actor.core.iterative_queries.contains_key(&put_target),
            "completed GET removed by actor tick"
        );
        assert!(
            actor.core.put_queries.contains_key(&put_target),
            "retained PUT remains pending"
        );
        assert!(
            actor.socket.inflight(&put_packet.transaction_id),
            "actual PUT RPC remains live"
        );
        assert_eq!(actor.socket.owned_deadline(operation), Some(deadline));
        if round < 3 {
            actor
                .owned_get_until(get_request.clone(), None, deadline)
                .expect("recreate GET on retained PUT operation");
            assert_eq!(
                actor.owned_resources.as_ref().unwrap().operations[&put_target],
                operation
            );
        }
    }
    assert!(matches!(
        actor.owned_get_until(get_request, None, deadline),
        Err(ResourceError::DeadlineExceeded)
    ));
    actor.socket.flush_owned().await;
    assert_eq!(
        bootstrap_peer.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(actor.core.put_queries.contains_key(&put_target));
    assert_eq!(actor.socket.operation_rpc_len(operation), 1);
    assert_eq!(actor.owned_error(), None);
    actor
        .owned_get_until(get(target(211)), None, deadline)
        .expect("new operation has fresh allowance");
    let fresh_operation = actor.owned_resources.as_ref().unwrap().operations[&target(211)];
    assert_ne!(fresh_operation, operation);
    assert_eq!(actor.socket.operation_rpc_len(fresh_operation), 1);
    assert_eq!(actor.socket.operation_rpc_len(operation), 1);
    actor.socket.flush_owned().await;
    let (length, _) =
        tokio::time::timeout(Duration::from_secs(2), bootstrap_peer.recv_from(&mut bytes))
            .await
            .expect("fresh GET receipt timeout")
            .expect("receive fresh GET");
    let fresh_packet = Message::from_bytes(&bytes[..length]).expect("decode fresh GET");
    assert!(
        matches!(fresh_packet.message_type, MessageType::Request(crate::common::RequestSpecific { request_type: crate::common::RequestTypeSpecific::GetValue(crate::common::GetValueRequestArguments { target: actual_target, .. }), .. }) if actual_target == target(211))
    );
    assert_eq!(
        put_peer.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "recreation must not send another PUT"
    );
}
