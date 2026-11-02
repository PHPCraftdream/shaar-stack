// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::*;

#[tokio::test]
async fn response_then_last_waiter_cancellation_releases_operation_receipt() {
    let (bootstrap, bootstrap_address) = capture();
    let (_second_peer, second_address) = capture();
    let (_maintenance_peer, maintenance_address) = capture();
    let mut actor = bounded_actor(bootstrap_address);
    actor
        .owned_ping(maintenance_address)
        .expect("admit independent maintenance RPC");
    let maintenance_operation = actor
        .owned_resources
        .as_ref()
        .unwrap()
        .maintenance
        .expect("maintenance operation allocated");
    assert_eq!(actor.socket.operation_rpc_len(maintenance_operation), 1);
    let target = Id::from([0x53; 20]);
    let (first_sender, first_receiver) = oneshot::channel();
    let (second_sender, second_receiver) = oneshot::channel();
    actor
        .owned_mutable(target, first_sender)
        .expect("admit first waiter");
    actor
        .owned_mutable(target, second_sender)
        .expect("admit second waiter");
    actor
        .core
        .iterative_queries
        .get_mut(&target)
        .expect("actual query")
        .visit(&mut actor.socket, second_address);
    actor.socket.flush().await;

    let (bootstrap_request, _) = receive_request(&bootstrap).await;
    let (second_request, _) = receive_request(&_second_peer).await;
    let operation = actor
        .owned_resources
        .as_ref()
        .expect("owned actor")
        .operations[&target];
    let reply = Message {
        transaction_id: bootstrap_request.transaction_id,
        version: Some([82, 83, 0, 6]),
        requester_ip: None,
        message_type: MessageType::Response(ResponseSpecific::FindNode(
            FindNodeResponseArguments {
                responder_id: Id::from([0x54; 20]),
                nodes: Box::new([]),
            },
        )),
        read_only: false,
    };
    bootstrap
        .send_to(
            &reply.to_bytes().expect("encode response"),
            actor.socket.local_addr().into(),
        )
        .await
        .expect("send bootstrap response");
    let (decoded, from) = receive_response(&mut actor).await;
    actor.process_message(decoded, from);
    actor.owned_note_response(bootstrap_request.transaction_id);

    assert!(actor.owned_has_response_operation(operation));
    assert!(
        actor.socket.owned_inflight(second_request.transaction_id),
        "second RPC remains live"
    );

    drop(first_receiver);
    actor.tick_owned();
    assert!(actor.owned_has_response_operation(operation));
    assert!(actor.core.iterative_queries.contains_key(&target));
    assert!(
        actor
            .owned_resources
            .as_ref()
            .unwrap()
            .operations
            .contains_key(&target)
    );
    assert_eq!(
        actor.owned_resources.as_ref().unwrap().maintenance,
        Some(maintenance_operation)
    );
    assert!(
        actor.socket.operation_rpc_len(maintenance_operation) > 0,
        "maintenance RPC is live"
    );

    drop(second_receiver);
    actor.tick_owned();
    assert!(!actor.owned_has_response_operation(operation));
    assert!(!actor.core.iterative_queries.contains_key(&target));
    assert!(
        !actor
            .owned_resources
            .as_ref()
            .unwrap()
            .operations
            .contains_key(&target)
    );
    assert!(
        !actor.socket.owned_inflight(second_request.transaction_id),
        "last waiter cancels second RPC"
    );
    assert_eq!(
        actor.owned_resources.as_ref().unwrap().maintenance,
        Some(maintenance_operation)
    );
    assert!(
        actor.socket.operation_rpc_len(maintenance_operation) > 0,
        "maintenance RPC survives last-waiter cancellation"
    );
}

#[tokio::test]
async fn result_waiter_limit_rejects_without_cancelling_live_query() {
    let (_peer, bootstrap) = capture();
    let mut actor = bounded_actor(bootstrap);
    let target = Id::from([0xa1; 20]);
    let mut receivers = Vec::new();
    for _ in 0..8 {
        let (sender, receiver) = oneshot::channel();
        actor
            .owned_mutable(target, sender)
            .expect("waiter admitted");
        receivers.push(receiver);
    }
    let operation = actor.owned_resources.as_ref().unwrap().operations[&target];
    let rpc_count = actor.socket.operation_rpc_len(operation);
    let (sender, receiver) = oneshot::channel();
    assert_eq!(actor.owned_mutable(target, sender), Ok(()));
    assert!(matches!(
        receiver.await.expect("typed result limit"),
        Err(ResourceError::ResultLimit)
    ));
    assert_eq!(actor.owned_error(), None);
    assert!(actor.core.iterative_queries.contains_key(&target));
    assert_eq!(
        actor.owned_resources.as_ref().unwrap().operations[&target],
        operation
    );
    assert_eq!(actor.socket.operation_rpc_len(operation), rpc_count);
    drop(receivers.pop());
    let (sender, mut replacement) = oneshot::channel();
    actor
        .owned_mutable(target, sender)
        .expect("released waiter capacity reused");
    assert!(matches!(
        replacement.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    let distinct = Id::from([0xa2; 20]);
    let (sender, _closed_receiver) = oneshot::channel();
    drop(_closed_receiver);
    actor
        .owned_mutable(distinct, sender)
        .expect("closed sender ignored");
    assert!(!actor.core.iterative_queries.contains_key(&distinct));
    assert!(
        !actor
            .owned_resources
            .as_ref()
            .unwrap()
            .operations
            .contains_key(&distinct)
    );
}

#[tokio::test]
async fn actual_actor_retains_completed_result_leases_until_last_clone_drops() {
    let (peer, peer_address) = capture();
    let (_maintenance_peer, maintenance_address) = capture();
    let mut actor = bounded_actor(peer_address);
    actor
        .owned_ping(maintenance_address)
        .expect("independent maintenance RPC");
    let target = Id::from([0xb1; 20]);
    let mut receivers = Vec::new();
    for _ in 0..8 {
        let (sender, receiver) = oneshot::channel();
        actor
            .owned_mutable(target, sender)
            .expect("coalesced actual waiter");
        receivers.push(receiver);
    }
    actor.socket.flush().await;
    let (request, source) = receive_request(&peer).await;
    let reply = Message {
        transaction_id: request.transaction_id,
        version: Some([82, 83, 0, 6]),
        requester_ip: None,
        message_type: MessageType::Response(ResponseSpecific::FindNode(
            FindNodeResponseArguments {
                responder_id: Id::from([0xb2; 20]),
                nodes: Box::new([]),
            },
        )),
        read_only: false,
    };
    peer.send_to(
        &reply.to_bytes().expect("encode actual response"),
        source.into(),
    )
    .await
    .expect("send actual response");
    let (decoded, from) = receive_response(&mut actor).await;
    actor.process_message(decoded, from);
    actor.owned_note_response(request.transaction_id);
    actor.tick_owned();

    let mut completed = Vec::new();
    for receiver in receivers {
        completed.push(
            receiver
                .await
                .expect("actual typed completion")
                .expect("successful completion"),
        );
    }
    assert!(
        completed
            .iter()
            .all(|result| result.network_completed() && result.items().is_empty())
    );
    let retained_clone = completed[0].clone();
    drop(completed.remove(0));

    let (sender, mut rejected) = oneshot::channel();
    actor
        .owned_mutable(Id::from([0xb3; 20]), sender)
        .expect("limit reports via typed result");
    assert!(matches!(
        rejected.try_recv(),
        Ok(Err(ResourceError::ResultLimit))
    ));

    drop(retained_clone);
    let (sender, mut admitted) = oneshot::channel();
    actor
        .owned_mutable(Id::from([0xb3; 20]), sender)
        .expect("released result lease admits new request");
    assert!(matches!(
        admitted.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    drop(completed);
    drop(admitted);
    actor.tick_owned();
}
