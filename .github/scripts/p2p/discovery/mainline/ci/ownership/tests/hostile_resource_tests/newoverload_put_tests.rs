// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::*;

#[tokio::test]
async fn visited_capacity_exhaustion_stops_only_the_real_query() {
    let (bootstrap, bootstrap_address) = capture();
    let (maintenance_peer, maintenance_address) = capture();
    let mut actor = bounded_actor(bootstrap_address);
    actor.owned_ping(maintenance_address).expect("maintenance ping");
    let maintenance = actor.owned_resources.as_ref().unwrap().maintenance.unwrap();
    let victim = Id::from([0xb1; 20]);
    let independent = Id::from([0xb2; 20]);
    let (victim_sender, victim_receiver) = oneshot::channel();
    let (other_sender, mut other_receiver) = oneshot::channel();
    actor.owned_mutable(victim, victim_sender).expect("victim query");
    actor
        .owned_mutable(independent, other_sender)
        .expect("independent GET");
    let budget = std::sync::Arc::clone(&actor.owned_resources.as_ref().unwrap().budget);
    let mut leases = Vec::new();

    while budget.visited_count() < 256 {
        leases.push(budget.reserve_visited().expect("hold visited capacity"));
    }

    assert_eq!(budget.visited_count(), 256);
    let query = actor.core.iterative_queries.get_mut(&victim).unwrap();
    query.add_candidate(hostile_node(900));
    query.visit_closest(&mut actor.socket);
    assert_eq!(query.owner_error(), Some(ResourceError::VisitedLimit));
    actor.retire_owned_operation_errors();
    assert!(matches!(
        victim_receiver.await.expect("typed victim"),
        Err(ResourceError::VisitedLimit)
    ));
    assert!(actor.core.iterative_queries.contains_key(&independent));
    assert!(matches!(
        other_receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert_eq!(actor.owned_resources.as_ref().unwrap().maintenance, Some(maintenance));
    assert_eq!(actor.socket.operation_rpc_len(maintenance), 1);
    actor.socket.flush().await;
    let _ = receive_request(&maintenance_peer).await;
    drop(leases);
    assert_eq!(budget.visited_count(), 2);
    assert_eq!(bootstrap.local_addr().unwrap().ip(), Ipv4Addr::LOCALHOST);
}

#[tokio::test]
async fn outbox_capacity_exhaustion_rolls_back_only_the_real_query() {
    let (bootstrap, bootstrap_address) = capture();
    let (maintenance_peer, maintenance_address) = capture();
    let mut actor = bounded_actor(bootstrap_address);
    actor.owned_ping(maintenance_address).expect("maintenance ping");
    let maintenance = actor.owned_resources.as_ref().unwrap().maintenance.unwrap();
    let victim = Id::from([0xc1; 20]);
    let independent = Id::from([0xc2; 20]);
    let (victim_sender, victim_receiver) = oneshot::channel();
    let (other_sender, mut other_receiver) = oneshot::channel();
    actor.owned_mutable(victim, victim_sender).expect("victim query");
    actor
        .owned_mutable(independent, other_sender)
        .expect("independent GET");
    actor.socket.flush().await;
    let _ = receive_request(&bootstrap).await;
    let _ = receive_request(&bootstrap).await;
    let _ = receive_request(&maintenance_peer).await;
    let actor_id = *actor.core.routing_table.id();
    let request = Message {
        transaction_id: 0xe1e2,
        version: Some([82, 83, 0, 6]),
        requester_ip: None,
        message_type: MessageType::Request(crate::common::RequestSpecific {
            requester_id: actor_id,
            request_type: crate::common::RequestTypeSpecific::Ping,
        }),
        read_only: false,
    };

    while actor.socket.owned_test_state().unwrap().0 < 128 {
        actor
            .socket
            .send_datagram_owned(
                request.to_bytes().expect("encode actual KRPC ping"),
                bootstrap_address,
            )
            .expect("fill actual outbox");
    }

    let query = actor.core.iterative_queries.get_mut(&victim).unwrap();
    query.add_candidate(hostile_node(901));
    query.visit_closest(&mut actor.socket);
    assert_eq!(query.owner_error(), Some(ResourceError::OutboxFull));
    actor.retire_owned_operation_errors();
    assert!(matches!(
        victim_receiver.await.expect("typed victim"),
        Err(ResourceError::OutboxFull)
    ));
    assert!(actor.core.iterative_queries.contains_key(&independent));
    assert!(matches!(
        other_receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert_eq!(actor.owned_resources.as_ref().unwrap().maintenance, Some(maintenance));
    assert_eq!(actor.socket.operation_rpc_len(maintenance), 1);
    assert_eq!(actor.socket.owned_test_state().unwrap().0, 128);
}

#[tokio::test]
async fn candidate_overflow_completes_only_its_typed_owner() {
    let (bootstrap, bootstrap_address) = capture();
    let (maintenance_peer, maintenance_address) = capture();
    let mut actor = bounded_actor(bootstrap_address);
    actor
        .owned_ping(maintenance_address)
        .expect("independent maintenance RPC");
    let maintenance = actor.owned_resources.as_ref().unwrap().maintenance.unwrap();
    let victim = Id::from([0x91; 20]);
    let independent_get = Id::from([0x92; 20]);
    let put_target = Id::from([0x93; 20]);
    let (victim_sender, victim_receiver) = oneshot::channel();
    let (get_sender, mut get_receiver) = oneshot::channel();
    actor
        .owned_mutable(victim, victim_sender)
        .expect("victim typed GET");
    actor
        .owned_mutable(independent_get, get_sender)
        .expect("independent GET");
    let put = crate::common::PutRequestSpecific::PutImmutable(
        PutImmutableRequestArguments {
            target: put_target,
            v: vec![1, 2, 3].into_boxed_slice(),
        },
    );
    actor.owned_put(put, None).expect("independent actual PUT");
    let budget = std::sync::Arc::clone(&actor.owned_resources.as_ref().unwrap().budget);
    let mut holder_count = budget.holder_count();
    let mut candidate_index = 0;

    while holder_count < 256 {
        actor
            .core
            .iterative_queries
            .get_mut(&victim)
            .unwrap()
            .add_candidate(hostile_node(candidate_index));
        candidate_index += 1;
        holder_count = budget.holder_count();
    }

    assert_eq!(holder_count, 256);
    actor
        .core
        .iterative_queries
        .get_mut(&victim)
        .unwrap()
        .add_candidate(hostile_node(candidate_index));
    actor.retire_owned_operation_errors();
    assert!(matches!(
        victim_receiver.await.expect("typed victim completion"),
        Err(ResourceError::CandidateLimit)
    ));
    assert!(actor.core.iterative_queries.contains_key(&independent_get));
    assert!(matches!(
        get_receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(actor
        .owned_resources
        .as_ref()
        .unwrap()
        .operations
        .contains_key(&independent_get));
    assert!(actor.core.put_queries.contains_key(&put_target));
    assert_eq!(actor.owned_resources.as_ref().unwrap().maintenance, Some(maintenance));
    assert_eq!(actor.socket.operation_rpc_len(maintenance), 1);
    actor.socket.flush().await;
    let (maintenance_request, _) = receive_request(&maintenance_peer).await;
    assert!(matches!(
        maintenance_request.message_type,
        MessageType::Request(crate::common::RequestSpecific {
            request_type: crate::common::RequestTypeSpecific::Ping,
            ..
        })
    ));
    assert_eq!(bootstrap.local_addr().unwrap().ip(), Ipv4Addr::LOCALHOST);
}

#[tokio::test]
async fn rpc_overflow_is_local_to_the_query_with_actual_socket_requests() {
    let (bootstrap, bootstrap_address) = capture();
    let (maintenance_peer, maintenance_address) = capture();
    let mut actor = bounded_actor(bootstrap_address);
    actor
        .owned_ping(maintenance_address)
        .expect("independent maintenance ping");
    let maintenance = actor.owned_resources.as_ref().unwrap().maintenance.unwrap();
    let victim = Id::from([0xa1; 20]);
    let other = Id::from([0xa2; 20]);
    let (victim_sender, victim_receiver) = oneshot::channel();
    let (other_sender, mut other_receiver) = oneshot::channel();
    actor.owned_mutable(victim, victim_sender).expect("victim query");
    actor.owned_mutable(other, other_sender).expect("independent query");
    actor.socket.flush().await;
    let _ = receive_request(&bootstrap).await;
    let _ = receive_request(&bootstrap).await;
    let _ = receive_request(&maintenance_peer).await;
    let victim_operation = actor.owned_resources.as_ref().unwrap().operations[&victim];
    let request = crate::common::RequestSpecific {
        requester_id: *actor.core.routing_table.id(),
        request_type: crate::common::RequestTypeSpecific::Ping,
    };

    for _ in 0..15 {
        actor
            .socket
            .request_owned(bootstrap_address, request.clone(), victim_operation)
            .expect("actual RPC admitted");
    }

    let query = actor.core.iterative_queries.get_mut(&victim).unwrap();
    query.add_candidate(hostile_node(700));
    query.visit_closest(&mut actor.socket);
    assert_eq!(query.owner_error(), Some(ResourceError::RpcLimit));
    actor.retire_owned_operation_errors();
    assert!(matches!(
        victim_receiver.await.expect("typed victim completion"),
        Err(ResourceError::RpcLimit)
    ));
    assert!(actor.core.iterative_queries.contains_key(&other));
    assert!(matches!(
        other_receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(actor.core.put_queries.is_empty());
    assert_eq!(actor.owned_resources.as_ref().unwrap().maintenance, Some(maintenance));
    assert_eq!(actor.socket.operation_rpc_len(maintenance), 1);
    assert!(actor
        .owned_resources
        .as_ref()
        .unwrap()
        .operations
        .contains_key(&other));
    assert_eq!(actor.socket.operation_rpc_len(victim_operation), 0);
    assert_eq!(
        actor.socket.operation_rpc_len(
            actor.owned_resources.as_ref().unwrap().operations[&other]
        ),
        1
    );
    assert_eq!(actor.owned_error(), None);
}
