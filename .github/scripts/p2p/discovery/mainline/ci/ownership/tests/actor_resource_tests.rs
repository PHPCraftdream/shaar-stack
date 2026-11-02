// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
#[path = "resource_tests/admission_tests.rs"]
mod admission;
#[path = "resource_tests/lifecycle_tests.rs"]
mod lifecycle;
#[path = "resource_tests/put_tests.rs"]
mod put;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use crate::actor::Actor;
use crate::common::{
    FindNodeRequestArguments, Id, Node, PutImmutableRequestArguments, PutRequestSpecific,
};
use crate::core::iterative_query::GetRequestSpecific;
use crate::core::put_query::PutQuery;
use crate::resource::ResourceError;
use tokio::sync::oneshot;

fn captured_peer() -> (tokio::net::UdpSocket, SocketAddrV4) {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("capture peer bind");
    socket
        .set_nonblocking(true)
        .expect("Tokio requires nonblocking socket");
    let address = match socket.local_addr().expect("capture peer address") {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => unreachable!("IPv4 capture bind"),
    };
    (
        tokio::net::UdpSocket::from_std(socket).expect("register capture peer"),
        address,
    )
}

fn actor(bootstrap: SocketAddrV4) -> Actor {
    let mut actor = Actor::new_numeric(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        vec![bootstrap].into_boxed_slice(),
    )
    .expect("numeric bounded actor");
    actor
        .enable_owned_resources()
        .expect("enable actual actor budget");
    actor
}

fn target(seed: u8) -> Id {
    let mut bytes = [0; 20];
    bytes[19] = seed;
    Id::from(bytes)
}

fn get(target: Id) -> GetRequestSpecific {
    GetRequestSpecific::GetValue(crate::common::GetValueRequestArguments {
        target,
        seq: None,
        salt: None,
    })
}

fn put_request() -> PutRequestSpecific {
    PutRequestSpecific::PutImmutable(PutImmutableRequestArguments {
        target: Id::from([0x44; 20]),
        v: vec![1, 2, 3].into_boxed_slice(),
    })
}

fn token_node(index: usize) -> Node {
    let mut id = [0u8; 20];
    id[12..].copy_from_slice(&(index as u64).to_be_bytes());
    let address = SocketAddrV4::new(
        Ipv4Addr::new(
            10,
            1,
            ((index / 250) % 250 + 1) as u8,
            (index % 250 + 1) as u8,
        ),
        4000 + (index % 60_000) as u16,
    );
    Node::new_with_token(Id::from(id), address, vec![7, 8].into_boxed_slice())
}

#[tokio::test]
async fn actor_admits_eight_distinct_operations_and_rejects_ninth_without_side_effects() {
    let (_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let targets: Vec<_> = (1..=8).map(target).collect();
    for target in &targets {
        actor
            .owned_get(get(*target), None)
            .expect("eight operation slots admit");
    }
    assert_eq!(actor.owned_resources.as_ref().unwrap().operations.len(), 8);
    let ninth = target(9);
    let (sender, receiver) = oneshot::channel();
    assert_eq!(
        actor.owned_mutable(ninth, sender),
        Err(ResourceError::OperationLimit)
    );
    assert!(matches!(
        receiver.await.expect("typed rejection delivered"),
        Err(ResourceError::OperationLimit)
    ));
    assert!(!actor.core.iterative_queries.contains_key(&ninth));
    assert!(
        !actor
            .owned_resources
            .as_ref()
            .unwrap()
            .operations
            .contains_key(&ninth)
    );
    assert_eq!(actor.socket.owned_test_state().unwrap().2, 8);
}

#[tokio::test]
async fn owned_operation_admission_preserves_existing_work_on_rejection() {
    let (_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let live = target(31);
    let (live_sender, mut live_receiver) = oneshot::channel();
    actor
        .owned_mutable(live, live_sender)
        .expect("first operation admitted");
    let live_operation = actor.owned_resources.as_ref().unwrap().operations[&live];
    for peer_target in 32..=38 {
        actor
            .owned_get(get(target(peer_target)), None)
            .expect("remaining slots admit");
    }
    let (rejected_sender, rejected_receiver) = oneshot::channel();
    assert_eq!(
        actor.owned_mutable(target(39), rejected_sender),
        Err(ResourceError::OperationLimit)
    );
    assert!(matches!(
        rejected_receiver.await.expect("rejection is explicit"),
        Err(ResourceError::OperationLimit)
    ));
    assert!(actor.core.iterative_queries.contains_key(&live));
    assert!(actor.socket.operation_rpc_len(live_operation) > 0);
    assert!(matches!(
        live_receiver.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn maintenance_consumes_one_of_eight_operation_slots() {
    let (_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let self_id = *actor.core.routing_table.id();
    actor
        .owned_get(
            GetRequestSpecific::FindNode(FindNodeRequestArguments { target: self_id }),
            None,
        )
        .expect("maintenance operation admitted");
    for peer_target in 1..=7 {
        actor
            .owned_get(get(target(peer_target)), None)
            .expect("seven regular operations admitted");
    }
    assert_eq!(actor.owned_resources.as_ref().unwrap().operations.len(), 8);
    assert!(
        actor
            .owned_resources
            .as_ref()
            .unwrap()
            .maintenance
            .is_some()
    );
    let (sender, receiver) = oneshot::channel();
    assert_eq!(
        actor.owned_mutable(target(20), sender),
        Err(ResourceError::OperationLimit)
    );
    assert!(matches!(
        receiver.await.expect("typed full result"),
        Err(ResourceError::OperationLimit)
    ));
}

#[tokio::test]
async fn coalesced_owned_mutable_waiter_observes_existing_candidate_fault() {
    let (_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let target = target(61);
    let (first_sender, first_receiver) = oneshot::channel();
    actor
        .owned_mutable(target, first_sender)
        .expect("first typed waiter admitted");
    let query = actor
        .core
        .iterative_queries
        .get_mut(&target)
        .expect("active owned query");
    for index in 0..255 {
        query.add_candidate(Node::unique(index));
    }
    query.add_candidate(Node::unique(10_000));
    assert_eq!(
        actor.core.iterative_queries[&target].owner_error(),
        Some(ResourceError::CandidateLimit)
    );
    let (second_sender, second_receiver) = oneshot::channel();
    assert_eq!(
        actor.owned_mutable(target, second_sender),
        Err(ResourceError::CandidateLimit)
    );
    assert!(matches!(
        second_receiver
            .await
            .expect("second waiter receives typed error"),
        Err(ResourceError::CandidateLimit)
    ));
    actor.tick_owned();
    assert!(matches!(
        first_receiver
            .await
            .expect("first waiter receives latched error"),
        Err(ResourceError::CandidateLimit)
    ));
    assert_eq!(actor.owned_error(), None);
    assert!(!actor.core.iterative_queries.contains_key(&target));
    assert!(!actor.owned_resources.as_ref().unwrap().operations.contains_key(&target));
}

#[tokio::test]
async fn actual_actor_coalesces_targets_and_charges_shared_visited_store() {
    let (_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let budget = Arc::clone(&actor.owned_resources.as_ref().unwrap().budget);
    assert_eq!(budget.holder_count(), 1);
    let first = target(11);
    let second = target(12);
    actor
        .owned_get(get(first), None)
        .expect("first actual query");
    actor
        .owned_get(get(second), None)
        .expect("second actual query");
    actor
        .owned_get(get(first), None)
        .expect("coalesced duplicate");
    assert_eq!(actor.core.iterative_queries.len(), 2);
    assert_ne!(
        actor.owned_resources.as_ref().unwrap().operations[&first],
        actor.owned_resources.as_ref().unwrap().operations[&second]
    );
    assert_eq!(budget.visited_count(), 2);
    assert_eq!(actor.socket.owned_test_state().unwrap().2, 2);
    assert!(actor.core.cached_iterative_queries.is_empty());
}

#[tokio::test]
async fn candidate_limit_is_typed_and_bootstrap_lease_lives_until_actor_drop() {
    let (_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    actor.owned_disable_maintenance_for_test = true;
    let budget = Arc::clone(&actor.owned_resources.as_ref().unwrap().budget);
    let target = target(42);
    let (sender, receiver) = oneshot::channel();
    actor
        .owned_mutable(target, sender)
        .expect("typed actual query");
    let query = actor
        .core
        .iterative_queries
        .get_mut(&target)
        .expect("actual query map");
    for index in 0..255 {
        query.add_candidate(Node::unique(index));
    }
    assert_eq!(budget.holder_count(), 256);
    actor
        .core
        .iterative_queries
        .get_mut(&target)
        .unwrap()
        .add_candidate(Node::unique(10_000));
    actor.tick_owned();
    assert!(matches!(
        receiver.await.expect("typed result"),
        Err(ResourceError::CandidateLimit)
    ));
    assert_eq!(actor.owned_error(), None);
    assert_eq!(actor.socket.owned_test_state().unwrap().2, 0);
    assert_eq!(budget.holder_count(), 1);
    drop(actor);
    assert_eq!(budget.holder_count(), 0);
}

#[tokio::test]
async fn bootstrap_and_ping_share_one_actual_maintenance_operation_limit() {
    let (_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let self_id = *actor.core.routing_table.id();
    actor
        .owned_get(
            GetRequestSpecific::FindNode(FindNodeRequestArguments { target: self_id }),
            None,
        )
        .expect("bootstrap query uses maintenance operation");
    for port in 11000..11015 {
        actor
            .owned_ping(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
            .expect("maintenance RPC admitted");
        actor
            .owned_ping(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
            .expect("duplicate ping coalesced");
    }
    let maintenance = actor.owned_resources.as_ref().unwrap().maintenance.unwrap();
    assert_eq!(actor.socket.operation_rpc_len(maintenance), 16);
    assert_eq!(
        actor.owned_ping(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12000)),
        Err(ResourceError::RpcLimit)
    );
    assert_eq!(actor.socket.owned_test_state().unwrap().2, 16);
}

#[tokio::test]
async fn expired_before_admission_does_not_create_query_operation_or_rpc() {
    let (_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let target = target(72);
    let (sender, receiver) = oneshot::channel();

    actor
        .owned_mutable_until(target, sender, tokio::time::Instant::now())
        .expect("expired waiter is rejected without admission");
    assert!(matches!(
        receiver.await.expect("typed expired result"),
        Err(ResourceError::DeadlineExceeded)
    ));
    assert!(!actor.core.iterative_queries.contains_key(&target));
    assert!(
        !actor
            .owned_resources
            .as_ref()
            .unwrap()
            .operations
            .contains_key(&target)
    );
    assert_eq!(actor.socket.owned_test_state().unwrap().2, 0);
}

#[tokio::test]
async fn expired_coalesced_waiter_does_not_cancel_live_waiter() {
    let (_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let target = target(74);
    let (live_sender, mut live_receiver) = oneshot::channel();
    actor
        .owned_mutable_until(
            target,
            live_sender,
            tokio::time::Instant::now() + Duration::from_secs(10),
        )
        .expect("live waiter admitted");
    let operation = actor.owned_resources.as_ref().unwrap().operations[&target];
    let (expired_sender, expired_receiver) = oneshot::channel();
    actor
        .owned_mutable_until(target, expired_sender, tokio::time::Instant::now())
        .expect("expired waiter rejected");
    assert!(matches!(
        expired_receiver.await.expect("typed expired result"),
        Err(ResourceError::DeadlineExceeded)
    ));
    assert!(actor.core.iterative_queries.contains_key(&target));
    assert_eq!(
        actor.owned_resources.as_ref().unwrap().operations[&target],
        operation
    );
    assert_eq!(actor.socket.operation_rpc_len(operation), 1);
    assert!(matches!(
        live_receiver.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn expired_deadline_is_rejected_without_starting_or_cancelling_work() {
    let (_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let live_target = target(200);
    let (live_sender, mut live_receiver) = oneshot::channel();
    actor
        .owned_mutable(live_target, live_sender)
        .expect("live operation admitted");
    let live_operation = actor.owned_resources.as_ref().unwrap().operations[&live_target];
    let live_rpc_count = actor.socket.operation_rpc_len(live_operation);

    let (expired_sender, mut expired_receiver) = oneshot::channel();
    actor
        .owned_mutable_until(live_target, expired_sender, tokio::time::Instant::now())
        .expect("expired waiter rejected without admission");
    assert!(matches!(
        expired_receiver.try_recv(),
        Ok(Err(ResourceError::DeadlineExceeded))
    ));
    assert!(matches!(
        live_receiver.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    assert!(actor.core.iterative_queries.contains_key(&live_target));
    assert_eq!(
        actor.owned_resources.as_ref().unwrap().operations[&live_target],
        live_operation
    );
    assert_eq!(
        actor.socket.operation_rpc_len(live_operation),
        live_rpc_count
    );

    let expired_target = target(201);
    let (sender, mut receiver) = oneshot::channel();
    actor
        .owned_mutable_until(expired_target, sender, tokio::time::Instant::now())
        .expect("distinct expired request rejected without starting work");
    assert!(matches!(
        receiver.try_recv(),
        Ok(Err(ResourceError::DeadlineExceeded))
    ));
    assert!(!actor.core.iterative_queries.contains_key(&expired_target));
    assert!(
        !actor
            .owned_resources
            .as_ref()
            .unwrap()
            .operations
            .contains_key(&expired_target)
    );

    drop(live_receiver);
    actor.tick_owned();
    assert!(!actor.core.iterative_queries.contains_key(&live_target));
    assert!(
        !actor
            .owned_resources
            .as_ref()
            .unwrap()
            .operations
            .contains_key(&live_target)
    );
    assert_eq!(actor.socket.operation_rpc_len(live_operation), 0);
}

#[tokio::test]
async fn dropping_one_coalesced_waiter_keeps_query_until_last_drop() {
    let (_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let target = target(73);
    let (sender_one, receiver_one) = oneshot::channel();
    let (sender_two, receiver_two) = oneshot::channel();
    actor
        .owned_mutable(target, sender_one)
        .expect("first actual waiter");
    actor
        .owned_mutable(target, sender_two)
        .expect("coalesced waiter");
    let operation = actor.owned_resources.as_ref().unwrap().operations[&target];
    drop(receiver_one);
    actor.tick_owned();
    assert!(actor.core.iterative_queries.contains_key(&target));
    assert_eq!(actor.socket.operation_rpc_len(operation), 1);
    drop(receiver_two);
    actor.tick_owned();
    assert!(!actor.core.iterative_queries.contains_key(&target));
    assert!(
        !actor
            .owned_resources
            .as_ref()
            .unwrap()
            .operations
            .contains_key(&target)
    );
    assert_eq!(actor.socket.operation_rpc_len(operation), 0);
    assert_eq!(
        actor
            .socket
            .operation_rpc_len(actor.owned_resources.as_ref().unwrap().maintenance.unwrap()),
        1
    );
}

#[tokio::test]
async fn simultaneous_queries_and_maintenance_hit_real_aggregate_rpc_cap() {
    let (_bootstrap_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let self_id = *actor.core.routing_table.id();
    actor
        .owned_get(
            GetRequestSpecific::FindNode(FindNodeRequestArguments { target: self_id }),
            None,
        )
        .expect("maintenance bootstrap query admitted");
    let peers: Vec<_> = (0..121).map(|_| captured_peer()).collect();
    for (index, target) in (1..=7).map(target).enumerate() {
        let extra: Vec<_> = peers[index * 15..(index + 1) * 15]
            .iter()
            .map(|(_, address)| *address)
            .collect();
        actor
            .owned_get(get(target), Some(&extra))
            .expect("simultaneous query admitted");
    }
    for (_, address) in peers.iter().skip(105).take(15) {
        actor
            .owned_ping(*address)
            .expect("maintenance RPC admitted");
    }
    let maintenance = actor.owned_resources.as_ref().unwrap().maintenance.unwrap();
    assert_eq!(actor.socket.operation_rpc_len(maintenance), 16);
    assert_eq!(actor.socket.owned_test_state().unwrap().2, 128);
    let target = target(99);
    assert!(!actor.core.iterative_queries.contains_key(&target));
    assert!(
        !actor
            .owned_resources
            .as_ref()
            .unwrap()
            .operations
            .contains_key(&target)
    );
    let (sender, receiver) = oneshot::channel();
    assert_eq!(
        actor.owned_mutable(target, sender),
        Err(ResourceError::OperationLimit)
    );
    assert!(matches!(
        receiver.await.expect("typed failed admission"),
        Err(ResourceError::OperationLimit)
    ));
    assert!(!actor.core.iterative_queries.contains_key(&target));
    assert!(
        !actor
            .owned_resources
            .as_ref()
            .unwrap()
            .operations
            .contains_key(&target)
    );
    assert_eq!(actor.socket.owned_test_state().unwrap().2, 128);
}

#[tokio::test]
async fn expired_deadline_starts_no_work() {
    let (_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let target = target(210);
    let (sender, receiver) = oneshot::channel();
    actor
        .owned_mutable_until(target, sender, tokio::time::Instant::now())
        .expect("expired deadline rejected without admission");
    assert!(matches!(
        receiver.await.expect("typed deadline result"),
        Err(ResourceError::DeadlineExceeded)
    ));
    assert!(!actor.core.iterative_queries.contains_key(&target));
    assert!(
        !actor
            .owned_resources
            .as_ref()
            .unwrap()
            .operations
            .contains_key(&target)
    );
    assert_eq!(actor.socket.owned_test_state().unwrap().2, 0);
}
