// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::*;

#[tokio::test]
async fn held_put_keeps_operation_charge_after_shared_get_deadline() {
    let (_bootstrap_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    actor.owned_disable_maintenance_for_test = true;
    let now = tokio::time::Instant::now();
    let deadline = now + std::time::Duration::from_secs(5);
    let put_deadline = now + std::time::Duration::from_secs(10);
    let item = crate::common::MutableItem::new(
        &ed25519_dalek::SigningKey::from_bytes(&[0xA8; 32]),
        b"held shared get",
        1,
        None,
    );
    let target = *item.target();
    let (get_sender, mut get_receiver) = oneshot::channel();
    actor.owned_mutable_until(target, get_sender, deadline).expect("actual owned GET admitted");
    let operation = actor.owned_resources.as_ref().unwrap().operations[&target];
    let observer = actor.owned_publication_observer();
    let hold = observer.hold_cleanup_for_target(target).expect("hold acquired");
    let (reply, mut reply_rx) = oneshot::channel();
    let (cleanup, mut cleanup_rx) = oneshot::channel();
    let (cancel, cancel_rx) = oneshot::channel();
    let lease = actor.owned_request_budget().acquire().expect("actual request lease");
    actor.owned_put_admission_until(target, item, reply, cleanup, cancel_rx, put_deadline, lease);
    actor.maintain_owned_puts_at(now);
    let charged_operation = reply_rx.try_recv().expect("PUT admitted").expect("no admission error");
    cancel.send(()).expect("request cancellation");
    actor.maintain_owned_puts_at(now);
    assert_eq!(cleanup_rx.try_recv(), Err(tokio::sync::oneshot::error::TryRecvError::Empty));
    assert_eq!(actor.owned_resources.as_ref().unwrap().active_put_len(), 1);

    actor.expire_owned_operations_at(deadline);
    assert!(matches!(get_receiver.try_recv(), Ok(Err(ResourceError::DeadlineExceeded))));
    assert_eq!(actor.owned_resources.as_ref().unwrap().active_put_len(), 1);
    assert_eq!(actor.owned_resources.as_ref().unwrap().operations.get(&target), Some(&operation));
    assert_eq!(actor.socket.owned_put_deadline_for_test(target), Some(put_deadline));

    hold.release();
    actor.maintain_owned_puts_at(deadline);
    assert!(matches!(
        charged_operation.await,
        Ok(Err(crate::resource::OwnedPutError::Resource(ResourceError::DeadlineExceeded)))
    ));
    assert_eq!(cleanup_rx.try_recv(), Ok(()));
    assert_eq!(actor.owned_resources.as_ref().unwrap().active_put_len(), 0);
    assert!(!actor.owned_resources.as_ref().unwrap().operations.contains_key(&target));
    assert_eq!(actor.socket.owned_put_deadline_for_test(target), None);
}

#[tokio::test]
async fn failed_put_reservation_rolls_back_new_operation_and_preserves_coalesced_get() {
    let (_bootstrap_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let budget = Arc::clone(&actor.owned_resources.as_ref().unwrap().budget);
    let target = *put_request().target();
    let (sender, mut receiver) = oneshot::channel();
    actor
        .owned_mutable(target, sender)
        .expect("live GET operation admitted");
    let operation = actor.owned_resources.as_ref().unwrap().operations[&target];
    let extras: Box<[Node]> = (0..256).map(token_node).collect();
    let result = actor.owned_put(put_request(), Some(extras));
    assert!(matches!(
        result,
        Err(crate::core::put_query::PutError::Query(
            crate::core::put_query::PutQueryError::Resource(ResourceError::CandidateLimit)
        ))
    ));
    assert!(actor.core.iterative_queries.contains_key(&target));
    assert!(!actor.core.put_queries.contains_key(&target));
    assert_eq!(
        actor.owned_resources.as_ref().unwrap().operations[&target],
        operation
    );
    assert_eq!(actor.socket.operation_rpc_len(operation), 1);
    assert_eq!(budget.holder_count(), 1);
    assert_eq!(budget.visited_count(), 1);
    assert!(matches!(
        receiver.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn owned_put_duplicate_entries_retain_holders_but_visit_and_send_once() {
    let (_bootstrap_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let budget = Arc::clone(&actor.owned_resources.as_ref().unwrap().budget);
    let operation = actor
        .socket
        .allocate_operation()
        .expect("actual socket-owned operation");
    let duplicate = token_node(1);
    let mut put = PutQuery::new_owned(
        put_request(),
        Some(vec![duplicate.clone(), duplicate.clone()].into_boxed_slice()),
        operation,
        Arc::clone(&budget),
    )
    .expect("actual owned PutQuery retains duplicate entries");
    assert_eq!(budget.holder_count(), 3);
    put.start(&mut actor.socket, &[duplicate])
        .expect("nonempty closest nodes");
    assert_eq!(budget.visited_count(), 1);
    assert_eq!(actor.socket.operation_rpc_len(operation), 1);
    actor
        .socket
        .cancel_owned_transactions(&put.transaction_ids().to_vec());
    drop(put);
    assert_eq!(budget.visited_count(), 0);
    assert_eq!(budget.holder_count(), 1);
}

#[tokio::test]
async fn owned_put_hits_actual_per_operation_rpc_cap_with_typed_error() {
    let (_bootstrap_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let budget = Arc::clone(&actor.owned_resources.as_ref().unwrap().budget);
    let operation = actor
        .socket
        .allocate_operation()
        .expect("actual socket operation");
    let extras: Box<[Node]> = (0..17).map(token_node).collect();
    let closest = token_node(100);
    let mut put = PutQuery::new_owned(put_request(), Some(extras), operation, Arc::clone(&budget))
        .expect("actual retained candidate holders");
    let result = put.start(&mut actor.socket, &[closest]);
    assert!(matches!(
        result,
        Err(crate::core::put_query::PutError::Query(
            crate::core::put_query::PutQueryError::Resource(ResourceError::RpcLimit)
        ))
    ));
    assert_eq!(put.transaction_ids().len(), 16);
    assert_eq!(actor.socket.operation_rpc_len(operation), 16);
    actor
        .socket
        .cancel_owned_transactions(&put.transaction_ids().to_vec());
    drop(put);
    assert_eq!(budget.visited_count(), 0);
    assert_eq!(actor.socket.operation_rpc_len(operation), 0);
    assert_eq!(budget.holder_count(), 1);
}

#[tokio::test]
async fn put_cleanup_removes_only_its_transaction_ids_on_a_shared_operation() {
    let (_bootstrap_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let budget = Arc::clone(&actor.owned_resources.as_ref().unwrap().budget);
    let operation = actor
        .socket
        .allocate_operation()
        .expect("actual shared operation");
    let mut put = PutQuery::new_owned(
        put_request(),
        Some(vec![token_node(1), token_node(2)].into_boxed_slice()),
        operation,
        Arc::clone(&budget),
    )
    .expect("actual owned PUT store");
    put.start(&mut actor.socket, &[token_node(3)])
        .expect("nonempty closest nodes");
    let unrelated_tid = actor
        .socket
        .request_owned(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10001),
            crate::common::RequestSpecific {
                requester_id: Id::random(),
                request_type: crate::common::RequestTypeSpecific::Ping,
            },
            operation,
        )
        .expect("unrelated RPC shares operation allowance");
    actor
        .socket
        .cancel_owned_transactions(&put.transaction_ids().to_vec());
    assert!(actor.socket.owned_inflight(unrelated_tid));
    assert_eq!(actor.socket.operation_rpc_len(operation), 1);
    actor.socket.cancel_owned_operation(operation);
    drop(put);
    assert_eq!(budget.visited_count(), 0);
    assert_eq!(budget.holder_count(), 1);
}
