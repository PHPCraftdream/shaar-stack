// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::*;

#[tokio::test]
async fn actor_tick_preserves_pending_put_retries_and_stops_after_third_timeout() {
    let (_bootstrap_peer, bootstrap) = captured_peer();
    let (peer, address) = captured_peer();
    let mut actor = actor(bootstrap);
    let (maintenance_reached, _await_maintenance) = oneshot::channel();
    actor.owned_maintenance_after_operations = Some((8, maintenance_reached));
    let request = put_request();
    let put_target = *request.target();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    actor
        .owned_put_until(request.clone(), None, deadline)
        .expect("owned PUT operation");
    let operation = actor.owned_resources.as_ref().unwrap().operations[&put_target];
    let budget = Arc::clone(&actor.owned_resources.as_ref().unwrap().budget);
    let node = Node::new_with_token(Id::from([0x55; 20]), address, vec![7, 8].into_boxed_slice());
    let mut put =
        PutQuery::new_owned(request, None, operation, budget).expect("actual owned PUT query");
    put.start(&mut actor.socket, &[node])
        .expect("start PUT attempt");
    *actor
        .core
        .put_queries
        .get_mut(&put_target)
        .expect("actor PUT slot") = put;
    let mut buffer = [0_u8; 4096];
    let mut tids = Vec::new();

    for attempt in 1..=3 {
        actor.socket.flush_owned().await;
        let (length, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buffer))
            .await
            .expect("PUT packet receipt timeout")
            .expect("receive PUT packet");
        let packet =
            crate::common::Message::from_bytes(&buffer[..length]).expect("decode PUT packet");
        assert!(matches!(
            packet.message_type,
            crate::common::MessageType::Request(crate::common::RequestSpecific {
                request_type: crate::common::RequestTypeSpecific::Put(_),
                ..
            })
        ));
        assert!(
            !tids.contains(&packet.transaction_id),
            "retry uses a distinct transaction id"
        );
        tids.push(packet.transaction_id);
        if attempt < 3 {
            actor
                .core
                .put_queries
                .get_mut(&put_target)
                .unwrap()
                .set_owned_next_jitter(0);
        }
        actor.socket.expire_owned_requests(Duration::ZERO);
        actor.tick_owned();

        if attempt < 3 {
            assert!(
                actor.core.put_queries.contains_key(&put_target),
                "timed-out PUT remains pending"
            );
            assert_eq!(actor.socket.owned_deadline(operation), Some(deadline));
            assert!(
                actor
                    .core
                    .put_queries
                    .get(&put_target)
                    .unwrap()
                    .owned_retry_at()
                    .is_some(),
                "timeout schedules a retry"
            );
            actor.tick_owned();
            assert_eq!(
                actor.socket.operation_rpc_len(operation),
                1,
                "actor tick submits due retry"
            );
            assert_eq!(actor.socket.owned_deadline(operation), Some(deadline));
        } else {
            assert!(
                !actor.core.put_queries.contains_key(&put_target),
                "third timeout terminates PUT"
            );
            assert!(
                !actor
                    .owned_resources
                    .as_ref()
                    .unwrap()
                    .operations
                    .values()
                    .any(|&id| id == operation)
            );
            assert_eq!(actor.socket.owned_deadline(operation), None);
        }
        assert_eq!(actor.owned_error(), None);
    }
    assert_eq!(tids.len(), 3);
    actor.socket.flush_owned().await;
    assert_eq!(
        peer.try_recv_from(&mut buffer).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "no fourth PUT datagram"
    );
}

#[tokio::test]
async fn actual_owned_put_retries_three_submitted_attempts_then_stops() {
    let (_bootstrap_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let (peer, address) = captured_peer();
    let budget = Arc::clone(&actor.owned_resources.as_ref().unwrap().budget);
    let operation = actor
        .socket
        .allocate_operation()
        .expect("actual socket-owned operation");
    let node = Node::new_with_token(Id::from([0x55; 20]), address, vec![7, 8].into_boxed_slice());
    let mut put = PutQuery::new_owned(put_request(), None, operation, Arc::clone(&budget))
        .expect("actual owned PutQuery");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    actor
        .socket
        .register_owned_deadline(operation, deadline)
        .expect("register original operation deadline");
    put.start(&mut actor.socket, &[node])
        .expect("start PUT attempt");
    let mut buffer = [0_u8; 4096];
    let mut seen_tids = Vec::new();

    for attempt in 1..=3 {
        actor.socket.flush_owned().await;
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buffer))
                .await
                .expect("PUT attempt receipt timeout")
                .expect("receive PUT attempt");
        let message =
            crate::common::Message::from_bytes(&buffer[..length]).expect("decode PUT attempt");
        assert_eq!(
            source,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, actor.socket.local_addr().port())
        );
        assert!(matches!(
            message.message_type,
            crate::common::MessageType::Request(crate::common::RequestSpecific {
                request_type: crate::common::RequestTypeSpecific::Put(_),
                ..
            })
        ));
        let tid = message.transaction_id;
        assert!(
            !seen_tids.contains(&tid),
            "retry uses a distinct transaction id"
        );
        seen_tids.push(tid);
        actor.socket.expire_owned_requests(Duration::ZERO);
        assert!(
            !actor.socket.owned_inflight(tid),
            "submitted unanswered PUT expires locally"
        );

        if attempt < 3 {
            let now = tokio::time::Instant::now();
            put.set_owned_next_jitter(if attempt == 1 { 100 } else { 200 });
            assert!(
                put.schedule_owned_retry(&actor.socket, now),
                "schedule retry {attempt}"
            );
            let retry_at = put.owned_retry_at().expect("scheduled retry");
            let cap = if attempt == 1 { 100 } else { 200 };
            assert_eq!(retry_at, now + Duration::from_millis(cap));
            put.retry_owned_at(&mut actor.socket, retry_at - Duration::from_millis(1))
                .expect("early retry remains pending");
            assert_eq!(actor.socket.operation_rpc_len(operation), 0);
            put.retry_owned_at(&mut actor.socket, now + Duration::from_millis(cap))
                .expect("submit retry");
        }
    }

    assert!(!put.schedule_owned_retry(&actor.socket, tokio::time::Instant::now()));
    assert_eq!(actor.socket.owned_deadline(operation), Some(deadline));
    assert_eq!(actor.socket.operation_rpc_len(operation), 0);
    assert_eq!(
        peer.try_recv_from(&mut buffer).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(put);
    assert_eq!(budget.holder_count(), 1);
}

#[tokio::test]
async fn owned_put_retry_due_at_deadline_fails_without_resubmitting() {
    let (_bootstrap_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let (peer, address) = captured_peer();
    let budget = Arc::clone(&actor.owned_resources.as_ref().unwrap().budget);
    let operation = actor
        .socket
        .allocate_operation()
        .expect("actual socket-owned operation");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    actor
        .socket
        .register_owned_deadline(operation, deadline)
        .expect("register original operation deadline");
    let node = Node::new_with_token(Id::from([0x56; 20]), address, vec![7, 8].into_boxed_slice());
    let mut put = PutQuery::new_owned(put_request(), None, operation, Arc::clone(&budget))
        .expect("actual owned PutQuery");
    put.start(&mut actor.socket, &[node])
        .expect("start PUT attempt");
    actor.socket.flush_owned().await;

    let mut buffer = [0_u8; 4096];
    let (length, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buffer))
        .await
        .expect("PUT attempt receipt timeout")
        .expect("receive PUT attempt");
    let message =
        crate::common::Message::from_bytes(&buffer[..length]).expect("decode PUT attempt");
    assert!(matches!(
        message.message_type,
        crate::common::MessageType::Request(crate::common::RequestSpecific {
            request_type: crate::common::RequestTypeSpecific::Put(_),
            ..
        })
    ));
    actor.socket.expire_owned_requests(Duration::ZERO);
    assert_eq!(actor.socket.operation_rpc_len(operation), 0);

    put.set_owned_next_jitter(100);
    let schedule_at = deadline - Duration::from_millis(200);
    assert!(put.schedule_owned_retry(&actor.socket, schedule_at));
    let retry_at = put.owned_retry_at().expect("scheduled retry");
    assert_eq!(retry_at, deadline - Duration::from_millis(100));
    assert!(matches!(
        put.retry_owned_at(&mut actor.socket, deadline),
        Err(crate::core::PutError::Query(
            crate::core::PutQueryError::Resource(ResourceError::DeadlineExceeded)
        ))
    ));
    assert_eq!(actor.socket.operation_rpc_len(operation), 0);
    assert_eq!(actor.socket.owned_deadline(operation), Some(deadline));
    assert_eq!(
        peer.try_recv_from(&mut buffer).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(put);
    assert_eq!(budget.holder_count(), 1);
}
