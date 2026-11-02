// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use super::*;
use crate::core::{PutError, PutQueryError};
use crate::MutableItem;
use ed25519_dalek::SigningKey;
use tokio::sync::oneshot;
use tokio::time::Instant;

struct CleanupBoundary {
    budget: Arc<crate::resource::StoreBudget>,
    observed_holders: std::sync::atomic::AtomicUsize,
    observed_visited: std::sync::atomic::AtomicUsize,
}

impl Wake for CleanupBoundary {
    fn wake(self: Arc<Self>) {
        self.observed_holders.store(
            self.budget.holder_count(),
            std::sync::atomic::Ordering::SeqCst,
        );
        self.observed_visited.store(
            self.budget.visited_count(),
            std::sync::atomic::Ordering::SeqCst,
        );
    }
}

#[tokio::test]
async fn completed_get_put_start_failure_releases_query_and_leases_before_cleanup_ack() {
    for (deadline_failure, shared_get) in [(false, false), (false, true), (true, false), (true, true)] {
        let (peer, peer_address) = capture();
        let mut actor = bounded_actor(peer_address);
        actor.owned_disable_maintenance_for_test = true;
        let item = MutableItem::new(&SigningKey::from_bytes(&[0xB9; 32]), b"start-failure", 1, None);
        let target = *item.target();
        let operation_deadline = Instant::now() + std::time::Duration::from_secs(10);
        let (reply, mut reply_rx) = oneshot::channel();
        let (cleanup, mut cleanup_rx) = oneshot::channel();
        let (cancel_sender, cancel_rx) = oneshot::channel();
        let reqlease = actor.owned_request_budget().acquire().unwrap();
        actor.owned_put_admission_until(
            target,
            item,
            reply,
            cleanup,
            cancel_rx,
            operation_deadline,
            reqlease,
        );
        actor.maintain_owned_puts_at(Instant::now());
        let charged = reply_rx.try_recv().unwrap().unwrap();
        let operation = actor.owned_resources.as_ref().unwrap().operations[&target];
        let mut shared_get_rx = if shared_get {
            let (sender, receiver) = oneshot::channel();
            actor.owned_mutable_until(target, sender, operation_deadline).unwrap();
            Some(receiver)
        } else {
            None
        };
        actor.socket.flush().await;

        let (get_request, source) = receive_request(&peer).await;
        let response = Message {
            transaction_id: get_request.transaction_id,
            version: Some([82, 83, 0, 6]),
            requester_ip: None,
            message_type: MessageType::Response(ResponseSpecific::NoValues(
                crate::common::NoValuesResponseArguments {
                    responder_id: Id::from([0xBA; 20]),
                    token: vec![0x44].into_boxed_slice(),
                    nodes: None,
                },
            )),
            read_only: false,
        };
        peer.send_to(&response.to_bytes().expect("encode GET response"), source)
            .await
            .expect("send GET response");
        let (decoded, from) = receive_response(&mut actor).await;
        actor.process_message(decoded, from);
        actor.owned_note_response(get_request.transaction_id);
        actor.core.iterative_queries.get_mut(&target).unwrap()
            .add_candidate(crate::common::Node::new(Id::from([0xBA; 20]), peer_address));
        let budget = Arc::clone(&actor.owned_resources.as_ref().unwrap().budget);
        let query = actor.core.iterative_queries.get(&target).expect("completed GET query retained before tick");
        assert!(query.is_done(&actor.socket));
        let query_holders = query.closest().len() + query.responders().len();
        assert!(query.closest().len() > 0);
        assert!(query.responders().len() > 0);
        assert!(budget.visited_count() > 0);
        let expected_holders = budget.holder_count().checked_sub(query_holders)
            .expect("GET holder leases included in aggregate count");
        let expected_visited = 0;
        let boundary = Arc::new(CleanupBoundary {
            budget: Arc::clone(&budget),
            observed_holders: std::sync::atomic::AtomicUsize::new(usize::MAX),
            observed_visited: std::sync::atomic::AtomicUsize::new(usize::MAX),
        });
        let waker = Waker::from(Arc::clone(&boundary));
        let mut context = Context::from_waker(&waker);
        let mut cleanup_rx = Box::pin(cleanup_rx);
        assert!(matches!(cleanup_rx.as_mut().poll(&mut context), Poll::Pending));

        if deadline_failure {
            actor.owned_resources.as_mut().unwrap().put_start_deadline_operation = Some(operation);
        } else {
            actor.socket.fail_next_enqueue_for_test();
        }
        actor.tick_owned();

        assert_eq!(boundary.observed_holders.load(std::sync::atomic::Ordering::SeqCst), expected_holders);
        assert_eq!(boundary.observed_visited.load(std::sync::atomic::Ordering::SeqCst), expected_visited);
        assert!(matches!(cleanup_rx.as_mut().poll(&mut context), Poll::Ready(Ok(()))));
        let put_error = charged.await.expect("charged PUT receiver remains available");
        if deadline_failure {
            assert!(matches!(put_error, Err(crate::resource::OwnedPutError::Resource(
                crate::resource::ResourceError::DeadlineExceeded
            ))));
        } else {
            assert!(matches!(put_error, Err(crate::resource::OwnedPutError::Put(PutError::Query(
                PutQueryError::Resource(crate::resource::ResourceError::Enqueue)
            )))));
        }
        if let Some(receiver) = shared_get_rx.as_mut() {
            let completion = receiver.try_recv().expect("shared GET waiter resolved");
            if deadline_failure {
                assert!(matches!(completion, Err(crate::resource::ResourceError::DeadlineExceeded)));
            } else {
                assert!(completion.expect("shared GET completes normally").network_completed());
            }
        }
        assert!(!actor.core.iterative_queries.contains_key(&target));
        assert!(!actor.core.put_queries.contains_key(&target));
        assert!(!actor.owned_resources.as_ref().unwrap().operations.contains_key(&target));
        assert_eq!(actor.socket.owned_deadline(operation), None);
        assert!(!actor.owned_has_response_operation(operation));
        assert_eq!(budget.holder_count(), expected_holders);
        assert_eq!(budget.visited_count(), expected_visited);
        drop(cancel_sender);
    }
}

#[tokio::test]
async fn terminal_mutable_put_error_releases_operation_before_another_tick() {
    use tokio::time::Instant;
    use tokio::sync::oneshot;

    let (peer, peer_address) = capture();
    let mut actor = bounded_actor(peer_address);
    let item = MutableItem::new(&SigningKey::from_bytes(&[0xB7; 32]), b"terminal-error", 1, None);
    let target = *item.target();
    let (reply, mut reply_rx) = oneshot::channel();
    let (cleanup, mut cleanup_rx) = oneshot::channel();
    let (cancel_sender, cancel_rx) = oneshot::channel();
    let reqlease = actor.owned_request_budget().acquire().unwrap();
    let now = Instant::now();
    actor.owned_put_admission_until(
        target,
        item,
        reply,
        cleanup,
        cancel_rx,
        now + std::time::Duration::from_secs(10),
        reqlease,
    );
    actor.maintain_owned_puts_at(now);
    let charged = reply_rx.try_recv().unwrap().unwrap();
    let operation = actor.owned_resources.as_ref().unwrap().operations[&target];

    actor.socket.flush().await;
    let (get_request, source) = receive_request(&peer).await;
    let get_reply = Message {
        transaction_id: get_request.transaction_id,
        version: Some([82, 83, 0, 6]),
        requester_ip: None,
        message_type: MessageType::Response(ResponseSpecific::NoValues(
            crate::common::NoValuesResponseArguments {
                responder_id: Id::from([0xB8; 20]),
                token: vec![0x44].into_boxed_slice(),
                nodes: None,
            },
        )),
        read_only: false,
    };
    peer.send_to(&get_reply.to_bytes().expect("encode GET response"), source)
        .await
        .expect("send GET response");
    let (decoded, from) = receive_response(&mut actor).await;
    actor.process_message(decoded, from);
    actor.owned_note_response(get_request.transaction_id);
    actor.tick_owned();
    assert!(actor.core.put_queries.contains_key(&target));
    assert!(!actor.core.iterative_queries.contains_key(&target));
    actor.socket.flush().await;

    let (put_request, put_source) = receive_request(&peer).await;
    let error_reply = Message {
        transaction_id: put_request.transaction_id,
        version: Some([82, 83, 0, 6]),
        requester_ip: None,
        message_type: MessageType::Error(crate::common::ErrorSpecific {
            code: 201,
            description: "PUT rejected".to_owned(),
        }),
        read_only: false,
    };
    peer.send_to(&error_reply.to_bytes().expect("encode PUT error"), put_source)
        .await
        .expect("send PUT error");
    let (decoded, from) = receive_response(&mut actor).await;
    actor.process_message(decoded, from);
    actor.owned_note_response(put_request.transaction_id);
    assert!(actor.owned_has_response_operation(operation));
    assert!(!actor.socket.owned_inflight(put_request.transaction_id));

    let error = actor.core.put_queries.get_mut(&target).unwrap().check(&actor.socket)
        .expect_err("real protocol error terminates PUT");
    assert!(matches!(error, PutError::Query(PutQueryError::ErrorResponse(ref e)) if e.code == 201));
    let tids = actor.core.put_queries.remove(&target).unwrap().transaction_ids().to_vec();
    actor.core.iterative_queries.remove(&target);
    actor.socket.cancel_owned_transactions(&tids);
    actor.owned_finish_put(target, Err(error), tids);

    assert_eq!(cleanup_rx.try_recv(), Ok(()));
    assert!(!actor.core.put_queries.contains_key(&target));
    let owner = actor.owned_resources.as_ref().unwrap();
    assert!(!owner.operations.contains_key(&target));
    assert_eq!(actor.socket.owned_deadline(operation), None);
    assert!(!actor.owned_has_response_operation(operation));
    assert_eq!(actor.socket.owned_response_operation(), None);
    assert_eq!(actor.socket.operation_rpc_len(operation), 0);
    assert!(!actor.socket.owned_inflight(put_request.transaction_id));
    drop(charged);
}

#[tokio::test]
async fn holder_exhaustion_fails_put_but_preserves_completed_get_waiters() {
    use crate::common::GetMutableResponseArguments;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::net::UdpSocket;

    for mode in 0..4 {
        let (first, first_address) = capture();
        let second = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 0))
            .await.expect("bind distinct loopback peer");
        let second_address = match second.local_addr().expect("second peer address") {
            std::net::SocketAddr::V4(address) => address,
            address => panic!("expected IPv4 loopback peer, got {address}"),
        };
        let (maintenance_peer, maintenance_address) = capture();
        let mut actor = bounded_actor(first_address);
        actor.owned_disable_maintenance_for_test = true;
        let signer = SigningKey::from_bytes(&[0xC3; 32]);
        let item = MutableItem::new(&signer, b"completed-get-survives-put-budget", 7, None);
        let target = *item.target();
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        let (put_reply, mut put_reply_rx) = oneshot::channel();
        let (cleanup, mut cleanup_rx) = oneshot::channel();
        let (put_cancel, cancel_rx) = oneshot::channel();
        let request_lease = actor.owned_request_budget().acquire().expect("PUT request lease");
        actor.owned_put_admission_until(
            target, item.clone(), put_reply, cleanup, cancel_rx, deadline, request_lease,
        );
        actor.maintain_owned_puts_at(Instant::now());
        let charged_put = put_reply_rx.try_recv().expect("admitted PUT").expect("charged PUT receiver");
        let operation = actor.owned_resources.as_ref().expect("owned actor").operations[&target];

        let get_deadline = if mode == 1 {
            Instant::now() + std::time::Duration::from_secs(5)
        } else {
            deadline
        };
        let mut get_receiver = if mode == 3 {
            None
        } else {
            let (sender, receiver) = oneshot::channel();
            actor.owned_mutable_until(target, sender, get_deadline).expect("shared GET waiter");
            Some(receiver)
        };
        let (independent_sender, mut independent_receiver) = oneshot::channel();
        let independent_target = Id::from([0xC4; 20]);
        actor.owned_mutable(independent_target, independent_sender).expect("unrelated GET");
        actor.owned_ping(maintenance_address).expect("unrelated maintenance RPC");
        let maintenance_operation = actor.owned_resources.as_ref().expect("owned actor")
            .maintenance.expect("maintenance operation retained");
        actor.core.iterative_queries.get_mut(&target).expect("actual GET query")
            .visit(&mut actor.socket, second_address);
        actor.socket.flush().await;

        let (first_get, first_source) = receive_request(&first).await;
        let (second_get, second_source) = receive_request(&second).await;
        let record = |transaction_id, responder_id| Message {
            transaction_id,
            version: Some([82, 83, 0, 6]),
            requester_ip: None,
            message_type: MessageType::Response(ResponseSpecific::GetMutable(GetMutableResponseArguments {
                responder_id,
                token: vec![0x61, 0x62].into_boxed_slice(),
                nodes: None,
                v: item.value().to_vec().into_boxed_slice(),
                k: *item.key(),
                seq: item.seq(),
                sig: *item.signature(),
            })),
            read_only: false,
        };
        first.send_to(&record(first_get.transaction_id, Id::from([0xC5; 20])).to_bytes().expect("encode signed first response"), first_source)
            .await.expect("send first real response");
        let (decoded, from) = receive_response(&mut actor).await;
        actor.process_message(decoded, from);
        actor.owned_note_response(first_get.transaction_id);
        second.send_to(&record(second_get.transaction_id, Id::from([0xC6; 20])).to_bytes().expect("encode signed second response"), second_source)
            .await.expect("send signed second response");
        let (decoded, from) = receive_response(&mut actor).await;
        actor.process_message(decoded, from);
        actor.owned_note_response(second_get.transaction_id);

        let budget = Arc::clone(&actor.owned_resources.as_ref().expect("owned actor").budget);
        let query = actor.core.iterative_queries.get(&target).expect("completed query retained before tick");
        assert!(query.is_done(&actor.socket));
        assert_eq!(query.responders().nodes().len(), 2, "two real UDP responders");
        assert!(query.responders().nodes().iter().all(|node| node.token().is_some()));
        let get_holders = query.closest().len() + query.responders().len();
        let get_visited = 2;
        let retained_holders = budget.holder_count() - get_holders;
        assert!(retained_holders > 0, "bootstrap/routing/unrelated holders remain separately charged, not the PUT request");
        let mut external_leases = Vec::new();
        while budget.holder_count() < 255 {
            external_leases.push(budget.reserve_holder().expect("retain aggregate holder capacity"));
        }
        assert_eq!(budget.holder_count(), 255);
        assert_eq!(external_leases.len() + retained_holders + get_holders, 255,
            "intentional external leases are distinct from GET and existing operation holders");
        let expected_holders = 255 - get_holders;
        let expected_visited = budget.visited_count() - get_visited;

        if mode == 1 {
            tokio::time::pause();
            tokio::time::advance(get_deadline.saturating_duration_since(Instant::now())).await;
        }
        if mode == 2 {
            drop(get_receiver.take());
        }
        let boundary = Arc::new(CleanupBoundary {
            budget: Arc::clone(&budget),
            observed_holders: std::sync::atomic::AtomicUsize::new(usize::MAX),
            observed_visited: std::sync::atomic::AtomicUsize::new(usize::MAX),
        });
        let waker = Waker::from(Arc::clone(&boundary));
        let mut context = Context::from_waker(&waker);
        let mut cleanup_rx = Box::pin(cleanup_rx);
        assert!(matches!(cleanup_rx.as_mut().poll(&mut context), Poll::Pending));
        assert!(Instant::now() < deadline, "PUT deadline must remain live for holder exhaustion");
        actor.tick_owned();

        assert_eq!(boundary.observed_holders.load(std::sync::atomic::Ordering::SeqCst), expected_holders);
        assert_eq!(boundary.observed_visited.load(std::sync::atomic::Ordering::SeqCst), expected_visited);
        assert!(matches!(cleanup_rx.as_mut().poll(&mut context), Poll::Ready(Ok(()))));
        assert!(matches!(charged_put.await.expect("PUT result delivered"), Err(crate::resource::OwnedPutError::Put(PutError::Query(PutQueryError::Resource(crate::resource::ResourceError::CandidateLimit))))));
        if mode == 0 {
            let completion = get_receiver.as_mut().expect("live GET receiver").try_recv()
                .expect("live shared GET result delivered")
                .expect("completed shared GET remains successful");
            assert!(completion.network_completed(), "provenance comes from actual GET responses");
            assert_eq!(completion.items().len(), 2);
            assert!(completion.items().iter().all(|received| received.target() == &target
                && received.value() == item.value() && received.seq() == item.seq()
                && received.key() == item.key() && received.signature() == item.signature()));
        } else if mode == 1 {
            assert!(matches!(get_receiver.as_mut().expect("deadline GET receiver").try_recv(),
                Ok(Err(crate::resource::ResourceError::DeadlineExceeded))));
        } else {
            assert!(get_receiver.is_none(), "cancelled receiver dropped or never allocated");
        }
        assert!(!actor.core.iterative_queries.contains_key(&target));
        assert!(!actor.core.put_queries.contains_key(&target));
        assert!(!actor.owned_resources.as_ref().expect("owned actor").operations.contains_key(&target));
        assert_eq!(actor.socket.owned_deadline(operation), None);
        assert!(!actor.owned_has_response_operation(operation));
        assert_eq!(budget.holder_count(), expected_holders);
        assert_eq!(budget.visited_count(), expected_visited);
        assert!(actor.core.iterative_queries.contains_key(&independent_target));
        assert!(matches!(independent_receiver.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
        assert_eq!(actor.owned_resources.as_ref().expect("owned actor").maintenance, Some(maintenance_operation));
        assert!(actor.socket.operation_rpc_len(maintenance_operation) > 0);
        assert!(actor.owned_error().is_none());
        let _ = &maintenance_peer;
        drop(external_leases);
        drop(put_cancel);
        if mode == 1 {
            tokio::time::resume();
        }
    }
}
