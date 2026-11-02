// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::net::UdpSocket;

use crate::{OwnedDht, OwnedPutError};
use crate::core::{PutError, PutQueryError};
use ed25519_dalek::SigningKey;
use tokio::time::Instant;

use super::*;

#[tokio::test]
async fn public_mutable_put_uses_wire_token_and_returns_success_or_typed_error() {
    for success in [true, false] {
        let (peer, peer_address) = capture();
        let mut actor = bounded_actor(peer_address);
        actor.owned_disable_maintenance_for_test = true;
        let mut owner = OwnedDht::from_actor(actor);
        let handle = owner.handle();
        let actor_addr = handle.info().await.unwrap().local_addr();
        let signer = SigningKey::from_bytes(&[0xA7; 32]);
        let item = crate::common::MutableItem::new(&signer, b"public-wire-put", 7, None);
        let target = *item.target();
        let key = signer.verifying_key().to_bytes();

        let public = async {
            let mut operation = handle.put_mutable(item).await.expect("admit public PUT");
            let result = operation.wait().await;
            operation.cancel_and_wait().await.expect("actual PUT cleanup");
            result
        };
        let protocol = async {
            let (get, source) = receive_request(&peer).await;
            assert_eq!(source, actor_addr);
            let get_reply = Message {
                transaction_id: get.transaction_id,
                version: Some([82, 83, 0, 6]),
                requester_ip: None,
                message_type: MessageType::Response(ResponseSpecific::NoValues(
                    crate::common::NoValuesResponseArguments {
                        responder_id: Id::from([0xA8; 20]),
                        token: vec![0x44, 0x55].into_boxed_slice(),
                        nodes: None,
                    },
                )),
                read_only: false,
            };
            peer.send_to(&get_reply.to_bytes().expect("encode GET reply"), source)
                .await
                .expect("send GET reply");

            let (put, put_source) = receive_request(&peer).await;
            assert_eq!(put_source, source);
            assert_ne!(put.transaction_id, get.transaction_id);
            let (args, token) = match &put.message_type {
                MessageType::Request(request) => match &request.request_type {
                    crate::common::RequestTypeSpecific::Put(putreq) => {
                        match &putreq.put_request_type {
                            crate::common::PutRequestSpecific::PutMutable(args) => {
                                (args, putreq.token.as_ref())
                            }
                            other => panic!("expected mutable PUT, got {other:?}"),
                        }
                    }
                    other => panic!("expected PUT request, got {other:?}"),
                },
                other => panic!("expected PUT request, got {other:?}"),
            };
            assert_eq!(args.v.as_ref(), b"public-wire-put");
            assert_eq!(args.k, key);
            assert_eq!(args.seq, 7);
            assert_eq!(args.target, target);
            assert_eq!(token, &[0x44, 0x55]);

            let reply = Message {
                transaction_id: put.transaction_id,
                version: Some([82, 83, 0, 6]),
                requester_ip: None,
                message_type: if success {
                    MessageType::Response(ResponseSpecific::Ping(PingResponseArguments {
                        responder_id: Id::from([0xA9; 20]),
                    }))
                } else {
                    MessageType::Error(crate::common::ErrorSpecific {
                        code: 201,
                        description: "PUT rejected".to_owned(),
                    })
                },
                read_only: false,
            };
            peer.send_to(&reply.to_bytes().expect("encode PUT reply"), put_source)
                .await
                .expect("send PUT reply");
            (put.transaction_id, get.transaction_id)
        };

        let (result, (put_tid, get_tid)) = tokio::join!(public, protocol);
        if success {
            let receipt = result.expect("public PUT succeeds");
            assert_eq!(receipt.target(), target);
            assert!(receipt.transaction_ids().contains(&put_tid));
            assert!(!receipt.transaction_ids().contains(&get_tid));
        } else {
            assert!(matches!(
                result,
                Err(OwnedPutError::Put(PutError::Query(
                    PutQueryError::ErrorResponse(error)
                ))) if error.code == 201
            ));
        }

        owner.close().await.expect("close owner");
        let rebound = UdpSocket::bind(actor_addr).expect("owner released actor socket");
        drop(rebound);
    }
}

#[tokio::test]
async fn successful_public_put_receipt_clone_retains_result_charge() {
    let (peer, peer_address) = capture();
    let mut actor = bounded_actor(peer_address);
    actor.owned_disable_maintenance_for_test = true;
    let mut owner = OwnedDht::from_actor(actor);
    let handle = owner.handle();
    let actor_addr = handle.info().await.unwrap().local_addr();
    let mut retained_receipts = Vec::new();

    for i in 0..8u8 {
        let signer = SigningKey::from_bytes(&[i.wrapping_add(1); 32]);
        let item = crate::common::MutableItem::new(&signer, &[i], i64::from(i), None);
        let public = async {
            let mut operation = handle.put_mutable(item).await.expect("admit public PUT");
            let receipt = operation.wait().await.expect("successful public PUT");
            operation.cancel_and_wait().await.expect("actual PUT cleanup");
            receipt
        };
        let protocol = async {
            let (get, source) = receive_request(&peer).await;
            assert_eq!(source, actor_addr);
            let reply = Message {
                transaction_id: get.transaction_id,
                version: Some([82, 83, 0, 6]),
                requester_ip: None,
                message_type: MessageType::Response(ResponseSpecific::NoValues(
                    crate::common::NoValuesResponseArguments {
                        responder_id: Id::from([0xA8; 20]),
                        token: vec![0x44, 0x55].into_boxed_slice(),
                        nodes: None,
                    },
                )),
                read_only: false,
            };
            peer.send_to(&reply.to_bytes().expect("encode GET reply"), source)
                .await.expect("send GET reply");
            let (put, put_source) = receive_request(&peer).await;
            assert_eq!(put_source, source);
            let reply = Message {
                transaction_id: put.transaction_id,
                version: Some([82, 83, 0, 6]),
                requester_ip: None,
                message_type: MessageType::Response(ResponseSpecific::Ping(PingResponseArguments {
                    responder_id: Id::from([0xA9; 20]),
                })),
                read_only: false,
            };
            peer.send_to(&reply.to_bytes().expect("encode PUT reply"), put_source)
                .await.expect("send PUT reply");
        };
        let (receipt, ()) = tokio::join!(public, protocol);
        if i == 0 {
            retained_receipts.push(receipt.clone());
        }
        retained_receipts.push(receipt);
    }

    let signer = SigningKey::from_bytes(&[0xEE; 32]);
    let item = crate::common::MutableItem::new(&signer, b"ninth", 9, None);
    let mut ninth = Box::pin(handle.put_mutable(item));
    tokio::select! {
        biased;
        result = &mut ninth => panic!("ninth PUT admitted while successful receipts retained: {result:?}"),
        info = handle.info() => { info.expect("same actor alive while ninth queued"); }
    }
    drop(retained_receipts.remove(0));
    tokio::select! {
        biased;
        result = &mut ninth => panic!("cloned receipt did not retain result charge: {result:?}"),
        info = handle.info() => { info.expect("same actor alive while ninth queued"); }
    }
    drop(retained_receipts.remove(0));
    let mut admitted = ninth.await.expect("final receipt drop promotes ninth PUT");
    admitted.cancel_and_wait().await.expect("actual PUT cleanup");
    owner.close().await.expect("close owner");
}

#[tokio::test]
async fn public_put_cancellation_retains_get_until_admission_cleanup() {
    let (peer, addr) = capture();
    let mut actor = bounded_actor(addr);
    let item = crate::common::MutableItem::new(
        &SigningKey::from_bytes(&[0xA7; 32]),
        b"shared",
        1,
        None,
    );
    let target = *item.target();
    let (get_sender, mut get_receiver) = tokio::sync::oneshot::channel();
    actor.owned_mutable(target, get_sender).unwrap();
    actor.socket.flush().await;
    let (get_request, _) = receive_request(&peer).await;
    let operation = actor.owned_resources.as_ref().unwrap().operations[&target];
    let (reply, mut reply_rx) = tokio::sync::oneshot::channel();
    let (cleanup, mut cleanup_rx) = tokio::sync::oneshot::channel();
    let (cancel, cancel_rx) = tokio::sync::oneshot::channel();
    let lease = actor.owned_request_budget().acquire().unwrap();
    let now = Instant::now();
    actor.owned_put_admission_until(
        target,
        item,
        reply,
        cleanup,
        cancel_rx,
        now + Duration::from_secs(10),
        lease,
    );
    actor.maintain_owned_puts_at(now);
    let charged = reply_rx.try_recv().unwrap().unwrap();
    cancel.send(()).unwrap();
    actor.maintain_owned_puts_at(now);
    assert_eq!(cleanup_rx.try_recv(), Ok(()));
    assert!(actor.core.iterative_queries.contains_key(&target));
    assert!(!actor.core.put_queries.contains_key(&target));
    assert!(actor.socket.owned_inflight(get_request.transaction_id));
    assert_eq!(actor.owned_resources.as_ref().unwrap().operations[&target], operation);
    assert!(matches!(get_receiver.try_recv(), Err(tokio::sync::oneshot::error::TryRecvError::Empty)));
    drop(charged);
    drop(get_receiver);
    actor.maintain_owned_admissions_at(now);
    assert!(!actor.core.iterative_queries.contains_key(&target));
    assert_eq!(actor.socket.owned_test_state().unwrap().2, 0);
}

#[tokio::test(start_paused = true)]
async fn public_put_inbox_delay_does_not_reset_original_deadline() {
    let (peer, peer_address) = capture();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let mut actor = bounded_actor(peer_address);
    actor.owned_disable_maintenance_for_test = true;
    actor.socket.owned_flush_gate = Some((entered_tx, release_rx));
    let actor_addr = actor.socket.local_addr();
    let mut owner = OwnedDht::from_actor(actor);
    let handle = owner.handle();

    entered_rx.await.expect("actor enters held flush");
    let item = crate::common::MutableItem::new(
        &SigningKey::from_bytes(&[0xB7; 32]),
        b"inbox-delay",
        1,
        None,
    );
    let mut request = Box::pin(handle.put_mutable(item));
    tokio::select! {
        biased;
        result = &mut request => panic!("public PUT completed while actor flush was held: {result:?}"),
        _ = std::future::ready(()) => {}
    }

    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(matches!(
        request.await,
        Err(crate::resource::ResourceError::DeadlineExceeded)
    ));

    drop(release_tx);
    owner.close().await.expect("close owner");
    let mut bytes = [0u8; 2048];
    assert_eq!(
        peer.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "expired public PUT was never admitted or sent"
    );
    let rebound = UdpSocket::bind(actor_addr).expect("owner released actor socket");
    drop(rebound);
}

#[tokio::test(start_paused = true)]
async fn queued_public_puts_expire_at_original_deadline_without_queries() {
    let (_peer, addr) = capture();
    let mut actor = bounded_actor(addr);
    let now = Instant::now();
    let held_results: Vec<_> = (0..8)
        .map(|_| actor.owned_resources.as_ref().unwrap().reserve_result_for_test().unwrap())
        .collect();
    let mut queued = Vec::new();
    for i in 0..16u8 {
        let signer = SigningKey::from_bytes(&[i; 32]);
        let item = crate::common::MutableItem::new(&signer, b"queued", i64::from(i), None);
        let target = *item.target();
        let (reply, mut reply_rx) = tokio::sync::oneshot::channel();
        let (cleanup, mut cleanup_rx) = tokio::sync::oneshot::channel();
        let (cancel, cancel_rx) = tokio::sync::oneshot::channel();
        let lease = actor.owned_request_budget().acquire().unwrap();
        actor.owned_put_admission_until(target, item, reply, cleanup, cancel_rx, now + Duration::from_secs(10), lease);
        queued.push((target, reply_rx, cleanup_rx, cancel));
    }
    assert_eq!(actor.owned_resources.as_ref().unwrap().put_pending_len(), 16);
    let signer = SigningKey::from_bytes(&[0xEE; 32]);
    let item = crate::common::MutableItem::new(&signer, b"seventeenth", 17, None);
    let (reply, mut reply_rx) = tokio::sync::oneshot::channel();
    let (cleanup, mut cleanup_rx) = tokio::sync::oneshot::channel();
    let (_cancel, cancel_rx) = tokio::sync::oneshot::channel();
    let lease = actor.owned_request_budget().acquire().unwrap();
    actor.owned_put_admission_until(*item.target(), item, reply, cleanup, cancel_rx, now + Duration::from_secs(10), lease);
    assert!(matches!(reply_rx.try_recv().unwrap(), Err(crate::resource::ResourceError::OperationLimit)));
    assert_eq!(cleanup_rx.try_recv(), Ok(()));
    assert_eq!(actor.owned_resources.as_ref().unwrap().put_pending_len(), 16);
    assert!(actor.core.iterative_queries.is_empty());
    assert!(actor.core.put_queries.is_empty());
    tokio::time::advance(Duration::from_secs(10)).await;
    actor.maintain_owned_puts_at(Instant::now());
    for (_, mut reply, mut cleanup, _cancel) in queued.drain(..) {
        assert!(matches!(reply.try_recv().unwrap(), Err(crate::resource::ResourceError::DeadlineExceeded)));
        assert_eq!(cleanup.try_recv(), Ok(()));
    }
    assert!(actor.core.iterative_queries.is_empty());
    assert!(actor.core.put_queries.is_empty());
    assert_eq!(actor.owned_resources.as_ref().unwrap().put_pending_len(), 0);
    drop(held_results);
}

#[tokio::test]
async fn canceled_public_put_results_remain_budgeted_until_receivers_drop() {
    let (_peer, addr) = capture();
    let mut actor = bounded_actor(addr);
    let now = Instant::now();
    let signer = SigningKey::from_bytes(&[0xA7; 32]);
    let mut retained = Vec::new();

    for i in 0..8u8 {
        let item = crate::common::MutableItem::new(&signer, &[i], i64::from(i), None);
        let target = *item.target();
        let (reply, mut reply_rx) = tokio::sync::oneshot::channel();
        let (cleanup, mut cleanup_rx) = tokio::sync::oneshot::channel();
        let (cancel, cancel_rx) = tokio::sync::oneshot::channel();
        let lease = actor.owned_request_budget().acquire().unwrap();
        actor.owned_put_admission_until(
            target,
            item,
            reply,
            cleanup,
            cancel_rx,
            now + Duration::from_secs(10),
            lease,
        );
        actor.maintain_owned_puts_at(now);
        let charged = reply_rx.try_recv().unwrap().unwrap();
        cancel.send(()).unwrap();
        actor.maintain_owned_puts_at(now);
        assert_eq!(cleanup_rx.try_recv(), Ok(()));
        retained.push((charged, cleanup_rx));
    }

    assert!(actor.owned_resources.as_ref().unwrap().active_put_len() == 0);
    assert_eq!(actor.owned_resources.as_ref().unwrap().put_pending_len(), 0);
    let item = crate::common::MutableItem::new(&signer, b"ninth", 9, None);
    let target = *item.target();
    let (reply, mut reply_rx) = tokio::sync::oneshot::channel();
    let (cleanup, mut cleanup_rx) = tokio::sync::oneshot::channel();
    let (cancel, cancel_rx) = tokio::sync::oneshot::channel();
    let lease = actor.owned_request_budget().acquire().unwrap();
    actor.owned_put_admission_until(
        target,
        item,
        reply,
        cleanup,
        cancel_rx,
        now + Duration::from_secs(10),
        lease,
    );
    actor.maintain_owned_puts_at(now);
    assert!(matches!(reply_rx.try_recv(), Err(tokio::sync::oneshot::error::TryRecvError::Empty)));
    assert_eq!(actor.owned_resources.as_ref().unwrap().put_pending_len(), 1);

    drop(retained.pop());
    actor.maintain_owned_puts_at(now);
    let charged = reply_rx.try_recv().unwrap().unwrap();
    cancel.send(()).unwrap();
    actor.maintain_owned_puts_at(now);
    assert_eq!(cleanup_rx.try_recv(), Ok(()));
    drop(charged);
    assert_eq!(actor.owned_resources.as_ref().unwrap().put_pending_len(), 0);
}

#[tokio::test]
async fn held_send_public_put_cancel_observes_actual_cleanup() {
    let (peer, peer_address) = capture();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let mut actor = bounded_actor(peer_address);
    actor.owned_disable_maintenance_for_test = true;
    actor.socket.hold_next_persistent_send_for_test(entered_tx, release_rx);
    let mut owner = OwnedDht::from_actor(actor);
    let handle = owner.handle();
    let addr = handle.info().await.unwrap().local_addr();
    let item = crate::common::MutableItem::new(
        &SigningKey::from_bytes(&[0xA9; 32]),
        b"held",
        1,
        None,
    );
    let mut operation = handle.put_mutable(item).await.unwrap();
    entered_rx.await.unwrap();
    operation
        .cancel_and_wait()
        .await
        .expect("held-send cleanup observed");
    operation
        .cancel_and_wait()
        .await
        .expect("idempotent cleanup");
    assert!(matches!(
        operation.wait().await,
        Err(OwnedPutError::Resource(crate::resource::ResourceError::QueryCancelled))
    ));
    let mut buf = [0u8; 2048];
    assert_eq!(
        peer.try_recv_from(&mut buf).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(release_tx);
    owner.close().await.expect("close owner");
    UdpSocket::bind(addr).expect("owner released actor socket");
}

#[tokio::test(start_paused = true)]
async fn public_put_attempts_share_original_deadline_and_full_jitter_bounds() {
    let (peer, peer_address) = capture();
    let mut actor = bounded_actor(peer_address);
    actor.owned_disable_maintenance_for_test = true;
    let mut owner = OwnedDht::from_actor(actor);
    let handle = owner.handle();
    let actor_addr = handle.info().await.unwrap().local_addr();
    let item = crate::common::MutableItem::new(
        &SigningKey::from_bytes(&[0xB7; 32]),
        b"retry-deadline",
        1,
        None,
    );
    let target = *item.target();
    let mut operation = handle.put_mutable(item).await.expect("admit public PUT");

    let (get, source) = receive_request(&peer).await;
    assert_eq!(source, actor_addr);
    let get_reply = Message {
        transaction_id: get.transaction_id,
        version: Some([82, 83, 0, 6]),
        requester_ip: None,
        message_type: MessageType::Response(ResponseSpecific::NoValues(
            crate::common::NoValuesResponseArguments {
                responder_id: Id::from([0xA8; 20]),
                token: vec![0x44, 0x55].into_boxed_slice(),
                nodes: None,
            },
        )),
        read_only: false,
    };
    peer.send_to(&get_reply.to_bytes().expect("encode GET reply"), source)
        .await
        .expect("send GET reply");

    let (first, first_source) = receive_request(&peer).await;
    assert_eq!(first_source, source);
    assert_ne!(first.transaction_id, get.transaction_id);

    handle.test_put_control(target, 100).await.expect("expire first PUT");
    tokio::time::advance(Duration::from_millis(99)).await;
    handle.info().await.expect("timer barrier");
    let mut bytes = [0u8; 2048];
    assert_eq!(peer.try_recv_from(&mut bytes).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    tokio::time::advance(Duration::from_millis(1)).await;
    let (second, second_source) = receive_request(&peer).await;
    assert_eq!(second_source, source);
    assert_ne!(second.transaction_id, first.transaction_id);

    handle.test_put_control(target, 200).await.expect("expire second PUT");
    tokio::time::advance(Duration::from_millis(199)).await;
    handle.info().await.expect("timer barrier");
    assert_eq!(peer.try_recv_from(&mut bytes).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    tokio::time::advance(Duration::from_millis(1)).await;
    let (third, third_source) = receive_request(&peer).await;
    assert_eq!(third_source, source);
    assert_ne!(third.transaction_id, second.transaction_id);

    handle.test_put_control(target, 0).await.expect("expire third PUT");
    assert!(matches!(
        operation.wait().await,
        Err(OwnedPutError::Put(PutError::Query(PutQueryError::Timeout)))
    ));
    operation.cancel_and_wait().await.expect("observe actual cleanup");
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(peer.try_recv_from(&mut bytes).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    owner.close().await.expect("close owner");
    drop(UdpSocket::bind(actor_addr).expect("owner released actor socket"));
}

#[tokio::test(start_paused = true)]
async fn public_active_put_expires_without_late_send() {
    let (peer, peer_address) = capture();
    let mut actor = bounded_actor(peer_address);
    actor.owned_disable_maintenance_for_test = true;
    let mut owner = OwnedDht::from_actor(actor);
    let handle = owner.handle();
    let actor_addr = handle.info().await.expect("actor info").local_addr();
    let entry = Instant::now();
    let item = crate::common::MutableItem::new(
        &SigningKey::from_bytes(&[0xC7; 32]),
        b"active-expiry",
        1,
        None,
    );
    let mut operation = handle.put_mutable(item).await.expect("admit public PUT");

    let (get, source) = receive_request(&peer).await;
    assert_eq!(source, actor_addr);
    let get_reply = Message {
        transaction_id: get.transaction_id,
        version: Some([82, 83, 0, 6]),
        requester_ip: None,
        message_type: MessageType::Response(ResponseSpecific::NoValues(
            crate::common::NoValuesResponseArguments {
                responder_id: Id::from([0xA8; 20]),
                token: vec![0x44, 0x55].into_boxed_slice(),
                nodes: None,
            },
        )),
        read_only: false,
    };
    peer.send_to(&get_reply.to_bytes().expect("encode GET reply"), source)
        .await
        .expect("send GET reply");
    let (first, first_source) = receive_request(&peer).await;
    assert_eq!(first_source, source);
    assert_ne!(first.transaction_id, get.transaction_id);

    let deadline = entry + Duration::from_secs(10);
    tokio::time::advance(deadline.saturating_duration_since(Instant::now())).await;
    assert!(matches!(
        operation.wait().await,
        Err(OwnedPutError::Resource(crate::resource::ResourceError::DeadlineExceeded))
    ));
    operation.cancel_and_wait().await.expect("actual PUT cleanup");

    let mut bytes = [0u8; 2048];
    assert_eq!(
        peer.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "expired public PUT did not send a late retry"
    );
    handle.info().await.expect("actor remains live");
    owner.close().await.expect("close owner");
    drop(UdpSocket::bind(actor_addr).expect("owner released actor socket"));
}
