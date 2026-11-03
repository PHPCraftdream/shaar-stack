// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::*;
use crate::core::put_query::{PutError, PutQueryError};
use crate::{OwnedDht, OwnedPutError};
use ed25519_dalek::SigningKey;
use std::collections::HashSet;
use tokio::time::Instant;

#[tokio::test]
async fn failed_public_put_send_retires_target_and_allows_wire_success() {
    let (peer, address) = capture();
    let mut actor = bounded_actor(address);
    actor.owned_disable_maintenance_for_test = true;
    actor.socket.fail_next_send_for_test();
    let mut owner = OwnedDht::from_actor(actor);
    let handle = owner.handle();
    let signer = SigningKey::from_bytes(&[0xC1; 32]);
    let item = crate::common::MutableItem::new(&signer, b"send failure", 1, None);
    let target = *item.target();
    let mut failed = handle.put_mutable(item).await.expect("public admission");
    let result = tokio::time::timeout(std::time::Duration::from_secs(2), failed.wait())
        .await
        .expect("local send failure progresses without an unrelated actor wake");
    assert!(
        matches!(
            &result,
            Err(OwnedPutError::Resource(crate::resource::ResourceError::Send))
        ),
        "expected local Send failure, got {result:?}"
    );
    failed.cancel_and_wait().await.expect("failure cleanup");

    let item = crate::common::MutableItem::new(&signer, b"retry", 2, None);
    assert_eq!(*item.target(), target);
    let mut retry = handle
        .put_mutable(item)
        .await
        .expect("same target re-admitted");
    let protocol = async {
        let (get, source) = receive_request(&peer).await;
        let get_reply = Message {
            transaction_id: get.transaction_id,
            version: Some([82, 83, 0, 6]),
            requester_ip: None,
            message_type: MessageType::Response(ResponseSpecific::NoValues(
                crate::common::NoValuesResponseArguments {
                    responder_id: Id::from([0xC2; 20]),
                    token: vec![0x44].into_boxed_slice(),
                    nodes: None,
                },
            )),
            read_only: false,
        };
        peer.send_to(&get_reply.to_bytes().unwrap(), source)
            .await
            .unwrap();
        let (put, put_source) = receive_request(&peer).await;
        assert_eq!(put_source, source);
        let reply = Message {
            transaction_id: put.transaction_id,
            version: Some([82, 83, 0, 6]),
            requester_ip: None,
            message_type: MessageType::Response(ResponseSpecific::Ping(
                PingResponseArguments {
                    responder_id: Id::from([0xC3; 20]),
                },
            )),
            read_only: false,
        };
        peer.send_to(&reply.to_bytes().unwrap(), source)
            .await
            .unwrap();
        target
    };
    let (result, wire_target) = tokio::join!(retry.wait(), protocol);
    assert_eq!(wire_target, target);
    assert_eq!(result.unwrap().target(), target);
    retry.cancel_and_wait().await.expect("successful PUT cleanup");
    owner.close().await.expect("close owner");
}

#[tokio::test]
async fn legacy_put_error_response_retires_target_for_re_admission() {
    let (peer, address) = capture();
    let mut actor = bounded_actor(address);
    actor.owned_disable_maintenance_for_test = true;
    let signer = SigningKey::from_bytes(&[0xC4; 32]);
    let first = crate::common::MutableItem::new(&signer, b"legacy", 1, None);
    let target = *first.target();
    let mut args = crate::common::PutMutableRequestArguments::from(first, None);
    args.cas = Some(0);
    actor
        .owned_put(PutRequestSpecific::PutMutable(args), None)
        .unwrap();
    actor.socket.flush().await;

    let (get, source) = receive_request(&peer).await;
    let get_reply = Message {
        transaction_id: get.transaction_id,
        version: Some([82, 83, 0, 6]),
        requester_ip: None,
        message_type: MessageType::Response(ResponseSpecific::NoValues(
            crate::common::NoValuesResponseArguments {
                responder_id: Id::from([0xC5; 20]),
                token: vec![3].into_boxed_slice(),
                nodes: None,
            },
        )),
        read_only: false,
    };
    peer.send_to(&get_reply.to_bytes().unwrap(), source)
        .await
        .unwrap();
    let (decoded, from) = receive_response(&mut actor).await;
    actor.process_owned_publication_message(decoded, from);
    actor.tick_owned();
    actor.socket.flush().await;

    let (put, put_source) = receive_request(&peer).await;
    let error = Message {
        transaction_id: put.transaction_id,
        version: Some([82, 83, 0, 6]),
        requester_ip: None,
        message_type: MessageType::Error(crate::common::ErrorSpecific {
            code: 201,
            description: "rejected".into(),
        }),
        read_only: false,
    };
    peer.send_to(&error.to_bytes().unwrap(), put_source)
        .await
        .unwrap();
    let (decoded, from) = receive_response(&mut actor).await;
    actor.process_owned_publication_message(decoded, from);
    actor.tick_owned();
    assert!(!actor.core.put_queries.contains_key(&target));

    let next = crate::common::MutableItem::new(&signer, b"legacy retry", 2, None);
    assert_eq!(*next.target(), target);
    let mut args = crate::common::PutMutableRequestArguments::from(next, None);
    args.cas = Some(1);
    actor
        .owned_put(PutRequestSpecific::PutMutable(args), None)
        .expect("legacy same-target re-admission");
}

#[tokio::test]
async fn failed_puts_on_more_than_eight_targets_release_target_slots() {
    let (peer, address) = capture();
    let mut actor = bounded_actor(address);
    actor.owned_disable_maintenance_for_test = true;
    let now = Instant::now();
    let mut targets = HashSet::new();

    for index in 0..12u8 {
        let signer = SigningKey::from_bytes(&[index.wrapping_add(1); 32]);
        let item = crate::common::MutableItem::new(
            &signer,
            &[index],
            i64::from(index),
            None,
        );
        let target = *item.target();
        assert!(targets.insert(target), "target {index} must be distinct");
        let (reply, mut reply_rx) = oneshot::channel();
        let (cleanup, mut cleanup_rx) = oneshot::channel();
        let (_cancel, cancel_rx) = oneshot::channel();
        let lease = actor.owned_request_budget().acquire().expect("request lease");
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
        let mut charged = reply_rx.try_recv().unwrap().expect("actual admission");
        actor.socket.fail_next_send_for_test();
        actor.socket.flush().await;
        actor.retire_owned_operation_errors();
        actor.tick_owned();
        assert!(matches!(
            (&mut charged).await,
            Ok(Err(OwnedPutError::Resource(
                crate::resource::ResourceError::Send
            )))
        ));
        assert_eq!(cleanup_rx.try_recv(), Ok(()), "target {index}");
        assert!(!actor.core.put_queries.contains_key(&target), "target {index}");
    }

    let first_signer = SigningKey::from_bytes(&[1; 32]);
    let item = crate::common::MutableItem::new(&first_signer, &[0], 99, None);
    let target = *item.target();
    let (reply, mut reply_rx) = oneshot::channel();
    let (cleanup, _cleanup_rx) = oneshot::channel();
    let (_cancel, cancel_rx) = oneshot::channel();
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
    assert!(reply_rx.try_recv().unwrap().is_ok(), "same target slot reusable");
    assert!(actor.core.put_queries.contains_key(&target));
    let _ = peer;
}

#[tokio::test]
async fn send_failure_preserves_unrelated_get_and_maintenance_state() {
    let (peer, address) = capture();
    let (maintenance_peer, maintenance_address) = capture();
    let mut actor = bounded_actor(address);
    actor.owned_disable_maintenance_for_test = true;
    let signer = SigningKey::from_bytes(&[0xD1; 32]);
    let failed_item = crate::common::MutableItem::new(&signer, b"failed", 1, None);
    let failed_target = *failed_item.target();
    actor
        .owned_put(PutRequestSpecific::PutMutable(
            crate::common::PutMutableRequestArguments::from(failed_item, None),
        ), None)
        .expect("legacy PUT queued first");

    let unrelated_target = Id::from([0xD2; 20]);
    let (unrelated_sender, mut unrelated_receiver) = oneshot::channel();
    actor.owned_mutable(unrelated_target, unrelated_sender).expect("unrelated GET");
    actor.owned_ping(maintenance_address).expect("maintenance ping");
    let resource = actor.owned_resources.as_ref().unwrap();
    let unrelated_operation = resource.operations[&unrelated_target];
    let maintenance_operation = resource.maintenance.expect("maintenance operation");
    let unrelated_deadline = actor.socket.owned_deadline(unrelated_operation).unwrap();
    let unrelated_rounds = actor.socket.owned_get_rounds(unrelated_operation);
    let unrelated_rpc_len = actor.socket.operation_rpc_len(unrelated_operation);
    let maintenance_deadline = actor.socket.owned_deadline(maintenance_operation).unwrap();
    let maintenance_rpc_len = actor.socket.operation_rpc_len(maintenance_operation);

    actor.socket.fail_next_send_for_test();
    actor.socket.flush().await;
    actor.retire_owned_operation_errors();

    assert!(!actor.core.put_queries.contains_key(&failed_target));
    assert!(!actor.core.iterative_queries.contains_key(&failed_target));
    assert_eq!(actor.socket.owned_put_deadline_for_test(failed_target), None);
    assert_eq!(actor.owned_resources.as_ref().unwrap().operations[&unrelated_target], unrelated_operation);
    assert_eq!(actor.socket.owned_deadline(unrelated_operation), Some(unrelated_deadline));
    assert_eq!(actor.socket.owned_get_rounds(unrelated_operation), unrelated_rounds);
    assert_eq!(actor.socket.operation_rpc_len(unrelated_operation), unrelated_rpc_len);
    assert!(matches!(unrelated_receiver.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
    assert_eq!(actor.owned_resources.as_ref().unwrap().maintenance, Some(maintenance_operation));
    assert_eq!(actor.socket.owned_deadline(maintenance_operation), Some(maintenance_deadline));
    assert_eq!(actor.socket.operation_rpc_len(maintenance_operation), maintenance_rpc_len);

    actor.socket.flush().await;
    let (get, get_source) = receive_request(&peer).await;
    assert!(matches!(get.message_type,
        MessageType::Request(crate::common::RequestSpecific {
            request_type: crate::common::RequestTypeSpecific::GetValue(
                crate::common::GetValueRequestArguments { target, .. }
            ),
            ..
        }) if target == unrelated_target));
    let (ping, ping_source) = receive_request(&maintenance_peer).await;
    assert!(matches!(ping.message_type,
        MessageType::Request(crate::common::RequestSpecific {
            request_type: crate::common::RequestTypeSpecific::Ping,
            ..
        })));
    assert_eq!(get_source, ping_source);

    let retry = crate::common::MutableItem::new(&signer, b"retry", 2, None);
    assert_eq!(*retry.target(), failed_target);
    actor.owned_put(PutRequestSpecific::PutMutable(
        crate::common::PutMutableRequestArguments::from(retry, None),
    ), None).expect("same-target legacy re-admission");
}

#[tokio::test(start_paused = true)]
async fn recorded_send_error_precedes_put_deadline_expiry() {
    let (_peer, address) = capture();
    let mut actor = bounded_actor(address);
    actor.owned_disable_maintenance_for_test = true;
    let deadline = Instant::now() + Duration::from_millis(250);
    let item = crate::common::MutableItem::new(
        &SigningKey::from_bytes(&[0xCE; 32]),
        b"recorded send before expiry",
        1,
        None,
    );
    let target = *item.target();
    let (reply, mut reply_rx) = oneshot::channel();
    let (cleanup, mut cleanup_rx) = oneshot::channel();
    let (_cancel, cancel_rx) = oneshot::channel();
    let lease = actor.owned_request_budget().acquire().expect("request lease");
    actor.owned_put_admission_until(target, item, reply, cleanup, cancel_rx, deadline, lease);
    actor.maintain_owned_puts_at(Instant::now());
    let charged = reply_rx.try_recv().expect("admission receipt").expect("admitted PUT");
    actor.socket.fail_next_send_for_test();
    actor.socket.flush().await;
    tokio::time::advance(Duration::from_millis(250)).await;
    actor.tick();
    let result = charged.await.expect("typed result sender retained");
    assert!(
        matches!(
            &result,
            Err(OwnedPutError::Resource(ResourceError::Send))
        ),
        "recorded Send must win expiry: {result:?}"
    );
    assert_eq!(cleanup_rx.try_recv(), Ok(()));
    assert_eq!(actor.socket.owned_put_deadline_for_test(target), None);
    assert!(!actor.owned_resources.as_ref().unwrap().operations.contains_key(&target));
}
