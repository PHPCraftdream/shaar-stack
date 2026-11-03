// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::*;
use crate::common::PutMutableRequestArguments;
use crate::{OwnedPutError, PutRequestSpecific};
use ed25519_dalek::SigningKey;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::Instant;

#[tokio::test]
async fn failed_send_keeps_public_target_owned_until_cleanup_release() {
    let (peer, address) = capture();
    let mut actor = bounded_actor(address);
    actor.owned_disable_maintenance_for_test = true;
    let signer = SigningKey::from_bytes(&[0xD1; 32]);
    let item = crate::common::MutableItem::new(&signer, b"held failure", 1, None);
    let target = *item.target();

    let observer = actor.owned_publication_observer();
    let hold = observer
        .hold_cleanup_for_target(target)
        .expect("hold cleanup for target");
    let now = Instant::now();
    let deadline = now + Duration::from_secs(10);
    let (reply_tx, mut reply_rx) = oneshot::channel();
    let (cleanup_tx, mut cleanup_rx) = oneshot::channel();
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let lease = actor
        .owned_request_budget()
        .acquire()
        .expect("request budget lease");
    actor.owned_put_admission_until(
        target, item, reply_tx, cleanup_tx, cancel_rx, deadline, lease,
    );

    actor.maintain_owned_puts_at(now);
    let charged = reply_rx
        .try_recv()
        .expect("admission charged")
        .expect("charged receiver");
    let operation = actor.owned_resources.as_ref().unwrap().operations[&target];
    actor.socket.fail_next_send_for_test();
    actor.socket.flush().await;
    actor.retire_owned_operation_errors();

    assert!(matches!(
        cleanup_rx.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert_eq!(
        actor.owned_resources.as_ref().unwrap().operations[&target],
        operation
    );
    assert!(!actor.core.put_queries.contains_key(&target));
    assert_eq!(actor.socket.owned_deadline(operation), None);
    assert_eq!(
        actor.socket.owned_put_deadline_for_test(target),
        Some(deadline)
    );
    observer.wait_cleanup_held().await;

    let held_target_item = crate::common::MutableItem::new(&signer, b"held failure", 2, None);
    assert_eq!(*held_target_item.target(), target);
    assert!(matches!(
        actor.owned_put(
            PutRequestSpecific::PutMutable(PutMutableRequestArguments::from(
                held_target_item,
                None,
            )),
            None,
        ),
        Err(crate::core::PutError::Query(crate::core::PutQueryError::Resource(
            crate::resource::ResourceError::OperationLimit,
        )))
    ));
    assert_eq!(
        actor.socket.owned_put_deadline_for_test(target),
        Some(deadline)
    );

    let mut retained = Vec::new();
    for index in 0..7u8 {
        let item = crate::common::MutableItem::new(
            &SigningKey::from_bytes(&[index.wrapping_add(40); 32]),
            &[index],
            1,
            None,
        );
        let key = *item.target();
        actor
            .owned_put(
                PutRequestSpecific::PutMutable(PutMutableRequestArguments::from(item, None)),
                None,
            )
            .expect("legacy owned PUT fills available slot");
        let resource = actor.owned_resources.as_ref().unwrap();
        let operation = resource.operations[&key];
        let deadline = actor
            .socket
            .owned_deadline(operation)
            .expect("indexed deadline");
        let rounds = actor.socket.owned_get_rounds(operation);
        let rpc_len = actor.socket.operation_rpc_len(operation);
        retained.push((key, operation, deadline, rounds, rpc_len));
    }

    let ninth_item = crate::common::MutableItem::new(
        &SigningKey::from_bytes(&[70; 32]),
        b"ninth held slot",
        1,
        None,
    );
    let ninth_key = *ninth_item.target();
    let ninth_args = PutMutableRequestArguments::from(ninth_item, None);
    assert!(matches!(
        actor.owned_put(PutRequestSpecific::PutMutable(ninth_args.clone()), None),
        Err(crate::core::PutError::Query(crate::core::PutQueryError::Resource(
            crate::resource::ResourceError::OperationLimit,
        )))
    ));
    assert_eq!(
        actor.socket.owned_put_deadline_for_test(target),
        Some(deadline)
    );
    assert_eq!(
        actor.owned_resources.as_ref().unwrap().operations[&target],
        operation
    );

    hold.release();
    actor.maintain_owned_puts_at(now);
    assert!(matches!(
        charged.await,
        Ok(Err(OwnedPutError::Resource(crate::resource::ResourceError::Send)))
    ));
    assert_eq!(cleanup_rx.try_recv(), Ok(()));
    assert_eq!(actor.socket.owned_put_deadline_for_test(target), None);

    actor
        .owned_put(PutRequestSpecific::PutMutable(ninth_args), None)
        .expect("ninth target admitted after held cleanup");
    for (key, expected_operation, expected_deadline, expected_rounds, expected_rpc_len) in retained {
        let resource = actor.owned_resources.as_ref().unwrap();
        assert_eq!(resource.operations[&key], expected_operation);
        assert_eq!(
            actor.socket.owned_put_deadline_for_test(key),
            Some(expected_deadline)
        );
        assert_eq!(actor.socket.owned_get_rounds(expected_operation), expected_rounds);
        assert_eq!(
            actor.socket.operation_rpc_len(expected_operation),
            expected_rpc_len
        );
    }
    assert!(actor
        .owned_resources
        .as_ref()
        .unwrap()
        .operations
        .contains_key(&ninth_key));
    let _peer = peer;
    let _cancel_tx = cancel_tx;
}
