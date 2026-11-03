// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::*;
use crate::common::PutMutableRequestArguments;
use crate::{OwnedPutError, PutRequestSpecific};
use ed25519_dalek::SigningKey;
use std::net::SocketAddrV4;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::Instant;

#[tokio::test]
async fn transaction_exhaustion_retires_legacy_query_without_losing_held_admission() {
    let (a_peer, a_address) = capture();
    let (legacy_peer, legacy_address) = capture();
    let (third_peer, third_address) = capture();
    let mut actor = bounded_actor(a_address);
    actor.owned_disable_maintenance_for_test = true;

    let item = crate::common::MutableItem::new(
        &SigningKey::from_bytes(&[0xF1; 32]),
        b"held typed admission",
        1,
        None,
    );
    let target = *item.target();
    let observer = actor.owned_publication_observer();
    let hold = observer.hold_cleanup_for_target(target).expect("hold cleanup");
    let now = Instant::now();
    let (reply_tx, mut reply_rx) = oneshot::channel();
    let (cleanup_tx, mut cleanup_rx) = oneshot::channel();
    let (_cancel_tx, cancel_rx) = oneshot::channel();
    let lease = actor.owned_request_budget().acquire().expect("request lease");
    actor.owned_put_admission_until(target, item, reply_tx, cleanup_tx, cancel_rx, now + Duration::from_secs(10), lease);
    actor.maintain_owned_puts_at(now);
    let mut charged = reply_rx.try_recv().expect("admission charged").expect("charged receiver");
    let held_operation = actor.owned_resources.as_ref().unwrap().operations[&target];

    actor.owned_ping(a_address).expect("transaction A");
    actor.owned_ping(legacy_address).expect("transaction B");
    actor.socket.exhaust_owned_transactions_for_test();
    let legacy_item = crate::common::MutableItem::new(&SigningKey::from_bytes(&[0xF2; 32]), b"legacy query", 1, None);
    let legacy_target = *legacy_item.target();
    actor.owned_put(PutRequestSpecific::PutMutable(PutMutableRequestArguments::from(legacy_item, None)), None)
        .expect("legacy admission");
    let legacy_operation = actor.owned_resources.as_ref().unwrap().operations[&legacy_target];
    actor.owned_ping(third_address).expect("consume final transaction");
    let query = actor.core.iterative_queries.get_mut(&legacy_target).expect("legacy iterative query");
    query.visit(&mut actor.socket, SocketAddrV4::new(*third_address.ip(), third_address.port()));
    assert_eq!(query.owner_error(), Some(crate::resource::ResourceError::TransactionSpaceExhausted));

    actor.retire_owned_operation_errors();
    assert_eq!(actor.owned_error(), Some(crate::resource::ResourceError::TransactionSpaceExhausted));
    assert!(!actor.core.iterative_queries.contains_key(&legacy_target));
    assert!(!actor.core.put_queries.contains_key(&legacy_target));
    assert_eq!(actor.socket.owned_deadline(legacy_operation), None);
    assert_eq!(actor.socket.owned_put_deadline_for_test(legacy_target), None);
    assert!(matches!(cleanup_rx.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
    assert_eq!(actor.owned_resources.as_ref().unwrap().operations.get(&target), Some(&held_operation));
    assert!(actor.socket.owned_put_deadline_for_test(target).is_some());
    observer.wait_cleanup_held().await;

    hold.release();
    actor.tick_owned();
    assert!(matches!(charged.await, Ok(Err(OwnedPutError::Resource(crate::resource::ResourceError::TransactionSpaceExhausted)))));
    assert_eq!(cleanup_rx.try_recv(), Ok(()));
    assert!(actor.socket.owned_put_deadline_for_test(target).is_none());
    assert!(!actor.owned_resources.as_ref().unwrap().operations.contains_key(&target));
    assert!(actor.socket.owned_deadline(held_operation).is_none());
    let _ = (a_peer, legacy_peer, third_peer);
}
