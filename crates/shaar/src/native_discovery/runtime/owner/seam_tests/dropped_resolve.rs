// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::{WALL, record, resolve, setup};
use iroh_base::EndpointId;
use n0_mainline::MutableItem;
use std::time::Duration;
use tokio::time::Instant;

#[tokio::test]
async fn a_dropped_unpolled_resolve_future_changes_no_state() {
    let (mut peer, mut owner, _clock) = setup(0x7f).await;
    let item_x = record(0x80, WALL);
    let key_x = EndpointId::from_bytes(item_x.key()).expect("record key");
    let target_x = MutableItem::target_from_key(item_x.key(), None);

    // Constructed and dropped without ever being polled: no sample, no GET,
    // no delivery-budget charge, no cache entry.
    let future = owner.resolve_until(key_x, Instant::now() + Duration::from_secs(10));
    drop(future);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), peer.capture_get(target_x))
            .await
            .is_err(),
        "an unpolled resolve future must not issue a GET",
    );

    // No cache entry and the owner stays usable: the next resolve performs a
    // real GET and succeeds.
    let first = resolve(&mut owner, &mut peer, &item_x)
        .await
        .expect("owner remains usable after the dropped future");
    assert_eq!(first.addresses().len(), 1);
    drop(first);

    // No delivery-budget charge: seven held results leave the eighth distinct
    // key fully servable. A charged dropped future would have exhausted the
    // eight-permit delivery budget and rejected this resolve at delivery.
    let mut held = Vec::new();
    for seed in 0x81..0x88 {
        let item = record(seed, WALL);
        held.push(
            resolve(&mut owner, &mut peer, &item)
                .await
                .expect("charged result"),
        );
    }
    let eighth = record(0x88, WALL);
    let served = resolve(&mut owner, &mut peer, &eighth)
        .await
        .expect("the dropped future charged no delivery budget");
    assert_eq!(served.addresses().len(), 1);
    drop(served);

    // The budget recovers for the ninth key once one result is released.
    drop(held.pop());
    let ninth = record(0x89, WALL);
    let released = resolve(&mut owner, &mut peer, &ninth)
        .await
        .expect("the released budget serves the ninth key");
    assert_eq!(released.addresses().len(), 1);
    drop(released);
    drop(held);
    owner
        .close()
        .await
        .expect("actual joins with the budget released");
}
