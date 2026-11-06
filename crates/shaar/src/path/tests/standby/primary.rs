// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Primary standby contracts: hot standby, failover after the loss grace, recovery
//! inside the grace, return to native after the hold, a native dial that survives a
//! route announcement, and a closed owner. Offsets follow `PolicyConfig` of
//! `config()`: grace 20, attempt timeout 30, backoff 5 doubling to 20, hold 50.

use std::sync::Arc;

use super::fakes::{
    Dial, cancelled_after, completed, config, dials, kind, log, ms, native_lease, rig, roomy,
};
use crate::path::{Mode, PathKind, StandbyError};

#[tokio::test(start_paused = true)]
async fn the_first_follow_returns_native_and_the_fallback_connects_silently() {
    let mut rig = rig(
        &[Dial::Up(None)],
        &[Dial::Up(None)],
        Mode::Standby,
        config(),
    );

    assert_eq!(rig.owner.follow().await, Ok(PathKind::Native));
    assert_eq!(ms(rig.start), 0);
    assert_eq!(rig.native_dials(), [(0, 30)]);
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Native));

    // The held standby is not a new route: the next call waits. Its dial is only
    // polled by `follow`, so it is logged during this call, at offset zero.
    assert!(cancelled_after(100, rig.owner.follow()).await);
    assert_eq!(ms(rig.start), 100);
    assert_eq!(rig.native_dials(), [(0, 30)], "no new native dial");
    assert_eq!(rig.fallback_dials(), [(0, 30)], "hot standby dialed once");
    assert_eq!(
        log(&rig.fallback).links_dropped,
        0,
        "the standby stays held"
    );
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Native));
}

#[tokio::test(start_paused = true)]
async fn failover_comes_one_loss_grace_after_the_loss_and_the_lease_pins_the_link() {
    let mut rig = rig(
        &[Dial::Up(Some(10)), Dial::Fail, Dial::Fail],
        &[Dial::Up(None)],
        Mode::Standby,
        roomy(),
    );
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Native));
    let lease = native_lease(rig.owner.route());

    // Lost at 10, so the grace ends at 30; retries start at 15 and 25 and fail at once.
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Yggdrasil));
    assert_eq!(ms(rig.start), 30);
    assert_eq!(rig.native_dials(), [(0, 30), (15, 45), (25, 55)]);
    assert_eq!(rig.owner.active(), Some(PathKind::Yggdrasil));
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Yggdrasil));

    // The owner released its handle at the loss; the consumer's lease keeps the link.
    assert_eq!(log(&rig.native).links_dropped, 0);
    drop(lease);
    assert_eq!(log(&rig.native).links_dropped, 1);
    assert_eq!(log(&rig.fallback).links_dropped, 0);
}

#[tokio::test(start_paused = true)]
async fn recovery_inside_the_grace_returns_native_with_a_new_generation() {
    let mut rig = rig(
        &[Dial::Up(Some(10)), Dial::Up(None)],
        &[Dial::Up(None)],
        Mode::Standby,
        roomy(),
    );
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Native));
    let first = native_lease(rig.owner.route());

    // Lost at 10, redialed at 15 (backoff 5), well inside the grace that ends at 30.
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Native));
    assert_eq!(ms(rig.start), 15);
    assert_eq!(rig.owner.active(), Some(PathKind::Native));
    let second = native_lease(rig.owner.route());
    assert!(
        !Arc::ptr_eq(&first, &second),
        "a new link, a new generation"
    );
    assert_eq!(
        log(&rig.native).links_dropped,
        0,
        "the old lease pins its link"
    );
    drop(first);
    assert_eq!(log(&rig.native).links_dropped, 1);

    // Past the old grace end and the hold, Yggdrasil is never exposed.
    assert!(cancelled_after(100, rig.owner.follow()).await);
    assert_eq!(rig.owner.active(), Some(PathKind::Native));
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Native));
    assert_eq!(rig.native_dials(), [(0, 30), (15, 45)]);
    assert!(!rig.owner.native_exhausted());
}

#[tokio::test(start_paused = true)]
async fn native_returns_only_after_the_stable_hold_and_a_cancelled_follow_dials_nothing() {
    let mut rig = rig(
        &[Dial::Up(Some(10)), Dial::Fail, Dial::Fail, Dial::Up(None)],
        &[Dial::Up(None)],
        Mode::Standby,
        roomy(),
    );
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Native));
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Yggdrasil));
    assert_eq!(ms(rig.start), 30);

    // Attempts at 15 and 25 failed; the fourth starts at 45 (backoff capped at 20),
    // connects at once, and the hold then ends at 95.
    assert!(cancelled_after(60, rig.owner.follow()).await);
    assert_eq!(ms(rig.start), 90);
    let expected = [(0, 30), (15, 45), (25, 55), (45, 75)];
    assert_eq!(rig.native_dials(), expected);
    assert_eq!(completed(&rig.native).last(), Some(&(45, true)));
    assert_eq!(rig.owner.active(), Some(PathKind::Yggdrasil));
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Yggdrasil));

    // One millisecond short of the hold nothing has changed either.
    assert!(cancelled_after(4, rig.owner.follow()).await);
    assert_eq!(ms(rig.start), 94);
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Yggdrasil));

    assert_eq!(rig.owner.follow().await, Ok(PathKind::Native));
    assert_eq!(ms(rig.start), 95);
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Native));
    assert_eq!(rig.native_dials(), expected, "no duplicate native dial");
}

#[tokio::test(start_paused = true)]
async fn a_pending_native_dial_survives_the_route_announcement_and_ends_at_its_deadline() {
    let slow = Dial::Slow {
        ready_at_ms: 40,
        loss: None,
    };
    let mut rig = rig(
        &[Dial::Up(Some(10)), slow],
        &[Dial::Up(None)],
        Mode::Standby,
        roomy(),
    );
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Native));

    // Lost at 10; the retry starts at 15 with deadline 45 and is still pending when
    // the grace ends at 30 and failover is announced.
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Yggdrasil));
    assert_eq!(ms(rig.start), 30);
    assert_eq!(rig.native_dials(), [(0, 30), (15, 45)]);
    assert_eq!(log(&rig.native).dropped_mid_dial, 0);

    // The next call neither restarts nor drops it.
    assert!(cancelled_after(5, rig.owner.follow()).await);
    assert_eq!(ms(rig.start), 35);
    assert_eq!(rig.native_dials(), [(0, 30), (15, 45)]);
    assert_eq!(log(&rig.native).dropped_mid_dial, 0);
    assert_eq!(completed(&rig.native), [(0, true)]);

    // It completes at 40, before its original deadline 45, and starts the hold.
    assert!(cancelled_after(10, rig.owner.follow()).await);
    assert_eq!(ms(rig.start), 45);
    assert_eq!(completed(&rig.native), [(0, true), (40, true)]);
    assert_eq!(dials(&rig.native), [(0, 30), (15, 45)], "no extra dial");
    assert_eq!(log(&rig.native).dropped_mid_dial, 0);
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Yggdrasil));

    assert_eq!(rig.owner.follow().await, Ok(PathKind::Native));
    assert_eq!(ms(rig.start), 90, "completion at 40 plus the hold of 50");
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Native));
    assert_eq!(rig.native_dials(), [(0, 30), (15, 45)]);
}

#[tokio::test(start_paused = true)]
async fn a_closed_owner_dials_nothing_and_follow_reports_closed() {
    let mut rig = rig(
        &[Dial::Up(None)],
        &[Dial::Up(None)],
        Mode::Standby,
        config(),
    );

    assert_eq!(rig.owner.close().await, Ok(()));
    assert_eq!(rig.owner.follow().await, Err(StandbyError::Closed));
    assert_eq!(rig.owner.follow().await, Err(StandbyError::Closed));

    assert!(rig.native_dials().is_empty());
    assert!(rig.fallback_dials().is_empty());
    assert_eq!(rig.closes(), ["native closed", "fallback closed"]);
    assert_eq!(rig.owner.active(), None);
}
