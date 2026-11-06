// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Retained-state contracts: native retries behind a usable Ygg route, budget
//! exhaustion, the retained fallback pause, total outage, signal-only owners,
//! simultaneous evidence, cancellation of dials and of close, and lease
//! coexistence. Offsets follow `config()`: grace 20, attempt timeout 30, backoff 5
//! doubling to the cap 20, hold 50, three attempts (`roomy()` allows twenty). The
//! delay before attempt n is 0, 5, 10, 20, 20, so failing attempts start at
//! 0, 5, 15, 35, 55.

use std::sync::Arc;

use tokio::time::Instant;

use super::fakes::{
    Dial, Events, FakeDial, cancelled_after, completed, config, kind, log, ms, rig, rig_with,
    roomy, within, ygg_lease,
};
use crate::path::{DialError, Mode, PathKind, StandbyError};

#[tokio::test(start_paused = true)]
async fn native_retries_follow_the_policy_schedule_behind_a_usable_yggdrasil_route() {
    let mut rig = rig(&[], &[Dial::Up(None)], Mode::Standby, roomy());
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Yggdrasil));
    assert_eq!(ms(rig.start), 0);
    assert_eq!(rig.native_dials(), [(0, 30)]);

    // Each wake starts exactly one attempt; the calls in between start none, and the
    // cancelled calls never recreate an attempt or the hot standby.
    let schedule = [(0, 30), (5, 35), (15, 45), (35, 65), (55, 85)];
    let steps = [
        (3, 1),
        (4, 2),
        (4, 2),
        (6, 3),
        (10, 3),
        (10, 4),
        (10, 4),
        (10, 5),
    ];
    for (millis, count) in steps {
        assert!(cancelled_after(millis, rig.owner.follow()).await);
        assert_eq!(
            rig.native_dials(),
            &schedule[..count],
            "at {}",
            ms(rig.start)
        );
    }
    assert_eq!(ms(rig.start), 57);
    assert_eq!(rig.fallback_dials(), [(0, 30)]);
    assert_eq!(log(&rig.native).dropped_mid_dial, 0);
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Yggdrasil));
    assert!(!rig.owner.native_exhausted());
}

#[tokio::test(start_paused = true)]
async fn an_exhausted_native_budget_leaves_a_usable_yggdrasil_route_in_place() {
    let mut rig = rig(
        &[Dial::Fail, Dial::Fail, Dial::Fail, Dial::Up(None)],
        &[Dial::Up(None)],
        Mode::Standby,
        config(),
    );
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Yggdrasil));

    // Attempts at 0, 5 and 15; the budget is then spent and nothing is ever reported.
    assert!(cancelled_after(200, rig.owner.follow()).await);
    assert_eq!(ms(rig.start), 200);
    assert!(rig.owner.native_exhausted());
    assert_eq!(rig.owner.active(), Some(PathKind::Yggdrasil));
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Yggdrasil));
    assert_eq!(rig.native_dials(), [(0, 30), (5, 35), (15, 45)]);

    assert!(cancelled_after(100, rig.owner.follow()).await);
    assert_eq!(rig.native_dials().len(), 3, "no attempt after the budget");
    assert!(rig.owner.native_exhausted());
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Yggdrasil));
}

#[tokio::test(start_paused = true)]
async fn the_fallback_retry_pause_survives_cancelled_follow_calls() {
    let fallback = [
        Dial::Up(Some(40)),
        Dial::Fail,
        Dial::Fail,
        Dial::Fail,
        Dial::Up(None),
    ];
    let mut rig = rig(&[], &fallback, Mode::Standby, config());
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Yggdrasil));

    // The native budget is spent at 15; the Ygg link is lost at 40, so there is no
    // route at all, and the retained pause runs from 40 to 60.
    assert!(cancelled_after(50, rig.owner.follow()).await);
    assert!(rig.owner.native_exhausted());
    assert_eq!(rig.owner.active(), None);
    assert_eq!(kind(rig.owner.route()), None);
    assert_eq!(rig.native_dials().len(), 3);
    assert_eq!(rig.fallback_dials(), [(0, 30)]);
    assert_eq!(log(&rig.fallback).links_dropped, 1);

    // Regression: a fresh call used to dial at once. Short calls inside the pause
    // dial nothing.
    assert!(cancelled_after(5, rig.owner.follow()).await);
    assert!(cancelled_after(3, rig.owner.follow()).await);
    assert_eq!(ms(rig.start), 58);
    assert_eq!(rig.fallback_dials(), [(0, 30)]);

    let outage = Some(Err(StandbyError::Unavailable));
    assert_eq!(within(10, rig.owner.follow()).await, outage);
    assert_eq!(ms(rig.start), 60);
    assert_eq!(rig.fallback_dials(), [(0, 30), (60, 90)]);

    assert!(cancelled_after(7, rig.owner.follow()).await);
    assert_eq!(rig.fallback_dials().len(), 2, "pause until 80 holds");
    assert_eq!(within(20, rig.owner.follow()).await, outage);
    assert_eq!(ms(rig.start), 80);

    assert!(cancelled_after(5, rig.owner.follow()).await);
    assert_eq!(within(20, rig.owner.follow()).await, outage);
    assert_eq!(ms(rig.start), 100);

    assert_eq!(rig.owner.follow().await, Ok(PathKind::Yggdrasil));
    assert_eq!(ms(rig.start), 120);
    let spaced = [(0, 30), (60, 90), (80, 110), (100, 130), (120, 150)];
    assert_eq!(rig.fallback_dials(), spaced);
    assert_eq!(rig.native_dials().len(), 3);
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Yggdrasil));
}

#[tokio::test(start_paused = true)]
async fn a_total_outage_is_unavailable_and_a_recovering_fallback_ends_it() {
    // A signal-only owner with the same spent budget reports a different error.
    let mut signal = rig(&[], &[Dial::Up(None)], Mode::Signal, config());
    assert_eq!(signal.owner.follow().await, Err(StandbyError::Exhausted));
    assert_eq!(ms(signal.start), 15);
    assert!(signal.fallback_dials().is_empty());

    let mut rig = rig(
        &[],
        &[Dial::Fail, Dial::Fail, Dial::Up(None)],
        Mode::Standby,
        config(),
    );

    // One failed fallback attempt per call, then the pause bounds the next call.
    assert_eq!(rig.owner.follow().await, Err(StandbyError::Unavailable));
    assert_eq!(ms(rig.start), 15, "native budget spent at 15");
    assert_eq!(rig.native_dials(), [(0, 30), (5, 35), (15, 45)]);
    assert_eq!(rig.fallback_dials(), [(0, 30)]);
    assert!(rig.owner.native_exhausted());

    assert_eq!(rig.owner.follow().await, Err(StandbyError::Unavailable));
    assert_eq!(ms(rig.start), 20);
    assert_eq!(rig.fallback_dials(), [(0, 30), (20, 50)]);

    assert_eq!(rig.owner.follow().await, Ok(PathKind::Yggdrasil));
    assert_eq!(ms(rig.start), 40);
    assert_eq!(rig.fallback_dials(), [(0, 30), (20, 50), (40, 70)]);
    assert_eq!(rig.native_dials().len(), 3);
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Yggdrasil));
    assert!(rig.owner.native_exhausted(), "only a native link clears it");
}

#[tokio::test(start_paused = true)]
async fn signal_mode_never_dials_or_routes_the_fallback() {
    let mut never_up = rig(&[], &[Dial::Up(None)], Mode::Signal, config());
    assert_eq!(never_up.owner.follow().await, Err(StandbyError::Exhausted));
    assert_eq!(ms(never_up.start), 15);
    assert!(never_up.owner.native_exhausted());
    assert_eq!(never_up.owner.active(), None);
    assert_eq!(kind(never_up.owner.route()), None);
    assert!(never_up.fallback_dials().is_empty());

    // Native up, then lost at 10 with attempts at 15 and 25 failing: the spent budget
    // is reported while the grace has not ended, and Ygg is still not an option.
    let mut lost = rig(
        &[Dial::Up(Some(10))],
        &[Dial::Up(None)],
        Mode::Signal,
        config(),
    );
    assert_eq!(lost.owner.follow().await, Ok(PathKind::Native));
    assert_eq!(lost.owner.follow().await, Err(StandbyError::Exhausted));
    assert_eq!(ms(lost.start), 25);
    assert_eq!(lost.native_dials(), [(0, 30), (15, 45), (25, 55)]);
    assert_eq!(lost.owner.active(), Some(PathKind::Native));
    assert_eq!(kind(lost.owner.route()), None);
    assert_eq!(lost.owner.follow().await, Err(StandbyError::Exhausted));
    assert!(lost.fallback_dials().is_empty());
    assert!(log(&lost.fallback).completed.is_empty());
    assert_eq!(log(&lost.fallback).links_dropped, 0);
}

#[tokio::test(start_paused = true)]
async fn simultaneous_native_loss_and_fallback_readiness_resolve_by_evidence() {
    let late_native = Dial::Slow {
        ready_at_ms: 60,
        loss: None,
    };
    let mut rig = rig(
        &[Dial::Up(Some(25)), Dial::Fail, late_native],
        &[Dial::Slow {
            ready_at_ms: 25,
            loss: None,
        }],
        Mode::Standby,
        roomy(),
    );
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Native));
    assert!(cancelled_after(24, rig.owner.follow()).await);
    assert_eq!(rig.fallback_dials(), [(0, 30)]);
    assert!(completed(&rig.fallback).is_empty());

    // Both facts arrive at 25. The loss opens the grace (to 45) and the readiness is
    // recorded; there is no gap in which payload has no designated path.
    assert!(cancelled_after(2, rig.owner.follow()).await);
    assert_eq!(completed(&rig.fallback), [(25, true)]);
    assert_eq!(rig.owner.active(), Some(PathKind::Native));
    assert_eq!(kind(rig.owner.route()), None, "the native link is gone");

    assert_eq!(rig.owner.follow().await, Ok(PathKind::Yggdrasil));
    assert_eq!(
        ms(rig.start),
        45,
        "failover exactly at the end of the grace"
    );
    assert_eq!(rig.native_dials(), [(0, 30), (30, 60), (40, 70)]);
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Yggdrasil));

    // The pending native dial connects at 60: a late fact that restarts the hold
    // from 60 but does not undo the failover.
    assert!(cancelled_after(30, rig.owner.follow()).await);
    assert_eq!(completed(&rig.native).last(), Some(&(60, true)));
    assert_eq!(rig.owner.active(), Some(PathKind::Yggdrasil));
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Yggdrasil));
    assert_eq!(rig.native_dials().len(), 3);

    assert_eq!(rig.owner.follow().await, Ok(PathKind::Native));
    assert_eq!(ms(rig.start), 110, "connected at 60 plus the hold of 50");
}

#[tokio::test(start_paused = true)]
async fn a_cancelled_follow_keeps_a_pending_native_dial_and_its_result() {
    let slow = Dial::Slow {
        ready_at_ms: 20,
        loss: None,
    };
    let mut rig = rig(&[slow], &[Dial::Up(None)], Mode::Signal, config());

    assert!(cancelled_after(10, rig.owner.follow()).await);
    assert!(cancelled_after(5, rig.owner.follow()).await);
    assert_eq!(ms(rig.start), 15);
    assert_eq!(rig.native_dials(), [(0, 30)]);
    assert_eq!(log(&rig.native).dropped_mid_dial, 0);
    assert!(completed(&rig.native).is_empty());

    assert_eq!(rig.owner.follow().await, Ok(PathKind::Native));
    assert_eq!(ms(rig.start), 20);
    assert_eq!(completed(&rig.native), [(20, true)]);
    assert_eq!(rig.native_dials(), [(0, 30)]);
    assert_eq!(log(&rig.native).dropped_mid_dial, 0);
}

#[tokio::test(start_paused = true)]
async fn a_native_dial_is_abandoned_only_when_its_own_deadline_passes() {
    let mut rig = rig(
        &[Dial::Hang, Dial::Up(None)],
        &[Dial::Up(None)],
        Mode::Signal,
        config(),
    );
    assert!(cancelled_after(10, rig.owner.follow()).await);
    assert!(cancelled_after(10, rig.owner.follow()).await);
    assert_eq!(ms(rig.start), 20);
    assert_eq!(log(&rig.native).dropped_mid_dial, 0);
    assert_eq!(rig.native_dials(), [(0, 30)]);

    // The deadline 30 ends the hung dial; the retry follows after the backoff of 5.
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Native));
    assert_eq!(ms(rig.start), 35);
    assert_eq!(log(&rig.native).dropped_mid_dial, 1);
    assert_eq!(rig.native_dials(), [(0, 30), (35, 65)]);
    assert_eq!(completed(&rig.native), [(35, true)]);
}

#[tokio::test(start_paused = true)]
async fn a_cancelled_follow_keeps_a_pending_fallback_dial_and_its_result() {
    let slow = Dial::Slow {
        ready_at_ms: 20,
        loss: None,
    };
    let mut rig = rig(&[Dial::Up(None)], &[slow], Mode::Standby, config());
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Native));

    assert!(cancelled_after(10, rig.owner.follow()).await);
    assert!(cancelled_after(5, rig.owner.follow()).await);
    assert_eq!(ms(rig.start), 15);
    assert_eq!(rig.fallback_dials(), [(0, 30)]);
    assert_eq!(log(&rig.fallback).dropped_mid_dial, 0);
    assert!(completed(&rig.fallback).is_empty());

    assert!(cancelled_after(10, rig.owner.follow()).await);
    assert_eq!(completed(&rig.fallback), [(20, true)]);
    assert_eq!(rig.fallback_dials(), [(0, 30)]);
    assert_eq!(log(&rig.fallback).dropped_mid_dial, 0);
    assert_eq!(log(&rig.fallback).links_dropped, 0);
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Native));
}

#[tokio::test(start_paused = true)]
async fn a_fallback_dial_is_abandoned_only_at_its_deadline_and_retried_after_the_pause() {
    let mut rig = rig(
        &[Dial::Up(None)],
        &[Dial::Hang, Dial::Up(None)],
        Mode::Standby,
        config(),
    );
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Native));
    assert!(cancelled_after(10, rig.owner.follow()).await);
    assert!(cancelled_after(10, rig.owner.follow()).await);
    assert_eq!(log(&rig.fallback).dropped_mid_dial, 0);

    // Deadline 30 ends the dial; the pause then runs to 50.
    assert!(cancelled_after(15, rig.owner.follow()).await);
    assert_eq!(ms(rig.start), 35);
    assert_eq!(log(&rig.fallback).dropped_mid_dial, 1);
    assert_eq!(rig.fallback_dials(), [(0, 30)]);

    assert!(cancelled_after(20, rig.owner.follow()).await);
    assert_eq!(rig.fallback_dials(), [(0, 30), (50, 80)]);
    assert_eq!(completed(&rig.fallback), [(50, true)]);
    assert_eq!(log(&rig.fallback).dropped_mid_dial, 1);
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Native));
}

#[tokio::test(start_paused = true)]
async fn close_cancels_and_joins_a_pending_dial() {
    let mut rig = rig(&[Dial::Hang], &[Dial::Up(None)], Mode::Signal, config());
    assert!(cancelled_after(10, rig.owner.follow()).await);
    assert_eq!(log(&rig.native).dropped_mid_dial, 0);

    // Close is the one place a pending dial is abandoned before its deadline.
    assert_eq!(rig.owner.close().await, Ok(()));
    assert_eq!(ms(rig.start), 10);
    assert_eq!(log(&rig.native).dropped_mid_dial, 1);
    assert!(completed(&rig.native).is_empty());
    assert_eq!(rig.closes(), ["native closed", "fallback closed"]);
    assert_eq!(rig.owner.follow().await, Err(StandbyError::Closed));
    assert_eq!(rig.native_dials(), [(0, 30)]);
}

#[tokio::test(start_paused = true)]
async fn a_cancelled_close_resumes_and_closes_each_dialer_exactly_once_in_order() {
    let events = Events::default();
    let start = Instant::now();
    let native = FakeDial::new("native closed", &[Dial::Up(None)], &events, start);
    let fallback = FakeDial::new("fallback closed", &[Dial::Up(None)], &events, start);
    let mut rig = rig_with(
        (native.0.slow_close(40), native.1),
        (fallback.0.slow_close(60), fallback.1),
        events,
        Mode::Standby,
        config(),
    );
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Native));

    assert!(cancelled_after(10, rig.owner.close()).await);
    assert!(rig.closes().is_empty());
    assert!(cancelled_after(40, rig.owner.close()).await);
    assert_eq!(ms(rig.start), 50);
    assert_eq!(rig.closes(), ["native closed"]);
    assert_eq!(log(&rig.fallback).closed, 0);

    assert_eq!(rig.owner.close().await, Ok(()));
    assert_eq!(ms(rig.start), 60);
    assert_eq!(rig.closes(), ["native closed", "fallback closed"]);
    assert_eq!(log(&rig.native).closed, 1);
    assert_eq!(log(&rig.fallback).closed, 1);

    assert_eq!(rig.owner.close().await, Ok(()));
    assert_eq!(ms(rig.start), 60);
    assert_eq!(rig.closes(), ["native closed", "fallback closed"]);
    assert_eq!(rig.owner.follow().await, Err(StandbyError::Closed));
}

#[tokio::test(start_paused = true)]
async fn a_failing_fallback_close_still_closes_native_and_a_retry_completes() {
    let events = Events::default();
    let start = Instant::now();
    let native = FakeDial::new("native closed", &[Dial::Up(None)], &events, start);
    let fallback = FakeDial::new("fallback closed", &[Dial::Up(None)], &events, start);
    let mut rig = rig_with(
        native,
        (fallback.0.failing_close(1), fallback.1),
        events,
        Mode::Standby,
        config(),
    );
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Native));

    assert_eq!(rig.owner.close().await, Err(DialError));
    assert_eq!(rig.closes(), ["native closed"]);
    assert_eq!(log(&rig.fallback).closed, 0);

    assert_eq!(rig.owner.close().await, Ok(()));
    assert_eq!(rig.closes(), ["native closed", "fallback closed"]);
    assert_eq!(log(&rig.native).closed, 1, "native is not closed twice");
    assert_eq!(log(&rig.fallback).closed, 1);

    assert_eq!(rig.owner.close().await, Ok(()));
    assert_eq!(rig.closes(), ["native closed", "fallback closed"]);
}

#[tokio::test(start_paused = true)]
async fn a_held_lease_neither_blocks_follow_nor_closes_its_link_early() {
    let mut rig = rig(
        &[Dial::Up(Some(10)), Dial::Fail, Dial::Fail, Dial::Up(None)],
        &[Dial::Up(None)],
        Mode::Standby,
        roomy(),
    );
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Native));
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Yggdrasil));
    assert_eq!(ms(rig.start), 30);
    let lease = ygg_lease(rig.owner.route());

    // Native reconnects at 45 and returns after the hold at 95, lease still held.
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Native));
    assert_eq!(ms(rig.start), 95);
    assert_eq!(rig.owner.active(), Some(PathKind::Native));
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Native));
    assert_eq!(log(&rig.fallback).links_dropped, 0);
    assert_eq!(rig.fallback_dials(), [(0, 30)]);

    // Close joins every task although a consumer still holds the lease; the owner
    // has released its own handle, so the consumer's is the last one.
    assert_eq!(rig.owner.close().await, Ok(()));
    assert_eq!(rig.closes(), ["native closed", "fallback closed"]);
    assert_eq!(Arc::strong_count(&lease), 1);
    assert_eq!(log(&rig.fallback).links_dropped, 0);
    drop(rig.owner);
    assert_eq!(log(&rig.fallback).links_dropped, 0);

    drop(lease);
    assert_eq!(log(&rig.fallback).links_dropped, 1);
}
