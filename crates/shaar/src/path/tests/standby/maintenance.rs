// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deterministic native-maintenance controls for the retained standby owner.

use super::super::{Decision, Event, PathPolicy};
use super::fakes::{Dial, cancelled_after, config, kind, ms, rig};
use crate::path::{Mode, NativeObservation, PathKind, PolicyConfig, StandbyError};

#[tokio::test(start_paused = true)]
async fn capped_maintenance_preserves_budget_and_ygg_route() {
    let mut rig = rig(&[Dial::Fail; 6], &[Dial::Up(None)], Mode::Standby, config());
    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = std::sync::Arc::clone(&events);
    rig.owner.set_observer(move |event| {
        let mut events = observed.lock().expect("events");
        if events.len() < 32 {
            events.push(event);
        }
    });
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Yggdrasil));

    assert!(cancelled_after(80, rig.owner.follow()).await);
    assert_eq!(ms(rig.start), 80);
    assert!(rig.owner.native_exhausted());
    assert_eq!(rig.owner.attempts_used(), 3);
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Yggdrasil));
    assert_eq!(
        rig.native_dials(),
        [(0, 30), (5, 35), (15, 45), (35, 65), (55, 85), (75, 105)]
    );
    let starts: Vec<_> = events
        .lock()
        .expect("events")
        .iter()
        .filter_map(|event| match event {
            NativeObservation::AttemptStarted {
                attempt,
                at,
                deadline,
            } => Some((*attempt, *at, *deadline)),
            _ => None,
        })
        .collect();
    assert_eq!(
        starts,
        [
            (1, 0, 30),
            (2, 5, 35),
            (3, 15, 45),
            (4, 35, 65),
            (5, 55, 85),
            (6, 75, 105)
        ]
    );
    assert!(
        events
            .lock()
            .expect("events")
            .contains(&NativeObservation::Exhausted { at: 15 })
    );

    assert!(cancelled_after(40, rig.owner.follow()).await);
    assert_eq!(ms(rig.start), 120);
    assert_eq!(rig.native_dials().last(), Some(&(115, 145)));
    assert_eq!(rig.native_dials().len(), 8);
    assert!(rig.owner.native_exhausted());
    assert_eq!(rig.owner.attempts_used(), 3);
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Yggdrasil));
}

#[test]
fn maintenance_cooldown_is_completion_based_and_late_poll_starts_one_probe() {
    let config = PolicyConfig {
        max_attempts: 2,
        ..config()
    };
    let mut policy = PathPolicy::new(Mode::Standby, config, 0).expect("valid policy");
    assert_eq!(
        policy.step(0, Event::YggdrasilReady { generation: 1 }),
        Decision::Use(PathKind::Yggdrasil)
    );
    assert_eq!(
        policy.step(0, Event::Tick),
        Decision::AttemptNative {
            attempt: 1,
            deadline: 30
        }
    );
    assert_eq!(
        policy.step(1, Event::AttemptFailed { attempt: 1 }),
        Decision::Wait
    );
    assert_eq!(
        policy.step(6, Event::Tick),
        Decision::AttemptNative {
            attempt: 2,
            deadline: 36
        }
    );
    assert_eq!(
        policy.step(10, Event::AttemptFailed { attempt: 2 }),
        Decision::NativeExhausted
    );
    assert_eq!(policy.attempts_used(), 2);
    assert_eq!(policy.cooldown_deadline(), Some(30));
    assert_eq!(policy.step(29, Event::Tick), Decision::Wait);
    assert_eq!(
        policy.step(30, Event::Tick),
        Decision::AttemptNative {
            attempt: 3,
            deadline: 60
        }
    );
    assert_eq!(
        policy.step(31, Event::AttemptFailed { attempt: 2 }),
        Decision::Wait
    );
    assert_eq!(policy.next_wakeup(), Some(60));
    assert!(policy.accepts_attempt(3, 31));
    assert_eq!(
        policy.step(37, Event::AttemptFailed { attempt: 3 }),
        Decision::Wait
    );
    assert_eq!(policy.cooldown_deadline(), Some(57));
    assert_eq!(
        policy.step(100, Event::Tick),
        Decision::AttemptNative {
            attempt: 4,
            deadline: 130
        }
    );
    assert_eq!(policy.step(100, Event::Tick), Decision::Wait);
    assert_eq!(policy.next_wakeup(), Some(130));
    assert!(policy.budget_spent());
}

#[test]
fn attempt_admission_rejects_stale_wrong_expired_and_shutdown_results() {
    let mut policy = PathPolicy::new(Mode::Standby, config(), 0).expect("valid policy");
    assert_eq!(
        policy.step(0, Event::Tick),
        Decision::AttemptNative {
            attempt: 1,
            deadline: 30
        }
    );
    assert!(policy.accepts_attempt(1, 29));
    assert!(!policy.accepts_attempt(2, 29));
    assert!(!policy.accepts_attempt(1, 30));
    assert!(!policy.accepts_attempt(1, 31));
    assert_eq!(policy.step(30, Event::Tick), Decision::Wait);
    assert_eq!(
        policy.step(35, Event::Tick),
        Decision::AttemptNative {
            attempt: 2,
            deadline: 65
        }
    );
    assert!(!policy.accepts_attempt(1, 35));
    policy.step(35, Event::Shutdown);
    assert!(!policy.accepts_attempt(2, 36));
}

#[test]
fn backward_observation_time_is_clamped_before_updating_link_evidence() {
    let mut policy = PathPolicy::new(Mode::Standby, config(), 0).expect("valid policy");
    assert_eq!(
        policy.step(10, Event::YggdrasilReady { generation: 1 }),
        Decision::Use(PathKind::Yggdrasil)
    );
    assert_eq!(
        policy.step(15, Event::NativeUp { generation: 1 }),
        Decision::Wait
    );
    assert_eq!(policy.next_wakeup(), Some(65));
    assert_eq!(
        policy.step(5, Event::NativeUp { generation: 2 }),
        Decision::Wait
    );
    assert_eq!(policy.next_wakeup(), Some(65));
}

#[test]
fn ygg_down_cancels_maintenance_until_restored_and_keeps_failure_deadline() {
    let config = PolicyConfig {
        max_attempts: 1,
        ..config()
    };
    let mut policy = PathPolicy::new(Mode::Standby, config, 0).expect("valid policy");
    assert_eq!(
        policy.step(0, Event::YggdrasilReady { generation: 1 }),
        Decision::Use(PathKind::Yggdrasil)
    );
    assert_eq!(
        policy.step(0, Event::Tick),
        Decision::AttemptNative {
            attempt: 1,
            deadline: 30
        }
    );
    assert_eq!(
        policy.step(1, Event::AttemptFailed { attempt: 1 }),
        Decision::NativeExhausted
    );
    assert_eq!(policy.cooldown_deadline(), Some(21));
    assert_eq!(
        policy.step(10, Event::YggdrasilDown { generation: 2 }),
        Decision::NoPath
    );
    assert_eq!(policy.cooldown_deadline(), None);
    assert_eq!(
        policy.step(15, Event::YggdrasilReady { generation: 3 }),
        Decision::Use(PathKind::Yggdrasil)
    );
    assert_eq!(policy.cooldown_deadline(), Some(21));
    assert_eq!(policy.step(20, Event::Tick), Decision::Wait);
    assert_eq!(
        policy.step(21, Event::Tick),
        Decision::AttemptNative {
            attempt: 2,
            deadline: 51
        }
    );
}

#[tokio::test(start_paused = true)]
async fn original_attempt_deadline_and_cooldown_survive_cancelled_follow_reentry() {
    let mut rig = rig(
        &[Dial::Fail, Dial::Fail, Dial::Fail, Dial::Hang, Dial::Fail],
        &[Dial::Up(None)],
        Mode::Standby,
        config(),
    );
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Yggdrasil));
    assert!(cancelled_after(65, rig.owner.follow()).await);
    assert_eq!(ms(rig.start), 65);
    assert_eq!(rig.native_dials().last(), Some(&(35, 65)));
    assert_eq!(rig.native_dials().len(), 4);
    assert!(cancelled_after(19, rig.owner.follow()).await);
    assert_eq!(rig.native_dials().len(), 4);
    assert!(cancelled_after(1, rig.owner.follow()).await);
    assert_eq!(ms(rig.start), 85);
    assert_eq!(rig.native_dials().last(), Some(&(85, 115)));
    assert_eq!(rig.native_dials().len(), 5);
    assert!(rig.owner.native_exhausted());
}

#[tokio::test(start_paused = true)]
async fn unstable_success_keeps_ygg_and_budget_until_stable_hold_refills() {
    let mut rig = rig(
        &[
            Dial::Fail,
            Dial::Fail,
            Dial::Fail,
            Dial::Up(Some(40)),
            Dial::Fail,
            Dial::Up(None),
        ],
        &[Dial::Up(None)],
        Mode::Standby,
        config(),
    );
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Yggdrasil));
    assert!(cancelled_after(40, rig.owner.follow()).await);
    assert_eq!(ms(rig.start), 40);
    assert!(rig.owner.native_exhausted());
    assert_eq!(rig.owner.attempts_used(), 3);
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Yggdrasil));
    assert!(cancelled_after(20, rig.owner.follow()).await);
    assert_eq!(ms(rig.start), 60);
    assert_eq!(rig.native_dials().last(), Some(&(60, 90)));
    assert!(rig.owner.native_exhausted());
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Yggdrasil));
    assert!(cancelled_after(69, rig.owner.follow()).await);
    assert_eq!(ms(rig.start), 129);
    assert!(rig.owner.native_exhausted());
    assert_eq!(rig.owner.attempts_used(), 3);
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Yggdrasil));
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Native));
    assert_eq!(ms(rig.start), 130);
    assert!(!rig.owner.native_exhausted());
    assert_eq!(rig.owner.attempts_used(), 0);
}

#[tokio::test(start_paused = true)]
async fn stable_recovery_refills_a_later_down_episode_ordinary_budget() {
    let mut rig = rig(
        &[
            Dial::Fail,
            Dial::Fail,
            Dial::Fail,
            Dial::Up(Some(110)),
            Dial::Fail,
            Dial::Fail,
            Dial::Fail,
        ],
        &[Dial::Up(None)],
        Mode::Standby,
        config(),
    );
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Yggdrasil));
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Native));
    assert_eq!(ms(rig.start), 85);
    assert_eq!(rig.native_dials().len(), 4);
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Yggdrasil));
    assert_eq!(ms(rig.start), 130);
    assert_eq!(
        rig.native_dials(),
        [
            (0, 30),
            (5, 35),
            (15, 45),
            (35, 65),
            (110, 140),
            (115, 145),
            (125, 155)
        ]
    );
    assert!(rig.owner.native_exhausted());
    assert_eq!(rig.owner.attempts_used(), 3);
    assert_eq!(kind(rig.owner.route()), Some(PathKind::Yggdrasil));
}

#[tokio::test(start_paused = true)]
async fn signal_and_unusable_fallback_keep_finite_typed_exhaustion() {
    let mut signal = rig(&[], &[], Mode::Signal, config());
    assert_eq!(signal.owner.follow().await, Err(StandbyError::Exhausted));
    assert_eq!(signal.native_dials(), [(0, 30), (5, 35), (15, 45)]);
    let mut outage = rig(
        &[Dial::Fail, Dial::Fail, Dial::Fail],
        &[Dial::Fail],
        Mode::Standby,
        config(),
    );
    assert_eq!(outage.owner.follow().await, Err(StandbyError::Unavailable));
    assert_eq!(outage.native_dials(), [(0, 30), (5, 35), (15, 45)]);
    assert_eq!(outage.owner.follow().await, Err(StandbyError::Unavailable));
    assert_eq!(outage.native_dials().len(), 3);
}

#[tokio::test(start_paused = true)]
async fn shutdown_joins_active_maintenance_and_stops_scheduling() {
    let mut rig = rig(
        &[Dial::Fail, Dial::Fail, Dial::Fail, Dial::Hang],
        &[Dial::Up(None)],
        Mode::Standby,
        config(),
    );
    assert_eq!(rig.owner.follow().await, Ok(PathKind::Yggdrasil));
    assert!(cancelled_after(35, rig.owner.follow()).await);
    assert!(rig.owner.attempt_is_in_flight());
    assert_eq!(rig.native_dials().len(), 4);
    assert_eq!(rig.owner.close().await, Ok(()));
    assert_eq!(rig.owner.follow().await, Err(StandbyError::Closed));
    assert_eq!(rig.native_dials().len(), 4);
    assert_eq!(rig.closes(), ["native closed", "fallback closed"]);
}
