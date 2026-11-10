// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Scenario traces with the default parameters: loss grace 2000 ms, attempt
//! timeout 3000 ms, backoff 500 ms doubling up to 4000 ms, six attempts, stable
//! hold 5000 ms.

use super::super::{Decision, Event, Mode, PathKind, PolicyConfig};
use super::{Step, run, run_with};

const NATIVE: PathKind = PathKind::Native;
const YGG: PathKind = PathKind::Yggdrasil;

const fn up(generation: u64) -> Event {
    Event::NativeUp { generation }
}

const fn down(generation: u64) -> Event {
    Event::NativeDown { generation }
}

const fn ygg_ready(generation: u64) -> Event {
    Event::YggdrasilReady { generation }
}

const fn ygg_down(generation: u64) -> Event {
    Event::YggdrasilDown { generation }
}

const fn failed(attempt: u64) -> Event {
    Event::AttemptFailed { attempt }
}

#[test]
fn the_first_attempt_is_immediate_and_a_stable_native_path_refills_the_budget() {
    run(
        Mode::Standby,
        &[
            Step::Wakeup(Some(0)),
            Step::Time(
                0,
                &[Decision::AttemptNative {
                    attempt: 1,
                    deadline: 3000,
                }],
            ),
            Step::Wakeup(Some(3000)),
            Step::Event(100, up(1), &[Decision::Use(NATIVE)]),
            Step::Wakeup(Some(5100)),
            Step::Time(5099, &[]),
            Step::Time(5100, &[]),
            Step::Wakeup(None),
            Step::Active(Some(NATIVE)),
        ],
    );
}

#[test]
fn backoff_doubles_to_its_cap_and_the_budget_ends_in_exhaustion() {
    run(
        Mode::Standby,
        &[
            Step::Time(
                0,
                &[Decision::AttemptNative {
                    attempt: 1,
                    deadline: 3000,
                }],
            ),
            Step::Time(2999, &[]),
            Step::Wakeup(Some(3000)),
            // The attempt times out exactly at its deadline; the retry waits 500 ms.
            Step::Time(3000, &[]),
            Step::Wakeup(Some(3500)),
            Step::Time(
                3500,
                &[Decision::AttemptNative {
                    attempt: 2,
                    deadline: 6500,
                }],
            ),
            Step::Event(4000, failed(2), &[]),
            Step::Wakeup(Some(5000)),
            Step::Time(
                5000,
                &[Decision::AttemptNative {
                    attempt: 3,
                    deadline: 8000,
                }],
            ),
            // A late report about attempt 2 changes nothing.
            Step::Event(5100, failed(2), &[]),
            Step::Wakeup(Some(8000)),
            Step::Event(5200, failed(3), &[]),
            Step::Wakeup(Some(7200)),
            Step::Time(
                7200,
                &[Decision::AttemptNative {
                    attempt: 4,
                    deadline: 10200,
                }],
            ),
            Step::Event(7300, failed(4), &[]),
            Step::Wakeup(Some(11300)),
            Step::Time(
                11300,
                &[Decision::AttemptNative {
                    attempt: 5,
                    deadline: 14300,
                }],
            ),
            // The delay after attempt 5 is 4000 ms; so is the one after attempt 6 would be.
            Step::Event(11400, failed(5), &[]),
            Step::Wakeup(Some(15400)),
            Step::Time(
                15400,
                &[Decision::AttemptNative {
                    attempt: 6,
                    deadline: 18400,
                }],
            ),
            Step::Event(15500, failed(6), &[Decision::NativeExhausted]),
            Step::Wakeup(None),
            Step::Time(1_000_000, &[]),
            // The native path coming up on its own ends the episode and refills later.
            Step::Event(1_000_001, up(1), &[Decision::Use(NATIVE)]),
            Step::Wakeup(Some(1_005_001)),
            Step::Time(1_005_001, &[]),
            // Attempt numbers keep counting across a refill, so the old report below is stale.
            Step::Event(
                1_006_000,
                down(1),
                &[Decision::AttemptNative {
                    attempt: 7,
                    deadline: 1_009_000,
                }],
            ),
            Step::Event(1_006_100, failed(1), &[]),
            // The grace expires (1_008_000) before the attempt deadline (1_009_000).
            Step::Wakeup(Some(1_008_000)),
        ],
    );
}

#[test]
fn standby_fails_over_after_the_grace_and_returns_only_after_the_hold() {
    run(
        Mode::Standby,
        &[
            Step::Time(
                0,
                &[Decision::AttemptNative {
                    attempt: 1,
                    deadline: 3000,
                }],
            ),
            Step::Event(100, up(1), &[Decision::Use(NATIVE)]),
            Step::Event(200, ygg_ready(1), &[]),
            Step::Event(1000, down(1), &[]),
            Step::Wakeup(Some(1500)),
            Step::Time(
                1500,
                &[Decision::AttemptNative {
                    attempt: 2,
                    deadline: 4500,
                }],
            ),
            Step::Wakeup(Some(3000)),
            Step::Time(2999, &[]),
            Step::Time(3000, &[Decision::Use(YGG)]),
            Step::Wakeup(Some(4500)),
            Step::Time(4500, &[]),
            Step::Wakeup(Some(5500)),
            Step::Time(
                5500,
                &[Decision::AttemptNative {
                    attempt: 3,
                    deadline: 8500,
                }],
            ),
            // The native path returns but must hold before payload moves back.
            Step::Event(6000, up(2), &[]),
            Step::Active(Some(YGG)),
            Step::Wakeup(Some(11000)),
            // It flaps inside the hold: no switch, the hold restarts.
            Step::Event(8000, down(2), &[]),
            Step::Wakeup(Some(10000)),
            Step::Time(
                10000,
                &[Decision::AttemptNative {
                    attempt: 4,
                    deadline: 13000,
                }],
            ),
            Step::Event(10500, up(3), &[]),
            Step::Wakeup(Some(15500)),
            Step::Time(15499, &[]),
            Step::Time(15500, &[Decision::Use(NATIVE)]),
            Step::Wakeup(None),
        ],
    );
}

#[test]
fn signal_mode_never_selects_yggdrasil_for_payload() {
    run(
        Mode::Signal,
        &[
            Step::Time(
                0,
                &[Decision::AttemptNative {
                    attempt: 1,
                    deadline: 3000,
                }],
            ),
            Step::Event(100, up(1), &[Decision::Use(NATIVE)]),
            Step::Event(200, ygg_ready(1), &[]),
            Step::Event(1000, down(1), &[]),
            Step::Time(
                1500,
                &[Decision::AttemptNative {
                    attempt: 2,
                    deadline: 4500,
                }],
            ),
            // After the grace there is no payload path, and Yggdrasil is not one.
            Step::Time(3000, &[Decision::NoPath]),
            Step::Event(3200, ygg_ready(2), &[]),
            Step::Active(None),
            Step::Event(3500, up(2), &[Decision::Use(NATIVE)]),
        ],
    );
}

#[test]
fn a_late_yggdrasil_route_is_used_at_once_when_no_path_remains() {
    run(
        Mode::Standby,
        &[
            Step::Time(
                0,
                &[Decision::AttemptNative {
                    attempt: 1,
                    deadline: 3000,
                }],
            ),
            Step::Event(100, up(1), &[Decision::Use(NATIVE)]),
            Step::Event(1000, down(1), &[]),
            Step::Time(
                1500,
                &[Decision::AttemptNative {
                    attempt: 2,
                    deadline: 4500,
                }],
            ),
            Step::Time(3000, &[Decision::NoPath]),
            Step::Event(3200, ygg_ready(1), &[Decision::Use(YGG)]),
            Step::Event(3300, ygg_down(1), &[Decision::NoPath]),
            Step::Event(3400, ygg_ready(2), &[Decision::Use(YGG)]),
        ],
    );
}

#[test]
fn a_ready_yggdrasil_route_carries_payload_before_native_exists_and_native_takes_it_back() {
    run(
        Mode::Standby,
        &[
            Step::Time(
                0,
                &[Decision::AttemptNative {
                    attempt: 1,
                    deadline: 3000,
                }],
            ),
            Step::Event(100, ygg_ready(1), &[Decision::Use(YGG)]),
            Step::Event(200, up(1), &[]),
            Step::Wakeup(Some(5200)),
            Step::Time(5200, &[Decision::Use(NATIVE)]),
        ],
    );
}

#[test]
fn stale_and_reordered_generations_cannot_undo_newer_facts() {
    run(
        Mode::Standby,
        &[
            Step::Time(
                0,
                &[Decision::AttemptNative {
                    attempt: 1,
                    deadline: 3000,
                }],
            ),
            Step::Event(100, up(2), &[Decision::Use(NATIVE)]),
            Step::Event(200, down(1), &[]),
            Step::Event(250, up(1), &[]),
            Step::Wakeup(Some(5100)),
            Step::Time(10_000, &[]),
            Step::Wakeup(None),
            Step::Active(Some(NATIVE)),
        ],
    );
}

#[test]
fn identical_evidence_does_not_restart_the_failover_clock() {
    run(
        Mode::Standby,
        &[
            Step::Time(
                0,
                &[Decision::AttemptNative {
                    attempt: 1,
                    deadline: 3000,
                }],
            ),
            Step::Event(100, up(1), &[Decision::Use(NATIVE)]),
            Step::Event(200, ygg_ready(1), &[]),
            Step::Event(1000, down(1), &[]),
            Step::Time(
                1500,
                &[Decision::AttemptNative {
                    attempt: 2,
                    deadline: 4500,
                }],
            ),
            Step::Event(2500, down(1), &[]),
            Step::Wakeup(Some(3000)),
            Step::Time(2999, &[]),
            Step::Time(3000, &[Decision::Use(YGG)]),
        ],
    );
}

#[test]
fn a_flap_inside_the_grace_causes_no_switch() {
    run(
        Mode::Standby,
        &[
            Step::Time(
                0,
                &[Decision::AttemptNative {
                    attempt: 1,
                    deadline: 3000,
                }],
            ),
            Step::Event(100, up(1), &[Decision::Use(NATIVE)]),
            Step::Event(200, ygg_ready(1), &[]),
            Step::Event(1000, down(1), &[]),
            Step::Time(
                1500,
                &[Decision::AttemptNative {
                    attempt: 2,
                    deadline: 4500,
                }],
            ),
            Step::Event(1800, up(2), &[]),
            Step::Time(20_000, &[]),
            Step::Wakeup(None),
            Step::Active(Some(NATIVE)),
        ],
    );
}

#[test]
fn losing_yggdrasil_inside_the_hold_returns_to_the_live_native_path_at_once() {
    run(
        Mode::Standby,
        &[
            Step::Time(
                0,
                &[Decision::AttemptNative {
                    attempt: 1,
                    deadline: 3000,
                }],
            ),
            Step::Event(100, up(1), &[Decision::Use(NATIVE)]),
            Step::Event(200, ygg_ready(1), &[]),
            Step::Event(1000, down(1), &[]),
            Step::Time(
                1500,
                &[Decision::AttemptNative {
                    attempt: 2,
                    deadline: 4500,
                }],
            ),
            Step::Time(3000, &[Decision::Use(YGG)]),
            Step::Event(3500, up(2), &[]),
            Step::Event(3600, ygg_down(1), &[Decision::Use(NATIVE)]),
        ],
    );
}

#[test]
fn losing_both_paths_reports_no_path_and_attempts_continue() {
    run(
        Mode::Standby,
        &[
            Step::Time(
                0,
                &[Decision::AttemptNative {
                    attempt: 1,
                    deadline: 3000,
                }],
            ),
            Step::Event(100, up(1), &[Decision::Use(NATIVE)]),
            Step::Event(200, ygg_ready(1), &[]),
            Step::Event(1000, down(1), &[]),
            Step::Time(
                1500,
                &[Decision::AttemptNative {
                    attempt: 2,
                    deadline: 4500,
                }],
            ),
            Step::Time(3000, &[Decision::Use(YGG)]),
            Step::Event(3500, ygg_down(1), &[Decision::NoPath]),
            Step::Time(4500, &[]),
            Step::Wakeup(Some(5500)),
            Step::Time(
                5500,
                &[Decision::AttemptNative {
                    attempt: 3,
                    deadline: 8500,
                }],
            ),
        ],
    );
}

#[test]
fn an_attempt_report_after_the_native_path_came_up_is_ignored() {
    run(
        Mode::Standby,
        &[
            Step::Time(
                0,
                &[Decision::AttemptNative {
                    attempt: 1,
                    deadline: 3000,
                }],
            ),
            Step::Event(100, up(1), &[Decision::Use(NATIVE)]),
            Step::Event(150, failed(1), &[]),
            Step::Wakeup(Some(5100)),
        ],
    );
}

#[test]
fn a_time_that_runs_backwards_is_clamped_to_the_latest_time() {
    run(
        Mode::Standby,
        &[
            Step::Time(
                0,
                &[Decision::AttemptNative {
                    attempt: 1,
                    deadline: 3000,
                }],
            ),
            Step::Event(5000, up(1), &[Decision::Use(NATIVE)]),
            // Reported "at 4000" after 5000: handled at 5000, so the retry is due at 5500.
            Step::Event(4000, down(1), &[]),
            Step::Wakeup(Some(5500)),
        ],
    );
}

#[test]
fn shutdown_closes_the_policy_for_good() {
    run(
        Mode::Standby,
        &[
            Step::Time(
                0,
                &[Decision::AttemptNative {
                    attempt: 1,
                    deadline: 3000,
                }],
            ),
            Step::Event(500, Event::Shutdown, &[Decision::Closed]),
            Step::Wakeup(None),
            Step::Event(600, up(1), &[Decision::Closed]),
            Step::Time(10_000, &[]),
            Step::Wakeup(None),
        ],
    );
}

#[test]
fn a_late_owner_still_learns_that_the_budget_is_spent() {
    // Two attempts only; the owner sleeps through the grace and the last deadline, so one
    // late step both fails over and discovers the exhaustion.
    let config = PolicyConfig {
        max_attempts: 2,
        ..PolicyConfig::default()
    };
    run_with(
        Mode::Standby,
        config,
        &[
            Step::Time(
                0,
                &[Decision::AttemptNative {
                    attempt: 1,
                    deadline: 3000,
                }],
            ),
            Step::Event(100, up(1), &[Decision::Use(NATIVE)]),
            Step::Event(200, ygg_ready(1), &[]),
            Step::Event(1000, down(1), &[]),
            Step::Time(
                1500,
                &[Decision::AttemptNative {
                    attempt: 2,
                    deadline: 4500,
                }],
            ),
            Step::Event(
                5000,
                Event::Tick,
                &[Decision::Use(YGG), Decision::NativeExhausted],
            ),
            Step::Wakeup(Some(9_000)),
            Step::Time(
                9_000,
                &[Decision::AttemptNative {
                    attempt: 3,
                    deadline: 12_000,
                }],
            ),
            Step::Event(9_100, failed(2), &[]),
            Step::Wakeup(Some(12_000)),
            Step::Event(9_200, failed(3), &[]),
            Step::Wakeup(Some(13_200)),
            Step::Time(
                13_200,
                &[Decision::AttemptNative {
                    attempt: 4,
                    deadline: 16_200,
                }],
            ),
        ],
    );
}

#[test]
fn a_stale_attempt_report_across_a_refill_cannot_cancel_the_new_attempt() {
    let config = PolicyConfig {
        max_attempts: 2,
        ..PolicyConfig::default()
    };
    run_with(
        Mode::Standby,
        config,
        &[
            Step::Time(
                0,
                &[Decision::AttemptNative {
                    attempt: 1,
                    deadline: 3000,
                }],
            ),
            Step::Event(100, up(1), &[Decision::Use(NATIVE)]),
            Step::Time(5100, &[]),
            Step::Event(
                6000,
                down(1),
                &[Decision::AttemptNative {
                    attempt: 2,
                    deadline: 9000,
                }],
            ),
            Step::Event(6100, failed(1), &[]),
            // The grace expires (8000) before the attempt deadline (9000).
            Step::Wakeup(Some(8000)),
        ],
    );
}
