// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Event-trace tests of the path policy. Each trace feeds observations at fixed
//! times and expects exactly the listed decisions; `Time` steps fire every wakeup
//! the policy asks for, the way an owner with a timer would.

mod negotiation;
mod owner;
mod recovery;
mod traces;

use super::{ConfigError, Decision, Event, Millis, Mode, PathKind, PathPolicy, PolicyConfig};

/// One line of a trace.
pub(super) enum Step {
    /// Deliver an observation at the given time, then settle due work.
    Event(Millis, Event, &'static [Decision]),
    /// Let time pass up to and including the given time, firing wakeups.
    Time(Millis, &'static [Decision]),
    /// The policy asks to be woken at this time (or never).
    Wakeup(Option<Millis>),
    /// The payload path the policy has designated.
    Active(Option<PathKind>),
}

/// Step until nothing is due at `at`; a policy that never settles is a defect.
fn settle(policy: &mut PathPolicy, at: Millis, first: Event) -> Vec<Decision> {
    let mut decisions = Vec::new();
    let mut event = first;
    for _ in 0..32 {
        let decision = policy.step(at, event);
        if decision != Decision::Wait {
            decisions.push(decision);
        }
        event = Event::Tick;
        if !policy.next_wakeup().is_some_and(|wake| wake <= at) {
            return decisions;
        }
    }
    panic!("the policy did not settle at {at}: {decisions:?}");
}

fn advance(policy: &mut PathPolicy, until: Millis) -> Vec<Decision> {
    let mut decisions = Vec::new();
    for _ in 0..256 {
        match policy.next_wakeup() {
            Some(wake) if wake <= until => decisions.extend(settle(policy, wake, Event::Tick)),
            _ => return decisions,
        }
    }
    panic!("wakeups did not stop before {until}");
}

/// Replay a trace from time zero with the default parameters.
pub(super) fn run(mode: Mode, steps: &[Step]) {
    run_with(mode, PolicyConfig::default(), steps);
}

/// Replay a trace from time zero with the given parameters.
pub(super) fn run_with(mode: Mode, config: PolicyConfig, steps: &[Step]) {
    let mut policy = PathPolicy::new(mode, config, 0).expect("valid parameters");
    let mut expected_active = None;
    for (index, step) in steps.iter().enumerate() {
        let observed = match *step {
            Step::Event(at, event, expect) => {
                let decisions = settle(&mut policy, at, event);
                assert_eq!(decisions, expect, "step {index}: {event:?} at {at}");
                decisions
            }
            Step::Time(until, expect) => {
                let decisions = advance(&mut policy, until);
                assert_eq!(decisions, expect, "step {index}: time up to {until}");
                decisions
            }
            Step::Wakeup(expect) => {
                assert_eq!(policy.next_wakeup(), expect, "step {index}: wakeup");
                Vec::new()
            }
            Step::Active(expect) => {
                assert_eq!(policy.active(), expect, "step {index}: active path");
                Vec::new()
            }
        };
        for decision in observed {
            match decision {
                Decision::Use(path) => expected_active = Some(path),
                Decision::NoPath => expected_active = None,
                _ => {}
            }
        }
        assert_eq!(
            policy.active(),
            expected_active,
            "step {index}: the active path follows the Use and NoPath decisions"
        );
    }
}

#[test]
fn default_parameters_are_valid() {
    assert_eq!(PolicyConfig::default().validate(), Ok(()));
}

#[test]
fn every_zero_parameter_is_rejected_by_name() {
    let base = PolicyConfig::default();
    let cases = [
        (
            PolicyConfig {
                loss_grace: 0,
                ..base
            },
            "loss_grace",
        ),
        (
            PolicyConfig {
                attempt_timeout: 0,
                ..base
            },
            "attempt_timeout",
        ),
        (
            PolicyConfig {
                backoff_base: 0,
                ..base
            },
            "backoff_base",
        ),
        (
            PolicyConfig {
                backoff_cap: 0,
                ..base
            },
            "backoff_cap",
        ),
        (
            PolicyConfig {
                max_attempts: 0,
                ..base
            },
            "max_attempts",
        ),
        (
            PolicyConfig {
                stable_hold: 0,
                ..base
            },
            "stable_hold",
        ),
    ];
    for (config, name) in cases {
        assert_eq!(config.validate(), Err(ConfigError::Zero(name)), "{name}");
        assert_eq!(
            PathPolicy::new(Mode::Standby, config, 0).err(),
            Some(ConfigError::Zero(name)),
            "{name}: construction refuses it too"
        );
    }
}

#[test]
fn a_backoff_base_above_the_cap_is_rejected() {
    let config = PolicyConfig {
        backoff_base: 5_000,
        backoff_cap: 4_000,
        ..PolicyConfig::default()
    };
    assert_eq!(config.validate(), Err(ConfigError::BackoffAboveCap));
}
