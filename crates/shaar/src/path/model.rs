// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Vocabulary of the path policy: parameters, observations and decisions.
//!
//! Time is a caller-supplied monotonic count of milliseconds; the policy never
//! reads a clock. Observations carry the generation of the connection they
//! describe so that late or reordered reports cannot undo newer facts.

/// Monotonic milliseconds from an injected clock; never wall-clock time.
pub(crate) type Millis = u64;

/// Fallback mode of the node (`fallback` in the configuration).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Yggdrasil and libp2p carry negotiation only; payload stays on the native path.
    Signal,
    /// Yggdrasil may carry authenticated payload while the native path is unavailable.
    Standby,
}

/// Paths that can carry application payload. libp2p never appears here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PathKind {
    Native,
    Yggdrasil,
}

/// Observations reported by the owners of the real paths. Reports of one
/// generation are applied in arrival order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Event {
    /// The native connection of this generation became usable.
    NativeUp { generation: u64 },
    /// The native connection of this generation was lost.
    NativeDown { generation: u64 },
    /// A requested native attempt ended without a connection. Attempt numbers are
    /// unique for the lifetime of the policy, so a late report cannot cancel a newer attempt.
    AttemptFailed { attempt: u64 },
    /// The Yggdrasil route of this generation proved ready (authenticated probe delivered).
    YggdrasilReady { generation: u64 },
    /// The Yggdrasil route of this generation was lost.
    YggdrasilDown { generation: u64 },
    /// Time passed; carries no new fact.
    Tick,
    /// The node is shutting down; every later step answers `Closed`.
    Shutdown,
}

/// What the owner must do next. At most one decision is returned per step; the
/// owner steps again with `Tick` while `next_wakeup` is not in the future.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    /// Nothing to do.
    Wait,
    /// Carry payload on this path from now on.
    Use(PathKind),
    /// Start native attempt number `attempt`; it must report before `deadline`.
    AttemptNative { attempt: u64, deadline: Millis },
    /// The attempt budget is spent; no further native attempt is made until the
    /// native path comes up by itself. Reported once per down episode.
    NativeExhausted,
    /// No path can carry payload right now.
    NoPath,
    /// The policy is closed.
    Closed,
}

/// Why a parameter set is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConfigError {
    /// The named parameter must be greater than zero.
    Zero(&'static str),
    /// The first backoff delay exceeds the cap.
    BackoffAboveCap,
}

/// Tunable bounds of the policy. All durations are milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PolicyConfig {
    /// How long the native path must stay down before payload fails over.
    pub(crate) loss_grace: Millis,
    /// Deadline of one native attempt.
    pub(crate) attempt_timeout: Millis,
    /// Delay before the second attempt; doubles per attempt up to the cap.
    pub(crate) backoff_base: Millis,
    /// Upper bound of the delay between attempts.
    pub(crate) backoff_cap: Millis,
    /// Absolute number of attempts before the budget is spent.
    pub(crate) max_attempts: u32,
    /// How long the native path must stay up before payload returns to it and
    /// the attempt budget is refilled.
    pub(crate) stable_hold: Millis,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            loss_grace: 2_000,
            attempt_timeout: 3_000,
            backoff_base: 500,
            backoff_cap: 4_000,
            max_attempts: 6,
            stable_hold: 5_000,
        }
    }
}

impl PolicyConfig {
    /// Reject parameter sets that would make the policy degenerate.
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        let required = [
            ("loss_grace", self.loss_grace),
            ("attempt_timeout", self.attempt_timeout),
            ("backoff_base", self.backoff_base),
            ("backoff_cap", self.backoff_cap),
            ("max_attempts", u64::from(self.max_attempts)),
            ("stable_hold", self.stable_hold),
        ];
        if let Some(name) = required
            .iter()
            .find(|(_, value)| *value == 0)
            .map(|(name, _)| *name)
        {
            return Err(ConfigError::Zero(name));
        }
        if self.backoff_base > self.backoff_cap {
            return Err(ConfigError::BackoffAboveCap);
        }
        Ok(())
    }
}
