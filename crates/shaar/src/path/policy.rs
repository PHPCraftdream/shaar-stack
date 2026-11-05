// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The path policy: a deterministic state machine over injected monotonic time.
//!
//! State is a fixed-size struct. Retries are bounded by `max_attempts` and the
//! budget refills only after the native path stayed up for `stable_hold`.
//! Identical evidence changes nothing, so it can never restart a switching cycle.

use super::model::{ConfigError, Decision, Event, Millis, Mode, PathKind, PolicyConfig};

/// Last known state of one path and when it last changed.
#[derive(Clone, Copy, Debug)]
struct Link {
    up: bool,
    generation: u64,
    since: Millis,
}

/// The single native attempt that is currently running.
#[derive(Clone, Copy, Debug)]
struct InFlight {
    attempt: u64,
    deadline: Millis,
}

#[derive(Debug)]
pub(crate) struct PathPolicy {
    mode: Mode,
    config: PolicyConfig,
    clock: Millis,
    closed: bool,
    native: Link,
    yggdrasil: Link,
    active: Option<PathKind>,
    attempts_used: u32,
    last_attempt: u64,
    in_flight: Option<InFlight>,
    next_attempt_at: Option<Millis>,
    exhausted_reported: bool,
}

impl PathPolicy {
    /// Start with both paths down; the first native attempt is due at `now`.
    pub(crate) fn new(mode: Mode, config: PolicyConfig, now: Millis) -> Result<Self, ConfigError> {
        config.validate()?;
        let down = Link {
            up: false,
            generation: 0,
            since: now,
        };
        Ok(Self {
            mode,
            config,
            clock: now,
            closed: false,
            native: down,
            yggdrasil: down,
            active: None,
            attempts_used: 0,
            last_attempt: 0,
            in_flight: None,
            next_attempt_at: Some(now),
            exhausted_reported: false,
        })
    }

    /// The path currently designated to carry payload.
    pub(crate) fn active(&self) -> Option<PathKind> {
        self.active
    }

    /// Apply one observation at `now` and return the next decision. A `now` that
    /// lies before the latest seen time is treated as that latest time.
    pub(crate) fn step(&mut self, now: Millis, event: Event) -> Decision {
        if self.closed {
            return Decision::Closed;
        }
        self.clock = self.clock.max(now);
        let now = self.clock;
        match event {
            Event::Shutdown => {
                self.closed = true;
                self.in_flight = None;
                self.next_attempt_at = None;
                return Decision::Closed;
            }
            Event::NativeUp { generation } => self.observe_native(now, generation, true),
            Event::NativeDown { generation } => self.observe_native(now, generation, false),
            Event::AttemptFailed { attempt } => self.attempt_failed(now, attempt),
            Event::YggdrasilReady { generation } => self.observe_yggdrasil(now, generation, true),
            Event::YggdrasilDown { generation } => self.observe_yggdrasil(now, generation, false),
            Event::Tick => {}
        }
        self.decide(now)
    }

    /// The earliest time at which stepping with `Tick` would change something.
    /// A value at or before the current time means "step again now".
    pub(crate) fn next_wakeup(&self) -> Option<Millis> {
        if self.closed {
            return None;
        }
        let mut wake: Option<Millis> = None;
        let mut note = |at: Millis| wake = Some(wake.map_or(at, |known| known.min(at)));
        if let Some(flight) = self.in_flight {
            note(flight.deadline);
        }
        let idle = !self.native.up && self.in_flight.is_none();
        if let Some(at) = self.next_attempt_at.filter(|_| idle) {
            note(at);
        }
        match self.active {
            Some(PathKind::Native) if !self.native.up => {
                note(self.native.since.saturating_add(self.config.loss_grace));
            }
            Some(PathKind::Yggdrasil) if self.native.up && self.yggdrasil_usable() => {
                note(self.native.since.saturating_add(self.config.stable_hold));
            }
            _ => {}
        }
        if self.native.up && self.attempts_used > 0 {
            note(self.native.since.saturating_add(self.config.stable_hold));
        }
        if self.exhaustion_pending() {
            note(self.clock);
        }
        wake
    }

    /// The budget is spent, nothing is running or scheduled, and the owner was not told yet.
    fn exhaustion_pending(&self) -> bool {
        !self.native.up
            && self.in_flight.is_none()
            && self.next_attempt_at.is_none()
            && self.attempts_used >= self.config.max_attempts
            && !self.exhausted_reported
    }

    fn yggdrasil_usable(&self) -> bool {
        self.mode == Mode::Standby && self.yggdrasil.up
    }

    fn observe_native(&mut self, now: Millis, generation: u64, up: bool) {
        if generation < self.native.generation {
            return;
        }
        let transition = self.native.up != up;
        let renewed = up && generation > self.native.generation;
        self.native.generation = generation;
        if transition || renewed {
            self.native.since = now;
        }
        if !transition {
            return;
        }
        self.native.up = up;
        if up {
            self.in_flight = None;
            self.next_attempt_at = None;
            self.exhausted_reported = false;
        } else {
            self.schedule_retry(now);
        }
    }

    fn observe_yggdrasil(&mut self, now: Millis, generation: u64, ready: bool) {
        if generation < self.yggdrasil.generation {
            return;
        }
        let transition = self.yggdrasil.up != ready;
        self.yggdrasil.generation = generation;
        if transition {
            self.yggdrasil.up = ready;
            self.yggdrasil.since = now;
        }
    }

    fn attempt_failed(&mut self, now: Millis, attempt: u64) {
        if self
            .in_flight
            .is_some_and(|flight| flight.attempt == attempt)
        {
            self.in_flight = None;
            self.schedule_retry(now);
        }
    }

    /// Delay before attempt `n`: none for the first, then base * 2^(n-2) up to the cap.
    fn delay_before(&self, n: u32) -> Millis {
        if n <= 1 {
            return 0;
        }
        let shift = (n - 2).min(32);
        self.config
            .backoff_base
            .saturating_mul(1u64 << shift)
            .min(self.config.backoff_cap)
    }

    fn schedule_retry(&mut self, now: Millis) {
        if self.in_flight.is_some() {
            return;
        }
        self.next_attempt_at = (self.attempts_used < self.config.max_attempts)
            .then(|| now.saturating_add(self.delay_before(self.attempts_used + 1)));
    }

    fn decide(&mut self, now: Millis) -> Decision {
        self.expire_attempt(now);
        if let Some(decision) = self.select_payload(now) {
            return decision;
        }
        if let Some(decision) = self.next_attempt(now) {
            return decision;
        }
        self.refill(now);
        Decision::Wait
    }

    fn expire_attempt(&mut self, now: Millis) {
        if self.in_flight.is_some_and(|flight| now >= flight.deadline) {
            self.in_flight = None;
            self.schedule_retry(now);
        }
    }

    /// Choose the payload path with hysteresis: fail over only after the grace,
    /// return to native only after the hold, and never switch without evidence.
    fn select_payload(&mut self, now: Millis) -> Option<Decision> {
        let usable = self.yggdrasil_usable();
        let chosen = match self.active {
            None if self.native.up => Some(Decision::Use(PathKind::Native)),
            None if usable => Some(Decision::Use(PathKind::Yggdrasil)),
            None => None,
            Some(PathKind::Native) if self.native.up => None,
            Some(PathKind::Native) => {
                let expired = now >= self.native.since.saturating_add(self.config.loss_grace);
                match (expired, usable) {
                    (false, _) => None,
                    (true, true) => Some(Decision::Use(PathKind::Yggdrasil)),
                    (true, false) => Some(Decision::NoPath),
                }
            }
            Some(PathKind::Yggdrasil) if !usable => Some(if self.native.up {
                Decision::Use(PathKind::Native)
            } else {
                Decision::NoPath
            }),
            Some(PathKind::Yggdrasil) => {
                let held = now >= self.native.since.saturating_add(self.config.stable_hold);
                (self.native.up && held).then_some(Decision::Use(PathKind::Native))
            }
        };
        match chosen {
            Some(Decision::Use(path)) => self.active = Some(path),
            Some(Decision::NoPath) => self.active = None,
            _ => {}
        }
        chosen
    }

    fn next_attempt(&mut self, now: Millis) -> Option<Decision> {
        if self.native.up || self.in_flight.is_some() {
            return None;
        }
        match self.next_attempt_at {
            Some(at) if now >= at => {
                let Some(attempt) = self.last_attempt.checked_add(1) else {
                    self.closed = true;
                    self.next_attempt_at = None;
                    return Some(Decision::Closed);
                };
                self.last_attempt = attempt;
                self.attempts_used = self.attempts_used.saturating_add(1);
                let deadline = now.saturating_add(self.config.attempt_timeout);
                self.in_flight = Some(InFlight { attempt, deadline });
                self.next_attempt_at = None;
                Some(Decision::AttemptNative { attempt, deadline })
            }
            Some(_) => None,
            None if self.exhaustion_pending() => {
                self.exhausted_reported = true;
                Some(Decision::NativeExhausted)
            }
            None => None,
        }
    }

    fn refill(&mut self, now: Millis) {
        let held = now >= self.native.since.saturating_add(self.config.stable_hold);
        if self.native.up && held {
            self.attempts_used = 0;
        }
    }
}
