// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `follow`: wait for a payload route that is new, advancing all retained work.
//!
//! Everything `follow` needs lives in the owner, and the only await is one biased
//! select, so dropping the future at any point loses nothing. Observations are
//! handled synchronously right after the select returns, never across an await.

use std::time::Duration;

use tokio::time::{Instant, sleep_until};

use super::super::model::{Decision, Event, PathKind};
use super::super::owner::Dialer;
use super::side::{Done, Outcome, State, finished};
use super::{Cmd, StandbyError, StandbyOwner};

/// Route identity: kind and generation of the held link of that kind.
type RouteId = Option<(PathKind, u64)>;

/// What ended one wait.
enum Wake<D: Dialer, F: Dialer> {
    Native(Done<D>),
    Fallback(Done<F>),
    Time,
}

async fn wait_until(at: Option<Instant>) {
    match at {
        Some(at) => sleep_until(at).await,
        None => std::future::pending().await,
    }
}

impl<D, F> StandbyOwner<D, F>
where
    D: Dialer + 'static,
    D::Link: 'static,
    F: Dialer + 'static,
    F::Link: 'static,
{
    fn route_id(&self) -> RouteId {
        match self.policy.active()? {
            PathKind::Native => self
                .native
                .link
                .as_ref()
                .map(|_| (PathKind::Native, self.native.generation)),
            PathKind::Yggdrasil => self
                .fallback
                .link
                .as_ref()
                .map(|_| (PathKind::Yggdrasil, self.fallback.generation)),
        }
    }

    /// Feed one event to the policy and keep what its decision asks for.
    fn step(&mut self, event: Event) -> Result<(), StandbyError> {
        let now = self.millis(Instant::now());
        match self.policy.step(now, event) {
            Decision::AttemptNative { attempt, deadline } => {
                // A newer request replaces an older unstarted one: the policy
                // already expired that attempt.
                self.native_cmd = Some(Cmd {
                    attempt,
                    deadline: self.instant(deadline),
                });
            }
            Decision::NativeExhausted => self.native_exhausted = true,
            Decision::Closed => return Err(StandbyError::Closed),
            // Routing is derived from the policy's active path.
            Decision::Wait | Decision::NoPath | Decision::Use(_) => {}
        }
        Ok(())
    }

    /// Start whatever each idle side should be doing. Returns the attempt number of
    /// a native request whose deadline had already passed; the caller reports it failed.
    fn start_work(&mut self, now: Instant) -> Option<u64> {
        if self.native.is_idle() {
            if self.native.link.is_some() {
                self.native.start_watch();
            } else if let Some(cmd) = self.native_cmd.take() {
                if now >= cmd.deadline {
                    return Some(cmd.attempt);
                }
                // The original deadline, so a request that waited is not extended.
                self.native.start_dial(cmd.attempt, cmd.deadline);
            }
        }
        if self.standby && self.fallback.is_idle() {
            if self.fallback.link.is_some() {
                self.fallback.start_watch();
            } else if self.fallback.pause_until.is_none_or(|at| now >= at) {
                self.fallback.pause_until = None;
                let limit = now + Duration::from_millis(self.config.attempt_timeout);
                self.fallback.start_dial(0, limit);
            }
        }
        None
    }

    /// The next time something can change without new evidence: the policy's
    /// wakeup or the end of the fallback retry pause.
    fn wake_at(&self) -> Option<Instant> {
        let policy = self.policy.next_wakeup().map(|at| self.instant(at));
        let pause = if self.standby && self.fallback.is_idle() && self.fallback.link.is_none() {
            self.fallback.pause_until
        } else {
            None
        };
        match (policy, pause) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    fn on_native(&mut self, done: Done<D>) -> Event {
        let Done {
            dialer,
            outcome,
            attempt,
        } = done;
        self.native.state = State::Idle(dialer);
        match outcome {
            Outcome::Dialed(Ok(link)) => {
                let generation = self.native.install(link);
                self.native_exhausted = false;
                // Any unstarted request is stale now that a link is held.
                self.native_cmd = None;
                Event::NativeUp { generation }
            }
            Outcome::Dialed(Err(_)) => Event::AttemptFailed { attempt },
            Outcome::Lost => {
                self.native.link = None;
                Event::NativeDown {
                    generation: self.native.generation,
                }
            }
            Outcome::Cancelled => Event::Tick,
        }
    }

    fn on_fallback(&mut self, done: Done<F>, failed_seen: &mut bool) -> Event {
        let Done {
            dialer, outcome, ..
        } = done;
        self.fallback.state = State::Idle(dialer);
        let pause = Duration::from_millis(self.config.backoff_cap);
        match outcome {
            Outcome::Dialed(Ok(link)) => {
                let generation = self.fallback.install(link);
                *failed_seen = false;
                self.fallback.pause_until = None;
                Event::YggdrasilReady { generation }
            }
            Outcome::Dialed(Err(_)) => {
                *failed_seen = true;
                self.fallback.pause_until = Some(Instant::now() + pause);
                Event::Tick
            }
            Outcome::Lost => {
                self.fallback.link = None;
                self.fallback.pause_until = Some(Instant::now() + pause);
                Event::YggdrasilDown {
                    generation: self.fallback.generation,
                }
            }
            Outcome::Cancelled => Event::Tick,
        }
    }

    /// Wait for a payload route that is new compared with the route held at call
    /// start (kind plus link generation) and return its kind.
    ///
    /// A restore of the same kind inside the loss grace is new (new generation); a
    /// failover is reported when the policy emits `Use(Yggdrasil)`, a return to
    /// native only when it emits `Use(Native)`; a hot standby fallback becoming
    /// ready under a healthy native route returns nothing. Errors: `Closed`;
    /// `Exhausted` for owners without a usable fallback once the native budget is
    /// spent and no native link is held; `Unavailable` for standby owners when in
    /// addition no fallback link is held and a fallback dial fails while this call
    /// is polled. That dial may have started in an earlier call; its deadline and
    /// the retained retry pause are not reset by repeated observations.
    ///
    /// Work advances only while this future is polled. A native dial pending when
    /// a route is returned stays pending in the owner and ends at its original
    /// deadline during a later call; no duplicate attempt is created.
    /// cancel-safe: yes — all state is retained in the owner and observations are
    /// applied without an await in between.
    pub(crate) async fn follow(&mut self) -> Result<PathKind, StandbyError> {
        if self.closed {
            return Err(StandbyError::Closed);
        }
        let baseline = self.route_id();
        let mut failed_seen = false;
        let mut event = Event::Tick;
        loop {
            self.step(event)?;
            if let Some(attempt) = self.start_work(Instant::now()) {
                event = Event::AttemptFailed { attempt };
                continue;
            }

            if let Some((kind, _)) = self.route_id().filter(|id| Some(*id) != baseline) {
                return Ok(kind);
            }
            if self.native_exhausted && self.native.link.is_none() {
                if !self.standby {
                    return Err(StandbyError::Exhausted);
                }
                if self.fallback.link.is_none() && failed_seen {
                    return Err(StandbyError::Unavailable);
                }
            }

            let at = self.wake_at();
            // Evidence is preferred over time when both are ready.
            let wake = tokio::select! {
                biased;
                done = finished(&mut self.native) => Wake::Native(done),
                done = finished(&mut self.fallback) => Wake::Fallback(done),
                () = wait_until(at) => Wake::Time,
            };
            event = match wake {
                Wake::Native(done) => self.on_native(done),
                Wake::Fallback(done) => self.on_fallback(done, &mut failed_seen),
                Wake::Time => Event::Tick,
            };
        }
    }
}
