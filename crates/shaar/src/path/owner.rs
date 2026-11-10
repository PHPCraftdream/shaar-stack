// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The path owner: drives the path policy with real time and a native dialer.
//!
//! The owner is a coordinator, not a task: the caller polls it, so there is one
//! owner of every connection and nothing is detached. It turns policy decisions
//! into dials and dial results into observations. Only the native path exists in
//! this version (`Mode::Signal`); Yggdrasil and signaling are wired by later leaves.

use std::time::Duration;

use tokio::time::{Instant, sleep_until, timeout_at};

use super::model::{ConfigError, Decision, Event, Millis, Mode, PathKind, PolicyConfig};
use super::policy::PathPolicy;

/// A dial ended without a connection. The policy only needs to know that it failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DialError;

/// Why the owner could not establish the native path.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the signal-mode native-only owner is exercised by the path traces; the roles drive StandbyOwner"
    )
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EstablishError {
    /// The attempt budget is spent; no further attempt is made by this call.
    Exhausted,
    /// The owner is closed.
    Closed,
}

/// Opens payload-capable connections to the one peer this owner serves.
pub(crate) trait Dialer {
    /// The connection a successful dial produces; dropping it closes it.
    type Link;

    /// One bounded dial (for example resolve, then connect). It must give up at
    /// `deadline`; a link completed after the deadline is closed, not returned.
    async fn dial(&mut self, deadline: Instant) -> Result<Self::Link, DialError>;

    /// Observe loss of this exact link, including an already closed link.
    /// cancel-safe: yes — the observer must be level-triggered and retain no event.
    async fn lost(&mut self, link: &Self::Link);

    /// Release everything the dialer owns, joined. Must tolerate repeated calls.
    /// cancel-safe: yes — an interrupted close must remain resumable by another call.
    async fn close(&mut self) -> Result<(), DialError>;
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the signal-mode native-only owner is exercised by the path traces; the roles drive StandbyOwner"
    )
)]
pub(crate) struct PathOwner<D: Dialer> {
    dialer: D,
    policy: PathPolicy,
    started: Instant,
    generation: u64,
    link: Option<D::Link>,
    closed: bool,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the signal-mode native-only owner is exercised by the path traces; the roles drive StandbyOwner"
    )
)]
impl<D: Dialer> PathOwner<D> {
    /// Start in `signal` mode with the policy clock at zero; the first attempt is due at once.
    pub(crate) fn new(dialer: D, config: PolicyConfig) -> Result<Self, ConfigError> {
        Ok(Self {
            dialer,
            policy: PathPolicy::new(Mode::Signal, config, 0)?,
            started: Instant::now(),
            generation: 0,
            link: None,
            closed: false,
        })
    }

    /// The path designated to carry payload.
    pub(crate) fn active(&self) -> Option<PathKind> {
        self.policy.active()
    }

    /// The connection of the active path, if one is designated and held.
    pub(crate) fn payload(&self) -> Option<&D::Link> {
        match self.policy.active() {
            Some(PathKind::Native) => self.link.as_ref(),
            _ => None,
        }
    }

    fn millis(&self, at: Instant) -> Millis {
        u64::try_from(at.saturating_duration_since(self.started).as_millis()).unwrap_or(u64::MAX)
    }

    fn instant(&self, millis: Millis) -> Instant {
        self.started + Duration::from_millis(millis)
    }

    /// Run the policy until native payload is available or the attempt budget is spent.
    /// A failed dial is retried on the policy's backoff schedule.
    /// cancel-safe: NO — a dial cancelled in flight is abandoned and its link is lost;
    /// the policy state stays consistent, so calling again resumes the schedule.
    pub(crate) async fn establish(&mut self) -> Result<(), EstablishError> {
        if self.payload().is_some() {
            return Ok(());
        }
        self.drive(Event::Tick).await
    }

    /// Wait for native loss, then restore a new payload using the remaining budget.
    /// The caller cancels this operation before closing the owner; streams are not migrated.
    /// cancel-safe: NO — a retry dial may be abandoned, but the loss and schedule persist.
    pub(crate) async fn maintain(&mut self) -> Result<(), EstablishError> {
        while let Some(link) = self.link.as_ref() {
            let wake = self.policy.next_wakeup().map(|at| self.instant(at));
            let lost = match wake {
                Some(at) => {
                    tokio::select! {
                        biased;
                        () = self.dialer.lost(link) => true,
                        () = sleep_until(at) => false,
                    }
                }
                None => {
                    self.dialer.lost(link).await;
                    true
                }
            };
            if lost {
                return self
                    .drive(Event::NativeDown {
                        generation: self.generation,
                    })
                    .await;
            }
            self.policy.step(self.millis(Instant::now()), Event::Tick);
        }
        self.drive(Event::Tick).await
    }

    async fn drive(&mut self, mut event: Event) -> Result<(), EstablishError> {
        loop {
            let now = self.millis(Instant::now());
            let decision = self.policy.step(now, event);
            if matches!(event, Event::NativeDown { .. }) {
                self.link = None;
            }
            event = Event::Tick;
            if self.payload().is_some() {
                return Ok(());
            }
            match decision {
                Decision::Use(PathKind::Native) => return Ok(()),
                Decision::AttemptNative { attempt, deadline } => {
                    let limit = self.instant(deadline);
                    event = match self.attempt(limit).await {
                        Ok(link) => {
                            self.generation += 1;
                            self.link = Some(link);
                            Event::NativeUp {
                                generation: self.generation,
                            }
                        }
                        _ => Event::AttemptFailed { attempt },
                    };
                }
                Decision::Wait => match self.policy.next_wakeup() {
                    Some(at) => sleep_until(self.instant(at)).await,
                    None => return Err(EstablishError::Exhausted),
                },
                Decision::Closed => return Err(EstablishError::Closed),
                Decision::NoPath => {}
                Decision::NativeExhausted | Decision::Use(PathKind::Yggdrasil) => {
                    return Err(EstablishError::Exhausted);
                }
            }
        }
    }

    async fn attempt(&mut self, limit: Instant) -> Result<D::Link, DialError> {
        let started = self.started;
        let dial = timeout_at(limit, self.dialer.dial(limit));
        tokio::pin!(dial);
        loop {
            let wake = self
                .policy
                .next_wakeup()
                .map_or(limit, |at| started + Duration::from_millis(at));
            tokio::select! {
                result = &mut dial => {
                    return match result {
                        Ok(Ok(link)) if Instant::now() < limit => Ok(link),
                        _ => Err(DialError),
                    };
                }
                () = sleep_until(wake) => {
                    let now = Instant::now();
                    if now >= limit {
                        return Err(DialError);
                    }
                    let millis = u64::try_from(now.saturating_duration_since(started).as_millis())
                        .unwrap_or(u64::MAX);
                    self.policy.step(millis, Event::Tick);
                }
            }
        }
    }

    /// Shut down: the policy is told first, then the link is dropped and the dialer
    /// is closed and joined. Idempotent.
    /// cancel-safe: yes — an interrupted backend close can be resumed.
    pub(crate) async fn close(&mut self) -> Result<(), DialError> {
        if self.closed {
            return Ok(());
        }
        let now = self.millis(Instant::now());
        self.policy.step(now, Event::Shutdown);
        self.link = None;
        self.dialer.close().await?;
        self.closed = true;
        Ok(())
    }
}
