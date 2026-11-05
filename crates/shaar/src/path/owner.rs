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

    /// Release everything the dialer owns, joined. Must tolerate repeated calls.
    async fn close(&mut self) -> Result<(), DialError>;
}

pub(crate) struct PathOwner<D: Dialer> {
    dialer: D,
    policy: PathPolicy,
    started: Instant,
    generation: u64,
    link: Option<D::Link>,
    closed: bool,
}

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
        let mut event = Event::Tick;
        loop {
            let now = self.millis(Instant::now());
            let decision = self.policy.step(now, event);
            event = Event::Tick;
            match decision {
                Decision::Use(PathKind::Native) => return Ok(()),
                Decision::AttemptNative { attempt, deadline } => {
                    let limit = self.instant(deadline);
                    event = match timeout_at(limit, self.dialer.dial(limit)).await {
                        Ok(Ok(link)) => {
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
                // `NoPath` follows a lost native path and `Use(Yggdrasil)` needs `standby`:
                // neither can happen while establishing in `signal` mode.
                Decision::NativeExhausted
                | Decision::NoPath
                | Decision::Use(PathKind::Yggdrasil) => {
                    return Err(EstablishError::Exhausted);
                }
            }
        }
    }

    /// Shut down: the policy is told first, then the link is dropped and the dialer
    /// is closed and joined. Idempotent.
    pub(crate) async fn close(&mut self) -> Result<(), DialError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let now = self.millis(Instant::now());
        self.policy.step(now, Event::Shutdown);
        self.link = None;
        self.dialer.close().await
    }
}
