// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The standby owner: follows the payload route of one peer over a native dialer
//! and, in `Mode::Standby`, a hot fallback (Yggdrasil) dialer.
//!
//! The owner is a caller-driven coordinator. It spawns no task and detaches no
//! work: every dial and every loss watch is a boxed future parked inside the owner
//! and polled only by `follow` and `close`. Dropping the owner aborts that work, but
//! that is not a joined shutdown; `close` is. Work therefore progresses only while
//! the caller polls the owner; no hidden coordinator exists, and an attempt polled
//! after its deadline fails by timeout.
//!
//! `PathPolicy` alone owns selection, hysteresis and retry budgets. The owner turns
//! its decisions into dials and real observations into its events and adds no
//! switching rule. All state lives in the owner, so a cancelled `follow` loses
//! nothing and a native dial pending when a route is announced stays pending until
//! its original deadline. The fallback retry pause is a bound equal to
//! `PolicyConfig::backoff_cap`; it is retained, so repeated calls cannot bypass it.
//!
//! Routes are owned leases (`Arc` clones), so a consumer may keep a live forward
//! on a route while the owner keeps being polled and recovers the native path.
//! In-flight TCP streams are never migrated or replayed: a new route carries new
//! streams only. A lease may outlive the owner; its drop releases the consumer's
//! session handle, and leases are bounded by the consumer (a `Session` admits at
//! most 16 forwards). The caller must stop and drop its leases before relying on
//! the release of admission charges.

mod follow;
mod side;

use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use super::model::{ConfigError, Event, Millis, Mode, PathKind, PolicyConfig};
use super::owner::{DialError, Dialer};
use super::policy::PathPolicy;

use side::Side;

/// Why `follow` could not produce a route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StandbyError {
    /// The native budget is spent and this owner cannot use a fallback.
    Exhausted,
    /// The native budget is spent and no fallback route exists either.
    Unavailable,
    /// The owner is closed.
    Closed,
}

/// The connection that carries payload now, as an owned lease.
#[derive(Debug)]
pub(crate) enum Route<N, Y> {
    Native(Arc<N>),
    Yggdrasil(Arc<Y>),
}

/// A native attempt requested by the policy and not yet started.
struct Cmd {
    attempt: u64,
    /// The original attempt deadline, never extended by a later start.
    deadline: Instant,
}

pub(crate) struct StandbyOwner<D, F>
where
    D: Dialer + 'static,
    D::Link: 'static,
    F: Dialer + 'static,
    F::Link: 'static,
{
    policy: PathPolicy,
    config: PolicyConfig,
    started: Instant,
    native: Side<D>,
    fallback: Side<F>,
    /// The fallback is dialed and may carry payload (`Mode::Standby`).
    standby: bool,
    /// One slot: the policy has already expired an older unstarted attempt.
    native_cmd: Option<Cmd>,
    /// The policy reported the native budget spent; cleared by the next native link.
    native_exhausted: bool,
    dialer_closed: bool,
    fallback_closed: bool,
    closed: bool,
}

impl<D, F> StandbyOwner<D, F>
where
    D: Dialer + 'static,
    D::Link: 'static,
    F: Dialer + 'static,
    F::Link: 'static,
{
    /// Start with the policy clock at zero; the first native attempt is due at once.
    /// In `Mode::Signal` the fallback is never dialed, held or routed.
    pub(crate) fn new(
        dialer: D,
        fallback: F,
        mode: Mode,
        config: PolicyConfig,
    ) -> Result<Self, ConfigError> {
        Ok(Self {
            policy: PathPolicy::new(mode, config, 0)?,
            config,
            started: Instant::now(),
            native: Side::new(dialer),
            fallback: Side::new(fallback),
            standby: mode == Mode::Standby,
            native_cmd: None,
            native_exhausted: false,
            dialer_closed: false,
            fallback_closed: false,
            closed: false,
        })
    }

    /// The path designated to carry payload.
    #[cfg(test)]
    pub(crate) fn active(&self) -> Option<PathKind> {
        self.policy.active()
    }

    /// A lease on the link of the active path, if one is designated and held. It is
    /// `None` while that path's link is gone, for example during loss grace.
    pub(crate) fn route(&self) -> Option<Route<D::Link, F::Link>> {
        match self.policy.active()? {
            PathKind::Native => self
                .native
                .link
                .as_ref()
                .map(|l| Route::Native(Arc::clone(l))),
            PathKind::Yggdrasil => self
                .fallback
                .link
                .as_ref()
                .map(|l| Route::Yggdrasil(Arc::clone(l))),
        }
    }

    /// The native budget was reported spent and no native link was installed since.
    #[cfg(test)]
    pub(crate) fn native_exhausted(&self) -> bool {
        self.native_exhausted
    }

    fn millis(&self, at: Instant) -> Millis {
        u64::try_from(at.saturating_duration_since(self.started).as_millis()).unwrap_or(u64::MAX)
    }

    fn instant(&self, millis: Millis) -> Instant {
        self.started + Duration::from_millis(millis)
    }

    /// Express a fixture observation in the policy's monotonic clock coordinates.
    #[cfg(test)]
    pub(crate) fn observation_time(&self, at: Instant) -> Millis {
        self.millis(at)
    }

    /// Shut down in dependency order: the policy is told first, then each side's
    /// task is cancelled and joined (which returns its dialer), then the native and
    /// the fallback dialer are closed. A failing close does not skip the other
    /// dialer; the first error is returned and a later call retries only what is
    /// still open. Idempotent. Leases held by consumers are not revoked.
    /// cancel-safe: yes — cancellation and joins resume, an interrupted backend
    /// close can be resumed.
    pub(crate) async fn close(&mut self) -> Result<(), DialError> {
        if self.closed {
            return Ok(());
        }
        let now = self.millis(Instant::now());
        self.policy.step(now, Event::Shutdown);
        self.native_cmd = None;
        self.native.cancel();
        self.native.join().await;
        self.native.link = None;
        self.fallback.cancel();
        self.fallback.join().await;
        self.fallback.link = None;

        let native = if self.dialer_closed {
            Ok(())
        } else {
            let result = match self.native.idle_dialer() {
                Some(dialer) => dialer.close().await,
                None => Err(DialError),
            };
            self.dialer_closed = result.is_ok();
            result
        };
        let fallback = if self.fallback_closed {
            Ok(())
        } else {
            let result = match self.fallback.idle_dialer() {
                Some(dialer) => dialer.close().await,
                None => Err(DialError),
            };
            self.fallback_closed = result.is_ok();
            result
        };
        native.and(fallback)?;
        self.closed = true;
        Ok(())
    }
}
