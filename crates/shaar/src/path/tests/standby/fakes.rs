// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Scripted dialers shared by the standby tests. Every dial, completion, drop and
//! close is recorded against the paused clock, so a test asserts exact offsets.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::time::{Instant, sleep_until, timeout};

use crate::path::{DialError, Dialer, Mode, PathKind, PolicyConfig, Route, StandbyOwner};

/// What one scripted dial does; an exhausted script fails at once.
#[derive(Clone, Copy)]
pub(super) enum Dial {
    /// Connect at once; the link is lost at the given offset, never when `None`.
    Up(Option<u64>),
    Fail,
    /// Never finish; only the owner's deadline ends it.
    Hang,
    /// Connect successfully at an absolute offset, whatever the dial started at.
    Slow {
        ready_at_ms: u64,
        loss: Option<u64>,
    },
}

/// Everything one fake dialer observed, in milliseconds since the rig start.
#[derive(Default)]
pub(super) struct Log {
    /// `(start, deadline)` of every dial.
    pub(super) dials: Vec<(u64, u64)>,
    /// `(offset, succeeded)` of every dial that ran to its own end.
    pub(super) completed: Vec<(u64, bool)>,
    /// Dial futures dropped before they completed (cancelled or timed out).
    pub(super) dropped_mid_dial: usize,
    /// Link values dropped, that is, closed.
    pub(super) links_dropped: usize,
    /// Successful `close` calls.
    pub(super) closed: usize,
}

pub(super) type Shared = Arc<Mutex<Log>>;
/// Close order across both dialers: "native closed", "fallback closed".
pub(super) type Events = Arc<Mutex<Vec<&'static str>>>;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(super) fn log(shared: &Shared) -> MutexGuard<'_, Log> {
    lock(shared)
}

pub(super) fn dials(shared: &Shared) -> Vec<(u64, u64)> {
    lock(shared).dials.clone()
}

pub(super) fn completed(shared: &Shared) -> Vec<(u64, bool)> {
    lock(shared).completed.clone()
}

pub(super) fn closes(events: &Events) -> Vec<&'static str> {
    lock(events).clone()
}

/// The link value; dropping the last handle counts as closing it.
pub(super) struct FakeLink {
    lost_at: Option<Instant>,
    shared: Shared,
}

impl Drop for FakeLink {
    fn drop(&mut self) {
        lock(&self.shared).links_dropped += 1;
    }
}

/// Counts a dial future that is dropped before it reached its end.
struct DialGuard {
    shared: Shared,
    done: bool,
}

impl Drop for DialGuard {
    fn drop(&mut self) {
        if !self.done {
            lock(&self.shared).dropped_mid_dial += 1;
        }
    }
}

pub(super) struct FakeDial {
    name: &'static str,
    script: VecDeque<Dial>,
    shared: Shared,
    events: Events,
    start: Instant,
    close_failures: usize,
    close_ready_at: Option<u64>,
}

impl FakeDial {
    /// A dialer whose `close` records `name` (for example "native closed").
    pub(super) fn new(
        name: &'static str,
        script: &[Dial],
        events: &Events,
        start: Instant,
    ) -> (Self, Shared) {
        let shared = Shared::default();
        let dialer = Self {
            name,
            script: script.iter().copied().collect(),
            shared: Arc::clone(&shared),
            events: Arc::clone(events),
            start,
            close_failures: 0,
            close_ready_at: None,
        };
        (dialer, shared)
    }

    /// The first `count` calls of `close` fail without recording anything.
    pub(super) fn failing_close(mut self, count: usize) -> Self {
        self.close_failures = count;
        self
    }

    /// `close` is pending until this absolute offset, so a test can cancel it midway.
    /// The wait is absolute, so an interrupted close resumes where it left off.
    pub(super) fn slow_close(mut self, ready_at_ms: u64) -> Self {
        self.close_ready_at = Some(ready_at_ms);
        self
    }

    fn offset(&self, at: Instant) -> u64 {
        u64::try_from(at.duration_since(self.start).as_millis()).expect("test offset")
    }

    fn at(&self, millis: u64) -> Instant {
        self.start + Duration::from_millis(millis)
    }

    fn link(&self, loss: Option<u64>) -> FakeLink {
        FakeLink {
            lost_at: loss.map(|millis| self.at(millis)),
            shared: Arc::clone(&self.shared),
        }
    }
}

impl Dialer for FakeDial {
    type Link = FakeLink;

    async fn dial(&mut self, deadline: Instant) -> Result<FakeLink, DialError> {
        let mut guard = {
            let begun = self.offset(Instant::now());
            let limit = self.offset(deadline);
            lock(&self.shared).dials.push((begun, limit));
            DialGuard {
                shared: Arc::clone(&self.shared),
                done: false,
            }
        };
        let result = match self.script.pop_front().unwrap_or(Dial::Fail) {
            Dial::Up(loss) => Ok(self.link(loss)),
            Dial::Fail => Err(DialError),
            Dial::Slow { ready_at_ms, loss } => {
                sleep_until(self.at(ready_at_ms)).await;
                Ok(self.link(loss))
            }
            Dial::Hang => std::future::pending().await,
        };
        guard.done = true;
        let ended = self.offset(Instant::now());
        lock(&self.shared).completed.push((ended, result.is_ok()));
        result
    }

    /// Level-triggered from the scripted instant: a loss in the past resolves at once.
    async fn lost(&mut self, link: &FakeLink) {
        match link.lost_at {
            Some(at) => sleep_until(at).await,
            None => std::future::pending().await,
        }
    }

    async fn close(&mut self) -> Result<(), DialError> {
        if let Some(ready_at) = self.close_ready_at {
            sleep_until(self.at(ready_at)).await;
        }
        if self.close_failures > 0 {
            self.close_failures -= 1;
            return Err(DialError);
        }
        lock(&self.shared).closed += 1;
        lock(&self.events).push(self.name);
        Ok(())
    }
}

pub(super) struct Rig {
    pub(super) owner: StandbyOwner<FakeDial, FakeDial>,
    pub(super) native: Shared,
    pub(super) fallback: Shared,
    pub(super) events: Events,
    pub(super) start: Instant,
}

impl Rig {
    pub(super) fn native_dials(&self) -> Vec<(u64, u64)> {
        dials(&self.native)
    }

    pub(super) fn fallback_dials(&self) -> Vec<(u64, u64)> {
        dials(&self.fallback)
    }

    pub(super) fn closes(&self) -> Vec<&'static str> {
        closes(&self.events)
    }
}

/// Build a rig from prepared dialers, for example ones with scripted close failures.
pub(super) fn rig_with(
    native: (FakeDial, Shared),
    fallback: (FakeDial, Shared),
    events: Events,
    mode: Mode,
    config: PolicyConfig,
) -> Rig {
    let start = native.0.start;
    Rig {
        owner: StandbyOwner::new(native.0, fallback.0, mode, config).expect("config"),
        native: native.1,
        fallback: fallback.1,
        events,
        start,
    }
}

pub(super) fn rig(native: &[Dial], fallback: &[Dial], mode: Mode, config: PolicyConfig) -> Rig {
    let events = Events::default();
    let start = Instant::now();
    let native = FakeDial::new("native closed", native, &events, start);
    let fallback = FakeDial::new("fallback closed", fallback, &events, start);
    rig_with(native, fallback, events, mode, config)
}

pub(super) fn config() -> PolicyConfig {
    PolicyConfig {
        loss_grace: 20,
        attempt_timeout: 30,
        backoff_base: 5,
        backoff_cap: 20,
        max_attempts: 3,
        stable_hold: 50,
    }
}

/// Enough attempts that the native budget is not spent in the scenario.
pub(super) fn roomy() -> PolicyConfig {
    PolicyConfig {
        max_attempts: 20,
        ..config()
    }
}

/// Milliseconds elapsed on the paused clock since `start`.
pub(super) fn ms(start: Instant) -> u64 {
    u64::try_from(Instant::now().duration_since(start).as_millis()).expect("test offset")
}

pub(super) fn kind<N, Y>(route: Option<Route<N, Y>>) -> Option<PathKind> {
    route.map(|route| match route {
        Route::Native(_) => PathKind::Native,
        Route::Yggdrasil(_) => PathKind::Yggdrasil,
    })
}

/// The native lease of a route; any other route is a test failure.
pub(super) fn native_lease<N, Y>(route: Option<Route<N, Y>>) -> Arc<N> {
    match route {
        Some(Route::Native(lease)) => lease,
        _ => panic!("expected a native route"),
    }
}

/// The output of `future` if it finished within `millis`; otherwise it is dropped.
pub(super) async fn within<T>(millis: u64, future: impl Future<Output = T>) -> Option<T> {
    timeout(Duration::from_millis(millis), future).await.ok()
}

/// The Yggdrasil lease of a route; any other route is a test failure.
pub(super) fn ygg_lease<N, Y>(route: Option<Route<N, Y>>) -> Arc<Y> {
    match route {
        Some(Route::Yggdrasil(lease)) => lease,
        _ => panic!("expected a yggdrasil route"),
    }
}

/// True when `future` was still pending after `millis` and was dropped.
pub(super) async fn cancelled_after<T>(millis: u64, future: impl Future<Output = T>) -> bool {
    within(millis, future).await.is_none()
}
