// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The path owner against a scripted dialer under paused tokio time: every dial
//! happens at the instant the policy schedules it, so the offsets are exact.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::time::Instant;

use super::super::owner::{DialError, Dialer, EstablishError, PathOwner};
use super::{ConfigError, PathKind, PolicyConfig};

/// What one scripted dial does.
#[derive(Clone, Copy)]
enum Script {
    Succeed,
    Fail,
    /// Wait for the deadline, then fail, like a handshake that never completes.
    Hang,
}

#[derive(Default)]
struct Log {
    /// `(offset, deadline offset)` of every dial in milliseconds since the start.
    dials: Vec<(u64, u64)>,
    /// Lifecycle events in order: `"link dropped"` and `"dialer closed"`.
    events: Vec<&'static str>,
}

type Shared = Arc<Mutex<Log>>;

fn log(shared: &Shared) -> std::sync::MutexGuard<'_, Log> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

struct FakeLink(Shared);

impl Drop for FakeLink {
    fn drop(&mut self) {
        log(&self.0).events.push("link dropped");
    }
}

struct FakeDial {
    script: VecDeque<Script>,
    shared: Shared,
    start: Instant,
}

impl FakeDial {
    fn new(script: &[Script]) -> (Self, Shared) {
        let shared = Shared::default();
        let dial = Self {
            script: script.iter().copied().collect(),
            shared: Arc::clone(&shared),
            start: Instant::now(),
        };
        (dial, shared)
    }

    fn offset(&self, at: Instant) -> u64 {
        u64::try_from(at.duration_since(self.start).as_millis()).expect("small offset")
    }
}

impl Dialer for FakeDial {
    type Link = FakeLink;

    async fn dial(&mut self, deadline: Instant) -> Result<FakeLink, DialError> {
        let now = self.offset(Instant::now());
        let limit = self.offset(deadline);
        log(&self.shared).dials.push((now, limit));
        match self.script.pop_front().unwrap_or(Script::Fail) {
            Script::Succeed => Ok(FakeLink(Arc::clone(&self.shared))),
            Script::Fail => Err(DialError),
            Script::Hang => {
                tokio::time::sleep_until(deadline).await;
                Err(DialError)
            }
        }
    }

    async fn lost(&mut self, _: &FakeLink) {
        std::future::pending().await
    }

    async fn close(&mut self) -> Result<(), DialError> {
        log(&self.shared).events.push("dialer closed");
        Ok(())
    }
}

fn owner(script: &[Script], config: PolicyConfig) -> (PathOwner<FakeDial>, Shared) {
    let (dial, shared) = FakeDial::new(script);
    (
        PathOwner::new(dial, config).expect("valid parameters"),
        shared,
    )
}

fn dials(shared: &Shared) -> Vec<(u64, u64)> {
    log(shared).dials.clone()
}

fn events(shared: &Shared) -> Vec<&'static str> {
    log(shared).events.clone()
}

#[tokio::test(start_paused = true)]
async fn a_first_dial_that_succeeds_makes_native_the_payload_path() {
    let (mut owner, shared) = owner(&[Script::Succeed], PolicyConfig::default());
    assert!(
        owner.payload().is_none(),
        "no payload before the first dial"
    );
    assert_eq!(owner.active(), None);

    assert_eq!(owner.establish().await, Ok(()));

    assert_eq!(
        dials(&shared),
        [(0, 3_000)],
        "one dial, at once, with the attempt deadline"
    );
    assert_eq!(owner.active(), Some(PathKind::Native));
    assert!(owner.payload().is_some());
}

#[tokio::test(start_paused = true)]
async fn establishing_an_active_path_returns_at_once_without_another_dial() {
    let (mut owner, shared) = owner(&[Script::Succeed], PolicyConfig::default());
    owner.establish().await.expect("native established");
    let established_at = Instant::now();

    assert_eq!(owner.establish().await, Ok(()));
    assert_eq!(Instant::now(), established_at);
    tokio::time::advance(Duration::from_secs(10)).await;
    let later = Instant::now();
    assert_eq!(owner.establish().await, Ok(()));
    assert_eq!(Instant::now(), later);
    assert_eq!(dials(&shared), [(0, 3_000)]);
    assert!(events(&shared).is_empty(), "the original link stays alive");
    assert!(owner.payload().is_some());
}

#[tokio::test(start_paused = true)]
async fn failed_dials_are_retried_on_the_backoff_schedule() {
    let script = [Script::Fail, Script::Fail, Script::Fail, Script::Succeed];
    let (mut owner, shared) = owner(&script, PolicyConfig::default());

    assert_eq!(owner.establish().await, Ok(()));

    // Delays before attempts 2, 3 and 4 are 500, 1000 and 2000 ms.
    assert_eq!(
        dials(&shared),
        [(0, 3_000), (500, 3_500), (1_500, 4_500), (3_500, 6_500)]
    );
    assert!(owner.payload().is_some());
}

#[tokio::test(start_paused = true)]
async fn a_dial_that_hangs_ends_at_its_deadline_and_the_next_one_waits_the_backoff() {
    let (mut owner, shared) = owner(&[Script::Hang, Script::Succeed], PolicyConfig::default());

    assert_eq!(owner.establish().await, Ok(()));

    assert_eq!(dials(&shared), [(0, 3_000), (3_500, 6_500)]);
}

#[tokio::test(start_paused = true)]
async fn a_spent_budget_stops_after_exactly_max_attempts() {
    let config = PolicyConfig {
        max_attempts: 3,
        ..PolicyConfig::default()
    };
    let (mut owner, shared) = owner(&[Script::Fail, Script::Fail, Script::Fail], config);

    assert_eq!(owner.establish().await, Err(EstablishError::Exhausted));

    assert_eq!(dials(&shared), [(0, 3_000), (500, 3_500), (1_500, 4_500)]);
    assert!(owner.payload().is_none());
    assert_eq!(owner.active(), None);
    // The budget stays spent: a second call dials nothing more.
    assert_eq!(owner.establish().await, Err(EstablishError::Exhausted));
    assert_eq!(dials(&shared).len(), 3);
}

#[tokio::test(start_paused = true)]
async fn a_cancelled_establish_resumes_without_a_duplicate_attempt() {
    let (mut owner, shared) = owner(&[Script::Hang, Script::Succeed], PolicyConfig::default());

    let cancelled = tokio::time::timeout(Duration::from_secs(1), owner.establish()).await;
    assert!(cancelled.is_err(), "the first dial is still hanging");
    assert_eq!(dials(&shared), [(0, 3_000)]);

    assert_eq!(owner.establish().await, Ok(()));

    // The abandoned attempt expires at 3000 ms; the retry follows after the backoff.
    assert_eq!(dials(&shared), [(0, 3_000), (3_500, 6_500)]);
    assert!(owner.payload().is_some());
}

#[tokio::test(start_paused = true)]
async fn close_tells_the_policy_drops_the_link_then_joins_the_dialer() {
    let (mut owner, shared) = owner(&[Script::Succeed], PolicyConfig::default());
    owner.establish().await.expect("native established");

    assert_eq!(owner.close().await, Ok(()));

    assert_eq!(events(&shared), ["link dropped", "dialer closed"]);
    assert!(owner.payload().is_none());
    assert_eq!(owner.establish().await, Err(EstablishError::Closed));
    // Closing again changes nothing.
    assert_eq!(owner.close().await, Ok(()));
    assert_eq!(events(&shared), ["link dropped", "dialer closed"]);
}

#[tokio::test(start_paused = true)]
async fn closing_before_any_dial_closes_only_the_dialer() {
    let (mut owner, shared) = owner(&[Script::Succeed], PolicyConfig::default());

    assert_eq!(owner.close().await, Ok(()));

    assert_eq!(events(&shared), ["dialer closed"]);
    assert!(dials(&shared).is_empty());
    assert_eq!(owner.establish().await, Err(EstablishError::Closed));
    assert!(dials(&shared).is_empty(), "a closed owner never dials");
}

#[tokio::test(start_paused = true)]
async fn invalid_parameters_are_rejected_before_any_dial() {
    let config = PolicyConfig {
        attempt_timeout: 0,
        ..PolicyConfig::default()
    };
    let (dial, shared) = FakeDial::new(&[Script::Succeed]);

    let rejected = PathOwner::new(dial, config);

    assert!(matches!(
        rejected,
        Err(ConfigError::Zero("attempt_timeout"))
    ));
    assert!(dials(&shared).is_empty());
}
