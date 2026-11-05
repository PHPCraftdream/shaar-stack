// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Loss and recovery contracts under an injected, paused monotonic clock.

use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use tokio::time::Instant;

use super::super::owner::{DialError, Dialer, EstablishError, PathOwner};
use super::{PathKind, PolicyConfig};

#[derive(Clone, Copy)]
enum Dial {
    Up(Option<u64>),
    Fail,
    Hang,
}

#[derive(Default)]
struct Log {
    dials: Vec<(u64, u64)>,
    dropped: usize,
    closed: usize,
    losses: usize,
}

type Shared = Arc<Mutex<Log>>;

struct Link {
    lost_at: Option<Instant>,
    log: Shared,
}

impl Drop for Link {
    fn drop(&mut self) {
        self.log.lock().expect("test log").dropped += 1;
    }
}

struct RecoveryDial {
    script: VecDeque<Dial>,
    log: Shared,
    start: Instant,
    close_at: Option<Instant>,
}

impl Dialer for RecoveryDial {
    type Link = Link;

    async fn dial(&mut self, deadline: Instant) -> Result<Link, DialError> {
        let offset = |instant: Instant| {
            u64::try_from(instant.duration_since(self.start).as_millis()).expect("test offset")
        };
        self.log
            .lock()
            .expect("test log")
            .dials
            .push((offset(Instant::now()), offset(deadline)));
        match self.script.pop_front().expect("unexpected extra dial") {
            Dial::Up(loss) => Ok(Link {
                lost_at: loss.map(|at| self.start + Duration::from_millis(at)),
                log: Arc::clone(&self.log),
            }),
            Dial::Fail => Err(DialError),
            Dial::Hang => std::future::pending().await,
        }
    }

    async fn lost(&mut self, link: &Link) {
        match link.lost_at {
            Some(at) => tokio::time::sleep_until(at).await,
            None => std::future::pending().await,
        }
        self.log.lock().expect("test log").losses += 1;
    }

    async fn close(&mut self) -> Result<(), DialError> {
        if let Some(at) = self.close_at {
            tokio::time::sleep_until(at).await;
        }
        self.log.lock().expect("test log").closed += 1;
        Ok(())
    }
}

fn config() -> PolicyConfig {
    PolicyConfig {
        loss_grace: 20,
        attempt_timeout: 30,
        backoff_base: 5,
        backoff_cap: 20,
        max_attempts: 3,
        stable_hold: 50,
    }
}

fn owner(script: &[Dial]) -> (PathOwner<RecoveryDial>, Shared) {
    let log = Shared::default();
    let dial = RecoveryDial {
        script: script.iter().copied().collect(),
        log: Arc::clone(&log),
        start: Instant::now(),
        close_at: None,
    };
    (PathOwner::new(dial, config()).expect("config"), log)
}

fn dials(log: &Shared) -> Vec<(u64, u64)> {
    log.lock().expect("test log").dials.clone()
}

async fn poll_once<F: Future>(future: F) -> Option<F::Output> {
    tokio::pin!(future);
    poll_fn(|cx| {
        Poll::Ready(match future.as_mut().poll(cx) {
            Poll::Ready(value) => Some(value),
            Poll::Pending => None,
        })
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_same_kind_restore_inside_grace_returns_without_waiting_for_a_use_edge() {
    let (mut owner, log) = owner(&[Dial::Up(Some(10)), Dial::Up(None)]);
    owner.establish().await.expect("initial path");
    let start = Instant::now();
    owner.maintain().await.expect("restored during grace");
    assert_eq!(Instant::now() - start, Duration::from_millis(15));
    assert_eq!(dials(&log), [(0, 30), (15, 45)]);
    assert_eq!(owner.active(), Some(PathKind::Native));
    assert!(owner.payload().is_some());
    assert_eq!(log.lock().expect("log").dropped, 1);
}

#[tokio::test(start_paused = true)]
async fn healthy_hold_refills_the_budget_before_a_later_loss() {
    let (mut owner, log) = owner(&[Dial::Up(Some(100)), Dial::Fail, Dial::Fail, Dial::Up(None)]);
    owner.establish().await.expect("initial path");
    owner.maintain().await.expect("refilled recovery budget");
    assert_eq!(dials(&log), [(0, 30), (100, 130), (105, 135), (115, 145)]);
    assert!(owner.payload().is_some());
}

#[tokio::test(start_paused = true)]
async fn grace_expires_even_while_a_retry_dial_is_pending() {
    let (mut owner, log) = owner(&[Dial::Up(Some(10)), Dial::Hang, Dial::Up(None)]);
    owner.establish().await.expect("initial path");
    assert!(
        tokio::time::timeout(Duration::from_millis(29), owner.maintain())
            .await
            .is_err()
    );
    assert!(owner.payload().is_none());
    assert_eq!(owner.active(), Some(PathKind::Native));
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(poll_once(owner.maintain()).await.is_none());
    assert_eq!(owner.active(), None, "grace ends at exactly 30 ms");
    owner.maintain().await.expect("restore after NoPath");
    assert_eq!(dials(&log), [(0, 30), (15, 45), (55, 85)]);
    assert!(owner.payload().is_some());
}

#[tokio::test(start_paused = true)]
async fn a_live_hanging_dial_preserves_the_grace_timer_and_retry_deadline() {
    let (mut owner, log) = owner(&[Dial::Up(Some(10)), Dial::Hang, Dial::Up(None)]);
    owner.establish().await.expect("initial path");
    owner.maintain().await.expect("restore after timeout");
    assert_eq!(dials(&log), [(0, 30), (15, 45), (55, 85)]);
    assert!(owner.payload().is_some());
}

#[tokio::test(start_paused = true)]
async fn the_grace_timer_runs_before_a_live_dial_finishes() {
    let (mut owner, log) = owner(&[Dial::Up(Some(10)), Dial::Hang, Dial::Up(None)]);
    owner.establish().await.expect("initial path");
    assert!(
        tokio::time::timeout(Duration::from_millis(31), owner.maintain())
            .await
            .is_err()
    );
    assert_eq!(
        owner.active(),
        None,
        "the 30 ms grace fired before dial deadline 45 ms"
    );
    assert!(owner.payload().is_none());
    owner.maintain().await.expect("resume after grace");
    assert_eq!(dials(&log), [(0, 30), (15, 45), (55, 85)]);
}

#[tokio::test(start_paused = true)]
async fn a_spent_recovery_budget_never_starts_an_extra_dial() {
    let (mut owner, log) = owner(&[Dial::Up(Some(10)), Dial::Fail, Dial::Fail]);
    owner.establish().await.expect("initial path");
    assert_eq!(owner.maintain().await, Err(EstablishError::Exhausted));
    assert_eq!(owner.maintain().await, Err(EstablishError::Exhausted));
    assert_eq!(dials(&log), [(0, 30), (15, 45), (25, 55)]);
    assert!(owner.payload().is_none());
}

#[tokio::test(start_paused = true)]
async fn cancelling_loss_observation_does_not_lose_or_duplicate_the_event() {
    let (mut owner, log) = owner(&[Dial::Up(Some(10)), Dial::Up(None)]);
    owner.establish().await.expect("initial path");
    assert!(
        tokio::time::timeout(Duration::from_millis(5), owner.maintain())
            .await
            .is_err()
    );
    assert!(owner.payload().is_some());
    owner
        .maintain()
        .await
        .expect("loss observed after resuming");
    assert_eq!(log.lock().expect("log").losses, 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), owner.maintain())
            .await
            .is_err()
    );
    assert_eq!(
        log.lock().expect("log").losses,
        1,
        "the old link cannot report another loss"
    );
    assert_eq!(dials(&log), [(0, 30), (15, 45)]);
}

#[tokio::test(start_paused = true)]
async fn a_loss_at_the_hold_boundary_does_not_refill_a_down_path() {
    let (mut owner, log) = owner(&[Dial::Up(Some(50)), Dial::Up(None)]);
    owner.establish().await.expect("initial path");
    owner.maintain().await.expect("recovery");
    assert_eq!(dials(&log), [(0, 30), (55, 85)]);
}

#[tokio::test(start_paused = true)]
async fn shutdown_in_the_down_window_cannot_restart_the_dialer() {
    let (mut owner, log) = owner(&[Dial::Up(Some(10)), Dial::Hang]);
    owner.establish().await.expect("initial path");
    assert!(
        tokio::time::timeout(Duration::from_millis(12), owner.maintain())
            .await
            .is_err()
    );
    owner.close().await.expect("closed");
    assert_eq!(owner.maintain().await, Err(EstablishError::Closed));
    assert_eq!(owner.establish().await, Err(EstablishError::Closed));
    assert_eq!(dials(&log), [(0, 30)]);
    assert_eq!(log.lock().expect("log").dropped, 1);
    assert_eq!(log.lock().expect("log").closed, 1);
}

#[tokio::test(start_paused = true)]
async fn a_cancelled_close_is_resumed_until_the_backend_is_joined() {
    let log = Shared::default();
    let dial = RecoveryDial {
        script: [Dial::Up(None)].into_iter().collect(),
        log: Arc::clone(&log),
        start: Instant::now(),
        close_at: Some(Instant::now() + Duration::from_millis(50)),
    };
    let mut owner = PathOwner::new(dial, config()).expect("config");
    owner.establish().await.expect("initial path");
    assert!(
        tokio::time::timeout(Duration::from_millis(10), owner.close())
            .await
            .is_err()
    );
    assert!(owner.payload().is_none());
    assert_eq!(owner.maintain().await, Err(EstablishError::Closed));
    assert_eq!(log.lock().expect("log").closed, 0);
    owner.close().await.expect("backend join resumed");
    owner.close().await.expect("idempotent joined close");
    assert_eq!(log.lock().expect("log").dropped, 1);
    assert_eq!(log.lock().expect("log").closed, 1);
}
