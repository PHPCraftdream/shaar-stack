// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The shared negotiation composition against phase scripts and paused time.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

use super::super::owner::EstablishError;
use crate::path::{DialError, Dialer, Negotiating, Negotiation, PathOwner, PolicyConfig};

#[derive(Clone, Copy)]
enum Phase {
    Ready,
    Fail,
    Hang,
}

#[derive(Default)]
struct Log {
    native: Vec<(u64, u64)>,
    negotiate: Vec<(u64, u64)>,
    closed: usize,
}

type Shared = Arc<Mutex<Log>>;

struct Script {
    native: VecDeque<Phase>,
    negotiate: VecDeque<Phase>,
    log: Shared,
    start: Instant,
    first_loss: Option<u64>,
}

impl Script {
    fn offset(&self, at: Instant) -> u64 {
        u64::try_from(at.duration_since(self.start).as_millis()).expect("test offset")
    }
}

impl Dialer for Script {
    type Link = Option<Instant>;

    async fn dial(&mut self, deadline: Instant) -> Result<Self::Link, DialError> {
        let pair = (self.offset(Instant::now()), self.offset(deadline));
        let first = {
            let mut log = self.log.lock().expect("log");
            let first = log.native.is_empty();
            log.native.push(pair);
            first
        };
        match self.native.pop_front().expect("unexpected native phase") {
            Phase::Ready => Ok(if first {
                self.first_loss
                    .map(|at| self.start + Duration::from_millis(at))
            } else {
                None
            }),
            Phase::Fail => Err(DialError),
            Phase::Hang => std::future::pending().await,
        }
    }

    async fn lost(&mut self, link: &Self::Link) {
        match link {
            Some(at) => tokio::time::sleep_until(*at).await,
            None => std::future::pending().await,
        }
    }

    async fn close(&mut self) -> Result<(), DialError> {
        self.log.lock().expect("log").closed += 1;
        Ok(())
    }
}

impl Negotiation for Script {
    async fn negotiate(&mut self, deadline: Instant) -> Result<(), DialError> {
        let pair = (self.offset(Instant::now()), self.offset(deadline));
        self.log.lock().expect("log").negotiate.push(pair);
        match self.negotiate.pop_front().expect("unexpected negotiation") {
            Phase::Ready => Ok(()),
            Phase::Fail => Err(DialError),
            Phase::Hang => std::future::pending().await,
        }
    }
}

fn owner(
    native: &[Phase],
    negotiate: &[Phase],
    loss: Option<u64>,
) -> (PathOwner<Negotiating<Script>>, Shared) {
    let log = Shared::default();
    let script = Script {
        native: native.iter().copied().collect(),
        negotiate: negotiate.iter().copied().collect(),
        log: Arc::clone(&log),
        start: Instant::now(),
        first_loss: loss,
    };
    let config = PolicyConfig {
        loss_grace: 20,
        attempt_timeout: 40,
        backoff_base: 10,
        backoff_cap: 20,
        max_attempts: 3,
        stable_hold: 100,
    };
    (
        PathOwner::new(Negotiating::new(script), config).expect("config"),
        log,
    )
}

#[tokio::test(start_paused = true)]
async fn a_healthy_path_never_negotiates() {
    let (mut owner, log) = owner(&[Phase::Ready], &[], None);
    owner.establish().await.expect("native");
    owner.establish().await.expect("still native");
    assert!(
        tokio::time::timeout(Duration::from_millis(200), owner.maintain())
            .await
            .is_err()
    );
    let log = log.lock().expect("log");
    assert_eq!(log.native, [(0, 40)]);
    assert!(log.negotiate.is_empty());
}

#[tokio::test(start_paused = true)]
async fn successful_down_window_negotiation_precedes_native() {
    let (mut owner, log) = owner(&[Phase::Ready, Phase::Ready], &[Phase::Ready], Some(10));
    owner.establish().await.expect("native");
    owner.maintain().await.expect("recovered native");
    let log = log.lock().expect("log");
    assert_eq!(log.negotiate, [(20, 40)]);
    assert_eq!(log.native, [(0, 40), (20, 60)]);
}

#[tokio::test(start_paused = true)]
async fn failed_negotiation_does_not_skip_reachable_native() {
    let (mut owner, log) = owner(&[Phase::Ready, Phase::Ready], &[Phase::Fail], Some(10));
    owner.establish().await.expect("native");
    owner
        .maintain()
        .await
        .expect("native despite signaling failure");
    let log = log.lock().expect("log");
    assert_eq!(log.negotiate, [(20, 40)]);
    assert_eq!(log.native, [(0, 40), (20, 60)]);
}

#[tokio::test(start_paused = true)]
async fn hanging_negotiations_reserve_half_the_attempt_for_native() {
    let (mut owner, log) = owner(
        &[Phase::Ready, Phase::Fail, Phase::Ready],
        &[Phase::Hang, Phase::Hang],
        Some(10),
    );
    owner.establish().await.expect("native");
    owner
        .maintain()
        .await
        .expect("native phases remain reachable");
    let log = log.lock().expect("log");
    assert_eq!(log.negotiate, [(20, 40), (60, 80)]);
    assert_eq!(log.native, [(0, 40), (40, 60), (80, 100)]);
}

#[tokio::test(start_paused = true)]
async fn a_hanging_native_phase_still_ends_at_the_original_deadline() {
    let (mut owner, log) = owner(
        &[Phase::Ready, Phase::Hang, Phase::Ready],
        &[Phase::Ready, Phase::Ready],
        Some(10),
    );
    owner.establish().await.expect("native");
    owner
        .maintain()
        .await
        .expect("native retry after original deadline");
    let log = log.lock().expect("log");
    assert_eq!(log.negotiate, [(20, 40), (80, 100)]);
    assert_eq!(log.native, [(0, 40), (20, 60), (80, 120)]);
}

#[tokio::test(start_paused = true)]
async fn exhaustion_still_includes_every_uncancelled_native_phase() {
    let (mut owner, log) = owner(
        &[Phase::Ready, Phase::Fail, Phase::Fail],
        &[Phase::Hang, Phase::Hang],
        Some(10),
    );
    owner.establish().await.expect("native");
    assert_eq!(owner.maintain().await, Err(EstablishError::Exhausted));
    assert_eq!(owner.maintain().await, Err(EstablishError::Exhausted));
    let log = log.lock().expect("log");
    assert_eq!(log.negotiate, [(20, 40), (60, 80)]);
    assert_eq!(log.native, [(0, 40), (40, 60), (80, 100)]);
}

#[tokio::test(start_paused = true)]
async fn cancelled_negotiation_resumes_without_a_duplicate_attempt() {
    let (mut owner, log) = owner(
        &[Phase::Ready, Phase::Ready],
        &[Phase::Hang, Phase::Hang],
        Some(10),
    );
    owner.establish().await.expect("native");
    assert!(
        tokio::time::timeout(Duration::from_millis(25), owner.maintain())
            .await
            .is_err()
    );
    owner.maintain().await.expect("resumed recovery");
    let log = log.lock().expect("log");
    assert_eq!(log.negotiate, [(20, 40), (80, 100)]);
    assert_eq!(log.native, [(0, 40), (100, 120)]);
}

#[tokio::test(start_paused = true)]
async fn shutdown_after_cancelled_negotiation_joins_once() {
    let (mut owner, log) = owner(&[Phase::Ready], &[Phase::Hang], Some(10));
    owner.establish().await.expect("native");
    assert!(
        tokio::time::timeout(Duration::from_millis(25), owner.maintain())
            .await
            .is_err()
    );
    owner.close().await.expect("joined");
    owner.close().await.expect("already joined");
    assert_eq!(owner.maintain().await, Err(EstablishError::Closed));
    let log = log.lock().expect("log");
    assert_eq!(log.closed, 1);
    assert_eq!(log.native, [(0, 40)]);
    assert_eq!(log.negotiate, [(20, 40)]);
}
