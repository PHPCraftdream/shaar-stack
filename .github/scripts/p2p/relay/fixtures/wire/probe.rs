#![forbid(unsafe_code)]
//! Observations and scheduling barriers in the isolated wire fixture only.

use futures::task::AtomicWaker;
use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

pub const BUILD_VARIANT: &str = "baseline";
static MODE: AtomicUsize = AtomicUsize::new(0);
static ARMED: AtomicBool = AtomicBool::new(false);
static HOLD: AtomicBool = AtomicBool::new(false);
static BLOCKED: AtomicBool = AtomicBool::new(false);
static REVOKED: AtomicBool = AtomicBool::new(false);
static RESUMED: AtomicBool = AtomicBool::new(false);
static NEGOTIATED: AtomicUsize = AtomicUsize::new(0);
static RESERVE_STARTED: AtomicUsize = AtomicUsize::new(0);
static RESERVE_SERIALIZED: AtomicUsize = AtomicUsize::new(0);
static CONNECT_STARTED: AtomicUsize = AtomicUsize::new(0);
static REQUESTS: AtomicUsize = AtomicUsize::new(0);
static REUSE: AtomicUsize = AtomicUsize::new(0);
static CANCEL: Mutex<Option<Box<dyn FnOnce() + Send>>> = Mutex::new(None);
static OBSERVER: AtomicWaker = AtomicWaker::new();
static PROTOCOL: AtomicWaker = AtomicWaker::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Protocol = 1,
    Renewal = 2,
    Reuse = 3,
}

#[derive(Clone, Copy, Debug)]
pub struct Snapshot {
    pub blocked: bool,
    pub revoked: bool,
    pub resumed: bool,
    pub negotiated: usize,
    pub reserve_started: usize,
    pub reserve_serialized: usize,
    pub connect_started: usize,
    pub requests: usize,
    pub reuse: usize,
}

/// Called only after the preceding fixture's executor was joined.
pub fn reset(phase: Phase) {
    let previous = CANCEL.lock().unwrap().take();
    drop(previous);
    MODE.store(phase as usize, Ordering::SeqCst);
    for flag in [&ARMED, &HOLD, &BLOCKED, &REVOKED, &RESUMED] {
        flag.store(false, Ordering::SeqCst);
    }
    for count in [
        &NEGOTIATED,
        &RESERVE_STARTED,
        &RESERVE_SERIALIZED,
        &CONNECT_STARTED,
        &REQUESTS,
        &REUSE,
    ] {
        count.store(0, Ordering::SeqCst);
    }
}

pub fn arm(cancel: impl FnOnce() + Send + 'static) {
    let previous = CANCEL.lock().unwrap().replace(Box::new(cancel));
    drop(previous);
    ARMED.store(true, Ordering::SeqCst);
}

pub fn snapshot() -> Snapshot {
    Snapshot {
        blocked: BLOCKED.load(Ordering::SeqCst),
        revoked: REVOKED.load(Ordering::SeqCst),
        resumed: RESUMED.load(Ordering::SeqCst),
        negotiated: NEGOTIATED.load(Ordering::SeqCst),
        reserve_started: RESERVE_STARTED.load(Ordering::SeqCst),
        reserve_serialized: RESERVE_SERIALIZED.load(Ordering::SeqCst),
        connect_started: CONNECT_STARTED.load(Ordering::SeqCst),
        requests: REQUESTS.load(Ordering::SeqCst),
        reuse: REUSE.load(Ordering::SeqCst),
    }
}

pub fn poll_observation(
    cx: &mut Context<'_>,
    predicate: impl FnOnce(Snapshot) -> bool,
) -> Poll<()> {
    OBSERVER.register(cx.waker());
    if predicate(snapshot()) {
        Poll::Ready(())
    } else {
        Poll::Pending
    }
}

fn revoke() {
    let cancel = CANCEL.lock().unwrap().take();
    if let Some(cancel) = cancel {
        cancel();
        REVOKED.store(true, Ordering::SeqCst);
        OBSERVER.wake();
    }
}

pub fn release_protocol() {
    // The barrier precedes the next independent protocol admission, not its I/O.
    revoke();
    HOLD.store(false, Ordering::SeqCst);
    PROTOCOL.wake();
}

pub(crate) fn negotiated(success: bool) {
    if !success {
        return;
    }
    let count = NEGOTIATED.fetch_add(1, Ordering::SeqCst) + 1;
    if count >= 3
        && ARMED.load(Ordering::SeqCst)
        && MODE.load(Ordering::SeqCst) == Phase::Protocol as usize
    {
        HOLD.store(true, Ordering::SeqCst);
    }
    OBSERVER.wake();
}

pub(crate) fn before_protocol_poll(cx: &mut Context<'_>) -> Poll<()> {
    PROTOCOL.register(cx.waker());
    if HOLD.load(Ordering::SeqCst) {
        BLOCKED.store(true, Ordering::SeqCst);
        OBSERVER.wake();
        return Poll::Pending;
    }
    Poll::Ready(())
}

pub(crate) fn after_protocol_poll() {
    if BLOCKED.load(Ordering::SeqCst) && !HOLD.load(Ordering::SeqCst) {
        RESUMED.store(true, Ordering::SeqCst);
        OBSERVER.wake();
    }
}

pub(crate) fn before_renewal() {
    if ARMED.load(Ordering::SeqCst) && MODE.load(Ordering::SeqCst) == Phase::Renewal as usize {
        revoke();
    }
}

pub(crate) fn before_reuse() {
    if ARMED.load(Ordering::SeqCst) && MODE.load(Ordering::SeqCst) == Phase::Reuse as usize {
        revoke();
    }
}

pub(crate) fn request_admitted() {
    REQUESTS.fetch_add(1, Ordering::SeqCst);
    OBSERVER.wake();
}
pub(crate) fn reuse_admitted() {
    REUSE.fetch_add(1, Ordering::SeqCst);
    OBSERVER.wake();
}
pub(crate) fn reserve_started() {
    RESERVE_STARTED.fetch_add(1, Ordering::SeqCst);
    OBSERVER.wake();
}
pub(crate) fn reserve_serialized() {
    RESERVE_SERIALIZED.fetch_add(1, Ordering::SeqCst);
    OBSERVER.wake();
}
pub(crate) fn connect_started() {
    CONNECT_STARTED.fetch_add(1, Ordering::SeqCst);
    OBSERVER.wake();
}
