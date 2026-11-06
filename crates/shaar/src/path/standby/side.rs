// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
//! One retained side of the standby owner: a dialer, its held link and at most one
//! boxed task.
//!
//! The dialer moves by value into the single task that needs it (a dial or a loss
//! watch) and comes back inside `Done` when that task completes. Between `follow`
//! calls the task simply stays parked in its `Busy` slot, so work survives the
//! return or cancellation of any caller future. Dropping a `Busy` aborts its task;
//! only the owner's `close` joins it.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::oneshot;
use tokio::time::{Instant, timeout_at};

use super::super::owner::{DialError, Dialer};

/// How a task ended.
pub(super) enum Outcome<L> {
    /// A dial ended; a link completed after its deadline is reported as an error.
    Dialed(Result<L, DialError>),
    /// The watched link was lost.
    Lost,
    /// The owner cancelled the task while closing.
    Cancelled,
}

/// A finished task that hands the dialer back.
pub(super) struct Done<T: Dialer> {
    pub(super) dialer: T,
    pub(super) outcome: Outcome<T::Link>,
    /// The policy's attempt number for a native dial; unused otherwise.
    pub(super) attempt: u64,
}

/// The one running task of a side.
pub(super) struct Busy<T: Dialer> {
    // `'static` and not `Send`: it is polled only by the caller of the owner.
    task: Pin<Box<dyn Future<Output = Done<T>>>>,
    /// Taken by `cancel`; a task whose sender is gone is simply awaited.
    cancel: Option<oneshot::Sender<()>>,
}

pub(super) enum State<T: Dialer> {
    Idle(T),
    Busy(Busy<T>),
    /// Transient inside synchronous functions only; never observable across an await.
    Gone,
}

pub(super) struct Side<T>
where
    T: Dialer + 'static,
    T::Link: 'static,
{
    pub(super) state: State<T>,
    /// Count of links installed; the identity of the held link.
    pub(super) generation: u64,
    /// The owner's handle; consumers may hold more clones.
    pub(super) link: Option<Arc<T::Link>>,
    /// Earliest start of the next fallback dial; unused by the native side.
    pub(super) pause_until: Option<Instant>,
}

impl<T> Side<T>
where
    T: Dialer + 'static,
    T::Link: 'static,
{
    pub(super) fn new(dialer: T) -> Self {
        Self {
            state: State::Idle(dialer),
            generation: 0,
            link: None,
            pause_until: None,
        }
    }

    pub(super) fn is_idle(&self) -> bool {
        matches!(self.state, State::Idle(_))
    }

    fn take_idle(&mut self) -> Option<T> {
        match std::mem::replace(&mut self.state, State::Gone) {
            State::Idle(dialer) => Some(dialer),
            other => {
                self.state = other;
                None
            }
        }
    }

    /// Store a fresh link and return its generation.
    pub(super) fn install(&mut self, link: T::Link) -> u64 {
        self.generation += 1;
        self.link = Some(Arc::new(link));
        self.generation
    }

    /// Start one dial that gives up at the absolute `deadline`. No-op unless idle.
    pub(super) fn start_dial(&mut self, attempt: u64, deadline: Instant) {
        let Some(dialer) = self.take_idle() else {
            return;
        };
        let (cancel, mut cancel_rx) = oneshot::channel::<()>();
        let task = async move {
            let mut dialer = dialer;
            let outcome = tokio::select! {
                biased;
                _ = &mut cancel_rx => Outcome::Cancelled,
                result = timeout_at(deadline, dialer.dial(deadline)) => {
                    // Same rule as the native-only owner: a late link is dropped.
                    Outcome::Dialed(match result {
                        Ok(Ok(link)) if Instant::now() < deadline => Ok(link),
                        _ => Err(DialError),
                    })
                }
            };
            Done {
                dialer,
                outcome,
                attempt,
            }
        };
        self.state = State::Busy(Busy {
            task: Box::pin(task),
            cancel: Some(cancel),
        });
    }

    /// Start watching the held link for loss. No-op unless idle with a link.
    pub(super) fn start_watch(&mut self) {
        let Some(link) = self.link.clone() else {
            return;
        };
        let Some(dialer) = self.take_idle() else {
            return;
        };
        let (cancel, mut cancel_rx) = oneshot::channel::<()>();
        let task = async move {
            let mut dialer = dialer;
            let outcome = tokio::select! {
                biased;
                _ = &mut cancel_rx => Outcome::Cancelled,
                () = dialer.lost(&*link) => Outcome::Lost,
            };
            Done {
                dialer,
                outcome,
                attempt: 0,
            }
        };
        self.state = State::Busy(Busy {
            task: Box::pin(task),
            cancel: Some(cancel),
        });
    }

    /// Ask the running task, if any, to stop. Idempotent.
    pub(super) fn cancel(&mut self) {
        let State::Busy(busy) = &mut self.state else {
            return;
        };
        if let Some(cancel) = busy.cancel.take() {
            // A task that already finished has dropped its receiver; that is fine.
            let _ = cancel.send(());
        }
    }

    /// Await the running task and park its dialer again. Cancel-safe: the state
    /// is replaced only after the task completed. Returns at once when idle.
    pub(super) async fn join(&mut self) {
        if let State::Busy(busy) = &mut self.state {
            let done = busy.task.as_mut().await;
            self.state = State::Idle(done.dialer);
        }
    }

    /// The dialer, if no task holds it.
    pub(super) fn idle_dialer(&mut self) -> Option<&mut T> {
        match &mut self.state {
            State::Idle(dialer) => Some(dialer),
            _ => None,
        }
    }
}

/// Completion of the running task. Pending when idle. Cancel-safe: the state is
/// untouched until the caller handles the returned `Done` synchronously.
pub(super) async fn finished<T>(side: &mut Side<T>) -> Done<T>
where
    T: Dialer + 'static,
    T::Link: 'static,
{
    match &mut side.state {
        State::Busy(busy) => busy.task.as_mut().await,
        _ => std::future::pending().await,
    }
}
