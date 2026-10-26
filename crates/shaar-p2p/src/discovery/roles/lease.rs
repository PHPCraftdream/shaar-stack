use std::{io, net::SocketAddr, task::Context};

use tokio::time::Instant;

use super::{AttemptKey, LeaseKind, View, denied};

/// A field of the complete dial future, retained through Noise and after Ready.
/// The transport must arm a timer at `deadline`; this registry does not spawn timers.
pub(crate) struct Lease {
    view: View,
    key: AttemptKey,
    kind: LeaseKind,
    slot: usize,
    deadline: Instant,
}

impl Lease {
    pub(super) fn new(
        view: View,
        key: AttemptKey,
        kind: LeaseKind,
        slot: usize,
        deadline: Instant,
    ) -> Self {
        Self {
            view,
            key,
            kind,
            slot,
            deadline,
        }
    }

    pub(crate) fn key(&self) -> AttemptKey {
        self.key
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(crate) fn check(&self) -> io::Result<()> {
        self.view.check(self.key, Instant::now()).map(|_| ())
    }

    /// Registration and admission share one critical section, preventing lost wakes.
    /// A successful check admits one subsequent poll, not retroactive I/O rollback.
    pub(crate) fn poll_check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        // Waker clone/drop may invoke foreign code, including registry reentry.
        let next = cx.waker().clone();
        let (previous, accepted) = {
            let mut state = self.view.lock();
            let closed = state.closed;
            let entry = state
                .attempts
                .get_mut(&self.key.connection)
                .ok_or_else(denied)?;
            if entry.key != self.key {
                return Err(denied());
            }
            let slot = entry.waiters[self.slot].as_mut().ok_or_else(denied)?;
            let previous = slot.waker.replace(next);
            let accepted =
                !closed && !entry.revoked && !entry.terminal && Instant::now() < entry.deadline;
            (previous, accepted)
        };
        drop(previous);
        if accepted { Ok(()) } else { Err(denied()) }
    }

    pub(crate) fn record_numeric(&self, endpoint: SocketAddr, now: Instant) -> io::Result<()> {
        if self.kind != LeaseKind::Numeric {
            return Err(denied());
        }
        self.view.record_numeric(self.key, endpoint, now)
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let (waiter, removed) = {
            let mut state = self.view.lock();
            let Some(entry) = state.attempts.get_mut(&self.key.connection) else {
                return;
            };
            if entry.key != self.key {
                return;
            }
            let waiter = entry.waiters[self.slot].take();
            entry.leases -= 1;
            if self.kind == LeaseKind::Root {
                entry.roots -= 1;
            }
            let removed = if entry.terminal && entry.leases == 0 {
                state.attempts.remove(&self.key.connection)
            } else {
                None
            };
            (waiter, removed)
        };
        drop(waiter);
        drop(removed);
    }
}
