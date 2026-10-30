//! Infrastructure-only lifecycle records share the ordinary owner mutex.

use libp2p::{PeerId, swarm::ConnectionId};
use std::net::SocketAddr;

use super::{AttemptKey, Owner, State};

mod referrals;
pub(crate) use referrals::Epoch;
pub(super) use referrals::{Admission, Hint};

/// Counted permit whose only effect is its exact row's count and Drop.
pub(crate) struct Permit {
    view: super::View,
    key: AttemptKey,
}

pub(super) fn collect(state: &mut State) {
    for slot in &mut state.infrastructure {
        let reclaim = slot.as_ref().is_some_and(|row| {
            row.native_terminal
                && row.connection_terminal
                && row.permits == 0
                && state
                    .attempts
                    .get(&row.key.connection)
                    .is_none_or(|attempt| attempt.key != row.key || attempt.leases == 0)
        });
        if reclaim {
            *slot = None;
        }
    }
}

impl Owner {
    /// Reserve capacity and reject retained connection IDs before staging.
    pub(crate) fn stage_infrastructure(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
        deadline: tokio::time::Instant,
        now: tokio::time::Instant,
        root: super::Root,
    ) -> std::io::Result<(AttemptKey, Permit)> {
        if self.view().role(peer) != Some(super::Role::Infrastructure) {
            return Err(super::denied());
        }
        let state = self.view.lock();
        if state.closed
            || state.attempts.contains_key(&connection)
            || state
                .infrastructure
                .iter()
                .flatten()
                .any(|row| row.key.connection == connection)
        {
            return Err(super::denied());
        }
        drop(state);
        {
            let state = self.view.lock();
            if state.infrastructure.iter().flatten().count() >= super::INFRASTRUCTURE_CONNECTIONS {
                return Err(super::full());
            }
        }
        let key = self.admit(peer, connection, deadline, now)?;
        if let Err(error) = self.pin_root(key, root, now) {
            self.terminal(key, None, now);
            return Err(error);
        }
        let installed = {
            let mut state = self.view.lock();
            if state.closed
                || state
                    .infrastructure
                    .iter()
                    .flatten()
                    .any(|row| row.key.connection == connection)
            {
                false
            } else if let Some(slot) = state.infrastructure.iter_mut().find(|slot| slot.is_none()) {
                *slot = Some(super::InfrastructureRow {
                    key,
                    deadline,
                    native_terminal: false,
                    connection_terminal: false,
                    authenticated: None,
                    withdrawn: false,
                    permits: 1,
                });
                true
            } else {
                false
            }
        };
        if !installed {
            self.terminal(key, None, now);
            return Err(super::full());
        }
        Ok((
            key,
            Permit {
                view: self.view(),
                key,
            },
        ))
    }

    /// ConnectionClosed, OutgoingConnectionError, or synchronous dial failure proves no live connection remains.
    /// This signal revokes staged authority but does not substitute for Owner::terminal(native).
    pub(crate) fn infrastructure_terminal(&mut self, key: AttemptKey) {
        let notify = {
            let mut state = self.view.lock();
            let Some(row) = state
                .infrastructure
                .iter_mut()
                .flatten()
                .find(|row| row.key == key)
            else {
                return;
            };
            row.connection_terminal = true;
            let notify = state
                .attempts
                .get_mut(&key.connection)
                .filter(|entry| entry.key == key)
                .map(|entry| {
                    entry.revoked = true;
                    entry.numeric = None;
                    super::take_wakers(entry)
                });
            collect(&mut state);
            notify
        };
        if let Some(notify) = notify {
            super::wake(notify);
        }
        self.view.1.notify_waiters();
    }

    pub(crate) fn infrastructure_withdraw(&mut self, key: AttemptKey) {
        let notify = {
            let mut state = self.view.lock();
            let Some(row) = state
                .infrastructure
                .iter_mut()
                .flatten()
                .find(|row| row.key == key)
            else {
                return;
            };
            row.withdrawn = true;
            let notify = state
                .attempts
                .get_mut(&key.connection)
                .filter(|entry| entry.key == key)
                .map(|entry| {
                    entry.revoked = true;
                    entry.numeric = None;
                    super::take_wakers(entry)
                });
            collect(&mut state);
            notify
        };
        if let Some(notify) = notify {
            super::wake(notify);
        }
        self.view.1.notify_waiters();
    }
}

impl super::View {
    /// cancel-safe: yes — observes final charge release without changing authority.
    pub(crate) async fn join_infrastructure_release(&self) {
        loop {
            let notified = self.1.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.lock().infrastructure.iter().all(Option::is_none) {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn infrastructure_pending(
        &self,
        key: AttemptKey,
        now: tokio::time::Instant,
    ) -> bool {
        let state = self.lock();
        if state.closed {
            return false;
        }
        let Some(row) = state.infrastructure.iter().flatten().find(|row| {
            row.key == key && !row.withdrawn && !row.connection_terminal && !row.native_terminal
        }) else {
            return false;
        };
        let Some(attempt) = state.attempts.get(&key.connection) else {
            return false;
        };
        attempt.key == key
            && !attempt.revoked
            && !attempt.terminal
            && now < attempt.deadline
            && now < row.deadline
            && attempt.root.is_some()
    }

    pub(crate) fn infrastructure_live(&self, key: AttemptKey) -> Option<SocketAddr> {
        let state = self.lock();
        if state.closed {
            return None;
        }
        let row = state.infrastructure.iter().flatten().find(|row| {
            row.key == key && !row.withdrawn && !row.connection_terminal && row.native_terminal
        })?;
        row.authenticated
    }

    #[cfg(test)]
    pub(crate) fn infrastructure_permit(&self, key: AttemptKey) -> Option<Permit> {
        let mut state = self.lock();
        if state.closed {
            return None;
        }
        let row = state
            .infrastructure
            .iter()
            .flatten()
            .find(|row| row.key == key)?;
        if row.withdrawn || row.connection_terminal || row.permits >= super::LEASES {
            return None;
        }
        let attempt = state.attempts.get(&key.connection);
        if row.native_terminal {
            row.authenticated?;
        } else {
            let attempt = attempt?;
            if attempt.key != key
                || attempt.revoked
                || attempt.terminal
                || tokio::time::Instant::now() >= attempt.deadline
                || attempt.root.is_none()
            {
                return None;
            }
        }
        let row = state
            .infrastructure
            .iter_mut()
            .flatten()
            .find(|row| row.key == key)?;
        row.permits += 1;
        Some(Permit {
            view: self.clone(),
            key,
        })
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        {
            let mut state = self.view.lock();
            if let Some(row) = state
                .infrastructure
                .iter_mut()
                .flatten()
                .find(|row| row.key == self.key)
            {
                row.permits -= 1;
            }
            collect(&mut state);
        }
        self.view.1.notify_waiters();
    }
}

#[cfg(test)]
mod tests;
