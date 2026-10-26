use std::io;

use libp2p::{PeerId, swarm::ConnectionId};
use tokio::time::Instant;

use super::{AttemptKey, Lease, LeaseKind, Owner, Role, View, denied, take_wakers, wake};

impl Owner {
    pub(crate) fn admit_child(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
        deadline: Instant,
        now: Instant,
    ) -> io::Result<AttemptKey> {
        let (role, serial) = {
            let state = self.view.lock();
            if state.closed
                || deadline <= now
                || deadline > now + std::time::Duration::from_secs(10)
            {
                return Err(denied());
            }
            if state.attempts.len() + state.inbound_count >= super::PENDING
                || state.attempts.contains_key(&connection)
                || View::inbound_contains(&state, connection)
                || state.attempts.values().any(|entry| entry.key.peer == peer)
            {
                return Err(super::full());
            }
            let role = state.identities.get(&peer).ok_or_else(denied)?.role;
            if role != Role::Application {
                return Err(denied());
            }
            (role, state.serial.checked_add(1).ok_or_else(super::full)?)
        };
        let mut state = self.view.lock();
        if state.closed
            || state.attempts.len() + state.inbound_count >= super::PENDING
            || state.attempts.contains_key(&connection)
            || View::inbound_contains(&state, connection)
        {
            return Err(super::full());
        }
        state.serial = serial;
        let key = AttemptKey {
            peer,
            connection,
            serial,
            owner: state.owner,
        };
        state.attempts.insert(
            connection,
            super::Attempt {
                key,
                role,
                deadline,
                revoked: false,
                terminal: false,
                roots: 0,
                leases: 0,
                numeric: None,
                root: None,
                waiters: std::array::from_fn(|_| None),
                child: true,
            },
        );
        Ok(key)
    }

    pub(crate) fn terminal_child(&mut self, key: AttemptKey, peer: PeerId, now: Instant) -> bool {
        let mut state = self.view.lock();
        let closed = state.closed;
        let Some(entry) = state.attempts.get_mut(&key.connection) else {
            return false;
        };
        if entry.key != key || !entry.child {
            return false;
        }
        let valid = !closed
            && !entry.revoked
            && !entry.terminal
            && now < entry.deadline
            && peer == key.peer;
        entry.terminal = true;
        let (notify, removed) = {
            let notify = take_wakers(entry);
            let removed = if entry.leases == 0 {
                state.attempts.remove(&key.connection)
            } else {
                None
            };
            (notify, removed)
        };
        drop(state);
        wake(notify);
        drop(removed);
        valid
    }
}

impl View {
    pub(crate) fn attempt_for_connection(&self, id: ConnectionId) -> Option<AttemptKey> {
        self.lock().attempts.get(&id).map(|entry| entry.key)
    }

    pub(crate) fn is_child(&self, key: AttemptKey) -> bool {
        self.lock()
            .attempts
            .get(&key.connection)
            .is_some_and(|entry| entry.key == key && entry.child)
    }

    pub(crate) fn pending_lease(&self, key: AttemptKey, now: Instant) -> io::Result<Lease> {
        let mut state = self.lock();
        if state.closed {
            return Err(denied());
        }
        let entry = state.attempts.get_mut(&key.connection).ok_or_else(denied)?;
        if entry.key != key
            || !entry.child
            || entry.revoked
            || entry.terminal
            || now >= entry.deadline
        {
            return Err(denied());
        }
        if entry.leases >= super::LEASES {
            return Err(super::full());
        }
        let slot = entry
            .waiters
            .iter()
            .position(Option::is_none)
            .ok_or_else(super::full)?;
        entry.waiters[slot] = Some(super::Waiter { waker: None });
        entry.leases += 1;
        Ok(Lease::new(
            self.clone(),
            key,
            LeaseKind::Pending,
            slot,
            entry.deadline,
        ))
    }
}
