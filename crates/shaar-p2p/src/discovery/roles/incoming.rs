use std::io;

use libp2p::{Multiaddr, swarm::ConnectionId};

use super::{PENDING, State, View, denied, full};

pub(super) struct Row {
    pub(super) serial: u64,
    pub(super) owner: u64,
    local: Vec<u8>,
    remote: Vec<u8>,
    pub(super) connection: Option<ConnectionId>,
    pub(super) terminal: bool,
    retained: usize,
    pub(super) waiter: Option<std::task::Waker>,
}

pub(crate) struct InboundLease {
    view: View,
    serial: u64,
    owner: u64,
}

impl View {
    pub(crate) fn incoming_lease(
        &self,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> io::Result<InboundLease> {
        let local = local.to_vec();
        let remote = remote.to_vec();
        if local.len() > 256 || remote.len() > 256 {
            return Err(full());
        }
        let mut state = self.lock();
        if state.closed {
            return Err(denied());
        }
        if state.attempts.len() + state.inbound_count >= PENDING {
            return Err(full());
        }
        let serial = state.serial.checked_add(1).ok_or_else(full)?;
        state.serial = serial;
        let owner = state.owner;
        let index = state
            .inbound
            .iter()
            .position(Option::is_none)
            .ok_or_else(full)?;
        state.inbound[index] = Some(Row {
            serial,
            owner,
            local,
            remote,
            connection: None,
            terminal: false,
            retained: 1,
            waiter: None,
        });
        state.inbound_count += 1;
        Ok(InboundLease {
            view: self.clone(),
            serial,
            owner,
        })
    }

    pub(super) fn inbound_contains(state: &State, id: ConnectionId) -> bool {
        state
            .inbound
            .iter()
            .flatten()
            .any(|row| row.connection == Some(id))
    }
}

impl InboundLease {
    pub(crate) fn poll_check(&mut self, cx: &mut std::task::Context<'_>) -> io::Result<()> {
        let next = cx.waker().clone();
        let (valid, previous) = {
            let mut state = self.view.lock();
            let closed = state.closed;
            let row = state.inbound.iter_mut().flatten().find(|row| {
                row.serial == self.serial && row.owner == self.owner && row.retained > 0
            });
            match row {
                Some(row) => {
                    let terminal = row.terminal;
                    let previous = row.waiter.replace(next);
                    (!closed && !terminal, previous)
                }
                None => (false, None),
            }
        };
        drop(previous);
        if valid { Ok(()) } else { Err(denied()) }
    }

    pub(crate) fn check(&self) -> io::Result<()> {
        let state = self.view.lock();
        if state.closed
            || !state.inbound.iter().flatten().any(|row| {
                row.serial == self.serial
                    && row.owner == self.owner
                    && row.retained > 0
                    && !row.terminal
            })
        {
            return Err(denied());
        }
        Ok(())
    }

    fn release(&mut self) {
        let (removed, waiter) = {
            let mut state = self.view.lock();
            let Some(index) = state.inbound.iter().position(|row| {
                row.as_ref()
                    .is_some_and(|r| r.serial == self.serial && r.owner == self.owner)
            }) else {
                return;
            };
            let row = state.inbound[index].as_mut().expect("located row");
            let waiter = row.waiter.take();
            row.retained = row.retained.saturating_sub(1);
            let removed = if row.retained == 0 && (row.terminal || row.connection.is_none()) {
                state.inbound_count -= 1;
                state.inbound[index].take()
            } else {
                None
            };
            (removed, waiter)
        };
        drop(removed);
        drop(waiter);
    }
}
impl Drop for InboundLease {
    fn drop(&mut self) {
        self.release();
    }
}

impl super::Owner {
    pub(crate) fn admit_inbound_at(
        &mut self,
        id: ConnectionId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> io::Result<()> {
        let local = local.to_vec();
        let remote = remote.to_vec();
        let mut state = self.view.lock();
        if state.closed {
            return Err(denied());
        }
        if state.attempts.contains_key(&id) || View::inbound_contains(&state, id) {
            return Err(full());
        }
        let state_owner = state.owner;
        let row = state
            .inbound
            .iter_mut()
            .flatten()
            .find(|row| {
                row.owner == state_owner
                    && row.connection.is_none()
                    && row.local == local
                    && row.remote == remote
            })
            .ok_or_else(denied)?;
        row.connection = Some(id);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn admit_inbound(&mut self, connection: ConnectionId) -> io::Result<()> {
        let mut state = self.view.lock();
        if state.closed {
            return Err(denied());
        }
        if state.attempts.len() + state.inbound_count >= PENDING
            || state.attempts.contains_key(&connection)
            || View::inbound_contains(&state, connection)
        {
            return Err(full());
        }
        let index = state
            .inbound
            .iter()
            .position(Option::is_none)
            .ok_or_else(full)?;
        let serial = state.serial.checked_add(1).ok_or_else(full)?;
        state.serial = serial;
        let owner = state.owner;
        state.inbound[index] = Some(Row {
            serial,
            owner,
            local: Vec::new(),
            remote: Vec::new(),
            connection: Some(connection),
            terminal: false,
            retained: 0,
            waiter: None,
        });
        state.inbound_count += 1;
        Ok(())
    }

    pub(crate) fn finish_inbound(&mut self, connection: ConnectionId) {
        let (removed, waiter) = {
            let mut state = self.view.lock();
            let Some(index) = state.inbound.iter().position(|row| {
                row.as_ref()
                    .is_some_and(|r| r.connection == Some(connection))
            }) else {
                return;
            };
            let row = state.inbound[index].as_mut().expect("located row");
            row.terminal = true;
            let waiter = row.waiter.take();
            let removed = if row.retained == 0 {
                state.inbound_count -= 1;
                state.inbound[index].take()
            } else {
                None
            };
            (removed, waiter)
        };
        drop(removed);
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }
}
