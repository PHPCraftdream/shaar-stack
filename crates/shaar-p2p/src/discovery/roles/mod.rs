//! Carrier-owned authority. Parsed scalar inputs only; no network work under the mutex.

mod address;
mod incoming;
mod infrastructure;
mod lease;
mod pending;
#[cfg(test)]
mod tests;

use libp2p::{PeerId, swarm::ConnectionId};
use std::task::Waker;
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard},
};
use tokio::time::Instant;

pub(crate) use address::Root;
pub(crate) use incoming::InboundLease;
pub(crate) use infrastructure::Permit as InfrastructurePermit;
pub(crate) use lease::Lease;

const IDENTITIES: usize = 56;
const APPLICATIONS: usize = 16;
const EXPLICIT: usize = 8;
const INFRASTRUCTURE: usize = 32;
pub(crate) const INFRASTRUCTURE_CONNECTIONS: usize = 4;
const PENDING: usize = 8;
const ROOTS: usize = 4;
const LEASES: usize = ROOTS * 2;

// Non-reused namespaces prevent keys crossing owners. Relaxed only issues unique
// numbers; it does not publish registry state or synchronize payload access.
static NEXT_OWNER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    Application,
    ExplicitRelay(SocketAddr),
    Infrastructure,
}

#[derive(Clone, Copy)]
struct Identity {
    role: Role,
    reserved: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AttemptKey {
    pub(crate) peer: PeerId,
    pub(crate) connection: ConnectionId,
    serial: u64,
    owner: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LeaseKind {
    Root,
    Numeric,
    Pending,
}

struct Attempt {
    key: AttemptKey,
    role: Role,
    deadline: Instant,
    revoked: bool,
    terminal: bool,
    roots: usize,
    leases: usize,
    numeric: Option<SocketAddr>,
    root: Option<Root>,
    child: bool,
    waiters: [Option<Waiter>; LEASES],
}

struct InfrastructureRow {
    key: AttemptKey,
    connection_terminal: bool,
    native_terminal: bool,
    authenticated: Option<SocketAddr>,
    withdrawn: bool,
    deadline: Instant,
    permits: usize,
}

struct Waiter {
    waker: Option<Waker>,
}

fn take_wakers(entry: &mut Attempt) -> [Option<Waker>; LEASES] {
    std::array::from_fn(|index| {
        entry.waiters[index]
            .as_mut()
            .and_then(|slot| slot.waker.take())
    })
}

fn wake(wakers: [Option<Waker>; LEASES]) {
    for waker in wakers.into_iter().flatten() {
        waker.wake();
    }
}

struct State {
    owner: u64,
    closed: bool,
    serial: u64,
    identities: HashMap<PeerId, Identity>,
    attempts: HashMap<ConnectionId, Attempt>,
    pub(super) inbound: [Option<incoming::Row>; PENDING],
    pub(super) inbound_count: usize,
    infrastructure: [Option<InfrastructureRow>; INFRASTRUCTURE_CONNECTIONS],
}

/// Only this non-cloneable capability admits identities and attempts or revokes authority.
pub(crate) struct Owner {
    view: View,
}

/// Synchronous checks and exact-key future accounting, never identity admission.
#[derive(Clone)]
pub(crate) struct View(Arc<Mutex<State>>, Arc<tokio::sync::Notify>);

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "destination authority unavailable",
    )
}
fn full() -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        "destination authority capacity exhausted",
    )
}

impl View {
    // DNS and executor futures need synchronous revocation checks. Critical sections
    // contain bounded lookups and scalar accounting, never callbacks or resource Drop.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(|poison| {
            let mut state = poison.into_inner();
            state.closed = true;
            state
        })
    }

    pub(crate) fn role(&self, peer: PeerId) -> Option<Role> {
        let state = self.lock();
        (!state.closed)
            .then(|| state.identities.get(&peer).map(|entry| entry.role))
            .flatten()
    }

    pub(crate) fn current(&self, peer: PeerId, now: Instant) -> Option<AttemptKey> {
        let state = self.lock();
        state
            .attempts
            .values()
            .find(|attempt| attempt.key.peer == peer && live(&state, attempt, now))
            .map(|attempt| attempt.key)
    }

    pub(crate) fn check(&self, key: AttemptKey, now: Instant) -> io::Result<Role> {
        let state = self.lock();
        let attempt = state.attempts.get(&key.connection).ok_or_else(denied)?;
        if attempt.key != key || !live(&state, attempt, now) {
            return Err(denied());
        }
        Ok(attempt.role)
    }

    pub(crate) fn lease(
        &self,
        key: AttemptKey,
        kind: LeaseKind,
        now: Instant,
    ) -> io::Result<Lease> {
        let (slot, deadline) = {
            let mut state = self.lock();
            if state.closed {
                return Err(denied());
            }
            let attempt = state.attempts.get_mut(&key.connection).ok_or_else(denied)?;
            if attempt.key != key || attempt.revoked || attempt.terminal || now >= attempt.deadline
            {
                return Err(denied());
            }
            let root_limit = if attempt.role == Role::Infrastructure {
                1
            } else {
                ROOTS
            };
            if attempt.leases >= LEASES
                || (kind == LeaseKind::Root && attempt.roots >= root_limit)
                || (kind == LeaseKind::Numeric && attempt.leases - attempt.roots >= attempt.roots)
            {
                return Err(full());
            }
            let slot = attempt
                .waiters
                .iter()
                .position(Option::is_none)
                .ok_or_else(full)?;
            attempt.waiters[slot] = Some(Waiter { waker: None });
            attempt.leases += 1;
            if kind == LeaseKind::Root {
                attempt.roots += 1;
            }
            (slot, attempt.deadline)
        };
        Ok(Lease::new(self.clone(), key, kind, slot, deadline))
    }

    fn record_numeric(
        &self,
        key: AttemptKey,
        endpoint: SocketAddr,
        now: Instant,
    ) -> io::Result<()> {
        let mut state = self.lock();
        if state.closed {
            return Err(denied());
        }
        let attempt = state.attempts.get_mut(&key.connection).ok_or_else(denied)?;
        if attempt.key != key || attempt.revoked || attempt.terminal || now >= attempt.deadline {
            return Err(denied());
        }
        let root = attempt.root.as_ref().ok_or_else(denied)?;
        if !Self::pinned_numeric(attempt.role, root, endpoint) {
            return Err(denied());
        }
        if !numeric_usable(endpoint) {
            return Err(denied());
        }
        if attempt.numeric.is_some_and(|previous| previous != endpoint) {
            return Err(denied());
        }
        attempt.numeric = Some(endpoint);
        Ok(())
    }
}

// Preserve numeric APP/explicit-relay scope; infrastructure adds its strict classifier.
fn numeric_usable(endpoint: SocketAddr) -> bool {
    endpoint.port() != 0
        && !endpoint.ip().is_unspecified()
        && !endpoint.ip().is_multicast()
        && !matches!(endpoint, SocketAddr::V6(value) if value.scope_id() != 0 || value.flowinfo() != 0)
}

fn live(state: &State, attempt: &Attempt, now: Instant) -> bool {
    !state.closed && !attempt.revoked && !attempt.terminal && now < attempt.deadline
}

impl Owner {
    pub(crate) fn new(applications: &[PeerId], seeds: &[PeerId]) -> io::Result<Self> {
        // Check raw counts before deduplication and before allocating registry storage.
        if applications.len() > APPLICATIONS || seeds.len() > INFRASTRUCTURE {
            return Err(full());
        }
        if applications.iter().any(|peer| seeds.contains(peer)) {
            return Err(denied());
        }
        let owner = NEXT_OWNER
            .try_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |value| value.checked_add(1),
            )
            .map_err(|_| full())?;
        let mut identities = HashMap::with_capacity(IDENTITIES);
        for &peer in applications {
            identities.insert(
                peer,
                Identity {
                    role: Role::Application,
                    reserved: true,
                },
            );
        }
        for &peer in seeds {
            identities.insert(
                peer,
                Identity {
                    role: Role::Infrastructure,
                    reserved: true,
                },
            );
        }
        Ok(Self {
            view: View(
                Arc::new(Mutex::new(State {
                    owner,
                    closed: false,
                    serial: 0,
                    identities,
                    attempts: HashMap::with_capacity(PENDING),
                    inbound: std::array::from_fn(|_| None),
                    inbound_count: 0,
                    infrastructure: std::array::from_fn(|_| None),
                })),
                Arc::new(tokio::sync::Notify::new()),
            ),
        })
    }

    pub(crate) fn view(&self) -> View {
        self.view.clone()
    }

    pub(crate) fn admit_identity(&mut self, peer: PeerId, role: Role) -> io::Result<()> {
        if role == Role::Application {
            return Err(denied());
        }
        if let Role::ExplicitRelay(endpoint) = role
            && !numeric_usable(endpoint)
        {
            return Err(denied());
        }
        let mut state = self.view.lock();
        if state.closed {
            return Err(denied());
        }
        if let Some(existing) = state.identities.get(&peer) {
            return if existing.role == role {
                Ok(())
            } else {
                Err(denied())
            };
        }
        let count = state
            .identities
            .values()
            .filter(|entry| match role {
                Role::ExplicitRelay(_) => matches!(entry.role, Role::ExplicitRelay(_)),
                Role::Infrastructure => entry.role == Role::Infrastructure,
                Role::Application => false,
            })
            .count();
        let limit = if role == Role::Infrastructure {
            INFRASTRUCTURE
        } else {
            EXPLICIT
        };
        if count >= limit || state.identities.len() >= IDENTITIES {
            return Err(full());
        }
        state.identities.insert(
            peer,
            Identity {
                role,
                reserved: false,
            },
        );
        Ok(())
    }

    /// The carrier supplies its already admitted absolute deadline; this never resets it.
    pub(crate) fn admit(
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
            if state.attempts.len() + state.inbound_count >= PENDING
                || state.attempts.contains_key(&connection)
                || View::inbound_contains(&state, connection)
                || state.attempts.values().any(|entry| entry.key.peer == peer)
            {
                return Err(full());
            }
            (
                state.identities.get(&peer).ok_or_else(denied)?.role,
                state.serial.checked_add(1).ok_or_else(full)?,
            )
        };
        // Only this owner can insert or close; concurrent lease drops only release charges.
        let mut state = self.view.lock();
        if state.closed {
            return Err(denied());
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
            Attempt {
                key,
                role,
                deadline,
                revoked: false,
                terminal: false,
                roots: 0,
                leases: 0,
                numeric: None,
                root: None,
                child: false,
                waiters: std::array::from_fn(|_| None),
            },
        );
        Ok(key)
    }

    #[cfg(test)]
    pub(crate) fn revoke(&mut self, key: AttemptKey) {
        let notify = {
            let mut state = self.view.lock();
            state
                .attempts
                .get_mut(&key.connection)
                .filter(|entry| entry.key == key)
                .map(|entry| {
                    entry.revoked = true;
                    entry.numeric = None;
                    take_wakers(entry)
                })
        };
        if let Some(notify) = notify {
            wake(notify);
        }
    }

    /// Only an exact authenticated terminal success may consume the numeric witness.
    /// Failure, wrong peer, cancellation and expiry discard it without promotion.
    pub(crate) fn terminal(
        &mut self,
        key: AttemptKey,
        authenticated: Option<PeerId>,
        now: Instant,
    ) -> Option<SocketAddr> {
        let (witness, notify, removed) = {
            let mut state = self.view.lock();
            let closed = state.closed;
            let entry = state.attempts.get_mut(&key.connection)?;
            if entry.key != key {
                return None;
            }
            let first_terminal = !entry.terminal;
            let witness = if first_terminal
                && !closed
                && !entry.revoked
                && now < entry.deadline
                && authenticated == Some(key.peer)
            {
                entry.numeric.take()
            } else {
                entry.numeric = None;
                None
            };
            entry.terminal = true;
            let notify = take_wakers(entry);
            let removed = if entry.leases == 0 {
                state.attempts.remove(&key.connection)
            } else {
                None
            };
            let infrastructure = state
                .infrastructure
                .iter_mut()
                .flatten()
                .find(|row| row.key == key);
            if first_terminal && let Some(row) = infrastructure {
                row.native_terminal = true;
                row.authenticated = witness;
                if witness.is_none() {
                    row.withdrawn = true;
                }
            }
            infrastructure::collect(&mut state);
            (witness, notify, removed)
        };
        wake(notify);
        drop(removed);
        self.view.1.notify_waiters();
        witness
    }

    pub(crate) fn forget_identity(&mut self, peer: PeerId) -> io::Result<()> {
        let mut state = self.view.lock();
        if state
            .identities
            .get(&peer)
            .is_some_and(|entry| entry.reserved)
            || state.attempts.values().any(|entry| entry.key.peer == peer)
            || state
                .infrastructure
                .iter()
                .flatten()
                .any(|row| row.key.peer == peer)
        {
            return Err(denied());
        }
        state.identities.remove(&peer);
        Ok(())
    }

    pub(crate) fn close(&mut self) {
        let notifications = {
            let mut state = self.view.lock();
            state.closed = true;
            for row in state.infrastructure.iter_mut().flatten() {
                row.withdrawn = true;
            }
            infrastructure::collect(&mut state);
            let mut notifications: [Option<[Option<Waker>; LEASES]>; PENDING] =
                std::array::from_fn(|_| None);
            for (slot, entry) in notifications.iter_mut().zip(state.attempts.values_mut()) {
                entry.revoked = true;
                entry.numeric = None;
                *slot = Some(take_wakers(entry));
            }
            let inbound: [Option<Waker>; PENDING] = std::array::from_fn(|index| {
                state.inbound[index]
                    .as_mut()
                    .and_then(|row| row.waiter.take())
            });
            (notifications, inbound)
        };
        for notify in notifications.0.into_iter().flatten() {
            wake(notify);
        }
        for waiter in notifications.1.into_iter().flatten() {
            waiter.wake();
        }
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.close();
    }
}
