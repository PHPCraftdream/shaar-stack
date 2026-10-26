//! Owner-gated relay operations. The Carrier stages exact trusted intent
//! (relay peer, pinned numeric endpoint, generation, deadline) — precharged
//! with an `OperationCapability` at stage time — before `listen_on`/`dial`;
//! the patched transport's factory consults only that recorded intent, taking
//! the precharged capability exactly once. Never hints, history or raw peer
//! address lists.

use std::{
    collections::HashMap,
    net::SocketAddr,
    num::NonZeroU64,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use libp2p::relay as protocol;
use protocol::client::{
    OperationCapability, OperationDescriptor, OperationFactory, OperationKind, OperationOwner,
};
use tokio::sync::Notify;

use super::*;
use crate::discovery::roles::{self, Role};

/// Two slots per relay peer (reserve + connect) over the bounded relay set.
const INTENTS: usize = RESERVATIONS + PENDING_LIMIT;
/// Bounded total of live records (Staged/Issued/Established) plus retained
/// tombstones. A successor is staged before the superseded capability is
/// released, so two generations per slot is the steady maximum: `2 * INTENTS`
/// bounds memory without ever evicting live rows. Staging at the cap fails
/// with WouldBlock; capacity is freed only by `prune_released`.
const RECORDS: usize = 2 * INTENTS;

/// Which staged operation an intent, owner or dial ticket refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Slot {
    Reserve,
    Connect,
}

/// Bounded tracking for an authenticated, control-bound relay dial. A gate
/// operation is not a registry dial attempt; it never enters the ledger.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ticket {
    pub(crate) relay: PeerId,
    pub(crate) generation: u64,
}

/// Exact record key: the generation disambiguates concurrent dials through the
/// same relay, so a successor never overwrites a predecessor.
type Key = (PeerId, Slot, u64);

/// Lifecycle of one staged generation. `Staged` holds the precharged
/// capability until the factory takes it exactly once; `Retired` is a
/// tombstone that keeps its capacity charge until its `released` flag is set
/// and `prune_released` removes it.
enum RecordState {
    Staged,
    Issued,
    Established,
    Retired,
}

struct Record {
    endpoint: SocketAddr,
    deadline: Instant,
    // First authenticated control connection wins; later checks require equality.
    control: Option<ConnectionId>,
    // None: reserve intent; Some: connect intent restricted to this destination.
    destination: Option<PeerId>,
    state: RecordState,
    // Taken exactly once by the factory; dropped with the record on retire.
    capability: Option<OperationCapability>,
    // Sole cancellation owner; taken out and dropped outside every guard.
    owner: Option<OperationOwner>,
    terminal: bool,
    // Set by the released callback only; true once the owner AND every
    // capability clone have been dropped.
    released: Arc<AtomicBool>,
    pending_hold: Arc<Mutex<Option<roles::Lease>>>,
}

impl Record {
    fn retired(&self) -> bool {
        matches!(self.state, RecordState::Retired)
    }
    /// A charge is outstanding until the row is retired AND released.
    fn outstanding(&self) -> bool {
        !self.retired() || !self.terminal || !self.released.load(Ordering::Acquire)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

struct GateCore {
    counter: AtomicU64,
    records: Mutex<HashMap<Key, Record>>,
    // The roles View is installed by `factory`; absent means fail closed.
    roles: Mutex<Option<roles::View>>,
    // Release join: the released callback and every retire path fire this
    // without holding (or ever taking) the records lock; join_release
    // registers its waiter first and re-checks on every wake, so a lost
    // wakeup can only cost an extra wait, never a missed completion.
    notify: Notify,
}

/// Clones share the same core; every closure stored inside an
/// `OperationOwner` captures only a `Weak<GateCore>` (plus cheap `View`/flag
/// clones), so an owner can never keep the gate — or its own record — alive.
#[derive(Clone)]
pub(crate) struct Gate {
    core: Arc<GateCore>,
}

fn denied() -> io::Error {
    io::Error::from(io::ErrorKind::PermissionDenied)
}

/// Takes owners and unissued capabilities out of every retired row so they
/// can be dropped strictly outside the records guard.
fn retired_unissued(
    records: &mut HashMap<Key, Record>,
) -> Vec<(Option<OperationOwner>, Option<OperationCapability>)> {
    let mut retired = Vec::new();
    for record in records.values_mut() {
        if record.retired()
            && let Some(owner) = record.owner.take()
        {
            retired.push((Some(owner), record.capability.take()));
        }
    }
    retired
}

/// The descriptor address is the relay transport address without the
/// P2p/P2pCircuit suffix; the ledger never saw the circuit address itself.
fn endpoint(address: &Multiaddr) -> Option<SocketAddr> {
    let mut parts = address.iter();
    match (parts.next()?, parts.next()?, parts.next()) {
        (Protocol::Ip4(ip), Protocol::Tcp(port), None) => Some(SocketAddr::from((ip, port))),
        (Protocol::Ip6(ip), Protocol::Tcp(port), None) => Some(SocketAddr::from((ip, port))),
        _ => None,
    }
}

impl Gate {
    pub(crate) fn new() -> Self {
        Self {
            core: Arc::new(GateCore {
                counter: AtomicU64::new(0),
                records: Mutex::new(HashMap::with_capacity(RECORDS)),
                roles: Mutex::new(None),
                notify: Notify::new(),
            }),
        }
    }

    /// Single generation source: descriptor generations (NonZeroU64) and
    /// route/record generations (u64) draw from this one counter, so the
    /// mapping is the identity (values start at 1 and never wrap).
    /// Native relay addresses are admitted only by an active exact intent.
    pub(crate) fn native_permit(&self, peer: PeerId, address: &Multiaddr) -> bool {
        let mut parts = address.iter();
        let Some((first, second)) = parts.next().zip(parts.next()) else {
            return false;
        };
        let socket = match (first, second) {
            (Protocol::Ip4(ip), Protocol::Tcp(port)) => SocketAddr::from((ip, port)),
            (Protocol::Ip6(ip), Protocol::Tcp(port)) => SocketAddr::from((ip, port)),
            _ => return false,
        };
        let Some(Protocol::P2p(relay)) = parts.next() else {
            return false;
        };
        let (slot, destination) = match parts.next() {
            None => {
                if relay != peer {
                    return false;
                }
                (None, None)
            }
            Some(Protocol::P2pCircuit) => {
                let Some(Protocol::P2p(app)) = parts.next() else {
                    return false;
                };
                if app != peer || parts.next().is_some() {
                    return false;
                }
                (Some(Slot::Connect), Some(app))
            }
            _ => return false,
        };
        let view = { lock(&self.core.roles).clone() };
        let Some(view) = view else { return false };
        if view.role(relay) != Some(Role::ExplicitRelay(socket))
            || destination.is_some_and(|app| view.role(app) != Some(Role::Application))
        {
            return false;
        }
        let now = Instant::now();
        lock(&self.core.records).iter().any(|(key, record)| {
            key.0 == relay
                && slot.is_none_or(|slot| key.1 == slot && record.destination == destination)
                && record.endpoint == socket
                && !record.retired()
                && record.deadline > now
        })
    }

    /// Final publication veto for a specific issued/established connect row.
    pub(crate) fn connection_permit(&self, ticket: Ticket, destination: PeerId) -> bool {
        let key = (ticket.relay, Slot::Connect, ticket.generation);
        let now = Instant::now();
        let permitted = {
            let records = lock(&self.core.records);
            records.get(&key).and_then(|record| {
                (!record.retired()
                    && record.destination == Some(destination)
                    && record.control.is_some()
                    && (matches!(record.state, RecordState::Established)
                        || (matches!(record.state, RecordState::Issued) && record.deadline > now)))
                    .then_some(record.endpoint)
            })
        };
        let Some(endpoint) = permitted else {
            return false;
        };
        let view = lock(&self.core.roles).clone();
        view.is_some_and(|view| {
            view.role(destination) == Some(Role::Application)
                && view.role(ticket.relay) == Some(Role::ExplicitRelay(endpoint))
        })
    }

    pub(crate) fn next(&self) -> io::Result<u64> {
        self.core
            .counter
            .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map(|previous| previous + 1)
            .map_err(|_| super::super::capacity())
    }

    /// Stages `intent` precharged with its capability, retiring superseded
    /// generations of the same slot. Retired owners and never-issued
    /// capabilities are dropped outside the guard; the tombstone charge
    /// remains until the record is released and pruned.
    fn stage(
        &self,
        peer: PeerId,
        slot: Slot,
        generation: u64,
        endpoint: SocketAddr,
        deadline: Instant,
        destination: Option<PeerId>,
    ) -> io::Result<()> {
        let kind = match (slot, destination) {
            (Slot::Reserve, None) => OperationKind::Reserve,
            (Slot::Connect, Some(destination)) => OperationKind::Connect { destination },
            _ => return Err(denied()),
        };
        let descriptor = OperationDescriptor::new(
            peer,
            multiaddr(endpoint),
            kind,
            NonZeroU64::new(generation).ok_or_else(denied)?,
        );
        let released = Arc::new(AtomicBool::new(false));
        let pending_hold = Arc::new(Mutex::new(None));
        let (owner, capability) = OperationCapability::owned(
            descriptor,
            {
                // Weak: the admit path upgrades per call and fails closed if
                // the gate is gone. No strong gate reference in any owner.
                let core = Arc::downgrade(&self.core);
                move |descriptor, control| {
                    core.upgrade()
                        .is_some_and(|core| core.admit(descriptor, control))
                }
            },
            {
                // Release observation only: set the flag, then fire the join
                // notification. No map access, no counters, no locks, no await.
                let released = released.clone();
                let pending_hold = pending_hold.clone();
                let core = Arc::downgrade(&self.core);
                move || {
                    let lease = { lock(&pending_hold).take() };
                    drop(lease);
                    released.store(true, Ordering::Release);
                    if let Some(core) = core.upgrade() {
                        core.notify.notify_waiters();
                    }
                }
            },
        );
        // Insert the fresh generation, superseding older ones of the same
        // slot; their owners and unissued capabilities are dropped strictly
        // after the records guard is released.
        let retired = {
            let mut records = lock(&self.core.records);
            if records.len() >= RECORDS {
                return Err(capacity());
            }
            for (key, record) in records.iter_mut() {
                if key.0 == peer && key.1 == slot && slot == Slot::Reserve && !record.retired() {
                    record.state = RecordState::Retired;
                }
            }
            records.insert(
                (peer, slot, generation),
                Record {
                    endpoint,
                    deadline,
                    control: None,
                    destination,
                    state: RecordState::Staged,
                    terminal: false,
                    capability: Some(capability),
                    owner: Some(owner),
                    released,
                    pending_hold,
                },
            );
            retired_unissued(&mut records)
        };
        drop(retired);
        self.core.notify.notify_waiters();
        Ok(())
    }

    /// Staged before `listen_on`; the factory translates from this live intent.
    pub(crate) fn stage_reserve(
        &self,
        peer: PeerId,
        endpoint: SocketAddr,
        deadline: Instant,
    ) -> io::Result<u64> {
        let generation = self.next()?;
        self.stage(peer, Slot::Reserve, generation, endpoint, deadline, None)?;
        Ok(generation)
    }

    pub(crate) fn stage_connect(
        &self,
        relay: PeerId,
        endpoint: SocketAddr,
        destination: PeerId,
        deadline: Instant,
    ) -> io::Result<Ticket> {
        let generation = self.next()?;
        self.stage(
            relay,
            Slot::Connect,
            generation,
            endpoint,
            deadline,
            Some(destination),
        )?;
        Ok(Ticket { relay, generation })
    }

    /// A buffered reservation acceptance may publish only while its exact
    /// issued reservation capability remains live on the authenticated control.
    pub(crate) fn reservation_permit(
        &self,
        peer: PeerId,
        generation: u64,
        control: ConnectionId,
    ) -> bool {
        lock(&self.core.records)
            .get(&(peer, Slot::Reserve, generation))
            .is_some_and(|record| {
                matches!(record.state, RecordState::Issued)
                    && record.deadline > Instant::now()
                    && record.control == Some(control)
            })
    }

    /// A reservation acceptance renews the exact staged Reserve generation so
    /// the capability issued at `listen_on` stays admitted until the next
    /// expiry or revoke. Stale generations are ignored.
    pub(crate) fn accepted(
        &self,
        peer: PeerId,
        generation: u64,
        deadline: Instant,
        control: ConnectionId,
    ) {
        let mut records = lock(&self.core.records);
        if let Some(record) = records.get_mut(&(peer, Slot::Reserve, generation))
            && !record.retired()
        {
            record.deadline = deadline;
            if record.control.is_none() {
                record.control = Some(control);
            }
        }
    }

    /// An established circuit outlives its dial deadline; only the exact
    /// generation flips, so stale tickets are a no-op. Teardown follows the
    /// route via `revoke_generation` in the connection-closed path.
    pub(crate) fn establish(&self, ticket: Ticket) {
        let mut records = lock(&self.core.records);
        if let Some(record) = records.get_mut(&(ticket.relay, Slot::Connect, ticket.generation))
            && matches!(record.state, RecordState::Staged | RecordState::Issued)
        {
            record.state = RecordState::Established;
        }
    }

    /// Retires EVERY generation of `slot` (stop/teardown of the whole slot):
    /// owners are cancelled and dropped outside all guards, tombstones keep
    /// their charge until released and pruned. Use `revoke_generation` when a
    /// live successor generation must survive (old circuit close, failed dial
    /// of a superseded generation).
    pub(crate) fn revoke(&self, peer: PeerId, slot: Slot) {
        self.retire(|(other, other_slot, _)| *other == peer && *other_slot == slot);
    }

    /// Retires only the exact generation row; a no-op when the row is absent
    /// or already retired under a different generation. This is the old-circuit
    /// close path: it never touches a successor generation of the same slot.
    pub(crate) fn revoke_generation(&self, peer: PeerId, slot: Slot, generation: u64) {
        self.retire(|(other, other_slot, other_generation)| {
            *other == peer && *other_slot == slot && *other_generation == generation
        });
    }

    /// Deadline-driven withdrawal: expired unestablished generations lose
    /// eligibility; owners are cancelled/dropped outside all guards, rows
    /// become retained tombstones.
    pub(crate) fn expire(&self, now: Instant) {
        self.retire_record(|record| {
            !matches!(record.state, RecordState::Established) && record.deadline <= now
        });
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        lock(&self.core.records)
            .values()
            .filter(|record| matches!(record.state, RecordState::Staged | RecordState::Issued))
            .map(|record| record.deadline)
            .min()
    }

    /// Removes fully released tombstones; this is the only path that frees
    /// capacity. Cheap; call from deadline sweeps or shutdown.
    pub(crate) fn prune_released(&self) {
        let mut records = lock(&self.core.records);
        records.retain(|_, record| {
            !(record.retired() && record.terminal && record.released.load(Ordering::Acquire))
        });
    }

    /// Shutdown: retire everything; owners drop outside guards.
    pub(crate) fn revoke_all(&self) {
        self.retire(|_| true);
    }

    /// Marks an actual Swarm terminal outcome; withdrawal alone never sets it.
    pub(crate) fn terminal(&self, ticket: Ticket) {
        if let Some(record) =
            lock(&self.core.records).get_mut(&(ticket.relay, Slot::Connect, ticket.generation))
        {
            record.terminal = true;
        }
        self.core.notify.notify_waiters();
    }

    /// Marks a reserve generation terminal after ListenerClosed or listen error.
    pub(crate) fn terminal_reservation(&self, peer: PeerId, generation: u64) {
        if let Some(record) = lock(&self.core.records).get_mut(&(peer, Slot::Reserve, generation)) {
            record.terminal = true;
        }
        self.core.notify.notify_waiters();
    }

    /// Call only after Swarm/executor destruction during whole shutdown.
    pub(crate) fn finish_shutdown(&self) {
        for record in lock(&self.core.records).values_mut() {
            record.terminal = true;
        }
        self.core.notify.notify_waiters();
    }

    /// Release is observed once the owner AND every capability clone are gone.
    /// Pure notify re-check loop: the waiter registers before each check, and
    /// every release path fires `notify_one`, so completion needs no polling.
    pub(crate) async fn join_release(&self) -> io::Result<()> {
        loop {
            let notified = self.core.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let records = lock(&self.core.records);
                if !records.values().any(Record::outstanding) {
                    return Ok(());
                }
            }
            notified.await;
        }
    }

    /// The factory the patched transport calls synchronously inside
    /// `listen_on` (Reserve) and `dial` (Connect); it never blocks or awaits.
    pub(crate) fn factory(&self, roles: roles::View) -> OperationFactory {
        self.factory_with_pending(roles, true)
    }

    #[cfg(test)]
    pub(crate) fn factory_unbound(&self, roles: roles::View) -> OperationFactory {
        self.factory_with_pending(roles, false)
    }

    fn factory_with_pending(&self, roles: roles::View, require_pending: bool) -> OperationFactory {
        let core = Arc::downgrade(&self.core);
        *lock(&self.core.roles) = Some(roles.clone());
        Arc::new(move |peer, address, kind| match core.upgrade() {
            Some(gate) => gate.issue(peer, address, kind, &roles, require_pending),
            None => Err(denied()),
        })
    }

    /// Flips matching live rows to `Retired`, then drops their owners and
    /// unissued capabilities strictly outside the records lock.
    fn retire<F>(&self, select: F)
    where
        F: Fn(&Key) -> bool,
    {
        let retired = {
            let mut records = lock(&self.core.records);
            for (key, record) in records.iter_mut() {
                if select(key) && !record.retired() {
                    record.state = RecordState::Retired;
                }
            }
            retired_unissued(&mut records)
        };
        drop(retired);
        self.core.notify.notify_waiters();
    }

    fn retire_record<F>(&self, select: F)
    where
        F: Fn(&Record) -> bool,
    {
        let retired = {
            let mut records = lock(&self.core.records);
            for record in records.values_mut() {
                if !record.retired() && select(record) {
                    record.state = RecordState::Retired;
                }
            }
            retired_unissued(&mut records)
        };
        drop(retired);
        self.core.notify.notify_waiters();
    }
}

#[path = "gate_factory.rs"]
mod factory;
#[cfg(test)]
#[path = "gate_test_support.rs"]
mod test_support;
