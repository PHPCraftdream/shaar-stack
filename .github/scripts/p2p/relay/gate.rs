#![forbid(unsafe_code)]

use std::{
    fmt,
    future::Future,
    io,
    num::NonZeroU64,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
};

use libp2p_core::Multiaddr;
use libp2p_identity::PeerId;
use libp2p_swarm::ConnectionId;

/// The operation requested at the transport call boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OperationKind {
    Reserve,
    Connect { destination: PeerId },
}

/// Immutable owner-issued intent. The address excludes the relay peer suffix.
#[derive(Debug)]
pub struct OperationDescriptor {
    peer: PeerId,
    address: Multiaddr,
    kind: OperationKind,
    generation: NonZeroU64,
}

impl OperationDescriptor {
    pub fn new(
        peer: PeerId,
        address: Multiaddr,
        kind: OperationKind,
        generation: NonZeroU64,
    ) -> Self {
        Self {
            peer,
            address,
            kind,
            generation,
        }
    }
    pub fn peer(&self) -> PeerId {
        self.peer
    }
    pub fn address(&self) -> &Multiaddr {
        &self.address
    }
    pub fn kind(&self) -> OperationKind {
        self.kind
    }
    pub fn generation(&self) -> NonZeroU64 {
        self.generation
    }
}

type Admit = dyn Fn(&OperationDescriptor, Option<ConnectionId>) -> bool + Send + Sync;

/// Called synchronously by transport listen/dial, never by delayed request dispatch.
/// The owner must return a fresh, already charged capability for its staged intent.
pub type OperationFactory =
    Arc<dyn Fn(PeerId, &Multiaddr, OperationKind) -> io::Result<OperationCapability> + Send + Sync>;

struct Authority {
    descriptor: OperationDescriptor,
    admit: Box<Admit>,
    // Captured owner lease remains alive until every request/event/placeholder drops.
    released: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl Drop for Authority {
    fn drop(&mut self) {
        if let Some(released) = self.released.take() {
            released();
        }
    }
}

// Short locks serialize one control binding and two waker slots, not I/O or policy.
// No callback, waker vtable, resource destruction or await runs under these locks.
struct Shared {
    authority: Option<Authority>,
    cancelled: AtomicBool,
    claimed: AtomicBool,
    control: Mutex<Option<ConnectionId>>,
    // One idle handler and one protocol future per operation; never a waiter list.
    idle: Mutex<Option<Waker>>,
    protocol: Mutex<Option<Waker>>,
}

/// Sole cancellation owner. Dropping it revokes the operation and wakes both sites.
/// Update authoritative owner state before calling `cancel`, then release its
/// registry guard before cancellation wakes tasks. Callbacks never grant permission
/// independently of that state. Cancellation cannot be reversed.
pub struct OperationOwner(Arc<Shared>);

impl OperationOwner {
    pub fn cancel(&self) {
        self.0.cancel();
    }
}

impl Drop for OperationOwner {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Opaque operation lease, not a peer-wide permission or a transferable role.
#[derive(Clone)]
pub struct OperationCapability(Arc<Shared>);

impl fmt::Debug for OperationCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperationCapability")
            .field(
                "descriptor",
                &self.0.authority.as_ref().map(|a| &a.descriptor),
            )
            .finish_non_exhaustive()
    }
}

impl OperationCapability {
    /// Allocate once per charged operation, never per renewal. `admit` checks the
    /// authoritative owner ledger, including generation, deadline and control.
    /// `None` control authorizes only exact staged intent, never a peer-wide grant;
    /// `Some` must match the owner's authenticated connection binding.
    /// There is no deadline timer here. On expiry the SDK owner must withdraw the
    /// ledger entry, unlock, then cancel/drop the owner to wake an idle handler.
    /// Reservation ownership is independent of a transient native dial attempt.
    /// `released` waits for OperationOwner AND every capability clone to disappear.
    /// Cancel alone retains the owner's reference. Take/drop it outside ledger
    /// locks before awaiting release; use weak captures to avoid ownership cycles.
    /// The release callback runs outside gate locks.
    pub fn owned(
        descriptor: OperationDescriptor,
        admit: impl Fn(&OperationDescriptor, Option<ConnectionId>) -> bool + Send + Sync + 'static,
        released: impl FnOnce() + Send + Sync + 'static,
    ) -> (OperationOwner, Self) {
        let shared = Arc::new(Shared::new(Some(Authority {
            descriptor,
            admit: Box::new(admit),
            released: Some(Box::new(released)),
        })));
        (OperationOwner(shared.clone()), Self(shared))
    }

    pub fn generation(&self) -> Option<NonZeroU64> {
        self.0.authority.as_ref().map(|a| a.descriptor.generation)
    }

    pub(crate) fn capture(
        factory: Option<&OperationFactory>,
        peer: PeerId,
        address: &Multiaddr,
        kind: OperationKind,
    ) -> io::Result<Self> {
        let operation = match factory {
            Some(factory) => factory(peer, address, kind)?,
            None => Self(Arc::new(Shared::new(None))),
        };
        if let Some(authority) = &operation.0.authority {
            let descriptor = &authority.descriptor;
            if descriptor.peer != peer || descriptor.address != *address || descriptor.kind != kind
            {
                return Err(denied());
            }
        }
        if operation.0.claimed.swap(true, Ordering::AcqRel) || !operation.live() {
            return Err(denied());
        }
        Ok(operation)
    }

    pub(crate) fn bind(&self, control: ConnectionId) -> bool {
        if !self.check(Some(control)) {
            return false;
        }
        let bound = {
            let Ok(mut current) = self.0.control.lock() else {
                return false;
            };
            match *current {
                Some(old) => old == control,
                None => {
                    *current = Some(control);
                    true
                }
            }
        };
        bound && self.live()
    }

    pub(crate) fn matches(&self, peer: PeerId, kind: OperationKind) -> bool {
        self.0.authority.as_ref().is_none_or(|authority| {
            authority.descriptor.peer == peer && authority.descriptor.kind == kind
        })
    }

    pub(crate) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub(crate) fn cancel(&self) {
        self.0.cancel();
    }

    pub(crate) fn live(&self) -> bool {
        let control = match self.0.control.lock() {
            Ok(control) => *control,
            Err(_) => return false,
        };
        if !self.check(control) {
            self.0.cancel();
            return false;
        }
        true
    }

    fn check(&self, control: Option<ConnectionId>) -> bool {
        if self.0.cancelled.load(Ordering::Acquire) {
            return false;
        }
        let admitted = self
            .0
            .authority
            .as_ref()
            .is_none_or(|authority| (authority.admit)(&authority.descriptor, control));
        admitted && !self.0.cancelled.load(Ordering::Acquire)
    }

    pub(crate) fn poll_live(&self, cx: &Context<'_>, protocol: bool) -> bool {
        let slot = if protocol {
            &self.0.protocol
        } else {
            &self.0.idle
        };
        // Waker vtables may reenter: clone, drop and wake only outside the mutex.
        let replacement = cx.waker().clone();
        let previous = {
            let Ok(mut slot) = slot.lock() else {
                return false;
            };
            slot.replace(replacement)
        };
        drop(previous);
        self.live()
    }

    /// cancel-safe: yes — denial drops the protocol future without another poll.
    pub(crate) async fn run<F, T, E>(&self, future: F) -> Result<T, E>
    where
        F: Future<Output = Result<T, E>>,
        E: From<io::Error>,
    {
        let mut future = std::pin::pin!(future);
        futures::future::poll_fn(|cx| {
            if !self.poll_live(cx, true) {
                return Poll::Ready(Err(denied().into()));
            }
            future.as_mut().poll(cx)
        })
        .await
    }
}

impl Shared {
    fn new(authority: Option<Authority>) -> Self {
        Self {
            authority,
            cancelled: AtomicBool::new(false),
            claimed: AtomicBool::new(false),
            control: Mutex::new(None),
            idle: Mutex::new(None),
            protocol: Mutex::new(None),
        }
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        for slot in [&self.idle, &self.protocol] {
            let waker = {
                let mut slot = slot.lock().unwrap_or_else(|error| error.into_inner());
                slot.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }
}

pub(crate) fn denied() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}

pub(crate) struct CancelOnDrop(pub(crate) Option<OperationCapability>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if let Some(operation) = &self.0 {
            operation.cancel();
        }
    }
}

#[cfg(test)]
#[path = "operation_tests.rs"]
mod tests;
