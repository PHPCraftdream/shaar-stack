#![forbid(unsafe_code)]
//! Fixture-only, single-operation observation; never installed in product sources.

use crate::operation_gate::{OperationCapability, OperationKind};
use libp2p_identity::PeerId;
use libp2p_swarm::ConnectionId;
use std::{
    io,
    sync::{
        Mutex,
        atomic::{AtomicU8, Ordering},
    },
    task::{Context, Poll, Waker},
};

pub const BUILD_VARIANT: &str = "baseline";
type Identity = (u64, ConnectionId);
pub(crate) type Descriptor = Option<(PeerId, OperationKind, u64)>;
static MODE: AtomicU8 = AtomicU8::new(0);

struct ListenerState {
    peer: Option<PeerId>,
    generation: Option<u64>,
    queued: Option<Identity>,
    held: bool,
    retained: Option<OperationCapability>,
    observer: Option<Waker>,
    barrier: Option<Waker>,
}

static LISTENER: Mutex<ListenerState> = Mutex::new(ListenerState {
    peer: None,
    generation: None,
    queued: None,
    held: false,
    retained: None,
    observer: None,
    barrier: None,
});

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub entered: Option<Identity>,
    pub held: bool,
    pub fresh_inner_polls: usize,
    pub denied_protocol_polls: usize,
    pub listener_entered: Option<u64>,
    pub error_queued: Option<Identity>,
    pub listener_held: bool,
}

struct State {
    peer: Option<PeerId>,
    entered: Option<Identity>,
    held: bool,
    polls: usize,
    denied: usize,
    retained: Option<OperationCapability>,
    retention_taken: bool,
    observer: Option<Waker>,
    barrier: Option<Waker>,
}

// One fixture operation and one observer; foreign vtables run outside this lock.
static STATE: Mutex<State> = Mutex::new(State {
    peer: None,
    entered: None,
    held: false,
    polls: 0,
    denied: 0,
    retained: None,
    retention_taken: false,
    observer: None,
    barrier: None,
});

fn state_snapshot(state: &State) -> Snapshot {
    Snapshot {
        entered: state.entered,
        held: state.held,
        fresh_inner_polls: state.polls,
        denied_protocol_polls: state.denied,
        listener_entered: None,
        error_queued: None,
        listener_held: false,
    }
}

pub fn arm(peer: PeerId) -> io::Result<()> {
    let mut state = STATE
        .lock()
        .map_err(|_| io::Error::other("probe poisoned"))?;
    if state.peer.is_some()
        || MODE
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
    {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    state.peer = Some(peer);
    state.held = true;
    Ok(())
}

pub fn snapshot() -> Snapshot {
    if MODE.load(Ordering::SeqCst) == 2 {
        listener_snapshot(&LISTENER.lock().expect("fixture listener lock"))
    } else {
        state_snapshot(&STATE.lock().expect("fixture probe lock"))
    }
}

fn observe(cx: &mut Context<'_>, previous: Option<usize>, resolution: bool) -> Poll<Snapshot> {
    let replacement = cx.waker().clone();
    let (result, previous_waker, unused) = {
        let mut state = STATE.lock().expect("fixture probe lock");
        let result = state_snapshot(&state);
        let ready = match previous {
            Some(count) => result.fresh_inner_polls != count || (resolution && state.denied > 0),
            None => result.entered.is_some(),
        };
        if ready {
            (
                Poll::Ready(result),
                state.observer.take(),
                Some(replacement),
            )
        } else {
            (Poll::Pending, state.observer.replace(replacement), None)
        }
    };
    drop(previous_waker);
    drop(unused);
    result
}

pub fn poll_entered(cx: &mut Context<'_>) -> Poll<Snapshot> {
    observe(cx, None, false)
}

pub fn poll_progress(cx: &mut Context<'_>, previous_inner_polls: usize) -> Poll<Snapshot> {
    observe(cx, Some(previous_inner_polls), false)
}

pub fn poll_resolution(cx: &mut Context<'_>) -> Poll<Snapshot> {
    observe(cx, Some(0), true)
}

pub fn release_protocol() {
    let (barrier, observer) = {
        let mut state = STATE.lock().expect("fixture probe lock");
        state.held = false;
        (state.barrier.take(), state.observer.take())
    };
    if let Some(waker) = barrier {
        waker.wake();
    }
    if let Some(waker) = observer {
        waker.wake();
    }
}

/// Reset only after the scenario has destroyed the prior operation owners.
pub fn reset() {
    let (retained, barrier, observer) = {
        let mut state = STATE.lock().expect("fixture probe lock");
        state.peer = None;
        state.entered = None;
        state.held = false;
        state.polls = 0;
        state.denied = 0;
        state.retention_taken = false;
        (
            state.retained.take(),
            state.barrier.take(),
            state.observer.take(),
        )
    };
    drop(retained);
    if let Some(waker) = barrier {
        waker.wake();
    }
    if let Some(waker) = observer {
        waker.wake();
    }
    reset_listener();
}

fn reset_listener() {
    let (retained, barrier, observer) = {
        let mut state = LISTENER.lock().expect("fixture listener lock");
        state.peer = None;
        state.generation = None;
        state.queued = None;
        state.held = false;
        (
            state.retained.take(),
            state.barrier.take(),
            state.observer.take(),
        )
    };
    MODE.store(0, Ordering::SeqCst);
    drop(retained);
    if let Some(waker) = barrier {
        waker.wake();
    }
    if let Some(waker) = observer {
        waker.wake();
    }
}

pub fn take_retained() -> Option<OperationCapability> {
    if MODE.load(Ordering::SeqCst) == 2 {
        return LISTENER
            .lock()
            .expect("fixture listener lock")
            .retained
            .take();
    }
    let mut state = STATE.lock().expect("fixture probe lock");
    state.retention_taken = true;
    state.retained.take()
}

pub fn bound_live(capability: &OperationCapability) -> bool {
    capability.live()
}

pub(crate) fn before_protocol_poll(
    cx: &mut Context<'_>,
    capability: &OperationCapability,
    descriptor: Descriptor,
    control: Option<ConnectionId>,
) -> Poll<()> {
    let Some((peer, OperationKind::Reserve, generation)) = descriptor else {
        return Poll::Ready(());
    };
    if STATE.lock().expect("fixture probe lock").peer != Some(peer) {
        return Poll::Ready(());
    }
    let control = control.expect("selected protocol must be authenticated and bound");
    assert_ne!(generation, 0);
    let replacement = cx.waker().clone();
    let retained = capability.clone();
    let (held, old_barrier, unused_waker, unused_capability, observer) = {
        let mut state = STATE.lock().expect("fixture probe lock");
        assert_eq!(state.peer, Some(peer), "fixture reset during an owned poll");
        let identity = (generation, control);
        let first = state.entered.is_none();
        if let Some(previous) = state.entered {
            assert_eq!(previous, identity, "only one owned operation may park");
        }
        state.entered = Some(identity);
        let unused_capability = if first && !state.retention_taken {
            state.retained.replace(retained)
        } else {
            Some(retained)
        };
        let (old_barrier, unused_waker) = if state.held {
            (state.barrier.replace(replacement), None)
        } else {
            (state.barrier.take(), Some(replacement))
        };
        let observer = if first { state.observer.take() } else { None };
        (
            state.held,
            old_barrier,
            unused_waker,
            unused_capability,
            observer,
        )
    };
    drop(old_barrier);
    drop(unused_waker);
    drop(unused_capability);
    if let Some(waker) = observer {
        waker.wake();
    }
    if held { Poll::Pending } else { Poll::Ready(()) }
}

pub(crate) fn inner_poll_started(descriptor: Descriptor, control: Option<ConnectionId>) {
    resolution_observed(descriptor, control, false);
}

pub(crate) fn protocol_denied(descriptor: Descriptor, control: Option<ConnectionId>) {
    resolution_observed(descriptor, control, true);
}

fn listener_snapshot(state: &ListenerState) -> Snapshot {
    Snapshot {
        entered: None,
        held: false,
        fresh_inner_polls: 0,
        denied_protocol_polls: 0,
        listener_entered: state.generation,
        error_queued: state.queued,
        listener_held: state.held,
    }
}

pub fn arm_listener(peer: PeerId) -> io::Result<()> {
    let mut state = LISTENER
        .lock()
        .map_err(|_| io::Error::other("listener probe poisoned"))?;
    if state.peer.is_some()
        || MODE
            .compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
    {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    state.peer = Some(peer);
    state.held = true;
    Ok(())
}

pub fn poll_queued_listener(cx: &mut Context<'_>) -> Poll<Snapshot> {
    let next = cx.waker().clone();
    let (result, old, unused) = {
        let mut state = LISTENER.lock().expect("fixture listener lock");
        let ready = state.held
            && state
                .queued
                .is_some_and(|(generation, _)| Some(generation) == state.generation);
        if ready {
            (
                Poll::Ready(listener_snapshot(&state)),
                state.observer.take(),
                Some(next),
            )
        } else {
            (Poll::Pending, state.observer.replace(next), None)
        }
    };
    drop(old);
    drop(unused);
    result
}

pub fn release_listener() {
    let (barrier, observer) = {
        let mut state = LISTENER.lock().expect("fixture listener lock");
        state.held = false;
        (state.barrier.take(), state.observer.take())
    };
    if let Some(waker) = barrier {
        waker.wake();
    }
    if let Some(waker) = observer {
        waker.wake();
    }
}

pub(crate) fn before_listener_poll(
    cx: &mut Context<'_>,
    capability: &OperationCapability,
) -> Poll<()> {
    if MODE.load(Ordering::SeqCst) != 2 {
        return Poll::Ready(());
    }
    let Some((peer, OperationKind::Reserve, generation, _)) = capability.proof_identity() else {
        return Poll::Ready(());
    };
    let next = cx.waker().clone();
    let (held, old, unused, observer) = {
        let mut state = LISTENER.lock().expect("fixture listener lock");
        if state.peer != Some(peer) {
            (false, None, Some(next), None)
        } else {
            let first = state.generation.is_none();
            if let Some(previous) = state.generation {
                assert_eq!(previous, generation, "one selected listener generation");
            }
            state.generation = Some(generation);
            let (old, unused) = if state.held {
                (state.barrier.replace(next), None)
            } else {
                (state.barrier.take(), Some(next))
            };
            let observer = if first { state.observer.take() } else { None };
            (state.held, old, unused, observer)
        }
    };
    drop(old);
    drop(unused);
    if let Some(waker) = observer {
        waker.wake();
    }
    if held { Poll::Pending } else { Poll::Ready(()) }
}

pub(crate) fn typed_error_queued(capability: &OperationCapability) {
    if MODE.load(Ordering::SeqCst) != 2 {
        return;
    }
    let Some((peer, OperationKind::Reserve, generation, control)) = capability.proof_identity()
    else {
        return;
    };
    let control = control.expect("typed rejection belongs to an authenticated control");
    let retained = capability.clone();
    let (unused, observer) = {
        let mut state = LISTENER.lock().expect("fixture listener lock");
        if state.peer != Some(peer) {
            (Some(retained), None)
        } else {
            assert!(
                state.queued.is_none(),
                "one actual successful typed-error send"
            );
            state.queued = Some((generation, control));
            (state.retained.replace(retained), state.observer.take())
        }
    };
    drop(unused);
    if let Some(waker) = observer {
        waker.wake();
    }
}

fn resolution_observed(descriptor: Descriptor, control: Option<ConnectionId>, denied: bool) {
    let Some((peer, OperationKind::Reserve, generation)) = descriptor else {
        return;
    };
    let observer = {
        let mut state = STATE.lock().expect("fixture probe lock");
        if state.peer != Some(peer) {
            return;
        }
        assert_eq!(state.entered, control.map(|control| (generation, control)));
        assert!(state.entered.is_some(), "inner poll without barrier entry");
        let counter = if denied {
            &mut state.denied
        } else {
            &mut state.polls
        };
        *counter = counter.checked_add(1).expect("bounded fixture poll count");
        state.observer.take()
    };
    if let Some(waker) = observer {
        waker.wake();
    }
}
