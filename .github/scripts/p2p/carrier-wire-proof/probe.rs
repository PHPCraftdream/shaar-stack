#![forbid(unsafe_code)]
//! Fixture-only, single-operation observation; never installed in product sources.

use crate::operation_gate::{OperationCapability, OperationKind};
use libp2p_identity::PeerId;
use libp2p_swarm::ConnectionId;
use std::{
    io,
    sync::Mutex,
    task::{Context, Poll, Waker},
};

pub const BUILD_VARIANT: &str = "baseline";
type Identity = (u64, ConnectionId);
pub(crate) type Descriptor = Option<(PeerId, OperationKind, u64)>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub entered: Option<Identity>,
    pub held: bool,
    pub fresh_inner_polls: usize,
    pub denied_protocol_polls: usize,
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
    }
}

pub fn arm(peer: PeerId) -> io::Result<()> {
    let mut state = STATE
        .lock()
        .map_err(|_| io::Error::other("probe poisoned"))?;
    if state.peer.is_some() {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    state.peer = Some(peer);
    state.held = true;
    Ok(())
}

pub fn snapshot() -> Snapshot {
    state_snapshot(&STATE.lock().expect("fixture probe lock"))
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
}

pub fn take_retained() -> Option<OperationCapability> {
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
