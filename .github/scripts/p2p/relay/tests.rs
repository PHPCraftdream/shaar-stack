#![forbid(unsafe_code)]

use super::*;
use std::{sync::atomic::AtomicUsize, task::Wake};

fn descriptor(kind: OperationKind, generation: u64) -> OperationDescriptor {
    OperationDescriptor::new(
        PeerId::random(),
        "/memory/121".parse().unwrap(),
        kind,
        NonZeroU64::new(generation).unwrap(),
    )
}

fn owned() -> (OperationOwner, OperationCapability) {
    OperationCapability::owned(descriptor(OperationKind::Reserve, 1), |_, _| true, || {})
}

#[test]
fn owner_drop_revokes_all_clones_without_rearming() {
    let (owner, operation) = owned();
    let clone = operation.clone();
    assert!(clone.live());
    drop(owner);
    assert!(!operation.live());
    assert!(!clone.bind(ConnectionId::new_unchecked(1)));
}

#[test]
fn authoritative_state_is_checked_again_not_snapshotted() {
    let eligible = Arc::new(AtomicBool::new(true));
    let check = eligible.clone();
    let (_owner, operation) = OperationCapability::owned(
        descriptor(OperationKind::Reserve, 1),
        move |_, _| check.load(Ordering::Acquire),
        || {},
    );
    assert!(operation.live());
    eligible.store(false, Ordering::Release);
    assert!(!operation.live());
    eligible.store(true, Ordering::Release);
    assert!(!operation.live(), "observed revocation was rearmed");
}

#[test]
fn descriptor_mismatch_and_repeated_capture_are_rejected() {
    let (_owner, operation) = owned();
    let context = &operation.0.authority.as_ref().unwrap().descriptor;
    let peer = context.peer;
    let address = context.address.clone();
    let captured = operation.clone();
    let factory: OperationFactory = Arc::new(move |_, _, _| Ok(captured.clone()));
    assert!(
        OperationCapability::capture(
            Some(&factory),
            PeerId::random(),
            &address,
            OperationKind::Reserve
        )
        .is_err()
    );
    assert!(
        OperationCapability::capture(
            Some(&factory),
            peer,
            &"/memory/122".parse().unwrap(),
            OperationKind::Reserve
        )
        .is_err()
    );
    assert!(
        OperationCapability::capture(
            Some(&factory),
            peer,
            &address,
            OperationKind::Connect { destination: peer }
        )
        .is_err()
    );
    assert!(
        OperationCapability::capture(Some(&factory), peer, &address, OperationKind::Reserve)
            .is_ok()
    );
    assert!(
        OperationCapability::capture(Some(&factory), peer, &address, OperationKind::Reserve)
            .is_err()
    );
}

#[test]
fn authenticated_binding_cannot_change_control_generation() {
    let (_owner, operation) = owned();
    let first = ConnectionId::new_unchecked(1);
    assert!(operation.bind(first));
    assert!(operation.bind(first));
    assert!(!operation.bind(ConnectionId::new_unchecked(2)));
    assert!(operation.live());
}

#[test]
fn owner_can_reject_the_authenticated_control() {
    let accepted = ConnectionId::new_unchecked(9);
    let (_owner, operation) = OperationCapability::owned(
        descriptor(OperationKind::Reserve, 1),
        move |_, control| control.is_none_or(|id| id == accepted),
        || {},
    );
    assert!(!operation.bind(ConnectionId::new_unchecked(8)));
    assert!(operation.bind(accepted));
}

struct CountWake(AtomicUsize);
impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn cancellation_wakes_both_sites_and_registration_is_bounded() {
    let (owner, operation) = owned();
    let idle = Arc::new(CountWake(AtomicUsize::new(0)));
    let protocol = Arc::new(CountWake(AtomicUsize::new(0)));
    let idle_waker = Waker::from(idle.clone());
    let protocol_waker = Waker::from(protocol.clone());
    for _ in 0..8 {
        assert!(operation.poll_live(&Context::from_waker(&idle_waker), false));
        assert!(operation.poll_live(&Context::from_waker(&protocol_waker), true));
    }
    owner.cancel();
    assert_eq!(idle.0.load(Ordering::SeqCst), 1);
    assert_eq!(protocol.0.load(Ordering::SeqCst), 1);
    assert!(!operation.poll_live(&Context::from_waker(&idle_waker), false));
}

#[test]
fn cancelled_protocol_future_is_not_polled_again() {
    let (owner, operation) = owned();
    let polls = AtomicUsize::new(0);
    let future = futures::future::poll_fn(|_| {
        polls.fetch_add(1, Ordering::SeqCst);
        Poll::<io::Result<()>>::Pending
    });
    let mut guarded = std::pin::pin!(operation.run(future));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(guarded.as_mut().poll(&mut cx).is_pending());
    owner.cancel();
    assert!(matches!(
        guarded.as_mut().poll(&mut cx),
        Poll::Ready(Err(_))
    ));
    assert_eq!(
        polls.load(Ordering::SeqCst),
        1,
        "operation future poll gate bypassed"
    );
}

#[test]
fn unpolled_cancelled_protocol_never_performs_its_first_poll() {
    let (owner, operation) = owned();
    owner.cancel();
    let result: io::Result<()> = futures::executor::block_on(operation.run(async {
        panic!("revoked operation reached first protocol poll");
    }));
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
}

#[test]
fn charge_release_waits_for_owner_and_every_placeholder_clone() {
    let drops = Arc::new(AtomicUsize::new(0));
    let on_drop = drops.clone();
    let (owner, operation) = OperationCapability::owned(
        descriptor(OperationKind::Reserve, 1),
        |_, _| true,
        move || {
            on_drop.fetch_add(1, Ordering::SeqCst);
        },
    );
    let placeholder = operation.clone();
    drop(owner);
    drop(operation);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(placeholder);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn retained_owner_delays_release_after_all_capabilities_are_dropped() {
    let drops = Arc::new(AtomicUsize::new(0));
    let released = drops.clone();
    let (owner, operation) = OperationCapability::owned(
        descriptor(OperationKind::Reserve, 1),
        |_, _| true,
        move || {
            released.fetch_add(1, Ordering::SeqCst);
        },
    );
    let clone = operation.clone();
    drop(operation);
    drop(clone);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    owner.cancel();
    assert_eq!(
        drops.load(Ordering::SeqCst),
        0,
        "cancel released a retained owner"
    );
    drop(owner);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn admission_callback_may_cancel_without_gate_lock_reentrancy() {
    let holder: Arc<Mutex<Option<OperationOwner>>> = Arc::new(Mutex::new(None));
    let callback = holder.clone();
    let (owner, operation) = OperationCapability::owned(
        descriptor(OperationKind::Reserve, 1),
        move |_, _| {
            let owner = callback.lock().unwrap().take();
            drop(owner);
            true
        },
        || {},
    );
    *holder.lock().unwrap() = Some(owner);
    assert!(!operation.bind(ConnectionId::new_unchecked(3)));
}

struct ReenterWake(OperationCapability);
impl Wake for ReenterWake {
    fn wake(self: Arc<Self>) {
        assert!(!self.0.live());
        self.0.cancel();
    }
}

#[test]
fn cancellation_waker_may_reenter_the_gate() {
    let (owner, operation) = owned();
    let waker = Waker::from(Arc::new(ReenterWake(operation.clone())));
    assert!(operation.poll_live(&Context::from_waker(&waker), false));
    owner.cancel();
    assert!(!operation.live());
}

#[test]
fn stale_operation_cancellation_does_not_revoke_another_operation() {
    let (old_owner, old) = owned();
    let (_new_owner, new) = owned();
    old_owner.cancel();
    assert!(!old.live());
    assert!(new.live());
    assert!(!old.same(&new));
}
