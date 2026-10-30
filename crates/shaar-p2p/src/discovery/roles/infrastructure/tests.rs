use super::super::*;
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Wake, Waker},
    time::Duration,
};

fn peer() -> PeerId {
    libp2p::identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id()
}

fn connection(value: usize) -> ConnectionId {
    ConnectionId::new_unchecked(value)
}

fn root(peer: PeerId) -> Root {
    use libp2p::multiaddr::Protocol;
    let address = libp2p::Multiaddr::empty()
        .with(Protocol::Ip4("8.8.8.8".parse().unwrap()))
        .with(Protocol::Tcp(4001))
        .with(Protocol::P2p(peer));
    Root::new(address.as_ref(), peer).unwrap()
}

fn stage(owner: &mut Owner, peer: PeerId, id: usize) -> (AttemptKey, InfrastructurePermit) {
    let now = Instant::now();
    owner
        .stage_infrastructure(
            peer,
            connection(id),
            now + Duration::from_secs(10),
            now,
            root(peer),
        )
        .unwrap()
}

#[test]
fn infrastructure_stage_has_four_bounded_slots_and_releases_on_both_terminals() {
    let peers: Vec<_> = (0..5).map(|_| peer()).collect();
    let mut owner = Owner::new(&[], &peers).unwrap();
    let mut staged: Vec<_> = peers[..4]
        .iter()
        .enumerate()
        .map(|(index, peer)| stage(&mut owner, *peer, index))
        .collect();
    let now = Instant::now();
    assert!(
        owner
            .stage_infrastructure(
                peers[4],
                connection(4),
                now + Duration::from_secs(5),
                now,
                root(peers[4])
            )
            .is_err()
    );
    let key = staged[0].0;
    owner.terminal(key, None, now);
    owner.infrastructure_terminal(key);
    assert!(
        owner
            .stage_infrastructure(
                peers[4],
                connection(4),
                now + Duration::from_secs(5),
                now,
                root(peers[4])
            )
            .is_err()
    );
    drop(staged.remove(0));
    stage(&mut owner, peers[4], 4);
}

#[test]
fn infrastructure_permits_retain_rows_and_terminal_order_is_irrelevant() {
    let p = peer();
    let mut owner = Owner::new(&[], &[p]).unwrap();
    let (key, initial) = stage(&mut owner, p, 1);
    let view = owner.view();
    let mut permits = vec![initial];
    for _ in 1..super::super::LEASES {
        permits.push(view.infrastructure_permit(key).unwrap());
    }
    assert!(view.infrastructure_permit(key).is_none());
    owner.infrastructure_terminal(key);
    owner.terminal(key, None, Instant::now());
    assert!(view.infrastructure_permit(key).is_none());
    drop(permits);
    stage(&mut owner, p, 2);
}

#[test]
fn infrastructure_root_failure_rolls_back_and_stale_owner_key_is_rejected() {
    let p = peer();
    let mut owner = Owner::new(&[], &[p]).unwrap();
    let now = Instant::now();
    assert!(
        owner
            .stage_infrastructure(
                p,
                connection(19),
                now + Duration::from_secs(3),
                now,
                root(peer())
            )
            .is_err()
    );
    let (key, permit) = stage(&mut owner, p, 20);
    let foreign = stage(&mut Owner::new(&[], &[p]).unwrap(), p, 20).0;
    assert!(owner.view().infrastructure_permit(foreign).is_none());
    assert!(!owner.view().infrastructure_pending(foreign, now));
    drop(permit);
    assert!(owner.view().infrastructure_pending(key, now));
}
#[test]
fn authenticated_numeric_witness_survives_duplicate_terminal_and_retained_permit() {
    let p = peer();
    let mut owner = Owner::new(&[], &[p]).unwrap();
    let (key, permit) = stage(&mut owner, p, 7);
    let view = owner.view();
    let root_lease = view.lease(key, LeaseKind::Root, Instant::now()).unwrap();
    let numeric = view.lease(key, LeaseKind::Numeric, Instant::now()).unwrap();
    let endpoint: SocketAddr = "8.8.8.8:4001".parse().unwrap();
    numeric.record_numeric(endpoint, Instant::now()).unwrap();
    assert_eq!(view.infrastructure_live(key), None);
    assert_eq!(owner.terminal(key, Some(p), Instant::now()), Some(endpoint));
    assert_eq!(view.infrastructure_live(key), Some(endpoint));
    assert!(view.infrastructure_permit(key).is_some());
    assert_eq!(owner.terminal(key, None, Instant::now()), None);
    assert_eq!(view.infrastructure_live(key), Some(endpoint));
    drop(numeric);
    drop(root_lease);
    owner.infrastructure_terminal(key);
    assert_eq!(view.infrastructure_live(key), None);
    drop(permit);
    assert_ne!(stage(&mut owner, p, 8).0, key);
}

#[test]
fn infrastructure_numeric_guard_drop_orders_and_expiry_are_deterministic() {
    let p = peer();
    let mut owner = Owner::new(&[], &[p]).unwrap();
    let now = Instant::now();
    let (key, permit) = owner
        .stage_infrastructure(
            p,
            connection(30),
            now + Duration::from_secs(2),
            now,
            root(p),
        )
        .unwrap();
    let view = owner.view();
    let root_lease = view.lease(key, LeaseKind::Root, Instant::now()).unwrap();
    let mut extra = Vec::new();
    for _ in 1..super::super::LEASES {
        extra.push(view.infrastructure_permit(key).unwrap());
    }
    assert!(view.infrastructure_permit(key).is_none());
    owner.terminal(key, Some(p), now);
    assert_eq!(view.infrastructure_live(key), None);
    owner.infrastructure_terminal(key);
    assert!(view.infrastructure_permit(key).is_none());
    drop((extra, permit, root_lease));
    let (next, permit) = stage(&mut owner, p, 31);
    assert_ne!(next, key);
    owner.infrastructure_terminal(next);
    owner.terminal(next, None, Instant::now());
    drop(permit);
    let (expired, permit) = stage(&mut owner, p, 32);
    assert!(
        !owner
            .view()
            .infrastructure_pending(expired, Instant::now() + Duration::from_secs(11))
    );
    drop(permit);
}

#[test]
fn infrastructure_withdrawal_revokes_numeric_guard_and_foreign_keys_are_inert() {
    let p = peer();
    let mut owner = Owner::new(&[], &[p]).unwrap();
    let (key, permit) = stage(&mut owner, p, 40);
    let foreign = stage(&mut Owner::new(&[], &[p]).unwrap(), p, 40).0;
    let root_lease = owner
        .view()
        .lease(key, LeaseKind::Root, Instant::now())
        .unwrap();
    let numeric = owner
        .view()
        .lease(key, LeaseKind::Numeric, Instant::now())
        .unwrap();
    numeric
        .record_numeric("8.8.8.8:4001".parse().unwrap(), Instant::now())
        .unwrap();
    owner.infrastructure_withdraw(foreign);
    assert!(owner.view().infrastructure_pending(key, Instant::now()));
    owner.infrastructure_withdraw(key);
    assert!(!owner.view().infrastructure_pending(key, Instant::now()));
    assert!(
        numeric
            .record_numeric("8.8.8.8:4001".parse().unwrap(), Instant::now())
            .is_err()
    );
    drop((numeric, root_lease, permit));
}

#[test]
fn infrastructure_close_reconciles_pending_rows() {
    let p = peer();
    let mut owner = Owner::new(&[], &[p]).unwrap();
    let (key, permit) = stage(&mut owner, p, 50);
    owner.close();
    assert!(!owner.view().infrastructure_pending(key, Instant::now()));
    assert!(owner.view().infrastructure_permit(key).is_none());
    drop(permit);
}

struct WakeFlag(AtomicBool);
impl Wake for WakeFlag {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[test]
fn infrastructure_withdrawal_wakes_registered_numeric_lease() {
    let p = peer();
    let mut owner = Owner::new(&[], &[p]).unwrap();
    let (key, permit) = stage(&mut owner, p, 70);
    let _root_lease = owner
        .view()
        .lease(key, LeaseKind::Root, Instant::now())
        .unwrap();
    let mut lease = owner
        .view()
        .lease(key, LeaseKind::Numeric, Instant::now())
        .unwrap();
    let notified = Arc::new(WakeFlag(AtomicBool::new(false)));
    let waker = Waker::from(notified.clone());
    assert!(lease.poll_check(&mut Context::from_waker(&waker)).is_ok());
    owner.infrastructure_withdraw(key);
    assert!(notified.0.load(Ordering::SeqCst));
    assert!(lease.poll_check(&mut Context::from_waker(&waker)).is_err());
    owner.terminal(key, None, Instant::now());
    owner.infrastructure_terminal(key);
    drop((lease, _root_lease, permit));
}

#[test]
fn infrastructure_collector_drop_orders_preserve_four_of_four_capacity() {
    for native_first in [true, false] {
        let peers: Vec<_> = (0..5).map(|_| peer()).collect();
        let mut owner = Owner::new(&[], &peers).unwrap();
        let mut rows: Vec<_> = peers[..4]
            .iter()
            .enumerate()
            .map(|(i, &p)| stage(&mut owner, p, 80 + i))
            .collect();
        let (key, permit) = rows.remove(0);
        let root_lease = owner
            .view()
            .lease(key, LeaseKind::Root, Instant::now())
            .unwrap();
        let mut numeric = owner
            .view()
            .lease(key, LeaseKind::Numeric, Instant::now())
            .unwrap();
        numeric
            .record_numeric("8.8.8.8:4001".parse().unwrap(), Instant::now())
            .unwrap();
        let notified = Arc::new(WakeFlag(AtomicBool::new(false)));
        numeric
            .poll_check(&mut Context::from_waker(&Waker::from(notified.clone())))
            .unwrap();
        if native_first {
            assert_eq!(
                owner.terminal(key, Some(peers[0]), Instant::now()),
                Some("8.8.8.8:4001".parse().unwrap())
            );
            assert!(owner.view().infrastructure_live(key).is_some());
            owner.infrastructure_terminal(key);
        } else {
            owner.infrastructure_terminal(key);
            assert!(!owner.view().infrastructure_pending(key, Instant::now()));
            assert!(
                numeric
                    .poll_check(&mut Context::from_waker(Waker::noop()))
                    .is_err()
            );
            assert!(owner.view.lock().attempts.contains_key(&key.connection));
            assert_eq!(owner.terminal(key, Some(peers[0]), Instant::now()), None);
        }
        assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 4);
        assert!(notified.0.load(Ordering::SeqCst));
        assert!(
            numeric
                .poll_check(&mut Context::from_waker(Waker::noop()))
                .is_err()
        );
        assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 4);
        assert!(owner.view().infrastructure_permit(key).is_none());
        assert!(
            owner
                .stage_infrastructure(
                    peers[4],
                    connection(84),
                    Instant::now() + Duration::from_secs(5),
                    Instant::now(),
                    root(peers[4])
                )
                .is_err()
        );
        if native_first {
            drop(permit);
            assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 4);
            drop(numeric);
            assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 4);
            drop(root_lease);
        } else {
            drop(numeric);
            assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 4);
            drop(permit);
            assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 4);
            drop(root_lease);
        }
        assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 3);
        let (replacement_key, replacement_permit) = stage(&mut owner, peers[4], 84);
        assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 4);
        owner.terminal(replacement_key, None, Instant::now());
        owner.infrastructure_terminal(replacement_key);
        drop(replacement_permit);
        assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 3);
        for (key, permit) in rows {
            owner.terminal(key, None, Instant::now());
            owner.infrastructure_terminal(key);
            drop(permit);
        }
    }
}

#[test]
fn infrastructure_live_nonreserved_identity_survives_witness_until_all_authority_drops() {
    let p = peer();
    let mut owner = Owner::new(&[], &[]).unwrap();
    owner.admit_identity(p, Role::Infrastructure).unwrap();
    let (key, permit) = stage(&mut owner, p, 90);
    let root_lease = owner
        .view()
        .lease(key, LeaseKind::Root, Instant::now())
        .unwrap();
    let numeric = owner
        .view()
        .lease(key, LeaseKind::Numeric, Instant::now())
        .unwrap();
    numeric
        .record_numeric("8.8.8.8:4001".parse().unwrap(), Instant::now())
        .unwrap();
    assert_eq!(
        owner.terminal(key, Some(p), Instant::now()),
        Some("8.8.8.8:4001".parse().unwrap())
    );
    drop(numeric);
    drop(root_lease);
    assert!(owner.view().role(p).is_some());
    assert!(owner.forget_identity(p).is_err());
    assert!(
        owner
            .admit_identity(p, Role::ExplicitRelay("8.8.8.8:4001".parse().unwrap()))
            .is_err()
    );
    owner.infrastructure_terminal(key);
    assert!(owner.forget_identity(p).is_err());
    drop(permit);
    assert!(owner.forget_identity(p).is_ok());
    assert_eq!(owner.view().role(p), None);
}

#[test]
fn infrastructure_role_rejects_application_but_allows_new_identity_admission() {
    let p = peer();
    let app = peer();
    let mut owner = Owner::new(&[app], &[p]).unwrap();
    let unregistered = peer();
    owner
        .admit_identity(unregistered, Role::Infrastructure)
        .unwrap();
    let retained = stage(&mut owner, unregistered, 59);
    assert_eq!(owner.view().role(unregistered), Some(Role::Infrastructure));
    let now = Instant::now();
    assert!(
        owner
            .stage_infrastructure(
                app,
                connection(60),
                now + Duration::from_secs(1),
                now,
                root(app)
            )
            .is_err()
    );
    assert!(owner.forget_identity(unregistered).is_err());
    owner.terminal(retained.0, None, now);
    owner.infrastructure_terminal(retained.0);
    drop(retained.1);
    assert!(owner.forget_identity(unregistered).is_ok());
}

#[cfg(test)]
mod contacts;
#[cfg(test)]
mod matrix;
