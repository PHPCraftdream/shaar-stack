use super::*;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Wake, Waker},
    time::Duration,
};

fn peer() -> PeerId {
    libp2p::identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id()
}
fn id(value: usize) -> ConnectionId {
    ConnectionId::new_unchecked(value)
}
fn endpoint() -> SocketAddr {
    "127.0.0.1:4001".parse().unwrap()
}
fn admit(owner: &mut Owner, peer: PeerId, value: usize) -> AttemptKey {
    let now = Instant::now();
    let key = owner
        .admit(peer, id(value), now + Duration::from_secs(10), now)
        .unwrap();
    let endpoint = match owner.view().role(peer).unwrap() {
        Role::Application => endpoint(),
        Role::ExplicitRelay(endpoint) => endpoint,
        Role::Infrastructure => "8.8.8.8:4001".parse().unwrap(),
    };
    use libp2p::multiaddr::Protocol;
    let host = match endpoint.ip() {
        std::net::IpAddr::V4(ip) => Protocol::Ip4(ip),
        std::net::IpAddr::V6(ip) => Protocol::Ip6(ip),
    };
    let address = libp2p::Multiaddr::empty()
        .with(host)
        .with(Protocol::Tcp(endpoint.port()))
        .with(Protocol::P2p(peer));
    owner
        .pin_root(key, Root::new(address.as_ref(), peer).unwrap(), now)
        .unwrap();
    key
}

#[test]
fn destination_roles_identity_bounds_and_conflicts() {
    let apps: Vec<_> = (0..16).map(|_| peer()).collect();
    let seeds: Vec<_> = (0..32).map(|_| peer()).collect();
    let mut owner = Owner::new(&apps, &seeds).unwrap();
    let view = owner.view();
    for app in &apps {
        assert!(owner.admit_identity(*app, Role::Infrastructure).is_err());
        assert!(
            owner
                .admit_identity(*app, Role::ExplicitRelay(endpoint()))
                .is_err()
        );
        assert!(owner.forget_identity(*app).is_err());
    }
    for seed in &seeds {
        assert!(
            owner
                .admit_identity(*seed, Role::ExplicitRelay(endpoint()))
                .is_err()
        );
        assert!(owner.forget_identity(*seed).is_err());
        assert!(view.current(*seed, Instant::now()).is_none());
    }
    for _ in 0..8 {
        owner
            .admit_identity(peer(), Role::ExplicitRelay(endpoint()))
            .unwrap();
    }
    assert!(
        owner
            .admit_identity(peer(), Role::ExplicitRelay(endpoint()))
            .is_err()
    );
    assert!(owner.admit_identity(peer(), Role::Infrastructure).is_err());
    assert!(owner.admit_identity(peer(), Role::Application).is_err());
    assert!(Owner::new(&[apps[0]; 17], &[]).is_err());
    assert!(Owner::new(&[], &[seeds[0]; 33]).is_err());
    assert!(Owner::new(&[apps[0]], &[apps[0]]).is_err());
}

#[test]
fn destination_roles_explicit_endpoint_is_pinned_until_identity_retirement() {
    let p = peer();
    let mut owner = Owner::new(&[], &[]).unwrap();
    owner
        .admit_identity(p, Role::ExplicitRelay(endpoint()))
        .unwrap();
    owner
        .admit_identity(p, Role::ExplicitRelay(endpoint()))
        .unwrap();
    assert!(owner.admit_identity(p, Role::Infrastructure).is_err());
    assert!(
        owner
            .admit_identity(p, Role::ExplicitRelay("127.0.0.1:4002".parse().unwrap()))
            .is_err()
    );
    owner.forget_identity(p).unwrap();
    owner.admit_identity(p, Role::Infrastructure).unwrap();
    assert_eq!(owner.view().role(p), Some(Role::Infrastructure));
}

#[test]
fn destination_roles_inbound_and_outbound_share_eight_slots() {
    let peers: Vec<_> = (0..8).map(|_| peer()).collect();
    let mut owner = Owner::new(&peers, &[]).unwrap();
    let now = Instant::now();
    owner.admit_inbound(id(100)).unwrap();
    assert!(owner.admit_inbound(id(100)).is_err());
    assert!(
        owner
            .admit(peers[0], id(100), now + Duration::from_secs(1), now)
            .is_err()
    );
    let outbound = admit(&mut owner, peers[0], 101);
    assert!(owner.admit_inbound(id(101)).is_err());
    owner.finish_inbound(id(100));
    owner.terminal(outbound, None, now);
    for index in 0..4 {
        owner.admit_inbound(id(index)).unwrap();
    }
    let keys: Vec<_> = peers[..4]
        .iter()
        .enumerate()
        .map(|(index, peer)| admit(&mut owner, *peer, index + 4))
        .collect();
    let now = Instant::now();
    assert!(
        owner
            .admit(peers[4], id(8), now + Duration::from_secs(1), now)
            .is_err()
    );
    assert!(owner.admit_inbound(id(8)).is_err());
    owner.revoke(keys[0]);
    assert!(owner.admit_inbound(id(8)).is_err());
    owner.terminal(keys[0], None, now);
    owner.admit_inbound(id(8)).unwrap();
    owner.finish_inbound(id(0));
    admit(&mut owner, peers[4], 9);
    assert!(owner.admit_inbound(id(10)).is_err());
}

#[tokio::test]
async fn destination_roles_cancel_terminal_and_both_lease_drops_gate_successor() {
    let p = peer();
    let mut owner = Owner::new(&[p], &[]).unwrap();
    let view = owner.view();
    let old = admit(&mut owner, p, 1);
    let root = view.lease(old, LeaseKind::Root, Instant::now()).unwrap();
    let inner = view.lease(old, LeaseKind::Numeric, Instant::now()).unwrap();
    owner.revoke(old);
    assert!(view.check(old, Instant::now()).is_err());
    owner.terminal(old, None, Instant::now());
    drop(root);
    let now = Instant::now();
    assert!(
        owner
            .admit(p, id(2), now + Duration::from_secs(1), now)
            .is_err()
    );
    assert!(owner.forget_identity(p).is_err());
    assert!(inner.record_numeric(endpoint(), now).is_err());
    drop(inner);
    let next = admit(&mut owner, p, 2);
    assert_ne!(old.serial, next.serial);
    owner.revoke(old);
    assert!(view.check(next, Instant::now()).is_ok());
    assert!(view.check(old, Instant::now()).is_err());
    assert_eq!(owner.terminal(old, Some(p), Instant::now()), None);
    assert!(view.check(next, Instant::now()).is_ok());
}

#[tokio::test]
async fn destination_roles_destruction_before_terminal_does_not_reclaim_charge() {
    let p = peer();
    let mut owner = Owner::new(&[], &[p]).unwrap();
    let key = admit(&mut owner, p, 1);
    let lease = owner
        .view()
        .lease(key, LeaseKind::Root, Instant::now())
        .unwrap();
    drop(lease);
    owner.revoke(key);
    let now = Instant::now();
    assert!(
        owner
            .admit(p, id(2), now + Duration::from_secs(1), now)
            .is_err()
    );
    owner.terminal(key, None, now);
    admit(&mut owner, p, 2);
}

#[tokio::test]
async fn destination_roles_leases_and_watchers_are_bounded() {
    let p = peer();
    let mut owner = Owner::new(&[p], &[]).unwrap();
    let key = admit(&mut owner, p, 1);
    let view = owner.view();
    assert!(view.lease(key, LeaseKind::Numeric, Instant::now()).is_err());
    let mut leases = Vec::new();
    for _ in 0..4 {
        leases.push(view.lease(key, LeaseKind::Root, Instant::now()).unwrap());
    }
    assert!(view.lease(key, LeaseKind::Root, Instant::now()).is_err());
    for _ in 0..4 {
        leases.push(view.lease(key, LeaseKind::Numeric, Instant::now()).unwrap());
    }
    assert!(view.lease(key, LeaseKind::Numeric, Instant::now()).is_err());
    owner.terminal(key, None, Instant::now());
    assert!(view.lease(key, LeaseKind::Root, Instant::now()).is_err());
    drop(leases);
    admit(&mut owner, p, 2);
}

#[tokio::test]
async fn destination_roles_exact_authenticated_witness_and_wrong_peer_discard() {
    let expected = peer();
    let wrong = peer();
    let mut owner = Owner::new(&[expected], &[]).unwrap();
    for (index, authenticated) in [Some(wrong), None, Some(expected)].into_iter().enumerate() {
        let key = admit(&mut owner, expected, index);
        let root = owner
            .view()
            .lease(key, LeaseKind::Root, Instant::now())
            .unwrap();
        let inner = owner
            .view()
            .lease(key, LeaseKind::Numeric, Instant::now())
            .unwrap();
        assert!(root.record_numeric(endpoint(), Instant::now()).is_err());
        inner.record_numeric(endpoint(), Instant::now()).unwrap();
        assert!(
            inner
                .record_numeric("127.0.0.1:4002".parse().unwrap(), Instant::now())
                .is_err()
        );
        assert_eq!(
            owner.terminal(key, authenticated, Instant::now()),
            (authenticated == Some(expected)).then_some(endpoint())
        );
        assert_eq!(owner.terminal(key, authenticated, Instant::now()), None);
        assert!(inner.record_numeric(endpoint(), Instant::now()).is_err());
        drop((root, inner));
    }
}

#[tokio::test]
async fn destination_roles_numeric_witness_enforces_strict_and_exact_endpoint_roles() {
    for role in [Role::Infrastructure, Role::ExplicitRelay(endpoint())] {
        let p = peer();
        let mut owner = Owner::new(&[], &[]).unwrap();
        owner.admit_identity(p, role).unwrap();
        let key = admit(&mut owner, p, 1);
        let root = owner
            .view()
            .lease(key, LeaseKind::Root, Instant::now())
            .unwrap();
        let inner = owner
            .view()
            .lease(key, LeaseKind::Numeric, Instant::now())
            .unwrap();
        let global = "8.8.8.8:4001".parse().unwrap();
        let (allowed, denied) = if role == Role::Infrastructure {
            (global, endpoint())
        } else {
            (endpoint(), global)
        };
        assert!(inner.record_numeric(denied, Instant::now()).is_err());
        inner.record_numeric(allowed, Instant::now()).unwrap();
        assert_eq!(owner.terminal(key, Some(p), Instant::now()), Some(allowed));
        drop((root, inner));
    }
}

#[test]
fn destination_roles_serial_overflow_deadline_and_foreign_keys_fail_closed() {
    let p = peer();
    let mut a = Owner::new(&[p], &[]).unwrap();
    let mut b = Owner::new(&[p], &[]).unwrap();
    let ka = admit(&mut a, p, 1);
    let kb = admit(&mut b, p, 1);
    assert_ne!(ka, kb);
    assert!(b.view().check(ka, Instant::now()).is_err());
    b.revoke(ka);
    assert!(b.view().check(kb, Instant::now()).is_ok());
    a.terminal(ka, None, Instant::now());
    a.view.lock().serial = u64::MAX;
    let now = Instant::now();
    assert!(
        a.admit(p, id(2), now + Duration::from_secs(1), now)
            .is_err()
    );
    assert!(a.view().current(p, now).is_none());
    let mut owner = Owner::new(&[p], &[]).unwrap();
    assert!(owner.admit(p, id(3), now, now).is_err());
    assert!(
        owner
            .admit(p, id(3), now + Duration::from_secs(11), now)
            .is_err()
    );
    assert!(
        owner
            .admit(peer(), id(3), now + Duration::from_secs(1), now)
            .is_err()
    );
}

struct Reenter {
    view: View,
    blocked: Arc<AtomicBool>,
    poisoned: Arc<AtomicBool>,
    woke: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}
impl Reenter {
    fn probe(&self) {
        let (blocked, poisoned) = match self.view.0.try_lock() {
            Ok(_) => (false, false),
            Err(std::sync::TryLockError::WouldBlock) => (true, false),
            Err(std::sync::TryLockError::Poisoned(_)) => (false, true),
        };
        self.blocked.fetch_or(blocked, Ordering::SeqCst);
        self.poisoned.fetch_or(poisoned, Ordering::SeqCst);
    }
}
impl Wake for Reenter {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.probe();
        self.woke.fetch_or(true, Ordering::SeqCst);
    }
}
impl Drop for Reenter {
    fn drop(&mut self) {
        self.probe();
        self.dropped.fetch_or(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn destination_roles_revocation_wakes_and_drops_foreign_wakers_outside_lock() {
    let p = peer();
    let mut owner = Owner::new(&[p], &[]).unwrap();
    let key = admit(&mut owner, p, 1);
    let view = owner.view();
    let mut root = view.lease(key, LeaseKind::Root, Instant::now()).unwrap();
    let woke = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let blocked = Arc::new(AtomicBool::new(false));
    let poisoned = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(Reenter {
        view: view.clone(),
        blocked: blocked.clone(),
        poisoned: poisoned.clone(),
        woke: woke.clone(),
        dropped: dropped.clone(),
    }));
    assert!(root.poll_check(&mut Context::from_waker(&waker)).is_ok());
    owner.revoke(key);
    assert!(woke.load(Ordering::SeqCst));
    assert!(!blocked.load(Ordering::SeqCst));
    assert!(!poisoned.load(Ordering::SeqCst));
    assert!(view.check(key, Instant::now()).is_err());
    assert!(root.poll_check(&mut Context::from_waker(&waker)).is_err());
    owner.terminal(key, None, Instant::now());
    drop(waker);
    drop(root);
    assert!(dropped.load(Ordering::SeqCst));
    assert!(!blocked.load(Ordering::SeqCst));
    assert!(!poisoned.load(Ordering::SeqCst));
    admit(&mut owner, p, 2);
}

#[tokio::test]
async fn destination_roles_cancel_before_first_poll_is_not_lost() {
    let p = peer();
    let mut owner = Owner::new(&[p], &[]).unwrap();
    let key = admit(&mut owner, p, 1);
    let mut root = owner
        .view()
        .lease(key, LeaseKind::Root, Instant::now())
        .unwrap();
    owner.revoke(key);
    assert!(
        root.poll_check(&mut Context::from_waker(Waker::noop()))
            .is_err()
    );
    owner.terminal(key, None, Instant::now());
    drop(root);
    admit(&mut owner, p, 2);
}

#[tokio::test(start_paused = true)]
async fn destination_roles_absolute_deadline_covers_unpolled_lease() {
    let p = peer();
    let mut owner = Owner::new(&[p], &[]).unwrap();
    let key = admit(&mut owner, p, 1);
    let mut root = owner
        .view()
        .lease(key, LeaseKind::Root, Instant::now())
        .unwrap();
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(
        root.poll_check(&mut Context::from_waker(Waker::noop()))
            .is_err()
    );
    assert_eq!(owner.terminal(key, Some(p), Instant::now()), None);
    drop(root);
}

#[tokio::test]
async fn destination_roles_close_and_owner_drop_seal_retained_handles() {
    let p = peer();
    let mut owner = Owner::new(&[p], &[]).unwrap();
    let key = admit(&mut owner, p, 1);
    let view = owner.view();
    let mut root = view.lease(key, LeaseKind::Root, Instant::now()).unwrap();
    owner.close();
    assert!(view.role(p).is_none());
    assert!(view.current(p, Instant::now()).is_none());
    assert!(view.lease(key, LeaseKind::Root, Instant::now()).is_err());
    assert!(owner.admit_inbound(id(2)).is_err());
    assert!(owner.admit_identity(peer(), Role::Infrastructure).is_err());
    assert!(
        root.poll_check(&mut Context::from_waker(Waker::noop()))
            .is_err()
    );
    drop(owner);
    assert!(view.check(key, Instant::now()).is_err());
    drop(root);
    let mut owner = Owner::new(&[p], &[]).unwrap();
    let key = admit(&mut owner, p, 3);
    let view = owner.view();
    drop(owner);
    assert!(view.check(key, Instant::now()).is_err());
}

#[test]
fn destination_roles_replacing_and_dropping_waiters_can_reenter_without_runtime() {
    let p = peer();
    let mut owner = Owner::new(&[p], &[]).unwrap();
    let key = admit(&mut owner, p, 1);
    let view = owner.view();
    let mut root = view.lease(key, LeaseKind::Root, Instant::now()).unwrap();
    assert_eq!(root.key(), key);
    assert!(root.deadline() > Instant::now());
    for replacing in [true, false] {
        let dropped = Arc::new(AtomicBool::new(false));
        let blocked = Arc::new(AtomicBool::new(false));
        let poisoned = Arc::new(AtomicBool::new(false));
        let waker = Waker::from(Arc::new(Reenter {
            view: view.clone(),
            blocked: blocked.clone(),
            poisoned: poisoned.clone(),
            woke: Arc::new(AtomicBool::new(false)),
            dropped: dropped.clone(),
        }));
        assert!(root.poll_check(&mut Context::from_waker(&waker)).is_ok());
        drop(waker);
        assert!(!dropped.load(Ordering::SeqCst));
        if replacing {
            assert!(
                root.poll_check(&mut Context::from_waker(Waker::noop()))
                    .is_ok()
            );
        } else {
            drop(root);
            root = view.lease(key, LeaseKind::Root, Instant::now()).unwrap();
        }
        assert!(dropped.load(Ordering::SeqCst));
        assert!(!blocked.load(Ordering::SeqCst));
        assert!(!poisoned.load(Ordering::SeqCst));
        assert!(view.check(key, Instant::now()).is_ok());
    }
    owner.terminal(key, None, Instant::now());
    drop(root);
}

#[test]
fn destination_roles_revocation_discards_an_already_recorded_numeric_witness() {
    let p = peer();
    let mut owner = Owner::new(&[], &[]).unwrap();
    owner
        .admit_identity(p, Role::ExplicitRelay(endpoint()))
        .unwrap();
    let key = admit(&mut owner, p, 1);
    let view = owner.view();
    let root = view.lease(key, LeaseKind::Root, Instant::now()).unwrap();
    let inner = view.lease(key, LeaseKind::Numeric, Instant::now()).unwrap();
    inner.record_numeric(endpoint(), Instant::now()).unwrap();
    owner.revoke(key);
    assert_eq!(owner.terminal(key, Some(p), Instant::now()), None);
    assert!(owner.forget_identity(p).is_err());
    drop((root, inner));
    owner.forget_identity(p).unwrap();
    owner.admit_identity(p, Role::Infrastructure).unwrap();
    assert!(view.check(key, Instant::now()).is_err());
}
