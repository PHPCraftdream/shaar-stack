use super::*;

#[test]
fn matrix_a_eight_ordinary_attempts_share_quota_but_not_infrastructure_slots() {
    let peers: Vec<_> = (0..13).map(|_| peer()).collect();
    let mut owner = Owner::new(&peers[..9], &peers[9..13]).unwrap();
    let mut ordinary = Vec::new();
    for (index, &p) in peers[..8].iter().enumerate() {
        ordinary.push(
            owner
                .admit(
                    p,
                    connection(index),
                    Instant::now() + Duration::from_secs(5),
                    Instant::now(),
                )
                .unwrap(),
        );
    }
    assert_eq!(owner.view.lock().attempts.len(), 8);
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 0);
    assert!(
        owner
            .stage_infrastructure(
                peers[9],
                connection(20),
                Instant::now() + Duration::from_secs(5),
                Instant::now(),
                root(peers[9])
            )
            .is_err()
    );
    assert_eq!(owner.view.lock().attempts.len(), 8);
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 0);
    owner.terminal(ordinary.remove(0), None, Instant::now());
    let (first, first_permit) = stage(&mut owner, peers[9], 20);
    assert_eq!(owner.view.lock().attempts.len(), 8);
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 1);
    owner.terminal(first, None, Instant::now());
    owner.infrastructure_terminal(first);
    drop(first_permit);
    for key in ordinary {
        owner.terminal(key, None, Instant::now());
    }

    let peers: Vec<_> = (0..5).map(|_| peer()).collect();
    let mut owner = Owner::new(&[], &peers).unwrap();
    let mut rows: Vec<_> = peers[..4]
        .iter()
        .enumerate()
        .map(|(i, &p)| stage(&mut owner, p, 30 + i))
        .collect();
    assert!(
        owner
            .stage_infrastructure(
                peers[4],
                connection(34),
                Instant::now() + Duration::from_secs(5),
                Instant::now(),
                root(peers[4])
            )
            .is_err()
    );
    for (key, permit) in rows.drain(..) {
        owner.terminal(key, None, Instant::now());
        owner.infrastructure_terminal(key);
        drop(permit);
    }
}

#[test]
fn matrix_a_inbound_charge_blocks_infrastructure_until_finished() {
    let peers: Vec<_> = (0..8).map(|_| peer()).collect();
    let mut owner = Owner::new(&peers[..7], &peers[7..]).unwrap();
    let mut ordinary = Vec::new();
    for (index, &p) in peers[..7].iter().enumerate() {
        ordinary.push(
            owner
                .admit(
                    p,
                    connection(index),
                    Instant::now() + Duration::from_secs(5),
                    Instant::now(),
                )
                .unwrap(),
        );
    }
    let inbound = connection(7);
    owner.admit_inbound(inbound).unwrap();
    {
        let state = owner.view.lock();
        assert_eq!(state.attempts.len(), 7);
        assert_eq!(state.inbound_count, 1);
        assert_eq!(state.infrastructure.iter().flatten().count(), 0);
    }
    assert!(
        owner
            .stage_infrastructure(
                peers[7],
                connection(20),
                Instant::now() + Duration::from_secs(5),
                Instant::now(),
                root(peers[7]),
            )
            .is_err()
    );
    owner.finish_inbound(inbound);
    let (key, permit) = stage(&mut owner, peers[7], 20);
    {
        let state = owner.view.lock();
        assert_eq!(state.attempts.len(), 8);
        assert_eq!(state.inbound_count, 0);
        assert_eq!(state.infrastructure.iter().flatten().count(), 1);
    }
    owner.terminal(key, None, Instant::now());
    owner.infrastructure_terminal(key);
    drop(permit);
    for key in ordinary {
        owner.terminal(key, None, Instant::now());
    }
    {
        let state = owner.view.lock();
        assert_eq!(state.attempts.len(), 0);
        assert_eq!(state.inbound_count, 0);
        assert_eq!(state.infrastructure.iter().flatten().count(), 0);
    }
}

#[test]
fn matrix_b_same_connection_successor_rejects_stale_old_keys() {
    let p = peer();
    let mut owner = Owner::new(&[], &[p]).unwrap();
    let (old, old_permit) = stage(&mut owner, p, 220);
    let old_root = owner
        .view()
        .lease(old, LeaseKind::Root, Instant::now())
        .unwrap();
    let old_numeric = owner
        .view()
        .lease(old, LeaseKind::Numeric, Instant::now())
        .unwrap();
    assert!(
        owner
            .stage_infrastructure(
                p,
                connection(220),
                Instant::now() + Duration::from_secs(5),
                Instant::now(),
                root(p)
            )
            .is_err()
    );
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 1);
    assert!(
        owner
            .stage_infrastructure(
                p,
                connection(220),
                Instant::now() + Duration::from_secs(5),
                Instant::now(),
                root(p)
            )
            .is_err()
    );
    owner.infrastructure_withdraw(old);
    owner.terminal(old, None, Instant::now());
    owner.infrastructure_terminal(old);
    assert!(
        owner
            .stage_infrastructure(
                p,
                connection(220),
                Instant::now() + Duration::from_secs(5),
                Instant::now(),
                root(p)
            )
            .is_err()
    );
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 1);
    drop(old_root);
    drop(old_numeric);
    drop(old_permit);
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 0);
    let (next, next_permit) = stage(&mut owner, p, 220);
    assert_ne!(old.serial, next.serial);
    let next_root = owner
        .view()
        .lease(next, LeaseKind::Root, Instant::now())
        .unwrap();
    let mut numeric = owner
        .view()
        .lease(next, LeaseKind::Numeric, Instant::now())
        .unwrap();
    let notified = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(Flag(notified.clone())));
    numeric
        .poll_check(&mut Context::from_waker(&waker))
        .unwrap();
    assert!(owner.view().infrastructure_permit(old).is_none());
    assert!(!owner.view().infrastructure_pending(old, Instant::now()));
    assert_eq!(owner.view().infrastructure_live(old), None);
    assert!(
        owner
            .view()
            .lease(old, LeaseKind::Root, Instant::now())
            .is_err()
    );
    owner.terminal(old, Some(p), Instant::now());
    owner.infrastructure_terminal(old);
    owner.infrastructure_withdraw(old);
    assert!(!notified.load(Ordering::SeqCst));
    assert!(owner.view().infrastructure_pending(next, Instant::now()));
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 1);
    assert_eq!(owner.view.lock().attempts.len(), 1);
    assert!(!notified.load(Ordering::SeqCst));
    numeric
        .poll_check(&mut Context::from_waker(&waker))
        .unwrap();
    assert!(owner.view().infrastructure_pending(next, Instant::now()));
    owner.terminal(next, None, Instant::now());
    owner.infrastructure_terminal(next);
    drop((numeric, next_root, next_permit));
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 0);
}

#[test]
fn matrix_c_different_connection_retains_authenticated_record_until_permit_drops() {
    let p = peer();
    let mut owner = Owner::new(&[], &[p]).unwrap();
    let (old, permit) = stage(&mut owner, p, 230);
    let view = owner.view();
    let root_lease = view.lease(old, LeaseKind::Root, Instant::now()).unwrap();
    let numeric = view.lease(old, LeaseKind::Numeric, Instant::now()).unwrap();
    numeric
        .record_numeric("8.8.8.8:4001".parse().unwrap(), Instant::now())
        .unwrap();
    assert!(owner.terminal(old, Some(p), Instant::now()).is_some());
    owner.infrastructure_terminal(old);
    assert_eq!(view.lock().infrastructure.iter().flatten().count(), 1);
    drop((root_lease, numeric));
    assert_eq!(view.lock().infrastructure.iter().flatten().count(), 1);
    let (next, next_permit) = stage(&mut owner, p, 231);
    assert_ne!(old, next);
    assert!(owner.view().infrastructure_pending(next, Instant::now()));
    assert_eq!(view.infrastructure_live(old), None);
    assert_eq!(view.lock().infrastructure.iter().flatten().count(), 2);
    let next_root = view.lease(next, LeaseKind::Root, Instant::now()).unwrap();
    let mut next_numeric = view
        .lease(next, LeaseKind::Numeric, Instant::now())
        .unwrap();
    let notified = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(Flag(notified.clone())));
    let mut context = Context::from_waker(&waker);
    next_numeric.poll_check(&mut context).unwrap();
    owner.terminal(old, None, Instant::now());
    owner.infrastructure_terminal(old);
    owner.infrastructure_withdraw(old);
    assert_eq!(view.infrastructure_live(old), None);
    assert!(view.infrastructure_pending(next, Instant::now()));
    assert!(!notified.load(Ordering::SeqCst));
    next_numeric.poll_check(&mut context).unwrap();
    assert_eq!(view.lock().infrastructure.iter().flatten().count(), 2);
    drop(permit);
    assert_eq!(view.lock().infrastructure.iter().flatten().count(), 1);
    assert!(view.infrastructure_pending(next, Instant::now()));
    assert!(!notified.load(Ordering::SeqCst));
    next_numeric.poll_check(&mut context).unwrap();
    owner.terminal(next, None, Instant::now());
    owner.infrastructure_terminal(next);
    drop(next_root);
    assert_eq!(view.lock().infrastructure.iter().flatten().count(), 1);
    drop(next_numeric);
    drop(next_permit);
    assert_eq!(view.lock().infrastructure.iter().flatten().count(), 0);
}

struct Flag(Arc<AtomicBool>);
impl Wake for Flag {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn key_matrix(
    owner: &mut Owner,
    p: PeerId,
    id: usize,
) -> (AttemptKey, InfrastructurePermit, Lease, Lease) {
    let (key, permit) = stage(owner, p, id);
    let root = owner
        .view()
        .lease(key, LeaseKind::Root, Instant::now())
        .unwrap();
    let numeric = owner
        .view()
        .lease(key, LeaseKind::Numeric, Instant::now())
        .unwrap();
    (key, permit, root, numeric)
}

#[test]
fn matrix_d_all_malformed_keys_leave_active_count_and_waiter_untouched() {
    let p = peer();
    let mut owner = Owner::new(&[], &[p]).unwrap();
    let (key, permit, root_lease, mut numeric) = key_matrix(&mut owner, p, 240);
    let mut wrong_peer = key;
    wrong_peer.peer = peer();
    let mut wrong_connection = key;
    wrong_connection.connection = connection(241);
    let mut wrong_serial = key;
    wrong_serial.serial += 1;
    let foreign = stage(&mut Owner::new(&[], &[p]).unwrap(), p, 240).0;
    let notified = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(Flag(notified.clone())));
    let mut context = Context::from_waker(&waker);
    numeric.poll_check(&mut context).unwrap();
    for wrong in [wrong_peer, wrong_connection, wrong_serial, foreign] {
        assert!(!owner.view().infrastructure_pending(wrong, Instant::now()));
        assert!(owner.view().infrastructure_permit(wrong).is_none());
        assert!(
            owner
                .view()
                .lease(wrong, LeaseKind::Root, Instant::now())
                .is_err()
        );
        assert!(
            owner
                .view()
                .lease(wrong, LeaseKind::Numeric, Instant::now())
                .is_err()
        );
        owner.infrastructure_terminal(wrong);
        owner.infrastructure_withdraw(wrong);
        owner.terminal(wrong, Some(p), Instant::now());
        assert!(!notified.load(Ordering::SeqCst));
        assert!(numeric.poll_check(&mut context).is_ok());
        assert!(owner.view().infrastructure_pending(key, Instant::now()));
        assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 1);
        assert_eq!(owner.view.lock().attempts.len(), 1);
        assert!(!notified.load(Ordering::SeqCst));
    }
    owner.terminal(key, None, Instant::now());
    owner.infrastructure_terminal(key);
    drop((root_lease, numeric, permit));
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 0);
    assert_eq!(owner.view.lock().attempts.len(), 0);
}

#[test]
fn matrix_e_wrong_endpoint_and_authentication_never_promote() {
    for outcome in [None, Some(peer())] {
        let p = peer();
        let mut owner = Owner::new(&[], &[p]).unwrap();
        let (key, permit, root_lease, numeric) = key_matrix(&mut owner, p, 250);
        for endpoint in ["8.8.4.4:4001", "8.8.8.8:4002"] {
            let endpoint: SocketAddr = endpoint.parse().unwrap();
            let address: libp2p::Multiaddr =
                format!("/ip4/{}/tcp/{}/p2p/{p}", endpoint.ip(), endpoint.port())
                    .parse()
                    .unwrap();
            assert!(!owner.view().permits_address(address.as_ref()));
            assert!(numeric.record_numeric(endpoint, Instant::now()).is_err());
        }
        numeric
            .record_numeric("8.8.8.8:4001".parse().unwrap(), Instant::now())
            .unwrap();
        assert_eq!(owner.terminal(key, outcome, Instant::now()), None);
        assert_eq!(owner.view().infrastructure_live(key), None);
        assert!(owner.view().infrastructure_permit(key).is_none());
        assert_eq!(owner.terminal(key, Some(p), Instant::now()), None);
        assert_eq!(owner.view().infrastructure_live(key), None);
        owner.infrastructure_terminal(key);
        drop((root_lease, numeric, permit));
        assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 0);
        assert_eq!(owner.view.lock().attempts.len(), 0);
    }
}

#[test]
fn matrix_h_close_pending_wakes_without_terminal_flags_then_collects_exactly() {
    let p = peer();
    let mut owner = Owner::new(&[], &[p]).unwrap();
    let (key, permit, root_lease, mut numeric) = key_matrix(&mut owner, p, 260);
    numeric
        .record_numeric("8.8.8.8:4001".parse().unwrap(), Instant::now())
        .unwrap();
    let notified = Arc::new(AtomicBool::new(false));
    numeric
        .poll_check(&mut Context::from_waker(&Waker::from(Arc::new(Flag(
            notified.clone(),
        )))))
        .unwrap();
    owner.close();
    assert!(!owner.view().infrastructure_pending(key, Instant::now()));
    assert!(owner.view().infrastructure_permit(key).is_none());
    assert!(owner.view().infrastructure_live(key).is_none());
    assert!(notified.load(Ordering::SeqCst));
    assert!(
        numeric
            .poll_check(&mut Context::from_waker(Waker::noop()))
            .is_err()
    );
    {
        let state = owner.view.lock();
        let row = state
            .infrastructure
            .iter()
            .flatten()
            .find(|row| row.key == key)
            .unwrap();
        assert!(!row.native_terminal && !row.connection_terminal);
        assert_eq!(state.infrastructure.iter().flatten().count(), 1);
    }
    drop(permit);
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 1);
    owner.terminal(key, None, Instant::now());
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 1);
    owner.infrastructure_terminal(key);
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 1);
    drop(root_lease);
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 1);
    drop(numeric);
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 0);
    assert_eq!(owner.view.lock().attempts.len(), 0);
}

#[test]
fn matrix_g_deadline_rejects_authenticated_witness_and_collects_only_after_both_terminals() {
    let p = peer();
    let mut owner = Owner::new(&[], &[p]).unwrap();
    let now = Instant::now();
    let deadline = now + Duration::from_secs(2);
    let endpoint: SocketAddr = "8.8.8.8:4001".parse().unwrap();
    let (key, permit) = owner
        .stage_infrastructure(p, connection(270), deadline, now, root(p))
        .unwrap();
    let root_lease = owner.view().lease(key, LeaseKind::Root, now).unwrap();
    let numeric = owner.view().lease(key, LeaseKind::Numeric, now).unwrap();
    numeric.record_numeric(endpoint, now).unwrap();
    assert!(
        owner
            .view()
            .infrastructure_pending(key, deadline - Duration::from_nanos(1))
    );
    assert!(!owner.view().infrastructure_pending(key, deadline));
    assert!(
        !owner
            .view()
            .infrastructure_pending(key, deadline + Duration::from_nanos(1))
    );
    drop(permit);
    {
        let state = owner.view.lock();
        let row = state
            .infrastructure
            .iter()
            .flatten()
            .find(|row| row.key == key)
            .unwrap();
        assert!(!row.native_terminal && !row.connection_terminal);
        assert_eq!(state.infrastructure.iter().flatten().count(), 1);
    }
    assert_eq!(owner.terminal(key, Some(p), deadline), None);
    assert_eq!(owner.view().infrastructure_live(key), None);
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 1);
    assert_eq!(owner.view.lock().attempts.len(), 1);
    owner.infrastructure_terminal(key);
    {
        let state = owner.view.lock();
        let row = state
            .infrastructure
            .iter()
            .flatten()
            .find(|row| row.key == key)
            .unwrap();
        assert!(row.native_terminal && row.connection_terminal);
        assert_eq!(state.infrastructure.iter().flatten().count(), 1);
    }
    assert_eq!(owner.terminal(key, Some(p), deadline), None);
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 1);
    drop(root_lease);
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 1);
    drop(numeric);
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 0);
    assert_eq!(owner.view.lock().attempts.len(), 0);
}

#[test]
fn matrix_f_both_terminal_orders_signal_and_retain_until_exact_last_guard() {
    let p = peer();

    // Native completion first preserves the authenticated live witness.
    let mut owner = Owner::new(&[], &[p]).unwrap();
    let (key, permit, root_lease, numeric) = key_matrix(&mut owner, p, 280);
    let endpoint: SocketAddr = "8.8.8.8:4001".parse().unwrap();
    numeric.record_numeric(endpoint, Instant::now()).unwrap();
    assert_eq!(owner.terminal(key, Some(p), Instant::now()), Some(endpoint));
    assert_eq!(owner.view().infrastructure_live(key), Some(endpoint));
    {
        let state = owner.view.lock();
        let row = state
            .infrastructure
            .iter()
            .flatten()
            .find(|row| row.key == key)
            .unwrap();
        assert!(row.native_terminal);
        assert!(!row.connection_terminal);
        assert_eq!(state.infrastructure.iter().flatten().count(), 1);
    }
    drop(permit);
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 1);
    drop(root_lease);
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 1);
    assert_eq!(owner.view.lock().attempts.len(), 1);
    drop(numeric);
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 1);
    assert_eq!(owner.view.lock().attempts.len(), 0);
    owner.infrastructure_terminal(key);
    assert_eq!(owner.view().infrastructure_live(key), None);
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 0);
    assert_eq!(owner.view.lock().attempts.len(), 0);
    assert!(owner.view().infrastructure_permit(key).is_none());

    let mut owner = Owner::new(&[], &[p]).unwrap();
    let (key, permit, root_lease, mut numeric) = key_matrix(&mut owner, p, 281);
    let endpoint: SocketAddr = "8.8.8.8:4001".parse().unwrap();
    let notified = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(Flag(notified.clone())));
    numeric
        .poll_check(&mut Context::from_waker(&waker))
        .unwrap();
    numeric.record_numeric(endpoint, Instant::now()).unwrap();
    owner.infrastructure_terminal(key);
    assert!(notified.load(Ordering::SeqCst));
    assert!(
        numeric
            .poll_check(&mut Context::from_waker(Waker::noop()))
            .is_err()
    );
    assert!(
        numeric
            .record_numeric("8.8.8.8:4001".parse().unwrap(), Instant::now())
            .is_err()
    );
    {
        let state = owner.view.lock();
        let row = state
            .infrastructure
            .iter()
            .flatten()
            .find(|row| row.key == key)
            .unwrap();
        assert!(!row.native_terminal);
        assert!(row.connection_terminal);
        assert_eq!(state.infrastructure.iter().flatten().count(), 1);
        assert_eq!(state.attempts.len(), 1);
    }
    drop(permit);
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 1);
    drop(root_lease);
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 1);
    drop(numeric);
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 1);
    assert_eq!(owner.view.lock().attempts.len(), 1);
    {
        let state = owner.view.lock();
        let row = state
            .infrastructure
            .iter()
            .flatten()
            .find(|row| row.key == key)
            .unwrap();
        assert!(!row.native_terminal);
        assert!(row.connection_terminal);
    }
    assert_eq!(owner.terminal(key, Some(p), Instant::now()), None);
    assert_eq!(owner.view.lock().infrastructure.iter().flatten().count(), 0);
    assert_eq!(owner.view.lock().attempts.len(), 0);
    assert!(owner.view().infrastructure_permit(key).is_none());
}
