use super::*;
use crate::discovery::roles::Owner;
use libp2p::{
    Multiaddr,
    core::Endpoint,
    swarm::{ConnectionDenied, NetworkBehaviour},
};
use std::{io, sync::Arc};
use tokio::time::Instant;

fn peer() -> PeerId {
    Keypair::generate_ed25519().public().to_peer_id()
}

fn addr(port: u16, peer: PeerId) -> Multiaddr {
    format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer}")
        .parse()
        .unwrap()
}

fn rawaddr(port: u16) -> Multiaddr {
    format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap()
}

fn admission(apps: &[PeerId]) -> Admission {
    Admission::with_authority(apps.to_vec(), Owner::new(apps, &[]).unwrap(), None).unwrap()
}

fn establish(
    admission: &mut Admission,
    id: ConnectionId,
    peer: PeerId,
    address: &Multiaddr,
) -> Result<libp2p::swarm::dummy::ConnectionHandler, ConnectionDenied> {
    admission.handle_established_outbound_connection(
        id,
        peer,
        address,
        Endpoint::Dialer,
        libp2p::core::transport::PortUse::New,
    )
}

#[test]
fn carrier_destination_inbound_close_wakes_retained_upgrade() {
    use futures::task::{ArcWake, waker};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct WakeCounter(AtomicUsize);
    impl ArcWake for WakeCounter {
        fn wake_by_ref(counter: &Arc<Self>) {
            counter.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let mut owner = Owner::new(&[], &[]).unwrap();
    let view = owner.view();
    let mut lease = view.incoming_lease(&rawaddr(1), &rawaddr(2)).unwrap();
    let counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
    let waker = waker(counter.clone());
    let mut cx = std::task::Context::from_waker(&waker);
    lease.poll_check(&mut cx).unwrap();
    owner.close();
    assert_eq!(counter.0.load(Ordering::SeqCst), 1);
    assert!(lease.poll_check(&mut cx).is_err());
    drop(lease);
}

#[test]
fn carrier_destination_invalid_root_does_not_leak_admission() {
    let app = peer();
    let mut admission = admission(&[app]);
    let bad = addr(4001, peer());
    assert_eq!(
        admission
            .stage_native(app, &bad, ConnectionId::new_unchecked(1))
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(
        admission
            .stage_native(app, &addr(4001, app), ConnectionId::new_unchecked(1))
            .unwrap()
            .is_some()
    );
}

#[test]
fn carrier_destination_pin_failure_is_terminal_and_reusable() {
    let app = peer();
    let mut admission = admission(&[app]);
    let dns: Multiaddr = format!("/dns4/owned.example./tcp/4001/p2p/{app}")
        .parse()
        .unwrap();
    assert!(
        admission
            .stage_native(app, &dns, ConnectionId::new_unchecked(2))
            .is_err()
    );
    assert!(
        admission
            .stage_native(app, &addr(4002, app), ConnectionId::new_unchecked(2))
            .unwrap()
            .is_some()
    );
}

#[test]
fn carrier_destination_inbound_budget_tracks_real_registry_leases_and_terminal() {
    let apps: Vec<_> = (0..10).map(|_| peer()).collect();
    let mut admission = admission(&apps);
    let view = admission.roles_view().unwrap();
    let mut leases = Vec::new();
    let mut inbound = Vec::new();
    for n in 0..4u16 {
        let local = rawaddr(4000 + n);
        let remote = rawaddr(5000 + n);
        let id = ConnectionId::new_unchecked(10 + n as usize);
        leases.push(view.incoming_lease(&local, &remote).unwrap());
        admission
            .handle_pending_inbound_connection(id, &local, &remote)
            .unwrap();
        inbound.push((id, local, remote));
    }
    let mut attempts = Vec::new();
    for n in 0..4 {
        let id = ConnectionId::new_unchecked(20 + n);
        let key = admission
            .stage_native(apps[4 + n], &addr(4100 + n as u16, apps[4 + n]), id)
            .unwrap()
            .unwrap();
        attempts.push(key);
    }
    let ninth = addr(4180, apps[8]);
    let ninth_id = ConnectionId::new_unchecked(28);
    assert_eq!(
        admission
            .stage_native(apps[8], &ninth, ninth_id)
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    let (id, local, remote) = &inbound[0];
    assert!(
        admission
            .handle_established_inbound_connection(*id, apps[0], local, remote)
            .is_ok()
    );
    assert!(admission.stage_native(apps[8], &ninth, ninth_id).is_err());
    drop(leases.remove(0));
    assert!(
        admission
            .stage_native(apps[8], &ninth, ninth_id)
            .unwrap()
            .is_some()
    );
    drop((leases, attempts));
}

#[test]
fn carrier_destination_pending_inbound_release_precedes_terminal() {
    let apps: Vec<_> = (0..9).map(|_| peer()).collect();
    let mut admission = admission(&apps);
    let view = admission.roles_view().unwrap();
    let local = rawaddr(4200);
    let remote = rawaddr(5200);
    let id = ConnectionId::new_unchecked(40);
    let lease = view.incoming_lease(&local, &remote).unwrap();
    admission
        .handle_pending_inbound_connection(id, &local, &remote)
        .unwrap();
    drop(lease);
    for n in 0..7 {
        assert!(
            admission
                .stage_native(
                    apps[n],
                    &addr(4300 + n as u16, apps[n]),
                    ConnectionId::new_unchecked(50 + n)
                )
                .unwrap()
                .is_some()
        );
    }
    assert_eq!(
        admission
            .stage_native(
                apps[7],
                &addr(4407, apps[7]),
                ConnectionId::new_unchecked(57)
            )
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(
        admission
            .handle_established_inbound_connection(id, apps[8], &local, &remote)
            .is_ok()
    );
    assert!(
        admission
            .stage_native(
                apps[7],
                &addr(4407, apps[7]),
                ConnectionId::new_unchecked(57)
            )
            .unwrap()
            .is_some()
    );
}

#[test]
fn carrier_destination_terminal_requires_exact_numeric_witness() {
    let app = peer();
    let mut admission = admission(&[app]);
    let address = addr(4300, app);
    let first = ConnectionId::new_unchecked(50);
    let key = admission
        .stage_native(app, &address, first)
        .unwrap()
        .unwrap();
    assert!(establish(&mut admission, first, app, &address).is_err());
    assert!(admission.connection(&app).is_none());
    admission.terminal(key, None);

    let second = ConnectionId::new_unchecked(51);
    let key = admission
        .stage_native(app, &address, second)
        .unwrap()
        .unwrap();
    let view = admission.roles_view().unwrap();
    let root = view.root_lease(address.as_ref()).unwrap();
    let (numeric, endpoint) = view.numeric_lease(address.as_ref()).unwrap();
    numeric.record_numeric(endpoint, Instant::now()).unwrap();
    assert!(establish(&mut admission, second, app, &address).is_ok());
    admission.terminal(key, Some(app));
    drop((root, numeric));

    let third = ConnectionId::new_unchecked(52);
    let key = admission
        .stage_native(app, &address, third)
        .unwrap()
        .unwrap();
    let view = admission.roles_view().unwrap();
    let root = view.root_lease(address.as_ref()).unwrap();
    let (numeric, endpoint) = view.numeric_lease(address.as_ref()).unwrap();
    numeric.record_numeric(endpoint, Instant::now()).unwrap();
    assert!(establish(&mut admission, third, peer(), &address).is_err());
    assert!(admission.connection(&app).is_none());
    admission.terminal(key, None);
    drop((root, numeric));
}
