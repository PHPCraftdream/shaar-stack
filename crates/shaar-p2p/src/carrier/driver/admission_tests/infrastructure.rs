use super::*;
use crate::discovery::roles::{AttemptKey, InfrastructurePermit, Lease, Role};
use libp2p::{core::ConnectedPoint, swarm::behaviour::FromSwarm};
use std::time::Duration;

fn address(port: u16, peer: PeerId) -> Multiaddr {
    format!("/ip4/8.8.8.8/tcp/{port}/p2p/{peer}")
        .parse()
        .unwrap()
}

fn configured(peers: &[PeerId]) -> Admission {
    Admission::with_authority(vec![], Owner::new(&[], peers).unwrap(), None).unwrap()
}

fn stage(
    admission: &mut Admission,
    peer: PeerId,
    address: &Multiaddr,
    id: ConnectionId,
) -> (AttemptKey, InfrastructurePermit) {
    admission
        .stage_infrastructure(peer, address, id, Instant::now() + Duration::from_secs(10))
        .unwrap()
}

fn pending(
    admission: &mut Admission,
    peer: PeerId,
    id: ConnectionId,
    addresses: &[Multiaddr],
) -> bool {
    admission
        .handle_pending_outbound_connection(id, Some(peer), addresses, Endpoint::Dialer)
        .is_ok()
}

fn guards(admission: &Admission, address: &Multiaddr, witness: bool) -> (Lease, Lease) {
    let view = admission.roles_view().unwrap();
    let context = view.root_lease(address.as_ref()).unwrap();
    let (numeric, endpoint) = view.numeric_lease(address.as_ref()).unwrap();
    if witness {
        numeric.record_numeric(endpoint, Instant::now()).unwrap();
    }
    (context, numeric)
}

fn finish(admission: &mut Admission, key: AttemptKey, permit: InfrastructurePermit) {
    admission.withdraw_infrastructure(key);
    admission.terminal(key, None);
    admission.terminal_infrastructure(key);
    drop(permit);
}

fn connected(admission: &mut Admission, peer: PeerId, id: ConnectionId, address: &Multiaddr) {
    let endpoint = ConnectedPoint::Dialer {
        address: address.clone(),
        role_override: Endpoint::Dialer,
        port_use: libp2p::core::transport::PortUse::New,
    };
    admission.on_swarm_event(FromSwarm::ConnectionEstablished(
        libp2p::swarm::behaviour::ConnectionEstablished {
            peer_id: peer,
            connection_id: id,
            endpoint: &endpoint,
            failed_addresses: &[],
            other_established: 0,
        },
    ));
}

fn closed(admission: &mut Admission, peer: PeerId, id: ConnectionId, address: &Multiaddr) {
    let endpoint = ConnectedPoint::Dialer {
        address: address.clone(),
        role_override: Endpoint::Dialer,
        port_use: libp2p::core::transport::PortUse::New,
    };
    admission.on_swarm_event(FromSwarm::ConnectionClosed(
        libp2p::swarm::behaviour::ConnectionClosed {
            peer_id: peer,
            connection_id: id,
            endpoint: &endpoint,
            cause: None,
            remaining_established: 0,
        },
    ));
}

#[test]
fn carrier_infrastructure_admission_requires_exact_staged_root_and_control() {
    let infra = peer();
    let foreign = peer();
    let mut admission = configured(&[infra]);
    let id = ConnectionId::new_unchecked(145);
    let root = address(4450, infra);
    assert!(!pending(
        &mut admission,
        infra,
        id,
        std::slice::from_ref(&root)
    ));
    let (key, permit) = stage(&mut admission, infra, &root, id);
    assert!(pending(
        &mut admission,
        infra,
        id,
        std::slice::from_ref(&root)
    ));
    assert!(!pending(&mut admission, infra, id, &[address(4451, infra)]));
    assert!(!pending(
        &mut admission,
        foreign,
        id,
        std::slice::from_ref(&root)
    ));
    assert!(!pending(
        &mut admission,
        infra,
        id,
        &[address(4450, foreign)]
    ));
    assert!(!pending(
        &mut admission,
        infra,
        ConnectionId::new_unchecked(146),
        std::slice::from_ref(&root)
    ));
    assert!(!pending(
        &mut admission,
        infra,
        id,
        &[root.clone(), root.clone()]
    ));
    let bare: Multiaddr = "/ip4/8.8.8.8/tcp/4450".parse().unwrap();
    assert!(pending(&mut admission, infra, id, &[bare]));
    admission.withdraw_infrastructure(key);
    assert!(!pending(
        &mut admission,
        infra,
        id,
        std::slice::from_ref(&root)
    ));
    finish(&mut admission, key, permit);
}

#[test]
fn carrier_infrastructure_admission_rejects_absent_authority_and_other_roles() {
    let app = peer();
    let infra = peer();
    let root = address(4460, infra);
    let id = ConnectionId::new_unchecked(147);
    let mut legacy = Admission::new(vec![]).unwrap();
    assert!(
        legacy
            .stage_infrastructure(infra, &root, id, Instant::now() + Duration::from_secs(10))
            .is_err()
    );
    let mut admission =
        Admission::with_authority(vec![app], Owner::new(&[app], &[infra]).unwrap(), None).unwrap();
    for candidate in [app, peer()] {
        assert!(
            admission
                .stage_infrastructure(
                    candidate,
                    &address(4460, candidate),
                    id,
                    Instant::now() + Duration::from_secs(10),
                )
                .is_err()
        );
    }
    assert!(
        admission
            .stage_infrastructure(
                infra,
                &address(4460, app),
                id,
                Instant::now() + Duration::from_secs(10),
            )
            .is_err()
    );
    let (key, permit) = stage(&mut admission, infra, &root, id);
    finish(&mut admission, key, permit);
}

#[test]
fn carrier_infrastructure_admission_requires_owned_charge_and_numeric_witness() {
    let infra = peer();
    let mut admission = configured(&[infra]);
    let root = address(4470, infra);
    let first = ConnectionId::new_unchecked(150);
    let key = admission
        .stage_native(infra, &root, first)
        .unwrap()
        .unwrap();
    let leases = guards(&admission, &root, true);
    assert!(!pending(
        &mut admission,
        infra,
        first,
        std::slice::from_ref(&root)
    ));
    assert!(establish(&mut admission, first, infra, &root).is_err());
    admission.terminal(key, None);
    drop(leases);

    for (offset, witness, authenticated) in [(1, false, infra), (2, true, peer())] {
        let id = ConnectionId::new_unchecked(150 + offset);
        let (key, permit) = stage(&mut admission, infra, &root, id);
        let leases = guards(&admission, &root, witness);
        assert!(establish(&mut admission, id, authenticated, &root).is_err());
        assert!(
            admission
                .roles_view()
                .unwrap()
                .infrastructure_live(key)
                .is_none()
        );
        assert!(admission.connection(&infra).is_none());
        finish(&mut admission, key, permit);
        drop(leases);
    }
}

#[test]
fn carrier_infrastructure_admission_authenticates_without_application_or_relay_authority() {
    let infra = peer();
    let mut admission = configured(&[infra]);
    let root = address(4480, infra);
    let id = ConnectionId::new_unchecked(160);
    let (key, permit) = stage(&mut admission, infra, &root, id);
    let leases = guards(&admission, &root, true);
    assert!(establish(&mut admission, id, infra, &root).is_ok());
    let view = admission.roles_view().unwrap();
    assert_eq!(
        view.infrastructure_live(key),
        Some("8.8.8.8:4480".parse().unwrap())
    );
    connected(&mut admission, infra, id, &root);
    assert_eq!(admission.connection(&infra), Some(id));
    assert!(!admission.allows(&infra));
    assert_eq!(admission.application_connections().count(), 0);
    assert!(admission.authorize_relay(infra).is_err());
    assert_eq!(view.role(infra), Some(Role::Infrastructure));
    assert!(admission.terminal(key, Some(infra)).is_none());
    assert!(view.infrastructure_live(key).is_some());
    closed(&mut admission, infra, id, &root);
    assert!(admission.connection(&infra).is_none());
    finish(&mut admission, key, permit);
    assert!(view.infrastructure_live(key).is_none());
    drop(leases);
}

#[test]
fn carrier_infrastructure_admission_rejects_unsolicited_inbound_and_withdrawn_upgrade() {
    let infra = peer();
    let mut admission = configured(&[infra]);
    let root = address(4490, infra);
    let id = ConnectionId::new_unchecked(170);
    let (key, permit) = stage(&mut admission, infra, &root, id);
    let leases = guards(&admission, &root, true);
    assert!(
        admission
            .handle_established_inbound_connection(
                ConnectionId::new_unchecked(171),
                infra,
                &rawaddr(4490),
                &rawaddr(4491),
            )
            .is_err()
    );
    assert!(pending(
        &mut admission,
        infra,
        id,
        std::slice::from_ref(&root)
    ));
    admission.withdraw_infrastructure(key);
    assert!(leases.0.check().is_err());
    assert!(leases.1.check().is_err());
    assert!(establish(&mut admission, id, infra, &root).is_err());
    finish(&mut admission, key, permit);
    drop(leases);
}

#[test]
fn carrier_infrastructure_admission_retains_four_slots_until_final_guard_destruction() {
    let peers: Vec<_> = (0..5).map(|_| peer()).collect();
    let mut admission = configured(&peers);
    let mut staged: Vec<_> = peers[..4]
        .iter()
        .enumerate()
        .map(|(index, &peer)| {
            let root = address(4500 + index as u16, peer);
            stage(
                &mut admission,
                peer,
                &root,
                ConnectionId::new_unchecked(180 + index),
            )
        })
        .collect();
    let fifth = address(4504, peers[4]);
    let fifth_id = ConnectionId::new_unchecked(184);
    let root = address(4500, peers[0]);
    let (key, permit) = staged.remove(0);
    let leases = guards(&admission, &root, false);
    finish(&mut admission, key, permit);
    assert!(
        admission
            .stage_infrastructure(
                peers[4],
                &fifth,
                fifth_id,
                Instant::now() + Duration::from_secs(10),
            )
            .is_err()
    );
    drop(leases);
    let fifth = stage(&mut admission, peers[4], &fifth, fifth_id);
    for (key, permit) in staged.into_iter().chain(std::iter::once(fifth)) {
        finish(&mut admission, key, permit);
    }
}

#[test]
fn carrier_infrastructure_admission_preserves_application_and_explicit_connection_capacity() {
    let peers: Vec<_> = (0..28).map(|_| peer()).collect();
    let mut owner = Owner::new(&peers[..16], &peers[24..]).unwrap();
    for (index, &relay) in peers[16..24].iter().enumerate() {
        owner
            .admit_identity(
                relay,
                Role::ExplicitRelay(format!("8.8.8.8:{}", 4616 + index).parse().unwrap()),
            )
            .unwrap();
    }
    let mut admission = Admission::with_authority(peers[..16].to_vec(), owner, None).unwrap();
    let mut charges = Vec::new();
    for (index, &peer) in peers.iter().enumerate() {
        let id = ConnectionId::new_unchecked(200 + index);
        let root = address(4600 + index as u16, peer);
        if index >= 24 {
            charges.push(stage(&mut admission, peer, &root, id));
        } else {
            admission.stage_native(peer, &root, id).unwrap().unwrap();
        }
        assert!(pending(
            &mut admission,
            peer,
            id,
            std::slice::from_ref(&root)
        ));
        let leases = guards(&admission, &root, true);
        assert!(establish(&mut admission, id, peer, &root).is_ok());
        connected(&mut admission, peer, id, &root);
        drop(leases);
    }
    assert_eq!(admission.application_connections().count(), 16);
    for (index, &peer) in peers.iter().enumerate() {
        let id = ConnectionId::new_unchecked(200 + index);
        assert_eq!(admission.connection(&peer), Some(id));
        closed(
            &mut admission,
            peer,
            id,
            &address(4600 + index as u16, peer),
        );
    }
    for (key, permit) in charges {
        finish(&mut admission, key, permit);
    }

    let mut legacy = Admission::new(peers[..16].to_vec()).unwrap();
    for (index, &peer) in peers[..24].iter().enumerate() {
        if index >= 16 {
            legacy.authorize_relay(peer).unwrap();
        }
        let id = ConnectionId::new_unchecked(300 + index);
        let root = address(4700 + index as u16, peer);
        assert!(establish(&mut legacy, id, peer, &root).is_ok());
        connected(&mut legacy, peer, id, &root);
    }
    assert!(legacy.authorize_relay(peers[24]).is_err());
    assert!(
        establish(
            &mut legacy,
            ConnectionId::new_unchecked(324),
            peers[24],
            &address(4724, peers[24])
        )
        .is_err()
    );
}
