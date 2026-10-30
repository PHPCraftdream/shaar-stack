use super::*;

fn contact(value: u8) -> PeerId {
    let mut bytes = [value; 34];
    bytes[0] = 0x12;
    bytes[1] = 32;
    PeerId::from_bytes(&bytes).unwrap()
}

#[test]
fn destination_roles_lifetime_contacts_include_seeds_and_failed_retired_attempts() {
    let seeds: Vec<_> = (0..4).map(contact).collect();
    let mut owner = Owner::new(&[], &seeds).unwrap();
    let view = owner.view();
    for value in 4..32 {
        let peer = contact(value);
        owner.admit_identity(peer, Role::Infrastructure).unwrap();
        let (key, permit) = stage(&mut owner, peer, usize::from(value));
        assert!(owner.terminal(key, None, Instant::now()).is_none());
        owner.infrastructure_terminal(key);
        drop(permit);
        owner.forget_identity(peer).unwrap();
        assert_eq!(view.role(peer), None);
    }
    assert_eq!(
        owner
            .admit_identity(contact(32), Role::Infrastructure)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::WouldBlock,
        "RETIRED_CONTACT_REPLENISHED_LIFETIME_BUDGET"
    );
    for peer in seeds {
        assert_eq!(view.role(peer), Some(Role::Infrastructure));
        assert!(owner.forget_identity(peer).is_err());
    }
}

#[test]
fn destination_roles_lifetime_contacts_readmit_without_charging_a_new_identity() {
    let mut owner = Owner::new(&[], &[]).unwrap();
    for value in 0..32 {
        let peer = contact(value);
        owner.admit_identity(peer, Role::Infrastructure).unwrap();
        owner.admit_identity(peer, Role::Infrastructure).unwrap();
        owner.forget_identity(peer).unwrap();
    }
    assert!(
        owner
            .admit_identity(contact(32), Role::Infrastructure)
            .is_err()
    );
    for value in 0..32 {
        let peer = contact(value);
        owner.admit_identity(peer, Role::Infrastructure).unwrap();
        assert_eq!(owner.view().role(peer), Some(Role::Infrastructure));
    }
    for value in 0..32 {
        owner.forget_identity(contact(value)).unwrap();
    }
    assert_eq!(
        owner
            .admit_identity(contact(32), Role::Infrastructure)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn destination_roles_lifetime_contacts_deduplicate_seeds_and_preserve_other_role_retirement() {
    let seed = contact(0);
    let app = contact(200);
    let mut owner = Owner::new(&[app], &[seed; 32]).unwrap();
    assert!(owner.admit_identity(app, Role::Infrastructure).is_err());
    for value in 1..32 {
        let peer = contact(value);
        owner.admit_identity(peer, Role::Infrastructure).unwrap();
        owner.forget_identity(peer).unwrap();
    }
    let fresh = contact(32);
    assert!(owner.admit_identity(fresh, Role::Infrastructure).is_err());
    let explicit = Role::ExplicitRelay("8.8.8.8:4001".parse().unwrap());
    owner.admit_identity(fresh, explicit).unwrap();
    assert_eq!(owner.view().role(fresh), Some(explicit));
    owner.forget_identity(fresh).unwrap();
    assert_eq!(owner.view().role(fresh), None);
    assert!(owner.admit_identity(fresh, Role::Infrastructure).is_err());
    let known = contact(1);
    owner.admit_identity(known, explicit).unwrap();
    owner.forget_identity(known).unwrap();
    owner.admit_identity(known, Role::Infrastructure).unwrap();
    assert_eq!(owner.view().role(known), Some(Role::Infrastructure));
}

#[test]
fn destination_roles_lifetime_contacts_survive_retained_cleanup_without_retaining_authority() {
    let mut owner = Owner::new(&[], &[]).unwrap();
    for value in 0..31 {
        owner
            .admit_identity(contact(value), Role::Infrastructure)
            .unwrap();
        owner.forget_identity(contact(value)).unwrap();
    }
    let peer = contact(31);
    owner.admit_identity(peer, Role::Infrastructure).unwrap();
    let (key, permit) = stage(&mut owner, peer, 100);
    let view = owner.view();
    let lease = view.lease(key, LeaseKind::Root, Instant::now()).unwrap();
    owner.terminal(key, None, Instant::now());
    owner.infrastructure_terminal(key);
    assert!(owner.forget_identity(peer).is_err());
    assert!(
        owner
            .admit_identity(contact(32), Role::Infrastructure)
            .is_err()
    );
    drop(permit);
    assert!(owner.forget_identity(peer).is_err());
    drop(lease);
    owner.forget_identity(peer).unwrap();
    assert_eq!(view.role(peer), None);
    assert!(
        view.pending_infrastructure_root(key, Instant::now())
            .is_none()
    );
    assert!(view.infrastructure_permit(key).is_none());
    assert!(
        owner
            .admit_identity(contact(32), Role::Infrastructure)
            .is_err()
    );
    owner.admit_identity(peer, Role::Infrastructure).unwrap();
    assert!(view.current(peer, Instant::now()).is_none());
    assert!(
        view.pending_infrastructure_root(key, Instant::now())
            .is_none()
    );
}
