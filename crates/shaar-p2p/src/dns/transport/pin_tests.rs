use super::support::*;
use crate::discovery::roles::{AttemptKey, Owner, Role, Root};
use libp2p::{PeerId, swarm::ConnectionId};
use std::time::Duration;
use tokio::time::Instant;

fn unpinned(owner: &mut Owner, peer: PeerId, connection: ConnectionId) -> AttemptKey {
    let now = Instant::now();
    owner
        .admit(peer, connection, now + Duration::from_secs(10), now)
        .unwrap()
}

#[test]
fn destination_guard_root_expected_peer_mismatch_grants_no_authority() {
    let expected = peer();
    let foreign = peer();
    let mut owner = Owner::new(&[expected], &[]).unwrap();
    let key = unpinned(&mut owner, expected, ConnectionId::new_unchecked(1));
    let selected = address("/ip4/127.0.0.1/tcp/4001", expected);
    let forged = address("/ip4/127.0.0.1/tcp/4001", foreign);
    assert!(Root::new(forged.as_ref(), expected).is_err());
    assert!(Root::new(selected.as_ref(), foreign).is_err());
    assert!(
        owner
            .pin_root(
                key,
                Root::new(forged.as_ref(), foreign).unwrap(),
                Instant::now(),
            )
            .is_err()
    );
    let view = owner.view();
    assert!(view.root_lease(selected.as_ref()).is_err());
    assert!(view.root_lease(forged.as_ref()).is_err());
    assert!(!view.permits_address(selected.as_ref()));
    owner
        .pin_root(
            key,
            Root::new(selected.as_ref(), expected).unwrap(),
            Instant::now(),
        )
        .unwrap();
    let _root = view.root_lease(selected.as_ref()).unwrap();
    assert!(
        owner
            .pin_root(
                key,
                Root::new(forged.as_ref(), foreign).unwrap(),
                Instant::now(),
            )
            .is_err()
    );
    assert!(view.permits_address(selected.as_ref()));
    assert!(!view.permits_address(forged.as_ref()));
    assert!(view.numeric_lease(forged.as_ref()).is_err());
    let (_numeric, endpoint) = view.numeric_lease(selected.as_ref()).unwrap();
    assert_eq!(endpoint, "127.0.0.1:4001".parse().unwrap());
}

#[test]
fn destination_guard_repeated_pin_preserves_original_selected_root() {
    let (mut owner, view, key, selected) = setup(Role::Application, "/ip4/127.0.0.1/tcp/4001");
    let replacement = address("/ip4/127.0.0.1/tcp/4002", key.peer);
    for candidate in [&selected, &replacement] {
        assert!(
            owner
                .pin_root(
                    key,
                    Root::new(candidate.as_ref(), key.peer).unwrap(),
                    Instant::now()
                )
                .is_err()
        );
    }
    assert!(view.root_lease(replacement.as_ref()).is_err());
    let _root = view.root_lease(selected.as_ref()).unwrap();
    assert!(view.permits_address(selected.as_ref()));
    assert!(!view.permits_address(replacement.as_ref()));
    assert!(view.numeric_lease(replacement.as_ref()).is_err());
    let (numeric, endpoint) = view.numeric_lease(selected.as_ref()).unwrap();
    assert_eq!(endpoint, "127.0.0.1:4001".parse().unwrap());
    drop(numeric);
}

#[test]
fn destination_guard_foreign_key_with_matching_connection_cannot_pin_or_replace() {
    let (_foreign_owner, foreign_view, foreign_key, foreign_root) =
        setup(Role::Application, "/ip4/127.0.0.1/tcp/4001");
    let mut owner = Owner::new(&[foreign_key.peer], &[]).unwrap();
    let key = unpinned(&mut owner, foreign_key.peer, foreign_key.connection);
    assert_eq!(key.peer, foreign_key.peer);
    assert_eq!(key.connection, foreign_key.connection);
    assert_ne!(key, foreign_key);
    let selected = address("/ip4/127.0.0.1/tcp/4002", key.peer);
    let view = owner.view();
    assert!(
        owner
            .pin_root(
                foreign_key,
                Root::new(foreign_root.as_ref(), key.peer).unwrap(),
                Instant::now()
            )
            .is_err()
    );
    assert!(view.root_lease(foreign_root.as_ref()).is_err());
    assert!(view.root_lease(selected.as_ref()).is_err());
    owner
        .pin_root(
            key,
            Root::new(selected.as_ref(), key.peer).unwrap(),
            Instant::now(),
        )
        .unwrap();
    assert!(
        owner
            .pin_root(
                foreign_key,
                Root::new(foreign_root.as_ref(), key.peer).unwrap(),
                Instant::now()
            )
            .is_err()
    );
    let _root = view.root_lease(selected.as_ref()).unwrap();
    assert!(view.permits_address(selected.as_ref()));
    assert!(!view.permits_address(foreign_root.as_ref()));
    let _foreign_root = foreign_view.root_lease(foreign_root.as_ref()).unwrap();
    assert!(foreign_view.permits_address(foreign_root.as_ref()));
    assert!(!foreign_view.permits_address(selected.as_ref()));
}

#[test]
fn destination_guard_stale_key_cannot_pin_successor_reusing_connection_id() {
    let (mut owner, view, old, old_root) = setup(Role::Application, "/ip4/127.0.0.1/tcp/4001");
    owner.terminal(old, None, Instant::now());
    let next = unpinned(&mut owner, old.peer, old.connection);
    assert_ne!(old, next);
    let selected = address("/ip4/127.0.0.1/tcp/4002", old.peer);
    assert!(
        owner
            .pin_root(
                old,
                Root::new(old_root.as_ref(), old.peer).unwrap(),
                Instant::now()
            )
            .is_err()
    );
    assert!(view.root_lease(old_root.as_ref()).is_err());
    assert!(view.root_lease(selected.as_ref()).is_err());
    owner
        .pin_root(
            next,
            Root::new(selected.as_ref(), next.peer).unwrap(),
            Instant::now(),
        )
        .unwrap();
    assert!(
        owner
            .pin_root(
                old,
                Root::new(old_root.as_ref(), old.peer).unwrap(),
                Instant::now()
            )
            .is_err()
    );
    assert!(view.root_lease(old_root.as_ref()).is_err());
    let _root = view.root_lease(selected.as_ref()).unwrap();
    assert!(view.permits_address(selected.as_ref()));
    assert!(!view.permits_address(old_root.as_ref()));
}

#[test]
fn destination_guard_revoked_unpinned_key_cannot_acquire_root_authority() {
    let peer = peer();
    let mut owner = Owner::new(&[peer], &[]).unwrap();
    let key = unpinned(&mut owner, peer, ConnectionId::new_unchecked(1));
    let selected = address("/ip4/127.0.0.1/tcp/4001", peer);
    owner.revoke(key);
    assert!(
        owner
            .pin_root(
                key,
                Root::new(selected.as_ref(), peer).unwrap(),
                Instant::now()
            )
            .is_err()
    );
    let view = owner.view();
    assert!(view.root_lease(selected.as_ref()).is_err());
    assert!(!view.permits_address(selected.as_ref()));
    assert!(view.numeric_lease(selected.as_ref()).is_err());
    owner.terminal(key, None, Instant::now());
    let next = unpinned(&mut owner, peer, key.connection);
    assert!(view.root_lease(selected.as_ref()).is_err());
    owner
        .pin_root(
            next,
            Root::new(selected.as_ref(), peer).unwrap(),
            Instant::now(),
        )
        .unwrap();
    let _root = view.root_lease(selected.as_ref()).unwrap();
    assert!(view.permits_address(selected.as_ref()));
}

#[tokio::test(start_paused = true)]
async fn destination_guard_expired_unpinned_key_cannot_acquire_root_authority() {
    let peer = peer();
    let mut owner = Owner::new(&[peer], &[]).unwrap();
    let key = unpinned(&mut owner, peer, ConnectionId::new_unchecked(1));
    let selected = address("/ip4/127.0.0.1/tcp/4001", peer);
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(
        owner
            .pin_root(
                key,
                Root::new(selected.as_ref(), peer).unwrap(),
                Instant::now()
            )
            .is_err()
    );
    let view = owner.view();
    assert!(view.root_lease(selected.as_ref()).is_err());
    assert!(!view.permits_address(selected.as_ref()));
    assert!(view.numeric_lease(selected.as_ref()).is_err());
    owner.terminal(key, None, Instant::now());
    let next = unpinned(&mut owner, peer, key.connection);
    assert!(view.root_lease(selected.as_ref()).is_err());
    owner
        .pin_root(
            next,
            Root::new(selected.as_ref(), peer).unwrap(),
            Instant::now(),
        )
        .unwrap();
    let _root = view.root_lease(selected.as_ref()).unwrap();
    assert!(view.permits_address(selected.as_ref()));
}
