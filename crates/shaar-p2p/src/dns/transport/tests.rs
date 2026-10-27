#[path = "pin_tests.rs"]
mod pin_tests;
#[path = "support.rs"]
mod support;

use super::Guard;
use crate::discovery::roles::{Owner, Role, Root};
use libp2p::{Multiaddr, Transport, multiaddr::Protocol, swarm::ConnectionId};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};
use support::*;
use tokio::time::Instant;

#[tokio::test]
async fn destination_guard_initial_root_is_exact_and_app_cannot_borrow_dns_or_child_endpoint() {
    let (mut owner, view, key, selected) = setup(Role::Application, "/ip4/127.0.0.1/tcp/4001");
    let (inner, counts) = Observed::new(true);
    let mut guard = Guard::context(inner, view.clone());
    for rejected in [
        address("/ip4/127.0.0.1/tcp/4002", key.peer),
        address("/dns4/owned.example./tcp/4001", key.peer),
        address("/ip4/127.0.0.1/tcp/4001", peer()),
    ] {
        assert!(guard.dial(rejected, options()).is_err());
    }
    assert_eq!(count(&counts.dials), 0);
    let mut future = guard.dial(selected, options()).unwrap();
    assert_eq!(count(&counts.dials), 1);
    assert!(matches!(poll(&mut future), Poll::Ready(Ok(_))));
    owner.terminal(key, Some(key.peer), Instant::now());
    assert!(view.current(key.peer, Instant::now()).is_none());
}

#[tokio::test]
async fn destination_guard_suffix_prefix_and_circuit_forgery_never_invokes_inner() {
    let (_owner, view, key, selected) = setup(Role::Application, "/ip4/127.0.0.1/tcp/4001");
    let (inner, counts) = Observed::new(true);
    let mut guard = Guard::context(inner, view);
    let repeated = selected.clone().with(Protocol::P2p(key.peer));
    let circuit = selected
        .clone()
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(key.peer));
    let interior = Multiaddr::empty()
        .with(Protocol::P2p(key.peer))
        .with(Protocol::Ip4("127.0.0.1".parse().unwrap()))
        .with(Protocol::Tcp(4001))
        .with(Protocol::P2p(key.peer));
    for rejected in [
        "/ip4/127.0.0.1/tcp/4001".parse().unwrap(),
        repeated,
        circuit,
        interior,
        address("/ip4/127.0.0.1/udp/4001", key.peer),
    ] {
        assert!(guard.dial(rejected, options()).is_err());
    }
    assert_eq!(count(&counts.dials), 0);
}

#[tokio::test]
async fn destination_guard_staged_unpinned_and_closed_contexts_are_not_permits() {
    let peer = peer();
    let mut owner = Owner::new(&[peer], &[]).unwrap();
    let now = Instant::now();
    let key = owner
        .admit(
            peer,
            ConnectionId::new_unchecked(1),
            now + Duration::from_secs(10),
            now,
        )
        .unwrap();
    let selected = address("/ip4/127.0.0.1/tcp/4001", peer);
    let (inner, counts) = Observed::new(true);
    let mut guard = Guard::context(inner, owner.view());
    assert!(guard.dial(selected.clone(), options()).is_err());
    owner
        .pin_root(key, Root::new(selected.as_ref(), peer).unwrap(), now)
        .unwrap();
    owner.close();
    assert!(guard.dial(selected, options()).is_err());
    assert_eq!(count(&counts.dials), 0);
}

#[tokio::test]
async fn destination_guard_strict_numeric_and_all_dns_spellings_share_policy() {
    for prefix in [
        "/ip4/8.8.8.8/tcp/4001",
        "/dns/owned.example./tcp/4001",
        "/dns4/owned.example./tcp/4001",
        "/dns6/owned.example./tcp/4001",
        "/dnsaddr/owned.example.",
    ] {
        let numeric_root = prefix.starts_with("/ip4/");
        let (_owner, view, key, selected) = setup(Role::Infrastructure, prefix);
        let (inner, counts) = Observed::new(true);
        let mut outer = Guard::context(inner, view.clone());
        let _root = outer.dial(selected.clone(), options()).unwrap();
        assert_eq!(count(&counts.dials), 1);
        for prefix in [
            "/dnsaddr/nested.example.",
            "/dns4/nested.example./tcp/4002",
            "/ip4/8.8.4.4/tcp/4001",
            "/ip6/2606:4700::1111/tcp/4001",
        ] {
            assert_eq!(
                view.permits_address(address(prefix, key.peer).as_ref()),
                !numeric_root
            );
        }
        let (inner, native_counts) = Observed::new(true);
        let mut numeric = Guard::numeric(inner, view.clone());
        for prefix in [
            "/ip4/127.0.0.1/tcp/4001",
            "/ip4/10.0.0.1/tcp/4001",
            "/ip6/::1/tcp/4001",
            "/ip6/::ffff:8.8.8.8/tcp/4001",
        ] {
            let rejected = address(prefix, key.peer);
            assert!(!view.permits_address(rejected.as_ref()));
            assert!(numeric.dial(rejected, options()).is_err());
        }
        assert_eq!(count(&native_counts.dials), 0);
        let endpoint = if numeric_root {
            for prefix in ["/ip4/8.8.4.4/tcp/4001", "/ip4/8.8.8.8/tcp/4002"] {
                assert!(numeric.dial(address(prefix, key.peer), options()).is_err());
            }
            assert_eq!(count(&native_counts.dials), 0);
            "/ip4/8.8.8.8/tcp/4001"
        } else {
            "/ip4/8.8.4.4/tcp/4001"
        };
        let _native = numeric
            .dial(address(endpoint, key.peer), options())
            .unwrap();
        assert_eq!(count(&native_counts.dials), 1);
        assert!(
            outer
                .dial(
                    address("/dns4/other.example./tcp/4001", key.peer),
                    options()
                )
                .is_err()
        );
    }
}

#[tokio::test]
async fn destination_guard_explicit_relay_numeric_private_endpoint_is_exact() {
    let endpoint = "127.0.0.1:4001".parse().unwrap();
    let (mut owner, view, key, selected) =
        setup(Role::ExplicitRelay(endpoint), "/ip4/127.0.0.1/tcp/4001");
    let (inner, counts) = Observed::new(true);
    let mut guard = Guard::context(Guard::numeric(inner, view.clone()), view.clone());
    assert!(
        guard
            .dial(address("/ip4/127.0.0.1/tcp/4002", key.peer), options())
            .is_err()
    );
    let mut future = guard.dial(selected, options()).unwrap();
    assert!(matches!(poll(&mut future), Poll::Ready(Ok(_))));
    assert_eq!(count(&counts.dials), 1);
    assert_eq!(
        owner.terminal(key, Some(key.peer), Instant::now()),
        Some(endpoint)
    );
}

#[tokio::test]
async fn destination_guard_cancel_after_construction_blocks_first_native_poll() {
    let (mut owner, view, key, selected) = setup(Role::Application, "/ip4/127.0.0.1/tcp/4001");
    let (inner, counts) = Observed::new(true);
    let mut guard = Guard::context(Guard::numeric(inner, view.clone()), view);
    let mut future = guard.dial(selected, options()).unwrap();
    assert_eq!(count(&counts.dials), 1);
    assert_eq!(count(&counts.polls), 0);
    owner.revoke(key);
    assert!(matches!(poll(&mut future), Poll::Ready(Err(_))));
    assert_eq!(count(&counts.polls), 0);
    assert_eq!(count(&counts.futures_dropped), 1);
    assert_eq!(owner.terminal(key, Some(key.peer), Instant::now()), None);
}

#[tokio::test]
async fn destination_guard_cancel_after_expansion_blocks_numeric_dial() {
    let (mut owner, view, key, selected) =
        setup(Role::Infrastructure, "/dns4/owned.example./tcp/4001");
    let root = view.root_lease(selected.as_ref()).unwrap();
    let candidate = address("/ip4/8.8.8.8/tcp/4001", key.peer);
    assert!(view.permits_address(candidate.as_ref()));
    owner.revoke(key);
    let (inner, counts) = Observed::new(true);
    let mut numeric = Guard::numeric(inner, view.clone());
    assert!(numeric.dial(candidate.clone(), options()).is_err());
    assert!(!view.permits_address(candidate.as_ref()));
    assert_eq!(count(&counts.dials), 0);
    drop(root);
}

#[tokio::test]
async fn destination_guard_pending_future_revocation_wakes_without_another_inner_poll() {
    struct Counter(AtomicUsize);
    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let (mut owner, view, key, selected) = setup(Role::Application, "/ip4/127.0.0.1/tcp/4001");
    let (inner, counts) = Observed::new(false);
    let mut guard = Guard::context(Guard::numeric(inner, view.clone()), view);
    let mut future = guard.dial(selected, options()).unwrap();
    let counter = Arc::new(Counter(AtomicUsize::new(0)));
    let waker = Waker::from(counter.clone());
    use std::{future::Future, pin::Pin};
    assert!(
        Pin::new(&mut future)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(count(&counts.polls), 1);
    owner.revoke(key);
    assert!(count(&counter.0) > 0);
    assert!(matches!(poll(&mut future), Poll::Ready(Err(_))));
    assert_eq!(count(&counts.polls), 1);
}

#[tokio::test(start_paused = true)]
async fn destination_guard_absolute_deadline_includes_queue_and_unpolled_time() {
    let (mut owner, view, key, selected) = setup(Role::Application, "/ip4/127.0.0.1/tcp/4001");
    tokio::time::advance(Duration::from_secs(9)).await;
    let (inner, counts) = Observed::new(false);
    let mut guard = Guard::context(Guard::numeric(inner, view.clone()), view);
    let mut future = guard.dial(selected.clone(), options()).unwrap();
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(matches!(poll(&mut future), Poll::Ready(Err(_))));
    assert_eq!(count(&counts.polls), 0);
    assert!(guard.dial(selected, options()).is_err());
    assert_eq!(owner.terminal(key, Some(key.peer), Instant::now()), None);
}

#[tokio::test]
async fn destination_guard_ready_future_keeps_root_charge_until_drop() {
    let (mut owner, view, key, selected) = setup(Role::Application, "/ip4/127.0.0.1/tcp/4001");
    let (inner, _) = Observed::new(true);
    let mut guard = Guard::context(Guard::numeric(inner, view.clone()), view);
    let mut future = guard.dial(selected.clone(), options()).unwrap();
    assert!(matches!(poll(&mut future), Poll::Ready(Ok(_))));
    assert_eq!(
        owner.terminal(key, Some(key.peer), Instant::now()),
        Some("127.0.0.1:4001".parse().unwrap())
    );
    let now = Instant::now();
    assert!(
        owner
            .admit(
                key.peer,
                ConnectionId::new_unchecked(2),
                now + Duration::from_secs(10),
                now
            )
            .is_err()
    );
    drop(future);
    let next = stage(&mut owner, key.peer, &selected, 2);
    assert_ne!(key, next);
}

#[tokio::test]
async fn destination_guard_revocation_inside_admitted_poll_discards_ready_output() {
    let (owner, view, key, selected) = setup(Role::Application, "/ip4/127.0.0.1/tcp/4001");
    let owner = Arc::new(Mutex::new(owner));
    let (mut inner, counts) = Observed::new(true);
    let revoke = owner.clone();
    inner.on_poll = Some(Box::new(move || revoke.lock().unwrap().revoke(key)));
    let mut guard = Guard::context(Guard::numeric(inner, view.clone()), view);
    let mut future = guard.dial(selected, options()).unwrap();
    assert!(matches!(poll(&mut future), Poll::Ready(Err(_))));
    assert_eq!(count(&counts.polls), 1);
    assert_eq!(count(&counts.outputs_dropped), 1);
    assert_eq!(
        owner
            .lock()
            .unwrap()
            .terminal(key, Some(key.peer), Instant::now()),
        None
    );
}

#[tokio::test]
async fn destination_guard_wrong_authenticated_peer_and_inner_errors_discard_witness() {
    for fail in [false, true] {
        let (mut owner, view, key, selected) = setup(Role::Application, "/ip4/127.0.0.1/tcp/4001");
        let (mut inner, counts) = Observed::new(true);
        inner.fail = fail;
        let mut guard = Guard::context(Guard::numeric(inner, view.clone()), view);
        let mut future = guard.dial(selected, options()).unwrap();
        let result = poll(&mut future);
        assert_eq!(matches!(result, Poll::Ready(Err(_))), fail);
        assert_eq!(count(&counts.polls), 1);
        assert_eq!(owner.terminal(key, Some(peer()), Instant::now()), None);
        drop(future);
    }
}

#[tokio::test]
async fn destination_guard_owned_resolver_override_is_fail_closed_and_borrowed() {
    use libp2p::dns::Resolver;
    let (mut owner, view, key, selected) = setup(Role::Infrastructure, "/dnsaddr/owned.example.");
    let executor = crate::OwnedExecutor::new();
    let (lifetime, raw) =
        crate::dns::OwnedResolver::new(&["127.0.0.1:53".parse().unwrap()], executor.handle())
            .unwrap();
    let allowed = address("/ip4/8.8.8.8/tcp/4001", key.peer);
    assert!(!raw.permits_address(allowed.as_ref()));
    let resolver = raw.with_roles(view.clone());
    assert!(!resolver.permits_address(allowed.as_ref()));
    let root = view.root_lease(selected.as_ref()).unwrap();
    assert!(resolver.permits_address(allowed.as_ref()));
    for prefix in [
        "/ip4/127.0.0.1/tcp/4001",
        "/dns4/Upper.example./tcp/4001",
        "/dnsaddr/relative",
    ] {
        assert!(!resolver.permits_address(address(prefix, key.peer).as_ref()));
    }
    owner.revoke(key);
    assert!(!resolver.permits_address(allowed.as_ref()));
    lifetime.close();
    drop(root);
    executor.shutdown().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn destination_guard_deadline_wakes_an_otherwise_silent_pending_future() {
    let (_owner, view, _key, selected) = setup(Role::Application, "/ip4/127.0.0.1/tcp/4001");
    let (inner, counts) = Observed::new(false);
    let mut guard = Guard::context(Guard::numeric(inner, view.clone()), view);
    let future = guard.dial(selected, options()).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(11), future).await;
    assert!(
        matches!(result, Ok(Err(_))),
        "ABSOLUTE_GUARD_TIMER_DID_NOT_WAKE"
    );
    assert_eq!(count(&counts.polls), 1);
}

#[tokio::test]
async fn destination_guard_root_survives_numeric_success_during_pending_authentication() {
    let (mut owner, view, key, selected) = setup(Role::Application, "/ip4/127.0.0.1/tcp/4001");
    let (inner, counts) = Observed::new(true);
    let native = Guard::numeric(inner, view.clone()).and_then(|output, _| async move {
        // Model an upgrade waiting after TCP success, not a real Noise handshake.
        std::future::pending::<()>().await;
        Ok::<_, std::io::Error>(output)
    });
    let mut guard = Guard::context(native, view.clone());
    let mut future = guard.dial(selected.clone(), options()).unwrap();
    assert!(poll(&mut future).is_pending());
    assert_eq!(count(&counts.polls), 1);
    assert_eq!(count(&counts.outputs_dropped), 0);
    owner.revoke(key);
    assert!(matches!(poll(&mut future), Poll::Ready(Err(_))));
    assert_eq!(count(&counts.outputs_dropped), 1);
    assert_eq!(owner.terminal(key, Some(key.peer), Instant::now()), None);
    let now = Instant::now();
    assert!(
        owner
            .admit(
                key.peer,
                ConnectionId::new_unchecked(2),
                now + Duration::from_secs(10),
                now
            )
            .is_err()
    );
    drop(future);
    stage(&mut owner, key.peer, &selected, 2);
}

#[tokio::test]
async fn destination_guard_same_encoded_private_input_is_denied_by_strict_authority() {
    let (mut app, app_view, key, selected) = setup(Role::Application, "/ip4/127.0.0.1/tcp/4001");
    let (inner, _) = Observed::new(true);
    let mut app_guard = Guard::context(Guard::numeric(inner, app_view.clone()), app_view);
    let mut app_future = app_guard.dial(selected.clone(), options()).unwrap();
    assert!(matches!(poll(&mut app_future), Poll::Ready(Ok(_))));
    app.terminal(key, Some(key.peer), Instant::now());
    let mut strict = Owner::new(&[], &[key.peer]).unwrap();
    let now = Instant::now();
    let strict_key = strict
        .admit(
            key.peer,
            ConnectionId::new_unchecked(2),
            now + Duration::from_secs(10),
            now,
        )
        .unwrap();
    assert!(
        strict
            .pin_root(
                strict_key,
                Root::new(selected.as_ref(), key.peer).unwrap(),
                now
            )
            .is_err()
    );
    let root = address("/dns4/owned.example./tcp/4001", key.peer);
    strict
        .pin_root(strict_key, Root::new(root.as_ref(), key.peer).unwrap(), now)
        .unwrap();
    let view = strict.view();
    let _root = view.root_lease(root.as_ref()).unwrap();
    let (inner, counts) = Observed::new(true);
    let mut numeric = Guard::numeric(inner, view.clone());
    assert!(!view.permits_address(selected.as_ref()));
    assert!(numeric.dial(selected, options()).is_err());
    assert_eq!(count(&counts.dials), 0);
}
