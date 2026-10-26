//! Gate lifecycle and admission microtests.

use super::relay::gate::{Gate, Slot, Ticket};
use super::*;
use crate::discovery::roles::{Owner, Role};
use libp2p::{Multiaddr, relay::client::OperationKind};
use std::{num::NonZeroU64, sync::atomic::Ordering as AtomicOrdering};
use tokio::time::{Instant, timeout};
const RECORD_BUDGET: usize = 20;
fn peer() -> PeerId {
    Keypair::generate_ed25519().public().to_peer_id()
}
fn endpoint() -> SocketAddr {
    "127.0.0.1:4001".parse().unwrap()
}
fn other_endpoint() -> SocketAddr {
    "127.0.0.1:4002".parse().unwrap()
}
fn plain(endpoint: SocketAddr) -> Multiaddr {
    let host = match endpoint.ip() {
        std::net::IpAddr::V4(ip) => Protocol::Ip4(ip),
        std::net::IpAddr::V6(ip) => Protocol::Ip6(ip),
    };
    Multiaddr::empty()
        .with(host)
        .with(Protocol::Tcp(endpoint.port()))
}
fn configured(
    relay: PeerId,
    application: PeerId,
    endpoint: SocketAddr,
) -> (Owner, crate::discovery::roles::View) {
    let mut owner = Owner::new(&[application], &[]).unwrap();
    owner
        .admit_identity(relay, Role::ExplicitRelay(endpoint))
        .unwrap();
    let view = owner.view();
    (owner, view)
}
fn deadline(seconds: u64) -> Instant {
    Instant::now() + Duration::from_secs(seconds)
}

#[test]
fn carrier_destination_factory_admits_exact_staged_relay_intent() {
    let relay = peer();
    let application = peer();
    let (_owner, view) = configured(relay, application, endpoint());
    let gate = Gate::new();
    let staged = gate.stage_reserve(relay, endpoint(), deadline(60)).unwrap();
    let factory = gate.factory_unbound(view.clone());
    let capability = factory(relay, &plain(endpoint()), OperationKind::Reserve).unwrap();
    assert_eq!(
        capability.generation(),
        Some(NonZeroU64::new(staged).unwrap())
    );
    let connect = gate
        .stage_connect(relay, endpoint(), application, deadline(60))
        .unwrap();
    let capability = factory(
        relay,
        &plain(endpoint()),
        OperationKind::Connect {
            destination: application,
        },
    )
    .unwrap();
    assert_eq!(
        capability.generation(),
        Some(NonZeroU64::new(connect.generation).unwrap())
    );
    assert_ne!(connect.generation, staged);
}

#[test]
fn carrier_destination_factory_denies_wrong_endpoint_kind_and_destination() {
    let relay = peer();
    let application = peer();
    let infrastructure = peer();
    let (_owner, view) = configured(relay, application, endpoint());
    let gate = Gate::new();
    gate.stage_reserve(relay, endpoint(), deadline(60)).unwrap();
    // Wrong endpoint: the ledger pins one exact relay endpoint.
    assert_eq!(
        factory_error(&gate, &view, || (
            relay,
            plain(other_endpoint()),
            OperationKind::Reserve
        )),
        io::ErrorKind::PermissionDenied
    );
    // Kind mismatch: only the reserve slot is staged for this relay.
    assert_eq!(
        factory_error(&gate, &view, || (
            relay,
            plain(endpoint()),
            OperationKind::Connect {
                destination: application
            }
        )),
        io::ErrorKind::PermissionDenied
    );
    let gate = Gate::new();
    gate.stage_connect(relay, endpoint(), application, deadline(60))
        .unwrap();
    // Destination mismatch against the staged connect intent.
    assert_eq!(
        factory_error(&gate, &view, || (
            relay,
            plain(endpoint()),
            OperationKind::Connect {
                destination: infrastructure
            }
        )),
        io::ErrorKind::PermissionDenied
    );
    // A non-application destination (infrastructure identity) is never admitted.
    let gate = Gate::new();
    gate.stage_connect(relay, endpoint(), infrastructure, deadline(60))
        .unwrap();
    assert_eq!(
        factory_error(&gate, &view, || (
            relay,
            plain(endpoint()),
            OperationKind::Connect {
                destination: infrastructure
            }
        )),
        io::ErrorKind::PermissionDenied
    );
}

fn factory_error(
    gate: &Gate,
    view: &crate::discovery::roles::View,
    request: impl FnOnce() -> (PeerId, Multiaddr, OperationKind),
) -> io::ErrorKind {
    let factory = gate.factory_unbound(view.clone());
    let (peer, address, kind) = request();
    factory(peer, &address, kind).unwrap_err().kind()
}

#[test]
fn carrier_destination_missing_role_view_rejects_without_fallback() {
    let relay = peer();
    let application = peer();
    // A view with no relay identity at all: staging alone grants nothing.
    let owner = Owner::new(&[application], &[]).unwrap();
    let view = owner.view();
    let gate = Gate::new();
    gate.stage_reserve(relay, endpoint(), deadline(60)).unwrap();
    gate.stage_connect(relay, endpoint(), application, deadline(60))
        .unwrap();
    assert_eq!(
        factory_error(&gate, &view, || (
            relay,
            plain(endpoint()),
            OperationKind::Reserve
        )),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        factory_error(&gate, &view, || (
            relay,
            plain(endpoint()),
            OperationKind::Connect {
                destination: application
            }
        )),
        io::ErrorKind::PermissionDenied
    );
    // Denied issues never charge or retire the staged intent budget.
    assert!(gate.next_deadline().is_some());
}

#[test]
fn carrier_destination_generation_is_shared_and_stale_intent_fails_closed() {
    let relay = peer();
    let application = peer();
    let (_owner, view) = configured(relay, application, endpoint());
    let gate = Gate::new();
    let stale = gate
        .stage_connect(relay, endpoint(), application, deadline(60))
        .unwrap();
    gate.revoke(relay, Slot::Connect);
    gate.terminal(stale);
    let fresh = gate
        .stage_connect(relay, endpoint(), application, deadline(60))
        .unwrap();
    assert!(fresh.generation > stale.generation);
    let factory = gate.factory_unbound(view);
    let capability = factory(
        relay,
        &plain(endpoint()),
        OperationKind::Connect {
            destination: application,
        },
    )
    .unwrap();
    assert!(gate.test_admit(
        relay,
        fresh.generation,
        plain(endpoint()),
        OperationKind::Connect {
            destination: application
        },
        None,
    ));
    gate.establish(stale);
    assert!(gate.test_admit(
        relay,
        fresh.generation,
        plain(endpoint()),
        OperationKind::Connect {
            destination: application
        },
        None,
    ));
    gate.expire(Instant::now() + Duration::from_secs(120));
    assert!(!gate.test_admit(
        relay,
        fresh.generation,
        plain(endpoint()),
        OperationKind::Connect {
            destination: application
        },
        None,
    ));
    assert_eq!(
        factory(
            relay,
            &plain(endpoint()),
            OperationKind::Connect {
                destination: application
            },
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::PermissionDenied,
    );
    drop(capability);
    gate.terminal(fresh);
    gate.prune_released();
}

#[test]
fn carrier_destination_reservation_independent_of_dial_failure_and_cancel() {
    let relay = peer();
    let application = peer();
    let (_owner, view) = configured(relay, application, endpoint());
    let gate = Gate::new();
    gate.stage_reserve(relay, endpoint(), deadline(60)).unwrap();
    let ticket = gate
        .stage_connect(relay, endpoint(), application, deadline(60))
        .unwrap();
    let factory = gate.factory_unbound(view.clone());
    let failed = factory(
        relay,
        &plain(endpoint()),
        OperationKind::Connect {
            destination: application,
        },
    )
    .unwrap();
    // The driver's dial-failure path revokes only the connect slot; the staged
    // reservation on the same relay stays independent and admissible.
    gate.revoke(ticket.relay, Slot::Connect);
    drop(failed);
    let capability = factory(relay, &plain(endpoint()), OperationKind::Reserve).unwrap();
    assert!(capability.generation().is_some());
    // The reserve slot keeps its single claimed capability: a duplicate issue
    // for the same staged intent is refused, not silently regranted.
    assert_eq!(
        factory(relay, &plain(endpoint()), OperationKind::Reserve)
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    // Staging a fresh connect intent on an unrelated relay stays possible.
    gate.stage_connect(peer(), endpoint(), application, deadline(60))
        .unwrap();
}

#[test]
fn carrier_destination_accepted_renews_deadline_and_extends_eligibility() {
    let relay = peer();
    let application = peer();
    let (_owner, view) = configured(relay, application, endpoint());
    let gate = Gate::new();
    let factory = gate.factory_unbound(view);
    let generation = gate.stage_reserve(relay, endpoint(), deadline(5)).unwrap();
    let capability = factory(relay, &plain(endpoint()), OperationKind::Reserve).unwrap();
    let reserve = plain(endpoint());
    assert!(gate.test_admit(
        relay,
        generation,
        reserve.clone(),
        OperationKind::Reserve,
        None
    ));
    assert!(gate.test_admit(
        relay,
        generation,
        reserve.clone(),
        OperationKind::Reserve,
        Some(ConnectionId::new_unchecked(7))
    ));
    gate.accepted(
        relay,
        generation,
        deadline(50),
        ConnectionId::new_unchecked(7),
    );
    gate.expire(Instant::now() + Duration::from_secs(10));
    assert!(gate.test_admit(
        relay,
        generation,
        reserve.clone(),
        OperationKind::Reserve,
        Some(ConnectionId::new_unchecked(7))
    ));
    assert!(!gate.test_admit(
        relay,
        generation,
        reserve.clone(),
        OperationKind::Reserve,
        Some(ConnectionId::new_unchecked(8))
    ));
    assert!(!gate.test_admit(relay, generation, reserve, OperationKind::Reserve, None));
    drop(capability);
}

#[test]
fn carrier_destination_expiry_removes_intent_without_timers() {
    let relay = peer();
    let application = peer();
    let (_owner, view) = configured(relay, application, endpoint());
    let gate = Gate::new();
    gate.stage_reserve(relay, endpoint(), Instant::now())
        .unwrap();
    gate.expire(Instant::now());
    assert_eq!(gate.next_deadline(), None);
    assert_eq!(
        factory_error(&gate, &view, || (
            relay,
            plain(endpoint()),
            OperationKind::Reserve
        )),
        io::ErrorKind::PermissionDenied
    );
    // Established generations remain admissible for their exact control after
    // the original deadline; a separate unestablished generation expires.
    let ticket = gate
        .stage_connect(relay, endpoint(), application, deadline(60))
        .unwrap();
    let factory = gate.factory_unbound(view.clone());
    let capability = factory(
        relay,
        &plain(endpoint()),
        OperationKind::Connect {
            destination: application,
        },
    )
    .unwrap();
    let control = ConnectionId::new_unchecked(7);
    let request = OperationKind::Connect {
        destination: application,
    };
    assert!(gate.test_admit(
        relay,
        ticket.generation,
        plain(endpoint()),
        request,
        Some(control),
    ));
    gate.establish(ticket);
    gate.expire(Instant::now() + Duration::from_secs(3600));
    assert!(gate.test_admit(
        relay,
        ticket.generation,
        plain(endpoint()),
        OperationKind::Connect {
            destination: application,
        },
        Some(control),
    ));
    assert!(!gate.test_admit(
        relay,
        ticket.generation,
        plain(endpoint()),
        OperationKind::Connect {
            destination: application,
        },
        Some(ConnectionId::new_unchecked(8)),
    ));

    let pending = gate
        .stage_connect(relay, endpoint(), application, deadline(60))
        .unwrap();
    let pending_capability = factory(
        relay,
        &plain(endpoint()),
        OperationKind::Connect {
            destination: application,
        },
    )
    .unwrap();
    gate.expire(Instant::now() + Duration::from_secs(3600));
    assert!(!gate.test_admit(
        relay,
        pending.generation,
        plain(endpoint()),
        OperationKind::Connect {
            destination: application,
        },
        Some(control),
    ));
    drop((capability, pending_capability));
}

#[test]
fn carrier_destination_intent_budget_is_bounded_with_backpressure() {
    let gate = Gate::new();
    let relays: Vec<_> = (0..RECORD_BUDGET).map(|_| peer()).collect();
    let application = peer();
    let mut generations = Vec::with_capacity(RECORD_BUDGET);
    for relay in &relays {
        generations.push(
            gate.stage_reserve(*relay, endpoint(), deadline(60))
                .unwrap(),
        );
    }
    assert_eq!(
        gate.stage_reserve(peer(), endpoint(), deadline(60))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    // A revoked generation keeps its charge as a released-only-later
    // tombstone: capacity is NOT freed by the revoke itself.
    gate.revoke(relays[0], Slot::Reserve);
    gate.terminal_reservation(relays[0], generations[0]);
    assert_eq!(
        gate.stage_reserve(peer(), endpoint(), deadline(60))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    // The released flag is set only by the capability/owner release callback.
    let flag = gate
        .released_flag(relays[0], Slot::Reserve, generations[0])
        .unwrap();
    assert!(flag.load(AtomicOrdering::Acquire));
    gate.prune_released();
    // The freed charge is reusable; the connect slot of an already staged
    // relay is a distinct key and consumes it independently.
    gate.stage_connect(relays[1], endpoint(), application, deadline(60))
        .unwrap();
    assert_eq!(
        gate.stage_reserve(peer(), endpoint(), deadline(60))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn carrier_destination_revoked_generation_retains_charge_until_released_and_pruned() {
    let relay = peer();
    let application = peer();
    let (_owner, view) = configured(relay, application, endpoint());
    let gate = Gate::new();
    let staged = gate.stage_reserve(relay, endpoint(), deadline(60)).unwrap();
    let factory = gate.factory_unbound(view);
    let capability = factory(relay, &plain(endpoint()), OperationKind::Reserve).unwrap();
    assert_eq!(
        capability.generation(),
        Some(NonZeroU64::new(staged).unwrap())
    );
    let flag = gate
        .released_flag(relay, Slot::Reserve, staged)
        .expect("staged record exposes its release flag");
    gate.revoke(relay, Slot::Reserve);
    gate.terminal_reservation(relay, staged);
    assert!(!flag.load(AtomicOrdering::Acquire));
    assert_eq!(gate.record_count(), 1);
    drop(capability);
    assert!(flag.load(AtomicOrdering::Acquire));
    gate.prune_released();
    assert_eq!(gate.record_count(), 0);
    let fresh = gate.stage_reserve(relay, endpoint(), deadline(60)).unwrap();
    assert!(fresh > staged);
}

#[test]
fn carrier_destination_distinct_connect_destinations_coexist_per_generation() {
    let relay = peer();
    let application_a = peer();
    let application_b = peer();
    let mut owner = Owner::new(&[application_a, application_b], &[]).unwrap();
    owner
        .admit_identity(relay, Role::ExplicitRelay(endpoint()))
        .unwrap();
    let view = owner.view();
    let gate = Gate::new();
    let ticket_a = gate
        .stage_connect(relay, endpoint(), application_a, deadline(60))
        .unwrap();
    let ticket_b = gate
        .stage_connect(relay, endpoint(), application_b, deadline(60))
        .unwrap();
    // Concurrent distinct destinations never overwrite: each keeps its own
    // generation row behind the same (relay, endpoint) pair.
    assert_ne!(ticket_a.generation, ticket_b.generation);
    let factory = gate.factory_unbound(view);
    let capability_a = factory(
        relay,
        &plain(endpoint()),
        OperationKind::Connect {
            destination: application_a,
        },
    )
    .unwrap();
    assert_eq!(
        capability_a.generation(),
        Some(NonZeroU64::new(ticket_a.generation).unwrap())
    );
    let capability_b = factory(
        relay,
        &plain(endpoint()),
        OperationKind::Connect {
            destination: application_b,
        },
    )
    .unwrap();
    assert_eq!(
        capability_b.generation(),
        Some(NonZeroU64::new(ticket_b.generation).unwrap())
    );
    assert!(gate.test_admit(
        relay,
        ticket_a.generation,
        plain(endpoint()),
        OperationKind::Connect {
            destination: application_a
        },
        None,
    ));
    assert!(gate.test_admit(
        relay,
        ticket_b.generation,
        plain(endpoint()),
        OperationKind::Connect {
            destination: application_b
        },
        None,
    ));
    gate.revoke_generation(relay, Slot::Connect, ticket_a.generation);
    assert!(!gate.test_admit(
        relay,
        ticket_a.generation,
        plain(endpoint()),
        OperationKind::Connect {
            destination: application_a
        },
        None,
    ));
    assert!(gate.test_admit(
        relay,
        ticket_b.generation,
        plain(endpoint()),
        OperationKind::Connect {
            destination: application_b
        },
        None,
    ));
}

#[test]
fn carrier_destination_revoke_generation_spares_a_live_successor() {
    let relay = peer();
    let application = peer();
    let (_owner, view) = configured(relay, application, endpoint());
    let gate = Gate::new();
    let first = gate
        .stage_connect(relay, endpoint(), application, deadline(60))
        .unwrap();
    let second = gate
        .stage_connect(relay, endpoint(), application, deadline(60))
        .unwrap();
    // Closing the old circuit retires only its own generation: the first row
    // is released-for-prune, the successor is untouched and still live.
    gate.revoke_generation(relay, Slot::Connect, first.generation);
    gate.terminal(Ticket {
        relay,
        generation: first.generation,
    });
    assert!(
        gate.released_flag(relay, Slot::Connect, first.generation)
            .is_some()
    );
    let factory = gate.factory_unbound(view.clone());
    let capability = factory(
        relay,
        &plain(endpoint()),
        OperationKind::Connect {
            destination: application,
        },
    )
    .unwrap();
    assert_eq!(
        capability.generation(),
        Some(NonZeroU64::new(second.generation).unwrap())
    );
    // A plain revoke (stop/teardown) retires every generation of the slot.
    drop(capability);
    drop(factory);
    gate.revoke(relay, Slot::Connect);
    gate.terminal(second);
    assert_eq!(
        factory_error(&gate, &view, || (
            relay,
            plain(endpoint()),
            OperationKind::Connect {
                destination: application
            }
        )),
        io::ErrorKind::PermissionDenied
    );
}

#[test]
fn carrier_destination_stale_generation_establish_is_a_no_op() {
    let relay = peer();
    let application = peer();
    let (_owner, view) = configured(relay, application, endpoint());
    let gate = Gate::new();
    let factory = gate.factory_unbound(view.clone());
    let stale = gate
        .stage_connect(relay, endpoint(), application, deadline(60))
        .unwrap();
    gate.revoke_generation(relay, Slot::Connect, stale.generation);
    gate.terminal(stale);
    gate.prune_released();
    assert_eq!(gate.record_count(), 0);
    let fresh = gate
        .stage_connect(relay, endpoint(), application, deadline(60))
        .unwrap();
    let capability = factory(
        relay,
        &plain(endpoint()),
        OperationKind::Connect {
            destination: application,
        },
    )
    .unwrap();
    assert!(gate.test_admit(
        relay,
        fresh.generation,
        plain(endpoint()),
        OperationKind::Connect {
            destination: application,
        },
        None,
    ));
    gate.establish(stale);
    gate.expire(Instant::now() + Duration::from_secs(120));
    assert!(!gate.test_admit(
        relay,
        fresh.generation,
        plain(endpoint()),
        OperationKind::Connect {
            destination: application,
        },
        None,
    ));
    assert!(
        factory(
            relay,
            &plain(endpoint()),
            OperationKind::Connect {
                destination: application,
            },
        )
        .is_err()
    );
    gate.terminal(fresh);
    gate.prune_released();
    assert_eq!(gate.record_count(), 1);
    drop(capability);
    gate.prune_released();
    assert_eq!(gate.record_count(), 0);
}
