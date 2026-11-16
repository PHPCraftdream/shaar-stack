//! Unit tests for leaf L1 (dial ordering, R1) over the extracted candidate
//! loop that `NativeDialer::dial` drives in production. The `connect` seam is
//! faked with pending (silent) and immediate typed-refusal futures under
//! paused Tokio time, so every timing oracle is exact virtual time and no
//! sockets are involved. Acceptance letters refer to leaf L1 in
//! `docs/plans/p13-controlled-network.md`.

use std::{future::Future, pin::Pin, sync::Mutex, time::Duration};

use super::*;

type ConnectFuture = Pin<Box<dyn Future<Output = Result<Session, NetworkError>>>>;

/// The silent candidates use private/local scope like the recorded A5 record
/// (only the server's private address); public-scope probes use globally
/// routable addresses outside every documented local range.
fn dialed(addresses: &[SocketAddr]) -> Vec<SocketAddr> {
    addresses.to_vec()
}

/// Builds the connect seam: `silent` addresses never answer (pending), every
/// other address returns an immediate typed non-fatal refusal. Every dialed
/// address is recorded in order.
fn connect_seam(
    calls: Arc<Mutex<Vec<SocketAddr>>>,
    silent: Vec<SocketAddr>,
) -> impl FnMut(SocketAddr) -> ConnectFuture {
    move |address: SocketAddr| {
        calls.lock().expect("call log lock").push(address);
        if silent.contains(&address) {
            Box::pin(std::future::pending::<Result<Session, NetworkError>>()) as ConnectFuture
        } else {
            Box::pin(std::future::ready::<Result<Session, NetworkError>>(Err(
                NetworkError::Closed,
            ))) as ConnectFuture
        }
    }
}

fn log(calls: &Arc<Mutex<Vec<SocketAddr>>>) -> Vec<SocketAddr> {
    calls.lock().expect("call log lock").clone()
}

/// Public/reflexive-scope candidates are ordered ahead of private/local-scope
/// candidates, and both classes keep their record order; an ordered list is a
/// fixed point.
#[test]
fn public_first_order_keeps_both_class_orders() {
    let public_a = SocketAddr::from(([8, 8, 8, 8], 443));
    let public_b = SocketAddr::from(([9, 9, 9, 9], 443));
    let local_a = SocketAddr::from(([10, 0, 0, 1], 1000));
    let local_b = SocketAddr::from(([192, 168, 1, 1], 1001));
    let mut mixed = vec![local_a, public_a, local_b, public_b];
    public_first_order(&mut mixed);
    assert_eq!(mixed, vec![public_a, public_b, local_a, local_b]);
    public_first_order(&mut mixed);
    assert_eq!(mixed, vec![public_a, public_b, local_a, local_b]);
}

/// The documented heuristic: RFC 1918, CGNAT 100.64/10, IPv4 loopback and
/// link-local, IPv6 loopback and link-local and their IPv4-mapped forms are
/// private/local; everything else — including IPv6 global unicast and
/// unique-local addresses, which the documented list does not name — is
/// public/reflexive scope.
#[test]
fn scope_heuristic_matches_the_documented_local_ranges() {
    for text in [
        "10.1.2.3:1",
        "172.16.0.1:1",
        "172.31.255.255:1",
        "192.168.10.10:1",
        "100.64.0.0:1",
        "100.127.255.255:1",
        "127.0.0.1:1",
        "169.254.9.9:1",
        "[::1]:1",
        "[fe80::1]:1",
        "[febf::ffff]:1",
        "[::ffff:10.0.0.1]:1",
        "[::ffff:127.0.0.1]:1",
    ] {
        let address: SocketAddr = text.parse().expect("test address parses");
        assert!(
            candidate_is_local(address),
            "{address} must be private/local"
        );
    }
    for text in [
        "172.15.255.255:1",
        "172.32.0.1:1",
        "100.63.255.255:1",
        "100.128.0.0:1",
        "169.255.0.1:1",
        "8.8.8.8:53",
        "[2001:db8::1]:1",
        "[fc00::1]:1",
        "[::ffff:8.8.8.8]:1",
    ] {
        let address: SocketAddr = text.parse().expect("test address parses");
        assert!(
            !candidate_is_local(address),
            "{address} must be public/reflexive"
        );
    }
}

/// (a) With a silent first private/local candidate and a second candidate
/// that answers at once, one attempt still reaches the second candidate: the
/// first consumes exactly its one-second slice, not the attempt deadline.
/// The previous behavior ended the attempt on the first timeout.
#[tokio::test(start_paused = true)]
async fn silent_first_candidate_yields_to_the_second_inside_one_attempt() {
    let first = SocketAddr::from(([10, 0, 2, 2], 4242));
    let second = SocketAddr::from(([10, 0, 2, 3], 4243));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut candidates = dialed(&[first, second]);
    let started = Instant::now();
    let outcome = dial_candidate_list(
        &mut candidates,
        started + Duration::from_secs(10),
        connect_seam(Arc::clone(&calls), dialed(&[first])),
    )
    .await
    .expect("no fatal error: the exhausted list reaches the relay phase");
    assert!(outcome.is_none(), "both candidates failed, relay follows");
    assert_eq!(log(&calls), dialed(&[first, second]));
    assert_eq!(
        started.elapsed(),
        Duration::from_secs(1),
        "one slice, not the deadline"
    );
    assert!(candidates.is_empty(), "the exhausted list is cleared");
}

/// (b) Every timed-out candidate is dropped from the list: three silent
/// candidates are dialed exactly once each — no same-dial retry — and the
/// list is empty afterwards. The previous behavior ended the attempt on the
/// first timeout with the candidate retained.
#[tokio::test(start_paused = true)]
async fn timed_out_candidates_are_dropped_and_not_retried_in_the_same_dial() {
    let addresses = dialed(&[
        SocketAddr::from(([10, 0, 2, 2], 4242)),
        SocketAddr::from(([10, 0, 2, 3], 4243)),
        SocketAddr::from(([10, 0, 2, 4], 4244)),
    ]);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut candidates = dialed(&addresses);
    let started = Instant::now();
    let outcome = dial_candidate_list(
        &mut candidates,
        started + Duration::from_secs(30),
        connect_seam(Arc::clone(&calls), dialed(&addresses)),
    )
    .await
    .expect("no fatal error");
    assert!(outcome.is_none());
    assert_eq!(
        log(&calls),
        addresses,
        "each silent candidate is dialed exactly once"
    );
    assert_eq!(
        started.elapsed(),
        Duration::from_secs(3),
        "three one-second slices"
    );
    assert!(candidates.is_empty());
}

/// (c) When nothing works the candidate phase still ends bounded inside the
/// unchanged attempt budget (the production default is 3 s): two silent
/// private/local candidates cost exactly two slices and hand the attempt to
/// the unchanged relay phase and typed `Exhausted` exit.
#[tokio::test(start_paused = true)]
async fn all_silent_candidates_end_bounded_inside_the_attempt_budget() {
    let first = SocketAddr::from(([10, 0, 2, 2], 4242));
    let second = SocketAddr::from(([127, 0, 0, 1], 4243));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut candidates = dialed(&[first, second]);
    let started = Instant::now();
    let outcome = dial_candidate_list(
        &mut candidates,
        started + Duration::from_secs(3),
        connect_seam(Arc::clone(&calls), dialed(&[first, second])),
    )
    .await
    .expect("no fatal error");
    assert!(
        outcome.is_none(),
        "the empty list reaches relay negotiation"
    );
    assert_eq!(
        started.elapsed(),
        Duration::from_secs(2),
        "two slices inside 3 s"
    );
}

/// (d) A silent public-scope first candidate is not sliced: its timeout fires
/// at the full attempt deadline (three seconds, not one), the candidate is
/// dropped and the attempt then ends with the budget kept.
#[tokio::test(start_paused = true)]
async fn silent_public_first_candidate_keeps_the_full_attempt_deadline() {
    let public = SocketAddr::from(([8, 8, 8, 8], 4242));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut candidates = dialed(&[public]);
    let started = Instant::now();
    let outcome = dial_candidate_list(
        &mut candidates,
        started + Duration::from_secs(3),
        connect_seam(Arc::clone(&calls), dialed(&[public])),
    )
    .await;
    assert!(
        matches!(outcome, Ok(None)),
        "no fatal error, list exhausted"
    );
    assert_eq!(log(&calls), dialed(&[public]));
    assert_eq!(
        started.elapsed(),
        Duration::from_secs(3),
        "the full deadline, not a one-second slice"
    );
}

/// (d) A public-scope candidate that answers (here with an immediate typed
/// refusal) is not delayed by the slice either: it is dropped at once and the
/// private/local candidate behind it gets its own slice.
#[tokio::test(start_paused = true)]
async fn answering_public_candidate_is_dropped_at_once_before_the_local_slice() {
    let public = SocketAddr::from(([8, 8, 8, 8], 4242));
    let local = SocketAddr::from(([10, 0, 2, 3], 4243));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut candidates = dialed(&[public, local]);
    let started = Instant::now();
    let outcome = dial_candidate_list(
        &mut candidates,
        started + Duration::from_secs(30),
        connect_seam(Arc::clone(&calls), dialed(&[local])),
    )
    .await
    .expect("no fatal error");
    assert!(outcome.is_none());
    assert_eq!(log(&calls), dialed(&[public, local]));
    assert_eq!(
        started.elapsed(),
        Duration::from_secs(1),
        "only the local slice waits"
    );
}

/// (e) The recorded A5 shape — a private-only record whose candidate is
/// silent — still reaches relay negotiation inside one attempt: the loop
/// reports the exhausted list after exactly one slice instead of ending the
/// attempt at the deadline. The relay phase itself is unchanged.
#[tokio::test(start_paused = true)]
async fn silent_private_only_record_reaches_the_relay_phase() {
    let private = SocketAddr::from(([10, 0, 2, 2], 4242));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut candidates = dialed(&[private]);
    let started = Instant::now();
    let outcome = dial_candidate_list(
        &mut candidates,
        started + Duration::from_secs(3),
        connect_seam(Arc::clone(&calls), dialed(&[private])),
    )
    .await
    .expect("no fatal error");
    assert!(
        outcome.is_none(),
        "relay negotiation follows the exhausted list"
    );
    assert_eq!(log(&calls), dialed(&[private]));
    assert_eq!(started.elapsed(), Duration::from_secs(1));
}

/// Typed-error contract unchanged (R1 scope guard): a denied-key refusal is
/// fatal and still ends the attempt immediately, without dialing further
/// candidates and without removing anything from the list.
#[tokio::test(start_paused = true)]
async fn denied_key_refusal_still_ends_the_attempt_immediately() {
    let denied = SocketAddr::from(([10, 0, 2, 2], 4242));
    let later = SocketAddr::from(([10, 0, 2, 3], 4243));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&calls);
    let mut connect = move |address: SocketAddr| {
        recorded.lock().expect("call log lock").push(address);
        if address == denied {
            Box::pin(std::future::ready::<Result<Session, NetworkError>>(Err(
                NetworkError::AccessDenied,
            ))) as ConnectFuture
        } else {
            Box::pin(std::future::pending::<Result<Session, NetworkError>>()) as ConnectFuture
        }
    };
    let mut candidates = dialed(&[denied, later]);
    let started = Instant::now();
    let outcome = dial_candidate_list(
        &mut candidates,
        started + Duration::from_secs(30),
        &mut connect,
    )
    .await;
    assert_eq!(
        outcome.err(),
        Some(DialError),
        "a denied key ends the attempt"
    );
    assert_eq!(log(&calls), dialed(&[denied]));
    assert_eq!(
        candidates,
        dialed(&[denied, later]),
        "the fatal path retains the list"
    );
    assert_eq!(
        started.elapsed(),
        Duration::ZERO,
        "no waiting on a denied key"
    );
}

/// L0: with no configured relay the negotiation phase does not exist. The
/// direct phase still ends bounded (one silent local candidate costs its
/// one-second slice, the list is exhausted) and the negotiation guard
/// answers `None`, so the attempt ends typed without any relay dial.
#[tokio::test(start_paused = true)]
async fn no_configured_relay_ends_the_attempt_typed_after_the_direct_phase() {
    let private = SocketAddr::from(([10, 0, 2, 2], 4242));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut candidates = dialed(&[private]);
    let started = Instant::now();
    let outcome = dial_candidate_list(
        &mut candidates,
        started + Duration::from_secs(3),
        connect_seam(Arc::clone(&calls), dialed(&[private])),
    )
    .await
    .expect("the direct phase ends bounded without a fatal error");
    assert!(outcome.is_none(), "the exhausted list reaches negotiation");
    assert_eq!(started.elapsed(), Duration::from_secs(1));
    assert_eq!(
        negotiation_target(&None),
        None,
        "no configured relay: the negotiation phase does not exist"
    );
}

/// NAT-L4e: with a punch channel the record lookup may hold the attempt for one second at
/// most, so the punch phase keeps the rest of the 3 s attempt; without one the lookup keeps
/// its five seconds and the attempt deadline still wins.
#[tokio::test(start_paused = true)]
async fn the_record_lookup_leaves_the_punch_phase_its_share_of_the_attempt() {
    let now = Instant::now();
    let attempt = now + Duration::from_secs(3);
    assert_eq!(
        resolve_budget(now, attempt, true),
        now + Duration::from_secs(1)
    );
    assert!(
        attempt - resolve_budget(now, attempt, true) >= Duration::from_secs(2),
        "the punch phase keeps at least two seconds of a three second attempt"
    );
    assert_eq!(resolve_budget(now, attempt, false), attempt);
    let long = now + Duration::from_secs(30);
    assert_eq!(
        resolve_budget(now, long, false),
        now + Duration::from_secs(5)
    );
    assert_eq!(
        resolve_budget(now, long, true),
        now + Duration::from_secs(1)
    );
    let short = now + Duration::from_millis(400);
    assert_eq!(
        resolve_budget(now, short, true),
        short,
        "a shorter attempt deadline always wins"
    );
}
