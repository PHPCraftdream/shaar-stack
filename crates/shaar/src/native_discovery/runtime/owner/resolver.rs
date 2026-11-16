// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use iroh_base::EndpointId;
use n0_mainline::{OwnedDhtHandle, OwnedQueryCompletion};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot, watch};

use super::super::clock::{Clock, ClockSample};
use crate::native_discovery::codec::{DecodeError, decode_mutable_record};
use crate::native_discovery::policy::{
    ClockSample as PolicyClock, CompletedQuery, PolicyOwner, PreparedQuery, QuerySource,
    RecordError,
};

/// Owner-wide delivery budget: at most this many results (network or
/// cached) can be held by callers at once.
const DELIVERY_RESULTS: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ResolveError {
    Policy(RecordError),
    Decode(DecodeError),
    NoNetworkCompletion,
    DeadlineExceeded,
    DeliveryLimit,
}

#[derive(Debug)]
pub(crate) struct ResolvedAddresses {
    addresses: Vec<SocketAddr>,
    // Retain the actual backend result charge through delivery and caller use.
    _completion: Option<OwnedQueryCompletion>,
    // Owner-wide delivery budget charge; released when the caller drops the result.
    _delivery: OwnedSemaphorePermit,
}

impl ResolvedAddresses {
    pub(crate) fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }
}

pub(super) struct ResolverState {
    policy: PolicyOwner,
    delivery: Arc<Semaphore>,
    clock: Clock,
}

impl ResolverState {
    pub(super) fn new(clock: Clock) -> Self {
        Self {
            policy: PolicyOwner::new(),
            delivery: Arc::new(Semaphore::new(DELIVERY_RESULTS)),
            clock,
        }
    }

    pub(super) fn note_terminal_clock_fault(&mut self) {
        self.policy.note_terminal_clock_fault();
    }

    #[cfg(test)]
    pub(super) fn cache_deadline(&self, key: EndpointId) -> Option<u64> {
        self.policy.cache_deadline(key)
    }

    #[cfg(test)]
    pub(super) fn winner_sequence(&self, key: EndpointId) -> Option<i64> {
        self.policy.winner_sequence(key)
    }

    pub(super) fn begin(
        &mut self,
        key: EndpointId,
        sample: ClockSample,
    ) -> Result<Option<ResolvedAddresses>, ResolveError> {
        self.begin_with_freshness(key, sample, false)
    }

    pub(super) fn begin_fresh(
        &mut self,
        key: EndpointId,
        sample: ClockSample,
    ) -> Result<Option<ResolvedAddresses>, ResolveError> {
        self.begin_with_freshness(key, sample, true)
    }

    fn begin_with_freshness(
        &mut self,
        key: EndpointId,
        sample: ClockSample,
        fresh: bool,
    ) -> Result<Option<ResolvedAddresses>, ResolveError> {
        let now = policy_clock(sample);
        self.policy
            .observe_clock(now)
            .map_err(ResolveError::Policy)?;
        self.policy
            .admit_expected_key(key)
            .map_err(ResolveError::Policy)?;
        if fresh
            || self
                .policy
                .query_required(key, now)
                .map_err(ResolveError::Policy)?
        {
            return Ok(None);
        }
        // Cache hits are charged to the same owner-wide delivery budget as
        // network results, before any allocation.
        let permit = self
            .delivery
            .clone()
            .try_acquire_owned()
            .map_err(|_| ResolveError::DeliveryLimit)?;
        let addresses = self
            .policy
            .addresses(key, now)
            .map_err(ResolveError::Policy)?
            .to_vec();
        Ok(Some(ResolvedAddresses {
            addresses,
            _completion: None,
            _delivery: permit,
        }))
    }

    pub(super) async fn complete(
        &mut self,
        key: EndpointId,
        completion: OwnedQueryCompletion,
        sample: ClockSample,
        deadline: tokio::time::Instant,
    ) -> Result<ResolvedAddresses, ResolveError> {
        if !completion.network_completed() {
            return Err(ResolveError::NoNetworkCompletion);
        }
        if completion.items().len() > 32 {
            return Err(ResolveError::Policy(RecordError::BatchTooLarge));
        }
        let records = completion
            .items()
            .iter()
            .map(|item| {
                decode_mutable_record(item, key)
                    .map(Into::into)
                    .map_err(ResolveError::Decode)
            })
            .collect::<Result<Vec<_>, _>>()?;
        // `sample` is the backend receipt sample, taken locally from the
        // shared clock authority immediately after the backend future
        // returned; it anchors the cache receipt deadline.
        // `tokio::time::Instant::now()` below is the current-use time and
        // guards the original caller deadline; freshness is re-checked at
        // the commit point against a current-use wall sample, so a
        // verification or scheduling delay can never admit an age-expired
        // immediate result or shift the cache deadline.
        let query = CompletedQuery::new(QuerySource::Network, policy_clock(sample), records);
        // Preparation is transactional: neither the decode above nor the
        // policy preparation mutates winner or cache-deadline state.
        let prepared = self
            .policy
            .prepare_query(key, query)
            .map_err(ResolveError::Policy)?;
        #[cfg(test)]
        {
            // Test-only cooperative point: the paused-clock deadline
            // regression advances time here. Synchronous policy work cannot
            // be interrupted in production builds.
            tokio::task::yield_now().await;
        }
        let permit = self
            .delivery
            .clone()
            .try_acquire_owned()
            .map_err(|_| ResolveError::DeliveryLimit)?;
        // Current-use sample: taken locally at the commit point, after decode
        // and policy preparation. Its wall time re-checks signed age so a
        // verification or scheduling delay can never admit an age-expired
        // immediate result or extend freshness. A failed read is a terminal
        // clock fault for this owner.
        let use_wall_us = match self.clock.sample() {
            Ok(current) => current.wall_us,
            Err(_) => {
                self.policy.note_terminal_clock_fault();
                return Err(ResolveError::Policy(RecordError::ClockFault));
            }
        };
        // Last deadline observation: only synchronous commit work follows it.
        if tokio::time::Instant::now() >= deadline {
            return Err(ResolveError::DeadlineExceeded);
        }
        let addresses = match prepared {
            PreparedQuery::Deliver(outcome) => self
                .policy
                .commit_query_deliver(outcome, policy_clock(sample).monotonic_us, use_wall_us)
                .map_err(ResolveError::Policy)?
                .to_vec(),
            PreparedQuery::Conflict(outcome) => {
                self.policy.commit_query_conflict(outcome);
                return Err(ResolveError::Policy(RecordError::EqualSequenceConflict));
            }
            PreparedQuery::ExpiredCacheOnly => {
                return Err(ResolveError::Policy(RecordError::CacheExpired));
            }
        };
        Ok(ResolvedAddresses {
            addresses,
            _completion: Some(completion),
            _delivery: permit,
        })
    }
}

fn policy_clock(sample: ClockSample) -> PolicyClock {
    PolicyClock {
        wall_us: sample.wall_us,
        monotonic_us: sample.monotonic_before_us,
    }
}

/// Hard bound on one reflexive self-lookup, matching the adapter's internal
/// 10 s cap on `resolve_mutable` (`resolve_mutable` uses the same default).
pub(super) const REFLEXIVE_LOOKUP_BOUND: Duration = Duration::from_secs(10);
/// Fast start (production builds): the first lookups run at once and then follow
/// each other (`fast_start_pause`) until a vote is exposed or `FAST_START_WINDOW`
/// has passed, so the public address is known within seconds instead of two
/// refresh windows. Once per owner lifetime; afterwards the regular `REFRESH`
/// windows apply. Live lookups take 6 to 10 s each, so the pause matters.
pub(super) const FAST_START_INTERVAL: Duration = Duration::from_secs(5);
pub(super) const FAST_START_WINDOW: Duration = Duration::from_secs(30);
/// Pause after a window without any observation (lookup failed, bounded out or no vote
/// learned): the cold DHT is usually ready within seconds, so retry sooner.
pub(super) const FAST_START_RETRY: Duration = Duration::from_secs(2);
/// Floor between two lookups when the last window held an address: confirm it at once.
pub(super) const FAST_START_CONFIRM: Duration = Duration::from_millis(250);

/// Pause before the next fast-start lookup, by what the last window observed: an address
/// is confirmed right away, a window without observation is retried after a short pause,
/// and a completed lookup that found no vote waits the full interval.
pub(super) const fn fast_start_pause(observation: Option<Option<IpAddr>>) -> Duration {
    match observation {
        Some(Some(_)) => FAST_START_CONFIRM,
        Some(None) => FAST_START_INTERVAL,
        None => FAST_START_RETRY,
    }
}

/// Bound on the `info()` read that follows the window's own lookup.
const INFO_READ_BOUND: Duration = Duration::from_secs(2);

/// How a window's own self-lookup ended (a trace token, never an address).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Lookup {
    Completed,
    Incomplete,
    Bounded,
    Failed(n0_mainline::ResourceError),
}

impl std::fmt::Display for Lookup {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Completed => out.write_str("ok"),
            Self::Incomplete => out.write_str("incomplete"),
            Self::Bounded => out.write_str("bounded"),
            Self::Failed(error) => write!(out, "failed:{error:?}"),
        }
    }
}

/// One window: the lookup outcome and the `info()` read (`None` when the read failed or
/// was bounded out; `Some(None)` when no vote has been collected yet).
pub(super) struct Window {
    pub(super) lookup: Lookup,
    pub(super) info: Option<Option<IpAddr>>,
}

impl Window {
    /// The observation this window feeds the tally, if any. A completed lookup counts
    /// whatever it read, including "no vote". A lookup that did not complete counts only
    /// an address already learned from other finished queries of the same DHT actor
    /// (the pinned crate sets `public_address` on every finished query that collected a
    /// vote), never an absent vote: no network answer is not evidence of "no address".
    pub(super) fn observation(&self) -> Option<Option<IpAddr>> {
        match (self.lookup, self.info) {
            (_, None) => None,
            (Lookup::Completed, Some(address)) => Some(address),
            (_, Some(Some(address))) => Some(Some(address)),
            (_, Some(None)) => None,
        }
    }

    fn note(&self, start: tokio::time::Instant) {
        let (outcome, info) = match (self.observation(), self.info) {
            (Some(None), _) => ("empty", "none"),
            (Some(Some(_)), _) => ("observed", "some"),
            (None, Some(_)) => ("skipped", "none"),
            (None, None) => ("skipped", "failed"),
        };
        eprintln!(
            "{}",
            probe_line(outcome, &self.lookup, info, start.elapsed().as_millis())
        );
    }
}

/// One self-lookup, then the `info()` read, each raced against `stop` and its own bound
/// (`REFLEXIVE_LOOKUP_BOUND`, `INFO_READ_BOUND`). `None` means the watcher was stopped.
async fn reflexive_probe(
    handle: &OwnedDhtHandle,
    target: n0_mainline::Id,
    stop: &mut oneshot::Receiver<()>,
) -> Option<Window> {
    let bound = tokio::time::Instant::now() + REFLEXIVE_LOOKUP_BOUND;
    let lookup = tokio::select! {
        biased;
        _ = &mut *stop => return None,
        _ = tokio::time::sleep_until(bound) => Lookup::Bounded,
        done = handle.resolve_mutable(target) => match done {
            Ok(completion) if completion.network_completed() => Lookup::Completed,
            Ok(_) => Lookup::Incomplete,
            Err(error) => Lookup::Failed(error),
        },
    };
    let info_bound = tokio::time::Instant::now() + INFO_READ_BOUND;
    let info = tokio::select! {
        biased;
        _ = &mut *stop => return None,
        _ = tokio::time::sleep_until(info_bound) => None,
        read = handle.info() => read.ok().map(|info| {
            info.public_address().map(|address| IpAddr::V4(*address.ip()))
        }),
    };
    Some(Window { lookup, info })
}

/// The trace line of the first exposed majority: an outcome token and the time since the
/// watcher started, never an address.
pub(crate) fn window_line(outcome: &str, elapsed_ms: u128) -> String {
    format!("shaar: reflexive window outcome={outcome} elapsed_ms={elapsed_ms}")
}

/// The trace line of one window: outcome, how the lookup ended and what `info()` held
/// (`some`, `none` or `failed`); tokens only, never an address.
pub(crate) fn probe_line(
    outcome: &str,
    lookup: &impl std::fmt::Display,
    info: &str,
    elapsed_ms: u128,
) -> String {
    format!(
        "shaar: reflexive window outcome={outcome} lookup={lookup} info={info} elapsed_ms={elapsed_ms}"
    )
}

/// Pure majority filter over a fixed 3-window observation ring.
///
/// Resource bound: exactly 3 fixed slots, no heap allocation. Determinism:
/// `observe` is a pure function of the observation sequence. Per-query vote
/// ties inside the pinned crate (`best_address`, iterative_query.rs:129-141)
/// are unobservable here, so a single ambiguous window is never exposed: the
/// winner must be a unique candidate filling >= 2 of the 3 ring slots, i.e.
/// two agreeing windows; otherwise the incumbent exposed value stays.
pub(crate) struct ReflexiveTally {
    ring: [Option<IpAddr>; 3],
    cursor: usize,
    exposed: Option<IpAddr>,
}

impl ReflexiveTally {
    pub(crate) const fn new() -> Self {
        Self {
            ring: [None; 3],
            cursor: 0,
            exposed: None,
        }
    }

    /// Records one window observation (`None` = a completed lookup that
    /// collected no votes) and returns the exposed value. Initial value is
    /// `None`; with no unique majority the incumbent stays.
    pub(crate) fn observe(&mut self, observed: Option<IpAddr>) -> Option<IpAddr> {
        self.ring[self.cursor] = observed;
        self.cursor = (self.cursor + 1) % 3;
        // Two distinct candidates each filling >= 2 slots is impossible over
        // 3 slots, so the first majority found is the unique winner.
        for slot in self.ring {
            if let Some(candidate) = slot
                && self
                    .ring
                    .iter()
                    .filter(|occupied| **occupied == Some(candidate))
                    .count()
                    >= 2
            {
                self.exposed = Some(candidate);
                break;
            }
        }
        self.exposed
    }
}

/// Punch-only hint (leaf HINT-1): the address a window just observed, available before two
/// windows agree. Once a majority is exposed the hint follows it; an empty window never clears
/// it. It is never published and never counts toward the majority.
fn note_hint(
    hint: &watch::Sender<Option<IpAddr>>,
    observed: Option<IpAddr>,
    exposed: Option<IpAddr>,
) {
    if let Some(address) = exposed.or(observed) {
        hint.send_if_modified(|current| {
            let changed = *current != Some(address);
            *current = Some(address);
            changed
        });
    }
}

/// Advisory reflexive-address watcher. Never published anywhere (record,
/// publisher and dial behavior are untouched): publication is leaf L3.
///
/// Resource bounds: one GET query per `REFRESH` window (60 s) after an optional
/// fast start (at most seven lookups within the first 30 s, only until a vote is
/// exposed), each lookup hard-bounded by `REFLEXIVE_LOOKUP_BOUND` (10 s), no queues — the watch
/// channel is a single bounded slot. `firewalled()` is deliberately never
/// read: its confirm-by-ping branch is dead code in the pinned crate
/// (compares the address with itself, core.rs:391-408), so only
/// `public_address()` is trusted (Info::public_address, info.rs:35-37,
/// reading actor.core.public_address, info.rs:76).
///
/// Only the IP is exposed (`IpAddr`, never an endpoint): the BEP 42 `ip`
/// vote describes the DHT socket's mapping (6-byte IPv4+BE port,
/// messages.rs:24, parse :498-499, bytes_to_sockaddr :807-818; IPv6
/// rejected), and only the public IP is shared with the QUIC socket per
/// docs/plans/p13-controlled-network.md section 2 D1.
///
/// Cancel-safety: the outer loop exits promptly on `stop`; a stop mid-lookup
/// drops the in-flight future (adapter-documented cancel behavior: the
/// request lease is released by a drop guard, actor-side cleanup is not
/// joined) — this is the shutdown cancel path. The self-lookup races `stop`
/// first (biased) against `REFLEXIVE_LOOKUP_BOUND` and the subsequent `info()`
/// read against `INFO_READ_BOUND`, so shutdown cancels cleanly even while
/// `info()` is in flight. `resolve_mutable` runs a real iterative GET (votes
/// collected on every response, handle_response.rs:70-71) and the pinned crate
/// overwrites `public_address` whenever ANY finished query collected at least
/// one vote (core.rs:386-409). A lookup that completed counts whatever `info()`
/// holds; one that failed, was bounded out or got no network answer still
/// counts an address another finished query already learned, because the first
/// live smokes showed every own lookup ending without a completion while the
/// address stayed unknown (see `Window::observation`).
pub(super) async fn reflexive_loop(
    handle: OwnedDhtHandle,
    target: n0_mainline::Id,
    mut tally: ReflexiveTally,
    sender: watch::Sender<Option<IpAddr>>,
    hint: watch::Sender<Option<IpAddr>>,
    mut stop: oneshot::Receiver<()>,
    fast_start: bool,
) {
    let mut sent: Option<IpAddr> = None;
    let start = tokio::time::Instant::now();
    if fast_start {
        let deadline = start + FAST_START_WINDOW;
        loop {
            let Some(probe) = reflexive_probe(&handle, target, &mut stop).await else {
                return;
            };
            probe.note(start);
            let observation = probe.observation();
            if let Some(observed) = observation {
                let value = tally.observe(observed);
                note_hint(&hint, observed, value);
                if value != sent {
                    sender.send_replace(value);
                    sent = value;
                    eprintln!("{}", window_line("exposed", start.elapsed().as_millis()));
                }
            }
            if sent.is_some() || tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::select! {
                biased;
                _ = &mut stop => return,
                _ = tokio::time::sleep(fast_start_pause(observation)) => {}
            }
        }
    }
    let mut window = tokio::time::interval(super::loop_state::REFRESH);
    window.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Consume the immediate first tick (publisher_loop.rs:44-46) so the first
    // lookup happens at the first window boundary.
    window.tick().await;
    loop {
        tokio::select! {
            biased;
            _ = &mut stop => return,
            _ = window.tick() => {
                let Some(probe) = reflexive_probe(&handle, target, &mut stop).await else {
                    return;
                };
                probe.note(start);
                // No observation this window (bounded out, failed or no vote learned).
                let Some(observed) = probe.observation() else {
                    continue;
                };
                let value = tally.observe(observed);
                note_hint(&hint, observed, value);
                if value != sent {
                    sender.send_replace(value);
                    sent = value;
                    eprintln!("{}", window_line("exposed", start.elapsed().as_millis()));
                }
            }
        }
    }
}

#[cfg(test)]
mod window_line_tests {
    use super::{
        FAST_START_CONFIRM, FAST_START_INTERVAL, FAST_START_RETRY, Lookup, ReflexiveTally, Window,
        fast_start_pause, probe_line, window_line,
    };
    use n0_mainline::ResourceError;
    use std::net::{IpAddr, Ipv4Addr};

    const ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    const MISSES: [Lookup; 3] = [
        Lookup::Incomplete,
        Lookup::Bounded,
        Lookup::Failed(ResourceError::DeadlineExceeded),
    ];

    fn window(lookup: Lookup, info: Option<Option<IpAddr>>) -> Window {
        Window { lookup, info }
    }

    #[test]
    fn the_window_line_carries_an_outcome_and_a_time_only() {
        assert_eq!(
            window_line("observed", 21_000),
            "shaar: reflexive window outcome=observed elapsed_ms=21000"
        );
        assert_eq!(
            window_line("exposed", 0),
            "shaar: reflexive window outcome=exposed elapsed_ms=0"
        );
    }

    #[test]
    fn a_probe_line_carries_tokens_and_a_time_only() {
        assert_eq!(
            probe_line("skipped", &Lookup::Incomplete, "none", 1001),
            "shaar: reflexive window outcome=skipped lookup=incomplete info=none elapsed_ms=1001"
        );
        let failed = Lookup::Failed(ResourceError::DeadlineExceeded);
        assert_eq!(
            probe_line("observed", &failed, "some", 7),
            "shaar: reflexive window outcome=observed lookup=failed:DeadlineExceeded info=some elapsed_ms=7"
        );
        assert_eq!(Lookup::Completed.to_string(), "ok");
        assert_eq!(Lookup::Bounded.to_string(), "bounded");
    }

    #[test]
    fn a_completed_lookup_counts_whatever_the_info_read_holds() {
        let completed = |info| window(Lookup::Completed, info).observation();
        assert_eq!(completed(Some(Some(ADDRESS))), Some(Some(ADDRESS)));
        assert_eq!(completed(Some(None)), Some(None));
        assert_eq!(completed(None), None);
    }

    #[test]
    fn an_address_learned_elsewhere_counts_when_the_own_lookup_did_not_complete() {
        for lookup in MISSES {
            assert_eq!(
                window(lookup, Some(Some(ADDRESS))).observation(),
                Some(Some(ADDRESS)),
                "{lookup:?}"
            );
        }
    }

    #[test]
    fn no_network_answer_is_never_evidence_of_no_address() {
        for lookup in MISSES {
            assert_eq!(window(lookup, Some(None)).observation(), None, "{lookup:?}");
            assert_eq!(window(lookup, None).observation(), None, "{lookup:?}");
        }
    }

    #[test]
    fn the_fast_start_pause_follows_what_the_window_observed() {
        assert_eq!(fast_start_pause(Some(Some(ADDRESS))), FAST_START_CONFIRM);
        assert_eq!(fast_start_pause(Some(None)), FAST_START_INTERVAL);
        assert_eq!(fast_start_pause(None), FAST_START_RETRY);
        // An address is confirmed first, a failed window retried before a completed empty one,
        // and no pause is zero, so a fast start can never spin.
        assert!(FAST_START_CONFIRM < FAST_START_RETRY);
        assert!(FAST_START_RETRY < FAST_START_INTERVAL);
        assert!(!FAST_START_CONFIRM.is_zero());
    }

    #[test]
    fn the_punch_hint_follows_the_latest_observation_until_a_majority_is_exposed() {
        use super::note_hint;
        let other = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8));
        let (hint, view) = tokio::sync::watch::channel(None);
        note_hint(&hint, None, None);
        assert_eq!(*view.borrow(), None, "an empty window sets nothing");
        note_hint(&hint, Some(ADDRESS), None);
        assert_eq!(
            *view.borrow(),
            Some(ADDRESS),
            "one observation is enough for the hint"
        );
        note_hint(&hint, Some(other), None);
        assert_eq!(
            *view.borrow(),
            Some(other),
            "the latest single observation wins"
        );
        note_hint(&hint, None, None);
        assert_eq!(
            *view.borrow(),
            Some(other),
            "an empty window never clears it"
        );
        note_hint(&hint, Some(other), Some(ADDRESS));
        assert_eq!(
            *view.borrow(),
            Some(ADDRESS),
            "an exposed majority wins over a single observation"
        );
    }

    #[test]
    fn a_learned_address_still_needs_two_agreeing_windows_to_be_exposed() {
        let mut tally = ReflexiveTally::new();
        let learned = || {
            window(Lookup::Incomplete, Some(Some(ADDRESS)))
                .observation()
                .expect("an address learned elsewhere is an observation")
        };
        assert_eq!(tally.observe(learned()), None);
        assert_eq!(tally.observe(learned()), Some(ADDRESS));
    }
}
