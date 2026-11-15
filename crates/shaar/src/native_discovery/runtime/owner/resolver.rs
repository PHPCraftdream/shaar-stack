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

/// Advisory reflexive-address watcher. Never published anywhere (record,
/// publisher and dial behavior are untouched): publication is leaf L3.
///
/// Resource bounds: one GET query per `REFRESH` window (60 s), each lookup
/// hard-bounded by `REFLEXIVE_LOOKUP_BOUND` (10 s), no queues — the watch
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
/// joined) — this is the shutdown cancel path. The whole window work — the
/// self-lookup AND the subsequent `info()` read — races `stop` first
/// (biased) against a single `REFLEXIVE_LOOKUP_BOUND` per window, so
/// shutdown cancels cleanly even while `info()` is in flight. Lookup or
/// `info()` errors skip the window (no observation): `resolve_mutable` runs
/// a real iterative GET (votes collected on every response,
/// handle_response.rs:70-71); observing requires `network_completed()`
/// (resolver.rs:138 pattern), and the pinned crate overwrites
/// `public_address` only when the finished GET collected at least one vote
/// (core.rs:386-409).
pub(super) async fn reflexive_loop(
    handle: OwnedDhtHandle,
    target: n0_mainline::Id,
    mut tally: ReflexiveTally,
    sender: watch::Sender<Option<IpAddr>>,
    mut stop: oneshot::Receiver<()>,
) {
    let mut sent: Option<IpAddr> = None;
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
                let bound = tokio::time::Instant::now() + REFLEXIVE_LOOKUP_BOUND;
                let work = async {
                    let completion = handle.resolve_mutable(target).await.ok()?;
                    if !completion.network_completed() {
                        return None;
                    }
                    drop(completion);
                    let info = handle.info().await.ok()?;
                    Some(info.public_address().map(|address| IpAddr::V4(*address.ip())))
                };
                let observed = tokio::select! {
                    biased;
                    _ = &mut stop => return,
                    _ = tokio::time::sleep_until(bound) => None,
                    observed = work => observed,
                };
                let Some(observed) = observed else {
                    // Bounded out or skipped; no observation this window.
                    continue;
                };
                let value = tally.observe(observed);
                if value != sent {
                    sender.send_replace(value);
                    sent = value;
                }
            }
        }
    }
}
