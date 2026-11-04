// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use iroh_base::EndpointId;
use n0_mainline::OwnedQueryCompletion;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

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
pub(in crate::native_discovery) enum ResolveError {
    Policy(RecordError),
    Decode(DecodeError),
    NoNetworkCompletion,
    DeadlineExceeded,
    DeliveryLimit,
}

#[derive(Debug)]
pub(in crate::native_discovery) struct ResolvedAddresses {
    addresses: Vec<SocketAddr>,
    // Retain the actual backend result charge through delivery and caller use.
    _completion: Option<OwnedQueryCompletion>,
    // Owner-wide delivery budget charge; released when the caller drops the result.
    _delivery: OwnedSemaphorePermit,
}

impl ResolvedAddresses {
    pub(in crate::native_discovery) fn addresses(&self) -> &[SocketAddr] {
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
        let now = policy_clock(sample);
        self.policy
            .observe_clock(now)
            .map_err(ResolveError::Policy)?;
        self.policy
            .admit_expected_key(key)
            .map_err(ResolveError::Policy)?;
        if self
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
