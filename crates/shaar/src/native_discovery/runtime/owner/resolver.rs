// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use iroh_base::EndpointId;
use n0_mainline::OwnedQueryCompletion;
use std::net::SocketAddr;

use super::super::clock::ClockSample;
use crate::native_discovery::codec::{DecodeError, decode_mutable_record};
use crate::native_discovery::policy::{
    ClockSample as PolicyClock, CompletedQuery, PolicyOwner, QuerySource, RecordError,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::native_discovery) enum ResolveError {
    Policy(RecordError),
    Decode(DecodeError),
    NoNetworkCompletion,
}

#[derive(Debug)]
pub(in crate::native_discovery) struct ResolvedAddresses {
    addresses: Vec<SocketAddr>,
    // Retain the actual backend result charge through delivery and caller use.
    _completion: Option<OwnedQueryCompletion>,
}

impl ResolvedAddresses {
    pub(in crate::native_discovery) fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }
}

pub(super) struct ResolverState {
    policy: PolicyOwner,
}

impl ResolverState {
    pub(super) fn new() -> Self {
        Self {
            policy: PolicyOwner::new(),
        }
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
        let addresses = self
            .policy
            .addresses(key, now)
            .map_err(ResolveError::Policy)?
            .to_vec();
        Ok(Some(ResolvedAddresses {
            addresses,
            _completion: None,
        }))
    }

    pub(super) fn complete(
        &mut self,
        key: EndpointId,
        completion: OwnedQueryCompletion,
        sample: ClockSample,
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
        let query = CompletedQuery::new(QuerySource::Network, policy_clock(sample), records);
        let addresses = self
            .policy
            .complete_query_addresses(key, query)
            .map_err(ResolveError::Policy)?
            .to_vec();
        Ok(ResolvedAddresses {
            addresses,
            _completion: Some(completion),
        })
    }
}

fn policy_clock(sample: ClockSample) -> PolicyClock {
    PolicyClock {
        wall_us: sample.wall_us,
        monotonic_us: sample.monotonic_before_us,
    }
}
