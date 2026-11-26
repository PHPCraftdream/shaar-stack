// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

//! The network lookup of a record (leaf PKARR-4): the DHT and, beside it, the public pkarr relays.

use std::sync::atomic::Ordering;

use iroh_base::EndpointId;
use n0_mainline::{MutableItem, OwnedQueryCompletion, ResourceError};

use super::super::{RuntimeError, RuntimeOwner};
use super::{ResolveError, ResolvedAddresses};
use crate::native_discovery::runtime::publisher::relay::{Answer, Fetched, RelayRead, read_line};
use crate::network::observe::emit;

/// The next answer of the lookup's relay reads, or `None` when there are none (or none are left).
async fn relay_answer(reads: &mut Option<RelayRead>) -> Option<Answer> {
    match reads {
        Some(reads) => reads.next().await,
        None => None,
    }
}

impl RuntimeOwner {
    /// One network lookup of `key` (leaf PKARR-4): the DHT lookup and, beside it, one `GET` per
    /// configured pkarr relay. The first record that passes the policy is delivered and the rest
    /// is dropped; a relay answer that is not such a record is a miss and changes nothing. When
    /// the DHT ends with a miss while requests are still in flight, those are awaited (each ends
    /// by its own bound), never past `deadline`. With no relay this is the DHT lookup alone.
    /// cancel-safe: NO — a completion may be consumed; the retained owner still owns cleanup.
    pub(in crate::native_discovery::runtime::owner) async fn network_lookup(
        &mut self,
        key: EndpointId,
        deadline: tokio::time::Instant,
    ) -> Result<ResolvedAddresses, RuntimeError> {
        let handle = self.dht.as_ref().ok_or(RuntimeError::Closed)?.handle();
        let target = MutableItem::target_from_key(key.as_bytes(), None);
        let mut reads = self
            .reader
            .as_mut()
            .map(|reader| reader.begin(key, tokio::time::Instant::now()));
        let dht = handle.resolve_mutable_until(target, deadline);
        tokio::pin!(dht);
        let result = loop {
            tokio::select! {
                result = &mut dht => break result,
                Some(answer) = relay_answer(&mut reads) => {
                    if let Some(resolved) = self.take_relay_answer(key, answer, deadline).await {
                        return Ok(resolved);
                    }
                }
            }
        };
        match (self.complete_dht(key, result, deadline).await, reads) {
            (Err(miss @ (RuntimeError::Resolve(_) | RuntimeError::Resource(_))), Some(reads))
                if !reads.is_empty() =>
            {
                self.await_relays(key, reads, miss, deadline).await
            }
            (outcome, _) => outcome,
        }
    }

    async fn complete_dht(
        &mut self,
        key: EndpointId,
        result: Result<OwnedQueryCompletion, ResourceError>,
        deadline: tokio::time::Instant,
    ) -> Result<ResolvedAddresses, RuntimeError> {
        let completion = result.map_err(|error| match error {
            ResourceError::DeadlineExceeded => RuntimeError::DeadlineExceeded,
            other => RuntimeError::Resource(other),
        })?;
        let sample = match self.clock.sample() {
            Ok(sample) => sample,
            Err(error) => {
                self.resolver.note_terminal_clock_fault();
                self.clock_fault.store(true, Ordering::Release);
                let _ = tokio::time::timeout_at(deadline, self.withdraw())
                    .await
                    .map_err(|_| RuntimeError::DeadlineExceeded)?;
                return Err(error);
            }
        };
        if tokio::time::Instant::now() >= deadline {
            return Err(RuntimeError::DeadlineExceeded);
        }
        self.resolver
            .complete(key, completion, sample, deadline)
            .await
            .map_err(|error| match error {
                ResolveError::DeadlineExceeded => RuntimeError::DeadlineExceeded,
                other => RuntimeError::Resolve(other),
            })
    }

    /// The DHT lookup ended with `miss`; a relay may still hold the record.
    async fn await_relays(
        &mut self,
        key: EndpointId,
        mut reads: RelayRead,
        miss: RuntimeError,
        deadline: tokio::time::Instant,
    ) -> Result<ResolvedAddresses, RuntimeError> {
        loop {
            let answer = tokio::select! {
                answer = reads.next() => answer,
                () = tokio::time::sleep_until(deadline) => None,
            };
            let Some(answer) = answer else {
                return Err(miss);
            };
            if let Some(resolved) = self.take_relay_answer(key, answer, deadline).await {
                return Ok(resolved);
            }
        }
    }

    /// One relay answer: its trace line, the silence after a `429` and, for a packet, the same
    /// decode and policy as a DHT item. `Some` delivers the record; anything else is a miss.
    async fn take_relay_answer(
        &mut self,
        key: EndpointId,
        answer: Answer,
        deadline: tokio::time::Instant,
    ) -> Option<ResolvedAddresses> {
        let Answer {
            index,
            fetched,
            elapsed,
        } = answer;
        let mut delivered = None;
        let token = match &fetched {
            Fetched::Found(body) => {
                if let Ok(sample) = self.clock.sample() {
                    delivered = self
                        .resolver
                        .complete_relay(key, body, sample, deadline)
                        .await
                        .ok();
                }
                let class = if delivered.is_some() {
                    "found"
                } else {
                    "rejected"
                };
                class.to_owned()
            }
            other => other.token(),
        };
        if fetched == Fetched::RateLimited
            && let Some(reader) = self.reader.as_mut()
        {
            reader.silence(index, tokio::time::Instant::now());
        }
        emit(read_line(index, &token, elapsed));
        delivered
    }
}
