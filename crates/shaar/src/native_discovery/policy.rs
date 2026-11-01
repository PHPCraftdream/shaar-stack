// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::codec::DecodedRecord;
use iroh_base::EndpointId;
use std::{collections::BTreeMap, net::SocketAddr};

const MAX_KEYS: usize = 64;
const MAX_RECORD_BYTES: usize = 1104;
const MAX_BATCH_RECORDS: usize = 32;
const MAX_BATCH_BYTES: usize = 1104 * 32;
const MAX_ADDRESSES: usize = 4;
const MAX_METADATA_ENTRIES: usize = 1;
const MAX_USER_DATA_BYTES: usize = 245;
const MAX_AGE_US: i64 = 300_000_000;
const MAX_FUTURE_US: i64 = 30_000_000;
const MAX_CACHE_US: u64 = 30_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ClockSample {
    pub(super) wall_us: i64,
    pub(super) monotonic_us: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RecordObservation {
    pub(super) sequence: i64,
    pub(super) signed_at_us: i64,
    pub(super) signed_bytes: Vec<u8>,
    pub(super) addresses: Vec<SocketAddr>,
    pub(super) metadata: Vec<(String, String)>,
    verified_key: Option<EndpointId>,
}
impl RecordObservation {
    #[cfg(test)]
    pub(super) fn fixture(
        sequence: i64,
        signed_at_us: i64,
        signed_bytes: Vec<u8>,
        addresses: Vec<SocketAddr>,
    ) -> Self {
        Self {
            sequence,
            signed_at_us,
            signed_bytes,
            addresses,
            metadata: Vec::new(),
            verified_key: None,
        }
    }
}
impl From<DecodedRecord> for RecordObservation {
    fn from(record: DecodedRecord) -> Self {
        let (key, sequence, signed_at_us, signed_bytes, addresses, metadata) =
            record.into_policy_parts();
        Self {
            sequence,
            signed_at_us,
            signed_bytes,
            addresses,
            metadata,
            verified_key: Some(key),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum QuerySource {
    Network,
    CacheOnly,
    LocalActivePut,
}
#[derive(Clone, Debug)]
pub(super) struct CompletedQuery {
    source: QuerySource,
    completed_at: ClockSample,
    records: Vec<RecordObservation>,
}
impl CompletedQuery {
    pub(super) fn new(
        source: QuerySource,
        completed_at: ClockSample,
        records: Vec<RecordObservation>,
    ) -> Self {
        Self {
            source,
            completed_at,
            records,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RecordError {
    Unauthorized,
    Capacity,
    InvalidSequence,
    Replay,
    TooOld,
    TooFarFuture,
    CacheMiss,
    CacheExpired,
    EqualSequenceConflict,
    ClockFault,
    DeadlineOverflow,
    InvalidObservation,
    BatchTooLarge,
}
#[derive(Clone, Debug)]
struct PeerState {
    winner: Option<RecordObservation>,
    conflict: bool,
    cache_deadline: Option<u64>,
}
impl PeerState {
    fn new() -> Self {
        Self {
            winner: None,
            conflict: false,
            cache_deadline: None,
        }
    }
}
#[derive(Debug)]
pub(super) struct PolicyOwner {
    peers: BTreeMap<EndpointId, PeerState>,
    previous_clock: Option<ClockSample>,
    clock_fault: bool,
}
impl PolicyOwner {
    pub(super) fn new() -> Self {
        Self {
            peers: BTreeMap::new(),
            previous_clock: None,
            clock_fault: false,
        }
    }
    pub(super) fn admit_expected_key(&mut self, key: EndpointId) -> Result<(), RecordError> {
        if self.clock_fault {
            return Err(RecordError::ClockFault);
        }
        if self.peers.contains_key(&key) {
            return Ok(());
        }
        if self.peers.len() == MAX_KEYS {
            return Err(RecordError::Capacity);
        }
        self.peers.insert(key, PeerState::new());
        Ok(())
    }
    pub(super) fn complete_query(
        &mut self,
        key: EndpointId,
        mut query: CompletedQuery,
    ) -> Result<(), RecordError> {
        self.observe_clock(query.completed_at)?;
        if !self.peers.contains_key(&key) {
            return Err(RecordError::Unauthorized);
        }
        if query.source != QuerySource::Network {
            return self.lookup_cache(key, query.completed_at);
        }
        if query.records.is_empty() {
            return Err(RecordError::CacheMiss);
        }
        if query.records.len() > MAX_BATCH_RECORDS {
            return Err(RecordError::BatchTooLarge);
        }
        let mut batch_bytes = 0_usize;
        for record in &query.records {
            if record.verified_key.is_some_and(|verified| verified != key) {
                return Err(RecordError::Unauthorized);
            }
            if record.signed_bytes.len() > MAX_RECORD_BYTES {
                return Err(RecordError::BatchTooLarge);
            }
            batch_bytes = batch_bytes
                .checked_add(record.signed_bytes.len())
                .ok_or(RecordError::BatchTooLarge)?;
            if batch_bytes > MAX_BATCH_BYTES {
                return Err(RecordError::BatchTooLarge);
            }
        }
        for record in &mut query.records {
            let raw_count = record.addresses.len();
            if record.signed_bytes.is_empty()
                || raw_count > MAX_ADDRESSES
                || record.metadata.len() > MAX_METADATA_ENTRIES
                || record
                    .metadata
                    .iter()
                    .any(|(name, value)| name != "user-data" || value.len() > MAX_USER_DATA_BYTES)
            {
                return Err(RecordError::InvalidObservation);
            }
            if sequence_from_signed(record.sequence).is_err()
                || record.sequence != record.signed_at_us
            {
                return Err(RecordError::InvalidSequence);
            }
            let normalized = crate::native_discovery::validate_addresses(&record.addresses)
                .map_err(|_| RecordError::InvalidObservation)?;
            record.addresses = normalized;
            check_freshness(query.completed_at.wall_us, record.signed_at_us)?;
        }
        let peer = self.peers.get_mut(&key).ok_or(RecordError::Unauthorized)?;
        let mut conflict = false;
        let mut chosen: Option<&RecordObservation> = None;
        let mut maximum: Option<i64> = None;
        for record in &query.records {
            if maximum.is_none_or(|seen| record.sequence > seen) {
                maximum = Some(record.sequence);
                chosen = Some(record);
                conflict = false;
            } else if maximum == Some(record.sequence)
                && chosen.is_some_and(|old| old.signed_bytes != record.signed_bytes)
            {
                conflict = true;
            }
        }
        let maximum = maximum.ok_or(RecordError::CacheMiss)?;
        let mut supersedes = false;
        if let Some(winner) = &peer.winner {
            if maximum < winner.sequence {
                return Err(RecordError::Replay);
            }
            supersedes = maximum > winner.sequence;
            if maximum == winner.sequence
                && query
                    .records
                    .iter()
                    .filter(|record| record.sequence == maximum)
                    .any(|record| record.signed_bytes != winner.signed_bytes)
            {
                conflict = true;
            }
        }
        let chosen = chosen.ok_or(RecordError::CacheMiss)?;
        if conflict {
            if supersedes || peer.winner.is_none() {
                peer.winner = Some(chosen.clone());
            }
            peer.conflict = true;
            peer.cache_deadline = None;
            return Err(RecordError::EqualSequenceConflict);
        }
        if peer.conflict
            && peer
                .winner
                .as_ref()
                .is_some_and(|winner| maximum <= winner.sequence)
        {
            return Err(RecordError::EqualSequenceConflict);
        }
        let changed = peer
            .winner
            .as_ref()
            .is_none_or(|winner| chosen.sequence > winner.sequence);
        let winner = if changed {
            chosen
        } else {
            peer.winner.as_ref().ok_or(RecordError::CacheMiss)?
        };
        let remaining = check_freshness(query.completed_at.wall_us, winner.signed_at_us)?;
        let deadline = query
            .completed_at
            .monotonic_us
            .checked_add(remaining.min(MAX_CACHE_US))
            .ok_or(RecordError::DeadlineOverflow)?;
        if changed {
            peer.winner = Some(chosen.clone());
            peer.conflict = false;
        }
        peer.cache_deadline = Some(deadline);
        Ok(())
    }
    pub(super) fn lookup_cache(
        &mut self,
        key: EndpointId,
        now: ClockSample,
    ) -> Result<(), RecordError> {
        self.observe_clock(now)?;
        let peer = self.peers.get(&key).ok_or(RecordError::Unauthorized)?;
        if peer.conflict {
            return Err(RecordError::EqualSequenceConflict);
        }
        let winner = peer.winner.as_ref().ok_or(RecordError::CacheMiss)?;
        let deadline = peer.cache_deadline.ok_or(RecordError::CacheExpired)?;
        if now.monotonic_us >= deadline {
            return Err(RecordError::CacheExpired);
        }
        check_freshness(now.wall_us, winner.signed_at_us)?;
        Ok(())
    }
    pub(super) fn query_required(
        &mut self,
        key: EndpointId,
        now: ClockSample,
    ) -> Result<bool, RecordError> {
        self.observe_clock(now)?;
        let peer = self.peers.get(&key).ok_or(RecordError::Unauthorized)?;
        if peer.conflict {
            return Ok(true);
        }
        let Some(winner) = &peer.winner else {
            return Ok(true);
        };
        let Some(deadline) = peer.cache_deadline else {
            return Ok(true);
        };
        if now.monotonic_us >= deadline {
            return Ok(true);
        }
        Ok(check_freshness(now.wall_us, winner.signed_at_us).is_err())
    }
    pub(super) fn addresses(
        &mut self,
        key: EndpointId,
        now: ClockSample,
    ) -> Result<&[SocketAddr], RecordError> {
        self.lookup_cache(key, now)?;
        Ok(&self
            .peers
            .get(&key)
            .ok_or(RecordError::Unauthorized)?
            .winner
            .as_ref()
            .ok_or(RecordError::CacheMiss)?
            .addresses)
    }
    pub(super) fn metadata(
        &mut self,
        key: EndpointId,
        now: ClockSample,
    ) -> Result<&[(String, String)], RecordError> {
        self.lookup_cache(key, now)?;
        Ok(&self
            .peers
            .get(&key)
            .ok_or(RecordError::Unauthorized)?
            .winner
            .as_ref()
            .ok_or(RecordError::CacheMiss)?
            .metadata)
    }
    pub(super) fn cache_deadline(&self, key: EndpointId) -> Option<u64> {
        self.peers.get(&key)?.cache_deadline
    }
    pub(super) fn signed_timestamp(&self, key: EndpointId) -> Option<i64> {
        Some(self.peers.get(&key)?.winner.as_ref()?.signed_at_us)
    }
    pub(super) fn winner_sequence(&self, key: EndpointId) -> Option<i64> {
        Some(self.peers.get(&key)?.winner.as_ref()?.sequence)
    }
    pub(super) fn winner_bytes(&self, key: EndpointId) -> Option<&[u8]> {
        Some(&self.peers.get(&key)?.winner.as_ref()?.signed_bytes)
    }
    pub(super) fn has_conflict(&self, key: EndpointId, sequence: i64) -> bool {
        self.peers.get(&key).is_some_and(|peer| {
            peer.conflict
                && peer
                    .winner
                    .as_ref()
                    .is_some_and(|winner| winner.sequence == sequence)
        })
    }
    pub(super) fn authorized_peer_count(&self) -> usize {
        self.peers.len()
    }
    pub(super) fn expire_cache(&mut self, key: EndpointId) {
        if let Some(peer) = self.peers.get_mut(&key) {
            peer.cache_deadline = None;
        }
    }
    pub(super) fn observe_clock(&mut self, now: ClockSample) -> Result<(), RecordError> {
        if self.clock_fault {
            return Err(RecordError::ClockFault);
        }
        if self.previous_clock.is_some_and(|prior| {
            now.wall_us < prior.wall_us || now.monotonic_us < prior.monotonic_us
        }) {
            self.clock_fault = true;
            for peer in self.peers.values_mut() {
                peer.cache_deadline = None;
            }
            return Err(RecordError::ClockFault);
        }
        self.previous_clock = Some(now);
        Ok(())
    }
}
pub(super) fn check_freshness(now_wall_us: i64, signed_at_us: i64) -> Result<u64, RecordError> {
    if signed_at_us < 0 {
        return Err(RecordError::TooOld);
    }
    let delta = now_wall_us
        .checked_sub(signed_at_us)
        .ok_or(RecordError::TooFarFuture)?;
    if delta > MAX_AGE_US {
        return Err(RecordError::TooOld);
    }
    if delta < -MAX_FUTURE_US {
        return Err(RecordError::TooFarFuture);
    }
    Ok(MAX_AGE_US.saturating_sub(delta.max(0)) as u64)
}
pub(super) fn sequence_from_unsigned(value: u64) -> Result<i64, RecordError> {
    i64::try_from(value).map_err(|_| RecordError::InvalidSequence)
}
pub(super) fn sequence_from_signed(value: i64) -> Result<i64, RecordError> {
    if value < 0 {
        Err(RecordError::InvalidSequence)
    } else {
        Ok(value)
    }
}
