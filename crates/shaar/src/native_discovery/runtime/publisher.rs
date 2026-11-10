// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::super::address::{SnapshotError, validate_transport_addresses};
use super::clock::ClockSample;
use crate::identity::Identity;
use iroh_base::{EndpointId, TransportAddr};
use iroh_dns::endpoint_info::{EndpointData, EndpointInfo};
use std::net::SocketAddr;
use std::time::Duration;

const TTL_SECONDS: u32 = 30;
const SIGNED_AGE_SECONDS: u64 = 300;
const PUBLICATION_TTL: Duration = Duration::from_secs(SIGNED_AGE_SECONDS);
const MAX_DNS_BYTES: usize = 1000;
const MAX_SIGNED_BYTES: usize = 1104;
const MAX_FUTURE_US: i64 = 30_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PublishError {
    Snapshot(SnapshotError),
    WrongIdentity,
    ClockFault,
    TimestampOverflow,
    TimestampFuture,
    Oversize,
    GenerationOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PublicationStatus {
    Pending {
        generation: u64,
    },
    Published {
        generation: u64,
        expires_at: tokio::time::Instant,
    },
    Unavailable {
        generation: u64,
    },
}

impl PublicationStatus {
    pub(crate) fn generation(self) -> u64 {
        match self {
            Self::Pending { generation }
            | Self::Unavailable { generation }
            | Self::Published { generation, .. } => generation,
        }
    }

    pub(crate) fn pending(generation: u64) -> Self {
        Self::Pending { generation }
    }

    pub(crate) fn published(generation: u64, signed_at: tokio::time::Instant) -> Self {
        Self::Published {
            generation,
            expires_at: signed_at + PUBLICATION_TTL,
        }
    }

    pub(crate) fn unavailable(generation: u64) -> Self {
        Self::Unavailable { generation }
    }

    pub(crate) fn publication_ttl_seconds() -> u64 {
        SIGNED_AGE_SECONDS
    }

    pub(crate) fn current(self, now: tokio::time::Instant) -> Self {
        match self {
            Self::Published {
                generation,
                expires_at,
            } if now >= expires_at => Self::Unavailable { generation },
            status => status,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SignedSnapshot {
    pub(super) timestamp_us: i64,
    pub(super) bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CleanupReceipt {
    pub(super) cleanup_count: u64,
    pub(super) refresh_count: u64,
    pub(super) active: bool,
}

#[derive(Debug)]
pub(super) struct PublisherState {
    key: EndpointId,
    last_timestamp_us: Option<i64>,
    last_wall_us: Option<i64>,
    last_monotonic_before_us: Option<u64>,
    last_monotonic_after_us: Option<u64>,
    clock_fault: bool,
    generation: u64,
    last_signed_at: tokio::time::Instant,
    active: Option<Vec<SocketAddr>>,
}

impl PublisherState {
    pub(super) fn new(key: EndpointId) -> Self {
        Self {
            key,
            last_timestamp_us: None,
            last_wall_us: None,
            last_monotonic_before_us: None,
            last_monotonic_after_us: None,
            clock_fault: false,
            generation: 0,
            last_signed_at: tokio::time::Instant::now(),
            active: None,
        }
    }

    pub(super) fn replace(
        &mut self,
        identity: &Identity,
        snapshot: &[TransportAddr],
        sample: ClockSample,
    ) -> Result<(u64, Option<SignedSnapshot>), PublishError> {
        self.revoke()?;
        self.check_clock(sample)?;
        if EndpointId::from_bytes(&identity.public_key_bytes()).ok() != Some(self.key) {
            return Err(PublishError::WrongIdentity);
        }
        let addresses = validate_transport_addresses(snapshot).map_err(PublishError::Snapshot)?;
        if addresses.is_empty() {
            return Ok((self.generation, None));
        }
        let packet = self.make_packet(identity, &addresses, sample.wall_us)?;
        self.active = Some(addresses);
        Ok((self.generation, Some(packet)))
    }

    pub(super) fn refresh(
        &mut self,
        identity: &Identity,
        sample: ClockSample,
    ) -> Result<(u64, Option<SignedSnapshot>), PublishError> {
        if self.clock_fault {
            return Err(PublishError::ClockFault);
        }
        let active = self.active.clone().ok_or(PublishError::ClockFault)?;
        self.check_clock(sample)?;
        let packet = self.make_packet(identity, &active, sample.wall_us)?;
        Ok((self.generation, Some(packet)))
    }

    fn make_packet(
        &mut self,
        identity: &Identity,
        addresses: &[SocketAddr],
        wall_us: i64,
    ) -> Result<SignedSnapshot, PublishError> {
        if self.clock_fault {
            return Err(PublishError::ClockFault);
        }
        let timestamp = self.next_timestamp(wall_us)?;
        let info = EndpointInfo::from_parts(
            self.key,
            EndpointData::new(addresses.iter().copied().map(TransportAddr::Ip).collect()),
        );
        let signed_at = tokio::time::Instant::now();
        let packet = info
            .to_pkarr_signed_packet_at(&identity.transport_key(), TTL_SECONDS, timestamp)
            .map_err(|_| PublishError::Oversize)?;
        let bytes = packet.as_bytes().to_vec();
        let dns_bytes = bytes.len().checked_sub(104).ok_or(PublishError::Oversize)?;
        if dns_bytes > MAX_DNS_BYTES || bytes.len() > MAX_SIGNED_BYTES {
            return Err(PublishError::Oversize);
        }
        let timestamp_us = i64::try_from(timestamp).map_err(|_| PublishError::TimestampOverflow)?;
        self.last_timestamp_us = Some(timestamp_us);
        self.last_signed_at = signed_at;
        Ok(SignedSnapshot {
            timestamp_us,
            bytes,
        })
    }

    pub(super) fn revoke(&mut self) -> Result<u64, PublishError> {
        self.generation = self.generation.checked_add(1).ok_or_else(|| {
            self.clock_fault = true;
            self.active = None;
            PublishError::GenerationOverflow
        })?;
        self.active = None;
        Ok(self.generation)
    }

    pub(super) fn generation(&self) -> u64 {
        self.generation
    }

    pub(super) fn signed_at(&self) -> tokio::time::Instant {
        self.last_signed_at
    }

    pub(super) fn has_active(&self) -> bool {
        self.active.is_some()
    }

    pub(super) fn generation_is_active(&self, generation: u64) -> bool {
        self.active.is_some() && self.generation == generation
    }

    pub(super) fn check_clock(&mut self, sample: ClockSample) -> Result<(), PublishError> {
        if self.clock_fault {
            return Err(PublishError::ClockFault);
        }
        if sample.monotonic_before_us > sample.monotonic_after_us
            || self.last_wall_us.is_some_and(|last| sample.wall_us < last)
            || self
                .last_monotonic_before_us
                .is_some_and(|last| sample.monotonic_after_us < last)
        {
            #[cfg(test)]
            eprintln!(
                "publisher clock rejection (invalid-or-backward): previous_wall_us={:?}, previous_monotonic_before_us={:?}, previous_monotonic_after_us={:?}, sample={sample:?}",
                self.last_wall_us, self.last_monotonic_before_us, self.last_monotonic_after_us,
            );
            self.clock_fault = true;
            self.active = None;
            return Err(PublishError::ClockFault);
        }
        if let (Some(last_wall), Some(last_monotonic_after)) =
            (self.last_wall_us, self.last_monotonic_after_us)
        {
            let wall_elapsed = i128::from(sample.wall_us) - i128::from(last_wall);
            let proven_monotonic_elapsed = sample
                .monotonic_before_us
                .saturating_sub(last_monotonic_after);
            if wall_elapsed < i128::from(proven_monotonic_elapsed) {
                #[cfg(test)]
                eprintln!(
                    "publisher clock rejection (elapsed-deficit): previous_wall_us={last_wall}, previous_monotonic_after_us={last_monotonic_after}, wall_elapsed_us={wall_elapsed}, minimum_monotonic_elapsed_us={proven_monotonic_elapsed}, sample={sample:?}",
                );
                self.clock_fault = true;
                self.active = None;
                return Err(PublishError::ClockFault);
            }
        }
        self.last_wall_us = Some(sample.wall_us);
        self.last_monotonic_before_us = Some(sample.monotonic_before_us);
        self.last_monotonic_after_us = Some(sample.monotonic_after_us);
        Ok(())
    }

    fn next_timestamp(&self, wall_us: i64) -> Result<u64, PublishError> {
        let wall = u64::try_from(wall_us).map_err(|_| PublishError::TimestampOverflow)?;
        let candidate = match self.last_timestamp_us {
            Some(last) => {
                let next = last.checked_add(1).ok_or(PublishError::TimestampOverflow)?;
                wall.max(u64::try_from(next).map_err(|_| PublishError::TimestampOverflow)?)
            }
            None => wall,
        };
        let ceiling = wall_us
            .checked_add(MAX_FUTURE_US)
            .ok_or(PublishError::TimestampOverflow)?;
        if i64::try_from(candidate).map_err(|_| PublishError::TimestampOverflow)? > ceiling {
            return Err(PublishError::TimestampFuture);
        }
        Ok(candidate)
    }
}

#[cfg(test)]
mod tests;
