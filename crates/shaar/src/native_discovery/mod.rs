// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

mod address;
mod codec;
mod policy;
#[cfg_attr(not(test), expect(dead_code, reason = "P09 runtime wiring is pending"))]
mod runtime;

use address::validate_addresses;
#[cfg(test)]
use address::{SnapshotError, validate_snapshot, validate_transport_addresses};
#[cfg(test)]
use codec::{DecodeError, decode_record};
#[cfg(test)]
use policy::{
    ClockSample, CompletedQuery, PolicyOwner, QuerySource, RecordError, RecordObservation,
};
#[cfg(test)]
use policy::{check_freshness, sequence_from_signed, sequence_from_unsigned};

#[cfg(test)]
mod tests;
