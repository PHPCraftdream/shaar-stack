// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::{PUB1, id};
use crate::native_discovery::policy::{
    ClockSample, CompletedQuery, PolicyOwner, QuerySource, RecordError, RecordObservation,
};
use std::net::SocketAddr;

#[test]
fn initial_equal_maximum_conflict_retains_watermark_and_terminalizes_sequence() {
    let key = id(PUB1);
    let at = ClockSample {
        wall_us: 1_000_000_000,
        monotonic_us: 10,
    };
    let first = RecordObservation::fixture(at.wall_us, at.wall_us, vec![1], Vec::new());
    let second = RecordObservation::fixture(at.wall_us, at.wall_us, vec![2], Vec::new());
    let mut owner = PolicyOwner::new();
    owner.admit_expected_key(key).expect("authorized");
    assert_eq!(
        owner.complete_query(
            key,
            CompletedQuery::new(QuerySource::Network, at, vec![first.clone(), second])
        ),
        Err(RecordError::EqualSequenceConflict)
    );
    assert_eq!(owner.winner_sequence(key), Some(at.wall_us));
    assert!(owner.has_conflict(key, at.wall_us));
    assert_eq!(
        owner.complete_query(
            key,
            CompletedQuery::new(QuerySource::Network, at, vec![first])
        ),
        Err(RecordError::EqualSequenceConflict)
    );
}

#[test]
fn query_required_detects_wall_rollback_and_faults_owner() {
    let key = id(PUB1);
    let at = ClockSample {
        wall_us: 1_000_000_000,
        monotonic_us: 10,
    };
    let record =
        RecordObservation::fixture(at.wall_us, at.wall_us, vec![1], Vec::<SocketAddr>::new());
    let mut owner = PolicyOwner::new();
    owner.admit_expected_key(key).expect("authorized");
    owner
        .complete_query(
            key,
            CompletedQuery::new(QuerySource::Network, at, vec![record]),
        )
        .expect("installed");
    assert_eq!(
        owner.query_required(
            key,
            ClockSample {
                wall_us: at.wall_us - 1,
                monotonic_us: 11
            }
        ),
        Err(RecordError::ClockFault)
    );
    assert_eq!(owner.cache_deadline(key), None);
}

#[test]
fn network_batch_count_and_bytes_are_bounded_before_admission() {
    let key = id(PUB1);
    let at = ClockSample {
        wall_us: 1_000_000_000,
        monotonic_us: 10,
    };
    let mut owner = PolicyOwner::new();
    owner.admit_expected_key(key).expect("authorized");
    let over_count = (0..33)
        .map(|n| RecordObservation::fixture(at.wall_us + n, at.wall_us + n, vec![1], Vec::new()))
        .collect();
    assert_eq!(
        owner.complete_query(
            key,
            CompletedQuery::new(QuerySource::Network, at, over_count)
        ),
        Err(RecordError::BatchTooLarge)
    );
    let over_bytes = vec![RecordObservation::fixture(
        at.wall_us,
        at.wall_us,
        vec![1; 65_537],
        Vec::new(),
    )];
    assert_eq!(
        owner.complete_query(
            key,
            CompletedQuery::new(QuerySource::Network, at, over_bytes)
        ),
        Err(RecordError::BatchTooLarge)
    );
    assert_eq!(owner.winner_sequence(key), None);
}
