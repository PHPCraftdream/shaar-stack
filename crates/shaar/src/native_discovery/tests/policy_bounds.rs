// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::{PUB1, PUB2, id, identity};
use crate::native_discovery::codec::decode_record;
use crate::native_discovery::policy::{
    ClockSample, CompletedQuery, PolicyOwner, QuerySource, RecordError, RecordObservation,
};
use std::net::SocketAddr;

#[test]
fn checked_age_boundary_hands_off_without_cache_lifetime_and_receipts_renew_remaining_freshness() {
    let key = id(PUB1);
    let signed = iroh_dns::pkarr::SignedPacket::from_txt_strings(
        &identity().transport_key(),
        "_iroh",
        ["addr=127.0.0.1:443"],
        300,
    )
    .expect("signed record");
    let decoded = decode_record(signed.as_bytes(), key).expect("checked decode");
    let signed_at_us = decoded.signed_at_us;
    let observation: RecordObservation = decoded.into();
    let address = "127.0.0.1:443".parse::<SocketAddr>().expect("address");
    let mut owner = PolicyOwner::new();
    owner.admit_expected_key(key).expect("authorized");
    let receipt = |wall_us, monotonic_us, record: RecordObservation| {
        CompletedQuery::new(
            QuerySource::Network,
            ClockSample {
                wall_us,
                monotonic_us,
            },
            vec![record],
        )
    };
    assert_eq!(
        owner.complete_query_addresses(key, receipt(signed_at_us, 1, observation.clone())),
        Ok(&[address][..])
    );
    assert_eq!(owner.cache_deadline(key), Some(30_000_001));
    assert_eq!(
        owner.complete_query_addresses(
            key,
            receipt(signed_at_us + 10_000_000, 2, observation.clone())
        ),
        Ok(&[address][..])
    );
    assert_eq!(owner.cache_deadline(key), Some(30_000_002));
    assert_eq!(
        owner.complete_query_addresses(
            key,
            receipt(signed_at_us + 299_000_000, 3, observation.clone())
        ),
        Ok(&[address][..])
    );
    assert_eq!(owner.cache_deadline(key), Some(1_000_003));
    let boundary = ClockSample {
        wall_us: signed_at_us + 300_000_000,
        monotonic_us: 10,
    };
    let mut initial_owner = PolicyOwner::new();
    initial_owner.admit_expected_key(key).expect("authorized");
    assert_eq!(initial_owner.winner_sequence(key), None);
    assert_eq!(
        initial_owner.complete_query_addresses(
            key,
            receipt(boundary.wall_us, boundary.monotonic_us, observation.clone())
        ),
        Ok(&[address][..])
    );
    assert_eq!(
        initial_owner.cache_deadline(key),
        Some(boundary.monotonic_us)
    );
    assert_eq!(
        initial_owner.addresses(key, boundary),
        Err(RecordError::CacheExpired)
    );
    assert_eq!(
        initial_owner.metadata(key, boundary),
        Err(RecordError::CacheExpired)
    );
    assert_eq!(initial_owner.query_required(key, boundary), Ok(true));
    assert_eq!(
        owner.complete_query_addresses(
            key,
            receipt(boundary.wall_us, boundary.monotonic_us, observation.clone())
        ),
        Ok(&[address][..])
    );
    assert_eq!(owner.cache_deadline(key), Some(10));
    assert_eq!(
        owner.addresses(key, boundary),
        Err(RecordError::CacheExpired)
    );
    assert_eq!(
        owner.metadata(key, boundary),
        Err(RecordError::CacheExpired)
    );
    assert_eq!(owner.query_required(key, boundary), Ok(true));
    let stale = ClockSample {
        wall_us: signed_at_us + 300_000_001,
        monotonic_us: 11,
    };
    assert_eq!(
        owner
            .complete_query_addresses(key, receipt(stale.wall_us, stale.monotonic_us, observation)),
        Err(RecordError::TooOld)
    );
    assert_eq!(owner.cache_deadline(key), Some(10));
}

#[test]
fn cache_only_and_local_active_put_cannot_mint_immediate_results_or_renew_deadline() {
    let key = id(PUB1);
    let at = ClockSample {
        wall_us: 1_000_000_000,
        monotonic_us: 10,
    };
    let address = "127.0.0.1:443".parse::<SocketAddr>().expect("address");
    let record = RecordObservation::fixture(at.wall_us, at.wall_us, vec![1], vec![address]);
    let mut owner = PolicyOwner::new();
    owner.admit_expected_key(key).expect("authorized");
    owner
        .complete_query_addresses(
            key,
            CompletedQuery::new(QuerySource::Network, at, vec![record.clone()]),
        )
        .expect("install winner");
    for source in [QuerySource::CacheOnly, QuerySource::LocalActivePut] {
        let now = ClockSample {
            monotonic_us: 11,
            ..at
        };
        assert_eq!(
            owner.complete_query_addresses(
                key,
                CompletedQuery::new(source, now, vec![record.clone()])
            ),
            Err(RecordError::CacheExpired)
        );
        assert_eq!(
            owner.complete_query(key, CompletedQuery::new(source, now, vec![record.clone()])),
            Ok(())
        );
        assert_eq!(owner.cache_deadline(key), Some(30_000_010));
    }
    assert_eq!(
        owner.addresses(
            key,
            ClockSample {
                monotonic_us: 11,
                ..at
            }
        ),
        Ok(&[address][..])
    );
}

#[test]
fn rejected_network_batches_never_fall_back_to_cached_winner() {
    let key = id(PUB1);
    let at = ClockSample {
        wall_us: 1_000_000_000,
        monotonic_us: 10,
    };
    let address = "127.0.0.1:443".parse::<SocketAddr>().expect("address");
    let observation = |sequence, bytes: u8| {
        RecordObservation::fixture(sequence, sequence, vec![bytes], vec![address])
    };
    let cases = [
        (Vec::new(), RecordError::CacheMiss, Some(30_000_010)),
        (
            vec![observation(999_999_999, 2)],
            RecordError::Replay,
            Some(30_000_010),
        ),
        (
            vec![observation(699_999_999, 2)],
            RecordError::TooOld,
            Some(30_000_010),
        ),
        (
            vec![observation(1_030_000_001, 2)],
            RecordError::TooFarFuture,
            Some(30_000_010),
        ),
        (
            vec![RecordObservation::fixture(
                at.wall_us,
                at.wall_us,
                Vec::new(),
                vec![address],
            )],
            RecordError::InvalidObservation,
            Some(30_000_010),
        ),
        (
            vec![observation(at.wall_us, 2)],
            RecordError::EqualSequenceConflict,
            None,
        ),
    ];
    for (records, expected, expected_deadline) in cases {
        let mut owner = PolicyOwner::new();
        owner.admit_expected_key(key).expect("authorized");
        owner
            .complete_query_addresses(
                key,
                CompletedQuery::new(QuerySource::Network, at, vec![observation(at.wall_us, 1)]),
            )
            .expect("install winner");
        assert_eq!(
            owner.complete_query_addresses(
                key,
                CompletedQuery::new(
                    QuerySource::Network,
                    ClockSample {
                        monotonic_us: 11,
                        ..at
                    },
                    records,
                ),
            ),
            Err(expected)
        );
        assert_eq!(owner.winner_sequence(key), Some(at.wall_us));
        assert_eq!(owner.cache_deadline(key), expected_deadline);
    }
}

#[test]
fn checked_wrong_key_receipt_cannot_fall_back_to_cached_winner() {
    let source_key = id(PUB1);
    let admitted_key = id(PUB2);
    let signed = iroh_dns::pkarr::SignedPacket::from_txt_strings(
        &identity().transport_key(),
        "_iroh",
        ["addr=127.0.0.1:443"],
        300,
    )
    .expect("signed record");
    let decoded = decode_record(signed.as_bytes(), source_key).expect("checked decode");
    let signed_at_us = decoded.signed_at_us;
    let observation: RecordObservation = decoded.into();
    let other = "127.0.0.1:444"
        .parse::<SocketAddr>()
        .expect("other address");
    let mut owner = PolicyOwner::new();
    owner.admit_expected_key(admitted_key).expect("authorized");
    owner
        .complete_query_addresses(
            admitted_key,
            CompletedQuery::new(
                QuerySource::Network,
                ClockSample {
                    wall_us: signed_at_us,
                    monotonic_us: 10,
                },
                vec![RecordObservation::fixture(
                    signed_at_us,
                    signed_at_us,
                    vec![1],
                    vec![other],
                )],
            ),
        )
        .expect("install cached winner");
    let winner = owner.winner_bytes(admitted_key).map(<[u8]>::to_vec);
    assert_eq!(
        owner.complete_query_addresses(
            admitted_key,
            CompletedQuery::new(
                QuerySource::Network,
                ClockSample {
                    wall_us: signed_at_us,
                    monotonic_us: 11
                },
                vec![observation]
            ),
        ),
        Err(RecordError::Unauthorized)
    );
    assert_eq!(owner.cache_deadline(admitted_key), Some(30_000_010));
    assert_eq!(owner.winner_bytes(admitted_key).map(<[u8]>::to_vec), winner);
}

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
    assert_eq!(owner.query_required(key, at), Err(RecordError::ClockFault));
    assert_eq!(
        owner.complete_query_addresses(
            key,
            CompletedQuery::new(QuerySource::Network, at, Vec::new()),
        ),
        Err(RecordError::ClockFault)
    );
    assert_eq!(
        owner.admit_expected_key(id(PUB2)),
        Err(RecordError::ClockFault)
    );
}

#[test]
fn local_active_put_rejects_expired_cache_and_unauthorized_key() {
    let key = id(PUB1);
    let at = ClockSample {
        wall_us: 1_000_000_000,
        monotonic_us: 10,
    };
    let record = RecordObservation::fixture(at.wall_us, at.wall_us, vec![1], Vec::new());
    let mut owner = PolicyOwner::new();
    owner.admit_expected_key(key).expect("authorized");
    owner
        .complete_query(
            key,
            CompletedQuery::new(QuerySource::Network, at, vec![record]),
        )
        .expect("install");
    let expired = ClockSample {
        monotonic_us: 30_000_010,
        ..at
    };
    for source in [QuerySource::CacheOnly, QuerySource::LocalActivePut] {
        assert_eq!(
            owner.complete_query(key, CompletedQuery::new(source, expired, Vec::new())),
            Err(RecordError::CacheExpired)
        );
    }
    assert_eq!(
        owner.complete_query_addresses(
            id(PUB2),
            CompletedQuery::new(QuerySource::LocalActivePut, expired, Vec::new())
        ),
        Err(RecordError::Unauthorized)
    );
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
