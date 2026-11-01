// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::{PUB1, id};
use crate::native_discovery::{ClockSample, CompletedQuery, QuerySource, RecordError};

fn observation(sequence: i64, bytes: &[u8]) -> super::RecordObservation {
    super::policy_fixture(sequence, sequence, bytes.to_vec(), vec![])
}

#[test]
fn freshness_boundaries_are_inclusive_checked_and_sequence_safe() {
    let now = 2_000_000_000_000_000_i64;
    assert_eq!(
        crate::native_discovery::check_freshness(now, now - 300_000_000),
        Ok(0)
    );
    assert_eq!(
        crate::native_discovery::check_freshness(now, now + 30_000_000),
        Ok(300_000_000)
    );
    assert!(crate::native_discovery::check_freshness(now, now - 300_000_001).is_err());
    assert!(crate::native_discovery::check_freshness(now, now + 30_000_001).is_err());
    assert!(crate::native_discovery::check_freshness(now, -1).is_err());
    assert!(crate::native_discovery::check_freshness(now, i64::MAX).is_err());
    assert!(crate::native_discovery::check_freshness(now, i64::MIN).is_err());
    assert_eq!(crate::native_discovery::sequence_from_unsigned(0), Ok(0));
    assert_eq!(
        crate::native_discovery::sequence_from_unsigned(i64::MAX as u64),
        Ok(i64::MAX)
    );
    assert!(crate::native_discovery::sequence_from_unsigned(i64::MAX as u64 + 1).is_err());
    assert!(crate::native_discovery::sequence_from_unsigned(u64::MAX).is_err());
    assert_eq!(crate::native_discovery::sequence_from_signed(0), Ok(0));
    assert!(crate::native_discovery::sequence_from_signed(-1).is_err());
}

#[test]
fn age_caps_deadline_to_completion_receipt_plus_remaining_signed_lifetime() {
    let mut owner = crate::native_discovery::PolicyOwner::new();
    let key = id(PUB1);
    owner
        .admit_expected_key(key)
        .expect("caller authorizes key");
    let completed = ClockSample {
        wall_us: 1_000_000_000,
        monotonic_us: 50_000_000,
    };
    owner
        .complete_query(
            key,
            CompletedQuery::new(
                QuerySource::Network,
                completed,
                vec![observation(completed.wall_us - 299_000_000, &[8])],
            ),
        )
        .expect("fresh");
    assert_eq!(owner.cache_deadline(key), Some(51_000_000));
}

#[test]
fn query_completion_deduplicates_within_batch_and_cache_hits_never_renew() {
    let mut owner = crate::native_discovery::PolicyOwner::new();
    let key = id(PUB1);
    owner.admit_expected_key(key).expect("authorized");
    let completed = ClockSample {
        wall_us: 1_000_000_000,
        monotonic_us: 7_000_000,
    };
    let record = observation(completed.wall_us - 10_000_000, &[3]);
    owner
        .complete_query(
            key,
            CompletedQuery::new(
                QuerySource::Network,
                completed,
                vec![record.clone(), record],
            ),
        )
        .expect("same in-query candidate is one result");
    let deadline = owner.cache_deadline(key).expect("installed");
    assert_eq!(deadline, 37_000_000);
    assert_eq!(
        owner.lookup_cache(
            key,
            ClockSample {
                wall_us: completed.wall_us,
                monotonic_us: deadline - 1
            }
        ),
        Ok(())
    );
    assert_eq!(owner.cache_deadline(key), Some(deadline));
    assert!(
        owner
            .lookup_cache(
                key,
                ClockSample {
                    wall_us: completed.wall_us,
                    monotonic_us: deadline
                }
            )
            .is_err()
    );
    assert_eq!(
        owner.query_required(
            key,
            ClockSample {
                wall_us: completed.wall_us,
                monotonic_us: deadline
            }
        ),
        Ok(true)
    );
    assert_eq!(owner.cache_deadline(key), Some(deadline));
}

#[test]
fn only_completed_network_query_renews_and_signed_time_is_immutable() {
    let mut owner = crate::native_discovery::PolicyOwner::new();
    let key = id(PUB1);
    owner.admit_expected_key(key).expect("authorized");
    let signed_at = 1_000_000_000_i64;
    let first = ClockSample {
        wall_us: signed_at + 1_000_000,
        monotonic_us: 10_000_000,
    };
    owner
        .complete_query(
            key,
            CompletedQuery::new(
                QuerySource::Network,
                first,
                vec![observation(signed_at, &[5])],
            ),
        )
        .expect("fresh");
    let first_deadline = owner.cache_deadline(key).expect("first network receipt");
    assert_eq!(first_deadline, 40_000_000);
    for (source, at) in [
        (
            QuerySource::CacheOnly,
            ClockSample {
                wall_us: signed_at + 2_000_000,
                monotonic_us: 11_000_000,
            },
        ),
        (
            QuerySource::LocalActivePut,
            ClockSample {
                wall_us: signed_at + 3_000_000,
                monotonic_us: 12_000_000,
            },
        ),
    ] {
        assert_eq!(
            owner.complete_query(
                key,
                CompletedQuery::new(source, at, vec![observation(signed_at, &[5])])
            ),
            Ok(())
        );
        assert_eq!(owner.cache_deadline(key), Some(first_deadline));
        assert_eq!(owner.lookup_cache(key, at), Ok(()));
        assert_eq!(owner.query_required(key, at), Ok(false));
        assert_eq!(owner.signed_timestamp(key), Some(signed_at));
        assert_eq!(owner.winner_bytes(key), Some(&[5][..]));
    }
    let at_first_expiry = ClockSample {
        wall_us: signed_at + 31_000_000,
        monotonic_us: first_deadline,
    };
    assert_eq!(
        owner.lookup_cache(key, at_first_expiry),
        Err(RecordError::CacheExpired)
    );
    assert_eq!(owner.query_required(key, at_first_expiry), Ok(true));
    for (source, at) in [
        (
            QuerySource::CacheOnly,
            ClockSample {
                wall_us: signed_at + 32_000_000,
                monotonic_us: first_deadline + 1_000_000,
            },
        ),
        (
            QuerySource::LocalActivePut,
            ClockSample {
                wall_us: signed_at + 33_000_000,
                monotonic_us: first_deadline + 2_000_000,
            },
        ),
    ] {
        assert_eq!(
            owner.complete_query(
                key,
                CompletedQuery::new(source, at, vec![observation(signed_at, &[5])])
            ),
            Err(RecordError::CacheExpired)
        );
        assert_eq!(owner.lookup_cache(key, at), Err(RecordError::CacheExpired));
        assert_eq!(owner.query_required(key, at), Ok(true));
        assert_eq!(owner.cache_deadline(key), Some(first_deadline));
    }
    assert_eq!(owner.signed_timestamp(key), Some(signed_at));
    assert_eq!(owner.winner_sequence(key), Some(signed_at));
    assert_eq!(owner.winner_bytes(key), Some(&[5][..]));
    let renewed_at = ClockSample {
        wall_us: signed_at + 34_000_000,
        monotonic_us: first_deadline + 3_000_000,
    };
    owner
        .complete_query(
            key,
            CompletedQuery::new(
                QuerySource::Network,
                renewed_at,
                vec![observation(signed_at, &[5])],
            ),
        )
        .expect("same signed value, completed network query");
    let second_deadline = renewed_at.monotonic_us + 30_000_000;
    assert_eq!(second_deadline, 73_000_000);
    assert_eq!(owner.cache_deadline(key), Some(73_000_000));
    assert_eq!(owner.signed_timestamp(key), Some(signed_at));
    assert_eq!(owner.winner_sequence(key), Some(signed_at));
    assert_eq!(owner.winner_bytes(key), Some(&[5][..]));
    assert_eq!(owner.lookup_cache(key, renewed_at), Ok(()));
    assert_eq!(owner.query_required(key, renewed_at), Ok(false));
    let near_age_limit = ClockSample {
        wall_us: signed_at + 299_000_000,
        monotonic_us: 308_000_000,
    };
    owner
        .complete_query(
            key,
            CompletedQuery::new(
                QuerySource::Network,
                near_age_limit,
                vec![observation(signed_at, &[5])],
            ),
        )
        .expect("still-fresh requery has capped remaining lifetime");
    let near_limit_deadline = near_age_limit.monotonic_us + 1_000_000;
    assert_eq!(near_limit_deadline, 309_000_000);
    assert_eq!(owner.cache_deadline(key), Some(309_000_000));
    assert_eq!(owner.signed_timestamp(key), Some(signed_at));
    assert_eq!(owner.winner_sequence(key), Some(signed_at));
    assert_eq!(owner.winner_bytes(key), Some(&[5][..]));
    assert_eq!(owner.lookup_cache(key, near_age_limit), Ok(()));
    assert_eq!(owner.query_required(key, near_age_limit), Ok(false));
    let final_expiry = ClockSample {
        wall_us: signed_at + 300_000_000,
        monotonic_us: near_limit_deadline,
    };
    assert_eq!(
        owner.lookup_cache(key, final_expiry),
        Err(RecordError::CacheExpired)
    );
    assert_eq!(owner.query_required(key, final_expiry), Ok(true));
    assert!(matches!(
        owner.complete_query(
            key,
            CompletedQuery::new(
                QuerySource::Network,
                ClockSample {
                    wall_us: signed_at + 300_000_001,
                    monotonic_us: near_limit_deadline + 1
                },
                vec![observation(signed_at, &[5])],
            ),
        ),
        Err(RecordError::TooOld)
    ));
}

#[test]
fn forward_wall_jump_rejects_cached_signed_age_before_receipt_deadline() {
    let mut owner = crate::native_discovery::PolicyOwner::new();
    let key = id(PUB1);
    owner.admit_expected_key(key).expect("authorized");
    let signed_at = 1_000_000_000_i64;
    let initial = ClockSample {
        wall_us: signed_at + 1_000_000,
        monotonic_us: 10_000_000,
    };
    owner
        .complete_query(
            key,
            CompletedQuery::new(
                QuerySource::Network,
                initial,
                vec![super::policy_fixture(
                    signed_at,
                    signed_at,
                    vec![0x5a, 0xa5],
                    vec![super::socket("127.0.0.1".parse().expect("loopback"), 443)],
                )],
            ),
        )
        .expect("fresh signed record");

    let deadline = 40_000_000;
    assert_eq!(owner.cache_deadline(key), Some(deadline));
    let fresh_lookup = ClockSample {
        wall_us: signed_at + 2_000_000,
        monotonic_us: 11_000_000,
    };
    assert_eq!(owner.lookup_cache(key, fresh_lookup), Ok(()));
    assert_eq!(owner.query_required(key, fresh_lookup), Ok(false));

    let aged_lookup = ClockSample {
        wall_us: signed_at + 300_000_001,
        monotonic_us: 12_000_000,
    };
    assert!(aged_lookup.monotonic_us < deadline);
    assert_eq!(
        owner.lookup_cache(key, aged_lookup),
        Err(RecordError::TooOld)
    );
    assert_eq!(owner.cache_deadline(key), Some(deadline));
    let repeated_lookup = ClockSample {
        monotonic_us: 13_000_000,
        ..aged_lookup
    };
    assert_eq!(
        owner.lookup_cache(key, repeated_lookup),
        Err(RecordError::TooOld)
    );
    assert_eq!(owner.query_required(key, repeated_lookup), Ok(true));
    assert_eq!(owner.cache_deadline(key), Some(deadline));
    assert_eq!(owner.signed_timestamp(key), Some(signed_at));
    assert_eq!(owner.winner_sequence(key), Some(signed_at));
    assert_eq!(owner.winner_bytes(key), Some(&[0x5a, 0xa5][..]));
}

#[test]
fn age_300_is_immediate_only_age_over_300_is_rejected_and_deadline_overflow_safe() {
    let mut owner = crate::native_discovery::PolicyOwner::new();
    let key = id(PUB1);
    owner.admit_expected_key(key).expect("authorized");
    let now = ClockSample {
        wall_us: 2_000_000_000,
        monotonic_us: 10_000_000,
    };
    owner
        .complete_query(
            key,
            CompletedQuery::new(
                QuerySource::Network,
                now,
                vec![observation(now.wall_us - 300_000_000, &[1])],
            ),
        )
        .expect("age 300 inclusive");
    assert_eq!(owner.cache_deadline(key), Some(now.monotonic_us));
    assert!(owner.lookup_cache(key, now).is_err());
    assert_eq!(owner.query_required(key, now), Ok(true));
    assert!(matches!(
        owner.complete_query(
            key,
            CompletedQuery::new(
                QuerySource::Network,
                now,
                vec![observation(now.wall_us - 300_000_001, &[2])]
            )
        ),
        Err(RecordError::TooOld)
    ));
    assert_eq!(owner.winner_sequence(key), Some(now.wall_us - 300_000_000));
    let overflow = ClockSample {
        wall_us: 2_000_000_000,
        monotonic_us: u64::MAX - 1,
    };
    assert_eq!(
        owner.complete_query(
            key,
            CompletedQuery::new(
                QuerySource::Network,
                overflow,
                vec![observation(overflow.wall_us, &[3])]
            )
        ),
        Err(RecordError::DeadlineOverflow)
    );
}
