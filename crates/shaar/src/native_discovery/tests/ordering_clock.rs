// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::{PUB1, id, policy_fixture};
use crate::native_discovery::{ClockSample, CompletedQuery, QuerySource, RecordError};

fn sample(sequence: i64, bytes: &[u8]) -> super::RecordObservation {
    policy_fixture(sequence, sequence, bytes.to_vec(), vec![])
}

#[test]
fn greatest_sequence_wins_in_both_arrival_orders_and_lower_conflict_cannot_poison() {
    let base = 1_000_000_000_i64;
    let low = sample(base, &[1]);
    let low_conflict = sample(base, &[2]);
    let high = sample(base + 1, &[3]);
    let key = id(PUB1);
    let mut first = crate::native_discovery::PolicyOwner::new();
    let mut second = crate::native_discovery::PolicyOwner::new();
    first.admit_expected_key(key).expect("authorized");
    second.admit_expected_key(key).expect("authorized");
    let at = ClockSample {
        wall_us: base + 1,
        monotonic_us: 100,
    };
    first
        .complete_query(
            key,
            CompletedQuery::new(
                QuerySource::Network,
                at,
                vec![low.clone(), low_conflict.clone(), high.clone()],
            ),
        )
        .expect("higher sequence wins");
    second
        .complete_query(
            key,
            CompletedQuery::new(QuerySource::Network, at, vec![high, low_conflict, low]),
        )
        .expect("same winner under reverse arrival");
    for owner in [&first, &second] {
        assert_eq!(owner.winner_sequence(key), Some(base + 1));
        assert_eq!(owner.winner_bytes(key), Some(&[3][..]));
    }
}

#[test]
fn populated_winner_becomes_conflicted_on_later_equal_sequence() {
    let key = id(PUB1);
    let seq = 1_000_000_000_i64;
    let mut owner = crate::native_discovery::PolicyOwner::new();
    owner.admit_expected_key(key).expect("authorized");
    let address = std::net::SocketAddr::from(([192, 168, 1, 1], 1234));
    let original_observation = policy_fixture(seq, seq, vec![1], vec![address]);
    let conflict_observation = policy_fixture(seq, seq, vec![2], vec![address]);
    let record = original_observation.clone();
    let first = ClockSample {
        wall_us: seq,
        monotonic_us: 100,
    };
    owner
        .complete_query(
            key,
            CompletedQuery::new(QuerySource::Network, first, vec![record.clone()]),
        )
        .expect("initial winner");
    assert_eq!(owner.lookup_cache(key, first), Ok(()));
    assert_eq!(owner.query_required(key, first), Ok(false));
    assert_eq!(owner.winner_bytes(key), Some(&[1][..]));
    let conflict_at = ClockSample {
        wall_us: seq + 1,
        monotonic_us: 101,
    };
    assert_eq!(
        owner.complete_query(
            key,
            CompletedQuery::new(
                QuerySource::Network,
                conflict_at,
                vec![conflict_observation],
            )
        ),
        Err(RecordError::EqualSequenceConflict)
    );
    assert_eq!(owner.cache_deadline(key), None);
    assert_eq!(
        owner.lookup_cache(key, conflict_at),
        Err(RecordError::EqualSequenceConflict)
    );
    assert_eq!(owner.query_required(key, conflict_at), Ok(true));
    assert_eq!(owner.winner_sequence(key), Some(seq));
    assert_eq!(owner.winner_bytes(key), Some(&[1][..]));
    let duplicate_at = ClockSample {
        wall_us: seq + 2,
        monotonic_us: 102,
    };
    assert_eq!(
        owner.complete_query(
            key,
            CompletedQuery::new(QuerySource::Network, duplicate_at, vec![record.clone()])
        ),
        Err(RecordError::EqualSequenceConflict)
    );
    assert_eq!(
        owner.lookup_cache(key, duplicate_at),
        Err(RecordError::EqualSequenceConflict)
    );
    assert_eq!(owner.query_required(key, duplicate_at), Ok(true));
    for (source, at) in [
        (
            QuerySource::CacheOnly,
            ClockSample {
                wall_us: seq + 3,
                monotonic_us: 103,
            },
        ),
        (
            QuerySource::LocalActivePut,
            ClockSample {
                wall_us: seq + 4,
                monotonic_us: 104,
            },
        ),
    ] {
        assert_eq!(
            owner.complete_query(key, CompletedQuery::new(source, at, vec![record.clone()])),
            Err(RecordError::EqualSequenceConflict)
        );
        assert_eq!(
            owner.lookup_cache(key, at),
            Err(RecordError::EqualSequenceConflict)
        );
        assert_eq!(owner.query_required(key, at), Ok(true));
        assert_eq!(owner.winner_sequence(key), Some(seq));
        assert_eq!(owner.winner_bytes(key), Some(&[1][..]));
    }
    owner.expire_cache(key);
    let expired_at = ClockSample {
        wall_us: seq + 5,
        monotonic_us: 105,
    };
    assert_eq!(
        owner.complete_query(
            key,
            CompletedQuery::new(QuerySource::CacheOnly, expired_at, vec![record])
        ),
        Err(RecordError::EqualSequenceConflict)
    );
    assert_eq!(
        owner.lookup_cache(key, expired_at),
        Err(RecordError::EqualSequenceConflict)
    );
    assert_eq!(owner.query_required(key, expired_at), Ok(true));
    assert_eq!(owner.winner_bytes(key), Some(&[1][..]));
    let next = ClockSample {
        wall_us: seq + 10,
        monotonic_us: 110,
    };
    let recovered = policy_fixture(seq + 1, seq + 1, vec![3], vec![address]);
    owner
        .complete_query(
            key,
            CompletedQuery::new(QuerySource::Network, next, vec![recovered]),
        )
        .expect("greater sequence recovers");
    assert!(!owner.has_conflict(key, seq));
    assert_eq!(owner.winner_sequence(key), Some(seq + 1));
    assert_eq!(owner.winner_bytes(key), Some(&[3][..]));
    assert_eq!(owner.signed_timestamp(key), Some(seq + 1));
    assert_eq!(owner.cache_deadline(key), Some(30_000_110));
    assert_eq!(owner.lookup_cache(key, next), Ok(()));
    assert_eq!(owner.query_required(key, next), Ok(false));
}

#[test]
fn equal_current_max_conflict_survives_duplicates_and_expiry_until_greater_value() {
    let key = id(PUB1);
    let seq = 1_000_000_000_i64;
    let at = ClockSample {
        wall_us: seq,
        monotonic_us: 100,
    };
    let mut owner = crate::native_discovery::PolicyOwner::new();
    owner.admit_expected_key(key).expect("authorized");
    let conflict = || {
        CompletedQuery::new(
            QuerySource::Network,
            at,
            vec![sample(seq, &[1]), sample(seq, &[2])],
        )
    };
    assert_eq!(
        owner.complete_query(key, conflict()),
        Err(RecordError::EqualSequenceConflict)
    );
    assert!(owner.has_conflict(key, seq));
    assert_eq!(
        owner.complete_query(key, conflict()),
        Err(RecordError::EqualSequenceConflict)
    );
    owner.expire_cache(key);
    assert!(owner.has_conflict(key, seq));
    assert_eq!(
        owner.complete_query(
            key,
            CompletedQuery::new(
                QuerySource::Network,
                at,
                vec![sample(seq - 1, &[9]), sample(seq, &[1])]
            )
        ),
        Err(RecordError::EqualSequenceConflict)
    );
    owner
        .complete_query(
            key,
            CompletedQuery::new(QuerySource::Network, at, vec![sample(seq + 1, &[3])]),
        )
        .expect("greater sequence supersedes conflict");
    assert!(!owner.has_conflict(key, seq));
    assert_eq!(owner.winner_sequence(key), Some(seq + 1));
}

#[test]
fn equal_i64_max_conflicts_in_both_arrival_orders_and_sequence_bounds_are_checked() {
    let key = id(PUB1);
    let at = ClockSample {
        wall_us: i64::MAX,
        monotonic_us: 100,
    };
    let mut a = crate::native_discovery::PolicyOwner::new();
    let mut b = crate::native_discovery::PolicyOwner::new();
    a.admit_expected_key(key).expect("authorized");
    b.admit_expected_key(key).expect("authorized");
    let one = sample(i64::MAX, &[1]);
    let two = sample(i64::MAX, &[2]);
    assert_eq!(
        a.complete_query(
            key,
            CompletedQuery::new(QuerySource::Network, at, vec![one.clone(), two.clone()])
        ),
        Err(RecordError::EqualSequenceConflict)
    );
    assert_eq!(
        b.complete_query(
            key,
            CompletedQuery::new(QuerySource::Network, at, vec![two, one])
        ),
        Err(RecordError::EqualSequenceConflict)
    );
    for owner in [&a, &b] {
        assert!(owner.has_conflict(key, i64::MAX));
        assert_eq!(owner.winner_sequence(key), Some(i64::MAX));
    }
    assert_eq!(crate::native_discovery::sequence_from_unsigned(0), Ok(0));
    assert_eq!(
        crate::native_discovery::sequence_from_unsigned(i64::MAX as u64),
        Ok(i64::MAX)
    );
    assert!(crate::native_discovery::sequence_from_unsigned(i64::MAX as u64 + 1).is_err());
    assert!(crate::native_discovery::sequence_from_unsigned(u64::MAX).is_err());
    assert!(crate::native_discovery::sequence_from_signed(-1).is_err());
}

#[test]
fn sixty_four_watermarks_survive_cache_expiry_and_sixty_fifth_is_not_evicted_in() {
    let mut owner = crate::native_discovery::PolicyOwner::new();
    let at = ClockSample {
        wall_us: 1_000_000_000,
        monotonic_us: 100,
    };
    let mut keys = Vec::new();
    for n in 0..64_u8 {
        let key_bytes = [n; 32];
        let key = id(crate::identity::Identity::from_seed(key_bytes).public_key_bytes());
        keys.push((key, key_bytes));
        owner.admit_expected_key(key).expect("caller authorized");
        owner
            .complete_query(
                key,
                CompletedQuery::new(
                    QuerySource::Network,
                    at,
                    vec![sample(at.wall_us, &key_bytes)],
                ),
            )
            .expect("winner stored");
    }
    for (key, _) in &keys {
        owner.expire_cache(*key);
    }
    let extra = id(crate::identity::Identity::from_seed([64; 32]).public_key_bytes());
    assert_eq!(owner.admit_expected_key(extra), Err(RecordError::Capacity));
    assert_eq!(owner.authorized_peer_count(), 64);
    for (key, bytes) in keys {
        assert_eq!(owner.winner_bytes(key), Some(&bytes[..]));
        assert_eq!(
            owner.complete_query(
                key,
                CompletedQuery::new(
                    QuerySource::Network,
                    at,
                    vec![sample(at.wall_us - 1, &[99])],
                ),
            ),
            Err(RecordError::Replay)
        );
        assert_eq!(owner.winner_bytes(key), Some(&bytes[..]));
    }
}

#[test]
fn unauthorized_query_does_not_allocate_and_authorized_key_is_idempotent_at_capacity() {
    let mut owner = crate::native_discovery::PolicyOwner::new();
    let mut keys = Vec::new();
    for n in 0..64_u8 {
        let key = id(crate::identity::Identity::from_seed([n; 32]).public_key_bytes());
        keys.push(key);
        owner.admit_expected_key(key).expect("admitted");
    }
    let count = owner.authorized_peer_count();
    let unlisted = id(PUB1);
    assert_eq!(
        owner.complete_query(
            unlisted,
            CompletedQuery::new(
                QuerySource::Network,
                ClockSample {
                    wall_us: 1_000_000_000,
                    monotonic_us: 100
                },
                vec![sample(1_000_000_000, &[1])]
            )
        ),
        Err(RecordError::Unauthorized)
    );
    assert_eq!(owner.authorized_peer_count(), count);
    assert_eq!(owner.admit_expected_key(keys[0]), Ok(()));
    assert_eq!(owner.authorized_peer_count(), count);
}

#[test]
fn wall_rollback_after_populated_owner_is_terminal_but_new_owner_loses_watermark() {
    let key = id(PUB1);
    let mut owner = crate::native_discovery::PolicyOwner::new();
    owner.admit_expected_key(key).expect("authorized");
    let initial = ClockSample {
        wall_us: 500,
        monotonic_us: 1_000,
    };
    owner
        .complete_query(
            key,
            CompletedQuery::new(QuerySource::Network, initial, vec![sample(500, &[8])]),
        )
        .expect("state populated");
    assert_eq!(owner.winner_sequence(key), Some(500));
    let rollback = ClockSample {
        wall_us: 499,
        monotonic_us: 1_001,
    };
    assert_eq!(owner.observe_clock(rollback), Err(RecordError::ClockFault));
    assert!(owner.cache_deadline(key).is_none());
    let caught_up = ClockSample {
        wall_us: 501,
        monotonic_us: 1_002,
    };
    assert_eq!(owner.observe_clock(caught_up), Err(RecordError::ClockFault));
    assert_eq!(
        owner.complete_query(
            key,
            CompletedQuery::new(QuerySource::Network, caught_up, vec![sample(501, &[9])])
        ),
        Err(RecordError::ClockFault)
    );
    assert_eq!(owner.winner_sequence(key), Some(500));
    let mut restarted = crate::native_discovery::PolicyOwner::new();
    restarted
        .admit_expected_key(key)
        .expect("explicit new owner");
    restarted
        .complete_query(
            key,
            CompletedQuery::new(QuerySource::Network, caught_up, vec![sample(499, &[7])]),
        )
        .expect("process-local watermark is not durable");
    assert_eq!(restarted.winner_sequence(key), Some(499));
}

#[test]
fn monotonic_deadline_overflow_fails_closed() {
    let key = id(PUB1);
    let mut owner = crate::native_discovery::PolicyOwner::new();
    owner.admit_expected_key(key).expect("authorized");
    let at = ClockSample {
        wall_us: 1_000_000_000,
        monotonic_us: u64::MAX - 1,
    };
    assert_eq!(
        owner.complete_query(
            key,
            CompletedQuery::new(QuerySource::Network, at, vec![sample(at.wall_us, &[1])])
        ),
        Err(RecordError::DeadlineOverflow)
    );
}
