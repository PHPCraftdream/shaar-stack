// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::*;
use crate::native_discovery::runtime::clock::ClockSample;

fn sample(wall_us: i64, monotonic_us: u64) -> ClockSample {
    ClockSample {
        wall_us,
        monotonic_before_us: monotonic_us,
        monotonic_after_us: monotonic_us,
    }
}

#[test]
fn publication_status_uses_signed_freshness_horizon() {
    use super::PublicationStatus;
    use std::time::Duration;

    let signed_at = tokio::time::Instant::now();
    let acknowledged_at = signed_at + Duration::from_secs(5);
    let published = PublicationStatus::published(7, signed_at);
    assert!(matches!(
        published.current(signed_at + Duration::from_secs(299)),
        PublicationStatus::Published { generation: 7, .. }
    ));
    assert_eq!(PublicationStatus::publication_ttl_seconds(), 300);
    assert_eq!(
        published.current(signed_at + Duration::from_secs(300)),
        PublicationStatus::Unavailable { generation: 7 }
    );
    assert_eq!(
        published.current(acknowledged_at + Duration::from_secs(295)),
        PublicationStatus::Unavailable { generation: 7 },
        "a five-second PUT delay does not start another 300-second freshness window"
    );
}

#[test]
fn rejects_empty_and_invalid_snapshots_after_revoking_generation() {
    let identity = test_identity();
    let mut state = PublisherState::new(test_key(&identity));
    let address = test_address();
    let (old_generation, _) = state
        .replace(&identity, std::slice::from_ref(&address), sample(1_000, 0))
        .expect("valid initial snapshot");
    assert!(matches!(
        state.replace(&identity, &[], sample(1_001, 1)),
        Ok((_, None))
    ));
    assert!(!state.generation_is_active(old_generation));
    let (new_generation, _) = state
        .replace(&identity, &[address], sample(1_002, 2))
        .expect("valid replacement");
    let invalid = iroh_base::TransportAddr::Ip("127.0.0.1:0".parse().expect("zero port"));
    assert!(
        state
            .replace(&identity, &[invalid], sample(1_003, 3))
            .is_err()
    );
    assert!(!state.generation_is_active(new_generation));
}

#[test]
fn signed_packet_is_checked_by_upstream_decoder() {
    let identity = test_identity();
    let mut state = PublisherState::new(test_key(&identity));
    let (_, packet) = state
        .replace(
            &identity,
            &[test_address()],
            sample(1_700_000_000_000_000, 0),
        )
        .expect("publish checked packet");
    let signed = iroh_dns::pkarr::SignedPacket::from_bytes(&packet.expect("packet bytes").bytes)
        .expect("verify signature");
    let endpoint = iroh_dns::endpoint_info::EndpointInfo::from_pkarr_signed_packet(&signed)
        .expect("decode endpoint info");
    assert_eq!(endpoint.endpoint_id, test_key(&identity));
    assert_eq!(endpoint.ip_addrs().count(), 1);
}

#[test]
fn refresh_advances_timestamp_without_changing_generation() {
    let identity = test_identity();
    let mut state = PublisherState::new(test_key(&identity));
    let (generation, initial) = state
        .replace(
            &identity,
            &[test_address()],
            sample(1_700_000_000_000_000, 0),
        )
        .expect("initial publication");
    let initial_timestamp = initial.expect("signed packet").timestamp_us;
    let (refresh_generation, refreshed) = state
        .refresh(&identity, sample(1_700_000_000_000_000, 0))
        .expect("same-wall-clock refresh");
    assert_eq!(refresh_generation, generation);
    assert!(refreshed.expect("refreshed packet").timestamp_us > initial_timestamp);
    assert!(state.generation_is_active(generation));
}

#[test]
fn wall_rollback_is_terminal_and_preserves_watermark() {
    let identity = test_identity();
    let mut state = PublisherState::new(test_key(&identity));
    let (_, initial) = state
        .replace(
            &identity,
            &[test_address()],
            sample(1_700_000_000_000_100, 0),
        )
        .expect("initial publication");
    let watermark = initial.expect("signed packet").timestamp_us;
    assert_eq!(
        state.refresh(&identity, sample(1_700_000_000_000_099, 0)),
        Err(PublishError::ClockFault)
    );
    assert_eq!(state.last_timestamp_us, Some(watermark));
    assert_eq!(
        state.refresh(&identity, sample(1_700_000_000_000_101, 1)),
        Err(PublishError::ClockFault)
    );
    assert!(!state.has_active());
}

#[test]
fn monotonic_rollback_is_terminal_even_when_wall_advances() {
    let identity = test_identity();
    let mut state = PublisherState::new(test_key(&identity));
    state
        .replace(
            &identity,
            &[test_address()],
            sample(1_700_000_000_000_100, 10),
        )
        .expect("initial publication");
    assert_eq!(
        state.refresh(&identity, sample(1_700_000_000_000_101, 9)),
        Err(PublishError::ClockFault)
    );
}

#[test]
fn wall_advancing_half_as_fast_as_monotonic_is_terminal() {
    let identity = test_identity();
    let mut state = PublisherState::new(test_key(&identity));
    state
        .replace(
            &identity,
            &[test_address()],
            sample(1_700_000_000_000_100, 10),
        )
        .expect("initial publication");
    assert_eq!(
        state.refresh(&identity, sample(1_700_000_000_000_105, 20)),
        Err(PublishError::ClockFault)
    );
}

#[test]
fn bracketed_clock_detects_only_proven_wall_deficit() {
    let identity = test_identity();
    let mut state = PublisherState::new(test_key(&identity));
    state
        .replace(
            &identity,
            &[test_address()],
            ClockSample {
                wall_us: 1_700_000_000_000_000,
                monotonic_before_us: 10,
                monotonic_after_us: 12,
            },
        )
        .expect("initial sample");
    assert!(
        state
            .refresh(
                &identity,
                ClockSample {
                    wall_us: 1_700_000_000_000_005,
                    monotonic_before_us: 15,
                    monotonic_after_us: 18,
                },
            )
            .is_ok()
    );
}

#[test]
fn caught_up_wall_keeps_fault_terminal_and_timestamp_watermark() {
    let identity = test_identity();
    let mut state = PublisherState::new(test_key(&identity));
    let (_, packet) = state
        .replace(
            &identity,
            &[test_address()],
            sample(1_700_000_000_000_100, 10),
        )
        .expect("initial publication");
    let watermark = packet.expect("packet").timestamp_us;
    assert_eq!(
        state.refresh(&identity, sample(1_700_000_000_000_105, 20)),
        Err(PublishError::ClockFault)
    );
    assert_eq!(state.last_timestamp_us, Some(watermark));
    assert_eq!(
        state.refresh(&identity, sample(1_700_000_000_000_200, 21)),
        Err(PublishError::ClockFault)
    );
}

#[test]
fn ordinary_paired_progress_and_timestamp_future_boundaries() {
    let identity = test_identity();
    let mut state = PublisherState::new(test_key(&identity));
    let wall = 1_700_000_000_000_000_i64;
    state
        .replace(&identity, &[test_address()], sample(wall, 0))
        .expect("initial publication");
    assert!(state.refresh(&identity, sample(wall + 100, 100)).is_ok());
    let ceiling = wall + 30_000_000;
    state.last_timestamp_us = Some(ceiling - 1);
    assert_eq!(
        state.next_timestamp(wall),
        Ok(u64::try_from(ceiling).expect("positive timestamp"))
    );
    state.last_timestamp_us = Some(ceiling);
    assert_eq!(
        state.next_timestamp(wall),
        Err(PublishError::TimestampFuture)
    );
    state.last_timestamp_us = Some(i64::MAX);
    assert_eq!(
        state.next_timestamp(wall),
        Err(PublishError::TimestampOverflow)
    );
}

#[test]
fn generation_exhaustion_fails_closed_without_wrapping() {
    let identity = test_identity();
    let mut state = PublisherState::new(test_key(&identity));
    state.generation = u64::MAX;
    assert_eq!(state.revoke(), Err(PublishError::GenerationOverflow));
    assert!(state.clock_fault);
    assert!(!state.has_active());
}

#[test]
fn negative_wall_time_is_rejected_without_unsigned_wrap() {
    let state = PublisherState::new(test_key(&test_identity()));
    assert_eq!(
        state.next_timestamp(-1),
        Err(PublishError::TimestampOverflow)
    );
}

#[test]
fn observed_windows_clock_pairs_allow_forward_progress_with_bounded_rate_difference() {
    let identity = test_identity();
    let observed = [
        (
            1_794_309_404_059_869,
            5_750,
            1_794_309_404_182_505,
            128_388,
            128_390,
        ),
        (
            1_794_309_404_426_831,
            28_125,
            1_794_309_406_370_152,
            1_971_513,
            1_971_519,
        ),
        (
            1_794_309_417_370_558,
            46_899,
            1_794_309_420_359_054,
            3_035_529,
            3_035_535,
        ),
        (
            1_794_309_417_262_329,
            988,
            1_794_309_477_310_157,
            60_050_768,
            60_050_776,
        ),
    ];
    for (wall, after, next_wall, next_before, next_after) in observed {
        let mut state = PublisherState::new(test_key(&identity));
        state
            .check_clock(sample(wall, after))
            .expect("reference sample");
        state
            .check_clock(ClockSample {
                wall_us: next_wall,
                monotonic_before_us: next_before,
                monotonic_after_us: next_after,
            })
            .expect("observed forward progress stays inside the approved rate bound");
        assert!(!state.clock_fault);
    }
}

#[test]
fn rate_deficit_below_at_and_above_500_ppm_has_exact_terminal_boundaries() {
    let identity = test_identity();
    let wall = 1_700_000_000_000_000_i64;
    for (deficit, allowed) in [(499, true), (500, true), (501, false)] {
        let mut state = PublisherState::new(test_key(&identity));
        let (_, packet) = state
            .replace(&identity, &[test_address()], sample(wall, 0))
            .expect("initial publication");
        let watermark = packet.expect("signed packet").timestamp_us;
        let result = state.refresh(&identity, sample(wall + 1_000_000 - deficit, 1_000_000));
        if allowed {
            assert!(result.is_ok(), "allowed deficit {deficit}: {result:?}");
            assert!(state.has_active());
        } else {
            assert_eq!(result, Err(PublishError::ClockFault));
            assert!(!state.has_active());
            assert_eq!(state.last_timestamp_us, Some(watermark));
            assert_eq!(
                state.refresh(&identity, sample(wall + 2_000_000, 2_000_000)),
                Err(PublishError::ClockFault),
                "catch-up cannot clear a terminal excessive deficit"
            );
        }
    }
}

#[test]
fn fractional_rate_allowance_is_not_rounded_up_to_hide_a_deficit() {
    let identity = test_identity();
    let mut state = PublisherState::new(test_key(&identity));
    state
        .check_clock(sample(10_000, 0))
        .expect("initial sample");
    // One microsecond over 1,999 us exceeds 500 ppm; over 2,000 us it is exact.
    assert_eq!(
        state.check_clock(sample(11_998, 1_999)),
        Err(PublishError::ClockFault)
    );
    let mut exact = PublisherState::new(test_key(&identity));
    exact
        .check_clock(sample(10_000, 0))
        .expect("initial sample");
    assert_eq!(exact.check_clock(sample(11_999, 2_000)), Ok(()));
}

#[test]
fn overlapping_adjacent_brackets_cannot_hide_a_cumulative_wall_stall() {
    let identity = test_identity();
    let mut state = PublisherState::new(test_key(&identity));
    state
        .check_clock(ClockSample {
            wall_us: 1_000,
            monotonic_before_us: 0,
            monotonic_after_us: 2,
        })
        .expect("initial bracket");
    for before in [1, 2] {
        state
            .check_clock(ClockSample {
                wall_us: 1_000,
                monotonic_before_us: before,
                monotonic_after_us: before + 2,
            })
            .expect("adjacent uncertainty still overlaps the original sample");
    }
    assert_eq!(
        state.check_clock(ClockSample {
            wall_us: 1_000,
            monotonic_before_us: 3,
            monotonic_after_us: 5,
        }),
        Err(PublishError::ClockFault)
    );
    assert!(state.clock_fault);
}

#[test]
fn a_forward_wall_jump_does_not_grant_credit_for_a_later_stall() {
    let identity = test_identity();
    let mut state = PublisherState::new(test_key(&identity));
    state.check_clock(sample(1_000, 0)).expect("initial sample");
    state
        .check_clock(sample(1_001_000, 1))
        .expect("forward jump");
    assert_eq!(
        state.check_clock(sample(1_001_000, 2_001)),
        Err(PublishError::ClockFault),
        "adjacent comparison rejects a stall even when the lifetime anchor has forward credit"
    );
}

#[test]
fn invalid_brackets_and_observed_rollback_remain_strict_inside_rate_allowance() {
    let identity = test_identity();
    let mut rollback = PublisherState::new(test_key(&identity));
    rollback
        .check_clock(sample(10_000, 0))
        .expect("initial sample");
    assert_eq!(
        rollback.check_clock(sample(9_999, 1)),
        Err(PublishError::ClockFault)
    );
    let mut invalid = PublisherState::new(test_key(&identity));
    invalid
        .check_clock(sample(10_000, 0))
        .expect("initial sample");
    assert_eq!(
        invalid.check_clock(ClockSample {
            wall_us: 10_001,
            monotonic_before_us: 2,
            monotonic_after_us: 1,
        }),
        Err(PublishError::ClockFault)
    );
}

#[test]
fn clock_rate_comparison_handles_full_clock_delta_ranges_without_overflow() {
    assert!(!super::exceeds_clock_rate_deficit(
        i128::from(u64::MAX),
        u64::MAX
    ));
    assert!(super::exceeds_clock_rate_deficit(0, u64::MAX));
    let identity = test_identity();
    let mut state = PublisherState::new(test_key(&identity));
    state
        .check_clock(sample(i64::MIN, 0))
        .expect("initial comparison sample");
    assert_eq!(state.check_clock(sample(i64::MAX, u64::MAX)), Ok(()));
}

fn test_identity() -> crate::identity::Identity {
    crate::identity::Identity::from_seed([0x36; 32])
}

fn test_key(identity: &crate::identity::Identity) -> iroh_base::EndpointId {
    iroh_base::EndpointId::from_bytes(&identity.public_key_bytes()).expect("public key")
}

fn test_address() -> iroh_base::TransportAddr {
    iroh_base::TransportAddr::Ip("127.0.0.1:9000".parse().expect("loopback address"))
}
