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
        .replace(&identity, &[address.clone()], sample(1_000, 0))
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
fn wall_advancing_less_than_monotonic_is_terminal() {
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

fn test_identity() -> crate::identity::Identity {
    crate::identity::Identity::from_seed([0x36; 32])
}

fn test_key(identity: &crate::identity::Identity) -> iroh_base::EndpointId {
    iroh_base::EndpointId::from_bytes(&identity.public_key_bytes()).expect("public key")
}

fn test_address() -> iroh_base::TransportAddr {
    iroh_base::TransportAddr::Ip("127.0.0.1:9000".parse().expect("loopback address"))
}
