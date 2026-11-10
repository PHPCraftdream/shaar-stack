//! Real startup distributions; no route-ready or echo-RTT timing shortcut.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use iroh_base::PublicKey;
use tokio::sync::oneshot;
use tokio::time::Instant;

use crate::config::{ClientConfig, ServerConfig};
use crate::identity::Identity;
use crate::native_discovery::runtime::owner::LoopbackPeer;
use crate::network::{Allowlist, Limits, RelayFixture};
use crate::path::PathKind;
use crate::startup::role::{RoleEvent, RoleOptions, serve_server_with_events};

use super::super::fixtures::{
    ROLE_BUDGET, admit_and_capture, arm_client_on_peer, bootstrap_v4, client_role_config,
    dead_relay_address, echo_target, forward_and_echo, identity, pin_role, pub_key_hex, role_logs,
    server_role_config, start_listener,
};
use super::helpers::{assert_client_binds_released, assert_key_released_once};

// Owned only by this one sequential campaign; no sibling uses these live keys.
const SERVICE: u8 = 0x6C;
const CLIENT: u8 = 0x6D;
const TRANSIT: u8 = 0x6E;
const SAMPLES: usize = 20;

/// Nearest rank ceil(0.95 * 20): the nineteenth ordered observation.
fn p95(samples: &[Duration; SAMPLES]) -> Duration {
    let mut ordered = *samples;
    ordered.sort_unstable();
    ordered[18]
}

#[test]
fn percentile_keeps_the_adverse_tail_and_exact_threshold() {
    let mut samples = [Duration::from_secs(3); SAMPLES];
    samples[0] = Duration::MAX;
    assert_eq!(p95(&samples), Duration::from_secs(3));
    samples[1] = Duration::from_secs(3) + Duration::from_nanos(1);
    assert!(p95(&samples) > Duration::from_secs(3));
    samples[1] = Duration::MAX;
    assert_eq!(p95(&samples), Duration::MAX);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn known_and_cold_startup_measure_first_target_bytes_without_ready_route_bias() {
    tokio::time::timeout(Duration::from_secs(600), async {
        let mut service_peer = LoopbackPeer::bind().await;
        let relay = RelayFixture::start().await;
        let relay_id = relay.address.peer_id().to_string();
        let (transit, transit_port) = start_listener(TRANSIT).await;
        let transit_uri = format!("tcp://127.0.0.1:{transit_port}");
        let (mut echo, echo_address) = echo_target().await;
        let service: &'static Identity = Box::leak(Box::new(identity(SERVICE)));
        let client_identity: &'static Identity = Box::leak(Box::new(identity(CLIENT)));
        let client_key = PublicKey::from_bytes(&client_identity.public_key_bytes())
            .expect("campaign client key");
        let server_config: &'static ServerConfig = Box::leak(Box::new(server_role_config(
            echo_address,
            bootstrap_v4(&service_peer),
            &relay_id,
            relay.address.socket_addr(),
            &transit_uri,
            "standby",
        )));
        let (server_log, _) = role_logs();
        let (server_stop, server_stop_rx) = oneshot::channel();
        let mut server = pin_role(serve_server_with_events(
            server_config,
            service,
            Allowlist::new(&[client_key]).expect("campaign allowlist"),
            Limits::new(4).expect("campaign limits"),
            RoleOptions::default(),
            async move { let _ = server_stop_rx.await; },
            server_log.clone(),
        ));
        let item = admit_and_capture(
            &mut service_peer, &mut server, &server_log, ROLE_BUDGET,
        ).await;
        let mut native = match server_log.find(&|event| matches!(event, RoleEvent::NativeBound(_))) {
            Some(RoleEvent::NativeBound(address)) => address,
            other => panic!("independent bound native socket is required: {other:?}"),
        };
        // The server's socket remains owned and unblocked throughout BOTH cohorts.
        // Eligibility is fixed here, never derived from the client's chosen lease.
        if native.ip().is_unspecified() {
            native.set_ip(if native.is_ipv4() {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            } else {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            });
        }
        let mut ordinal = 0;
        let mut direct = 0;
        let mut cohorts = [[Duration::MAX; SAMPLES]; 2];
        for (cohort, samples) in cohorts.iter_mut().enumerate() {
            for (index, sample) in samples.iter_mut().enumerate() {
                ordinal += 1;
                let mut peer = LoopbackPeer::bind().await;
                // Known-address optimization is separate from the key-only cold cohort.
                let hint = (cohort == 0).then_some(native);
                let config: &'static ClientConfig = Box::leak(Box::new(client_role_config(
                    &pub_key_hex(service), bootstrap_v4(&peer), &relay_id,
                    dead_relay_address(), &transit_uri, "standby", hint,
                )));
                assert_eq!(config.server_address().is_some(), cohort == 0);
                // Includes retained startup, initial PUT, listener, resolve and handshake.
                let started_at = Instant::now();
                let (stop, mut client, log, listener) = tokio::select! {
                    armed = arm_client_on_peer(
                        config, client_identity, &mut peer, RoleOptions::default(), ROLE_BUDGET,
                    ) => armed,
                    result = &mut server => panic!("campaign server ended during startup: {result:?}"),
                };
                if cohort == 1 {
                    let target = n0_mainline::MutableItem::target_from_key(item.key(), None);
                    let (source, transaction) = tokio::time::timeout(ROLE_BUDGET, async {
                        tokio::select! {
                            get = peer.capture_get(target) => get,
                            result = &mut client => panic!("cold client ended before GET: {result:?}"),
                            result = &mut server => panic!("server ended before cold GET: {result:?}"),
                        }
                    }).await.expect("cold service-key GET reaches the wire");
                    tokio::select! {
                        _ = peer.reply_get(source, &transaction, &item) => {},
                        result = &mut client => panic!("cold client ended during reply: {result:?}"),
                        result = &mut server => panic!("server ended during cold reply: {result:?}"),
                    }
                }
                let mut record = Box::pin(peer.serve_record(&item));
                let first = tokio::time::timeout(ROLE_BUDGET, async {
                    tokio::select! {
                        ((), first) = async {
                            tokio::join!(
                                forward_and_echo(listener, b"metrics", &mut server, &mut client, "startup sample"),
                                echo.first_byte(),
                            )
                        } => first,
                        _ = &mut record => panic!("record responder ended during measured transfer"),
                    }
                }).await.expect("every scheduled startup sample must forward; failures are not omitted");
                assert_eq!(first.connection, ordinal);
                assert_eq!(first.byte, b'm');
                let paths: Vec<_> = log.snapshot().into_iter().filter_map(|event| match event {
                    RoleEvent::ForwardStarted(path) => Some(path),
                    _ => None,
                }).collect();
                assert_eq!(paths.len(), 1, "exactly one actual worker lease per sample");
                let elapsed = first.at.checked_duration_since(started_at)
                    .expect("first byte follows startup on the same monotonic clock");
                if paths[0] == PathKind::Native {
                    direct += 1;
                    *sample = elapsed;
                }
                // Non-native samples remain in the percentile as MAX, never disappear.
                eprintln!("P10 startup cohort={cohort} sample={index} native_available=true path={:?} first_byte_us={} direct_latency={sample:?}", paths[0], elapsed.as_micros());
                let _ = stop.send(());
                tokio::time::timeout(ROLE_BUDGET, async {
                    tokio::select! {
                        result = &mut client => result.expect("sample client joins cleanly"),
                        result = &mut server => panic!("server ended during client close: {result:?}"),
                        _ = &mut record => panic!("record responder ended during client close"),
                    }
                }).await.expect("sample client close is bounded");
                drop(record);
                assert_client_binds_released(config, "measured client");
            }
        }
        eprintln!("P10 startup summary samples_each={SAMPLES} known_p95={:?} cold_p95={:?} direct={direct} eligible={ordinal}", p95(&cohorts[0]), p95(&cohorts[1]));
        // Close all owners before applying the distribution thresholds.
        let _ = server_stop.send(());
        tokio::time::timeout(ROLE_BUDGET, &mut server).await
            .expect("campaign server close is bounded").expect("server joins cleanly");
        echo.close().await;
        tokio::time::timeout(ROLE_BUDGET, transit.close()).await
            .expect("transit close is bounded").expect("transit joins cleanly");
        relay.close().await;
        assert_key_released_once(SERVICE, "campaign server").await;
        assert_key_released_once(CLIENT, "campaign client").await;
        assert_key_released_once(TRANSIT, "campaign transit").await;
        assert_eq!(ordinal, 2 * SAMPLES);
        assert!(p95(&cohorts[0]) <= Duration::from_secs(3), "known-address p95 exceeds 3 s");
        assert!(p95(&cohorts[1]) <= Duration::from_secs(10), "cold-DHT p95 exceeds 10 s");
        assert!(direct * 100 >= ordinal * 95, "startup-only direct share below 95%; long-outage campaign remains additional");
    }).await.expect("fixed-size sequential startup campaign stays bounded");
}
