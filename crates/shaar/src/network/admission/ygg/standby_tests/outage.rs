// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
//! Native outage, failover and recovery scenarios over the standby fixture.
//!
//! The outage is "controlled native endpoint unavailability": the real native
//! server endpoint is stopped. No public-network or packet-filter blockade is
//! claimed. Zero libp2p APP traffic holds by construction: the fixture has no
//! signaling carrier at all.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::super::YggEndpoint;
use super::super::fallback::YggFallback;
use super::super::tests::{Frames, identity, key};
use super::{
    NativeDial, NativeServer, Target, YggServer, assert_same_identity, counted, forward_exact,
    native_only, native_released, test_config, ygg_pair, ygg_released,
};
use crate::network::{Allowlist, Endpoint, Limits};
use crate::path::{Mode, PathKind, PolicyConfig, Route, StandbyError, StandbyOwner};

const SESSIONS: usize = 4;

#[tokio::test(flavor = "multi_thread")]
async fn exhausted_native_budget_keeps_ygg_usable_then_total_outage_is_unavailable() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let config = PolicyConfig {
            max_attempts: 2,
            attempt_timeout: 1500,
            ..test_config()
        };
        config.validate().expect("outage policy config is valid");
        // Long enough to spend the whole native budget with slack.
        let window = Duration::from_millis(6 * (config.attempt_timeout + config.backoff_cap));

        let (server_seed, client_seed) = (0xC3, 0xC4);
        let (server_id, client_id) = (identity(server_seed), identity(client_seed));
        let target = Target::start().await;
        let (native_server, native_addr, _native_events) = NativeServer::start(
            &server_id,
            "127.0.0.1:0".parse().expect("bind address"),
            &[key(client_seed)],
            target.addr,
        )
        .await;
        let (server_bridge, client_bridge, port) = ygg_pair(server_seed, client_seed).await;
        let (server_endpoint, server_pump) = YggEndpoint::bind(
            &server_id,
            &server_bridge,
            Allowlist::new(&[key(client_seed)]).expect("allowlist"),
            Limits::new(SESSIONS).expect("limits"),
        )
        .await
        .expect("ygg server endpoint binds");
        let (ygg_server, _ygg_events) = YggServer::start(server_endpoint, server_pump, target.addr);

        let native_endpoint = Endpoint::bind(
            &client_id,
            "127.0.0.1:0".parse().expect("bind address"),
            Allowlist::new(&[key(server_seed)]).expect("allowlist"),
            Limits::new(SESSIONS).expect("limits"),
        )
        .await
        .expect("native client binds");
        let client_native_addr = native_endpoint.local_addr();
        let native_id = native_endpoint.id();
        let (client_endpoint, client_pump) = YggEndpoint::bind(
            &client_id,
            &client_bridge,
            Allowlist::new(&[key(server_seed)]).expect("allowlist"),
            Limits::new(SESSIONS).expect("limits"),
        )
        .await
        .expect("ygg client endpoint binds");
        let fallback = YggFallback::new(client_endpoint, client_pump, key(server_seed))
            .expect("server is allowlisted");
        let native_dials = Arc::new(AtomicUsize::new(0));
        let ygg_dials = Arc::new(AtomicUsize::new(0));
        let (fallback, probe) = counted(fallback, key(server_seed), Arc::clone(&ygg_dials));
        assert_same_identity(&client_id, &native_id, &probe.endpoint_id);
        let dialer = NativeDial::new(
            native_endpoint,
            key(server_seed),
            native_addr,
            Arc::clone(&native_dials),
            Arc::new(Mutex::new(Vec::new())),
        );
        let mut owner = StandbyOwner::new(dialer, fallback, Mode::Standby, config).expect("owner");

        // Healthy native route first: one exact forward reaches the target.
        assert_eq!(owner.follow().await, Ok(PathKind::Native));
        let Some(Route::Native(session)) = owner.route() else {
            panic!("native route expected");
        };
        forward_exact(&session, b"native before outage").await;
        native_only(&session);
        assert_eq!(target.accepts.load(Ordering::SeqCst), 1);
        target.wait_closed(1).await;
        drop(session);

        // Controlled native endpoint unavailability.
        let native_summary = native_server.stop().await;
        assert_eq!(native_summary.accepted, 1);
        assert_eq!(owner.follow().await, Ok(PathKind::Yggdrasil));

        // The policy emits NativeExhausted once per down episode and does not retry
        // native until native-up, so with Ygg usable this call neither errors nor
        // changes route: it must stay pending for the whole window.
        let waited = tokio::time::timeout(window, owner.follow()).await;
        assert!(
            waited.is_err(),
            "exhausted native budget must not end follow: {waited:?}"
        );
        assert!(owner.native_exhausted());
        // Policy bound: exhaustion needs `max_attempts` attempts since the last
        // budget refill, which may or may not have happened while native was held,
        // so the total is the cap or the cap plus the initial dial. Only these two
        // policy outcomes are accepted; fewer or more means a broken budget.
        let spent = native_dials.load(Ordering::SeqCst);
        let cap = usize::try_from(config.max_attempts).expect("attempts");
        assert!((cap..=cap + 1).contains(&spent), "native dials {spent}");
        assert_eq!(owner.active(), Some(PathKind::Yggdrasil));

        let Some(Route::Yggdrasil(session)) = owner.route() else {
            panic!("yggdrasil route expected");
        };
        let mut frames = Frames::new(&session, probe.peer_address.clone());
        let before = target.accepts.load(Ordering::SeqCst);
        forward_exact(&session, b"ygg after native budget exhausted").await;
        frames.checkpoint(&session);
        assert_eq!(target.accepts.load(Ordering::SeqCst), before + 1);
        target.wait_closed(before + 1).await;
        drop(session);

        // Total outage: the Ygg endpoint is really stopped too.
        let ygg_summary = ygg_server.stop().await;
        assert!(ygg_summary.accepted >= 1);
        let outcome = tokio::time::timeout(Duration::from_secs(30), owner.follow())
            .await
            .expect("total outage follow returns");
        assert_eq!(outcome, Err(StandbyError::Unavailable));
        assert_ne!(outcome, Err(StandbyError::Exhausted));
        assert_ne!(outcome, Err(StandbyError::Closed));
        assert_eq!(
            native_dials.load(Ordering::SeqCst),
            spent,
            "native is not retried while exhausted"
        );
        assert!(ygg_dials.load(Ordering::SeqCst) >= 2);

        owner.close().await.expect("owner closes");
        owner.close().await.expect("second close is idempotent");
        assert_eq!(probe.slots.available_permits(), SESSIONS);
        let (tx, rx, closed) = frames.finish().await;
        assert!(
            tx && rx && closed,
            "ygg path frames tx={tx} rx={rx} closed={closed}"
        );

        target.stop().await;
        client_bridge.close().await.expect("client bridge closes");
        server_bridge.close().await.expect("server bridge closes");
        ygg_released(server_seed, port).await;
        ygg_released(client_seed, port).await;
        native_released(&[native_addr, client_native_addr]).await;
    })
    .await
    .expect("outage deadline");
}
