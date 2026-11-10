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
    native_released, test_config, ygg_pair, ygg_released,
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
        // With a short valid policy, allow several capped maintenance cycles after
        // the ordinary native budget is spent. This is a liveness bound, not a
        // readiness oracle; exhaustion and continued Ygg routing are checked below.
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
        // Controlled native endpoint unavailability: stop the real listener
        // before the owner starts its unchanged finite burst.
        let native_summary = native_server.stop().await;
        assert_eq!(native_summary.accepted, 0);
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

        // The real native listener is unavailable from the first attempt.
        // The first usable route is authenticated Yggdrasil.
        assert_eq!(owner.follow().await, Ok(PathKind::Yggdrasil));
        assert_eq!(target.accepts.load(Ordering::SeqCst), 0);

        // Exhaustion remains observable, while a usable Ygg route lets the owner
        // perform capped native maintenance. The wait must stay pending on Ygg
        // through several failed probes; maintenance does not end the follow call.
        let waited = tokio::time::timeout(window, owner.follow()).await;
        assert!(
            waited.is_err(),
            "exhausted native budget must not end follow: {waited:?}"
        );
        // The unchanged ordinary burst and at least one maintenance probe ran.
        // Maintenance has no finite lifetime count; do not impose an upper cap.
        let spent = native_dials.load(Ordering::SeqCst);
        let cap = usize::try_from(config.max_attempts).expect("attempts");
        assert!(spent > cap, "ordinary budget plus maintenance dials {spent}");
        assert!(owner.native_exhausted(), "maintenance must not refill the burst budget");
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

        // Total outage: really stop the Ygg endpoint. One command already due
        // before the owner observes Ygg loss may start on that next follow poll;
        // after that, no further native maintenance can be scheduled without a
        // usable fallback. Preserve Unavailable (not Exhausted) as the outcome.
        let native_before_ygg_loss = native_dials.load(Ordering::SeqCst);
        let ygg_summary = ygg_server.stop().await;
        assert!(ygg_summary.accepted >= 1);
        let outcome = tokio::time::timeout(Duration::from_secs(30), owner.follow())
            .await
            .expect("total outage follow returns");
        assert_eq!(outcome, Err(StandbyError::Unavailable));
        assert_ne!(outcome, Err(StandbyError::Exhausted));
        assert_ne!(outcome, Err(StandbyError::Closed));
        let native_after_loss = native_dials.load(Ordering::SeqCst);
        assert!(
            native_after_loss <= native_before_ygg_loss + 1,
            "at most one already-due native probe may start while Ygg loss is observed: before={native_before_ygg_loss}, after={native_after_loss}"
        );
        // A further owner drive proves a finishing in-flight probe cannot schedule
        // another attempt after the fallback route has gone away.
        let second_outcome = tokio::time::timeout(Duration::from_secs(30), owner.follow())
            .await
            .expect("second total-outage follow returns");
        assert_eq!(second_outcome, Err(StandbyError::Unavailable));
        assert_eq!(
            native_dials.load(Ordering::SeqCst),
            native_after_loss,
            "no native maintenance starts after the Ygg route is unavailable"
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
