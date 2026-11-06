// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
//! Denial and refusal scenarios over the standby fixture.
//!
//! Zero libp2p APP traffic holds by construction: the fixture has no signaling
//! carrier. Each phase owns a fresh `Target`, so its accept counter is the oracle
//! of which client reached the service.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use iroh_base::PublicKey;
use shaar_ygg::YggPump;
use tokio::time::timeout;

use super::super::YggEndpoint;
use super::super::tests::{Frames, identity, key};
use super::{
    NativeServer, Target, YggServer, forward_exact, native_released, tcp_pair, ygg_pair,
    ygg_released,
};
use crate::network::{Allowlist, Endpoint, ForwardError, Limits, NetworkError, Session};

const SESSIONS: usize = 4;
const SETTLE: Duration = Duration::from_secs(30);

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().expect("loopback address")
}

fn limits() -> Limits {
    Limits::new(SESSIONS).expect("limits")
}

/// A forbidden client either fails to connect or holds a session that the server
/// closes with ACCESS_DENIED; either way no payload can be forwarded.
/// cancel-safe: NO — the session is consumed.
async fn assert_denied(connected: Result<Session, NetworkError>) {
    let Ok(session) = connected else {
        return;
    };
    let reason = timeout(SETTLE, session.closed())
        .await
        .expect("denied session closes");
    assert!(matches!(reason, NetworkError::AccessDenied), "{reason:?}");
    let (app, bridge) = tcp_pair().await;
    let forwarded = session.forward(bridge).await;
    assert!(
        matches!(forwarded, Err(ForwardError::AccessDenied)),
        "{forwarded:?}"
    );
    drop(app);
    session.close();
}

/// Runs `work` while the client pump writes; a stopped writer fails the test.
/// cancel-safe: NO — it forwards the cancel-safety of `work`.
async fn driven<T>(pump: &mut YggPump, work: impl Future<Output = T>) -> T {
    tokio::select! {
        out = work => out,
        stopped = pump.run() => panic!("ygg client writer stopped: {stopped:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn forbidden_clients_never_receive_a_serving_session_and_reach_no_target() {
    tokio::time::timeout(Duration::from_secs(120), async {
        native_half().await;
        ygg_forbidden_half().await;
        ygg_allowed_half().await;
    })
    .await
    .expect("denial deadline");
}

/// Forbidden C7 is refused by a native server that then serves allowed C6 exactly.
async fn native_half() {
    let (server_id, allowed_id, forbidden_id) = (identity(0xC5), identity(0xC6), identity(0xC7));
    let target = Target::start().await;
    let (server, server_addr, _events) =
        NativeServer::start(&server_id, loopback(), &[key(0xC6)], target.addr).await;

    let forbidden = Endpoint::bind(&forbidden_id, loopback(), Allowlist::default(), limits())
        .await
        .expect("forbidden client binds");
    let forbidden_addr = forbidden.local_addr();
    let connected = timeout(SETTLE, forbidden.connect(key(0xC5), server_addr))
        .await
        .expect("forbidden connect settles");
    assert_denied(connected).await;
    assert_eq!(target.accepts.load(Ordering::SeqCst), 0);
    forbidden.close().await;

    // Positive control against the same server proves the denial was identity-driven.
    let allowed = Endpoint::bind(
        &allowed_id,
        loopback(),
        Allowlist::new(&[key(0xC5)]).expect("allowlist"),
        limits(),
    )
    .await
    .expect("allowed client binds");
    let allowed_addr = allowed.local_addr();
    let session = timeout(SETTLE, allowed.connect(key(0xC5), server_addr))
        .await
        .expect("allowed connect settles")
        .expect("allowed client connects");
    forward_exact(&session, b"native allowed control").await;
    assert_eq!(target.accepts.load(Ordering::SeqCst), 1);
    session.close();
    allowed.close().await;

    let summary = server.stop().await;
    assert_eq!(summary.accepted, 1, "only the allowed client is served");
    assert!(summary.denied >= 1, "forbidden handshake was denied");
    target.stop().await;
    native_released(&[server_addr, forbidden_addr, allowed_addr]).await;
}

/// The server carrier registers C7, but its endpoint allowlist refuses C7 at TLS.
async fn ygg_forbidden_half() {
    let (server_id, client_id) = (identity(0xC5), identity(0xC7));
    let target = Target::start().await;
    let (server_bridge, client_bridge, port) = ygg_pair(0xC5, 0xC7).await;
    let (mut server_endpoint, server_pump) = YggEndpoint::bind(
        &server_id,
        &server_bridge,
        Allowlist::new(&[key(0xC7)]).expect("allowlist"),
        limits(),
    )
    .await
    .expect("ygg server binds");
    // Carrier registration stays; only the endpoint admission is revoked.
    server_endpoint.allowlist = Allowlist::default();
    let (server, _events) = YggServer::start(server_endpoint, server_pump, target.addr);

    let (mut client, mut client_pump) = YggEndpoint::bind(
        &client_id,
        &client_bridge,
        Allowlist::new(&[key(0xC5)]).expect("allowlist"),
        limits(),
    )
    .await
    .expect("ygg client binds");
    let server_key: PublicKey = key(0xC5);
    let denied = timeout(
        SETTLE,
        driven(&mut client_pump, async {
            assert_denied(client.connect(server_key).await).await;
        }),
    )
    .await;
    denied.expect("ygg denial settles");
    assert_eq!(target.accepts.load(Ordering::SeqCst), 0);
    assert_eq!(client.slots.available_permits(), SESSIONS);

    client.close(&mut client_pump).await.expect("client closes");
    let summary = server.stop().await;
    assert_eq!(
        summary.accepted, 0,
        "no serving session for a forbidden peer"
    );
    assert!(summary.reports.is_empty());
    assert!(summary.denied >= 1, "forbidden handshake was denied");
    target.stop().await;
    client_bridge.close().await.expect("client bridge closes");
    server_bridge.close().await.expect("server bridge closes");
    ygg_released(0xC5, port).await;
    ygg_released(0xC7, port).await;
}

/// Fresh cores: allowed C6 is served over Ygg and reaches the target exactly once.
async fn ygg_allowed_half() {
    let (server_id, client_id) = (identity(0xC5), identity(0xC6));
    let target = Target::start().await;
    let (server_bridge, client_bridge, port) = ygg_pair(0xC5, 0xC6).await;
    let (server_endpoint, server_pump) = YggEndpoint::bind(
        &server_id,
        &server_bridge,
        Allowlist::new(&[key(0xC6)]).expect("allowlist"),
        limits(),
    )
    .await
    .expect("ygg server binds");
    let (server, _events) = YggServer::start(server_endpoint, server_pump, target.addr);
    let (mut client, mut client_pump) = YggEndpoint::bind(
        &client_id,
        &client_bridge,
        Allowlist::new(&[key(0xC5)]).expect("allowlist"),
        limits(),
    )
    .await
    .expect("ygg client binds");

    let session = timeout(SETTLE, driven(&mut client_pump, client.connect(key(0xC5))))
        .await
        .expect("allowed ygg connect settles")
        .expect("allowed ygg client connects");
    // Attribution starts before forwarding so the owned path carries every frame.
    let peer_address = client.peer_address(&key(0xC5)).expect("peer address");
    let mut frames = Frames::new(&session, peer_address);
    timeout(
        SETTLE,
        driven(
            &mut client_pump,
            forward_exact(&session, b"ygg allowed control"),
        ),
    )
    .await
    .expect("ygg forward settles");
    frames.checkpoint(&session);
    assert_eq!(target.accepts.load(Ordering::SeqCst), 1);

    session.close();
    client.close(&mut client_pump).await.expect("client closes");
    assert_eq!(client.slots.available_permits(), SESSIONS);
    let summary = server.stop().await;
    assert_eq!(summary.accepted, 1);
    let (tx, rx, closed) = frames.finish().await;
    assert!(
        tx && rx && closed,
        "ygg path frames tx={tx} rx={rx} closed={closed}"
    );
    target.stop().await;
    client_bridge.close().await.expect("client bridge closes");
    server_bridge.close().await.expect("server bridge closes");
    ygg_released(0xC5, port).await;
    ygg_released(0xC6, port).await;
}
