// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
//! Forwarding and exact-echo scenarios over the standby fixture.
//!
//! No libp2p signaling carrier exists in this fixture, so zero libp2p APP bytes
//! hold by construction; the only payload routes are the native and Ygg sessions.
//! "Native unavailable" below means stopping the real native server endpoint, not
//! a public-network or packet-filter blockade.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use shaar_ygg::YggBridge;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout};

use super::super::YggEndpoint;
use super::super::tests::Frames;
use super::{
    CountedFallback, Endpoint, NativeDial, NativeServer, Probe, Target, YggFallback, YggServer,
    assert_same_identity, counted, forward_exact, identity, native_only, native_released, tcp_pair,
    test_config, ygg_pair, ygg_released,
};
use crate::identity::Identity;
use crate::network::{Allowlist, ForwardError, ForwardStats, Limits, STREAM_LIMIT, Session};
use crate::path::{Mode, PathKind, PolicyConfig, Route, StandbyError, StandbyOwner};

type Owner = StandbyOwner<NativeDial, CountedFallback>;

/// Endpoint admission slots of every endpoint in these tests.
const SLOTS: usize = 4;

/// Client half of one node: the owner plus the handles needed for proofs.
struct Client {
    owner: Owner,
    probe: Probe,
    native_addr: SocketAddr,
    native_dials: Arc<AtomicUsize>,
    fallback_dials: Arc<AtomicUsize>,
    native_dial_ok: Arc<Mutex<Vec<Instant>>>,
}

/// Binds the client's native endpoint and Ygg fallback under one identity.
async fn client(
    client_id: &Identity,
    server_id: &Identity,
    native_server: SocketAddr,
    bridge: &YggBridge,
    mode: Mode,
    config: PolicyConfig,
) -> Client {
    let server_key = server_id.transport_key().public();
    let allowlist = || Allowlist::new(&[server_key]).expect("allowlist");
    let limits = || Limits::new(SLOTS).expect("limits");
    let native = Endpoint::bind(
        client_id,
        "127.0.0.1:0".parse().expect("loopback"),
        allowlist(),
        limits(),
    )
    .await
    .expect("client native endpoint binds");
    let native_addr = native.local_addr();
    let native_id = native.id();
    let (endpoint, pump) = YggEndpoint::bind(client_id, bridge, allowlist(), limits())
        .await
        .expect("client Ygg endpoint binds");
    let fallback = YggFallback::new(endpoint, pump, server_key).expect("fallback allowlisted");
    let native_dials = Arc::new(AtomicUsize::new(0));
    let fallback_dials = Arc::new(AtomicUsize::new(0));
    let native_dial_ok = Arc::new(Mutex::new(Vec::new()));
    let (fallback, probe) = counted(fallback, server_key, Arc::clone(&fallback_dials));
    assert_same_identity(client_id, &native_id, &probe.endpoint_id);
    let dial = NativeDial::new(
        native,
        server_key,
        native_server,
        Arc::clone(&native_dials),
        Arc::clone(&native_dial_ok),
    );
    let owner = StandbyOwner::new(dial, fallback, mode, config).expect("owner");
    Client {
        owner,
        probe,
        native_addr,
        native_dials,
        fallback_dials,
        native_dial_ok,
    }
}

/// Binds the server's Ygg endpoint and starts its owned accept task.
async fn ygg_server(
    server_id: &Identity,
    client_id: &Identity,
    bridge: &YggBridge,
    target: SocketAddr,
) -> YggServer {
    let client_key = client_id.transport_key().public();
    let (endpoint, pump) = YggEndpoint::bind(
        server_id,
        bridge,
        Allowlist::new(&[client_key]).expect("allowlist"),
        Limits::new(SLOTS).expect("limits"),
    )
    .await
    .expect("server Ygg endpoint binds");
    assert_eq!(endpoint.id(), server_id.transport_key().public());
    YggServer::start(endpoint, pump, target).0
}

/// Owned lease on the native link; a live forward on it never borrows the owner.
fn native_lease(owner: &Owner) -> Arc<Session> {
    match owner.route() {
        Some(Route::Native(session)) => session,
        _ => panic!("expected the native route"),
    }
}

/// Owned lease on the Yggdrasil link.
fn ygg_lease(owner: &Owner) -> Arc<Session> {
    match owner.route() {
        Some(Route::Yggdrasil(session)) => session,
        _ => panic!("expected the Yggdrasil route"),
    }
}

fn payload(tag: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).expect("below 251").wrapping_add(tag))
        .collect()
}

fn accepted(target: &Target) -> usize {
    target.accepts.load(Ordering::SeqCst)
}

/// The client's own observation boundary: when its latest native dial completed.
fn last_dial_ok(log: &Mutex<Vec<Instant>>) -> Instant {
    let log = log.lock().expect("dial log lock");
    *log.last().expect("a native dial succeeded")
}

/// Drives `forward` until the target accepted `n` connections, so the stream is
/// known to be set up before any disruption. An early end of the forward fails.
async fn until_accepted(
    target: &Target,
    n: usize,
    mut forward: Pin<&mut impl Future<Output = Result<ForwardStats, ForwardError>>>,
) {
    tokio::select! {
        biased;
        () = target.wait_accepted(n) => {}
        ended = forward.as_mut() => panic!("forward ended before target accept {n}: {ended:?}"),
    }
}

/// Ends a held idle forward with a real exchange: the same connection that stayed
/// open across the route change must still echo exactly.
async fn release_exact(
    app: tokio::net::TcpStream,
    forward: Pin<&mut impl Future<Output = Result<ForwardStats, ForwardError>>>,
    bytes: &[u8],
) {
    let (mut read, mut write) = app.into_split();
    let writing = async {
        write.write_all(bytes).await.expect("app writes");
        write.shutdown().await.expect("app half-closes");
    };
    let reading = async {
        let mut echoed = Vec::new();
        read.read_to_end(&mut echoed).await.expect("app reads");
        assert_eq!(echoed.as_slice(), bytes);
    };
    let (stats, (), ()) = tokio::join!(forward, writing, reading);
    let stats = stats.expect("held forward completed");
    let size = u64::try_from(bytes.len()).expect("payload length");
    assert_eq!(stats.to_peer, size);
    assert_eq!(stats.from_peer, size);
}

#[tokio::test(flavor = "multi_thread")]
async fn native_ygg_native_new_tcp_follows_policy() {
    timeout(Duration::from_secs(120), async {
        let (server_id, client_id) = (identity(0xC1), identity(0xC2));
        let client_key = client_id.transport_key().public();
        let config = PolicyConfig::default();
        let target = Target::start().await;
        let (native_server, native_addr, _first_events) = NativeServer::start(
            &server_id,
            "127.0.0.1:0".parse().expect("loopback"),
            &[client_key],
            target.addr,
        )
        .await;
        let (server_bridge, client_bridge, port) = ygg_pair(0xC1, 0xC2).await;
        let Client {
            mut owner,
            probe,
            native_addr: client_addr,
            native_dials,
            fallback_dials,
            native_dial_ok,
        } = client(
            &client_id,
            &server_id,
            native_addr,
            &client_bridge,
            Mode::Standby,
            config,
        )
        .await;
        let permits = usize::from(STREAM_LIMIT);

        // 1. Native carries the first connection while healthy.
        assert_eq!(owner.follow().await, Ok(PathKind::Native));
        let native = native_lease(&owner);
        forward_exact(&native, &payload(1, 48 * 1024)).await;
        native_only(&native);
        assert_eq!(accepted(&target), 1);
        target.wait_closed(1).await;
        // Delay Ygg admission so the first payload route is deterministically native.
        let ygg_server = ygg_server(&server_id, &client_id, &server_bridge, target.addr).await;

        // 2. Cancelling a real in-flight forward returns its stream permit and ends
        // the target connection; the session itself stays healthy and usable.
        let (app, bridge) = tcp_pair().await;
        let mut cancelled = Box::pin(native.forward(bridge));
        until_accepted(&target, 2, cancelled.as_mut()).await;
        assert_eq!(native.streams.available_permits(), permits - 1);
        drop(cancelled);
        assert_eq!(native.streams.available_permits(), permits);
        drop(app);
        target.wait_closed(2).await;
        assert_eq!(accepted(&target), 2, "cancel must not replay the stream");
        forward_exact(&native, &payload(2, 4 * 1024)).await;
        assert_eq!(accepted(&target), 3);
        target.wait_closed(3).await;

        // 3. An in-flight forward that the target already accepted must fail when
        // the real native server stops; it is never replayed or migrated.
        let (app, bridge) = tcp_pair().await;
        let mut idle = Box::pin(native.forward(bridge));
        until_accepted(&target, 4, idle.as_mut()).await;
        assert_eq!(accepted(&target), 4);
        let (idle_result, first_summary) = tokio::join!(idle.as_mut(), native_server.stop());
        assert!(
            idle_result.is_err(),
            "in-flight forward survived native loss"
        );
        drop(idle);
        drop(app);
        drop(native);
        assert!(first_summary.accepted >= 1);
        target.wait_closed(4).await;
        assert_eq!(target.closed_count(), 4);
        assert_eq!(accepted(&target), 4, "no replay after the native loss");

        // 4. Policy fails over; a NEW TCP connection rides Ygg. The native retry
        // count depends on timing, so it is only bounded below.
        assert_eq!(owner.follow().await, Ok(PathKind::Yggdrasil));
        let ygg = ygg_lease(&owner);
        let mut frames = Frames::new(&ygg, probe.peer_address.clone());
        forward_exact(&ygg, &payload(5, 40 * 1024)).await;
        frames.checkpoint(&ygg);
        assert_eq!(accepted(&target), 5);
        target.wait_closed(5).await;

        // 5. A healthy Ygg forward stays open while the native server returns at
        // the same address. Both the owner and the held forward are polled.
        let (ygg_app, ygg_bridge) = tcp_pair().await;
        let mut held = Box::pin(ygg.forward(ygg_bridge));
        until_accepted(&target, 6, held.as_mut()).await;
        assert_eq!(accepted(&target), 6);
        let (second_server, second_addr, _second_events) =
            NativeServer::start(&server_id, native_addr, &[client_key], target.addr).await;
        assert_eq!(second_addr, native_addr);
        let followed = tokio::select! {
            biased;
            result = owner.follow() => result,
            ended = held.as_mut() => panic!("held Ygg forward ended early: {ended:?}"),
        };
        let returned_at = Instant::now();
        assert_eq!(followed, Ok(PathKind::Native));

        // NativeUp cannot precede the successful dial; compare the same policy clock.
        let up_at = owner.observation_time(last_dial_ok(&native_dial_ok));
        let returned_at = owner.observation_time(returned_at);
        let held_for = returned_at.saturating_sub(up_at);
        assert!(
            held_for >= config.stable_hold,
            "native returned after {held_for} policy ms, before the {} ms hold",
            config.stable_hold
        );

        // 6. A NEW TCP connection rides native while the old Ygg one is still open.
        let native = native_lease(&owner);
        forward_exact(&native, &payload(3, 56 * 1024)).await;
        native_only(&native);
        assert_eq!(accepted(&target), 7);

        // 7. The old connection finishes on its own path, exactly, never migrated.
        release_exact(ygg_app, held.as_mut(), &payload(6, 8 * 1024)).await;
        drop(held);
        target.wait_closed(7).await;
        assert_eq!(target.closed_count(), 7);
        assert_eq!(accepted(&target), 7, "no replay after the recovery");
        assert!(native_dials.load(Ordering::SeqCst) >= 2);
        assert!(fallback_dials.load(Ordering::SeqCst) >= 1);

        // Ordered shutdown: leases, owner, servers, target, then the Ygg bridges.
        drop(native);
        drop(ygg);
        owner.close().await.expect("owner closes");
        let second_summary = second_server.stop().await;
        let ygg_summary = ygg_server.stop().await;
        target.stop().await;
        assert!(second_summary.accepted >= 1);
        assert!(ygg_summary.accepted >= 1);
        let (tx, rx, closed) = frames.finish().await;
        assert!(
            tx && rx && closed,
            "Ygg path frames tx={tx} rx={rx} closed={closed}"
        );
        assert_eq!(probe.slots.available_permits(), SLOTS);
        client_bridge.close().await.expect("client bridge closes");
        server_bridge.close().await.expect("server bridge closes");
        ygg_released(0xC1, port).await;
        native_released(&[native_addr, client_addr]).await;
    })
    .await
    .expect("native_ygg_native_new_tcp_follows_policy deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn signal_mode_negotiates_through_ygg_but_never_forwards_payload_through_it() {
    timeout(Duration::from_secs(120), async {
        let (server_id, client_id) = (identity(0xC8), identity(0xC9));
        let target = Target::start().await;
        // A bound-then-released UDP address stands for a native endpoint that is
        // not running; the native server is never started in this test.
        let dead = {
            let socket = UdpSocket::bind("127.0.0.1:0").await.expect("probe socket");
            socket.local_addr().expect("probe address")
        };
        let (server_bridge, client_bridge, port) = ygg_pair(0xC8, 0xC9).await;
        // Negotiation-style traffic works: the real Ygg core answers a probe.
        client_bridge
            .probe(server_id.public_key_bytes(), Duration::from_secs(30))
            .await
            .expect("Ygg is probe-ready");
        let ygg_server = ygg_server(&server_id, &client_id, &server_bridge, target.addr).await;
        let config = PolicyConfig {
            max_attempts: 2,
            attempt_timeout: 300,
            ..test_config()
        };
        let Client {
            mut owner,
            probe,
            native_addr: client_addr,
            native_dials,
            fallback_dials,
            ..
        } = client(
            &client_id,
            &server_id,
            dead,
            &client_bridge,
            Mode::Signal,
            config,
        )
        .await;

        assert_eq!(owner.follow().await, Err(StandbyError::Exhausted));
        assert!(owner.route().is_none());
        assert!(owner.native_exhausted());
        // Each policy attempt starts exactly one dial, and the budget is the cap.
        assert_eq!(
            native_dials.load(Ordering::SeqCst),
            usize::try_from(config.max_attempts).expect("attempts")
        );
        assert_eq!(fallback_dials.load(Ordering::SeqCst), 0);

        owner.close().await.expect("owner closes");
        let ygg_summary = ygg_server.stop().await;
        assert_eq!(
            ygg_summary.accepted, 0,
            "Ygg carried a session in Signal mode"
        );
        assert_eq!(accepted(&target), 0);
        target.stop().await;
        assert_eq!(probe.slots.available_permits(), SLOTS);
        client_bridge.close().await.expect("client bridge closes");
        server_bridge.close().await.expect("server bridge closes");
        ygg_released(0xC8, port).await;
        native_released(&[client_addr]).await;
    })
    .await
    .expect("signal_mode_negotiates_through_ygg_but_never_forwards_payload_through_it deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_native_packet_loss_measures_twenty_first_byte_failovers() {
    use super::block::NativeGate;
    use std::fmt::Write as _;

    timeout(Duration::from_secs(600), async {
        let (server_id, client_id) = (identity(0xCD), identity(0xCE));
        let client_key = client_id.transport_key().public();
        let (server_bridge, client_bridge, port) = ygg_pair(0xCD, 0xCE).await;
        let mut target = Target::start().await;
        let mut samples = [Duration::MAX; 20];
        let mut rows = String::with_capacity(8192);
        rows.push_str("trial,phase,native_available,path,failover_ns\n");
        for (trial, sample) in samples.iter_mut().enumerate() {
            let (native_server, server_addr, _) = NativeServer::start(
                &server_id, "127.0.0.1:0".parse().expect("loopback"), &[client_key], target.addr,
            ).await;
            let gate = NativeGate::start(server_addr).await;
            let Client { mut owner, probe, native_addr: client_addr, .. } = client(
                &client_id, &server_id, gate.address, &client_bridge,
                Mode::Standby, PolicyConfig::default(),
            ).await;
            assert_eq!(owner.follow().await, Ok(PathKind::Native));
            let native = native_lease(&owner);
            let (_, (ordinal, byte, _)) = tokio::join!(forward_exact(&native, b"n"), target.first_byte());
            assert_eq!((ordinal, byte), (trial * 2 + 1, b'n'));
            native_only(&native);
            assert!(native.connection.paths().iter().all(|path|
                matches!(path.remote_addr(), iroh_base::TransportAddr::Ip(address) if *address == gate.address)
            ), "every native path must pass through the controlled gate");
            drop(native);
            target.wait_closed(trial * 2 + 1).await;
            writeln!(rows, "{trial},healthy,true,Native,0").expect("String formatting");
            let ygg_server = ygg_server(&server_id, &client_id, &server_bridge, target.addr).await;
            // Silent bidirectional packet loss, not an announced endpoint close.
            let blocked_at = gate.block();
            let followed = timeout(Duration::from_secs(30), owner.follow()).await;
            if matches!(followed, Ok(Ok(PathKind::Yggdrasil))) {
                let ygg = ygg_lease(&owner);
                let (ordinal, byte, at) = timeout(Duration::from_secs(30), async {
                    let (_, first) = tokio::join!(forward_exact(&ygg, b"y"), target.first_byte());
                    first
                }).await.expect("new Ygg TCP reaches the actual target");
                assert_eq!((ordinal, byte), (trial * 2 + 2, b'y'));
                *sample = at.checked_duration_since(blocked_at).expect("same monotonic clock");
                writeln!(rows, "{trial},blocked,false,Yggdrasil,{}", sample.as_nanos()).expect("String formatting");
                drop(ygg);
                target.wait_closed(trial * 2 + 2).await;
            }
            eprintln!("P10 failover trial={trial} silent_drop=true outcome={followed:?} first_target_byte={sample:?}");
            owner.close().await.expect("measured owner closes");
            let native_summary = native_server.stop().await;
            let ygg_summary = ygg_server.stop().await;
            let (passed, dropped) = gate.stop().await;
            native_released(&[server_addr, client_addr]).await;
            assert!(native_summary.accepted >= 1);
            assert!(passed > 0 && dropped > 0, "real traffic passed before and was dropped after blocking");
            assert!(matches!(followed, Ok(Ok(PathKind::Yggdrasil))), "silent loss did not fail over: {followed:?}");
            assert!(ygg_summary.accepted >= 1);
            assert_eq!(probe.slots.available_permits(), SLOTS);
        }
        target.stop().await;
        client_bridge.close().await.expect("client bridge joins");
        server_bridge.close().await.expect("server bridge joins");
        ygg_released(0xCD, port).await;
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors().nth(2).expect("workspace root").join("target/ci-selected");
        assert!(rows.len() <= 8192);
        tokio::fs::create_dir_all(&directory).await.expect("receipt directory");
        tokio::fs::write(directory.join("p10-failover-samples.csv"), rows).await.expect("all phase rows retained");
        samples.sort_unstable();
        eprintln!("P10 silent-loss failover samples=20 nearest_rank_p95={:?}", samples[18]);
        assert!(samples[18] <= Duration::from_secs(10), "silent-loss first-byte p95 exceeds 10 s: {samples:?}");
    }).await.expect("fixed-size packet-loss campaign stays bounded");
}
