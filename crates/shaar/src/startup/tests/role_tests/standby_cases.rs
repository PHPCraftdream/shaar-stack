//! Standby case (5c scenario step 5: "Mainline outage with a same-key Ygg
//! standby path through independent transit") over the production role
//! entrypoints: operational Mainline failure on BOTH sides must leave the
//! alternate transport owned, not fail the composition — the key-derived
//! Yggdrasil path through the independently owned third transit carries the
//! payload. The file also hosts the native-restore case: idle policy
//! progress (Tick-driven native attempts) returns an active Yggdrasil
//! fallback to native without disturbing already-active streams.

use iroh_base::PublicKey;
use std::net::{SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::sync::oneshot;

use crate::config::{ClientConfig, ServerConfig};
use crate::identity::Identity;
use crate::native_discovery::runtime::owner::LoopbackPeer;
use crate::network::{Allowlist, Limits, RelayFixture};
use crate::path::{PathKind, PolicyConfig};
use crate::startup::role::{
    RoleEvent, RoleOptions, serve_client_with_events, serve_server_with_events,
};

use super::fixtures::{
    RoleFuture, admit_and_capture, arm_client_on_peer, bootstrap_v4, client_role_config,
    dead_relay_address, echo_on_held_stream, echo_target, forward_and_echo, hold_echoing_stream,
    identity, pin_role, probe_claim_free, pub_key_hex, role_logs, server_role_config,
    shutdown_roles, silent_udp, start_listener, tuned_policy, wait_role_event,
};

// Unique seeds (see the fixtures.rs discipline comment): standby case uses
// server identity 0x5B, client identity 0x5C, transit 0x5D.
const CASE_A_SERVICE: u8 = 0x5B;
const CASE_A_CLIENT: u8 = 0x5C;
const CASE_A_TRANSIT: u8 = 0x5D;
// Native-restore case: server 0x66, client 0x67, transit 0x68.
const RESTORE_SERVER: u8 = 0x66;
const RESTORE_CLIENT: u8 = 0x67;
const RESTORE_TRANSIT: u8 = 0x68;

/// Whole-body bound for this case. Policy math: the client burns TWO native
/// attempts against the silent bootstrap (`max_attempts: 2`), each eating the
/// full 5s per-resolve Mainline budget (`dialers::RESOLVE_BUDGET`) inside the
/// 15s `attempt_timeout`, plus the 20ms backoff between them, before the
/// standby Ygg dial — so ~10s of resolve timeouts alone, then the fallback
/// dial, the payload round trip and two joined shutdowns. The shared 30s
/// role budget would be tight; 60s holds the whole sequence with
/// headroom and only fails loudly instead of hanging CI.
const STANDBY_BUDGET: Duration = Duration::from_secs(60);

/// Native-restore case bound: the EAGER standby policy switches to the Ygg
/// fallback as soon as the fallback dial through the transit succeeds, while
/// Tick-driven native attempts continue in the background against the silent
/// bootstrap. `max_attempts: 6` keeps those attempts alive — with 2 the
/// policy would report `NativeExhausted` and never re-attempt, so a later-
/// served record could never restore native. The restore resolves quickly
/// once served, plus the 200ms `stable_hold` switch, two payload streams and
/// two shutdowns. 90s bounds the whole body against CI hangs.
const RESTORE_BUDGET: Duration = Duration::from_secs(90);

/// W4 tuned policy with a WIDER attempt budget: with `max_attempts: 2` the
/// policy reports `NativeExhausted` after the two silent resolves and PARKS
/// FOREVER (path/policy.rs `next_attempt` never schedules again after the
/// exhaustion report), so a later-served record could never trigger the
/// restore. Six attempts keep the Tick-driven `AttemptNative` decisions alive
/// (`next_attempt` checks only `native.up`/`in_flight`, never `active`);
/// legal per `PolicyConfig::validate`.
fn restore_policy() -> RoleOptions {
    RoleOptions {
        policy: PolicyConfig {
            loss_grace: 200,
            attempt_timeout: 15_000,
            backoff_base: 20,
            backoff_cap: 200,
            max_attempts: 6,
            stable_hold: 200,
        },
    }
}

// Regressions caught: a native-attempt failure that fails the whole
// composition instead of falling through to the standby transport, a standby
// route that never carries real payload, a server composition that cannot
// admit while its own Mainline lookup is cold-dead (the outage-on-the-server
// side proof), or a shutdown that lies about the resources the alternate
// transport still held (the claim-release probes below close truthfully
// THROUGH the outage).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mainline_outage_leaves_the_alternate_transport_owned_and_standby_carries_payload() {
    tokio::time::timeout(STANDBY_BUDGET, async {
        // Both roles get a cold-lookup-dead Mainline bootstrap (a bound UDP
        // blackhole that never replies — SilentUdp keeps the socket alive
        // until drop), so every Mainline GET/PUT resolve times out inside
        // `RESOLVE_BUDGET`: the outage is total and on both sides.
        let silent_server = silent_udp();
        let silent_client = silent_udp();
        // Real relay fixture: the SERVER's required signaling settings must be
        // real (the composition needs them to admit), even though the CLIENT
        // side deliberately cannot reach any relay.
        let fixture = RelayFixture::start().await;
        let relay_id = fixture.address.peer_id().to_string();
        let relay_address = fixture.address.socket_addr();
        // Real, independently owned third transit: the only working path
        // between the roles.
        let (transit, transit_port) = start_listener(CASE_A_TRANSIT).await;
        let transit_uri = format!("tcp://127.0.0.1:{transit_port}");
        let (echo, echo_address) = echo_target().await;

        let server_identity: &'static Identity = Box::leak(Box::new(identity(CASE_A_SERVICE)));
        let client_identity: &'static Identity = Box::leak(Box::new(identity(CASE_A_CLIENT)));
        let client_key =
            PublicKey::from_bytes(&client_identity.public_key_bytes()).expect("fixture client key");
        let server_bootstrap: SocketAddrV4 = match silent_server.address {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => panic!("silent bootstrap must bind IPv4"),
        };
        let server_config: &'static ServerConfig = Box::leak(Box::new(server_role_config(
            echo_address,
            server_bootstrap,
            &relay_id,
            relay_address,
            &transit_uri,
            "standby",
        )));
        // The client's REQUIRED relay settings point at the deliberately dead
        // address; no direct hint: the key is the only service locator.
        let dead_relay = dead_relay_address();
        let client_bootstrap: SocketAddrV4 = match silent_client.address {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => panic!("silent bootstrap must bind IPv4"),
        };
        let client_config: &'static ClientConfig = Box::leak(Box::new(client_role_config(
            &pub_key_hex(server_identity),
            client_bootstrap,
            &relay_id,
            dead_relay,
            &transit_uri,
            "standby",
            None,
        )));
        assert!(
            client_config.server_address().is_none(),
            "the standby outage case carries no legacy direct locator"
        );

        // SERVER role: pinned and driven in-body. Admission must succeed
        // DESPITE the dead Mainline bootstrap (the outage-on-the-server-side
        // proof); the initial PUT simply never gets acknowledged against the
        // blackhole.
        let (server_log, client_log) = role_logs();
        let (server_stop, server_stop_rx) = oneshot::channel();
        let mut server: RoleFuture = pin_role(serve_server_with_events(
            server_config,
            server_identity,
            Allowlist::new(&[client_key]).expect("fixture allowlist"),
            Limits::new(4).expect("fixture limits"),
            tuned_policy(),
            async move {
                let _ = server_stop_rx.await;
            },
            server_log.clone(),
        ));
        let admitted = |event: &RoleEvent| matches!(event, RoleEvent::Admitted);
        let admitted_event = tokio::time::timeout(STANDBY_BUDGET, async {
            tokio::select! {
                result = &mut server => panic!("server role ended early: {result:?}"),
                event = server_log.wait(&admitted) => event,
            }
        })
        .await
        .expect("the server composition admits through the Mainline outage");
        assert_eq!(admitted_event, RoleEvent::Admitted);

        // CLIENT role: pinned, no arm helper (silent bootstrap — there is no
        // bootstrap peer to arm against). The role emits ListenerReady before
        // any dial; the single-slot-free lossless log makes every subsequent
        // wait an unconditional scan plus cancel-safe `wait`.
        let (client_stop, client_stop_rx) = oneshot::channel();
        let mut client: RoleFuture = pin_role(serve_client_with_events(
            client_config,
            client_identity,
            Limits::new(4).expect("fixture limits"),
            tuned_policy(),
            async move {
                let _ = client_stop_rx.await;
            },
            client_log.clone(),
        ));
        let listener_ready = |event: &RoleEvent| matches!(event, RoleEvent::ListenerReady(_));
        let listener_address = tokio::time::timeout(STANDBY_BUDGET, async {
            tokio::select! {
                result = &mut client => panic!("client role ended early: {result:?}"),
                result = &mut server => panic!("server ended during client arming: {result:?}"),
                event = client_log.wait(&listener_ready) => match event {
                    RoleEvent::ListenerReady(address) => address,
                    other => panic!(
                        "unexpected role event while awaiting the listener: {other:?}"
                    ),
                },
            }
        })
        .await
        .expect("the client listener becomes ready within the standby budget");

        // The route through the outage: the key-derived Yggdrasil path through
        // the independently owned third transit — never the dead relay, never
        // a native session.
        // BOTH roles must be driven here: the client's standby dial is only
        // admitted when the server role pumps and accepts its Ygg endpoint.
        let route_active_ygg =
            |event: &RoleEvent| matches!(event, RoleEvent::RouteActive(PathKind::Yggdrasil));
        let route = tokio::time::timeout(
            STANDBY_BUDGET,
            wait_role_event(
                &mut server,
                &mut client,
                &server_log,
                &client_log,
                route_active_ygg,
                "standby",
            ),
        )
        .await
        .expect("the client reaches the key-derived Yggdrasil route through the outage");
        assert_eq!(
            route,
            RoleEvent::RouteActive(PathKind::Yggdrasil),
            "the route through the outage is the standby Yggdrasil path"
        );

        // Server-side mirror of the same session: the Ygg session the standby
        // route dialed is admitted server-side. Both pinned futures are
        // driven together here.
        let server_session = wait_role_event(
            &mut server,
            &mut client,
            &server_log,
            &client_log,
            |event| matches!(event, RoleEvent::SessionAdmitted(PathKind::Yggdrasil)),
            "standby",
        )
        .await;
        assert_eq!(
            server_session,
            RoleEvent::SessionAdmitted(PathKind::Yggdrasil),
            "the standby session is admitted as Yggdrasil on the server side"
        );

        // Structural standby oracle: the client composition's REAL payload
        // acquisition was observed present at its live transfer — the route
        // above could only exist through the real same-key Yggdrasil path.
        let payload_on = |event: &RoleEvent| matches!(event, RoleEvent::YggPayloadAcquired(true));
        assert!(
            client_log.find(&payload_on).is_some(),
            "the client transferred the real Yggdrasil payload pair: {:?}",
            client_log.snapshot()
        );

        // Full-path proof: the byte pattern crosses the client listener, the
        // standby Ygg session, the server role and its fixed loopback target.
        let pattern = b"shaar-5c-standby";
        forward_and_echo(
            listener_address,
            pattern,
            &mut server,
            &mut client,
            "standby",
        )
        .await;
        assert_eq!(
            echo.count(),
            1,
            "exactly one fixed-target connection served the forwarded pattern"
        );

        // Graceful shutdowns of BOTH roles through the outage: fire each stop
        // sender, then drive each role to its joined truthful `Ok`.
        let _ = server_stop.send(());
        let _ = client_stop.send(());
        shutdown_roles(&mut server, &mut client).await;

        // Cleanup truthfulness: the SERVER claim release below proves the
        // alternate transport survived the outage and still closed
        // truthfully; the transit, relay fixture and echo target close
        // bounded, and the blackhole sockets drop.
        echo.close().await;
        let closed = tokio::time::timeout(STANDBY_BUDGET, transit.close()).await;
        assert!(
            closed.is_ok() && closed.expect("checked").is_ok(),
            "owned transit closes cleanly"
        );
        fixture.close().await;
        drop(silent_server);
        drop(silent_client);
        probe_claim_free(CASE_A_SERVICE, "server identity claim released").await;
        probe_claim_free(CASE_A_CLIENT, "client identity claim released").await;
        probe_claim_free(CASE_A_TRANSIT, "transit identity claim released").await;
    })
    .await
    .expect("case A completes within the standby budget");
}

// ---------------------------------------------------------------------------
// C3 — idle policy progress restores native without disturbing active streams
// ---------------------------------------------------------------------------

// 5c criteria: "no stale path-only snapshot may replace ongoing policy work"
// + idle policy progress. Policy reading (path/policy.rs): the policy DOES
// re-attempt native while a Yggdrasil fallback is active — `next_attempt`
// (lines 262-287) issues Tick-driven `AttemptNative` whenever `!native.up`
// and no attempt is in flight, without consulting `active` — and
// `select_payload` (lines 249-252) returns to native once
// `native.up && now >= native.since + stable_hold`; the budget refills only
// after that hold (`refill`, lines 289-294). NATIVE-RESTORE is implemented.
// Regressions caught: a switch that tears down in-flight forward workers (the
// FIRST stream must keep echoing over its original Ygg lease), a policy that
// never re-attempts native under an active fallback, or a stale snapshot
// that replaces the restored session ordering (the ordered snapshot oracle
// proves the native admission is the RESTORED session).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_policy_progress_restores_native_without_disturbing_active_streams() {
    tokio::time::timeout(RESTORE_BUDGET, async {
        let mut service_peer = LoopbackPeer::bind().await;
        let fixture = RelayFixture::start().await;
        let relay_id = fixture.address.peer_id().to_string();
        let relay_address = fixture.address.socket_addr();
        let (transit, transit_port) = start_listener(RESTORE_TRANSIT).await;
        let transit_uri = format!("tcp://127.0.0.1:{transit_port}");
        let (echo, echo_address) = echo_target().await;

        let server_identity: &'static Identity = Box::leak(Box::new(identity(RESTORE_SERVER)));
        let client_identity: &'static Identity = Box::leak(Box::new(identity(RESTORE_CLIENT)));
        let client_key =
            PublicKey::from_bytes(&client_identity.public_key_bytes()).expect("fixture client key");
        let server_config: &'static ServerConfig = Box::leak(Box::new(server_role_config(
            echo_address,
            bootstrap_v4(&service_peer),
            &relay_id,
            relay_address,
            &transit_uri,
            "standby",
        )));
        // CLIENT bootstrap: a LoopbackPeer with NOTHING served — pre-
        // `serve_record` GETs simply go unanswered (the socket only replies
        // while a fixture future is awaiting it): exactly the silent phase.
        // Plus the dead relay port.
        let mut client_peer = LoopbackPeer::bind().await;
        let client_config: &'static ClientConfig = Box::leak(Box::new(client_role_config(
            &pub_key_hex(server_identity),
            bootstrap_v4(&client_peer),
            &relay_id,
            dead_relay_address(),
            &transit_uri,
            "standby",
            None,
        )));

        // SERVER role: pinned; admission and its real initial PUT are
        // concurrently retained, then the PUT is acknowledged.
        let (server_log, _unused_log) = role_logs();
        let (server_stop, server_stop_rx) = oneshot::channel();
        let mut server: RoleFuture = pin_role(serve_server_with_events(
            server_config,
            server_identity,
            Allowlist::new(&[client_key]).expect("fixture allowlist"),
            Limits::new(4).expect("fixture limits"),
            tuned_policy(),
            async move {
                let _ = server_stop_rx.await;
            },
            server_log.clone(),
        ));
        let item =
            admit_and_capture(&mut service_peer, &mut server, &server_log, RESTORE_BUDGET).await;

        // CLIENT through the silent phase: the EAGER standby policy owns the
        // route through the transit as soon as the fallback dial succeeds,
        // while native attempts against the unanswered bootstrap continue in
        // the background. The client is armed on its bootstrap peer (PUT
        // captured and acknowledged BEFORE the record server below is armed).
        let (client_stop, mut client, client_log, listener_address) = {
            let arming = arm_client_on_peer(
                client_config,
                client_identity,
                &mut client_peer,
                restore_policy(),
                RESTORE_BUDGET,
            );
            tokio::select! {
                armed = arming => armed,
                result = &mut server => panic!("server ended during restore-client arming: {result:?}"),
            }
        };
        wait_role_event(
            &mut server,
            &mut client,
            &server_log,
            &client_log,
            |event| matches!(event, RoleEvent::RouteActive(PathKind::Yggdrasil)),
            "client",
        )
        .await;
        // FIRST stream: a HELD Ygg lease with a live echo.
        let first_pattern = b"shaar-5c-restore-first";
        let mut held_first = hold_echoing_stream(
            listener_address,
            first_pattern,
            &mut server,
            &mut client,
            "first stream",
        )
        .await;

        // THE RESTORE: serve the freshly captured server record to the
        // client's bootstrap; the next Tick-driven native attempt resolves,
        // and the policy returns the payload to native after `stable_hold`.
        let mut record = Box::pin(client_peer.serve_record(&item));
        let route_active_native =
            |event: &RoleEvent| matches!(event, RoleEvent::RouteActive(PathKind::Native));
        tokio::time::timeout(RESTORE_BUDGET, async {
            tokio::select! {
                result = &mut server => panic!("server role ended early: {result:?}"),
                result = &mut client => panic!("client role ended early: {result:?}"),
                _ = &mut record => {
                    panic!("client bootstrap record server terminated during the restore")
                }
                event = client_log.wait(&route_active_native) => event,
            }
        })
        .await
        .expect("the idle policy progress restores the native route");

        // SECOND stream rides NATIVE; the FIRST stream still echoes over its
        // original Ygg lease — the in-flight stream was never replaced.
        {
            let transfers = async {
                forward_and_echo(
                    listener_address,
                    b"shaar-5c-restore-second",
                    &mut server,
                    &mut client,
                    "second stream",
                )
                .await;
                echo_on_held_stream(
                    &mut held_first,
                    first_pattern,
                    &mut server,
                    &mut client,
                    "first stream",
                )
                .await;
            };
            tokio::select! {
                () = transfers => {},
                _ = &mut record => panic!("record responder ended during restored forwarding"),
            }
        }
        assert_eq!(
            echo.count(),
            2,
            "exactly the two fixed-target connections (first + second stream)"
        );

        let _ = server_stop.send(());
        let _ = client_stop.send(());
        tokio::select! {
            () = shutdown_roles(&mut server, &mut client) => {},
            _ = &mut record => panic!("record responder ended during restored shutdown"),
        }
        drop(record);
        drop(held_first);

        // Ordered lossless snapshot oracle: the native admission comes AFTER
        // the Ygg admission — the native session is the RESTORED one.
        let seen = server_log.snapshot();
        let ygg_index = seen
            .iter()
            .position(|event| *event == RoleEvent::SessionAdmitted(PathKind::Yggdrasil))
            .expect("the first (Ygg) session admission was recorded");
        let native_index = seen
            .iter()
            .position(|event| *event == RoleEvent::SessionAdmitted(PathKind::Native))
            .expect("the restored native session admission was recorded");
        assert!(
            ygg_index < native_index,
            "the native admission is the RESTORED session, never the first: {seen:?}"
        );

        echo.close().await;
        let closed = tokio::time::timeout(RESTORE_BUDGET, transit.close()).await;
        assert!(
            closed.is_ok() && closed.expect("checked").is_ok(),
            "owned transit closes cleanly"
        );
        fixture.close().await;
        probe_claim_free(RESTORE_SERVER, "server identity claim released").await;
        probe_claim_free(RESTORE_CLIENT, "client identity claim released").await;
        probe_claim_free(RESTORE_TRANSIT, "transit identity claim released").await;
    })
    .await
    .expect("the native-restore case completes within its budget");
}
