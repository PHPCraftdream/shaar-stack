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
use crate::path::{NativeObservation, PathKind, PolicyConfig};
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
// Task 32 reuses the already-owned native-restore cohort; there is no new
// process-wide Ygg seed allocation. The signed record responder stays unarmed
// until the actual owner exhaustion barrier.
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

/// The default-policy bound includes six 3 s attempts, their 0.5+1+2+4+4 s
/// backoffs, one 4 s cooldown, one 3 s renewed dial, and the 5 s stable hold.
fn task32_policy_bound() -> Duration {
    let policy = PolicyConfig::default();
    let attempts = policy
        .attempt_timeout
        .saturating_mul(u64::from(policy.max_attempts));
    let mut delay = policy.backoff_base;
    let mut backoffs = 0_u64;
    for _ in 1..policy.max_attempts {
        backoffs = backoffs.saturating_add(delay);
        delay = delay.saturating_mul(2).min(policy.backoff_cap);
    }
    Duration::from_millis(
        attempts
            .saturating_add(backoffs)
            .saturating_add(policy.backoff_cap)
            .saturating_add(policy.attempt_timeout)
            .saturating_add(policy.stable_hold),
    )
}

/// Fixture allowances comprise the role phase waits, real echoes, joined
/// shutdown and owned-fixture release probes.
fn task32_case_bound() -> Duration {
    let role = super::fixtures::ROLE_BUDGET;
    let claim = Duration::from_secs(10);
    task32_policy_bound() + role + role + role + role + role + role + role + claim + claim + claim
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

/// Task32 replaces the earlier tuned native restore with the true default-budget
/// exhaustion case; the production startup and forwarding oracles stay in place.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_policy_progress_restores_native_without_disturbing_active_streams() {
    let outer_deadline = tokio::time::Instant::now() + task32_case_bound();
    tokio::time::timeout_at(outer_deadline, async {
        eprintln!("Task32 phase: startup");
        let mut service_peer = LoopbackPeer::bind().await;
        let policy = PolicyConfig::default();
        assert_eq!(policy.max_attempts, 6);
        assert_eq!(policy.attempt_timeout, 3_000);
        assert_eq!(policy.backoff_cap, 4_000);
        assert_eq!(policy.stable_hold, 5_000);
        let fixture = RelayFixture::start().await;
        let relay_id = fixture.address.peer_id().to_string();
        let relay_address = fixture.address.socket_addr();
        let (transit, transit_port) = start_listener(RESTORE_TRANSIT).await;
        let transit_uri = format!("tcp://127.0.0.1:{transit_port}");
        let (echo, echo_address) = echo_target().await;
        let server_identity: &'static Identity = Box::leak(Box::new(identity(RESTORE_SERVER)));
        let client_identity: &'static Identity = Box::leak(Box::new(identity(RESTORE_CLIENT)));
        let client_key = PublicKey::from_bytes(&client_identity.public_key_bytes())
            .expect("fixture client key");
        let server_config: &'static ServerConfig = Box::leak(Box::new(server_role_config(
            echo_address,
            bootstrap_v4(&service_peer),
            &relay_id,
            relay_address,
            &transit_uri,
            "standby",
        )));
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
        assert!(client_config.server_address().is_none());

        let (server_log, _unused_server_log) = role_logs();
        let (server_stop, server_stop_rx) = oneshot::channel();
        let mut server: RoleFuture = pin_role(serve_server_with_events(
            server_config,
            server_identity,
            Allowlist::new(&[client_key]).expect("fixture allowlist"),
            Limits::new(4).expect("fixture limits"),
            tuned_policy(),
            async move { let _ = server_stop_rx.await; },
            server_log.clone(),
        ));
        let item = admit_and_capture(
            &mut service_peer, &mut server, &server_log, super::fixtures::ROLE_BUDGET,
        ).await;

        eprintln!("Task32 phase: server admitted and signed initial PUT captured");
        let (client_stop, mut client, client_log, listener_address) = {
            let arming = arm_client_on_peer(
                client_config,
                client_identity,
                &mut client_peer,
                RoleOptions { policy },
                super::fixtures::ROLE_BUDGET,
            );
            tokio::select! {
                armed = arming => armed,
                result = &mut server => panic!("Task32 server ended during client arming: {result:?}"),
            }
        };
        eprintln!("Task32 phase: client armed; awaiting authenticated Ygg route");
        let route_ygg = wait_role_event(
            &mut server,
            &mut client,
            &server_log,
            &client_log,
            |event| *event == RoleEvent::RouteActive(PathKind::Yggdrasil),
            "Task32 Ygg route",
        )
        .await;
        assert_eq!(route_ygg, RoleEvent::RouteActive(PathKind::Yggdrasil));
        let admitted_ygg = wait_role_event(
            &mut server,
            &mut client,
            &server_log,
            &client_log,
            |event| *event == RoleEvent::SessionAdmitted(PathKind::Yggdrasil),
            "Task32 server-side Ygg admission",
        )
        .await;
        assert_eq!(admitted_ygg, RoleEvent::SessionAdmitted(PathKind::Yggdrasil));
        let mut held_ygg = hold_echoing_stream(
            listener_address,
            b"task32-held-ygg-before-exhaustion",
            &mut server,
            &mut client,
            "Task32 held Ygg TCP stream",
        )
        .await;
        assert_eq!(echo.count(), 1);
        eprintln!("Task32 phase: held Ygg stream echoed; awaiting real ordinary exhaustion");
        let exhausted_pred = |event: &RoleEvent| matches!(
            event,
            RoleEvent::NativeOwner { observation: NativeObservation::Exhausted { .. }, .. }
        );
        // Exact exchange keeps the old lease live before we await the callback.
        echo_on_held_stream(
            &mut held_ygg,
            b"task32-ygg-before-exhaustion",
            &mut server,
            &mut client,
            "Task32 Ygg stream before barrier",
        )
        .await;
        let exhausted = tokio::time::timeout_at(outer_deadline, async {
            tokio::select! {
                result = &mut server => panic!("Task32 server ended before exhaustion: {result:?}"),
                result = &mut client => panic!("Task32 client ended before exhaustion: {result:?}"),
                event = client_log.wait(&exhausted_pred) => event,
            }
        })
        .await
        .expect("real NativeExhausted event inside derived whole-case deadline");
        let observations: Vec<_> = client_log
            .snapshot()
            .into_iter()
            .filter_map(|event| match event {
                RoleEvent::NativeOwner { observation, .. } => Some(observation),
                _ => None,
            })
            .collect();
        let exhausted_index = observations.iter().position(|observation|
            matches!(observation, NativeObservation::Exhausted { .. })
        ).expect("bounded role log retains the actual exhaustion observation");
        let prefix = &observations[..exhausted_index];
        let starts: Vec<_> = prefix.iter().filter_map(|observation| match observation {
            NativeObservation::AttemptStarted { attempt, .. } => Some(*attempt),
            _ => None,
        }).collect();
        let failures = prefix.iter().filter(|observation|
            matches!(observation, NativeObservation::AttemptFailed { .. })
        ).count();
        assert_eq!(starts, (1..=u64::from(policy.max_attempts)).collect::<Vec<_>>(),
            "ordinary attempt identities are distinct and sequential: {observations:?}");
        assert_eq!(failures, usize::try_from(policy.max_attempts).expect("default count fits usize"),
            "all ordinary dials genuinely failed before exhaustion: {observations:?}");
        assert!(!prefix.iter().any(|observation|
            matches!(observation, NativeObservation::Accepted { .. })
        ), "no genuine native success precedes ordinary exhaustion: {observations:?}");

        let RoleEvent::NativeOwner {
            observation: NativeObservation::Exhausted { at: exhaustion_ms },
            observed_at: exhaustion_at,
        } = exhausted else { unreachable!("exhaustion predicate selected owner exhaustion"); };
        // The real old Ygg TCP stream still echoes after the genuine exhaustion
        // barrier. Only afterward is the captured signed publication exposed.
        tokio::time::timeout_at(
            outer_deadline,
            echo_on_held_stream(
                &mut held_ygg,
                b"task32-old-ygg-stream-after-exhaustion-before-record",
                &mut server,
                &mut client,
                "Task32 old Ygg stream after exhaustion",
            ),
        )
        .await
        .expect("same held Ygg stream still echoes after the real exhaustion barrier");
        eprintln!("Task32 phase: exhausted at {exhaustion_ms} ms; old Ygg stream still echoes; exposing record");
        let mut record = Box::pin(client_peer.serve_record(&item));
        let accepted_pred = |event: &RoleEvent| {
            matches!(
                event,
                RoleEvent::NativeOwner {
                    observation: NativeObservation::Accepted { attempt, .. },
                    ..
                } if *attempt > u64::from(policy.max_attempts)
            )
        };
        let accepted = tokio::time::timeout_at(outer_deadline, async {
            tokio::select! {
                result = &mut server => panic!("Task32 server ended during renewed native dial: {result:?}"),
                result = &mut client => panic!("Task32 client ended during renewed native dial: {result:?}"),
                _ = &mut record => panic!("signed record responder ended before native recovery"),
                event = client_log.wait(&accepted_pred) => event,
            }
        })
        .await
        .expect("genuine native recovery dial within the derived deadline");
        let first_maintenance_ms = client_log
            .snapshot()
            .into_iter()
            .find_map(|event| match event {
                RoleEvent::NativeOwner {
                    observation: NativeObservation::AttemptStarted { attempt, at, .. },
                    ..
                } if attempt > u64::from(policy.max_attempts) => Some(at),
                _ => None,
            })
            .expect("owner actually starts a post-exhaustion maintenance attempt");
        assert!(
            first_maintenance_ms >= exhaustion_ms.saturating_add(policy.backoff_cap),
            "first maintenance dial started before retained backoff-cap cooldown"
        );
        let RoleEvent::NativeOwner {
            observation: NativeObservation::Accepted { at: accepted_ms, .. },
            observed_at: accepted_at,
        } = accepted else { unreachable!("accepted predicate selected an owner success"); };
        assert!(accepted_ms >= exhaustion_ms, "native success is after ordinary exhaustion");

        eprintln!("Task32 phase: genuine renewed native dial accepted at {accepted_ms} ms; stable hold");
        let native_route_pred = |event: &RoleEvent| matches!(event, RoleEvent::NativeRouteActive(_));
        let native_route = tokio::time::timeout_at(outer_deadline, async {
            tokio::select! {
                result = &mut server => panic!("Task32 server ended during stable hold: {result:?}"),
                result = &mut client => panic!("Task32 client ended during stable hold: {result:?}"),
                _ = &mut record => panic!("signed record responder ended during stable hold"),
                event = client_log.wait(&native_route_pred) => event,
            }
        })
        .await
        .expect("native route selection follows stable hold within derived bound");
        let RoleEvent::NativeRouteActive(route_at) = native_route else {
            unreachable!("native route predicate selected native route event");
        };
        let held_ms = u64::try_from(route_at.saturating_duration_since(accepted_at).as_millis())
            .unwrap_or(u64::MAX);
        assert!(
            held_ms >= policy.stable_hold.saturating_sub(1),
            "native active after {held_ms} ms; stable_hold={} ms",
            policy.stable_hold
        );
        assert!(route_at > exhaustion_at, "native selection follows real exhaustion");

        eprintln!("Task32 phase: native route active after {held_ms} ms; checking both TCP streams");
        let forwarding = async {
            forward_and_echo(
                listener_address,
                b"task32-new-native-tcp-stream",
                &mut server,
                &mut client,
                "Task32 new native TCP stream",
            )
            .await;
            echo_on_held_stream(
                &mut held_ygg,
                b"task32-same-old-ygg-stream-after-native-switch",
                &mut server,
                &mut client,
                "Task32 original Ygg stream after switch",
            )
            .await;
        };
        tokio::select! {
            () = forwarding => {},
            _ = &mut record => panic!("signed record responder ended during final stream checks"),
        }
        assert_eq!(echo.count(), 2, "old Ygg and new native streams each reached target");
        let admitted = server_log.snapshot();
        let ygg_index = admitted
            .iter()
            .position(|event| *event == RoleEvent::SessionAdmitted(PathKind::Yggdrasil))
            .expect("the original Ygg admission remains recorded");
        let native_index = admitted
            .iter()
            .position(|event| *event == RoleEvent::SessionAdmitted(PathKind::Native))
            .expect("server admitted the recovered native session");
        assert!(
            ygg_index < native_index,
            "native admission follows the original Ygg admission: {admitted:?}"
        );

        eprintln!("Task32 phase: both stream checks passed; joined shutdown");
        let _ = server_stop.send(());
        let _ = client_stop.send(());
        tokio::select! {
            () = shutdown_roles(&mut server, &mut client) => {},
            _ = &mut record => panic!("record responder ended during joined shutdown"),
        }
        eprintln!("Task32 phase: both role wrappers joined");
        drop(record);
        drop(held_ygg);
        echo.close().await;
        tokio::time::timeout(super::fixtures::ROLE_BUDGET, transit.close())
            .await
            .expect("Task32 transit close bound")
            .expect("transit closes cleanly");
        fixture.close().await;
        drop(service_peer);
        probe_claim_free(RESTORE_SERVER, "Task32 server key released").await;
        probe_claim_free(RESTORE_CLIENT, "Task32 client key released").await;
        probe_claim_free(RESTORE_TRANSIT, "Task32 transit key released").await;
        eprintln!("Task32 phase: all fixtures joined and key claims released");
    })
    .await
    .expect("Task32 real I/O recovery within derived policy and fixture bounds");
}
