//! Location cases (5c criteria 1 and 2) over the production role
//! entrypoints: key-only service location through a real signed Mainline
//! publication and key+relay-only location with native payload forwarding.
//! The relay case captures both actual sessions before forwarding, observes
//! semantic path frames through registered close receipts, and requires complete
//! TX attribution. Noq's close-only transmit branch sends no later APP; checking
//! both senders therefore does not require pretending close stats are RX drain.
//! Raw transport counters and fixture.close are not zero-APP evidence.
//!
//! Role futures are PINNED and driven inside the test body (the client role
//! future is not `Send`); every fixture wait keeps the role futures as
//! select arms so a role that ends early panics with its truthful result.

use iroh_base::PublicKey;

use tokio::sync::oneshot;

use crate::config::{ClientConfig, ServerConfig};
use crate::identity::Identity;
use crate::native_discovery::runtime::owner::LoopbackPeer;
use crate::network::{Allowlist, Limits, RelayFixture};
use crate::path::PathKind;
use crate::startup::role::{RoleEvent, serve_client_with_events, serve_server_with_events};

use super::fixtures::{
    ROLE_BUDGET, admit_and_capture, arm_client_on_peer, bootstrap_v4, client_role_config,
    dead_relay_address, echo_target, forward_and_echo, identity, pin_role, probe_claim_free,
    pub_key_hex, role_logs, server_role_config, silent_udp, start_listener, tuned_policy,
    wait_role_event,
};

// Unique seeds (see the fixtures.rs discipline comment): case 1 uses
// identity 0x51 / client 0x52 / transit 0x53; case 2 uses 0x54 / 0x55 /
// 0x56.
const CASE_ONE_SERVICE: u8 = 0x51;
const CASE_ONE_CLIENT: u8 = 0x52;
const CASE_ONE_TRANSIT: u8 = 0x53;
const CASE_TWO_SERVICE: u8 = 0x54;
const CASE_TWO_CLIENT: u8 = 0x55;
const CASE_TWO_TRANSIT: u8 = 0x56;

// Regressions caught: replacing the client's cold key-directed Mainline GET
// with the legacy direct locator, skipping the lookup and reusing the
// server's PUT as the client's knowledge, answering the resolve with a fake
// record instead of the independently captured signed PUT — and, via the
// wire-level GET oracle, any "resolve" that never sends a service-key GET
// against the bootstrap at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_only_client_resolves_the_signed_publication_and_forwards_a_byte() {
    tokio::time::timeout(ROLE_BUDGET, async {
        let mut service_peer = LoopbackPeer::bind().await;
        let mut client_peer = LoopbackPeer::bind().await;
        let fixture = RelayFixture::start().await;
        let relay_id = fixture.address.peer_id().to_string();
        let relay_address = fixture.address.socket_addr();
        let (transit, transit_port) = start_listener(CASE_ONE_TRANSIT).await;
        let transit_uri = format!("tcp://127.0.0.1:{transit_port}");
        let (echo, echo_address) = echo_target().await;

        let server_identity: &'static Identity = Box::leak(Box::new(identity(CASE_ONE_SERVICE)));
        let client_identity: &'static Identity = Box::leak(Box::new(identity(CASE_ONE_CLIENT)));
        let client_key =
            PublicKey::from_bytes(client_identity.public_key_bytes()).expect("fixture client key");
        let server_config: &'static ServerConfig = Box::leak(Box::new(server_role_config(
            echo_address,
            bootstrap_v4(&service_peer),
            &relay_id,
            relay_address,
            &transit_uri,
            "standby",
        )));
        // The client's relay settings point at a deliberately dead address:
        // relay negotiation CANNOT rescue a failed resolve, so the only way
        // to the server address is the cold Mainline GET.
        let dead_relay = dead_relay_address();
        let client_config: &'static ClientConfig = Box::leak(Box::new(client_role_config(
            &pub_key_hex(server_identity),
            bootstrap_v4(&client_peer),
            &relay_id,
            dead_relay,
            &transit_uri,
            "standby",
            None,
        )));
        assert!(
            client_config.server_address().is_none(),
            "key-only case carries no legacy direct locator"
        );

        // Server role: admission and its real initial PUT are concurrently
        // captured and the PUT acknowledged; the signed item is kept for the
        // record server and the GET oracle.
        let (server_stop, server_stop_rx) = oneshot::channel();
        let (server_log, _unused_log) = role_logs();
        let mut server = pin_role(serve_server_with_events(
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
            admit_and_capture(&mut service_peer, &mut server, &server_log, ROLE_BUDGET).await;

        // Client role: its own initial PUT on the client peer and the
        // listener-ready event are concurrently observed (the fixture also
        // acknowledges the PUT); NO record server is armed yet, so nothing
        // can answer the client's upcoming GET in advance. Keep the admitted
        // server role continuously driven while client arming waits.
        let (client_stop, mut client, client_log, listener_address) = tokio::select! {
            armed = arm_client_on_peer(
                client_config,
                client_identity,
                &mut client_peer,
                tuned_policy(),
                ROLE_BUDGET,
            ) => armed,
            result = &mut server => panic!("server ended while arming client: {result:?}"),
        };

        // GET ORACLE: with the client relay dead and no record server armed,
        // the ONLY possible discovery path is the client's own service-key
        // GET — observe it actually hit the wire at the fixture bootstrap
        // before any record is served.
        let target = n0_mainline::MutableItem::target_from_key(item.key(), None);
        let (_get_source, _get_payload) = tokio::time::timeout(ROLE_BUDGET, async {
            tokio::select! {
                g = client_peer.capture_get(target) => g,
                result = &mut client => panic!(
                    "client ended before its cold service-key GET: {result:?}"
                ),
                result = &mut server => panic!("server ended early: {result:?}"),
            }
        })
        .await
        .expect("the client's service-key GET is observed on the wire within the budget");

        // Only now serve the independently captured signed publication and
        // await the resolved route as a native-path positive. It does not
        // establish zero relay application bytes.
        let mut record_server = Box::pin(client_peer.serve_record(&item));
        let route_active_native =
            |event: &RoleEvent| matches!(event, RoleEvent::RouteActive(PathKind::Native));
        let route = tokio::time::timeout(ROLE_BUDGET, async {
            tokio::select! {
                event = client_log.wait(&route_active_native) => event,
                result = &mut client => panic!(
                    "client ended while resolving through its cold GET: {result:?}"
                ),
                result = &mut server => panic!("server ended early: {result:?}"),
                _ = &mut record_server => panic!("record server terminated"),
            }
        })
        .await
        .expect("the client resolves the service key through its own cold Mainline GET");
        assert_eq!(
            route,
            RoleEvent::RouteActive(PathKind::Native),
            "the observed route is native"
        );
        // Forwarding positive control: the byte pattern crosses the client
        // listener, native session, server role and fixed loopback target.
        // Keep the actual signed-record responder polled through the echo.
        tokio::select! {
            _ = forward_and_echo(
                listener_address,
                b"shaar-5c-case-one",
                &mut server,
                &mut client,
                "case one",
            ) => {}
            _ = &mut record_server => panic!("record responder terminated during native echo"),
        }
        assert_eq!(
            echo.count(),
            1,
            "exactly one fixed-target connection served the forwarded pattern"
        );

        // Stop both roles before awaiting either; completion guards prevent a
        // completed role future from being polled again. Keep the real record
        // responder live while the owning roles drain.
        let _ = server_stop.send(());
        let _ = client_stop.send(());
        let mut server_done = false;
        let mut client_done = false;
        tokio::time::timeout(ROLE_BUDGET, async {
            while !server_done || !client_done {
                tokio::select! {
                    result = &mut server, if !server_done => {
                        assert!(result.is_ok(), "server role shutdown succeeds: {result:?}");
                        server_done = true;
                    }
                    result = &mut client, if !client_done => {
                        assert!(result.is_ok(), "client role shutdown succeeds: {result:?}");
                        client_done = true;
                    }
                    _ = &mut record_server => panic!("record responder terminated during role shutdown"),
                }
            }
        })
        .await
        .expect("both role futures complete within the budget");
        // Cleanup truthfulness: transit key claim released, the relay
        // fixture's joined close (bookkeeping + port rebind) and the bounded
        // echo-target join all succeed; every seed claim is released.
        echo.close().await;
        let closed = tokio::time::timeout(ROLE_BUDGET, transit.close()).await;
        assert!(
            closed.is_ok() && closed.expect("checked").is_ok(),
            "owned transit closes cleanly"
        );
        fixture.close().await;
        probe_claim_free(CASE_ONE_SERVICE, "server identity claim released").await;
        probe_claim_free(CASE_ONE_CLIENT, "client identity claim released").await;
        probe_claim_free(CASE_ONE_TRANSIT, "transit identity claim released").await;
    })
    .await
    .expect("case 1 completes within the role budget");
}

// Regressions caught: a dialer that aborts the attempt when the cold
// Mainline resolve fails instead of falling through to the key-directed
// pinned-relay negotiation, a relay negotiation that yields a RELAY session,
// or a negotiation that truncates/drops application bytes. Both actual sessions
// must retain complete signaling-path-zero APP and native STREAM evidence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pinned_relay_negotiation_carries_native_payload_with_zero_relay_payload() {
    tokio::time::timeout(ROLE_BUDGET, async {
        let mut service_peer = LoopbackPeer::bind().await;
        // Cold lookup is DELIBERATELY unavailable: the only bootstrap is a
        // bound UDP blackhole that never replies, so GETs time out inside the
        // resolve budget (SilentUdp keeps the socket alive until drop).
        let silent = silent_udp();
        let fixture = RelayFixture::start().await;
        let relay_id = fixture.address.peer_id().to_string();
        let relay_address = fixture.address.socket_addr();
        let (transit, transit_port) = start_listener(CASE_TWO_TRANSIT).await;
        let transit_uri = format!("tcp://127.0.0.1:{transit_port}");
        let (echo, echo_address) = echo_target().await;

        let server_identity: &'static Identity = Box::leak(Box::new(identity(CASE_TWO_SERVICE)));
        let client_identity: &'static Identity = Box::leak(Box::new(identity(CASE_TWO_CLIENT)));
        let client_key =
            PublicKey::from_bytes(client_identity.public_key_bytes()).expect("fixture client key");
        let server_config: &'static ServerConfig = Box::leak(Box::new(server_role_config(
            echo_address,
            bootstrap_v4(&service_peer),
            &relay_id,
            relay_address,
            &transit_uri,
            "standby",
        )));
        let client_bootstrap = match silent.address {
            std::net::SocketAddr::V4(address) => address,
            std::net::SocketAddr::V6(_) => panic!("silent bootstrap must bind IPv4"),
        };
        // REAL relay settings in BOTH configs: negotiation goes through the
        // pinned relay, while the cold lookup stays dead.
        let client_config: &'static ClientConfig = Box::leak(Box::new(client_role_config(
            &pub_key_hex(server_identity),
            client_bootstrap,
            &relay_id,
            relay_address,
            &transit_uri,
            "signal",
            None,
        )));
        assert!(
            client_config.server_address().is_none(),
            "relay-only case carries no legacy direct locator; the key plus the pinned \
             relay are the only service locators"
        );

        let (server_stop, server_stop_rx) = oneshot::channel();
        let (mut server_log, _unused_log) = role_logs();
        let server_frames = server_log.observe_native_frames();
        let mut server = pin_role(serve_server_with_events(
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
        let _item =
            admit_and_capture(&mut service_peer, &mut server, &server_log, ROLE_BUDGET).await;

        // Client role armed inline (silent bootstrap: arm_client_on_peer's
        // PUT-capture loop cannot be used against a blackhole peer); the
        // listener-ready event is awaited while driving the pinned future.
        let (client_stop, client_stop_rx) = oneshot::channel();
        let (mut client_log, _unused_client_log) = role_logs();
        let client_frames = client_log.observe_native_frames();
        let mut client = pin_role(serve_client_with_events(
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
        let listener_address = tokio::time::timeout(ROLE_BUDGET, async {
            loop {
                tokio::select! {
                    event = client_log.wait(&listener_ready) => match event {
                        RoleEvent::ListenerReady(address) => break address,
                        other => panic!(
                            "unexpected role event while awaiting the listener: {other:?}"
                        ),
                    },
                    result = &mut client => panic!(
                        "client ended while awaiting its listener: {result:?}"
                    ),
                    result = &mut server => panic!("server ended while awaiting client listener: {result:?}"),
                }
            }
        })
        .await
        .expect("client listener becomes ready within the budget");

        // Route observation is a native-path positive; it does not establish
        // that no application bytes traversed the relay.
        let route_active = |event: &RoleEvent| matches!(event, RoleEvent::RouteActive(_));
        let route = tokio::time::timeout(
            ROLE_BUDGET,
            wait_role_event(
                &mut server,
                &mut client,
                &server_log,
                &client_log,
                route_active,
                "relay negotiation case",
            ),
        )
        .await
        .expect("the client reaches a route through relay negotiation");
        assert_eq!(
            route,
            RoleEvent::RouteActive(PathKind::Native),
            "negotiation through the pinned relay selects the native path"
        );

        // Positive forwarding control: the 256 KiB pattern is delivered
        // byte-for-byte over the observed native session to the real echo
        // target. Payload size and echo success do not prove zero relay APP.
        let payload = vec![0xA5_u8; 256 * 1024];
        forward_and_echo(
            listener_address,
            &payload,
            &mut server,
            &mut client,
            "case two",
        )
        .await;
        assert_eq!(
            echo.count(),
            1,
            "exactly one fixed-target connection served the forwarded pattern"
        );
        assert!(
            server_log
                .find(&|event| *event == RoleEvent::SessionAdmitted(PathKind::Native))
                .is_some(),
            "server recorded real native-session admission alongside route and echo evidence"
        );
        assert!(
            fixture.relayed_bytes() > 0,
            "raw relay control/transport bytes observed after successful negotiation and native echo"
        );

        // Stop both roles before awaiting either; completion guards prevent a
        // completed role future from being polled again.
        let _ = server_stop.send(());
        let _ = client_stop.send(());
        let mut server_done = false;
        let mut client_done = false;
        tokio::time::timeout(ROLE_BUDGET, async {
            while !server_done || !client_done {
                tokio::select! {
                    result = &mut server, if !server_done => {
                        assert!(result.is_ok(), "server role shutdown succeeds: {result:?}");
                        server_done = true;
                    }
                    result = &mut client, if !client_done => {
                        assert!(result.is_ok(), "client role shutdown succeeds: {result:?}");
                        client_done = true;
                    }
                }
            }
        })
        .await
        .expect("both role futures complete within the budget");
        tokio::time::timeout(ROLE_BUDGET, async {
            tokio::join!(server_frames.finish(), client_frames.finish());
        })
        .await
        .expect("both actual sessions retain complete signaling-zero APP evidence through close");

        echo.close().await;
        let closed = tokio::time::timeout(ROLE_BUDGET, transit.close()).await;
        assert!(
            closed.is_ok() && closed.expect("checked").is_ok(),
            "owned transit closes cleanly"
        );
        // The fixture close is lifecycle hygiene only, not relay-payload evidence.
        fixture.close().await;
        drop(silent);
        probe_claim_free(CASE_TWO_SERVICE, "server identity claim released").await;
        probe_claim_free(CASE_TWO_CLIENT, "client identity claim released").await;
        probe_claim_free(CASE_TWO_TRANSIT, "transit identity claim released").await;
    })
    .await
    .expect("case 2 completes within the role budget");
}
