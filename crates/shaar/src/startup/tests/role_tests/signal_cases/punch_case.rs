//! Leaf L4 acceptance role test: two relay-less composed roles coordinate a
//! NAT punch over the real Yggdrasil bridge control channel and carry one
//! exact TCP echo over the resulting direct (Native) path, while zero
//! application payload ever rides Yggdrasil (signal mode).
//!
//! Fake-NAT setup: the client carries a silent direct hint
//! (`127.0.0.1:1` — connection refused) so the direct-candidate phase fails
//! fast, and the server's punch test seam supplies the Answer's mapped
//! endpoint (`ServerRole::native_addr`), standing in for the NAT mapping a
//! real deployment would learn from its responder. The punch exchange
//! itself stays production code. Stderr traces `shaar: client punch ...` /
//! `shaar: server punch ...` are emitted per attempt by the punch module;
//! stderr is not asserted here.
//!
//! The overall 90 s budget (well inside two `ROLE_BUDGET`s) covers two dial
//! attempts by design: attempt 1's Offer can be swallowed by Yggdrasil path
//! discovery before the Answer returns, and the tuned `max_attempts: 2`
//! policy retries — attempt 2 completes the exchange.

use std::net::SocketAddr;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use iroh_base::PublicKey;
use tokio::sync::oneshot;

use crate::config::{ClientConfig, ClientOverrides};
use crate::network::{Allowlist, Limits};
use crate::path::PathKind;
use crate::startup::role::server_close::set_punch_candidates_for_tests;
use crate::startup::role::{ClientRole, RoleEvent, ServerRole};

use super::super::fixtures::{
    ROLE_BUDGET, echo_target, forward_and_echo, identity, probe_claim_free, pub_key_hex,
    reserve_tcp_port, reserve_udp_port, role_logs, server_role_config_without_relay,
    start_listener, tuned_policy,
};

/// Client role config text WITHOUT signaling relay fields: mirrors
/// [`crate::startup::tests::role_tests::fixtures::client_role_config`] with
/// the relay pair dropped, so the composed client startup never enters the
/// relay negotiation phase.
fn client_role_config_without_relay(
    server_key_hex: &str,
    bootstrap: SocketAddrV4,
    transit_uri: &str,
    fallback: &str,
    direct_hint: Option<SocketAddr>,
) -> ClientConfig {
    let mainline_bind = SocketAddrV4::new(Ipv4Addr::LOCALHOST, reserve_udp_port());
    let signaling_bind: SocketAddr = format!("127.0.0.1:{}", reserve_tcp_port())
        .parse()
        .expect("reserved signaling bind");
    let hint_line = direct_hint
        .map(|address| format!("server_address: {address}\n"))
        .unwrap_or_default();
    let text = format!(
        "server: {server_key_hex}\nlisten: 127.0.0.1:0\n{hint_line}fallback: {fallback}\n\
         network: {{\n    mainline: {{\n        bind: {mainline_bind}\n        bootstrap: [\n    \
         {bootstrap}\n        ]\n    }}\n    signaling: {{\n        bind: {signaling_bind}\n    \
         }}\n    ygg: {{\n        peers: [\n            {transit_uri}\n        ]\n    }}\n}}\n",
    );
    ClientConfig::from_text(&text, &ClientOverrides::default())
        .expect("fixture client role config parses")
}

// Fresh seeds per the fixtures.rs discipline comment: service 0x72, client
// 0x73, transit 0x74.
const PUNCH_SERVICE: u8 = 0x72;
const PUNCH_CLIENT: u8 = 0x73;
const PUNCH_TRANSIT: u8 = 0x74;
/// Covers two full dial attempts (`max_attempts: 2`), each bounded by the
/// 1.5 s punch exchange and the 2 s client probe window, plus startup.
const PUNCH_BUDGET: Duration = Duration::from_secs(90);
/// Deadline of the Ygg path warm-up probe (same value as the signal cases).
const PROBE_BUDGET: Duration = Duration::from_secs(10);

/// Bridge counters for failure messages: where did the exchange stop?
fn counters(who: &str, bridge: &shaar_ygg::YggBridge) -> String {
    format!(
        "{who} bridge: carrier_submitted={} control={} queued={} dropped={} ignored={}",
        bridge.carrier_submitted_datagrams(),
        bridge.control_datagrams(),
        bridge.queued_datagrams(),
        bridge.dropped_datagrams(),
        bridge.ignored_frames()
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn punch_exchange_establishes_the_direct_path_and_ygg_payload_stays_zero() {
    tokio::time::timeout(PUNCH_BUDGET, async {
        let (transit, transit_port) = start_listener(PUNCH_TRANSIT).await;
        let transit_uri = format!("tcp://127.0.0.1:{transit_port}");
        let (echo, echo_address) = echo_target().await;

        // Dead Mainline bootstrap for BOTH roles: bind a loopback UDP port,
        // take its address, then drop the socket. Composed startup tolerates
        // a dead bootstrap (readiness degrades only); no LoopbackPeer is
        // needed because no signed-record exchange is required here.
        let dead_bootstrap_v4 = {
            let socket =
                std::net::UdpSocket::bind("127.0.0.1:0").expect("dead bootstrap binds loopback");
            let address = socket.local_addr().expect("dead bootstrap address");
            let v4 = match address {
                SocketAddr::V4(v4) => v4,
                SocketAddr::V6(_) => panic!("loopback bootstrap binds IPv4"),
            };
            drop(socket);
            v4
        };

        let server_identity = identity(PUNCH_SERVICE);
        let client_identity = identity(PUNCH_CLIENT);
        let client_key =
            PublicKey::from_bytes(&client_identity.public_key_bytes()).expect("fixture client key");
        let server_config = server_role_config_without_relay(
            echo_address,
            dead_bootstrap_v4,
            &transit_uri,
            "signal",
        );
        let client_config = client_role_config_without_relay(
            &pub_key_hex(&server_identity),
            dead_bootstrap_v4,
            &transit_uri,
            "signal",
            Some("127.0.0.1:1".parse().expect("silent direct hint")),
        );

        let (server_log, client_log) = role_logs();
        let mut server_role = ServerRole::with_events(
            server_config,
            &server_identity,
            Allowlist::new(&[client_key]).expect("fixture allowlist"),
            Limits::new(4).expect("fixture limits"),
            tuned_policy(),
            server_log.clone(),
        )
        .expect("server role builds");
        let (server_stop, server_stop_rx) = oneshot::channel();
        tokio::time::timeout(ROLE_BUDGET, server_role.start())
            .await
            .expect("server start completes within the budget")
            .expect("server role starts");
        let server_bridge = server_role
            .ygg_bridge_for_tests()
            .expect("started server retains its Ygg bridge");

        // Fake-NAT seam, armed after start and before run: the responder's
        // per-call provider returns exactly this mapped endpoint, so the
        // Answer carries the server's externally visible address. The composed
        // endpoint reports its bind (a wildcard is never a valid candidate), so
        // the mapped endpoint is loopback plus the real bound port.
        let server_native = server_role
            .native_addr()
            .expect("started server reports its native bound address");
        set_punch_candidates_for_tests(vec![SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            server_native.port(),
        ))]);

        let mut client_role = ClientRole::with_events(
            client_config,
            &client_identity,
            Limits::new(4).expect("fixture limits"),
            tuned_policy(),
            client_log.clone(),
        )
        .expect("client role builds");
        let (client_stop, client_stop_rx) = oneshot::channel();
        tokio::time::timeout(ROLE_BUDGET, client_role.start())
            .await
            .expect("client start completes within the budget")
            .expect("client role starts");
        let client_bridge = client_role
            .ygg_bridge_for_tests()
            .expect("started client retains its Ygg bridge");

        // Warm the Yggdrasil path in both directions with the bridge's own
        // authenticated Ping/Pong (it retransmits until answered): cold path
        // discovery is Yggdrasil's convergence, not the punch exchange under
        // test. Bridge tasks run on their own, so no role loop is needed yet.
        client_bridge
            .probe(server_identity.public_key_bytes(), PROBE_BUDGET)
            .await
            .expect("real authenticated Ygg Ping/Pong warms the path");

        // Pinned role loops and shutdown waiters live only in this lexical
        // scope; it ends before shutdown reborrows either role. Role futures
        // are driven in-body (they are not Send; nothing is spawned).
        {
            let mut server_shutdown = std::pin::pin!(async move {
                let _ = server_stop_rx.await;
            });
            let mut server_run = std::pin::pin!(server_role.run(&mut server_shutdown));
            let mut client_shutdown = std::pin::pin!(async move {
                let _ = client_stop_rx.await;
            });
            let mut client_run = std::pin::pin!(client_role.run(&mut client_shutdown));

            // The route is the punch-established session: the refused silent
            // hint candidate cannot have produced a Native session, so a
            // `RouteActive(Native)` here proves the coordinated exchange
            // selected the direct path. An attempt-1 Offer may be swallowed
            // by Ygg path discovery; the retry policy covers it.
            let route_active_native =
                |event: &RoleEvent| matches!(event, RoleEvent::RouteActive(PathKind::Native));
            let route = tokio::time::timeout(ROLE_BUDGET, async {
                tokio::select! {
                    result = &mut server_run => {
                        panic!(
                            "server ended awaiting the punch route: {result:?}; {}; {}",
                            counters("server", &server_bridge),
                            counters("client", &client_bridge)
                        )
                    }
                    result = &mut client_run => {
                        panic!(
                            "client ended awaiting the punch route: {result:?}; {}; {}",
                            counters("server", &server_bridge),
                            counters("client", &client_bridge)
                        )
                    }
                    event = client_log.wait(&route_active_native) => event,
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "client never established the punch-coordinated native route; {}; {}",
                    counters("server", &server_bridge),
                    counters("client", &client_bridge)
                )
            });
            assert_eq!(route, RoleEvent::RouteActive(PathKind::Native));

            let listener_ready = |event: &RoleEvent| matches!(event, RoleEvent::ListenerReady(_));
            let listener_address = client_log
                .find(&listener_ready)
                .and_then(|event| match event {
                    RoleEvent::ListenerReady(address) => Some(address),
                    other => panic!("unexpected listener event: {other:?}"),
                })
                .expect("client listener became ready before dialing");

            // Exact request/reply over the direct path chosen after the
            // coordinated exchange; both role loops stay polled throughout.
            tokio::time::timeout(ROLE_BUDGET, async {
                forward_and_echo(
                    listener_address,
                    b"shaar-l4-punch",
                    &mut server_run,
                    &mut client_run,
                    "punch",
                )
                .await;
            })
            .await
            .expect("punch-path forwarded echo completes within the budget");
            assert_eq!(echo.count(), 1, "one exact echo over the direct path");

            // Stop and join both roles; never repoll a completed run future.
            let _ = server_stop.send(());
            let _ = client_stop.send(());
            let mut server_done = false;
            let mut client_done = false;
            tokio::time::timeout(ROLE_BUDGET, async {
                while !server_done || !client_done {
                    tokio::select! {
                        result = &mut server_run, if !server_done => {
                            result.expect("server run ends successfully");
                            server_done = true;
                        }
                        result = &mut client_run, if !client_done => {
                            result.expect("client run ends successfully");
                            client_done = true;
                        }
                    }
                }
            })
            .await
            .expect("both role run loops join within the budget");
        }

        // Joined shutdown reborrows each role; bridge Arc clones survive for
        // the final counter observations.
        {
            let server_close = server_role.shutdown();
            let client_close = client_role.shutdown();
            let (server_result, client_result) = tokio::join!(
                tokio::time::timeout(ROLE_BUDGET, server_close),
                tokio::time::timeout(ROLE_BUDGET, client_close),
            );
            server_result
                .expect("server joined close completes within the budget")
                .expect("server joined close succeeds");
            client_result
                .expect("client joined close completes within the budget")
                .expect("client joined close succeeds");
        }

        // Log oracles: the direct session was admitted, no Ygg session ever
        // was, and neither side acquired a Ygg payload pair.
        assert!(
            server_log
                .snapshot()
                .contains(&RoleEvent::SessionAdmitted(PathKind::Native)),
            "server admitted the punch-established native session: {:?}",
            server_log.snapshot()
        );
        assert!(
            !server_log
                .snapshot()
                .contains(&RoleEvent::SessionAdmitted(PathKind::Yggdrasil)),
            "server admitted no Yggdrasil session: {:?}",
            server_log.snapshot()
        );
        for (who, log) in [("server", &server_log), ("client", &client_log)] {
            assert!(
                log.find(&|event| matches!(event, RoleEvent::YggPayloadAcquired(false)))
                    .is_some(),
                "{who} recorded the signal-mode payload verdict: {:?}",
                log.snapshot()
            );
            assert!(
                log.find(&|event| matches!(event, RoleEvent::YggPayloadAcquired(true)))
                    .is_none(),
                "{who} never acquired a Ygg payload pair: {:?}",
                log.snapshot()
            );
        }

        // Bridge oracles, snapshotted on BOTH bridges right after the echo
        // and again through joined shutdown: in signal mode the payload
        // table admitted nothing, while the offer/answer exchange visibly
        // rode the control channel (control datagrams plus the carrier
        // envelopes the punch exchange itself submitted).
        let echo_counts = |who: &'static str, bridge: &std::sync::Arc<shaar_ygg::YggBridge>| {
            // The payload table admitted nothing. `dropped` is not asserted: an
            // Offer that reaches a peer before it registered its control
            // capability is legitimately refused by both tables.
            assert_eq!(
                bridge.queued_datagrams(),
                0,
                "{who} admitted no carrier payload in signal mode"
            );
            assert!(
                bridge.carrier_submitted_datagrams() > 0,
                "{who} submitted the punch exchange as carrier envelopes"
            );
            assert!(
                bridge.control_datagrams() > 0,
                "{who} exchanged punch messages on the control channel"
            );
            (
                bridge.queued_datagrams(),
                bridge.dropped_datagrams(),
                bridge.carrier_submitted_datagrams(),
                bridge.control_datagrams(),
            )
        };
        let server_at_echo = echo_counts("server", &server_bridge);
        let client_at_echo = echo_counts("client", &client_bridge);

        echo.close().await;
        // Lifetime counters through joined shutdown: the payload table still
        // admitted nothing, and the exchange counters only grew.
        for (who, bridge, at_echo) in [
            ("server", &server_bridge, server_at_echo),
            ("client", &client_bridge, client_at_echo),
        ] {
            let after = (
                bridge.queued_datagrams(),
                bridge.dropped_datagrams(),
                bridge.carrier_submitted_datagrams(),
                bridge.control_datagrams(),
            );
            assert_eq!(after.0, 0, "{who} admitted no carrier payload at all");
            assert!(
                after.2 >= at_echo.2 && after.3 >= at_echo.3,
                "{who} exchange counters never shrink: {after:?}"
            );
        }

        let closed = tokio::time::timeout(ROLE_BUDGET, transit.close()).await;
        assert!(
            closed.is_ok() && closed.expect("checked").is_ok(),
            "transit closes cleanly after the punch case"
        );
        probe_claim_free(PUNCH_SERVICE, "service identity claim released").await;
        probe_claim_free(PUNCH_CLIENT, "client identity claim released").await;
        probe_claim_free(PUNCH_TRANSIT, "transit identity claim released").await;

        // Reset the fake-NAT seam so no other test in this binary inherits
        // the injected candidates.
        set_punch_candidates_for_tests(Vec::new());
    })
    .await
    .expect("punch role acceptance completes within its budget");
}
