//! Leaf L4b acceptance role test: two composed roles with a pinned relay coordinate a NAT punch
//! over the authenticated carrier link's side channel and carry one exact TCP echo over the
//! resulting direct (Native) session.
//!
//! Fake-NAT setup as in the Yggdrasil case: the server's punch seam supplies the mapped endpoint
//! its Answer carries, the exchange and probes stay production code. The Client has no direct
//! candidate and a silent Mainline bootstrap, so its only routes are the relay negotiation and
//! the punch. The punch counter proves which one produced the session: on loopback the relay
//! negotiation would reach a Native route too, so the route event alone proves nothing.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use iroh_base::PublicKey;
use tokio::sync::oneshot;

use crate::network::signaling::punch::carrier_punched_for_tests;
use crate::network::{Allowlist, Limits, RelayFixture};
use crate::path::PathKind;
use crate::startup::role::server_close::set_punch_candidates_for_tests;
use crate::startup::role::{ClientRole, RoleEvent, ServerRole};

use super::super::fixtures::{
    ROLE_BUDGET, client_role_config, echo_target, forward_and_echo, identity, probe_claim_free,
    pub_key_hex, role_logs, server_role_config, start_listener, tuned_policy,
};

// Seeds unused anywhere else in this binary (the key claim is process-wide).
const RELAY_PUNCH_SERVICE: u8 = 0x24;
const RELAY_PUNCH_CLIENT: u8 = 0x25;
const RELAY_PUNCH_TRANSIT: u8 = 0x26;
/// One dial attempt resolves for up to 5 s against the silent bootstrap, punches for half of the
/// rest, and a second attempt (`max_attempts: 2`) is the retry reserve.
const RELAY_PUNCH_BUDGET: Duration = Duration::from_secs(90);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pinned_relay_composition_punches_a_direct_session_over_the_carrier() {
    tokio::time::timeout(RELAY_PUNCH_BUDGET, async {
        let fixture = RelayFixture::start().await;
        let relay_id = fixture.address.peer_id().to_string();
        let relay_address = fixture.address.socket_addr();
        let (transit, transit_port) = start_listener(RELAY_PUNCH_TRANSIT).await;
        let transit_uri = format!("tcp://127.0.0.1:{transit_port}");
        let (echo, echo_address) = echo_target().await;

        // A bound and dropped UDP socket: a bootstrap that never answers.
        let dead_bootstrap = {
            let socket =
                std::net::UdpSocket::bind("127.0.0.1:0").expect("dead bootstrap binds loopback");
            match socket.local_addr().expect("dead bootstrap address") {
                SocketAddr::V4(address) => address,
                SocketAddr::V6(_) => panic!("loopback bootstrap binds IPv4"),
            }
        };

        let server_identity = identity(RELAY_PUNCH_SERVICE);
        let client_identity = identity(RELAY_PUNCH_CLIENT);
        let client_key =
            PublicKey::from_bytes(&client_identity.public_key_bytes()).expect("fixture client key");
        let server_config = server_role_config(
            echo_address,
            dead_bootstrap,
            &relay_id,
            relay_address,
            &transit_uri,
            "signal",
        );
        let client_config = client_role_config(
            &pub_key_hex(&server_identity),
            dead_bootstrap,
            &relay_id,
            relay_address,
            &transit_uri,
            "signal",
            None,
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

        // Fake-NAT seam for THIS server: the Answer carries loopback plus the real bound port.
        let server_native = server_role
            .native_addr()
            .expect("started server reports its native bound address");
        set_punch_candidates_for_tests(
            server_native.port(),
            vec![SocketAddr::from((
                Ipv4Addr::LOCALHOST,
                server_native.port(),
            ))],
        );

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

        let punched_before = carrier_punched_for_tests();
        {
            let mut server_shutdown = std::pin::pin!(async move {
                let _ = server_stop_rx.await;
            });
            let mut server_run = std::pin::pin!(server_role.run(&mut server_shutdown));
            let mut client_shutdown = std::pin::pin!(async move {
                let _ = client_stop_rx.await;
            });
            let mut client_run = std::pin::pin!(client_role.run(&mut client_shutdown));

            let route_active_native =
                |event: &RoleEvent| matches!(event, RoleEvent::RouteActive(PathKind::Native));
            let route = tokio::time::timeout(ROLE_BUDGET, async {
                tokio::select! {
                    result = &mut server_run => {
                        panic!("server ended awaiting the punch route: {result:?}")
                    }
                    result = &mut client_run => {
                        panic!("client ended awaiting the punch route: {result:?}")
                    }
                    event = client_log.wait(&route_active_native) => event,
                }
            })
            .await
            .expect("the client establishes a native route within the budget");
            assert_eq!(route, RoleEvent::RouteActive(PathKind::Native));
            assert!(
                carrier_punched_for_tests() > punched_before,
                "the native session came from the carrier punch, not from the relay negotiation"
            );

            let listener_ready = |event: &RoleEvent| matches!(event, RoleEvent::ListenerReady(_));
            let listener_address = client_log
                .find(&listener_ready)
                .map(|event| match event {
                    RoleEvent::ListenerReady(address) => address,
                    other => panic!("unexpected listener event: {other:?}"),
                })
                .expect("client listener became ready before dialing");
            tokio::time::timeout(ROLE_BUDGET, async {
                forward_and_echo(
                    listener_address,
                    b"shaar-l4b-punch",
                    &mut server_run,
                    &mut client_run,
                    "relay punch",
                )
                .await;
            })
            .await
            .expect("the forwarded echo completes within the budget");
            assert_eq!(echo.count(), 1, "one exact echo over the punched session");

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
        assert!(
            server_log
                .snapshot()
                .contains(&RoleEvent::SessionAdmitted(PathKind::Native)),
            "server admitted the punched native session: {:?}",
            server_log.snapshot()
        );

        let closed = tokio::time::timeout(ROLE_BUDGET, transit.close()).await;
        assert!(
            closed.is_ok() && closed.expect("checked").is_ok(),
            "transit closes cleanly after the relay punch case"
        );
        probe_claim_free(RELAY_PUNCH_SERVICE, "service identity claim released").await;
        probe_claim_free(RELAY_PUNCH_CLIENT, "client identity claim released").await;
        probe_claim_free(RELAY_PUNCH_TRANSIT, "transit identity claim released").await;
        set_punch_candidates_for_tests(server_native.port(), Vec::new());
    })
    .await
    .expect("relay punch role acceptance completes within its budget");
}
