//! Signal case (5c criterion "Signal mode with no Ygg application payload")
//! over production role entrypoints: real Ygg Ping/Pong stays healthy while
//! both retained bridges submit zero carrier datagrams. A real signed
//! Mainline record resolves a native route and carries a TCP echo to the fixed
//! target. No Ygg application path is built.

use std::time::Duration;

use iroh_base::PublicKey;
use tokio::sync::oneshot;

use crate::identity::Identity;
use crate::native_discovery::runtime::owner::LoopbackPeer;
use crate::network::{Allowlist, Limits, RelayFixture};
use crate::path::PathKind;
use crate::startup::role::{ClientRole, RoleEvent, ServerRole};

use super::fixtures::{
    bootstrap_v4, client_role_config, echo_target, forward_and_echo, identity, probe_claim_free,
    pub_key_hex, role_logs, server_role_config, start_listener, tuned_policy,
};

// Unique seeds (see the fixtures.rs discipline comment): server 0x5E, client
// 0x5F, transit 0x60.
const CASE_S_SERVICE: u8 = 0x5E;
const CASE_S_CLIENT: u8 = 0x5F;
const CASE_S_TRANSIT: u8 = 0x60;
const SIGNAL_BUDGET: Duration = Duration::from_secs(60);
const PROBE_BUDGET: Duration = Duration::from_secs(10);

fn key32(identity: &Identity) -> [u8; 32] {
    identity.public_key_bytes()
}

// The observation boundary is invocation of transport.send_to for an encoded
// carrier envelope, before its async completion. This says nothing about wire
// drain; Ping/Pong uses a distinct, uncounted send path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signal_mode_negotiates_but_ygg_never_carries_application_payload() {
    tokio::time::timeout(SIGNAL_BUDGET, async {
        // Independent peers keep real startup PUT capture separate from the
        // Mainline responder serving the captured signed service publication.
        let mut service_peer = LoopbackPeer::bind().await;
        let mut client_peer = LoopbackPeer::bind().await;
        let fixture = RelayFixture::start().await;
        let relay_id = fixture.address.peer_id().to_string();
        let relay_address = fixture.address.socket_addr();
        let (transit, transit_port) = start_listener(CASE_S_TRANSIT).await;
        let transit_uri = format!("tcp://127.0.0.1:{transit_port}");
        let (echo, echo_address) = echo_target().await;

        // Owned configs and local identities; no leaked statics.
        let server_identity = identity(CASE_S_SERVICE);
        let client_identity = identity(CASE_S_CLIENT);
        let client_key = PublicKey::from_bytes(client_identity.public_key_bytes())
            .expect("fixture client key");
        let server_config = server_role_config(
            echo_address,
            bootstrap_v4(&service_peer),
            &relay_id,
            relay_address,
            &transit_uri,
            "signal",
        );
        let client_config = client_role_config(
            &pub_key_hex(&server_identity),
            bootstrap_v4(&client_peer),
            &relay_id,
            relay_address,
            &transit_uri,
            "signal",
            None,
        );
        assert!(client_config.server_address().is_none());

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

        // Start and real PUT capture use separate completion guards. The capture
        // future is scoped to this race; if start wins, it is safely re-armed
        // while the role runs. No peer-borrowing holder survives to ACK.
        let (server_started, captured_server_put) = {
            let mut capture = Box::pin(service_peer.capture_put_record());
            let mut start = Box::pin(server_role.start());
            tokio::time::timeout(SIGNAL_BUDGET, async {
                tokio::select! {
                    result = &mut start => (Some(result), None),
                    captured = capture.as_mut() => (None, Some(captured)),
                }
            })
            .await
            .expect("server start or publication PUT completes")
        };
        let mut server_item = None;
        if let Some((source, transaction, _signed, item)) = captured_server_put {
            service_peer.acknowledge(source, &transaction).await;
            server_item = Some(item);
        }
        if let Some(result) = server_started {
            result.expect("server starts independently of PUT capture");
        } else {
            let start = server_role.start();
            tokio::time::timeout(SIGNAL_BUDGET, start)
                .await
                .expect("server start resumes after real PUT ACK")
                .expect("server role starts");
        }
        let server_bridge = server_role
            .ygg_bridge_for_tests()
            .expect("started server retains its Ygg bridge");
        // First possible server bridge observation, before role.run.
        let server_counts_at_bridge = (
            server_bridge.queued_datagrams(),
            server_bridge.dropped_datagrams(),
            server_bridge.carrier_submitted_datagrams(),
        );
        assert_eq!(server_counts_at_bridge.2, 0, "no carrier submission at first availability");

        let mut client_role = ClientRole::with_events(
            client_config,
            &client_identity,
            Limits::new(4).expect("fixture limits"),
            tuned_policy(),
            client_log.clone(),
        )
        .expect("client role builds");
        let (client_stop, client_stop_rx) = oneshot::channel();

        // Pinned role loops and shutdown waiters live only in this lexical
        // scope. It ends before shutdown reborrows either role.
        let client_bridge = {
            let mut server_shutdown = std::pin::pin!(async move {
                let _ = server_stop_rx.await;
            });
            let mut server_run = std::pin::pin!(server_role.run(&mut server_shutdown));

            if server_item.is_none() {
                let (source, transaction, _signed, item) = {
                    let mut capture = Box::pin(service_peer.capture_put_record());
                    tokio::time::timeout(
                        SIGNAL_BUDGET,
                        async {
                            tokio::select! {
                                captured = capture.as_mut() => captured,
                                result = &mut server_run => {
                                    panic!("server ended during publication PUT capture: {result:?}")
                                }
                            }
                        },
                    )
                    .await
                    .expect("server's actual publication PUT is captured")
                };
                server_item = Some(item);
                tokio::select! {
                    _ = service_peer.acknowledge(source, &transaction) => {}
                    result = &mut server_run => {
                        panic!("server ended while publication PUT was ACKed: {result:?}")
                    }
                }
            }

            // Client start and PUT capture have independent completion guards.
            // The capture is scoped to this race; if start wins, it is safely
            // re-armed under client.run. No holder survives to peer ACK.
            let (client_started, captured_client_put) = {
                let mut capture = Box::pin(client_peer.capture_put_record());
                let mut start = Box::pin(client_role.start());
                tokio::time::timeout(SIGNAL_BUDGET, async {
                    tokio::select! {
                        result = &mut start => (Some(result), None),
                        captured = capture.as_mut() => (None, Some(captured)),
                        result = &mut server_run => {
                            panic!("server ended during client startup/capture: {result:?}")
                        }
                    }
                })
                .await
                .expect("client start or its PUT capture completes")
            };
            let client_put_captured = captured_client_put.is_some();
            if let Some((source, transaction, _signed, _item)) = captured_client_put {
                tokio::select! {
                    _ = client_peer.acknowledge(source, &transaction) => {}
                    result = &mut server_run => {
                        panic!("server ended while client PUT was ACKed: {result:?}")
                    }
                }
            }
            if let Some(result) = client_started {
                result.expect("client starts independently of PUT capture");
            } else {
                let start = client_role.start();
                tokio::time::timeout(SIGNAL_BUDGET, async {
                    tokio::select! {
                        result = start => result,
                        result = &mut server_run => {
                            panic!("server ended while client start resumed: {result:?}")
                        }
                    }
                })
                .await
                .expect("client start resumes after its real PUT ACK")
                .expect("client role starts");
            }

            let client_bridge = client_role
                .ygg_bridge_for_tests()
                .expect("started client retains its Ygg bridge");
            // First client bridge observation, before role.run.
            let client_counts_at_bridge = (
                client_bridge.queued_datagrams(),
                client_bridge.dropped_datagrams(),
                client_bridge.carrier_submitted_datagrams(),
            );
            assert_eq!(client_counts_at_bridge.2, 0, "no carrier submission at first availability");
            let mut client_shutdown = std::pin::pin!(async move {
                let _ = client_stop_rx.await;
            });
            let mut client_run = std::pin::pin!(client_role.run(&mut client_shutdown));

            // If start won the race, re-arm the real PUT capture until
            // client.run drives any role-run-dependent publication work. Both
            // roles stay polled; the scoped capture is gone before peer ACK.
            if !client_put_captured {
                let (source, transaction, _signed, _item) = {
                    let mut capture = Box::pin(client_peer.capture_put_record());
                    tokio::time::timeout(
                        SIGNAL_BUDGET,
                        async {
                            tokio::select! {
                                captured = capture.as_mut() => captured,
                                result = &mut server_run => {
                                    panic!("server ended during client PUT capture: {result:?}")
                                }
                                result = &mut client_run => {
                                    panic!("client ended during its PUT capture: {result:?}")
                                }
                            }
                        },
                    )
                    .await
                    .expect("client's actual publication PUT is captured")
                };
                tokio::select! {
                    _ = client_peer.acknowledge(source, &transaction) => {}
                    result = &mut server_run => {
                        panic!("server ended while client PUT was ACKed: {result:?}")
                    }
                    result = &mut client_run => {
                        panic!("client ended while its PUT was ACKed: {result:?}")
                    }
                }
            }

            // Actual signed-record responder and both roles are polled for all
            // dependent operations. The client PUT was ACKed before this GET loop.
            let item = server_item.as_ref().expect("server signed item retained");
            let mut record_server = Box::pin(client_peer.serve_record(item));
            let listener_ready = |event: &RoleEvent| matches!(event, RoleEvent::ListenerReady(_));
            let listener_address = tokio::time::timeout(SIGNAL_BUDGET, async {
                tokio::select! {
                    result = &mut server_run => panic!("server ended awaiting listener: {result:?}"),
                    result = &mut client_run => panic!("client ended awaiting listener: {result:?}"),
                    result = &mut record_server => panic!("signed Mainline responder terminated: {result:?}"),
                    event = client_log.wait(&listener_ready) => match event {
                        RoleEvent::ListenerReady(address) => address,
                        other => panic!("unexpected listener event: {other:?}"),
                    }
                }
            })
            .await
            .expect("client listener becomes ready");

            // Positive control: real authenticated Ping/Pong on the retained
            // client bridge. Both roles and actual Mainline responder stay live.
            let probed = tokio::time::timeout(SIGNAL_BUDGET, async {
                tokio::select! {
                    probed = client_bridge.probe(key32(&server_identity), PROBE_BUDGET) => probed,
                    result = &mut server_run => panic!("server ended during Ygg control probe: {result:?}"),
                    result = &mut client_run => panic!("client ended during Ygg control probe: {result:?}"),
                    result = &mut record_server => panic!("signed Mainline responder terminated: {result:?}"),
                }
            })
            .await
            .expect("Ygg control probe completes within budget")
            .expect("real authenticated Ygg Ping/Pong succeeds");
            assert!(probed <= PROBE_BUDGET, "probe answered within its deadline");
            assert_eq!(
                server_bridge.carrier_submitted_datagrams(),
                server_counts_at_bridge.2,
                "real server Pong is a control frame, not a carrier submission"
            );
            assert_eq!(
                client_bridge.carrier_submitted_datagrams(),
                client_counts_at_bridge.2,
                "real client Ping is a control frame, not a carrier submission"
            );

            let route_active_native =
                |event: &RoleEvent| matches!(event, RoleEvent::RouteActive(PathKind::Native));
            let route = tokio::time::timeout(SIGNAL_BUDGET, async {
                tokio::select! {
                    result = &mut server_run => panic!("server ended during native resolve: {result:?}"),
                    result = &mut client_run => panic!("client ended during native resolve: {result:?}"),
                    result = &mut record_server => panic!("signed Mainline responder terminated: {result:?}"),
                    event = client_log.wait(&route_active_native) => event,
                }
            })
            .await
            .expect("client resolves the actual signed native route");
            assert_eq!(route, RoleEvent::RouteActive(PathKind::Native));

            // Positive native application control: real TCP bytes hit the
            // fixed target and echo byte-for-byte on the native route. Keep
            // the actual signed-record responder live alongside both roles.
            tokio::time::timeout(SIGNAL_BUDGET, async {
                tokio::select! {
                    result = &mut record_server => {
                        panic!("signed Mainline responder terminated during forwarded echo: {result:?}")
                    }
                    _ = forward_and_echo(
                        listener_address,
                        b"shaar-5c-signal",
                        &mut server_run,
                        &mut client_run,
                        "signal",
                    ) => {}
                }
            })
            .await
            .expect("native forwarded echo completes within budget");
            assert_eq!(echo.count(), 1, "one fixed-target TCP connection echoed");

            // Stop and join both roles with completion guards; never repoll a
            // completed run future. The Mainline responder remains active until
            // both roles join; the TCP echo stream has already completed.
            let _ = server_stop.send(());
            let _ = client_stop.send(());
            let mut server_done = false;
            let mut client_done = false;
            let mut server_result = None;
            let mut client_result = None;
            tokio::time::timeout(SIGNAL_BUDGET, async {
                while !server_done || !client_done {
                    tokio::select! {
                        result = &mut record_server => {
                            panic!("signed Mainline responder terminated during role join: {result:?}")
                        }
                        result = &mut server_run, if !server_done => {
                            server_done = true;
                            server_result = Some(result);
                        }
                        result = &mut client_run, if !client_done => {
                            client_done = true;
                            client_result = Some(result);
                        }
                    }
                }
            })
            .await
            .expect("both role run loops join within budget");
            server_result
                .expect("server run completion observed")
                .expect("server run ends successfully");
            client_result
                .expect("client run completion observed")
                .expect("client run ends successfully");
            drop(record_server);

            // Role flags support the counters; neither is the negative oracle.
            for (who, log) in [("server", &server_log), ("client", &client_log)] {
                assert!(
                    log.find(&|event| matches!(event, RoleEvent::YggPayloadAcquired(false)))
                        .is_some(),
                    "{who} transferred no Ygg payload pair: {:?}",
                    log.snapshot()
                );
                assert!(
                    log.find(&|event| matches!(event, RoleEvent::YggPayloadAcquired(true)))
                        .is_none(),
                    "{who} never acquired a Ygg payload pair: {:?}",
                    log.snapshot()
                );
                assert!(
                    !log.snapshot()
                        .contains(&RoleEvent::SessionAdmitted(PathKind::Yggdrasil)),
                    "{who} admitted no Ygg application session"
                );
            }
            assert!(
                server_log
                    .snapshot()
                    .contains(&RoleEvent::SessionAdmitted(PathKind::Native)),
                "server admitted the real native session"
            );
            assert_eq!(server_counts_at_bridge, (0, 0, 0));
            assert_eq!(client_counts_at_bridge, (0, 0, 0));
            client_bridge
        };

        // Pinned run/shutdown waiter scope ended. Joined shutdown reborrows
        // each role; bridge Arc clones survive for final counter observations.
        {
            let server_close = server_role.shutdown();
            let client_close = client_role.shutdown();
            let (server_result, client_result) = tokio::join!(
                tokio::time::timeout(SIGNAL_BUDGET, server_close),
                tokio::time::timeout(SIGNAL_BUDGET, client_close),
            );
            server_result
                .expect("server joined close completes within budget")
                .expect("server joined close succeeds");
            client_result
                .expect("client joined close completes within budget")
                .expect("client joined close succeeds");
        }

        // These lifetime counters prove zero carrier-send invocations through
        // joined shutdown, not future polling, network acceptance or wire drain. The
        // successful Ping/Pong and native echo are independent positive controls.
        assert_eq!(
            server_bridge.carrier_submitted_datagrams(),
            0,
            "server had no carrier-send invocation through joined shutdown"
        );
        assert_eq!(
            client_bridge.carrier_submitted_datagrams(),
            0,
            "client had no carrier-send invocation through joined shutdown"
        );
        assert_eq!(
            (server_bridge.queued_datagrams(), server_bridge.dropped_datagrams()),
            (0, 0),
            "server processed no carrier envelopes through joined shutdown"
        );
        assert_eq!(
            (client_bridge.queued_datagrams(), client_bridge.dropped_datagrams()),
            (0, 0),
            "client processed no carrier envelopes through joined shutdown"
        );

        echo.close().await;
        let closed = tokio::time::timeout(SIGNAL_BUDGET, transit.close()).await;
        assert!(
            closed.is_ok() && closed.expect("checked").is_ok(),
            "transit closes cleanly in signal mode"
        );
        fixture.close().await;
        probe_claim_free(CASE_S_SERVICE, "server identity claim released").await;
        probe_claim_free(CASE_S_CLIENT, "client identity claim released").await;
        probe_claim_free(CASE_S_TRANSIT, "transit identity claim released").await;
    })
    .await
    .expect("signal case completes within its budget");
}
