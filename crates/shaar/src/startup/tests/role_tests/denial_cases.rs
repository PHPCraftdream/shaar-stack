//! Denial case (5c criterion 5): a disallowed key completes a real cold native
//! lookup and is denied without reaching the fixed target; an allowed key then
//! succeeds through the SAME server and Ygg transit via the real carrier registry.
//!
//! Each role has an independent Mainline peer. The server PUT is captured and
//! ACKed; the denied peer directly answers its captured cold service-key GET
//! with the signed publication, while the allowed peer captures/ACKs its PUT
//! but never serves the service record. Both clients use a dead relay so native
//! discovery and admission are the only possible path for the denial.

use std::time::Duration;

use iroh_base::PublicKey;

use crate::config::{ClientConfig, ServerConfig};
use crate::native_discovery::runtime::owner::LoopbackPeer;
use crate::network::{Allowlist, Limits, RelayFixture};
use crate::path::PathKind;
use crate::startup::StartupError;
use crate::startup::role::{ClientRole, RoleEvent, ServerRole};

use super::fixtures::{
    bootstrap_v4, client_role_config, dead_relay_address, echo_target, forward_and_echo, identity,
    probe_claim_free, pub_key_hex, role_logs, server_role_config, start_listener, tuned_policy,
};

// Unique seeds: server 0x57, allowed client 0x58, denied client 0x59,
// independent transit 0x5A.
const CASE_FIVE_SERVICE: u8 = 0x57;
const CASE_FIVE_ALLOWED: u8 = 0x58;
const CASE_FIVE_DENIED: u8 = 0x59;
const CASE_FIVE_TRANSIT: u8 = 0x5A;
const DENIAL_BUDGET: Duration = Duration::from_secs(90);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disallowed_key_causes_zero_target_connections_and_allowed_key_succeeds() {
    tokio::time::timeout(DENIAL_BUDGET, async {
        let mut service_peer = LoopbackPeer::bind().await;
        let mut denied_peer = LoopbackPeer::bind().await;
        let fixture = RelayFixture::start().await;
        let relay_id = fixture.address.peer_id().to_string();
        let relay_address = fixture.address.socket_addr();
        let (transit, transit_port) = start_listener(CASE_FIVE_TRANSIT).await;
        let transit_uri = format!("tcp://127.0.0.1:{transit_port}");
        let (echo, echo_address) = echo_target().await;

        // Constructors own their identities/configurations; no static leaks.
        let server_identity = identity(CASE_FIVE_SERVICE);
        let denied_identity = identity(CASE_FIVE_DENIED);
        let allowed_identity = identity(CASE_FIVE_ALLOWED);
        let allowed_key = PublicKey::from_bytes(&allowed_identity.public_key_bytes())
            .expect("allowed fixture key");
        let server_key_hex = pub_key_hex(&server_identity);
        let server_config: ServerConfig = server_role_config(
            echo_address,
            bootstrap_v4(&service_peer),
            &relay_id,
            relay_address,
            &transit_uri,
            "standby",
        );
        let denied_config: ClientConfig = client_role_config(
            &server_key_hex,
            bootstrap_v4(&denied_peer),
            &relay_id,
            dead_relay_address(),
            &transit_uri,
            "standby",
            None,
        );
        assert!(denied_config.server_address().is_none());

        let (server_log, _unused_server_log) = role_logs();
        let mut server_role = ServerRole::with_events(
            server_config,
            &server_identity,
            Allowlist::new(&[allowed_key]).expect("allow only the positive-control key"),
            Limits::new(4).expect("fixture limits"),
            tuned_policy(),
            server_log.clone(),
        )
        .expect("server role builds");
        let (server_stop, server_stop_rx) = tokio::sync::oneshot::channel();

        // Start and real publication PUT capture race independently. If the
        // PUT wins, the capture borrow ends before ACK and start then resumes;
        // if start wins, capture is re-armed under the driven server run loop.
        let (server_started, captured_server_put) = {
            let mut capture = Box::pin(service_peer.capture_put_record());
            let mut start = Box::pin(server_role.start());
            tokio::time::timeout(DENIAL_BUDGET, async {
                tokio::select! {
                    result = &mut start => (Some(result), None),
                    captured = capture.as_mut() => (None, Some(captured)),
                }
            })
            .await
            .expect("server start or actual publication PUT completes")
        };
        let mut server_item = None;
        if let Some((source, transaction, _signed, item)) = captured_server_put {
            service_peer.acknowledge(source, &transaction).await;
            server_item = Some(item);
        }
        if let Some(result) = server_started {
            result.expect("server starts independently of publication capture");
        } else {
            tokio::time::timeout(DENIAL_BUDGET, server_role.start())
                .await
                .expect("server start resumes after actual PUT ACK")
                .expect("server role starts");
        }

        // Clone bridge observers before taking mutable run borrows. Counters
        // classify valid carrier envelopes at Shared::handle -> Registry::deliver;
        // the separate Ping/Pong branch is deliberately not used here.
        let server_bridge = server_role
            .ygg_bridge_for_tests()
            .expect("started server retains its Ygg bridge");
        let (queued_before_denial, dropped_before_denial) = (
            server_bridge.queued_datagrams(),
            server_bridge.dropped_datagrams(),
        );
        assert_eq!(queued_before_denial, 0, "no carrier traffic precedes denial");

        // Keep one server run waiter live across both client phases. Its actual
        // shutdown waiter and mutable run borrow end before server.shutdown().
        {
            let mut server_shutdown = std::pin::pin!(async move {
                let _ = server_stop_rx.await;
            });
            let mut server_run = Box::pin(server_role.run(&mut server_shutdown));

            if server_item.is_none() {
                let (source, transaction, _signed, item) = {
                    let mut capture = Box::pin(service_peer.capture_put_record());
                    tokio::time::timeout(DENIAL_BUDGET, async {
                        tokio::select! {
                            captured = capture.as_mut() => captured,
                            result = &mut server_run => panic!("server ended during PUT capture: {result:?}"),
                        }
                    })
                    .await
                    .expect("server's actual publication PUT is captured")
                };
                tokio::time::timeout(DENIAL_BUDGET, async {
                    tokio::select! {
                        _ = service_peer.acknowledge(source, &transaction) => {}
                        result = &mut server_run => panic!("server ended during PUT ACK: {result:?}"),
                    }
                })
                .await
                .expect("server publication PUT is ACKed");
                server_item = Some(item);
            }
            let server_item = server_item.expect("real signed server publication retained");

            let (denied_log, _unused_denied_log) = role_logs();
            let mut denied_role = ClientRole::with_events(
                denied_config,
                &denied_identity,
                Limits::new(4).expect("fixture limits"),
                tuned_policy(),
                denied_log.clone(),
            )
            .expect("denied role builds");
            let (denied_stop, denied_stop_rx) = tokio::sync::oneshot::channel::<()>();

            // Capture the denied client's PUT and finish start before constructing
            // its run loop. Both outcomes are retained independently while the
            // same server pump is driven; completed futures are never repolled.
            let (denied_start_result, captured_denied_put) = {
                let mut capture = Box::pin(denied_peer.capture_put_record());
                let mut start = Box::pin(denied_role.start());
                let mut start_result = None;
                let mut captured_put = None;
                tokio::time::timeout(DENIAL_BUDGET, async {
                    while start_result.is_none() || captured_put.is_none() {
                        tokio::select! {
                            result = &mut start, if start_result.is_none() => {
                                start_result = Some(result);
                            }
                            captured = capture.as_mut(), if captured_put.is_none() => {
                                captured_put = Some(captured);
                            }
                            result = &mut server_run => panic!("server ended during denied startup: {result:?}"),
                        }
                    }
                })
                .await
                .expect("denied start and its actual PUT capture complete");
                (
                    start_result.expect("denied start completes"),
                    captured_put.expect("denied client's actual PUT is captured"),
                )
            };
            denied_start_result.expect("denied role starts");
            let (source, transaction, _signed, _item) = captured_denied_put;
            tokio::time::timeout(DENIAL_BUDGET, async {
                tokio::select! {
                    _ = denied_peer.acknowledge(source, &transaction) => {}
                    result = &mut server_run => panic!("server ended during denied PUT ACK: {result:?}"),
                }
            })
            .await
            .expect("denied client's PUT is ACKed");

            // Retain the denied client's lifetime sender observation before run;
            // the same server's dropped-envelope counter below independently
            // confirms the unauthorized carrier attempt reached its registry.
            let denied_bridge = denied_role
                .ygg_bridge_for_tests()
                .expect("started denied client retains its bridge");
            {
                let mut denied_shutdown = std::pin::pin!(async move {
                    let _ = denied_stop_rx.await;
                });
                let mut denied_run = Box::pin(denied_role.run(&mut denied_shutdown));

                // Reply to this exact captured cold service-key GET with the
                // real signed publication. Completion of reply_get is the
                // response-send oracle; server and denied role stay driven
                // throughout, with no second query or relay rescue assumed.
                let target = n0_mainline::MutableItem::target_from_key(server_item.key(), None);
                let (source, transaction) = tokio::time::timeout(DENIAL_BUDGET, async {
                    tokio::select! {
                        get = denied_peer.capture_get(target) => get,
                        result = &mut server_run => panic!("server ended before denied cold GET: {result:?}"),
                        result = &mut denied_run => panic!("denied client ended before cold GET: {result:?}"),
                    }
                })
                .await
                .expect("denied client's real cold service-key GET is captured");
                tokio::time::timeout(DENIAL_BUDGET, async {
                    tokio::select! {
                        _ = denied_peer.reply_get(source, &transaction, &server_item) => {}
                        result = &mut server_run => panic!("server ended during actual signed GET reply: {result:?}"),
                        result = &mut denied_run => panic!("denied client ended during actual signed GET reply: {result:?}"),
                    }
                })
                .await
                .expect("actual captured GET receives the signed server publication");
                let denied_result = tokio::time::timeout(DENIAL_BUDGET, async {
                    tokio::select! {
                        result = &mut server_run => panic!("server ended during denial: {result:?}"),
                        result = &mut denied_run => result,
                    }
                })
                .await
                .expect("denied role completes within budget");
                assert!(
                    matches!(denied_result, Err(StartupError::Exhausted)),
                    "denial preserves truthful attempt exhaustion: {denied_result:?}"
                );
                assert_eq!(echo.count(), 0, "denied key never reaches fixed target");
            }

            // The denied run waiter has ended; it is not repolled. Join the
            // denied role while the same server pump continues, then inspect
            // the actual typed native rejection and carrier filter counters.
            drop(denied_stop);
            let denied_close = tokio::time::timeout(DENIAL_BUDGET, async {
                tokio::select! {
                    result = denied_role.shutdown() => result,
                    result = &mut server_run => panic!("server ended during denied joined shutdown: {result:?}"),
                }
            })
            .await
            .expect("denied joined shutdown completes");
            assert!(
                matches!(denied_close, Err(StartupError::Exhausted)),
                "denied joined shutdown returns the retained typed exhaustion error"
            );
            assert!(
                denied_bridge.carrier_submitted_datagrams() > 0,
                "denied client invoked carrier sends before terminal Exhausted"
            );
            assert!(
                server_log
                    .find(&|event| matches!(event, RoleEvent::AdmissionDenied(PathKind::Native)))
                    .is_some(),
                "server recorded real typed native AdmissionDenied: {:?}",
                server_log.snapshot()
            );
            let dropped_after_denial = server_bridge.dropped_datagrams();
            assert!(
                dropped_after_denial > dropped_before_denial,
                "unauthorized valid carrier envelopes were rejected by the same server registry: \
                 before={dropped_before_denial} after={dropped_after_denial}"
            );
            assert_eq!(
                server_bridge.queued_datagrams(),
                queued_before_denial,
                "denied carrier envelopes were not delivered"
            );
            assert_eq!(echo.count(), 0, "zero target connections through denied shutdown");

            // Allowed positive control has its own live bootstrap for PUT ACK,
            // but no service record responder; dead relay prevents native rescue.
            let mut allowed_peer = LoopbackPeer::bind().await;
            let allowed_config: ClientConfig = client_role_config(
                &server_key_hex,
                bootstrap_v4(&allowed_peer),
                &relay_id,
                dead_relay_address(),
                &transit_uri,
                "standby",
                None,
            );
            assert!(allowed_config.server_address().is_none());
            let (allowed_log, _unused_allowed_log) = role_logs();
            let mut allowed_role = ClientRole::with_events(
                allowed_config,
                &allowed_identity,
                Limits::new(4).expect("fixture limits"),
                tuned_policy(),
                allowed_log.clone(),
            )
            .expect("allowed role builds");
            let (allowed_stop, allowed_stop_rx) = tokio::sync::oneshot::channel();
            let (allowed_started, captured_allowed_put) = {
                let mut capture = Box::pin(allowed_peer.capture_put_record());
                let mut start = Box::pin(allowed_role.start());
                tokio::time::timeout(DENIAL_BUDGET, async {
                    tokio::select! {
                        result = &mut start => (Some(result), None),
                        captured = capture.as_mut() => (None, Some(captured)),
                        result = &mut server_run => panic!("server ended during allowed startup: {result:?}"),
                    }
                })
                .await
                .expect("allowed start or its own PUT capture completes")
            };
            let mut allowed_put_seen = captured_allowed_put.is_some();
            if let Some((source, transaction, _signed, _item)) = captured_allowed_put {
                tokio::time::timeout(DENIAL_BUDGET, async {
                    tokio::select! {
                        _ = allowed_peer.acknowledge(source, &transaction) => {}
                        result = &mut server_run => panic!("server ended during allowed PUT ACK: {result:?}"),
                    }
                })
                .await
                .expect("allowed client's own PUT is ACKed");
            }
            if let Some(result) = allowed_started {
                result.expect("allowed client starts independently of PUT capture");
            } else {
                tokio::time::timeout(DENIAL_BUDGET, async {
                    tokio::select! {
                        result = allowed_role.start() => result,
                        result = &mut server_run => panic!("server ended while allowed start resumed: {result:?}"),
                    }
                })
                .await
                .expect("allowed start resumes after its actual PUT ACK")
                .expect("allowed role starts");
            }
            let allowed_bridge = allowed_role
                .ygg_bridge_for_tests()
                .expect("started allowed client retains its bridge");
            let server_submitted_before_allowed = server_bridge.carrier_submitted_datagrams();
            {
                let mut allowed_shutdown = std::pin::pin!(async move {
                    let _ = allowed_stop_rx.await;
                });
                let mut allowed_run = Box::pin(allowed_role.run(&mut allowed_shutdown));
                if !allowed_put_seen {
                    let (source, transaction, _signed, _item) = {
                        let mut capture = Box::pin(allowed_peer.capture_put_record());
                        tokio::time::timeout(DENIAL_BUDGET, async {
                            tokio::select! {
                                captured = capture.as_mut() => captured,
                                result = &mut server_run => panic!("server ended during allowed PUT capture: {result:?}"),
                                result = &mut allowed_run => panic!("allowed client ended during PUT capture: {result:?}"),
                            }
                        })
                        .await
                        .expect("allowed client's actual PUT is captured")
                    };
                    tokio::time::timeout(DENIAL_BUDGET, async {
                        tokio::select! {
                            _ = allowed_peer.acknowledge(source, &transaction) => {}
                            result = &mut server_run => panic!("server ended during allowed PUT ACK: {result:?}"),
                            result = &mut allowed_run => panic!("allowed client ended during PUT ACK: {result:?}"),
                        }
                    })
                    .await
                    .expect("allowed client's PUT is ACKed");
                    allowed_put_seen = true;
                }
                assert!(allowed_put_seen);

                // No service-record responder runs on this peer. Both role
                // loops remain driven through Ygg route, admitted session, echo.
                let route_ygg =
                    |event: &RoleEvent| matches!(event, RoleEvent::RouteActive(PathKind::Yggdrasil));
                let route = tokio::time::timeout(DENIAL_BUDGET, async {
                    tokio::select! {
                        event = allowed_log.wait(&route_ygg) => event,
                        result = &mut server_run => panic!("server ended during allowed fallback: {result:?}"),
                        result = &mut allowed_run => panic!("allowed client ended during fallback: {result:?}"),
                    }
                })
                .await
                .expect("allowed standby route succeeds without service record or live relay");
                assert_eq!(route, RoleEvent::RouteActive(PathKind::Yggdrasil));
                let admitted_ygg = |event: &RoleEvent| {
                    matches!(event, RoleEvent::SessionAdmitted(PathKind::Yggdrasil))
                };
                let admitted = tokio::time::timeout(DENIAL_BUDGET, async {
                    tokio::select! {
                        event = server_log.wait(&admitted_ygg) => event,
                        result = &mut server_run => panic!("server ended during allowed Ygg admission: {result:?}"),
                        result = &mut allowed_run => panic!("allowed client ended during Ygg admission: {result:?}"),
                    }
                })
                .await
                .expect("same server admits allowed Ygg application session");
                assert_eq!(admitted, RoleEvent::SessionAdmitted(PathKind::Yggdrasil));
                let listener = match allowed_log
                    .find(&|event| matches!(event, RoleEvent::ListenerReady(_)))
                {
                    Some(RoleEvent::ListenerReady(address)) => address,
                    other => panic!("allowed listener address recorded: {other:?}"),
                };
                forward_and_echo(
                    listener,
                    b"shaar-5c-allowed-standby",
                    &mut server_run,
                    &mut allowed_run,
                    "allowed standby positive control",
                )
                .await;
                assert_eq!(echo.count(), 1, "allowed route reaches fixed target once");
                assert!(
                    allowed_bridge.carrier_submitted_datagrams() > 0,
                    "allowed positive control invoked a carrier send before real echo"
                );
                assert!(
                    server_bridge.carrier_submitted_datagrams() > server_submitted_before_allowed,
                    "same server invoked a carrier send during allowed positive control"
                );
                assert!(
                    server_bridge.queued_datagrams() > queued_before_denial,
                    "allowed envelopes pass Registry::deliver on SAME server bridge: \
                     pre-denial queued={queued_before_denial} now={}",
                    server_bridge.queued_datagrams()
                );

                let _ = allowed_stop.send(());
                let result = tokio::time::timeout(DENIAL_BUDGET, async {
                    tokio::select! {
                        result = &mut allowed_run => result,
                        result = &mut server_run => panic!("server ended during allowed run shutdown: {result:?}"),
                    }
                })
                .await
                .expect("allowed run completes within budget");
                result.expect("allowed run ends cleanly");
            }
            // Run/shutdown waiters ended; joined client shutdown reborrows role.
            assert!(allowed_put_seen);
            assert!(allowed_bridge.queued_datagrams() > 0);
            tokio::time::timeout(DENIAL_BUDGET, async {
                tokio::select! {
                    result = allowed_role.shutdown() => result,
                    result = &mut server_run => panic!("server ended during allowed joined shutdown: {result:?}"),
                }
            })
            .await
            .expect("allowed joined shutdown completes")
            .expect("allowed joined shutdown succeeds");

            let _ = server_stop.send(());
            tokio::time::timeout(DENIAL_BUDGET, &mut server_run)
                .await
                .expect("server run ends on shutdown")
                .expect("server run ends cleanly");
            drop(server_run);
        }
        // Server run and shutdown waiters are out of scope before joined close.
        tokio::time::timeout(DENIAL_BUDGET, server_role.shutdown())
            .await
            .expect("server joined shutdown completes")
            .expect("server joined shutdown succeeds");

        assert_eq!(echo.count(), 1, "only allowed key connected to target");
        echo.close().await;
        let closed = tokio::time::timeout(DENIAL_BUDGET, transit.close()).await;
        assert!(closed.is_ok() && closed.expect("checked").is_ok(), "transit closes");
        fixture.close().await;
        probe_claim_free(CASE_FIVE_SERVICE, "server identity claim released").await;
        probe_claim_free(CASE_FIVE_ALLOWED, "allowed identity claim released").await;
        probe_claim_free(CASE_FIVE_DENIED, "denied identity claim released").await;
        probe_claim_free(CASE_FIVE_TRANSIT, "transit identity claim released").await;
    })
    .await
    .expect("case 5 completes within its denial budget");
}
