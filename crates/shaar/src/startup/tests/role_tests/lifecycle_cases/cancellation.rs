//! Cancellation and gated rollback over retained role identities.

use std::future::Future;
use std::task::Poll;
use std::time::Duration;

use iroh_base::PublicKey;
use tokio::sync::oneshot;

use crate::config::{ClientConfig, ServerConfig};
use crate::identity::Identity;
use crate::native_discovery::runtime::owner::LoopbackPeer;
use crate::network::{Allowlist, Limits, RelayFixture};
use crate::path::PathKind;
use crate::startup::StartupError;
use crate::startup::role::{ClientRole, RoleEvent, ServerRole};

use super::super::fixtures::{
    bootstrap_v4, client_role_config, dead_relay_address, echo_target, forward_and_echo, identity,
    pub_key_hex, role_logs, server_role_config, start_listener, tuned_policy,
};
use super::helpers::{
    assert_client_binds_released, assert_key_released_once, assert_role_binds_released,
};

const CANCEL_SERVER: u8 = 0x6A;
const CANCEL_CLIENT: u8 = 0x72;
const CANCEL_TRANSIT: u8 = 0x73;
const ROLLBACK_SERVER: u8 = 0x74;
const CANCEL_BUDGET: Duration = Duration::from_secs(150);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_roles_cancel_and_resume_borrowed_waiters() {
    tokio::time::timeout(CANCEL_BUDGET, async {
        let mut service_peer = LoopbackPeer::bind().await;
        let mut client_peer = LoopbackPeer::bind().await;
        let mut rollback_peer = LoopbackPeer::bind().await;
        let mut rollback_client_peer = LoopbackPeer::bind().await;
        let fixture = RelayFixture::start().await;
        let relay_id = fixture.address.peer_id().to_string();
        let relay_address = fixture.address.socket_addr();
        let (transit, transit_port) = start_listener(CANCEL_TRANSIT).await;
        let transit_uri = format!("tcp://127.0.0.1:{transit_port}");
        let (echo, echo_address) = echo_target().await;

        let server_identity: &'static Identity = Box::leak(Box::new(identity(CANCEL_SERVER)));
        let client_identity: &'static Identity = Box::leak(Box::new(identity(CANCEL_CLIENT)));
        let rollback_client_identity: &'static Identity = Box::leak(Box::new(identity(
            super::client_starting::ROLLBACK_CLIENT,
        )));
        let rollback_identity: &'static Identity = Box::leak(Box::new(identity(ROLLBACK_SERVER)));
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
        let client_config: &'static ClientConfig = Box::leak(Box::new(client_role_config(
            &pub_key_hex(server_identity),
            bootstrap_v4(&client_peer),
            &relay_id,
            dead_relay_address(),
            &transit_uri,
            "standby",
            None,
        )));
        let rollback_client_config: &'static ClientConfig = Box::leak(Box::new(client_role_config(
            &pub_key_hex(server_identity),
            bootstrap_v4(&rollback_client_peer),
            &relay_id,
            dead_relay_address(),
            &transit_uri,
            "standby",
            None,
        )));
        let rollback_config: &'static ServerConfig = Box::leak(Box::new(server_role_config(
            echo_address,
            bootstrap_v4(&rollback_peer),
            &relay_id,
            relay_address,
            &transit_uri,
            "standby",
        )));

        let (server_log, _) = role_logs();
        let (mut server_role, controls) = ServerRole::with_events_seamed_for_tests(
            server_config.clone(),
            server_identity,
            Allowlist::new(&[client_key]).expect("fixture allowlist"),
            Limits::new(4).expect("fixture limits"),
            tuned_policy(),
            server_log.clone(),
            true,
            true,
        )
        .expect("the seamed server role builds");
        let (mut gate_entered, gate_release) = controls
            .after_bridge
            .expect("the post-bridge gate is armed");
        let server_item;
        {
            let mut start_waiter = std::pin::pin!(server_role.start());
            let mut capture = std::pin::pin!(service_peer.capture_put_record());
            let mut parked = false;
            let mut flight = None;
            tokio::time::timeout(CANCEL_BUDGET, async {
                while !parked || flight.is_none() {
                    tokio::select! {
                        result = &mut start_waiter => panic!(
                            "server start must stay parked at the bridge gate: {result:?}"),
                        entered = &mut gate_entered, if !parked => {
                            entered.expect("the post-bridge gate was entered");
                            parked = true;
                        }
                        captured = &mut capture, if flight.is_none() => {
                            flight = Some(captured);
                        }
                    }
                }
            })
            .await
            .expect("the composition parks at the gate and its initial PUT is captured");
            // Counterfactual: an entered-start-specific phase loss must not
            // escape by dropping a never-polled borrowed start waiter.
            let one_poll = std::future::poll_fn(|cx| match start_waiter.as_mut().poll(cx) {
                Poll::Pending => Poll::Ready(()),
                Poll::Ready(result) => panic!(
                    "server start escaped its closed gate during the guaranteed poll: {result:?}"
                ),
            });
            tokio::time::timeout(CANCEL_BUDGET, one_poll)
                .await
                .expect("one actual borrowed-start poll is Pending before waiter storage ends");
            let (_source, _transaction, _signed, item) =
                flight.expect("the server's initial PUT was captured");
            server_item = item;
        }
        let _ = gate_release.send(());
        {
            let resumed_start = std::pin::pin!(server_role.start());
            tokio::time::timeout(CANCEL_BUDGET, resumed_start)
                .await
                .expect("the resumed start completes within the budget")
                .expect("the same retained composition resumes and admits");
        }
        let observer = server_role
            .mainline_cleanup_observer_for_tests()
            .expect("the armed hold stored its observer");
        let hold = server_role
            .mainline_cleanup_hold_for_tests()
            .expect("the cleanup hold arms in the Live phase");

        let (server_stop, server_stop_rx) = oneshot::channel();
        let mut server_shutdown = std::pin::pin!(async move {
            let _ = server_stop_rx.await;
        });
        {
            let mut server_run = std::pin::pin!(server_role.run(&mut server_shutdown));
            let admitted = |event: &RoleEvent| matches!(event, RoleEvent::Admitted);
            tokio::time::timeout(CANCEL_BUDGET, async {
                tokio::select! {
                    result = &mut server_run => panic!(
                        "server run ended before admission observation: {result:?}"),
                    _ = server_log.wait(&admitted) => {}
                }
            })
            .await
            .expect("the server enters its live run");
        } // Cancel the borrowed server run waiter; the retained Live phase remains.

        // Reborrow the same server role. Keep it driven throughout every client
        // start, discovery, echo, close, and gated rollback transition below.
        {
            let mut server_run = std::pin::pin!(server_role.run(&mut server_shutdown));
            let admitted = |event: &RoleEvent| matches!(event, RoleEvent::Admitted);
            tokio::time::timeout(CANCEL_BUDGET, async {
                tokio::select! {
                    result = &mut server_run => panic!("server run ended early: {result:?}"),
                    _ = server_log.wait(&admitted) => {}
                }
            })
            .await
            .expect("the resumed server run admits");

            let (client_log, _) = role_logs();
            let (mut client_role, client_controls) = ClientRole::with_events_seamed_for_tests(
                client_config.clone(),
                client_identity,
                Limits::new(4).expect("fixture limits"),
                tuned_policy(),
                client_log.clone(),
                true,
            )
            .expect("the seamed client role builds in Starting");
            let (mut client_gate_entered, client_gate_release) = client_controls
                .after_bridge
                .expect("the client post-bridge gate is armed");
            let (client_stop, client_stop_rx) = oneshot::channel();
            let captured_put = {
                let mut client_start = std::pin::pin!(client_role.start());
                let mut capture = std::pin::pin!(client_peer.capture_put_record());
                let mut gate_seen = false;
                let mut captured = None;
                tokio::time::timeout(CANCEL_BUDGET, async {
                    while !gate_seen || captured.is_none() {
                        tokio::select! {
                            result = &mut server_run => panic!(
                                "server ended while the client reaches its startup gate: {result:?}"),
                            result = &mut client_start => panic!(
                                "client start escaped its closed post-bridge gate: {result:?}"),
                            entered = &mut client_gate_entered, if !gate_seen => {
                                entered.expect("client entered its post-bridge gate");
                                gate_seen = true;
                            }
                            put = &mut capture, if captured.is_none() => captured = Some(put),
                        }
                    }
                })
                .await
                .expect("client gate entry and its own initial PUT are observed");
                let one_poll = std::future::poll_fn(|cx| match client_start.as_mut().poll(cx) {
                    Poll::Pending => Poll::Ready(()),
                    Poll::Ready(result) => panic!(
                        "client start escaped its closed gate during the guaranteed poll: {result:?}"
                    ),
                });
                tokio::time::timeout(CANCEL_BUDGET, async {
                    tokio::select! {
                        result = &mut server_run => panic!(
                            "server ended during the client start poll: {result:?}"),
                        () = one_poll => {},
                    }
                })
                .await
                .expect("one actual client-start poll is Pending before waiter storage ends");
                captured.expect("client initial PUT captured")
            };
            let (source, transaction, _signed, _item) = captured_put;
            tokio::time::timeout(CANCEL_BUDGET, async {
                tokio::select! {
                    result = &mut server_run => panic!(
                        "server ended while the gated client PUT was acknowledged: {result:?}"),
                    () = client_peer.acknowledge(source, &transaction) => {}
                }
            })
            .await
            .expect("client's own PUT is acknowledged while its startup gate stays closed");
            let _ = client_gate_release.send(());
            tokio::time::timeout(CANCEL_BUDGET, async {
                tokio::select! {
                    result = &mut server_run => panic!(
                        "server ended while the client resumes start: {result:?}"),
                    result = client_role.start() => result.expect(
                        "the same retained client start resumes to a usable Live role"),
                }
            })
            .await
            .expect("resumed client start completes before its run begins");

            let mut record = Box::pin(client_peer.serve_record(&server_item));
            let mut client_shutdown = std::pin::pin!(async move {
                let _ = client_stop_rx.await;
            });
            let listener_address;
            {
                let mut client_run = std::pin::pin!(client_role.run(&mut client_shutdown));
                let listener_ready =
                    |event: &RoleEvent| matches!(event, RoleEvent::ListenerReady(_));
                listener_address = tokio::time::timeout(CANCEL_BUDGET, async {
                    tokio::select! {
                        result = &mut server_run => panic!(
                            "server ended while client listener arms: {result:?}"),
                        result = &mut client_run => panic!(
                            "client run ended while arming: {result:?}"),
                        _ = &mut record => panic!(
                            "record responder terminated during listener readiness"),
                        event = client_log.wait(&listener_ready) => match event {
                            RoleEvent::ListenerReady(address) => address,
                            other => panic!("unexpected event while arming: {other:?}"),
                        },
                    }
                })
                .await
                .expect("the client listener becomes ready");
                let route_active_native =
                    |event: &RoleEvent| matches!(event, RoleEvent::RouteActive(PathKind::Native));
                tokio::time::timeout(CANCEL_BUDGET, async {
                    tokio::select! {
                        result = &mut server_run => panic!("server run ended early: {result:?}"),
                        result = &mut client_run => panic!("client run ended early: {result:?}"),
                        _ = &mut record => panic!("record responder terminated"),
                        _ = client_log.wait(&route_active_native) => {}
                    }
                })
                .await
                .expect("the client resolves and activates its native route");
            }
            // The borrowed run waiter ended while the role remained Live.
            // Reborrow that same role for the real echo and joined shutdown.
            {
                let mut client_run = std::pin::pin!(client_role.run(&mut client_shutdown));
                {
                    let mut transfer = Box::pin(forward_and_echo(
                        listener_address,
                        b"shaar-5c-retain-echo",
                        &mut server_run,
                        &mut client_run,
                        "post-resume client",
                    ));
                    tokio::time::timeout(CANCEL_BUDGET, async {
                        tokio::select! {
                            _ = &mut record => panic!(
                                "record responder terminated during client echo"),
                            () = &mut transfer => {},
                        }
                    })
                    .await
                    .expect("client echo completes while the record responder is polled");
                }
                assert_eq!(echo.count(), 1, "the resumed role forwards real bytes");
                let _ = client_stop.send(());
                tokio::time::timeout(CANCEL_BUDGET, async {
                    tokio::select! {
                        result = &mut server_run => panic!(
                            "server ended during client run close: {result:?}"),
                        _ = &mut record => panic!(
                            "record responder terminated during client run close"),
                        result = &mut client_run => result,
                    }
                })
                .await
                .expect("the resumed client run ends within the budget")
                .expect("the client run ends cleanly on shutdown");
            }
            tokio::time::timeout(CANCEL_BUDGET, async {
                tokio::select! {
                    result = &mut server_run => panic!(
                        "server ended during client joined close: {result:?}"),
                    _ = &mut record => panic!(
                        "record responder terminated during client joined close"),
                    result = client_role.shutdown() => {
                        result.expect("client joined close is truthful Ok");
                    }
                }
            })
            .await
            .expect("the client joined close completes");
            let rebound = tokio::net::TcpListener::bind(listener_address)
                .await
                .expect("the retained client listener socket was released");
            drop(rebound);
            assert_client_binds_released(client_config, "cancelled client");
            drop(record); // Ends responder storage before independent rollback.

            super::client_starting::shutdown_client_while_starting(
                rollback_client_config,
                rollback_client_identity,
                &mut rollback_client_peer,
                &mut server_run,
            )
            .await;

            shutdown_server_while_starting(
                rollback_config,
                rollback_identity,
                &mut rollback_peer,
                &mut server_run,
                client_key,
            )
            .await;

            let _ = server_stop.send(());
            tokio::time::timeout(CANCEL_BUDGET, &mut server_run)
                .await
                .expect("the server run ends within the budget")
                .expect("the server run ends on shutdown");
        }

        // These assertions reject premature `Done(Ok)` or a resumed
        // continuation that loses the observed error; bind/key reuse rejects
        // lost owned cleanup. We intentionally never repoll a completed
        // continuation, which would be invalid. `SharedResourcesStart` caches
        // the first error of a cleanup attempt, and may cache the same pending
        // receipt observed here. A fresh or lost continuation returning a
        // different result is detected; reconstruction returning that same
        // cached upstream error may be indistinguishable. Removing only the
        // redundant role cache is likewise undetectable if the shared-resource
        // start repeats the same first error. No mutation was executed; this is
        // the scope of the regression.
        let observed_stage = {
            let mut waiter = std::pin::pin!(server_role.shutdown());
            let close_pending = |event: &RoleEvent| matches!(event, RoleEvent::ClosePending { .. });
            let mut cleanup_held = false;
            let mut close_pending_stage = None;
            tokio::time::timeout(CANCEL_BUDGET, async {
                while !cleanup_held || close_pending_stage.is_none() {
                    tokio::select! {
                        biased;
                        result = &mut waiter => panic!(
                            "shutdown unexpectedly completed before releasing the hold: {result:?}"),
                        () = observer.wait_cleanup_held(), if !cleanup_held => {
                            cleanup_held = true;
                        }
                        event = server_log.wait(&close_pending),
                            if close_pending_stage.is_none() => match event {
                                RoleEvent::ClosePending { stage } => close_pending_stage = Some(stage),
                                other => panic!("unexpected close event: {other:?}"),
                            }
                    }
                }
            })
            .await
            .expect("actual cleanup hold and pending-close receipt observed while held");
            close_pending_stage.expect("the real close receipt supplies its first error stage")
        };
        let observed_error = StartupError::Close {
            stage: observed_stage,
        };
        hold.release();
        let resumed = {
            let waiter = std::pin::pin!(server_role.shutdown());
            tokio::time::timeout(CANCEL_BUDGET, waiter)
                .await
                .expect("the resumed same-role shutdown reaches terminal cleanup")
        };
        assert_eq!(
            resumed,
            Err(observed_error.clone()),
            "the joined shutdown preserves the actual first pending-close error"
        );
        let repeated = {
            let waiter = std::pin::pin!(server_role.shutdown());
            tokio::time::timeout(CANCEL_BUDGET, waiter)
                .await
                .expect("the repeated shutdown returns its terminal result")
        };
        assert_eq!(
            repeated,
            Err(observed_error),
            "repeated close returns the observed first error"
        );
        assert_role_binds_released(server_config, "cancelled server");
        assert_key_released_once(CANCEL_SERVER, "server identity").await;

        echo.close().await;
        let closed = tokio::time::timeout(CANCEL_BUDGET, transit.close()).await;
        assert!(
            closed.is_ok() && closed.expect("checked").is_ok(),
            "transit closes"
        );
        fixture.close().await;
        assert_key_released_once(CANCEL_CLIENT, "client identity").await;
        assert_key_released_once(CANCEL_TRANSIT, "transit identity").await;
    })
    .await
    .expect("the retained-role cancellation case completes within its budget");
}

async fn shutdown_server_while_starting<S>(
    config: &'static ServerConfig,
    identity: &'static Identity,
    peer: &mut LoopbackPeer,
    outer_server: &mut S,
    allowed_client: PublicKey,
) where
    S: Future<Output = Result<(), StartupError>> + Unpin,
{
    let (log, _) = role_logs();
    let (mut role, controls) = ServerRole::with_events_seamed_for_tests(
        config.clone(),
        identity,
        Allowlist::new(&[allowed_client]).expect("rollback server allowlist"),
        Limits::new(4).expect("rollback server limits"),
        tuned_policy(),
        log,
        false,
        true,
    )
    .expect("rollback server retains a real post-acquisition gate");
    let (mut entered, release) = controls
        .after_bridge
        .expect("rollback server post-bridge gate is armed");

    let (source, transaction) = {
        let mut start = std::pin::pin!(role.start());
        let mut capture = std::pin::pin!(peer.capture_put_record());
        let mut gate_seen = false;
        let mut put = None;
        tokio::time::timeout(CANCEL_BUDGET, async {
            while !gate_seen || put.is_none() {
                tokio::select! {
                    result = &mut *outer_server => panic!(
                        "outer server stopped while rollback server starts: {result:?}"),
                    result = &mut start => panic!(
                        "rollback start escaped its closed gate: {result:?}"),
                    result = &mut entered, if !gate_seen => {
                        result.expect("rollback owner entered after-bridge gate");
                        gate_seen = true;
                    }
                    captured = &mut capture, if put.is_none() => put = Some(captured),
                }
            }
        })
        .await
        .expect("rollback gate entry and its real initial PUT are observed");
        // Counterfactual: an entered-start phase loss cannot hide behind dropping
        // a borrowed start waiter that was never polled.
        let one_poll = std::future::poll_fn(|cx| match start.as_mut().poll(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(result) => panic!(
                "rollback start escaped its closed gate during the guaranteed poll: {result:?}"
            ),
        });
        tokio::time::timeout(CANCEL_BUDGET, async {
            tokio::select! {
                result = &mut *outer_server => panic!(
                    "outer server stopped during rollback start poll: {result:?}"),
                () = one_poll => {},
            }
        })
        .await
        .expect("one actual rollback start poll is Pending before waiter storage ends");
        let (source, transaction, _signed, _item) = put.expect("rollback PUT captured");
        (source, transaction)
    };

    tokio::time::timeout(CANCEL_BUDGET, async {
        tokio::select! {
            result = &mut *outer_server => panic!(
                "outer server stopped while rollback PUT is acknowledged: {result:?}"),
            _ = peer.acknowledge(source, &transaction) => {},
        }
    })
    .await
    .expect("rollback server's PUT is acknowledged before its gate release");

    {
        let mut shutdown = std::pin::pin!(role.shutdown());
        let one_poll = std::future::poll_fn(|cx| match shutdown.as_mut().poll(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(result) => panic!(
                "rollback shutdown completed while the after-bridge gate stayed closed: {result:?}"
            ),
        });
        tokio::time::timeout(CANCEL_BUDGET, async {
            tokio::select! {
                result = &mut *outer_server => panic!(
                    "outer server stopped during rollback shutdown poll: {result:?}"),
                () = one_poll => {},
            }
        })
        .await
        .expect("one actual rollback shutdown poll is Pending before waiter storage ends");
    }
    let _ = release.send(());
    let joined = tokio::time::timeout(CANCEL_BUDGET, async {
        tokio::select! {
            result = &mut *outer_server => panic!(
                "outer server stopped while rollback close joins: {result:?}"),
            result = role.shutdown() => result,
        }
    })
    .await
    .expect("same rollback server shutdown joins after gate release");
    assert_eq!(
        joined,
        Ok(()),
        "rollback joins its real composition cleanly"
    );
    let repeated = role.shutdown().await;
    assert_eq!(
        repeated, joined,
        "repeated rollback shutdown matches terminal result"
    );
    assert_role_binds_released(config, "rollback server");
    tokio::time::timeout(CANCEL_BUDGET, async {
        tokio::select! {
            result = &mut *outer_server => panic!(
                "outer server stopped during rollback server key reuse: {result:?}"),
            () = assert_key_released_once(ROLLBACK_SERVER, "rollback server identity") => {},
        }
    })
    .await
    .expect("rollback server identity release is checked while the outer server is driven");
}
