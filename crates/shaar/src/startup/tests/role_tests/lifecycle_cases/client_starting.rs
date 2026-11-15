//! Client Starting-phase cancellation rollback over a real seamed composition.

use std::future::Future;
use std::net::{SocketAddr, SocketAddrV4};
use std::task::Poll;
use std::time::Duration;

use tokio::sync::oneshot;

use crate::config::{ClientConfig, ClientOverrides};
use crate::identity::Identity;
use crate::native_discovery::runtime::owner::LoopbackPeer;
use crate::network::Limits;
use crate::startup::StartupError;
use crate::startup::role::{ClientRole, RoleEvent};

use super::super::fixtures::{
    identity, pin_role, probe_claim_free, pub_key_hex, reserve_tcp_port, reserve_udp_port,
    role_logs, silent_udp, start_listener, tuned_policy,
};
use super::helpers::{assert_client_binds_released, assert_key_released_once};

pub(super) const ROLLBACK_CLIENT: u8 = 0x6B;
const CANCEL_BUDGET: Duration = Duration::from_secs(150);

// L0 relay-less client startup: identity 0x7B, transit 0x7C. Fresh bytes
// per the fixtures.rs discipline.
const RELAYLESS_CLIENT: u8 = 0x7B;
const RELAYLESS_TRANSIT: u8 = 0x7C;

pub(super) async fn shutdown_client_while_starting<S>(
    config: &'static ClientConfig,
    identity: &'static Identity,
    peer: &mut LoopbackPeer,
    outer_server: &mut S,
) where
    S: Future<Output = Result<(), StartupError>> + Unpin,
{
    let (log, _) = role_logs();
    let (mut role, controls) = ClientRole::with_events_seamed_for_tests(
        config.clone(),
        identity,
        Limits::new(4).expect("rollback client limits"),
        tuned_policy(),
        log,
        true,
    )
    .expect("rollback client retains a real post-bridge gate");
    let (mut entered, release) = controls
        .after_bridge
        .expect("rollback client post-bridge gate is armed");

    let (source, transaction) = {
        let mut start = std::pin::pin!(role.start());
        let mut capture = std::pin::pin!(peer.capture_put_record());
        let mut gate_seen = false;
        let mut put = None;
        tokio::time::timeout(CANCEL_BUDGET, async {
            while !gate_seen || put.is_none() {
                tokio::select! {
                    result = &mut *outer_server => panic!(
                        "outer server stopped while rollback client starts: {result:?}"),
                    result = &mut start => panic!(
                        "rollback client start escaped its closed gate: {result:?}"),
                    result = &mut entered, if !gate_seen => {
                        result.expect("rollback client entered after-bridge gate");
                        gate_seen = true;
                    }
                    captured = &mut capture, if put.is_none() => put = Some(captured),
                }
            }
        })
        .await
        .expect("rollback client gate entry and initial PUT are observed");
        let one_poll = std::future::poll_fn(|cx| match start.as_mut().poll(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(result) => panic!(
                "rollback client start escaped its closed gate during the guaranteed poll: {result:?}"
            ),
        });
        tokio::time::timeout(CANCEL_BUDGET, async {
            tokio::select! {
                result = &mut *outer_server => panic!(
                    "outer server stopped during rollback client start poll: {result:?}"),
                () = one_poll => {},
            }
        })
        .await
        .expect("one actual rollback client start poll is Pending before waiter storage ends");
        let (source, transaction, _signed, _item) = put.expect("rollback client PUT captured");
        (source, transaction)
    };

    tokio::time::timeout(CANCEL_BUDGET, async {
        tokio::select! {
            result = &mut *outer_server => panic!(
                "outer server stopped while rollback client PUT is acknowledged: {result:?}"),
            _ = peer.acknowledge(source, &transaction) => {},
        }
    })
    .await
    .expect("rollback client's own PUT is acknowledged while its gate stays closed");

    {
        let mut shutdown = std::pin::pin!(role.shutdown());
        let one_poll = std::future::poll_fn(|cx| match shutdown.as_mut().poll(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(result) => panic!(
                "rollback client shutdown completed while its gate stayed closed: {result:?}"
            ),
        });
        tokio::time::timeout(CANCEL_BUDGET, async {
            tokio::select! {
                result = &mut *outer_server => panic!(
                    "outer server stopped during rollback client shutdown poll: {result:?}"),
                () = one_poll => {},
            }
        })
        .await
        .expect("one actual rollback client shutdown poll is Pending before waiter storage ends");
    }
    let _ = release.send(());
    let joined = tokio::time::timeout(CANCEL_BUDGET, async {
        tokio::select! {
            result = &mut *outer_server => panic!(
                "outer server stopped while rollback client close joins: {result:?}"),
            result = role.shutdown() => result,
        }
    })
    .await
    .expect("same rollback client shutdown joins after gate release");
    assert_eq!(
        joined,
        Ok(()),
        "rollback client joins its real composition cleanly"
    );
    let repeated = tokio::time::timeout(CANCEL_BUDGET, async {
        tokio::select! {
            result = &mut *outer_server => panic!(
                "outer server stopped during repeated rollback client shutdown: {result:?}"),
            result = role.shutdown() => result,
        }
    })
    .await
    .expect("repeated rollback client shutdown completes");
    assert_eq!(
        repeated, joined,
        "repeated rollback client shutdown matches terminal result"
    );
    assert_client_binds_released(config, "rollback client");
    tokio::time::timeout(CANCEL_BUDGET, async {
        tokio::select! {
            result = &mut *outer_server => panic!(
                "outer server stopped during rollback client key reuse: {result:?}"),
            () = assert_key_released_once(ROLLBACK_CLIENT, "rollback client identity") => {},
        }
    })
    .await
    .expect("rollback client identity release is checked while the outer server is driven");
}

/// L0: the client role builds and starts with NO signaling relay fields.
/// The former unconditional `NetworkRequired` seed is gone; the standby
/// owner is built with a relay-less dialer and the local listener becomes
/// ready without any relay dial. End-to-end path choice belongs to later
/// leaves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_role_starts_without_relay_fields() {
    tokio::time::timeout(CANCEL_BUDGET, async {
        let silent = silent_udp();
        let bootstrap: SocketAddrV4 = match silent.address {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => panic!("silent bootstrap must bind IPv4"),
        };
        let (transit, transit_port) = start_listener(RELAYLESS_TRANSIT).await;
        let transit_uri = format!("tcp://127.0.0.1:{transit_port}");
        let server_key_hex = pub_key_hex(&identity(RELAYLESS_CLIENT));
        let mainline_bind = format!("127.0.0.1:{}", reserve_udp_port());
        let signaling_bind = format!("127.0.0.1:{}", reserve_tcp_port());
        let text = format!(
            "server: {server_key_hex}\nlisten: 127.0.0.1:0\nfallback: standby\nnetwork: {{\n    \
             mainline: {{\n        bind: {mainline_bind}\n        bootstrap: [\n            \
             {bootstrap}\n        ]\n    }}\n    signaling: {{\n        bind: {signaling_bind}\n    \
             }}\n    ygg: {{\n        peers: [\n            {transit_uri}\n        ]\n    }}\n}}\n"
        );
        let config = ClientConfig::from_text(&text, &ClientOverrides::default())
            .expect("relay-less client config parses");
        let role_identity = identity(RELAYLESS_CLIENT);
        let (log, _client_log_unused) = role_logs();
        let mut role = ClientRole::with_events(
            config.clone(),
            &role_identity,
            Limits::new(4).expect("fixture limits"),
            tuned_policy(),
            log.clone(),
        )
        .expect("relay-less client role builds");
        let (stop, stop_rx) = oneshot::channel();
        let mut client = pin_role(async move {
            let mut role = role;
            let mut shutdown = std::pin::pin!(async move {
                let _ = stop_rx.await;
            });
            let outcome = match role.start().await {
                Ok(()) => role.run(&mut shutdown).await,
                Err(error) => Err(error),
            };
            let close = role.shutdown().await;
            outcome.and(close)
        });

        let listener_ready = |event: &RoleEvent| matches!(event, RoleEvent::ListenerReady(_));
        let listener = tokio::time::timeout(CANCEL_BUDGET, async {
            tokio::select! {
                result = &mut client => panic!("relay-less client role ended early: {result:?}"),
                event = log.wait(&listener_ready) => match event {
                    RoleEvent::ListenerReady(address) => address,
                    other => panic!("unexpected role event while starting: {other:?}"),
                },
            }
        })
        .await
        .expect("the relay-less client reaches its listener");
        assert!(listener.port() != 0, "the listener bound a real port");

        let _ = stop.send(());
        tokio::time::timeout(CANCEL_BUDGET, client)
            .await
            .expect("relay-less client stops within the budget")
            .expect("relay-less client joined shutdown succeeds");

        assert_client_binds_released(&config, "relay-less client");
        drop(silent);
        let closed = tokio::time::timeout(CANCEL_BUDGET, transit.close()).await;
        assert!(closed.is_ok() && closed.expect("checked").is_ok(), "transit close");
        probe_claim_free(RELAYLESS_CLIENT, "relay-less client claim released").await;
        probe_claim_free(RELAYLESS_TRANSIT, "relay-less transit claim released").await;
    })
    .await
    .expect("the relay-less client startup case completes within the budget");
}
