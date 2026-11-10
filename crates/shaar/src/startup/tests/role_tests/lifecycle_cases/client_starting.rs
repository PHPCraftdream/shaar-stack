//! Client Starting-phase cancellation rollback over a real seamed composition.

use std::future::Future;
use std::task::Poll;
use std::time::Duration;

use crate::config::ClientConfig;
use crate::identity::Identity;
use crate::native_discovery::runtime::owner::LoopbackPeer;
use crate::network::Limits;
use crate::startup::StartupError;
use crate::startup::role::ClientRole;

use super::super::fixtures::{role_logs, tuned_policy};
use super::helpers::{assert_client_binds_released, assert_key_released_once};

pub(super) const ROLLBACK_CLIENT: u8 = 0x6B;
const CANCEL_BUDGET: Duration = Duration::from_secs(150);

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
