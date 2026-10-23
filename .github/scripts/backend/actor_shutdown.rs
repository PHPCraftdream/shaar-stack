#![forbid(unsafe_code)]
//! Shared actor shutdown boundary, compiled by iroh and the SDK regression tests.

use n0_future::{
    task::{AbortOnDropHandle, JoinError},
    time,
};
use std::time::Duration;

/// cancel-safe: NO — dropping this waiter aborts the task but cannot join it.
pub(crate) async fn finish_actor(mut task: AbortOnDropHandle<()>) -> Result<(), JoinError> {
    match time::timeout(Duration::from_millis(100), &mut task).await {
        Ok(result) => result,
        Err(_) => {
            task.abort();
            task.await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{net::UdpSocket, sync::oneshot};

    #[tokio::test(flavor = "current_thread")]
    async fn timed_out_actor_releases_udp_before_shutdown_returns() {
        time::timeout(Duration::from_secs(10), async {
            let address = "127.0.0.1:20011";
            let socket = UdpSocket::bind(address).await.unwrap();
            let task = AbortOnDropHandle::new(n0_future::task::spawn(async move {
                let _socket = socket;
                std::future::pending::<()>().await;
            }));
            let error = finish_actor(task)
                .await
                .expect_err("pending actor must be aborted");
            assert!(error.is_cancelled());
            // Current-thread execution makes an abort-without-join fail immediately here.
            let _rebound = UdpSocket::bind(address)
                .await
                .expect("aborted actor released UDP");
        })
        .await
        .expect("actor abort/join deadline");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn completed_actor_result_is_joined_without_abort() {
        let address = "127.0.0.1:20012";
        let socket = UdpSocket::bind(address).await.unwrap();
        let (ready, observed) = oneshot::channel();
        let task = AbortOnDropHandle::new(n0_future::task::spawn(async move {
            drop(socket);
            ready.send(()).unwrap();
        }));
        observed.await.unwrap();
        finish_actor(task).await.unwrap();
        let _rebound = UdpSocket::bind(address).await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn actor_panic_is_reported_after_its_udp_owner_is_dropped() {
        let address = "127.0.0.1:20013";
        let socket = UdpSocket::bind(address).await.unwrap();
        let (ready, observed) = oneshot::channel();
        let task = AbortOnDropHandle::new(n0_future::task::spawn(async move {
            let _socket = socket;
            ready.send(()).unwrap();
            panic!("actor panic fixture");
        }));
        observed.await.unwrap();
        assert!(finish_actor(task).await.unwrap_err().is_panic());
        let _rebound = UdpSocket::bind(address).await.unwrap();
    }
}
