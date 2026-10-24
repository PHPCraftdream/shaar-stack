#![forbid(unsafe_code)]
//! Shared actor shutdown boundary, compiled by iroh and the SDK regression tests.

use n0_future::{
    task::{AbortOnDropHandle, JoinError},
    time,
};
use std::{future::Future, time::Duration};
use tokio_util::task::TaskTracker;

/// Registers before spawn; the lease ends only after the future is destroyed.
pub(crate) fn track_child<F: Future>(
    tracker: &TaskTracker,
    future: F,
) -> impl Future<Output = F::Output> + use<F> {
    tracker.track_future(future)
}

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
    async fn child_lease_covers_unpolled_and_pending_future_destruction() {
        for (address, poll_child) in [("127.0.0.1:20014", false), ("127.0.0.1:20015", true)] {
            let tracker = TaskTracker::new();
            let socket = UdpSocket::bind(address).await.unwrap();
            let child = track_child(&tracker, async move {
                let _socket = socket;
                std::future::pending::<()>().await;
            });
            let mut child = Box::pin(child);
            if poll_child {
                std::future::poll_fn(|cx| {
                    assert!(child.as_mut().poll(cx).is_pending());
                    std::task::Poll::Ready(())
                })
                .await;
            }
            tracker.close();
            let wait = tracker.wait();
            tokio::pin!(wait);
            // Removing tracking must fail here, even if the child has not run.
            std::future::poll_fn(|cx| {
                assert!(wait.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            drop(child);
            wait.await;
            let _rebound = UdpSocket::bind(address).await.unwrap();
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn runtime_waits_for_children_after_parent_exit_abort_or_panic() {
        time::timeout(Duration::from_secs(10), async {
            for (address, mode) in [
                ("127.0.0.1:20016", 0),
                ("127.0.0.1:20017", 1),
                ("127.0.0.1:20018", 2),
            ] {
                let tracker = TaskTracker::new();
                let socket = UdpSocket::bind(address).await.unwrap();
                let child = track_child(&tracker, async move {
                    let _socket = socket;
                    std::future::pending::<()>().await;
                });
                let (ready, observed) = oneshot::channel();
                let parent = AbortOnDropHandle::new(n0_future::task::spawn(async move {
                    let mut children = n0_future::task::JoinSet::new();
                    children.spawn(child);
                    ready.send(()).unwrap();
                    match mode {
                        0 => (),
                        1 => std::future::pending::<()>().await,
                        _ => panic!("parent child-ownership fixture"),
                    }
                }));
                observed.await.unwrap();
                let result = finish_actor(parent).await;
                match mode {
                    0 => result.unwrap(),
                    1 => assert!(result.unwrap_err().is_cancelled()),
                    _ => assert!(result.unwrap_err().is_panic()),
                }
                tracker.close();
                tracker.wait().await;
                let _rebound = UdpSocket::bind(address).await.unwrap();
            }
        })
        .await
        .expect("nested actor destruction deadline");
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
