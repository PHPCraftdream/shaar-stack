#![forbid(unsafe_code)]
//! Shared endpoint shutdown boundaries, compiled by iroh and SDK regression tests.

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

/// Bounds best-effort peer notification, not subsequent joined local shutdown.
/// Pass only a closure observer, never an owner or task handle.
/// cancel-safe: yes — dropping the observer does not cancel its drivers.
pub(crate) async fn wait_for_protocol_close(observer: impl Future<Output = ()>) -> bool {
    time::timeout(Duration::from_secs(3), observer)
        .await
        .is_ok()
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

/// Closes kernel sockets explicitly; netwatch's Drop detaches its blocking close task.
/// cancel-safe: NO — cancellation cannot join the remaining sockets' kernel closes.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub(crate) async fn close_native_sockets(sockets: &[std::sync::Arc<netwatch::UdpSocket>]) {
    for socket in sockets {
        socket.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{net::UdpSocket, sync::oneshot};

    #[tokio::test(flavor = "current_thread")]
    async fn protocol_close_observes_ready_and_later_completion() {
        let mut ready = Box::pin(wait_for_protocol_close(std::future::ready(())));
        std::future::poll_fn(|cx| {
            assert_eq!(ready.as_mut().poll(cx), std::task::Poll::Ready(true));
            std::task::Poll::Ready(())
        })
        .await;
        let (complete, mut observed) = oneshot::channel();
        let mut waiting = Box::pin(wait_for_protocol_close(async {
            (&mut observed).await.unwrap();
        }));
        std::future::poll_fn(|cx| {
            assert!(waiting.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        complete.send(()).unwrap();
        assert!(waiting.await);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn protocol_close_grace_expiry_drops_only_the_observer() {
        time::timeout(Duration::from_secs(10), async {
            let (complete, mut observed) = oneshot::channel();
            assert!(
                !wait_for_protocol_close(async {
                    (&mut observed).await.unwrap();
                })
                .await
            );
            // The producer and its receiver remain usable after grace expiry.
            complete.send(()).unwrap();
            observed.await.unwrap();
        })
        .await
        .expect("protocol close grace did not expire");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelling_protocol_close_drops_only_the_observer() {
        let (complete, mut observed) = oneshot::channel();
        let mut waiting = Box::pin(wait_for_protocol_close(async {
            (&mut observed).await.unwrap();
        }));
        std::future::poll_fn(|cx| {
            assert!(waiting.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(waiting);
        complete.send(()).unwrap();
        observed.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn explicit_native_close_releases_sockets_with_sender_aliases_alive() {
        close_native_sockets(&[]).await;
        let first = std::sync::Arc::new(netwatch::UdpSocket::bind_local_v4(20041).unwrap());
        let second = std::sync::Arc::new(netwatch::UdpSocket::bind_local_v4(20042).unwrap());
        let first_sender = first.clone().create_sender();
        let second_sender = second.clone().create_sender();
        let sockets = [first.clone(), second.clone()];
        close_native_sockets(&sockets).await;
        assert!(first.is_closed() && second.is_closed());
        let _first_rebound = UdpSocket::bind("127.0.0.1:20041").await.unwrap();
        let _second_rebound = UdpSocket::bind("127.0.0.1:20042").await.unwrap();
        close_native_sockets(&sockets).await;
        drop((first_sender, second_sender));
    }

    #[test]
    fn native_drop_can_finish_before_its_detached_kernel_close() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        let (entered, observed) = std::sync::mpsc::sync_channel(1);
        let (release, released) = std::sync::mpsc::sync_channel(1);
        let blocker = runtime.spawn_blocking(move || {
            entered.send(()).unwrap();
            // Sender disappearance also releases this fixture during unwinding.
            let _ = released.recv();
        });
        observed.recv_timeout(Duration::from_secs(5)).unwrap();
        runtime.block_on(async {
            let socket = netwatch::UdpSocket::bind_local_v4(20043).unwrap();
            drop(socket);
            let error = UdpSocket::bind("127.0.0.1:20043").await.unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        });
        release.send(()).unwrap();
        runtime.block_on(blocker).unwrap();
        // Runtime Drop joins the foreign blocking close, unlike socket/actor Drop.
        drop(runtime);
        let _rebound = std::net::UdpSocket::bind("127.0.0.1:20043").unwrap();
    }

    #[test]
    fn explicit_native_close_waits_until_the_blocking_pool_executes_kernel_close() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        let (entered, observed) = std::sync::mpsc::sync_channel(1);
        let (release, released) = std::sync::mpsc::sync_channel(1);
        let blocker = runtime.spawn_blocking(move || {
            entered.send(()).unwrap();
            let _ = released.recv();
        });
        observed.recv_timeout(Duration::from_secs(5)).unwrap();
        runtime.block_on(async {
            let socket = std::sync::Arc::new(netwatch::UdpSocket::bind_local_v4(20044).unwrap());
            let sockets = [socket.clone()];
            let close = close_native_sockets(&sockets);
            tokio::pin!(close);
            std::future::poll_fn(|cx| {
                assert!(close.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            assert!(socket.is_closed());
            assert_eq!(
                UdpSocket::bind("127.0.0.1:20044").await.unwrap_err().kind(),
                std::io::ErrorKind::AddrInUse
            );
            release.send(()).unwrap();
            blocker.await.unwrap();
            close.await;
            let _rebound = UdpSocket::bind("127.0.0.1:20044").await.unwrap();
        });
    }

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
