#![forbid(unsafe_code)]

use super::noq;
use std::{
    future::Future,
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Wake, Waker},
    time::Duration,
};

#[path = "support.rs"]
pub(crate) mod support;
use support::Fixture;

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn pending(mut future: std::pin::Pin<&mut impl Future>) -> Arc<WakeCount> {
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(count.clone());
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    count
}

// cancel-safe: NO — phase expiry terminates this owned fixture.
async fn stage<T>(label: &'static str, future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(3), future)
        .await
        .unwrap_or_else(|_| panic!("{label}"))
}

#[derive(Clone, Copy)]
enum Exit {
    Io,
    Cancel,
    CancelQueuedRebind,
    Normal,
    LocalCloseIo,
    PeerCloseCancel,
    EndpointCancel,
}

// cancel-safe: NO — the test owns every task; a timeout fails the whole fixture.
async fn exercise(exit: Exit) {
    let fixture = Fixture::new();
    let (client, server) = stage("HANDSHAKE_DEADLINE", fixture.connect()).await;
    let mut send = client.open_uni().await.unwrap();
    let receive = stage("RETAINED_STREAM_DEADLINE", async {
        send.write_all(b"ready").await.unwrap();
        let mut receive = server.accept_uni().await.unwrap();
        let mut ready = [0; 5];
        receive.read_exact(&mut ready).await.unwrap();
        assert_eq!(&ready, b"ready");
        receive
    })
    .await;
    let path = client.path(noq::PathId::ZERO).unwrap();
    let weak_path = path.weak_handle();
    let weak = client.weak_handle();
    let on_closed = client.on_closed();
    let mut closed = Box::pin(client.closed());
    let mut all_draining = Box::pin(fixture.client.wait_all_draining());
    let mut idle = Box::pin(fixture.client.wait_idle());
    let closed_wakes = pending(closed.as_mut());
    let draining_wakes = pending(all_draining.as_mut());
    let idle_wakes = pending(idle.as_mut());

    let reason = match exit {
        Exit::Io | Exit::Cancel | Exit::CancelQueuedRebind | Exit::LocalCloseIo => {
            fixture.gate.arm();
            if matches!(exit, Exit::LocalCloseIo) {
                client.close(19u32.into(), b"local close before failure");
            } else {
                path.ping().unwrap();
            }
            stage("TRANSMIT_BARRIER_DEADLINE", fixture.gate.reached.notified()).await;
            if matches!(exit, Exit::Cancel | Exit::CancelQueuedRebind) {
                let queued =
                    matches!(exit, Exit::CancelQueuedRebind).then(|| fixture.queue_rebind());
                // Current-thread runtime: abort before the queued Rebind can be processed.
                fixture.client_runtime.join(1, true).await;
                if let Some(queued) = queued {
                    assert!(
                        queued.dropped.load(Ordering::SeqCst),
                        "queued sender survived driver destruction"
                    );
                }
                noq::ConnectionError::LocallyClosed
            } else {
                fixture.gate.release();
                stage(
                    "FATAL_DRIVER_JOIN_DEADLINE",
                    fixture.client_runtime.join(1, false),
                )
                .await;
                assert!(fixture.gate.failed.load(Ordering::SeqCst));
                if matches!(exit, Exit::LocalCloseIo) {
                    noq::ConnectionError::LocallyClosed
                } else {
                    noq::ConnectionError::LocalIo(io::ErrorKind::BrokenPipe)
                }
            }
        }
        Exit::Normal => {
            client.close(21u32.into(), b"ordinary close");
            fixture.client_runtime.join(1, false).await;
            noq::ConnectionError::LocallyClosed
        }
        Exit::PeerCloseCancel => {
            server.close(23u32.into(), b"peer close");
            let reason = client.closed().await;
            assert!(
                matches!(&reason, noq::ConnectionError::ApplicationClosed(close)
                if close.error_code == 23u32.into() && close.reason.as_ref() == b"peer close")
            );
            fixture.client_runtime.join(1, true).await;
            reason
        }
        Exit::EndpointCancel => {
            fixture.client_runtime.join(0, true).await;
            fixture.client_runtime.join(1, false).await;
            let reason = client.closed().await;
            assert!(
                matches!(&reason, noq::ConnectionError::TransportError(error)
                if error.code == noq::TransportErrorCode::INTERNAL_ERROR)
            );
            reason
        }
    };
    assert!(fixture.gate.dropped.load(Ordering::SeqCst));
    if matches!(exit, Exit::Io) {
        assert!(fixture.gate.failed.load(Ordering::SeqCst));
        assert!(
            weak.is_alive(),
            "retained connection escaped before notification phase"
        );
        assert_eq!(send.id().initiator(), noq::Side::Client);
        eprintln!("POST_FATAL_PRECONDITIONS_OK");
        stage("POST_FATAL_NOTIFICATION_DEADLINE", async {
            tokio::join!(
                client.closed(),
                fixture.client.wait_all_draining(),
                fixture.client.wait_idle()
            );
        })
        .await;
    }
    stage("ENDPOINT_IDLE_DEADLINE", fixture.client.wait_idle()).await;
    assert!(
        closed_wakes.0.load(Ordering::SeqCst) > 0,
        "closed waiter was not woken"
    );
    assert!(
        draining_wakes.0.load(Ordering::SeqCst) > 0,
        "draining waiter was not woken"
    );
    assert!(
        idle_wakes.0.load(Ordering::SeqCst) > 0,
        "idle waiter was not woken"
    );
    assert_eq!(closed.as_mut().await, reason);
    assert_eq!(on_closed.await.reason, reason);
    assert_eq!(client.on_closed().await.reason, reason);
    assert_eq!(client.close_reason(), Some(reason.clone()));
    assert!(matches!(send.write(b"after close").await,
        Err(noq::WriteError::ConnectionLost(error)) if error == reason));
    all_draining.as_mut().await;
    idle.as_mut().await;
    assert!(weak.is_alive(), "connection and stream remain retained");
    let _stats = path.stats();

    // Release the futures' borrows before moving their owners.
    drop(closed);
    drop(all_draining);
    drop(idle);
    server.close(0u32.into(), b"");
    if !matches!(exit, Exit::EndpointCancel) {
        // The one-entry client quota proves metadata was returned before handle drop.
        let (second, peer) = stage("SLOT_REUSE_DEADLINE", fixture.connect()).await;
        drop((send, client, path, weak_path));
        assert!(
            !weak.is_alive(),
            "no driver or observer strong reference escaped"
        );
        assert!(second.close_reason().is_none());
        let (stream, received) = stage("SLOT_REUSE_DATA_DEADLINE", async {
            let mut stream = second.open_uni().await.unwrap();
            stream.write_all(b"reused").await.unwrap();
            let mut received = peer.accept_uni().await.unwrap();
            let mut bytes = [0; 6];
            received.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"reused", "old drop must not drain the reused slot");
            (stream, received)
        })
        .await;
        second.close(0u32.into(), b"");
        peer.close(0u32.into(), b"");
        drop((stream, received, second, peer));
    } else {
        drop((send, client, path, weak_path));
        assert!(!weak.is_alive());
    }
    drop((receive, server));
    stage("CLEANUP_DEADLINE", fixture.finish()).await;
}

#[tokio::test]
async fn fatal_send_after_handshake_releases_retained_connection_and_stream() {
    tokio::time::timeout(Duration::from_secs(10), exercise(Exit::Io))
        .await
        .expect("OUTER_DEADLINE");
}

#[tokio::test]
async fn cancelled_driver_releases_retained_connection_and_stream() {
    tokio::time::timeout(Duration::from_secs(10), exercise(Exit::Cancel))
        .await
        .unwrap();
}

#[tokio::test]
async fn cancellation_drops_a_queued_rebind_sender_with_handles_retained() {
    tokio::time::timeout(Duration::from_secs(10), exercise(Exit::CancelQueuedRebind))
        .await
        .unwrap();
}

#[tokio::test]
async fn unpolled_driver_cancellation_finishes_connecting_and_endpoint() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let fixture = Fixture::new();
        let connecting = fixture
            .client
            .connect(fixture.server.local_addr().unwrap(), "localhost")
            .unwrap();
        // No await between construction and abort on this current-thread runtime.
        fixture.client_runtime.join(1, true).await;
        assert_eq!(
            connecting.await.unwrap_err(),
            noq::ConnectionError::LocallyClosed
        );
        fixture.client.wait_all_draining().await;
        fixture.client.wait_idle().await;
        assert!(fixture.gate.dropped.load(Ordering::SeqCst));
        fixture.finish().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn normal_close_and_old_handle_drop_do_not_drain_reused_slot() {
    tokio::time::timeout(Duration::from_secs(10), exercise(Exit::Normal))
        .await
        .unwrap();
}

#[tokio::test]
async fn send_failure_preserves_existing_local_close() {
    tokio::time::timeout(Duration::from_secs(10), exercise(Exit::LocalCloseIo))
        .await
        .unwrap();
}

#[tokio::test]
async fn cancellation_preserves_existing_peer_close() {
    tokio::time::timeout(Duration::from_secs(10), exercise(Exit::PeerCloseCancel))
        .await
        .unwrap();
}

#[tokio::test]
async fn endpoint_loss_wakes_registered_shutdown_waiters() {
    tokio::time::timeout(Duration::from_secs(10), exercise(Exit::EndpointCancel))
        .await
        .unwrap();
}

#[tokio::test]
async fn fatal_initial_reports_local_io_before_handshake() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let fixture = Fixture::new();
        fixture.gate.arm();
        let connecting = fixture
            .client
            .connect(fixture.server.local_addr().unwrap(), "localhost")
            .unwrap();
        fixture.gate.reached.notified().await;
        fixture.gate.release();
        fixture.client_runtime.join(1, false).await;
        let error = connecting.await.unwrap_err();
        assert_eq!(
            error,
            noq::ConnectionError::LocalIo(io::ErrorKind::BrokenPipe)
        );
        let converted: io::Error = error.into();
        assert_eq!(converted.kind(), io::ErrorKind::BrokenPipe);
        fixture.client.wait_all_draining().await;
        fixture.client.wait_idle().await;
        assert!(fixture.gate.dropped.load(Ordering::SeqCst));
        fixture.finish().await;
    })
    .await
    .unwrap();
}
