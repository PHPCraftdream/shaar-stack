#![forbid(unsafe_code)]

use super::*;
use crate::driver_failure::suite::support::Fixture;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio_stream::StreamExt;

#[derive(Debug, Default)]
struct Receipt {
    calls: AtomicUsize,
    drops: AtomicUsize,
    locked: AtomicUsize,
    missing: AtomicUsize,
}

#[derive(Debug)]
struct Probe {
    connection: WeakConnectionHandle,
    receipt: Arc<Receipt>,
}

impl Probe {
    fn observe(&self) {
        self.receipt.calls.fetch_add(1, Ordering::SeqCst);
        match self.connection.0.upgrade() {
            Some(connection) => {
                if !connection.state.driver_test_available() {
                    self.receipt.locked.fetch_add(1, Ordering::SeqCst);
                }
            }
            None => {
                self.receipt.missing.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        self.receipt.drops.fetch_add(1, Ordering::SeqCst);
        self.observe();
    }
}

fn probe(connection: &Connection) -> (Probe, Arc<Receipt>) {
    let receipt = Arc::new(Receipt::default());
    (
        Probe {
            connection: connection.weak_handle(),
            receipt: receipt.clone(),
        },
        receipt,
    )
}

fn released(receipt: &Receipt) {
    assert!(
        receipt.drops.load(Ordering::SeqCst) > 0,
        "resource was not destroyed"
    );
    assert_eq!(
        receipt.locked.load(Ordering::SeqCst),
        0,
        "resource callback ran under connection lock"
    );
    assert_eq!(
        receipt.missing.load(Ordering::SeqCst),
        0,
        "retained connection was unavailable"
    );
}

#[derive(Debug)]
struct SenderProbe {
    inner: Pin<Box<dyn UdpSender>>,
    _probe: Probe,
}

impl UdpSender for SenderProbe {
    fn poll_send(
        mut self: Pin<&mut Self>,
        transmit: &crate::udp::Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.inner.as_mut().poll_send(transmit, cx)
    }
}

#[derive(Debug)]
struct TimerProbe {
    inner: Pin<Box<dyn AsyncTimer>>,
    _probe: Probe,
}

impl AsyncTimer for TimerProbe {
    fn reset(mut self: Pin<&mut Self>, when: Instant) {
        self.inner.as_mut().reset(when);
    }
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.inner.as_mut().poll(cx)
    }
}

struct ProbeWake(Probe);
impl std::task::Wake for ProbeWake {
    fn wake(self: Arc<Self>) {
        self.0.observe();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.observe();
    }
}

#[derive(Debug)]
struct RebindSocket {
    inner: Box<dyn crate::AsyncUdpSocket>,
    connection: WeakConnectionHandle,
    receipt: Arc<Receipt>,
}
impl crate::AsyncUdpSocket for RebindSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(SenderProbe {
            inner: self.inner.create_sender(),
            _probe: Probe {
                connection: self.connection.clone(),
                receipt: self.receipt.clone(),
            },
        })
    }
    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [crate::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

// cancel-safe: NO — the timeout fails the entire fixture.
async fn inspect_driver_drop(fatal: bool) {
    let fixture = Fixture::new();
    let (client, server) = fixture.connect().await;
    let mut stream = client.open_uni().await.unwrap();
    stream.write_all(b"retained").await.unwrap();
    let mut received = server.accept_uni().await.unwrap();
    let mut data = [0; 8];
    received.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"retained");
    let (control, calibration) = probe(&client);
    {
        let _state = client
            .0
            .lock_without_waking("driver_test_probe_calibration");
        control.observe();
    }
    assert_eq!(calibration.locked.load(Ordering::SeqCst), 1);
    control.observe();
    assert_eq!(calibration.calls.load(Ordering::SeqCst), 2);
    assert_eq!(calibration.locked.load(Ordering::SeqCst), 1);
    drop(control);
    assert_eq!(calibration.drops.load(Ordering::SeqCst), 1);
    let unused = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut events = client.path_events();
    let mut opening = Box::pin(loop {
        let opening = client.open_path(unused.local_addr().unwrap(), proto::PathStatus::Backup);
        if opening.path_id().is_some() {
            break opening;
        }
        assert_eq!(
            opening.await.unwrap_err(),
            proto::PathError::RemoteCidsExhausted
        );
        loop {
            if matches!(
                events.next().await.unwrap().unwrap(),
                PathEvent::RemoteCidsAvailable { .. }
            ) {
                break;
            }
        }
    });
    // No await after admission: the new validation transmit cannot precede this gate.
    fixture.gate.arm();
    fixture.gate.reached.notified().await;
    let (active_probe, active) = probe(&client);
    let (timer_probe, timer) = probe(&client);
    let (driver_probe, driver) = probe(&client);
    let (path_probe, path) = probe(&client);
    let path_waker = Waker::from(Arc::new(ProbeWake(path_probe)));
    assert!(
        opening
            .as_mut()
            .poll(&mut Context::from_waker(&path_waker))
            .is_pending()
    );
    drop(path_waker);
    let old_waker = {
        let mut state = client.0.lock_without_waking("driver_test_install_probes");
        let sender = state.sender.take().expect("active sender");
        state.sender = Some(Box::pin(SenderProbe {
            inner: sender,
            _probe: active_probe,
        }));
        let old_timer = state.timer.take().expect("active connection timer");
        state.timer = Some(Box::pin(TimerProbe {
            inner: old_timer,
            _probe: timer_probe,
        }));
        state
            .driver
            .replace(Waker::from(Arc::new(ProbeWake(driver_probe))))
    };
    drop(old_waker);
    let queued = Arc::new(Receipt::default());
    if !fatal {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        fixture
            .client
            .rebind_abstract(Box::new(RebindSocket {
                inner: crate::TokioRuntime.wrap_udp_socket(socket).unwrap(),
                connection: client.weak_handle(),
                receipt: queued.clone(),
            }))
            .unwrap();
    }
    if fatal {
        fixture.gate.release();
    }
    fixture.client_runtime.join(1, !fatal).await;
    let weak = client.weak_handle();
    assert!(weak.is_alive());
    // Both application handles remain alive throughout every destructor assertion.
    for receipt in [&active, &timer, &driver] {
        released(receipt);
    }
    if !fatal {
        released(&queued);
    }
    assert!(
        path.calls.load(Ordering::SeqCst) > 0,
        "pending OpenPath was not notified"
    );
    assert_eq!(
        path.locked.load(Ordering::SeqCst),
        0,
        "OpenPath notified under connection lock"
    );
    assert_eq!(
        opening.await.unwrap_err(),
        proto::PathError::ValidationFailed
    );
    released(&path);
    assert!(matches!(
        stream.write(b"closed").await,
        Err(crate::WriteError::ConnectionLost(_))
    ));
    fixture.client.wait_all_draining().await;
    fixture.client.wait_idle().await;
    server.close(0u32.into(), b"");
    drop((client, stream, received, server, events, unused));
    assert!(
        !weak.is_alive(),
        "inspection probes retained a strong connection handle"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn fatal_driver_resource_destructors_observe_unlocked_retained_state() {
    tokio::time::timeout(Duration::from_secs(10), inspect_driver_drop(true))
        .await
        .unwrap();
}

#[tokio::test]
async fn cancelled_driver_resource_destructors_observe_unlocked_retained_state() {
    tokio::time::timeout(Duration::from_secs(10), inspect_driver_drop(false))
        .await
        .unwrap();
}
