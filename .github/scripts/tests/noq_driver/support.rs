#![forbid(unsafe_code)]

use super::noq;
use std::{
    future::Future,
    io::{self, IoSliceMut},
    net::{SocketAddr, UdpSocket},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};
use tokio::{sync::Notify, task::JoinHandle};

#[derive(Debug, Default)]
pub struct Gate {
    phase: AtomicU8,
    waker: Mutex<Option<Waker>>,
    pub reached: Notify,
    pub failed: AtomicBool,
    pub dropped: AtomicBool,
}

impl Gate {
    pub fn arm(&self) {
        assert_eq!(self.phase.swap(1, Ordering::SeqCst), 0);
    }

    pub fn release(&self) {
        self.phase.store(2, Ordering::SeqCst);
        let wake = self.waker.lock().unwrap().take();
        if let Some(wake) = wake {
            wake.wake();
        }
    }
}

#[derive(Debug)]
struct FaultSender {
    inner: Pin<Box<dyn noq::UdpSender>>,
    gate: Option<Arc<Gate>>,
}

impl noq::UdpSender for FaultSender {
    fn poll_send(
        mut self: Pin<&mut Self>,
        transmit: &noq::udp::Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(gate) = &self.gate {
            if gate.phase.load(Ordering::SeqCst) == 1 {
                *gate.waker.lock().unwrap() = Some(cx.waker().clone());
                gate.reached.notify_one();
                if gate.phase.load(Ordering::SeqCst) == 1 {
                    return Poll::Pending;
                }
            }
            if gate.phase.load(Ordering::SeqCst) == 2 {
                gate.failed.store(true, Ordering::SeqCst);
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "chosen fatal transmit",
                )));
            }
        }
        self.inner.as_mut().poll_send(transmit, cx)
    }
}

impl Drop for FaultSender {
    fn drop(&mut self) {
        if let Some(gate) = &self.gate {
            gate.dropped.store(true, Ordering::SeqCst);
        }
    }
}

#[derive(Debug)]
struct FaultSocket {
    inner: Box<dyn noq::AsyncUdpSocket>,
    gate: Arc<Gate>,
    senders: AtomicUsize,
}

impl noq::AsyncUdpSocket for FaultSocket {
    fn create_sender(&self) -> Pin<Box<dyn noq::UdpSender>> {
        // Endpoint sender first, then the first connection's independently owned sender.
        let connection = self.senders.fetch_add(1, Ordering::SeqCst) == 1;
        Box::pin(FaultSender {
            inner: self.inner.create_sender(),
            gate: connection.then(|| self.gate.clone()),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [noq::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

#[derive(Debug, Default)]
pub struct TrackedRuntime {
    // Test-only: at most one endpoint and two sequential connections per runtime.
    tasks: Mutex<Vec<Option<JoinHandle<()>>>>,
}

impl TrackedRuntime {
    pub async fn join(&self, index: usize, abort: bool) {
        let task = self.tasks.lock().unwrap()[index].take().unwrap();
        if abort {
            task.abort();
        }
        match task.await {
            Ok(()) => {}
            Err(error) if abort && error.is_cancelled() => {}
            Err(error) => panic!("driver failed: {error}"),
        }
    }

    pub async fn join_remaining(&self) {
        let tasks = std::mem::take(&mut *self.tasks.lock().unwrap());
        for task in tasks.into_iter().flatten() {
            task.await.expect("driver completed without panic");
        }
    }
}

impl Drop for TrackedRuntime {
    fn drop(&mut self) {
        for task in self.tasks.get_mut().unwrap().iter().flatten() {
            task.abort();
        }
    }
}

impl noq::Runtime for TrackedRuntime {
    fn new_timer(&self, when: std::time::Instant) -> Pin<Box<dyn noq::AsyncTimer>> {
        noq::TokioRuntime.new_timer(when)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        let mut tasks = self.tasks.lock().unwrap();
        assert!(tasks.len() < 3, "fixture task bound");
        tasks.push(Some(tokio::spawn(future)));
    }

    fn wrap_udp_socket(&self, socket: UdpSocket) -> io::Result<Box<dyn noq::AsyncUdpSocket>> {
        noq::TokioRuntime.wrap_udp_socket(socket)
    }

    fn now(&self) -> std::time::Instant {
        noq::TokioRuntime.now()
    }
}

pub struct Fixture {
    pub client: noq::Endpoint,
    pub server: noq::Endpoint,
    pub client_runtime: Arc<TrackedRuntime>,
    pub server_runtime: Arc<TrackedRuntime>,
    pub gate: Arc<Gate>,
}

impl Fixture {
    pub fn new() -> Self {
        use noq::Runtime;
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into());
        let mut server_config =
            noq::ServerConfig::with_single_cert(vec![cert.der().clone()], key).unwrap();
        let mut transport = noq::TransportConfig::default();
        transport.max_concurrent_multipath_paths(4);
        let transport = Arc::new(transport);
        server_config.transport_config(transport.clone());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let mut client_config = noq::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
        client_config.transport_config(transport);
        let client_runtime = Arc::new(TrackedRuntime::default());
        let server_runtime = Arc::new(TrackedRuntime::default());
        let gate = Arc::new(Gate::default());
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let socket = FaultSocket {
            inner: client_runtime.wrap_udp_socket(socket).unwrap(),
            gate: gate.clone(),
            senders: AtomicUsize::new(0),
        };
        let mut config = noq::EndpointConfig::default();
        config.max_connections(1);
        let client = noq::Endpoint::new_with_abstract_socket(
            config,
            None,
            Box::new(socket),
            client_runtime.clone(),
        )
        .unwrap();
        client.set_default_client_config(client_config);
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let server = noq::Endpoint::new(
            noq::EndpointConfig::default(),
            Some(server_config),
            socket,
            server_runtime.clone(),
        )
        .unwrap();
        Self {
            client,
            server,
            client_runtime,
            server_runtime,
            gate,
        }
    }

    pub fn queue_rebind(&self) -> Arc<Gate> {
        use noq::Runtime;
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let gate = Arc::new(Gate::default());
        self.client
            .rebind_abstract(Box::new(FaultSocket {
                inner: self.client_runtime.wrap_udp_socket(socket).unwrap(),
                gate: gate.clone(),
                // Rebind creates a connection sender without a new endpoint sender.
                senders: AtomicUsize::new(1),
            }))
            .unwrap();
        gate
    }

    pub async fn connect(&self) -> (noq::Connection, noq::Connection) {
        let client = self
            .client
            .connect(self.server.local_addr().unwrap(), "localhost")
            .unwrap();
        let server = async { self.server.accept().await.unwrap().await.unwrap() };
        let (client, server) = tokio::join!(client, server);
        (client.unwrap(), server)
    }

    pub async fn finish(self) {
        self.client.close(0u32.into(), b"");
        self.server.close(0u32.into(), b"");
        tokio::join!(self.client.wait_idle(), self.server.wait_idle());
        self.client_runtime.join_remaining().await;
        self.server_runtime.join_remaining().await;
    }
}
