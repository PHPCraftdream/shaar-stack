use super::{support::*, *};
use futures::{
    FutureExt,
    task::{ArcWake, waker},
};
use hickory_resolver::net::runtime::{DnsUdpSocket, Spawn};
use libp2p::dns::Resolver as _;
use std::{
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context, Poll},
};
use tokio::sync::{mpsc, watch};

#[derive(Default)]
struct Wakes(AtomicUsize);
impl ArcWake for Wakes {
    fn wake_by_ref(this: &Arc<Self>) {
        this.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn owned_dns_close_rejects_precreated_unpolled_lookup_connect_and_bind() {
    let server = Server::new().await;
    let (executor, lifetime, resolver, provider) = setup(server.address);
    let bind = provider.bind_udp(loopback(), server.address);
    let connect = provider.connect_tcp(server.address, None, None);
    let lookup = resolver.ipv4_lookup("unpolled.example.".into());
    lifetime.close();
    assert_eq!(bind.await.err().unwrap().kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(
        connect.await.err().unwrap().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert!(lookup.await.is_err());
    assert!(
        server.tcp.accept().now_or_never().is_none(),
        "CLOSED_UNPOLLED_TCP_CONNECTED"
    );
    server.quiet();
    assert_eq!(executor.active_tasks().unwrap(), 0);
    executor.shutdown().await.unwrap();
}

#[tokio::test]
async fn owned_dns_every_udp_send_and_socket_admission_checks_exact_endpoint() {
    let server = Server::new().await;
    let other = Server::new().await;
    let (executor, lifetime, _resolver, provider) = setup(server.address);
    assert_eq!(
        provider
            .bind_udp(loopback(), other.address)
            .await
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        provider
            .connect_tcp(other.address, None, None)
            .await
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    let socket = provider.bind_udp(loopback(), server.address).await.unwrap();
    assert_eq!(
        socket
            .send_to(b"not DNS", other.address)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    other.quiet();
    assert!(other.tcp.accept().now_or_never().is_none());
    // Positive control: the approved custom port is usable through this exact wrapper.
    socket
        .send_to(b"endpoint witness", server.address)
        .await
        .unwrap();
    let mut bytes = [0; 32];
    let (size, _) = server.udp.recv_from(&mut bytes).await.unwrap();
    assert_eq!(&bytes[..size], b"endpoint witness");
    lifetime.close();
    assert_eq!(
        socket
            .send_to(b"late", server.address)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
    drop(socket);
    executor.shutdown().await.unwrap();
    server.quiet();
}

#[tokio::test]
async fn owned_dns_close_wakes_registered_waiters_without_polling_foreign_work() {
    let lifetime = Lifetime::new();
    let gate = lifetime.gate();
    let wakes = Arc::new(Wakes::default());
    let wake = waker(wakes.clone());
    let mut context = Context::from_waker(&wake);
    let polls = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let work = Reenter {
        gate: gate.clone(),
        dropped: dropped.clone(),
        polls: polls.clone(),
    };
    let mut future = Box::pin(gate.during(work));
    assert!(future.as_mut().poll(&mut context).is_pending());
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    lifetime.close();
    assert!(wakes.0.load(Ordering::SeqCst) > 0, "DNS_CLOSE_LOST_WAKE");
    assert!(matches!(
        future.as_mut().poll(&mut context),
        Poll::Ready(Err(_))
    ));
    assert_eq!(
        polls.load(Ordering::SeqCst),
        1,
        "FOREIGN_WORK_POLLED_AFTER_CLOSE"
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "CANCELED_FOREIGN_FUTURE_NOT_DESTROYED"
    );
}

#[tokio::test]
async fn owned_dns_pending_connect_owns_bound_socket_before_spawn_and_close_destroys_it() {
    bounded(
        async {
            let server = Server::new().await;
            let (executor, lifetime, _resolver, mut provider) = setup(server.address);
            let (started, mut observed) = mpsc::channel(1);
            let (_release, released) = watch::channel(false);
            provider.pause_connect =
                Some(super::super::runtime::ConnectPause { started, released });
            let mut connect = provider.connect_tcp(server.address, Some(loopback()), None);
            let local = tokio::select! {
                result = &mut connect => panic!("CONNECT_BARRIER_NOT_HELD: {}", result.is_ok()),
                local = observed.recv() => local.unwrap(),
            };
            assert_eq!(
                executor.active_tasks().unwrap(),
                0,
                "CONNECT_UNEXPECTEDLY_SPAWNED"
            );
            assert!(
                tokio::net::TcpListener::bind(local).await.is_err(),
                "CONNECT_SOCKET_NOT_OWNED"
            );
            lifetime.close();
            assert_eq!(
                connect.await.err().unwrap().kind(),
                io::ErrorKind::BrokenPipe
            );
            executor.shutdown().await.unwrap();
            let _rebound = tokio::net::TcpListener::bind(local).await.unwrap();
            assert!(
                server.tcp.accept().now_or_never().is_none(),
                "UNPOLLED_CONNECT_STARTED_AFTER_CLOSE"
            );
            assert!(
                provider
                    .connect_tcp(server.address, None, None)
                    .await
                    .is_err()
            );
        },
        "OWNED_DNS_PENDING_CONNECT_CLOSE_DEADLINE",
    )
    .await;
}

struct Reenter {
    gate: Gate,
    dropped: Arc<AtomicBool>,
    polls: Arc<AtomicUsize>,
}
impl Future for Reenter {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
}
impl Drop for Reenter {
    fn drop(&mut self) {
        assert!(self.gate.check().is_err());
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn owned_dns_lifetime_drop_closes_retained_handles_and_rejected_drop_can_reenter() {
    let server = Server::new().await;
    let (executor, lifetime, resolver, provider) = setup(server.address);
    let mut handle = provider.create_handle();
    let dropped = Arc::new(AtomicBool::new(false));
    let polls = Arc::new(AtomicUsize::new(0));
    let future = Reenter {
        gate: provider.gate.clone(),
        dropped: dropped.clone(),
        polls: polls.clone(),
    };
    drop(lifetime);
    handle.spawn_bg(future);
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert!(resolver.ipv4_lookup("late.example.".into()).await.is_err());
    assert!(provider.bind_udp(loopback(), server.address).await.is_err());
    executor.shutdown().await.unwrap();
    server.quiet();
}
