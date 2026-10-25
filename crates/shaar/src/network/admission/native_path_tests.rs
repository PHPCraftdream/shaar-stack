#![forbid(unsafe_code)]

use super::*;
use crate::network::signaling::{SignaledEndpoint, bind_signaling, peer_id};
use shaar_p2p::CarrierHandle;
use std::{cell::Cell, future::Future, io};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::oneshot,
    task::JoinSet,
};

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

struct Fixture {
    client: Endpoint,
    server: SignaledEndpoint,
    handle: CarrierHandle,
    factory: Arc<SignalingTransport>,
    tasks: JoinSet<io::Result<()>>,
    stops: [oneshot::Sender<()>; 2],
    signaling: [SocketAddr; 2],
    native: [SocketAddr; 2],
    control: Session,
    accepted_control: Session,
}

impl Fixture {
    /// cancel-safe: NO — the outer test deadline aborts retained fixture tasks.
    async fn start() -> Self {
        let a = Identity::generate();
        let b = Identity::generate();
        let pa = a.transport_key().public();
        let pb = b.transport_key().public();
        let mut server =
            SignaledEndpoint::bind(&b, loopback(), loopback(), &[pa], Limits::default())
                .await
                .unwrap();
        let (carrier, handle, incoming) = bind_signaling(&a, loopback(), &[pb]).unwrap();
        let (factory, pump) = SignalingTransport::attach(handle.clone(), incoming).unwrap();
        let (carrier_stop, carrier_stopped) = oneshot::channel();
        let (pump_stop, pump_stopped) = oneshot::channel();
        let mut tasks = JoinSet::new();
        tasks.spawn(carrier.run(async {
            let _ = carrier_stopped.await;
        }));
        tasks.spawn(pump.run(async {
            let _ = pump_stopped.await;
        }));
        let signaling = [handle.local_addr().await.unwrap(), server.signaling_addr()];
        let client = Endpoint::bind_custom(
            &a,
            loopback(),
            Allowlist::new(&[pb]).unwrap(),
            Limits::new(2).unwrap(),
            Some(factory.clone()),
        )
        .await
        .unwrap();
        let native = [client.local_addr(), server.local_addr()];
        let remote = peer_id(&pb).unwrap();
        handle
            .connect(remote, server.signaling_addr())
            .await
            .unwrap();
        let address = factory.peer_address(remote).unwrap();
        let (control, accepted_control) =
            tokio::join!(client.connect_custom(pb, address), server.accept());
        let (control, accepted_control) = (control.unwrap(), accepted_control.unwrap());
        assert_eq!(client.slots.available_permits(), 1);
        Self {
            client,
            server,
            handle,
            factory,
            tasks,
            stops: [carrier_stop, pump_stop],
            signaling,
            native,
            control,
            accepted_control,
        }
    }

    /// cancel-safe: NO — the caller must retain the permit and unpublished connection.
    async fn handshake(&mut self) -> (iroh::endpoint::Connection, Session, OwnedSemaphorePermit) {
        let admission = self.client.admit().unwrap();
        let address = self
            .factory
            .peer_address(peer_id(&self.server.id()).unwrap())
            .unwrap();
        let target = EndpointAddr::from_parts(self.server.id(), [TransportAddr::Custom(address)]);
        let (connection, inbound) = tokio::join!(
            self.client.inner.connect(target, ALPN),
            self.server.accept()
        );
        let (connection, inbound) = (connection.unwrap(), inbound.unwrap());
        assert_ne!(connection.stable_id(), self.control.connection.stable_id());
        assert_ne!(
            inbound.connection.stable_id(),
            self.accepted_control.connection.stable_id()
        );
        assert_eq!(self.client.slots.available_permits(), 0);
        (connection, inbound, admission)
    }

    /// cancel-safe: yes — both futures are closure observers only.
    async fn control_is_open(&self) {
        for session in [&self.control, &self.accepted_control] {
            let closed = session.closed();
            tokio::pin!(closed);
            assert!(
                std::future::poll_fn(|cx| {
                    std::task::Poll::Ready(closed.as_mut().poll(cx).is_pending())
                })
                .await,
                "unrelated control connection was closed"
            );
        }
    }

    /// cancel-safe: NO — only completion proves both driver joins and socket release.
    async fn close(self) {
        self.close_with_phase(&Cell::new("joined fixture close"))
            .await;
    }

    /// cancel-safe: NO — phase observations do not replace either join boundary.
    async fn close_with_phase(self, phase: &Cell<&'static str>) {
        let started = std::time::Instant::now();
        let Self {
            client,
            server,
            handle,
            factory,
            mut tasks,
            stops,
            signaling,
            native,
            control,
            accepted_control,
        } = self;
        let client_done = Cell::new(false);
        let server_done = Cell::new(false);
        phase.set("joining native owners: neither complete");
        let (_, server_closed) = tokio::join!(
            async {
                client.close().await;
                client_done.set(true);
                phase.set(if server_done.get() {
                    "both native owners joined"
                } else {
                    "client native joined; server owner pending"
                });
                eprintln!("client native joined after {:?}", started.elapsed());
            },
            async {
                let result = server.close().await;
                server_done.set(true);
                phase.set(if client_done.get() {
                    "both native owners joined"
                } else {
                    "server owner joined; client native pending"
                });
                eprintln!(
                    "server owner joined after {:?}: {result:?}",
                    started.elapsed()
                );
                result
            }
        );
        server_closed.unwrap();
        phase.set("joining client carrier and pump: neither observed");
        for stop in stops {
            let _ = stop.send(());
        }
        let mut joined = 0;
        while let Some(result) = tasks.join_next().await {
            result.unwrap().unwrap();
            joined += 1;
            phase.set(if joined == 1 {
                "one client driver joined; other pending"
            } else {
                "both client drivers joined"
            });
            eprintln!(
                "client driver {joined}/2 joined after {:?}",
                started.elapsed()
            );
        }
        assert_eq!(joined, 2);
        phase.set("observe closed signaling handles");
        assert!(handle.local_addr().await.is_err());
        assert!(
            factory
                .peer_address(peer_id(&control.peer_id()).unwrap())
                .is_err()
        );
        phase.set("rebind joined native UDP sockets");
        for address in native {
            let _rebound = UdpSocket::bind(address).await.unwrap();
        }
        phase.set("rebind joined signaling TCP sockets");
        for address in signaling {
            let _rebound = TcpListener::bind(address).await.unwrap();
        }
        drop((control, accepted_control, factory, handle));
        phase.set("fixture close complete");
    }
}

/// cancel-safe: NO — terminal test deadline; cancellation is an explicit test branch.
async fn failed_finalization(cancel: bool) {
    let phase = Cell::new("fixture startup");
    tokio::time::timeout(Duration::from_secs(25), async {
        let mut fixture = Fixture::start().await;
        phase.set("second authenticated custom handshake");
        let (connection, inbound, admission) = fixture.handshake().await;
        // This address did not exist during either handshake or peer resolution.
        let blackhole = UdpSocket::bind(loopback()).await.unwrap();
        let address = blackhole.local_addr().unwrap();
        phase.set("post-handshake native validation witness");
        let mut finish = Box::pin(async {
            tokio::time::timeout(HANDSHAKE_TIMEOUT, fixture.client.finish_connect(
                connection, admission, fixture.server.id(), IncomingAddr::Ip(address),
            )).await.map_err(|_| NetworkError::Deadline)?
        });
        let mut bytes = [0; 2048];
        tokio::select! {
            result = &mut finish => panic!("native finalization ended before validation witness: {result:?}"),
            packet = blackhole.recv_from(&mut bytes) => {
                let (length, source) = packet.unwrap();
                assert!(length > 0);
                assert_eq!(source, fixture.client.local_addr());
            }
        }
        assert_eq!(fixture.client.slots.available_permits(), 0);
        if cancel {
            phase.set("cancel after validation witness");
            drop(finish);
        } else {
            phase.set("typed native validation failure");
            let result = finish.as_mut().await;
            eprintln!("native finalization result: {result:?}");
            assert!(matches!(result, Err(NetworkError::Deadline))
                || matches!(result, Err(NetworkError::NativePath(ref error))
                    if error.kind() == io::ErrorKind::NotConnected), "unexpected finalization: {result:?}");
            drop(finish);
        }
        assert_eq!(fixture.client.slots.available_permits(), 1);
        phase.set("unpublished new inbound closes without manual close");
        assert!(matches!(inbound.closed().await, NetworkError::Closed));
        fixture.control_is_open().await;
        phase.set("joined owners and socket rebind with handles retained");
        fixture.close_with_phase(&phase).await;
        drop(inbound);
    }).await.unwrap_or_else(|error| panic!("native finalization deadline: {error}; phase={}", phase.get()));
}

#[tokio::test(flavor = "current_thread")]
async fn unreachable_native_finalization_closes_only_the_unpublished_connection() {
    failed_finalization(false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_native_finalization_closes_only_the_unpublished_connection() {
    failed_finalization(true).await;
}

#[tokio::test(flavor = "current_thread")]
async fn reachable_native_finalization_publishes_session_and_holds_its_slot() {
    tokio::time::timeout(Duration::from_secs(25), async {
        let mut fixture = Fixture::start().await;
        let (connection, inbound, admission) = fixture.handshake().await;
        let address = fixture.server.local_addr();
        let session = fixture
            .client
            .finish_connect(
                connection,
                admission,
                fixture.server.id(),
                IncomingAddr::Ip(address),
            )
            .await
            .unwrap();
        assert!(session.connection.paths().iter().any(
            |path| matches!(path.remote_addr(), TransportAddr::Ip(remote) if *remote == address)
        ));
        assert_eq!(fixture.client.slots.available_permits(), 0);
        session.close();
        assert_eq!(fixture.client.slots.available_permits(), 1);
        assert!(matches!(inbound.closed().await, NetworkError::Closed));
        fixture.control_is_open().await;
        fixture.close().await;
        drop(inbound);
    })
    .await
    .expect("reachable native finalization lifecycle deadline");
}

/// cancel-safe: NO — the test explicitly drops an admitted public connect future.
async fn early_handshake(cancel: bool) {
    tokio::time::timeout(Duration::from_secs(25), async {
        let fixture = Fixture::start().await;
        // A different identity has no cached signaling route from the old control.
        let target = Identity::generate().transport_key().public();
        assert_ne!(target, fixture.server.id());
        let blackhole = UdpSocket::bind(loopback()).await.unwrap();
        let mut bytes = [0; 2048];
        let mut attempt = Box::pin(
            fixture
                .client
                .connect(target, blackhole.local_addr().unwrap()),
        );
        tokio::select! {
            result = &mut attempt => panic!("handshake ended before observed Initial: {result:?}"),
            packet = blackhole.recv_from(&mut bytes) => {
                let (length, source) = packet.unwrap();
                assert!(length >= 1200);
                assert_eq!(source, fixture.client.local_addr());
            }
        }
        assert_eq!(fixture.client.slots.available_permits(), 0);
        if !cancel {
            assert!(matches!(
                attempt.as_mut().await,
                Err(NetworkError::Deadline)
            ));
        }
        drop(attempt);
        assert_eq!(fixture.client.slots.available_permits(), 1);
        fixture.control_is_open().await;
        fixture.close().await;
    })
    .await
    .expect("public early handshake ownership deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn public_native_handshake_deadline_needs_no_inbound_progress() {
    early_handshake(false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn public_native_handshake_cancel_returns_slot_after_initial() {
    early_handshake(true).await;
}
