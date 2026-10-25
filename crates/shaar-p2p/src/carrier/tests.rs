use super::*;
use libp2p::{
    core::Endpoint,
    swarm::{
        DialError, NetworkBehaviour,
        behaviour::{DialFailure, FromSwarm},
    },
};
use tokio::{net::TcpListener, sync::oneshot, task::JoinSet};

fn key() -> Keypair {
    Keypair::generate_ed25519()
}

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

struct Pair {
    a: CarrierHandle,
    b: CarrierHandle,
    a_in: mpsc::Receiver<Received>,
    b_in: mpsc::Receiver<Received>,
    stops: Vec<oneshot::Sender<()>>,
    tasks: JoinSet<io::Result<()>>,
}

impl Pair {
    async fn start(deny_a: bool) -> Self {
        let ka = key();
        let kb = key();
        let pa = ka.public().to_peer_id();
        let pb = kb.public().to_peer_id();
        let (a, ah, ar) = Carrier::bind(ka, loopback(), vec![pb]).unwrap();
        let (b, bh, br) =
            Carrier::bind(kb, loopback(), if deny_a { vec![] } else { vec![pa] }).unwrap();
        let mut tasks = JoinSet::new();
        let mut stops = Vec::with_capacity(2);
        for owner in [a, b] {
            let (stop, stopped) = oneshot::channel();
            stops.push(stop);
            // Exactly two root drivers; every result is joined by close().
            tasks.spawn(owner.run(async {
                let _ = stopped.await;
            }));
        }
        ah.local_addr().await.unwrap();
        bh.local_addr().await.unwrap();
        Self {
            a: ah,
            b: bh,
            a_in: ar,
            b_in: br,
            stops,
            tasks,
        }
    }

    async fn connect(&self) -> ConnectionId {
        self.a
            .connect(self.b.peer_id(), self.b.local_addr().await.unwrap())
            .await
            .unwrap()
    }

    async fn close(mut self) {
        for stop in self.stops.drain(..) {
            stop.send(()).unwrap();
        }
        while let Some(result) = self.tasks.join_next().await {
            result.unwrap().unwrap();
        }
        assert!(self.a.commands.is_closed());
        assert!(self.b.commands.is_closed());
        assert!(self.a.local_addr().await.is_err());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn current_link_observations_revoke_queued_packets_across_reopen_and_shutdown() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut pair = Pair::start(false).await;
        let a_links = pair.a.links();
        let b_links = pair.b.links();
        assert!(a_links.borrow().is_empty());
        let first = pair.connect().await;
        assert_eq!(
            a_links.borrow().as_slice(),
            &[Link {
                peer: pair.b.peer_id(),
                connection: first,
                route: Route::Direct
            }]
        );
        let first_link = a_links.borrow()[0];
        pair.a
            .send_on(first_link, Datagram::new(b"first").unwrap())
            .await
            .unwrap();
        let old = pair.b_in.recv().await.unwrap();
        assert!(pair.b.is_current(&old));
        let forged = Received {
            peer: old.peer,
            connection: ConnectionId::new_unchecked(usize::MAX),
            route: old.route,
            packet: Datagram::new(b"forged").unwrap(),
        };
        assert!(!pair.b.is_current(&forged));
        let forged = Received {
            peer: old.peer,
            connection: old.connection,
            route: Route::Relayed {
                relay: None,
                generation: 1,
            },
            packet: Datagram::new(b"forged").unwrap(),
        };
        assert!(!pair.b.is_current(&forged));
        pair.a.disconnect(pair.b.peer_id()).await.unwrap();
        assert!(a_links.borrow().is_empty());
        pair.b.disconnect(pair.a.peer_id()).await.unwrap();
        assert!(b_links.borrow().is_empty());
        assert!(!pair.b.is_current(&old));
        let next = pair.connect().await;
        assert_ne!(next, first);
        assert_eq!(
            pair.a
                .send_on(first_link, Datagram::new(b"stale").unwrap())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotConnected
        );
        let next_link = a_links.borrow()[0];
        let wrong_route = Link {
            route: Route::Relayed {
                relay: None,
                generation: 1,
            },
            ..next_link
        };
        assert_eq!(
            pair.a
                .send_on(wrong_route, Datagram::new(b"wrong route").unwrap())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotConnected
        );
        pair.a
            .send_on(next_link, Datagram::new(b"next").unwrap())
            .await
            .unwrap();
        let current = pair.b_in.recv().await.unwrap();
        assert!(pair.b.is_current(&current));
        assert!(!pair.b.is_current(&old));
        assert_ne!(old.connection, current.connection);
        pair.close().await;
        assert!(a_links.borrow().is_empty());
        assert!(b_links.borrow().is_empty());
    })
    .await
    .expect("current native link observation deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn configuration_and_native_address_boundaries_are_explicit() {
    let peer = key().public().to_peer_id();
    assert!(Carrier::bind(key(), loopback(), vec![peer; super::super::PEER_LIMIT + 1]).is_err());
    assert!(Carrier::bind(key(), loopback(), vec![peer; super::super::PEER_LIMIT]).is_ok());
    for address in ["127.0.0.1:1", "[::1]:65535"] {
        let address: SocketAddr = address.parse().unwrap();
        assert_eq!(socket_address(&multiaddr(address)), Some(address));
    }
    assert!(socket_address(&"/ip4/127.0.0.1/udp/1234".parse().unwrap()).is_none());
    assert!(socket_address(&"/ip4/127.0.0.1/tcp/1234/p2p-circuit".parse().unwrap()).is_none());
}

#[test]
fn constructing_without_a_runtime_fails_without_panicking() {
    assert!(Carrier::bind(key(), loopback(), vec![]).is_err());
}

#[test]
fn authenticated_admission_bounds_peers_rejects_duplicates_and_forgets_closed_links() {
    use libp2p::core::ConnectedPoint;
    use libp2p::swarm::behaviour::{ConnectionClosed, ConnectionEstablished};
    let peers: Vec<_> = (0..super::super::PEER_LIMIT)
        .map(|_| key().public().to_peer_id())
        .collect();
    let mut admission = Admission::new(peers.clone()).unwrap();
    let address = multiaddr(loopback());
    let endpoint = ConnectedPoint::Listener {
        local_addr: address.clone(),
        send_back_addr: address.clone(),
    };
    for (index, peer) in peers.iter().enumerate() {
        let id = ConnectionId::new_unchecked(index);
        admission
            .handle_pending_inbound_connection(id, &address, &address)
            .unwrap();
        admission
            .handle_established_inbound_connection(id, *peer, &address, &address)
            .unwrap();
        admission.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
            peer_id: *peer,
            connection_id: id,
            endpoint: &endpoint,
            failed_addresses: &[],
            other_established: 0,
        }));
        assert_eq!(admission.connection(peer), Some(id));
    }
    let extra = ConnectionId::new_unchecked(100);
    assert!(
        admission
            .handle_established_inbound_connection(extra, peers[0], &address, &address)
            .is_err()
    );
    assert!(
        admission
            .handle_established_inbound_connection(
                extra,
                key().public().to_peer_id(),
                &address,
                &address
            )
            .is_err()
    );
    admission.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
        peer_id: peers[0],
        connection_id: ConnectionId::new_unchecked(0),
        endpoint: &endpoint,
        cause: None,
        remaining_established: 0,
    }));
    assert!(admission.connection(&peers[0]).is_none());
    admission
        .handle_established_inbound_connection(extra, peers[0], &address, &address)
        .unwrap();
    // A later composed behaviour may still reject: only the final established event registers a link.
    assert!(admission.connection(&peers[0]).is_none());
    admission.on_swarm_event(FromSwarm::DialFailure(DialFailure {
        peer_id: Some(peers[0]),
        error: &DialError::NoAddresses,
        connection_id: extra,
    }));
    admission
        .handle_established_inbound_connection(
            ConnectionId::new_unchecked(101),
            peers[0],
            &address,
            &address,
        )
        .unwrap();
}

#[test]
fn pending_noise_admission_is_bounded_and_failure_reclaims_the_slot() {
    let peer = key().public().to_peer_id();
    let mut admission = Admission::new(vec![peer]).unwrap();
    let address = multiaddr(loopback());
    for id in 0..PENDING_LIMIT {
        admission
            .handle_pending_inbound_connection(ConnectionId::new_unchecked(id), &address, &address)
            .unwrap();
    }
    assert!(
        admission
            .handle_pending_inbound_connection(
                ConnectionId::new_unchecked(PENDING_LIMIT),
                &address,
                &address
            )
            .is_err()
    );
    admission.on_swarm_event(FromSwarm::DialFailure(DialFailure {
        peer_id: Some(peer),
        error: &DialError::NoAddresses,
        connection_id: ConnectionId::new_unchecked(0),
    }));
    admission
        .handle_pending_outbound_connection(
            ConnectionId::new_unchecked(PENDING_LIMIT),
            Some(peer),
            &[],
            Endpoint::Dialer,
        )
        .unwrap();
    assert!(
        admission
            .handle_pending_outbound_connection(
                ConnectionId::new_unchecked(100),
                None,
                &[],
                Endpoint::Dialer
            )
            .is_err()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn live_noise_packets_are_exact_bidirectional_reused_and_reopened() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut pair = Pair::start(false).await;
        let connection = pair.connect().await;
        for bytes in [&[7_u8][..], &[9_u8; crate::MAX_DATAGRAM][..]] {
            pair.a
                .send(pair.b.peer_id(), Datagram::new(bytes).unwrap())
                .await
                .unwrap();
            let received = pair.b_in.recv().await.unwrap();
            assert_eq!(received.peer, pair.a.peer_id());
            assert_eq!(received.packet.as_bytes(), bytes);
            pair.b
                .send(pair.a.peer_id(), received.packet)
                .await
                .unwrap();
            let received = pair.a_in.recv().await.unwrap();
            assert_eq!(received.peer, pair.b.peer_id());
            assert_eq!(received.connection, connection);
            assert_eq!(received.packet.as_bytes(), bytes);
            assert_eq!(pair.connect().await, connection);
        }
        pair.a.disconnect(pair.b.peer_id()).await.unwrap();
        // Wait for the other side's close event too, not a scheduling sleep.
        pair.b.disconnect(pair.a.peer_id()).await.unwrap();
        let reopened = pair.connect().await;
        assert_ne!(reopened, connection);
        pair.a
            .send(pair.b.peer_id(), Datagram::new(b"reopened").unwrap())
            .await
            .unwrap();
        assert_eq!(
            pair.b_in.recv().await.unwrap().packet.as_bytes(),
            b"reopened"
        );
        pair.close().await;
    })
    .await
    .expect("live carrier deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn remote_queue_saturation_is_not_acknowledged_and_draining_resumes() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut pair = Pair::start(false).await;
        pair.connect().await;
        for byte in 0..QUEUE_LIMIT {
            pair.a
                .send(
                    pair.b.peer_id(),
                    Datagram::new(&[u8::try_from(byte).unwrap()]).unwrap(),
                )
                .await
                .unwrap();
        }
        assert!(
            pair.a
                .send(pair.b.peer_id(), Datagram::new(b"not admitted").unwrap())
                .await
                .is_err()
        );
        for byte in 0..QUEUE_LIMIT {
            assert_eq!(
                pair.b_in.recv().await.unwrap().packet.as_bytes(),
                &[u8::try_from(byte).unwrap()]
            );
        }
        pair.a
            .send(pair.b.peer_id(), Datagram::new(b"resumed").unwrap())
            .await
            .unwrap();
        assert_eq!(
            pair.b_in.recv().await.unwrap().packet.as_bytes(),
            b"resumed"
        );
        pair.close().await;
    })
    .await
    .expect("carrier queue admission deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn denied_and_wrong_pinned_connections_never_deliver_a_packet() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut pair = Pair::start(true).await;
        // Noise completion alone is not remote application-level admission.
        let _ = pair
            .a
            .connect(pair.b.peer_id(), pair.b.local_addr().await.unwrap())
            .await;
        assert!(
            pair.a
                .send(pair.b.peer_id(), Datagram::new(b"denied").unwrap())
                .await
                .is_err()
        );
        assert!(pair.b_in.try_recv().is_err());
        let wrong = key().public().to_peer_id();
        assert_eq!(
            pair.a
                .connect(wrong, pair.b.local_addr().await.unwrap())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        pair.close().await;

        let mut pair = Pair::start(false).await;
        // The allowed remote ID is pinned even when the supplied endpoint belongs to us.
        assert!(
            pair.a
                .connect(pair.b.peer_id(), pair.a.local_addr().await.unwrap())
                .await
                .is_err()
        );
        assert!(pair.a_in.try_recv().is_err());
        assert!(pair.b_in.try_recv().is_err());
        pair.close().await;
    })
    .await
    .expect("carrier authentication deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn submission_queue_rejects_before_waiting_and_cancelled_commands_do_not_dial() {
    let peer = key().public().to_peer_id();
    let (owner, handle, _incoming) = Carrier::bind(key(), loopback(), vec![peer]).unwrap();
    let mut replies = Vec::with_capacity(QUEUE_LIMIT);
    for _ in 0..QUEUE_LIMIT {
        let (reply, result) = oneshot::channel();
        handle
            .submit(Command::Connect(
                peer,
                "127.0.0.1:1".parse().unwrap(),
                reply,
            ))
            .unwrap();
        replies.push(result);
    }
    let (reply, _result) = oneshot::channel();
    assert_eq!(
        handle
            .submit(Command::Disconnect(peer, reply))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    drop(replies);
    // The exact same production dispatch drops cancelled connects before transport admission.
    let Carrier { mut core, executor } = owner;
    for _ in 0..QUEUE_LIMIT {
        let command = core.commands.recv().await.unwrap();
        core.command(command);
    }
    assert!(core.pending.is_empty());
    assert!(core.requests.is_empty());
    drop(core);
    executor.shutdown().await.unwrap();
    assert!(
        handle
            .connect(peer, "127.0.0.1:1".parse().unwrap())
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn joined_shutdown_releases_native_listener_with_handles_alive() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (owner, handle, _incoming) = Carrier::bind(key(), loopback(), vec![]).unwrap();
        let (stop, stopped) = oneshot::channel();
        let mut tasks = JoinSet::new();
        tasks.spawn(owner.run(async {
            let _ = stopped.await;
        }));
        let address = handle.local_addr().await.unwrap();
        stop.send(()).unwrap();
        tasks.join_next().await.unwrap().unwrap().unwrap();
        // No established TCP connection/TIME_WAIT in this physical ownership case.
        let _rebound = TcpListener::bind(address).await.unwrap();
        assert!(handle.local_addr().await.is_err());
        assert!(
            handle
                .disconnect(key().public().to_peer_id())
                .await
                .is_err()
        );
    })
    .await
    .expect("native listener release deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn silent_noise_peer_has_an_absolute_dial_deadline_and_joined_shutdown() {
    tokio::time::timeout(Duration::from_secs(25), async {
        let target = TcpListener::bind(loopback()).await.unwrap();
        let peer = key().public().to_peer_id();
        let (owner, handle, _incoming) = Carrier::bind(key(), loopback(), vec![peer]).unwrap();
        let (stop, stopped) = oneshot::channel();
        let mut tasks = JoinSet::new();
        tasks.spawn(owner.run(async {
            let _ = stopped.await;
        }));
        handle.local_addr().await.unwrap();
        let dial = handle.connect(peer, target.local_addr().unwrap());
        let silent = async {
            let (socket, _) = target.accept().await.unwrap();
            let _socket = socket;
            stopped_peer().await;
        };
        tokio::pin!(dial, silent);
        tokio::select! {
            result = &mut dial => assert!(result.is_err()),
            _ = &mut silent => unreachable!("silent fixture never completes"),
        }
        stop.send(()).unwrap();
        tasks.join_next().await.unwrap().unwrap().unwrap();
    })
    .await
    .expect("silent Noise peer deadline");
}

async fn stopped_peer() {
    std::future::pending::<()>().await;
}
