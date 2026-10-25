use super::*;
use crate::{Carrier, Datagram};
use futures::future::poll_fn;
use iroh::{
    Endpoint, EndpointAddr, SecretKey, TransportAddr,
    endpoint::{IncomingAddr, QuicTransportConfig, presets},
};
use libp2p::identity::Keypair;
use std::time::Duration;
use tokio::{sync::oneshot, task::JoinSet};

struct Pair {
    a: Arc<SignalingTransport>,
    b: Arc<SignalingTransport>,
    ah: CarrierHandle,
    bh: CarrierHandle,
    a_key: SecretKey,
    b_key: SecretKey,
    inject_b: mpsc::Sender<Inbound>,
    stops: Vec<oneshot::Sender<()>>,
    tasks: JoinSet<io::Result<()>>,
}

impl Pair {
    /// cancel-safe: NO — cancellation aborts retained fixture tasks but cannot join them.
    async fn start() -> Self {
        let a_key = SecretKey::generate();
        let b_key = SecretKey::generate();
        let mut a_seed = a_key.to_bytes();
        let mut b_seed = b_key.to_bytes();
        let ka = Keypair::ed25519_from_bytes(&mut a_seed).unwrap();
        let kb = Keypair::ed25519_from_bytes(&mut b_seed).unwrap();
        assert!(a_seed.iter().chain(&b_seed).all(|byte| *byte == 0));
        let pa = ka.public().to_peer_id();
        let pb = kb.public().to_peer_id();
        let (a_owner, ah, ar) =
            Carrier::bind(ka, "127.0.0.1:0".parse().unwrap(), vec![pb]).unwrap();
        let (b_owner, bh, br) =
            Carrier::bind(kb, "127.0.0.1:0".parse().unwrap(), vec![pa]).unwrap();
        let (a, ap) = SignalingTransport::attach(ah.clone(), ar).unwrap();
        let (b, bp) = SignalingTransport::attach(bh.clone(), br).unwrap();
        let inject_b = bp.deliver.clone();
        let mut tasks = JoinSet::new();
        let mut stops = Vec::with_capacity(4);
        for owner in [a_owner, b_owner] {
            let (stop, stopped) = oneshot::channel();
            stops.push(stop);
            tasks.spawn(owner.run(async {
                let _ = stopped.await;
            }));
        }
        for pump in [ap, bp] {
            let (stop, stopped) = oneshot::channel();
            stops.push(stop);
            tasks.spawn(pump.run(async {
                let _ = stopped.await;
            }));
        }
        ah.connect(pb, bh.local_addr().await.unwrap())
            .await
            .unwrap();
        let mut links = bh.links();
        loop {
            let ready = !links.borrow_and_update().is_empty();
            if ready {
                break;
            }
            links.changed().await.unwrap();
        }
        Self {
            a,
            b,
            ah,
            bh,
            a_key,
            b_key,
            inject_b,
            stops,
            tasks,
        }
    }
    /// cancel-safe: NO — successful return, not dropping the future, proves joined cleanup.
    async fn close(mut self) {
        let a_addr = self.ah.local_addr().await.unwrap();
        let b_addr = self.bh.local_addr().await.unwrap();
        for stop in self.stops.drain(..) {
            let _ = stop.send(());
        }
        let mut joined = 0;
        while let Some(result) = self.tasks.join_next().await {
            result.unwrap().unwrap();
            joined += 1;
        }
        assert_eq!(joined, 4);
        assert!(self.a.peer_address(self.bh.peer_id()).is_err());
        assert!(self.b.peer_address(self.ah.peer_id()).is_err());
        let _a = tokio::net::TcpListener::bind(a_addr).await.unwrap();
        let _b = tokio::net::TcpListener::bind(b_addr).await.unwrap();
    }
}

/// cancel-safe: yes — one complete datagram is returned without a later await.
async fn read(endpoint: &mut dyn CustomEndpoint) -> Vec<u8> {
    let mut output = [0; crate::MAX_DATAGRAM];
    let mut bufs = [io::IoSliceMut::new(&mut output)];
    let mut metas = [noq_udp::RecvMeta::default()];
    let mut infos = [RecvInfo::default()];
    let count = poll_fn(|cx| endpoint.poll_recv(cx, &mut bufs, &mut metas, &mut infos))
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(metas[0].stride, metas[0].len);
    output[..metas[0].len].to_vec()
}

#[tokio::test(flavor = "current_thread")]
async fn actual_carrier_pump_delivers_exact_datagrams_and_batches_with_owned_shutdown() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let pair = Pair::start().await;
        let mut a = pair.a.bind().unwrap();
        let mut b = pair.b.bind().unwrap();
        assert_eq!(pair.a.bind().unwrap_err().kind(), io::ErrorKind::AddrInUse);
        let sender = a.create_sender();
        let destination = pair.a.peer_address(pair.bh.peer_id()).unwrap();
        assert!(sender.is_valid_send_addr(&destination));
        assert!(!sender.is_valid_send_addr(&pair.b.peer_address(pair.ah.peer_id()).unwrap()));
        for bytes in [&[1][..], &[7; crate::MAX_DATAGRAM][..]] {
            poll_fn(|cx| pair.a.shared.poll_send(cx, &destination, bytes))
                .await
                .unwrap();
            assert_eq!(read(b.as_mut()).await, bytes);
            let reverse = pair.b.peer_address(pair.ah.peer_id()).unwrap();
            poll_fn(|cx| pair.b.shared.poll_send(cx, &reverse, bytes))
                .await
                .unwrap();
            assert_eq!(read(a.as_mut()).await, bytes);
        }
        // Inject only the receive-batch boundary; the exact carrier path above is real I/O.
        let link = pair.bh.links().borrow()[0];
        let source = pair.b.peer_address(pair.ah.peer_id()).unwrap();
        for byte in [3, 4] {
            pair.inject_b
                .send(Inbound {
                    received: Received {
                        peer: link.peer,
                        connection: link.connection,
                        route: link.route,
                        packet: Datagram::new(&[byte]).unwrap(),
                    },
                    source: source.clone(),
                })
                .await
                .unwrap();
        }
        let (mut first, mut second) = ([0; 1], [0; 1]);
        let mut bufs = [
            io::IoSliceMut::new(&mut first),
            io::IoSliceMut::new(&mut second),
        ];
        let mut metas = std::array::from_fn::<_, 2, _>(|_| noq_udp::RecvMeta::default());
        let mut infos = std::array::from_fn::<_, 2, _>(|_| RecvInfo::default());
        let batch = 2.min(noq_udp::BATCH_SIZE);
        assert_eq!(
            poll_fn(|cx| b.poll_recv(
                cx,
                &mut bufs[..batch],
                &mut metas[..batch],
                &mut infos[..batch]
            ))
            .await
            .unwrap(),
            batch
        );
        assert_eq!(first, [3]);
        if batch == 2 {
            assert_eq!(second, [4]);
        } else {
            assert_eq!(read(b.as_mut()).await, [4]);
        }
        drop(a);
        assert!(!sender.is_valid_send_addr(&destination));
        drop(b);
        pair.close().await;
    })
    .await
    .expect("owned signaling pump/datagram deadline");
}

/// cancel-safe: NO — a cancelled bind is not successful endpoint startup.
async fn endpoint(key: SecretKey, factory: Arc<SignalingTransport>) -> Endpoint {
    let transport = QuicTransportConfig::builder()
        .application_data_filter(|_| false)
        .build();
    Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .alpns(vec![b"shaar/bridge-test/1".to_vec()])
        .clear_ip_transports()
        .clear_relay_transports()
        .add_custom_transport(factory)
        .transport_config(transport)
        .bind()
        .await
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn real_iroh_handshake_uses_only_the_authenticated_custom_carrier() {
    tokio::time::timeout(Duration::from_secs(25), async {
        let pair = Pair::start().await;
        let a = endpoint(pair.a_key.clone(), pair.a.clone()).await;
        let b = endpoint(pair.b_key.clone(), pair.b.clone()).await;
        assert!(a.bound_sockets().is_empty());
        assert!(b.bound_sockets().is_empty());
        let target = pair.a.peer_address(pair.bh.peer_id()).unwrap();
        let source = pair.b.peer_address(pair.ah.peer_id()).unwrap();
        let remote = EndpointAddr::from_parts(b.id(), [TransportAddr::Custom(target)]);
        let client = a.connect(remote, b"shaar/bridge-test/1");
        let server = async {
            let incoming = b.accept().await.unwrap();
            assert_eq!(incoming.remote_addr(), IncomingAddr::Custom(source));
            incoming.await.unwrap()
        };
        let (client, server) = tokio::join!(client, server);
        let client = client.unwrap();
        assert_eq!(client.remote_id(), b.id());
        assert_eq!(server.remote_id(), a.id());
        // Keep connection and factory handles alive across joined shutdown.
        a.close().await;
        b.close().await;
        pair.close().await;
        drop((client, server));
    })
    .await
    .expect("actual Iroh custom-only control handshake deadline");
}
