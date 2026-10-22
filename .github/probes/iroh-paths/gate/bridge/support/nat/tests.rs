#![forbid(unsafe_code)]

#[path = "protocol.rs"]
mod protocol;
#[path = "relay.rs"]
mod relay;
#[path = "transport.rs"]
mod transport;

use iroh::endpoint::transports::{
    CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit,
};
use n0_watcher::Watcher;
use noq_udp::RecvMeta;
use protocol::{FRAME_MAX, Kind, Nonce};
use std::{future::poll_fn, io, net::SocketAddr, sync::Arc, task::Poll, time::Duration};
use tokio::{net::UdpSocket, task::JoinHandle};

fn marker() -> Nonce {
    protocol::nonce("0123456789abcdef0123456789abcdef").unwrap()
}
fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

type RelayResult = io::Result<(relay::Captures, [Option<SocketAddr>; 2])>;
struct Running {
    addr: SocketAddr,
    task: JoinHandle<RelayResult>,
}
impl Running {
    async fn start() -> Self {
        let relay = relay::Relay::bind(loopback(), marker()).await.unwrap();
        Self {
            addr: relay.addr().unwrap(),
            task: tokio::spawn(relay.run()),
        }
    }
    async fn finish(mut self) -> RelayResult {
        relay::stop(self.addr, marker()).await?;
        tokio::time::timeout(Duration::from_secs(5), &mut self.task)
            .await
            .map_err(|_| io::Error::other("relay join deadline"))?
            .map_err(io::Error::other)?
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn factories(running: &Running) -> (Arc<transport::Factory>, Arc<transport::Factory>) {
    let (a, b) = tokio::join!(
        transport::Factory::register(loopback(), running.addr, marker(), 0),
        transport::Factory::register(loopback(), running.addr, marker(), 1),
    );
    (a.unwrap(), b.unwrap())
}

async fn send(
    sender: &dyn CustomSender,
    destination: &iroh_base::CustomAddr,
    payload: &[u8],
) -> io::Result<()> {
    poll_fn(|cx| sender.poll_send(cx, destination, None, &Transmit::spike_new(payload, None))).await
}

async fn receive(endpoint: &mut dyn CustomEndpoint) -> io::Result<Vec<u8>> {
    let mut output = [0; protocol::PAYLOAD_MAX];
    tokio::time::timeout(
        Duration::from_secs(5),
        poll_fn(|cx| {
            let mut slots = [io::IoSliceMut::new(&mut output)];
            let mut metas = [RecvMeta::default()];
            let mut infos = [RecvInfo::default()];
            match endpoint.poll_recv(cx, &mut slots, &mut metas, &mut infos) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(1)) => Poll::Ready(Ok(output[..metas[0].len].to_vec())),
                Poll::Ready(Ok(_)) => {
                    Poll::Ready(Err(io::Error::other("unexpected receive batch")))
                }
            }
        }),
    )
    .await
    .map_err(|_| io::Error::other("receive deadline"))?
}

#[test]
fn envelope_golden_roundtrip_and_rejection_boundaries() {
    let nonce = marker();
    let mut output = [0; FRAME_MAX];
    for (kind, side, tag, bytes) in [
        (Kind::Register, 0, 0, &[][..]),
        (Kind::Ready, 1, 1, &[][..]),
        (Kind::Data, 1, 2, &[0, 255, 7][..]),
        (Kind::Stop, 255, 3, &[][..]),
    ] {
        let frame = protocol::encode(&mut output, &nonce, kind, side, bytes).unwrap();
        assert_eq!(&frame[..4], b"SN54");
        assert_eq!(&frame[4..6], &[tag, side]);
        assert_eq!(&frame[6..protocol::HEADER], &nonce);
        let decoded = protocol::decode(frame, &nonce).unwrap();
        assert_eq!(decoded.kind, kind);
        assert_eq!(decoded.side, side);
        assert_eq!(decoded.payload, bytes);
    }
    let maximum = vec![7; protocol::PAYLOAD_MAX];
    let frame = protocol::encode(&mut output, &nonce, Kind::Data, 0, &maximum)
        .unwrap()
        .to_vec();
    assert_eq!(protocol::decode(&frame, &nonce).unwrap().payload, maximum);
    for length in 0..protocol::HEADER {
        assert!(protocol::decode(&frame[..length], &nonce).is_err());
    }
    for offset in [0, 4, 5, 6] {
        let mut corrupt = frame.clone();
        corrupt[offset] = 254;
        assert!(protocol::decode(&corrupt, &nonce).is_err());
    }
    assert!(protocol::decode(&vec![0; FRAME_MAX + 1], &nonce).is_err());
    assert!(protocol::encode(&mut output, &nonce, Kind::Data, 0, &[]).is_err());
    assert!(protocol::encode(&mut output, &nonce, Kind::Ready, 0, &[1]).is_err());
    assert!(
        protocol::encode(
            &mut output,
            &nonce,
            Kind::Data,
            0,
            &vec![1; protocol::PAYLOAD_MAX + 1]
        )
        .is_err()
    );
    for invalid in ["", "short", "gggggggggggggggggggggggggggggggg"] {
        assert!(protocol::nonce(invalid).is_err());
    }
}

#[tokio::test]
async fn actual_relay_preserves_datagrams_both_directions_and_publisher_lifetime() {
    let running = Running::start().await;
    let (a, b) = factories(&running).await;
    let mut ea = a.bind().unwrap();
    let mut eb = b.bind().unwrap();
    assert!(a.bind().is_err());
    let sa = ea.create_sender();
    let sb = eb.create_sender();
    let to_a = b.remote_addr();
    let to_b = a.remote_addr();
    let mut watcher = ea.watch_local_addrs();
    assert_eq!(watcher.get(), vec![a.local_addr()]);
    drop(a);
    assert!(watcher.is_connected(), "bound endpoint retains publisher");
    for bytes in [vec![1], vec![7; protocol::PAYLOAD_MAX]] {
        send(sa.as_ref(), &to_b, &bytes).await.unwrap();
        assert_eq!(receive(eb.as_mut()).await.unwrap(), bytes);
        send(sb.as_ref(), &to_a, &bytes).await.unwrap();
        assert_eq!(receive(ea.as_mut()).await.unwrap(), bytes);
    }
    assert_eq!(b.stats(), (2, 2));
    drop(ea);
    assert!(!watcher.is_connected());
    assert_eq!(
        send(sa.as_ref(), &to_b, &[1]).await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    drop(eb);
    let (captures, peers) = running.finish().await.unwrap();
    assert!(peers.iter().all(Option::is_some));
    assert_eq!(captures[0], captures[1]);
    assert_eq!(captures[0], vec![vec![1], vec![7; protocol::PAYLOAD_MAX]]);
}

#[tokio::test]
async fn wrong_send_address_source_and_layout_are_rejected() {
    let running = Running::start().await;
    let (a, b) = factories(&running).await;
    let mut endpoint = a.bind().unwrap();
    let other = b.bind().unwrap();
    let sender = endpoint.create_sender();
    assert!(send(sender.as_ref(), &a.local_addr(), &[1]).await.is_err());
    let bad = Transmit::spike_new(&[1, 2], Some(1));
    assert!(
        poll_fn(|cx| sender.poll_send(cx, &a.remote_addr(), None, &bad))
            .await
            .is_err()
    );
    assert!(send(sender.as_ref(), &a.remote_addr(), &[]).await.is_err());
    assert!(
        send(
            sender.as_ref(),
            &a.remote_addr(),
            &vec![1; protocol::PAYLOAD_MAX + 1]
        )
        .await
        .is_err()
    );
    let valid = Transmit::spike_new(&[1], None);
    assert!(
        poll_fn(|cx| sender.poll_send(cx, &a.remote_addr(), Some(&a.remote_addr()), &valid))
            .await
            .is_err()
    );
    assert!(
        poll_fn(|cx| endpoint.poll_recv(cx, &mut [], &mut [], &mut []))
            .await
            .is_err()
    );
    let intruder = UdpSocket::bind(loopback()).await.unwrap();
    intruder
        .send_to(b"not from the registered relay", a.bound_addr().unwrap())
        .await
        .unwrap();
    assert_eq!(
        receive(endpoint.as_mut()).await.unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    drop(endpoint);
    drop(other);
    running.finish().await.unwrap();
}

#[tokio::test]
async fn relay_capture_capacity_fails_without_silent_eviction() {
    let running = Running::start().await;
    let (a, b) = factories(&running).await;
    let ea = a.bind().unwrap();
    let mut eb = b.bind().unwrap();
    let sender = ea.create_sender();
    for _ in 0..256 {
        send(sender.as_ref(), &a.remote_addr(), &[1]).await.unwrap();
        assert_eq!(receive(eb.as_mut()).await.unwrap(), [1]);
    }
    send(sender.as_ref(), &a.remote_addr(), &[2]).await.unwrap();
    let mut running = running;
    let result = tokio::time::timeout(Duration::from_secs(5), &mut running.task)
        .await
        .unwrap()
        .unwrap();
    assert!(result.unwrap_err().to_string().contains("capture limit"));
}

#[tokio::test]
async fn reordered_first_data_can_complete_registration_without_exposing_payload() {
    let socket = UdpSocket::bind(loopback()).await.unwrap();
    let address = socket.local_addr().unwrap();
    let respond = async {
        let mut input = [0; FRAME_MAX];
        let (length, source) = socket.recv_from(&mut input).await?;
        assert_eq!(
            protocol::decode(&input[..length], &marker()).unwrap().kind,
            Kind::Register
        );
        let mut output = [0; FRAME_MAX];
        let bytes = protocol::encode(&mut output, &marker(), Kind::Data, 1, &[9])?;
        socket.send_to(bytes, source).await?;
        Ok::<(), io::Error>(())
    };
    let (factory, response) = tokio::join!(
        transport::Factory::register(loopback(), address, marker(), 0),
        respond
    );
    response.unwrap();
    let factory = factory.unwrap();
    assert_eq!(factory.stats(), (0, 0));
    assert!(factory.bind().is_ok());
}

#[tokio::test]
async fn missing_peer_registration_times_out_and_never_passes_as_ready() {
    let running = Running::start().await;
    let error = transport::Factory::register(loopback(), running.addr, marker(), 0)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(
        running.finish().await.is_err(),
        "incomplete relay cannot report a complete case"
    );
}

#[tokio::test]
async fn relay_rejects_unregistered_data_and_changed_nonce() {
    for wrong_nonce in [false, true] {
        let mut running = Running::start().await;
        let socket = UdpSocket::bind(loopback()).await.unwrap();
        let mut output = [0; FRAME_MAX];
        let nonce = if wrong_nonce {
            protocol::nonce("ffffffffffffffffffffffffffffffff").unwrap()
        } else {
            marker()
        };
        let bytes = protocol::encode(&mut output, &nonce, Kind::Data, 0, &[1]).unwrap();
        socket.send_to(bytes, running.addr).await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), &mut running.task)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_err());
    }
}
