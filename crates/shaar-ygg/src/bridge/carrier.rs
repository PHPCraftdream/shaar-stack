use std::{
    fmt, io,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use iroh::endpoint::transports::{
    CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit,
};
use iroh_base::CustomAddr;
use n0_watcher::{Direct, Watchable};

use crate::{MAX_DATAGRAM_PEERS, PeerDatagrams, YggBridge};

use super::carrier_pump::YggPump;
use super::carrier_state::Shared;

/// Factory for a single endpoint bound to the selected authenticated peers.
pub struct YggCarrier {
    shared: Arc<Shared>,
    receivers: Mutex<Option<Vec<PeerDatagrams>>>,
    local: CustomAddr,
    addresses: Arc<Watchable<Vec<CustomAddr>>>,
}

impl fmt::Debug for YggCarrier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("YggCarrier(..)")
    }
}

impl YggCarrier {
    /// cancel-safe: yes — cancellation drops and revokes every opened capability.
    pub async fn attach(
        bridge: &YggBridge,
        local_key: [u8; 32],
        peers: &[[u8; 32]],
        budget: Duration,
    ) -> io::Result<(Arc<Self>, YggPump)> {
        if peers.is_empty() || bridge.public_key() != local_key || peers.len() > MAX_DATAGRAM_PEERS
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        for (index, peer) in peers.iter().enumerate() {
            if peers[..index].contains(peer) {
                return Err(io::ErrorKind::InvalidInput.into());
            }
        }
        let mut receivers = Vec::with_capacity(peers.len());
        let mut bindings = Vec::with_capacity(peers.len());
        for peer in peers {
            let capability = bridge
                .open_datagrams(*peer, budget)
                .await
                .map_err(|_| io::ErrorKind::NotConnected)?;
            bindings.push((*peer, capability.sender()));
            receivers.push(capability);
        }
        let shared = Arc::new(Shared::new(bindings)?);
        let local = shared.local();
        let factory = Arc::new(Self {
            shared: Arc::clone(&shared),
            receivers: Mutex::new(Some(receivers)),
            local: local.clone(),
            addresses: Arc::new(Watchable::new(vec![local])),
        });
        let pump = YggPump::new(shared);
        Ok((factory, pump))
    }

    pub fn peer_address(&self, peer: &[u8; 32]) -> io::Result<CustomAddr> {
        self.shared.peer_address(peer)
    }

    pub fn authenticated_peer(&self, address: &CustomAddr) -> io::Result<[u8; 32]> {
        self.shared.authenticated_peer(address)
    }
}

impl CustomTransport for YggCarrier {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        if self.shared.is_closed() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let receivers = self
            .receivers
            .lock()
            .map_err(|_| io::Error::other("carrier receiver state unavailable"))?
            .take()
            .ok_or_else(|| io::Error::from(io::ErrorKind::AddrInUse))?;
        Ok(Box::new(Bound {
            shared: Arc::clone(&self.shared),
            receivers,
            addresses: Arc::clone(&self.addresses),
            local: self.local.clone(),
            cursor: 0,
        }))
    }
}

struct Bound {
    shared: Arc<Shared>,
    receivers: Vec<PeerDatagrams>,
    addresses: Arc<Watchable<Vec<CustomAddr>>>,
    local: CustomAddr,
    cursor: usize,
}

impl fmt::Debug for Bound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("YggCarrierEndpoint(..)")
    }
}

impl Drop for Bound {
    fn drop(&mut self) {
        self.shared.close();
    }
}

impl CustomEndpoint for Bound {
    fn watch_local_addrs(&self) -> Direct<Vec<CustomAddr>> {
        self.addresses.watch()
    }

    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(Sender(Arc::clone(&self.shared), self.local.clone()))
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        infos: &mut [RecvInfo],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty()
            || bufs.len() != metas.len()
            || bufs.len() != infos.len()
            || bufs.len() > noq_udp::BATCH_SIZE
        {
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        if self.shared.is_closed() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let mut count = 0;
        let mut pending = 0;
        let start = self.cursor;
        for step in 0..self.receivers.len() {
            let index = (start + step) % self.receivers.len();
            match self.receivers[index].poll_recv(cx) {
                Poll::Pending => pending += 1,
                Poll::Ready(Ok(bytes)) => {
                    if bytes.len() > bufs[count].len() {
                        return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
                    }
                    let source = self.receivers[index].peer_key();
                    let address = match self.shared.peer_address(&source) {
                        Ok(address) => address,
                        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                            return Poll::Ready(Err(error));
                        }
                        Err(_) => continue,
                    };
                    if self.shared.authenticated_peer(&address).ok() != Some(source) {
                        continue;
                    }
                    bufs[count][..bytes.len()].copy_from_slice(&bytes);
                    metas[count] = noq_udp::RecvMeta::default();
                    metas[count].len = bytes.len();
                    metas[count].stride = bytes.len().max(1);
                    infos[count] = RecvInfo::new(address, Some(self.local.clone()));
                    count += 1;
                    self.cursor = (index + 1) % self.receivers.len();
                    if count == bufs.len() {
                        return Poll::Ready(Ok(count));
                    }
                }
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, error)));
                }
            }
        }
        if count > 0 {
            Poll::Ready(Ok(count))
        } else if pending == self.receivers.len() {
            Poll::Pending
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::test_support::{BUDGET, start_listener};

    #[tokio::test]
    async fn attach_rejects_identity_mismatch_empty_duplicate_and_too_many_peers() {
        let (transport, _) = start_listener(0xD1).await;
        let bridge = YggBridge::new(transport, []);
        let key = bridge.public_key();
        assert_eq!(
            YggCarrier::attach(&bridge, [0x55; 32], &[[0x44; 32]], BUDGET)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(YggCarrier::attach(&bridge, key, &[], BUDGET).await.is_err());
        assert!(
            YggCarrier::attach(&bridge, key, &[[0x44; 32], [0x44; 32]], BUDGET)
                .await
                .is_err()
        );
        assert!(
            YggCarrier::attach(&bridge, key, &[[0x44; 32]; 17], BUDGET)
                .await
                .is_err()
        );
        let capability = bridge
            .open_datagrams([0x44; 32], BUDGET)
            .await
            .expect("rejected attach left no registration");
        drop(capability);
        bridge.close().await.unwrap();
    }

    #[tokio::test]
    async fn address_attestation_rejects_unknown_foreign_and_revoked_peers() {
        let (transport, _) = start_listener(0xD2).await;
        let bridge = YggBridge::new(transport, []);
        let key = bridge.public_key();
        let (carrier, mut pump) = YggCarrier::attach(&bridge, key, &[[0x46; 32]], BUDGET)
            .await
            .unwrap();
        let address = carrier.peer_address(&[0x46; 32]).unwrap();
        assert_eq!(carrier.authenticated_peer(&address).unwrap(), [0x46; 32]);
        assert!(carrier.peer_address(&[0x47; 32]).is_err());
        assert!(carrier.authenticated_peer(&carrier.local).is_err());
        let (other_transport, _) = start_listener(0xDC).await;
        let other_bridge = YggBridge::new(other_transport, []);
        let (other_carrier, mut other_pump) = YggCarrier::attach(
            &other_bridge,
            other_bridge.public_key(),
            &[[0x46; 32]],
            BUDGET,
        )
        .await
        .unwrap();
        let foreign = other_carrier.peer_address(&[0x46; 32]).unwrap();
        assert!(carrier.authenticated_peer(&foreign).is_err());
        other_pump.close().await.unwrap();
        assert!(other_carrier.authenticated_peer(&foreign).is_err());
        drop(other_carrier);
        other_bridge.close().await.unwrap();
        pump.close().await.unwrap();
        assert!(carrier.authenticated_peer(&address).is_err());
        drop(carrier);
        bridge.close().await.unwrap();
    }

    #[tokio::test]
    async fn receive_wakers_reach_every_peer_and_empty_packets_keep_nonzero_stride() {
        use std::{
            future::poll_fn,
            io::IoSliceMut,
            sync::atomic::{AtomicUsize, Ordering},
            task::{Context, Poll, Wake},
        };

        use tokio::time::timeout;

        let (listener_transport, port) = start_listener(0xD6).await;
        let remote_transport = crate::test_support::start_dialer(0xD7, port).await;
        let second_transport = crate::test_support::start_dialer(0xE3, port).await;
        let remote_key = remote_transport.public_key();
        let second_key = second_transport.public_key();
        let bridge = YggBridge::new(listener_transport, [remote_key, second_key]);
        let remote = YggBridge::new(remote_transport, [bridge.public_key()]);
        let second_remote = YggBridge::new(second_transport, [bridge.public_key()]);
        let remote_cap = remote
            .open_datagrams(bridge.public_key(), BUDGET)
            .await
            .unwrap();
        let second_cap = second_remote
            .open_datagrams(bridge.public_key(), BUDGET)
            .await
            .unwrap();
        remote.probe(bridge.public_key(), BUDGET).await.unwrap();
        second_remote
            .probe(bridge.public_key(), BUDGET)
            .await
            .unwrap();
        bridge.probe(remote_key, BUDGET).await.unwrap();
        bridge.probe(second_key, BUDGET).await.unwrap();
        let (carrier, mut pump) = YggCarrier::attach(
            &bridge,
            bridge.public_key(),
            &[remote_key, second_key],
            BUDGET,
        )
        .await
        .unwrap();
        let mut endpoint = carrier.bind().unwrap();
        let mut invalid_bufs: [IoSliceMut<'_>; 0] = [];
        let mut invalid_metas = [noq_udp::RecvMeta::default()];
        let mut invalid_infos = [RecvInfo::default()];
        let invalid = poll_fn(|cx| {
            endpoint.poll_recv(
                cx,
                &mut invalid_bufs,
                &mut invalid_metas,
                &mut invalid_infos,
            )
        })
        .await;
        assert_eq!(invalid.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        let mut bytes = [0; 8];
        let mut metas = [noq_udp::RecvMeta::default()];
        let mut infos = [RecvInfo::default()];
        struct CountWake(AtomicUsize, tokio::sync::Notify);
        impl Wake for CountWake {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
                self.1.notify_one();
            }
        }
        let count = Arc::new(CountWake(AtomicUsize::new(0), tokio::sync::Notify::new()));
        let waker = std::task::Waker::from(Arc::clone(&count));
        let mut cx = Context::from_waker(&waker);
        let mut idle = [IoSliceMut::new(&mut bytes)];
        assert!(
            endpoint
                .poll_recv(&mut cx, &mut idle, &mut metas, &mut infos)
                .is_pending()
        );
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        let second_sender = second_cap.sender();
        let send = second_sender.send(b"second", BUDGET);
        timeout(BUDGET, send).await.unwrap().unwrap();
        timeout(BUDGET, count.1.notified())
            .await
            .expect("second receiver woke the registered poller");
        assert!(count.0.load(Ordering::SeqCst) > 0);
        let mut second_bytes = [0; 8];
        let mut second_bufs = [IoSliceMut::new(&mut second_bytes)];
        assert!(matches!(
            endpoint.poll_recv(&mut cx, &mut second_bufs, &mut metas, &mut infos),
            Poll::Ready(Ok(1))
        ));
        assert_eq!(&second_bytes[..metas[0].len], b"second");
        let expected_source = carrier.peer_address(&second_key).unwrap();
        assert_eq!(
            carrier.authenticated_peer(&expected_source).unwrap(),
            second_key
        );
        let expected_info = RecvInfo::new(expected_source, Some(carrier.local.clone()));
        assert_eq!(format!("{:?}", infos[0]), format!("{expected_info:?}"));

        let mut bufs = [IoSliceMut::new(&mut bytes)];
        let recv = poll_fn(|cx| endpoint.poll_recv(cx, &mut bufs, &mut metas, &mut infos));
        let remote_sender = remote_cap.sender();
        let (sent, got) = tokio::join!(remote_sender.send(&[], BUDGET), timeout(BUDGET, recv));
        sent.unwrap();
        assert_eq!(got.unwrap().unwrap(), 1);
        assert_eq!(metas[0].len, 0);
        assert_eq!(metas[0].stride, 1);
        let mut small = [0; 2];
        let mut small_bufs = [IoSliceMut::new(&mut small)];
        let too_small =
            poll_fn(|cx| endpoint.poll_recv(cx, &mut small_bufs, &mut metas, &mut infos));
        let (sent, received) = tokio::join!(
            remote_sender.send(b"larger", BUDGET),
            timeout(BUDGET, too_small),
        );
        sent.unwrap();
        assert_eq!(
            received.unwrap().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        drop(endpoint);
        pump.close().await.unwrap();
        bridge.close().await.unwrap();
        remote.close().await.unwrap();
        second_remote.close().await.unwrap();
    }

    #[tokio::test]
    async fn attach_cancellation_drops_partial_registrations() {
        use std::future::Future;
        use std::{future::poll_fn, task::Poll};

        let (transport, _) = start_listener(0xD8).await;
        let bridge = YggBridge::new(transport, []);
        let peers = [[0x51; 32], [0x52; 32]];
        let mut attaching = Box::pin(YggCarrier::attach(
            &bridge,
            bridge.public_key(),
            &peers,
            BUDGET,
        ));
        poll_fn(|cx| {
            assert!(attaching.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(attaching);
        for peer in peers {
            let capability = bridge.open_datagrams(peer, BUDGET).await.unwrap();
            drop(capability);
        }
        let second = bridge.open_datagrams([0x52; 32], BUDGET).await.unwrap();
        assert!(
            YggCarrier::attach(
                &bridge,
                bridge.public_key(),
                &[[0x53; 32], [0x52; 32]],
                BUDGET,
            )
            .await
            .is_err()
        );
        let first = bridge.open_datagrams([0x53; 32], BUDGET).await.unwrap();
        assert!(matches!(
            bridge.open_datagrams([0x52; 32], BUDGET).await,
            Err(crate::DatagramError::AlreadyRegistered)
        ));
        drop((first, second));
        bridge.close().await.unwrap();
    }

    #[tokio::test]
    async fn revoked_rx_rejects_a_datagram_already_queued() {
        use std::task::Poll;

        let (transport, port) = start_listener(0xE1).await;
        let remote_transport = crate::test_support::start_dialer(0xE2, port).await;
        let remote_key = remote_transport.public_key();
        let bridge = YggBridge::new(transport, [remote_key]);
        let remote = YggBridge::new(remote_transport, [bridge.public_key()]);
        let (carrier, pump) =
            YggCarrier::attach(&bridge, bridge.public_key(), &[remote_key], BUDGET)
                .await
                .unwrap();
        let mut receivers = carrier.receivers.lock().unwrap().take().unwrap();
        let mut receiver = receivers.remove(0);
        remote.probe(bridge.public_key(), BUDGET).await.unwrap();
        bridge.probe(remote_key, BUDGET).await.unwrap();
        let remote_cap = remote
            .open_datagrams(bridge.public_key(), BUDGET)
            .await
            .unwrap();
        let sender = remote_cap.sender();
        let before = bridge.queued_datagrams();
        tokio::time::timeout(BUDGET, async {
            while bridge.queued_datagrams() == before {
                sender.send(b"queued before revoke", BUDGET).await.unwrap();
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("queued datagram observation deadline");
        receiver.sender().revoke();
        std::future::poll_fn(|cx| {
            assert!(matches!(
                receiver.poll_recv(cx),
                Poll::Ready(Err(crate::DatagramError::Revoked))
            ));
            Poll::Ready(())
        })
        .await;
        drop(receiver);
        drop(carrier);
        drop(pump);
        bridge.close().await.unwrap();
        remote.close().await.unwrap();
    }

    #[tokio::test]
    async fn custom_sender_rejects_invalid_source_segmentation_and_oversize_payload() {
        use std::task::{Context, Poll, Wake, Waker};
        struct Noop;
        impl Wake for Noop {
            fn wake(self: Arc<Self>) {}
        }

        let (transport, _) = start_listener(0xDD).await;
        let bridge = YggBridge::new(transport, []);
        let (carrier, _pump) =
            YggCarrier::attach(&bridge, bridge.public_key(), &[[0x61; 32]], BUDGET)
                .await
                .unwrap();
        let mtu = carrier.receivers.lock().unwrap().as_ref().unwrap()[0]
            .sender()
            .mtu();
        let endpoint = carrier.bind().unwrap();
        let sender = Sender(Arc::clone(&carrier.shared), carrier.local.clone());
        let destination = carrier.peer_address(&[0x61; 32]).unwrap();
        let local = carrier.local.clone();
        let wrong_local = CustomAddr::from_parts(local.id(), &[0xff; 16]);
        let waker = Waker::from(Arc::new(Noop));
        let mut cx = Context::from_waker(&waker);
        let payload = [0xA5; 4];
        assert!(matches!(
            sender.poll_packet(&mut cx, &destination, Some(&wrong_local), &payload, None),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidInput
        ));
        for segment in [Some(2), Some(0)] {
            assert!(matches!(
                sender.poll_packet(&mut cx, &destination, Some(&local), &payload, segment),
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidInput
            ));
        }
        let oversize = vec![0; mtu + 1];
        assert!(matches!(
            sender.poll_packet(&mut cx, &destination, Some(&local), &oversize, None),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidInput
        ));
        for segment in [None, Some(payload.len())] {
            assert!(matches!(
                sender.poll_packet(&mut cx, &destination, Some(&local), &payload, segment),
                Poll::Ready(Ok(()))
            ));
        }
        drop(endpoint);
        bridge.close().await.unwrap();
    }

    #[tokio::test]
    async fn custom_endpoint_is_single_bind_and_drop_revokes_capabilities() {
        let (transport, _) = start_listener(0xD3).await;
        let bridge = YggBridge::new(transport, []);
        let (carrier, _pump) = YggCarrier::attach(
            &bridge,
            bridge.public_key(),
            &[[0x47; 32]],
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let address = carrier.peer_address(&[0x47; 32]).unwrap();
        let endpoint = carrier.bind().unwrap();
        assert_eq!(carrier.bind().unwrap_err().kind(), io::ErrorKind::AddrInUse);
        drop(endpoint);
        assert!(carrier.authenticated_peer(&address).is_err());
        bridge.close().await.unwrap();
    }
}

struct Sender(Arc<Shared>, CustomAddr);

impl fmt::Debug for Sender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("YggCarrierSender(..)")
    }
}

impl CustomSender for Sender {
    fn is_valid_send_addr(&self, address: &CustomAddr) -> bool {
        self.0.authenticated_peer(address).is_ok()
    }

    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        dst: &CustomAddr,
        src: Option<&CustomAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_packet(cx, dst, src, transmit.contents, transmit.segment_size)
    }
}

impl Sender {
    fn poll_packet(
        &self,
        cx: &mut Context<'_>,
        dst: &CustomAddr,
        src: Option<&CustomAddr>,
        contents: &[u8],
        segment_size: Option<usize>,
    ) -> Poll<io::Result<()>> {
        if src.is_some_and(|source| source != &self.1)
            || segment_size.is_some_and(|size| size == 0 || size != contents.len())
        {
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        self.0.poll_send(cx, dst, contents)
    }
}
