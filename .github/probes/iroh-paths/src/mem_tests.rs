//! Direct tests of the same queue operations used by the custom transport.
use super::*;
use iroh::endpoint::transports::CustomTransport;
use std::sync::atomic::AtomicUsize;
use std::task::Wake;

#[derive(Debug, Default)]
struct CountWake(AtomicUsize);
impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn waker() -> (Arc<CountWake>, Waker) {
    let state = Arc::new(CountWake::default());
    (state.clone(), Waker::from(state))
}

struct Rig {
    left: Box<dyn CustomEndpoint>,
    right: Box<dyn CustomEndpoint>,
    sender: Sender,
    network: Arc<MemNetwork>,
}

fn rig() -> Rig {
    let (left, right, network) = MemTransport::pair();
    Rig {
        left: left.bind().expect("left bind"),
        right: right.bind().expect("right bind"),
        sender: Sender {
            side: 0,
            network: network.clone(),
        },
        network,
    }
}

fn receive(
    ep: &mut dyn CustomEndpoint,
    cx: &mut Context<'_>,
    size: usize,
) -> (Poll<io::Result<usize>>, Vec<u8>) {
    let mut bytes = vec![0; size];
    let result = {
        let mut bufs = [io::IoSliceMut::new(&mut bytes)];
        let mut metas = [RecvMeta::default()];
        let mut infos = [RecvInfo::default()];
        ep.poll_recv(cx, &mut bufs, &mut metas, &mut infos)
    };
    (result, bytes)
}

fn fill(rig: &Rig, cx: &mut Context<'_>) {
    for _ in 0..QUEUE_CAP {
        assert!(matches!(
            rig.sender.send_packet(cx, &rig.network.local_addr(1), &[7]),
            Poll::Ready(Ok(()))
        ));
    }
}

#[test]
fn full_queue_registers_all_pollers_of_the_same_sender() {
    let mut rig = rig();
    let (a, wa) = waker();
    let (b, wb) = waker();
    let mut ca = Context::from_waker(&wa);
    let mut cb = Context::from_waker(&wb);
    let dst = rig.network.local_addr(1);
    fill(&rig, &mut ca);
    assert!(rig.sender.send_packet(&mut ca, &dst, &[1]).is_pending());
    assert!(rig.sender.send_packet(&mut cb, &dst, &[2]).is_pending());
    assert_eq!(rig.network.stats(0).wire_packets(), QUEUE_CAP as u64);
    assert!(matches!(
        receive(rig.right.as_mut(), &mut ca, 1).0,
        Poll::Ready(Ok(1))
    ));
    assert!(a.0.load(Ordering::Relaxed) > 0);
    assert!(b.0.load(Ordering::Relaxed) > 0);
    assert!(matches!(
        receive(rig.right.as_mut(), &mut ca, 1).0,
        Poll::Ready(Ok(1))
    ));
    assert!(matches!(
        rig.sender.send_packet(&mut ca, &dst, &[1]),
        Poll::Ready(Ok(()))
    ));
    assert!(matches!(
        rig.sender.send_packet(&mut cb, &dst, &[2]),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(rig.network.stats(0).wire_packets(), (QUEUE_CAP + 2) as u64);
    assert_eq!(rig.network.stats(0).delivered_packets(), 2);
    assert_eq!(rig.network.stats(1).delivered_packets(), 0);
}

#[test]
fn receive_registration_is_woken_by_enqueue() {
    let mut rig = rig();
    let (state, wake) = waker();
    let mut cx = Context::from_waker(&wake);
    assert!(
        receive(rig.right.as_mut(), &mut cx, MAX_PACKET)
            .0
            .is_pending()
    );
    assert!(matches!(
        rig.sender
            .send_packet(&mut cx, &rig.network.local_addr(1), b"hello"),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(state.0.load(Ordering::Relaxed), 1);
    let (result, bytes) = receive(rig.right.as_mut(), &mut cx, MAX_PACKET);
    assert!(matches!(result, Poll::Ready(Ok(1))));
    assert_eq!(&bytes[..5], b"hello");
    assert_eq!(rig.network.stats(0).wire_bytes(), 5);
    assert_eq!(rig.network.stats(0).delivered_bytes(), 5);
}

#[test]
fn small_receive_buffer_retains_the_packet() {
    let mut rig = rig();
    let (_, wake) = waker();
    let mut cx = Context::from_waker(&wake);
    let dst = rig.network.local_addr(1);
    assert!(matches!(
        rig.sender.send_packet(&mut cx, &dst, b"hello"),
        Poll::Ready(Ok(()))
    ));
    assert!(
        matches!(receive(rig.right.as_mut(), &mut cx, 4).0, Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::InvalidInput)
    );
    assert_eq!(rig.network.stats(0).delivered_packets(), 0);
    let (result, bytes) = receive(rig.right.as_mut(), &mut cx, 5);
    assert!(matches!(result, Poll::Ready(Ok(1))));
    assert_eq!(bytes, b"hello");
    assert_eq!(rig.network.stats(0).delivered_packets(), 1);
}

#[test]
fn exact_mtu_passes_and_oversize_or_invalid_destination_fails() {
    let mut rig = rig();
    let (_, wake) = waker();
    let mut cx = Context::from_waker(&wake);
    let dst = rig.network.local_addr(1);
    let packet = vec![9; MAX_PACKET];
    assert!(matches!(
        rig.sender.send_packet(&mut cx, &dst, &packet),
        Poll::Ready(Ok(()))
    ));
    assert!(
        matches!(rig.sender.send_packet(&mut cx, &dst, &vec![9; MAX_PACKET + 1]), Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::InvalidInput)
    );
    assert!(
        matches!(rig.sender.send_packet(&mut cx, &dst, &[]), Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::InvalidInput)
    );
    let invalid = CustomAddr::from_parts(TEST_TRANSPORT_ID, &[99]);
    assert!(
        matches!(rig.sender.send_packet(&mut cx, &invalid, &[1]), Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::InvalidInput)
    );
    assert_eq!(rig.network.stats(0).wire_packets(), 1);
    let (result, bytes) = receive(rig.right.as_mut(), &mut cx, MAX_PACKET);
    assert!(matches!(result, Poll::Ready(Ok(1))));
    assert_eq!(bytes, packet);
}

#[test]
fn closure_wakes_already_pending_receivers_and_writers() {
    let mut rig = rig();
    let (reader, wr) = waker();
    let (writer, ww) = waker();
    let mut cr = Context::from_waker(&wr);
    let mut cw = Context::from_waker(&ww);
    assert!(receive(rig.left.as_mut(), &mut cr, 1).0.is_pending());
    fill(&rig, &mut cw);
    let dst = rig.network.local_addr(1);
    assert!(rig.sender.send_packet(&mut cw, &dst, &[1]).is_pending());
    drop(rig.right);
    assert!(reader.0.load(Ordering::Relaxed) > 0);
    assert!(writer.0.load(Ordering::Relaxed) > 0);
    assert!(
        matches!(receive(rig.left.as_mut(), &mut cr, 1).0, Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::BrokenPipe)
    );
    assert!(
        matches!(rig.sender.send_packet(&mut cw, &dst, &[1]), Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::BrokenPipe)
    );
}

#[test]
fn cancelled_waiter_is_released_on_the_next_drain() {
    let mut rig = rig();
    let (state, wake) = waker();
    let weak = Arc::downgrade(&state);
    {
        let mut cx = Context::from_waker(&wake);
        fill(&rig, &mut cx);
        assert!(
            rig.sender
                .send_packet(&mut cx, &rig.network.local_addr(1), &[1])
                .is_pending()
        );
    }
    drop(wake);
    drop(state);
    assert!(weak.upgrade().is_some());
    let (_, wake) = waker();
    let mut cx = Context::from_waker(&wake);
    assert!(matches!(
        receive(rig.right.as_mut(), &mut cx, 1).0,
        Poll::Ready(Ok(1))
    ));
    assert!(weak.upgrade().is_none());
}

#[test]
fn waiter_admission_is_bounded_and_drain_releases_it() {
    let mut rig = rig();
    let (_, first) = waker();
    let mut cx = Context::from_waker(&first);
    fill(&rig, &mut cx);
    let dst = rig.network.local_addr(1);
    for _ in 0..MAX_WAITERS {
        let (_, wake) = waker();
        let mut cx = Context::from_waker(&wake);
        assert!(rig.sender.send_packet(&mut cx, &dst, &[1]).is_pending());
    }
    assert!(
        matches!(rig.sender.send_packet(&mut cx, &dst, &[1]), Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::WouldBlock)
    );
    assert!(matches!(
        receive(rig.right.as_mut(), &mut cx, 1).0,
        Poll::Ready(Ok(1))
    ));
    assert!(matches!(
        rig.sender.send_packet(&mut cx, &dst, &[1]),
        Poll::Ready(Ok(()))
    ));
}
