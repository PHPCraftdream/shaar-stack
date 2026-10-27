use std::{
    future::{Future, Ready},
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use libp2p::{
    Multiaddr, PeerId, Transport,
    core::{
        Endpoint,
        transport::{DialOpts, ListenerId, PortUse, TransportError, TransportEvent},
    },
    swarm::ConnectionId,
};
use tokio::time::Instant;

use crate::discovery::roles::{AttemptKey, Owner, Role, Root, View};

pub(super) fn peer() -> PeerId {
    libp2p::identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id()
}
pub(super) fn options() -> DialOpts {
    DialOpts {
        role: Endpoint::Dialer,
        port_use: PortUse::New,
    }
}
pub(super) fn address(prefix: &str, peer: PeerId) -> Multiaddr {
    prefix
        .parse::<Multiaddr>()
        .unwrap()
        .with(libp2p::multiaddr::Protocol::P2p(peer))
}
pub(super) fn stage(owner: &mut Owner, peer: PeerId, address: &Multiaddr, id: usize) -> AttemptKey {
    let now = Instant::now();
    let key = owner
        .admit(
            peer,
            ConnectionId::new_unchecked(id),
            now + std::time::Duration::from_secs(10),
            now,
        )
        .unwrap();
    owner
        .pin_root(key, Root::new(address.as_ref(), peer).unwrap(), now)
        .unwrap();
    key
}
pub(super) fn setup(role: Role, prefix: &str) -> (Owner, View, AttemptKey, Multiaddr) {
    let peer = peer();
    let mut owner = if role == Role::Application {
        Owner::new(&[peer], &[]).unwrap()
    } else {
        let mut owner = Owner::new(&[], &[]).unwrap();
        owner.admit_identity(peer, role).unwrap();
        owner
    };
    let address = address(prefix, peer);
    let key = stage(&mut owner, peer, &address, 1);
    let view = owner.view();
    (owner, view, key, address)
}

#[derive(Default)]
pub(super) struct Counts {
    pub(super) dials: AtomicUsize,
    pub(super) polls: AtomicUsize,
    pub(super) futures_dropped: AtomicUsize,
    pub(super) outputs_dropped: AtomicUsize,
    pub(super) ready: AtomicBool,
}

pub(super) struct Observed {
    pub(super) counts: Arc<Counts>,
    pub(super) on_poll: Option<Box<dyn FnOnce() + Send>>,
    pub(super) fail: bool,
}
impl Observed {
    pub(super) fn new(ready: bool) -> (Self, Arc<Counts>) {
        let counts = Arc::new(Counts::default());
        counts.ready.store(ready, Ordering::SeqCst);
        (
            Self {
                counts: counts.clone(),
                on_poll: None,
                fail: false,
            },
            counts,
        )
    }
}

pub(super) struct Output(Arc<Counts>);
impl Drop for Output {
    fn drop(&mut self) {
        self.0.outputs_dropped.fetch_add(1, Ordering::SeqCst);
    }
}
pub(super) struct ObservedFuture {
    counts: Arc<Counts>,
    on_poll: Option<Box<dyn FnOnce() + Send>>,
    fail: bool,
}
impl Future for ObservedFuture {
    type Output = io::Result<Output>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.counts.polls.fetch_add(1, Ordering::SeqCst);
        if let Some(hook) = this.on_poll.take() {
            hook();
        }
        if this.counts.ready.load(Ordering::SeqCst) {
            if this.fail {
                Poll::Ready(Err(io::ErrorKind::ConnectionRefused.into()))
            } else {
                Poll::Ready(Ok(Output(this.counts.clone())))
            }
        } else {
            Poll::Pending
        }
    }
}
impl Drop for ObservedFuture {
    fn drop(&mut self) {
        self.counts.futures_dropped.fetch_add(1, Ordering::SeqCst);
    }
}
impl Transport for Observed {
    type Output = Output;
    type Error = io::Error;
    type ListenerUpgrade = Ready<io::Result<Output>>;
    type Dial = ObservedFuture;
    fn listen_on(
        &mut self,
        _: ListenerId,
        _: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        Ok(())
    }
    fn remove_listener(&mut self, _: ListenerId) -> bool {
        true
    }
    fn dial(
        &mut self,
        _: Multiaddr,
        _: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        self.counts.dials.fetch_add(1, Ordering::SeqCst);
        Ok(ObservedFuture {
            counts: self.counts.clone(),
            on_poll: self.on_poll.take(),
            fail: self.fail,
        })
    }
    fn poll(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Poll::Pending
    }
}

pub(super) fn poll<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    Pin::new(future).poll(&mut Context::from_waker(std::task::Waker::noop()))
}
pub(super) fn count(value: &AtomicUsize) -> usize {
    value.load(Ordering::SeqCst)
}
