use std::{
    collections::{HashMap, VecDeque},
    io,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
};

use iroh_base::CustomAddr;
use libp2p::PeerId;
use tokio::sync::{Semaphore, watch};

use crate::{Datagram, Link};

pub(super) const QUEUE: usize = 32;
const PEERS: usize = 16;
const WAITERS: usize = 64;
const TYPE: u64 = 0x5348_4141_5200_0001;
static INSTANCE: AtomicU64 = AtomicU64::new(1);

type Wakeups = [Option<Waker>; WAITERS];

#[derive(Clone)]
struct Binding {
    link: Link,
    address: CustomAddr,
}

pub(super) struct Outgoing {
    pub link: Link,
    pub packet: Datagram,
}

struct State {
    by_peer: HashMap<PeerId, u64>,
    by_epoch: HashMap<u64, Binding>,
    epoch: u64,
    frames: VecDeque<Outgoing>,
    waiters: Wakeups,
    closed: bool,
}

pub(super) struct Shared {
    state: Mutex<State>,
    instance: u64,
    pub local: CustomAddr,
    pub ready: Semaphore,
    pub closed: watch::Sender<bool>,
}

fn error(kind: io::ErrorKind) -> io::Error {
    io::Error::new(kind, "signaling transport state unavailable")
}
fn wake(waiters: Wakeups) {
    for waiter in waiters.into_iter().flatten() {
        waiter.wake();
    }
}
fn address(instance: u64, epoch: u64) -> CustomAddr {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&instance.to_be_bytes());
    bytes[8..].copy_from_slice(&epoch.to_be_bytes());
    CustomAddr::from_parts(TYPE, &bytes)
}

impl Shared {
    pub fn new() -> io::Result<Self> {
        // Local namespace uniqueness, not a cryptographic nonce or remote authority.
        let instance = INSTANCE
            .try_update(Ordering::AcqRel, Ordering::Acquire, |id| id.checked_add(1))
            .map_err(|_| error(io::ErrorKind::Other))?;
        let (closed, _) = watch::channel(false);
        Ok(Self {
            state: Mutex::new(State {
                by_peer: HashMap::with_capacity(PEERS),
                by_epoch: HashMap::with_capacity(PEERS),
                epoch: 0,
                frames: VecDeque::with_capacity(QUEUE),
                waiters: std::array::from_fn(|_| None),
                closed: false,
            }),
            instance,
            local: address(instance, 0),
            ready: Semaphore::new(0),
            closed,
        })
    }

    fn epoch(&self, addr: &CustomAddr) -> io::Result<u64> {
        if addr.id() != TYPE || addr.data().len() != 16 {
            return Err(error(io::ErrorKind::InvalidInput));
        }
        let data = addr.data();
        let instance = u64::from_be_bytes(data[..8].try_into().expect("checked fixed size"));
        if instance != self.instance {
            return Err(error(io::ErrorKind::NotConnected));
        }
        Ok(u64::from_be_bytes(
            data[8..].try_into().expect("checked fixed size"),
        ))
    }

    pub fn refresh(&self, links: &[Link]) -> io::Result<()> {
        if links.len() > PEERS || links.windows(2).any(|pair| pair[0].peer >= pair[1].peer) {
            return Err(error(io::ErrorKind::InvalidData));
        }
        let waiters = {
            let mut state = self.state.lock().map_err(|_| error(io::ErrorKind::Other))?;
            if state.closed {
                return Err(error(io::ErrorKind::BrokenPipe));
            }
            state.by_epoch.retain(|_, binding| {
                links
                    .binary_search_by_key(&binding.link.peer, |link| link.peer)
                    .is_ok_and(|index| links[index] == binding.link)
            });
            let mut retained = [None; PEERS];
            for (slot, (epoch, binding)) in retained.iter_mut().zip(&state.by_epoch) {
                *slot = Some((binding.link.peer, *epoch));
            }
            state.by_peer.clear();
            for (peer, epoch) in retained.into_iter().flatten() {
                state.by_peer.insert(peer, epoch);
            }
            for link in links {
                if state.by_peer.contains_key(&link.peer) {
                    continue;
                }
                state.epoch = state
                    .epoch
                    .checked_add(1)
                    .ok_or_else(|| error(io::ErrorKind::Other))?;
                let epoch = state.epoch;
                state.by_epoch.insert(
                    epoch,
                    Binding {
                        link: *link,
                        address: address(self.instance, epoch),
                    },
                );
                state.by_peer.insert(link.peer, epoch);
            }
            std::mem::replace(&mut state.waiters, std::array::from_fn(|_| None))
        };
        wake(waiters);
        Ok(())
    }

    pub fn peer_address(&self, peer: PeerId) -> io::Result<CustomAddr> {
        let state = self.state.lock().map_err(|_| error(io::ErrorKind::Other))?;
        if state.closed {
            return Err(error(io::ErrorKind::BrokenPipe));
        }
        let epoch = state
            .by_peer
            .get(&peer)
            .ok_or_else(|| error(io::ErrorKind::NotConnected))?;
        Ok(state.by_epoch[epoch].address.clone())
    }

    pub fn link(&self, addr: &CustomAddr) -> io::Result<Link> {
        let epoch = self.epoch(addr)?;
        let state = self.state.lock().map_err(|_| error(io::ErrorKind::Other))?;
        if state.closed {
            return Err(error(io::ErrorKind::BrokenPipe));
        }
        state
            .by_epoch
            .get(&epoch)
            .map(|binding| binding.link)
            .ok_or_else(|| error(io::ErrorKind::NotConnected))
    }

    pub fn matches(&self, addr: &CustomAddr, link: Link) -> bool {
        let Ok(epoch) = self.epoch(addr) else {
            return false;
        };
        let Ok(state) = self.state.lock() else {
            return false;
        };
        !state.closed
            && state
                .by_epoch
                .get(&epoch)
                .is_some_and(|binding| binding.link == link)
    }

    pub fn is_closed(&self) -> bool {
        self.state.lock().is_ok_and(|state| state.closed)
    }

    pub fn accepts(&self, addr: &CustomAddr) -> bool {
        let Ok(epoch) = self.epoch(addr) else {
            return false;
        };
        let Ok(state) = self.state.lock() else {
            return false;
        };
        !state.closed && state.by_epoch.contains_key(&epoch)
    }

    pub fn poll_send(
        &self,
        cx: &mut Context<'_>,
        addr: &CustomAddr,
        bytes: &[u8],
    ) -> Poll<io::Result<()>> {
        let epoch = self.epoch(addr)?;
        if bytes.is_empty() || bytes.len() > crate::MAX_DATAGRAM {
            return Poll::Ready(Err(error(io::ErrorKind::InvalidInput)));
        }
        // Candidate destruction and all wake callbacks occur after the short critical section.
        let mut candidate = Some(cx.waker().clone());
        let result = {
            let mut state = self.state.lock().map_err(|_| error(io::ErrorKind::Other))?;
            if state.closed {
                return Poll::Ready(Err(error(io::ErrorKind::BrokenPipe)));
            }
            let link = match state.by_epoch.get(&epoch) {
                Some(binding) => binding.link,
                None => return Poll::Ready(Err(error(io::ErrorKind::NotConnected))),
            };
            if state.frames.len() < QUEUE {
                let packet = Datagram::new(bytes)?;
                state.frames.push_back(Outgoing { link, packet });
                Poll::Ready(Ok(()))
            } else if state
                .waiters
                .iter()
                .flatten()
                .any(|waker| waker.will_wake(cx.waker()))
            {
                Poll::Pending
            } else if let Some(slot) = state.waiters.iter_mut().find(|slot| slot.is_none()) {
                *slot = candidate.take();
                Poll::Pending
            } else {
                Poll::Ready(Err(error(io::ErrorKind::WouldBlock)))
            }
        };
        drop(candidate);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.ready.add_permits(1);
        }
        result
    }

    /// cancel-safe: yes — cancelled acquisition consumes no frame; dequeue has no await.
    pub async fn next(&self) -> io::Result<Option<Outgoing>> {
        let permit = match self.ready.acquire().await {
            Ok(permit) => permit,
            Err(_) => return Ok(None),
        };
        permit.forget();
        let (frame, waiters) = {
            let mut state = self.state.lock().map_err(|_| error(io::ErrorKind::Other))?;
            let frame = state.frames.pop_front();
            let waiters = std::mem::replace(&mut state.waiters, std::array::from_fn(|_| None));
            (frame, waiters)
        };
        wake(waiters);
        Ok(frame)
    }

    pub fn close(&self) {
        let waiters = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if state.closed {
                return;
            }
            state.closed = true;
            state.frames.clear();
            state.by_peer.clear();
            state.by_epoch.clear();
            std::mem::replace(&mut state.waiters, std::array::from_fn(|_| None))
        };
        self.ready.close();
        self.closed.send_replace(true);
        wake(waiters);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Route;
    use libp2p::{identity::Keypair, swarm::ConnectionId};
    use std::{
        sync::{Arc, Weak, atomic::AtomicUsize},
        task::Wake,
    };

    fn link(id: usize) -> Link {
        Link {
            peer: Keypair::generate_ed25519().public().to_peer_id(),
            connection: ConnectionId::new_unchecked(id),
            route: Route::Direct,
        }
    }
    struct Counter {
        shared: Weak<Shared>,
        count: AtomicUsize,
    }
    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            let shared = self.shared.upgrade().unwrap();
            assert!(
                shared.state.try_lock().is_ok(),
                "wake callback ran under queue lock"
            );
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn counted(shared: &Arc<Shared>) -> Arc<Counter> {
        Arc::new(Counter {
            shared: Arc::downgrade(shared),
            count: AtomicUsize::new(0),
        })
    }

    #[test]
    fn shutdown_observation_does_not_depend_on_watch_notification_publication() {
        let shared = Shared::new().unwrap();
        shared.state.lock().unwrap().closed = true;
        assert!(!*shared.closed.borrow());
        assert!(shared.is_closed());
    }

    #[test]
    fn local_addresses_bind_instance_and_epoch_without_peer_claims() {
        let shared = Shared::new().unwrap();
        let first = link(1);
        shared.refresh(&[first]).unwrap();
        let old = shared.peer_address(first.peer).unwrap();
        assert_eq!(old.data().len(), 16);
        assert!(shared.matches(&old, first));
        assert!(!Shared::new().unwrap().accepts(&old));
        assert!(!shared.accepts(&CustomAddr::from_parts(TYPE, &[0; 17])));
        assert!(!shared.accepts(&shared.local));
        let next = Link {
            connection: ConnectionId::new_unchecked(2),
            ..first
        };
        shared.refresh(&[next]).unwrap();
        let current = shared.peer_address(next.peer).unwrap();
        assert_ne!(current, old);
        assert!(!shared.accepts(&old));
        assert!(shared.matches(&current, next));
        shared.refresh(&[next]).unwrap();
        assert_eq!(shared.peer_address(next.peer).unwrap(), current);
        shared.refresh(&[]).unwrap();
        assert!(!shared.accepts(&current));
        shared.refresh(&[next]).unwrap();
        assert_ne!(shared.peer_address(next.peer).unwrap(), current);
        let too_many: Vec<_> = (0..=PEERS).map(link).collect();
        assert!(shared.refresh(&too_many).is_err());
        shared.close();
        assert!(shared.peer_address(next.peer).is_err());
        shared.close();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bounded_queue_wakes_every_distinct_waiter_outside_the_lock() {
        let shared = Arc::new(Shared::new().unwrap());
        let current = link(1);
        shared.refresh(&[current]).unwrap();
        let address = shared.peer_address(current.peer).unwrap();
        let producer = Waker::from(counted(&shared));
        let mut cx = Context::from_waker(&producer);
        for _ in 0..QUEUE {
            assert!(matches!(
                shared.poll_send(&mut cx, &address, b"queued"),
                Poll::Ready(Ok(()))
            ));
        }
        let waiters: Vec<_> = (0..WAITERS).map(|_| counted(&shared)).collect();
        for waiter in &waiters {
            let waker = Waker::from(waiter.clone());
            let mut cx = Context::from_waker(&waker);
            assert!(shared.poll_send(&mut cx, &address, b"waiting").is_pending());
            assert!(
                shared
                    .poll_send(&mut cx, &address, b"same waiter")
                    .is_pending()
            );
        }
        let extra = Waker::from(counted(&shared));
        let mut extra_cx = Context::from_waker(&extra);
        assert!(
            matches!(shared.poll_send(&mut extra_cx, &address, b"overflow"), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WouldBlock)
        );
        assert!(
            matches!(shared.poll_send(&mut extra_cx, &address, &[]), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidInput)
        );
        assert_eq!(
            shared.next().await.unwrap().unwrap().packet.as_bytes(),
            b"queued"
        );
        assert!(
            waiters
                .iter()
                .all(|waiter| waiter.count.load(Ordering::SeqCst) == 1)
        );
        assert!(matches!(
            shared.poll_send(&mut cx, &address, b"resumed"),
            Poll::Ready(Ok(()))
        ));
        assert!(
            shared
                .poll_send(&mut extra_cx, &address, b"closed waiter")
                .is_pending()
        );
        shared.close();
        assert!(shared.next().await.unwrap().is_none());
        assert!(!shared.accepts(&address));
        assert!(
            matches!(shared.poll_send(&mut cx, &address, b"closed"), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe)
        );
    }

    #[test]
    fn epoch_overflow_and_poison_fail_closed() {
        let shared = Arc::new(Shared::new().unwrap());
        shared.state.lock().unwrap().epoch = u64::MAX;
        assert!(shared.refresh(&[link(1)]).is_err());
        let poisoned = shared.clone();
        let result = std::thread::spawn(move || {
            let _guard = poisoned.state.lock().unwrap();
            panic!("intentional queue state poison");
        })
        .join();
        assert!(result.is_err());
        assert!(shared.peer_address(link(2).peer).is_err());
        shared.close();
        assert!(*shared.closed.borrow());
    }
}
