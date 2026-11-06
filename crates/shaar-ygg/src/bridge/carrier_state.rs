use std::{
    collections::VecDeque,
    io,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
};

use iroh_base::CustomAddr;
use tokio::sync::{Semaphore, watch};

use crate::bridge::{DatagramError, DatagramSender, MAX_DATAGRAM_PEERS};

const QUEUE: usize = 32;
const WAITERS: usize = 64;
const TYPE: u64 = 0x5348_5947_4700_0001;
static INSTANCE: AtomicU64 = AtomicU64::new(1);

type Wakeups = [Option<Waker>; WAITERS];

struct Binding {
    peer: [u8; 32],
    address: CustomAddr,
    sender: DatagramSender,
}

pub(crate) struct Outgoing {
    pub sender: DatagramSender,
    pub bytes: Vec<u8>,
}

struct State {
    queue: VecDeque<Outgoing>,
    waiters: Wakeups,
    closed: bool,
}

pub(crate) struct Shared {
    bindings: Vec<Binding>,
    instance: u64,
    state: Mutex<State>,
    pub ready: Semaphore,
    pub closed: watch::Sender<bool>,
}

fn error(kind: io::ErrorKind) -> io::Error {
    io::Error::new(kind, "carrier state unavailable")
}

fn datagram_error(failure: DatagramError) -> io::Error {
    let kind = match failure {
        DatagramError::Revoked => io::ErrorKind::NotConnected,
        DatagramError::Closed => io::ErrorKind::BrokenPipe,
        _ => io::ErrorKind::Other,
    };
    error(kind)
}

fn wake(waiters: Wakeups) {
    for waiter in waiters.into_iter().flatten() {
        waiter.wake();
    }
}

fn address(instance: u64, index: usize) -> CustomAddr {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&instance.to_be_bytes());
    let index = u64::try_from(index).expect("binding count is bounded");
    bytes[8..].copy_from_slice(&index.to_be_bytes());
    CustomAddr::from_parts(TYPE, &bytes)
}

fn decode(address: &CustomAddr) -> io::Result<(u64, usize)> {
    if address.id() != TYPE || address.data().len() != 16 {
        return Err(error(io::ErrorKind::InvalidInput));
    }
    let data = address.data();
    let instance = u64::from_be_bytes(data[..8].try_into().expect("checked fixed size"));
    let index = u64::from_be_bytes(data[8..].try_into().expect("checked fixed size"));
    let index = usize::try_from(index).map_err(|_| error(io::ErrorKind::InvalidInput))?;
    Ok((instance, index))
}

impl Shared {
    pub(crate) fn new(bindings: Vec<([u8; 32], DatagramSender)>) -> io::Result<Self> {
        if bindings.len() > MAX_DATAGRAM_PEERS {
            return Err(error(io::ErrorKind::InvalidData));
        }
        for (index, (peer, sender)) in bindings.iter().enumerate() {
            if bindings[..index].iter().any(|(prior, _)| prior == peer) {
                return Err(error(io::ErrorKind::InvalidData));
            }
            sender.status().map_err(datagram_error)?;
        }
        let instance = INSTANCE
            .try_update(Ordering::AcqRel, Ordering::Acquire, |id| id.checked_add(1))
            .map_err(|_| error(io::ErrorKind::Other))?;
        let bindings = bindings
            .into_iter()
            .enumerate()
            .map(|(index, (peer, sender))| Binding {
                peer,
                address: address(instance, index),
                sender,
            })
            .collect();
        let (closed, _) = watch::channel(false);
        Ok(Self {
            bindings,
            instance,
            state: Mutex::new(State {
                queue: VecDeque::with_capacity(QUEUE),
                waiters: std::array::from_fn(|_| None),
                closed: false,
            }),
            ready: Semaphore::new(0),
            closed,
        })
    }

    pub(crate) fn local(&self) -> CustomAddr {
        address(self.instance, MAX_DATAGRAM_PEERS)
    }

    pub(crate) fn peer_address(&self, peer: &[u8; 32]) -> io::Result<CustomAddr> {
        let state = self.state.lock().map_err(|_| error(io::ErrorKind::Other))?;
        if state.closed {
            return Err(error(io::ErrorKind::BrokenPipe));
        }
        let binding = self
            .bindings
            .iter()
            .find(|binding| &binding.peer == peer)
            .ok_or_else(|| error(io::ErrorKind::NotConnected))?;
        binding.sender.status().map_err(datagram_error)?;
        Ok(binding.address.clone())
    }

    pub(crate) fn authenticated_peer(&self, address: &CustomAddr) -> io::Result<[u8; 32]> {
        let (instance, index) = decode(address)?;
        if instance != self.instance {
            return Err(error(io::ErrorKind::NotConnected));
        }
        let state = self.state.lock().map_err(|_| error(io::ErrorKind::Other))?;
        if state.closed {
            return Err(error(io::ErrorKind::BrokenPipe));
        }
        let binding = self
            .bindings
            .get(index)
            .filter(|binding| binding.address == *address)
            .ok_or_else(|| error(io::ErrorKind::NotConnected))?;
        binding.sender.status().map_err(datagram_error)?;
        Ok(binding.peer)
    }

    pub(crate) fn poll_send(
        &self,
        cx: &mut Context<'_>,
        address: &CustomAddr,
        bytes: &[u8],
    ) -> Poll<io::Result<()>> {
        let (instance, index) = match decode(address) {
            Ok(decoded) => decoded,
            Err(failure) => return Poll::Ready(Err(failure)),
        };
        if instance != self.instance {
            return Poll::Ready(Err(error(io::ErrorKind::NotConnected)));
        }
        let mut candidate = Some(cx.waker().clone());
        let result = {
            let mut state = match self.state.lock() {
                Ok(state) => state,
                Err(_) => return Poll::Ready(Err(error(io::ErrorKind::Other))),
            };
            if state.closed {
                return Poll::Ready(Err(error(io::ErrorKind::BrokenPipe)));
            }
            let Some(binding) = self.bindings.get(index).filter(|b| b.address == *address) else {
                return Poll::Ready(Err(error(io::ErrorKind::NotConnected)));
            };
            if let Err(failure) = binding.sender.status() {
                return Poll::Ready(Err(datagram_error(failure)));
            }
            if bytes.len() > binding.sender.mtu() {
                return Poll::Ready(Err(error(io::ErrorKind::InvalidInput)));
            }
            if state.queue.len() < QUEUE {
                state.queue.push_back(Outgoing {
                    sender: binding.sender.clone(),
                    bytes: bytes.to_vec(),
                });
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

    pub(crate) async fn next(&self) -> io::Result<Option<Outgoing>> {
        let permit = match self.ready.acquire().await {
            Ok(permit) => permit,
            Err(_) => return Ok(None),
        };
        permit.forget();
        let (outgoing, waiters) = {
            let mut state = self.state.lock().map_err(|_| error(io::ErrorKind::Other))?;
            let outgoing = state.queue.pop_front();
            let waiters = std::mem::replace(&mut state.waiters, std::array::from_fn(|_| None));
            (outgoing, waiters)
        };
        wake(waiters);
        Ok(outgoing)
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.state.lock().map_or(true, |state| state.closed)
    }

    pub(crate) fn close(&self) {
        let waiters = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if state.closed {
                return;
            }
            state.closed = true;
            state.queue.clear();
            std::mem::replace(&mut state.waiters, std::array::from_fn(|_| None))
        };
        for binding in &self.bindings {
            binding.sender.revoke();
        }
        self.ready.close();
        self.closed.send_replace(true);
        wake(waiters);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{BUDGET, start_listener};
    use std::{
        sync::{Arc, Weak, atomic::AtomicUsize},
        task::Wake,
    };

    struct Counter {
        shared: Weak<Shared>,
        calls: AtomicUsize,
    }
    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            assert!(self.shared.upgrade().unwrap().state.try_lock().is_ok());
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn bounded_queue_wakes_distinct_waiters_outside_lock_and_closes() {
        let (transport, _) = start_listener(0xD5).await;
        let bridge = crate::YggBridge::new(transport, []);
        let cap = bridge.open_datagrams([0x48; 32], BUDGET).await.unwrap();
        let shared = Arc::new(Shared::new(vec![([0x48; 32], cap.sender())]).unwrap());
        let address = shared.peer_address(&[0x48; 32]).unwrap();
        let producer = Waker::from(Arc::new(Counter {
            shared: Arc::downgrade(&shared),
            calls: AtomicUsize::new(0),
        }));
        let mut cx = Context::from_waker(&producer);
        for _ in 0..32 {
            assert!(matches!(
                shared.poll_send(&mut cx, &address, b"full"),
                Poll::Ready(Ok(()))
            ));
        }
        let waiters: Vec<_> = (0..64)
            .map(|_| {
                Arc::new(Counter {
                    shared: Arc::downgrade(&shared),
                    calls: AtomicUsize::new(0),
                })
            })
            .collect();
        for waiter in &waiters {
            let waker = Waker::from(Arc::clone(waiter));
            let mut waiter_cx = Context::from_waker(&waker);
            assert!(
                shared
                    .poll_send(&mut waiter_cx, &address, b"wait")
                    .is_pending()
            );
            assert!(
                shared
                    .poll_send(&mut waiter_cx, &address, b"same")
                    .is_pending()
            );
        }
        let overflow = Waker::from(Arc::new(Counter {
            shared: Arc::downgrade(&shared),
            calls: AtomicUsize::new(0),
        }));
        let mut overflow_cx = Context::from_waker(&overflow);
        assert!(
            matches!(shared.poll_send(&mut overflow_cx, &address, b"overflow"),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WouldBlock)
        );
        shared.next().await.unwrap().unwrap();
        assert!(waiters.iter().all(|w| w.calls.load(Ordering::SeqCst) == 1));
        assert!(matches!(
            shared.poll_send(&mut cx, &address, b"resumed"),
            Poll::Ready(Ok(()))
        ));
        let close_waiter = Arc::new(Counter {
            shared: Arc::downgrade(&shared),
            calls: AtomicUsize::new(0),
        });
        let close_waker = Waker::from(Arc::clone(&close_waiter));
        let mut close_cx = Context::from_waker(&close_waker);
        assert!(
            shared
                .poll_send(&mut close_cx, &address, b"close-wait")
                .is_pending()
        );
        shared.close();
        assert_eq!(
            shared.authenticated_peer(&address).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(close_waiter.calls.load(Ordering::SeqCst), 1);
        assert!(shared.is_closed());
        assert!(shared.next().await.unwrap().is_none());
        bridge.close().await.unwrap();
    }
}
