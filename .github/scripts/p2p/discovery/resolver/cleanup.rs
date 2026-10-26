#![forbid(unsafe_code)]

use super::*;
use crate::proto::op::DnsRequestOptions;
use std::{
    future::{pending, Future},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Weak,
    },
    task::{Context, Poll, Waker},
};

type Requests = Mutex<HashMap<Arc<CacheKey>, SharedLookup>>;

struct ForeignFuture {
    requests: Weak<Requests>,
    key: Arc<CacheKey>,
    drops: Arc<AtomicUsize>,
    unlocked: Arc<AtomicBool>,
}

impl Future for ForeignFuture {
    type Output = Option<Result<DnsResponse, NetError>>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

impl Drop for ForeignFuture {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
        if let Some(requests) = self.requests.upgrade() {
            if let Some(mut requests) = requests.try_lock() {
                self.unlocked.store(true, Ordering::Relaxed);
                // Reenter the real registry without blocking, even in the counterfactual.
                requests.insert(self.key.clone(), SharedLookup(pending().boxed().shared()));
            }
        }
    }
}

fn fixture() -> (
    Arc<Requests>,
    ActiveRequestCleanup,
    Arc<AtomicUsize>,
    Arc<AtomicBool>,
) {
    let requests = Arc::new(Mutex::new(HashMap::new()));
    let request = DnsRequest::from_query(Query::default(), DnsRequestOptions::default());
    let key = Arc::new(CacheKey::from_request(&request));
    let drops = Arc::new(AtomicUsize::new(0));
    let unlocked = Arc::new(AtomicBool::new(false));
    let foreign = ForeignFuture {
        requests: Arc::downgrade(&requests),
        key: key.clone(),
        drops: drops.clone(),
        unlocked: unlocked.clone(),
    };
    requests
        .lock()
        .insert(key.clone(), SharedLookup(foreign.boxed().shared()));
    let cleanup = ActiveRequestCleanup {
        active_requests: requests.clone(),
        key,
    };
    (requests, cleanup, drops, unlocked)
}

#[test]
fn last_shared_future_is_destroyed_after_unlock_and_can_reenter() {
    let (requests, cleanup, drops, unlocked) = fixture();
    drop(cleanup);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert!(
        unlocked.load(Ordering::Relaxed),
        "FOREIGN_FUTURE_DROPPED_UNDER_LOCK"
    );
    assert_eq!(
        requests.lock().len(),
        1,
        "reentrant replacement must survive cleanup"
    );
}

#[test]
fn retained_shared_waiter_keeps_the_future_until_its_own_drop() {
    let (requests, cleanup, drops, unlocked) = fixture();
    let waiter = requests.lock().get(&cleanup.key).unwrap().clone();
    drop(cleanup);
    assert!(requests.lock().is_empty());
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    drop(waiter);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert!(unlocked.load(Ordering::Relaxed));
}

#[test]
fn absent_key_cleanup_is_idempotent_without_destroying_another_waiter() {
    let (requests, cleanup, drops, unlocked) = fixture();
    let absent = ActiveRequestCleanup {
        active_requests: requests.clone(),
        key: cleanup.key.clone(),
    };
    let removed = requests.lock().remove(&cleanup.key);
    drop(cleanup);
    drop(absent);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    drop(removed);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert!(unlocked.load(Ordering::Relaxed));
}

#[test]
fn shared_result_error_survives_registry_cleanup() {
    let (requests, cleanup, drops, _) = fixture();
    let removed = requests.lock().remove(&cleanup.key);
    drop(removed);
    let mut waiter = SharedLookup(
        futures_util::future::ready(Some(Err(NetError::Timeout)))
            .boxed()
            .shared(),
    );
    let previous = requests.lock().insert(cleanup.key.clone(), waiter.clone());
    drop(previous);
    drop(cleanup);
    assert!(requests.lock().is_empty());
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert!(matches!(
        Pin::new(&mut waiter).poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(NetError::Timeout))
    ));
}
