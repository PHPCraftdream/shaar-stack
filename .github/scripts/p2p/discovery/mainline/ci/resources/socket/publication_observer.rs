// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

//! Bounded observer for processed transaction receipts and owned PUT cleanup control.
//!
//! The actor/socket ingress seam records a receipt only after the actual
//! message-processing path has completed, including stale or ignored responses.
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

use crate::resource::ResourceError;

const RETIRED_QUERY_CAPACITY: usize = 32;
const RECEIPT_CAPACITY: usize = 128;

/// Cloneable observer for processed transaction receipts and bounded cleanup observation.
#[derive(Clone, Debug, Default)]
pub struct Observer {
    inner: Arc<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    state: Mutex<State>,
    changed: Notify,
    cleanup: Mutex<CleanupState>,
    cleanup_changed: Notify,
    actor_wake: Mutex<Option<Arc<Notify>>>,
    retired_queries: Mutex<VecDeque<crate::Id>>,
    retired_queries_changed: Notify,
}

#[derive(Debug, Default)]
struct CleanupState {
    held: bool,
    target: Option<crate::Id>,
    entered: bool,
}

#[derive(Debug, Default)]
struct State {
    receipts: VecDeque<(u64, u32)>,
    processed: u64,
}

/// Unique bounded cleanup hold released by dropping its token.
pub struct CleanupHold {
    observer: Observer,
    released: bool,
}

impl CleanupHold {
    /// Release the hold and wake the owned actor to finish cleanup.
    pub fn release(mut self) {
        self.observer.release_cleanup();
        self.released = true;
    }
}

impl std::fmt::Debug for CleanupHold {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("CleanupHold").field("released", &self.released).finish()
    }
}

impl Drop for CleanupHold {
    fn drop(&mut self) {
        if !self.released { self.observer.release_cleanup(); }
    }
}

impl Observer {
    pub(crate) fn attach_actor_wake(&self, wake: Arc<Notify>) {
        let replaced = {
            let mut slot = self.inner.actor_wake.lock()
                .expect("publication observer wake poisoned");
            slot.replace(wake)
        };
        drop(replaced);
    }

    /// Acquire the unique bounded hold for actor-side PUT cleanup.
    pub fn hold_cleanup(&self) -> Result<CleanupHold, ResourceError> {
        self.hold_cleanup_for(None)
    }

    /// Acquire the bounded hold for a target-specific PUT cleanup observation.
    pub fn hold_cleanup_for_target(&self, target: crate::Id) -> Result<CleanupHold, ResourceError> {
        self.hold_cleanup_for(Some(target))
    }

    fn hold_cleanup_for(&self, target: Option<crate::Id>) -> Result<CleanupHold, ResourceError> {
        {
            let mut cleanup = self.inner.cleanup.lock()
                .expect("publication observer cleanup poisoned");
            if cleanup.held {
                return Err(ResourceError::OperationLimit);
            }
            cleanup.held = true;
            cleanup.target = target;
            cleanup.entered = false;
        }
        Ok(CleanupHold { observer: self.clone(), released: false })
    }

    /// Wait until actor cancellation cleanup reaches the held PUT.
    pub async fn wait_cleanup_held(&self) {
        loop {
            let notified = self.inner.cleanup_changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let entered = self.inner.cleanup.lock()
                .expect("publication observer cleanup poisoned").entered;
            if entered { return; }
            notified.await;
        }
    }

    /// Record the completed backend retirement of one owned GET query target.
    /// Emitted only after the cancelled waiter's leases were dropped, the
    /// operation was cancelled with its transactions retired, and the
    /// iterative query was removed.
    pub(crate) fn note_query_retired(&self, target: crate::Id) {
        {
            let mut retired = self
                .inner
                .retired_queries
                .lock()
                .expect("publication observer retired queries poisoned");
            if retired.back() != Some(&target) {
                retired.push_back(target);
                if retired.len() > RETIRED_QUERY_CAPACITY {
                    retired.pop_front();
                }
            }
        }
        self.inner.retired_queries_changed.notify_waiters();
    }

    /// Whether `target` has a recorded owned-query retirement.
    pub fn has_retired_query(&self, target: crate::Id) -> bool {
        self.inner
            .retired_queries
            .lock()
            .expect("publication observer retired queries poisoned")
            .contains(&target)
    }

    /// Wait until `target` has a recorded owned-query retirement. One
    /// registered condition wait; no polling and no timeout-based completion.
    pub async fn wait_query_retired(&self, target: crate::Id) {
        loop {
            let notified = self.inner.retired_queries_changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.has_retired_query(target) {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn cleanup_is_held(&self) -> bool {
        self.inner.cleanup.lock()
            .expect("publication observer cleanup poisoned").held
    }

    pub(crate) fn cleanup_is_held_for(&self, target: crate::Id) -> bool {
        let cleanup = self.inner.cleanup.lock()
            .expect("publication observer cleanup poisoned");
        cleanup.held && cleanup.target.map_or(true, |held_target| held_target == target)
    }

    pub(crate) fn note_cleanup_entered(&self, target: crate::Id) {
        let entered = {
            let mut cleanup = self.inner.cleanup.lock()
                .expect("publication observer cleanup poisoned");
            if cleanup.held && cleanup.target.map_or(true, |held_target| held_target == target) {
                cleanup.entered = true;
                true
            } else {
                false
            }
        };
        if entered { self.inner.cleanup_changed.notify_waiters(); }
    }

    fn release_cleanup(&self) {
        let released = {
            let mut cleanup = self.inner.cleanup.lock()
                .expect("publication observer cleanup poisoned");
            if cleanup.held {
                cleanup.held = false;
                cleanup.target = None;
                cleanup.entered = false;
                true
            } else {
                false
            }
        };
        if released {
            self.inner.cleanup_changed.notify_waiters();
            let wake = {
                self.inner.actor_wake.lock()
                    .expect("publication observer wake poisoned").clone()
            };
            if let Some(wake) = wake { wake.notify_one(); }
        }
    }

    /// Record a transaction identifier after actual message processing.
    ///
    /// This is crate-private so callers cannot manufacture observation events.
    pub(crate) fn processed(&self, tid: u32) -> Result<u64, ResourceError> {
        let mut state = self.inner.state.lock().expect("publication observer poisoned");
        let sequence = state
            .processed
            .checked_add(1)
            .ok_or(ResourceError::ResultLimit)?;
        state.processed = sequence;
        if state.receipts.len() == RECEIPT_CAPACITY {
            state.receipts.pop_front();
        }
        state.receipts.push_back((sequence, tid));
        drop(state);
        self.inner.changed.notify_waiters();
        Ok(sequence)
    }

    /// Return the latest processed sequence number.
    pub fn cursor(&self) -> u64 {
        self.inner.state.lock().expect("publication observer poisoned").processed
    }

    /// Wait for this transaction identifier to be processed after `cursor`.
    /// Returns `ResultLimit` if the cursor predates retained history or the
    /// sequence counter has been exhausted.
    pub async fn wait_processed_after(
        &self,
        cursor: u64,
        tid: u32,
    ) -> Result<u64, ResourceError> {
        loop {
            let notified = self.inner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            let outcome = {
                let state = self.inner.state.lock().expect("publication observer poisoned");
                if state.processed == u64::MAX {
                    Some(Err(ResourceError::ResultLimit))
                } else if state.receipts.front().is_some_and(|(sequence, _)| {
                    cursor < sequence.saturating_sub(1)
                }) {
                    Some(Err(ResourceError::ResultLimit))
                } else {
                    state.receipts
                        .iter()
                        .find(|(sequence, seen_tid)| *sequence > cursor && *seen_tid == tid)
                        .map(|(sequence, _)| Ok(*sequence))
                }
            };
            if let Some(outcome) = outcome {
                return outcome;
            }
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Id;
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};

    #[tokio::test]
    async fn receipt_cursor_matching_and_bounded_eviction() {
        let observer = Observer::default();
        let cursor = observer.cursor();
        assert_eq!(observer.processed(7).expect("processed receipt"), cursor + 1);
        assert_eq!(observer.wait_processed_after(cursor, 7).await, Ok(cursor + 1));
        assert_eq!(observer.processed(8), Ok(cursor + 2));
        let pending = observer.wait_processed_after(cursor + 1, 7);
        tokio::pin!(pending);
        std::future::poll_fn(|context| {
            assert!(matches!(Future::poll(pending.as_mut(), context), Poll::Pending));
            Poll::Ready(())
        })
        .await;
        let mut latest = observer.cursor();
        for tid in 0..RECEIPT_CAPACITY as u32 {
            latest = observer.processed(tid).expect("processed bounded receipt");
        }
        let oldest_retained = latest - RECEIPT_CAPACITY as u64 + 1;
        assert_eq!(observer.wait_processed_after(0, 99).await, Err(ResourceError::ResultLimit));
        assert_eq!(observer.wait_processed_after(oldest_retained - 1, 0).await, Ok(oldest_retained));
    }

    #[tokio::test]
    async fn pending_waiter_is_send_and_observes_notification_after_registration() {
        let observer = Observer::default();
        let cursor = observer.cursor();
        let waiter = observer.wait_processed_after(cursor, 41);
        fn assert_send<T: Send>(_: &T) {}
        fn assert_future_send<T: Future + Send>(_: T) {}
        assert_send(&waiter);
        assert_future_send(observer.wait_processed_after(cursor, 42));
        tokio::pin!(waiter);
        std::future::poll_fn(|context| {
            assert!(matches!(Future::poll(waiter.as_mut(), context), Poll::Pending));
            Poll::Ready(())
        })
        .await;
        assert_eq!(observer.processed(41), Ok(cursor + 1));
        assert_eq!(waiter.await, Ok(cursor + 1));
    }

    #[tokio::test]
    async fn cleanup_hold_matches_target_and_drop_releases_actor_wake() {
        let observer = Observer::default();
        let wake = Arc::new(Notify::new());
        observer.attach_actor_wake(Arc::clone(&wake));
        let target = Id::from([1; 20]);
        let other = Id::from([2; 20]);
        let hold = observer.hold_cleanup_for_target(target).expect("unique cleanup hold");
        assert!(observer.cleanup_is_held());
        assert!(observer.cleanup_is_held_for(target));
        assert!(!observer.cleanup_is_held_for(other));
        observer.note_cleanup_entered(other);
        assert!(!observer.inner.cleanup.lock().expect("cleanup state").entered);
        observer.note_cleanup_entered(target);
        observer.wait_cleanup_held().await;
        drop(hold);
        wake.notified().await;
        assert!(!observer.cleanup_is_held());
        assert!(observer.hold_cleanup().is_ok());
    }

    #[test]
    fn receipt_sequence_exhaustion_is_an_observer_unit_boundary() {
        let observer = Observer::default();
        observer.inner.state.lock().expect("observer state").processed = u64::MAX;
        assert_eq!(observer.processed(5), Err(ResourceError::ResultLimit));
        assert_eq!(observer.cursor(), u64::MAX);
    }

    /// Counts wakings delivered through a registered waker; the std `Wake`
    /// trait builds it without unsafe and without an async runtime.
    #[derive(Default)]
    struct WakeCounter {
        wakes: AtomicUsize,
    }

    impl std::task::Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// The retirement note wakes the registered waiter even when the recorded
    /// target does not match; only the poll after the matching note recognizes
    /// the condition. Notification and condition recognition stay distinct, so
    /// removing `notify_waiters` from `note_query_retired` fails the wake
    /// counters below instead of hanging a waiter.
    #[test]
    fn query_retirement_note_wakes_the_registered_waker_before_target_recognition() {
        let observer = Observer::default();
        let retired_target = Id::from([0xD1; 20]);
        let other_target = Id::from([0xD2; 20]);
        let counter = Arc::new(WakeCounter::default());
        let mut pending = std::pin::pin!(observer.wait_query_retired(retired_target));
        let waker = Waker::from(Arc::clone(&counter));
        let mut context = Context::from_waker(&waker);
        let wakes = || counter.wakes.load(Ordering::SeqCst);

        assert!(matches!(
            Future::poll(pending.as_mut(), &mut context),
            Poll::Pending
        ));
        assert_eq!(wakes(), 0, "no note, no wake");

        observer.note_query_retired(other_target);
        assert_eq!(wakes(), 1, "non-matching note wakes the registered waker");
        assert!(matches!(
            Future::poll(pending.as_mut(), &mut context),
            Poll::Pending
        ));
        assert_eq!(wakes(), 1, "the recognition poll itself wakes nothing");

        observer.note_query_retired(retired_target);
        assert_eq!(wakes(), 2, "matching note wakes the registered waker");
        assert!(matches!(
            Future::poll(pending.as_mut(), &mut context),
            Poll::Ready(())
        ));
    }

    /// A retirement noted before the wait makes the very first poll ready.
    #[test]
    fn prior_query_retirement_note_makes_the_first_poll_ready() {
        let observer = Observer::default();
        let target = Id::from([0xD3; 20]);
        observer.note_query_retired(target);
        assert!(observer.has_retired_query(target));
        let counter = Arc::new(WakeCounter::default());
        let mut pending = std::pin::pin!(observer.wait_query_retired(target));
        let waker = Waker::from(Arc::clone(&counter));
        let mut context = Context::from_waker(&waker);
        assert!(matches!(
            Future::poll(pending.as_mut(), &mut context),
            Poll::Ready(())
        ));
        assert_eq!(
            counter.wakes.load(Ordering::SeqCst),
            0,
            "ready needs no wake"
        );
    }

    #[test]
    fn query_retirement_history_is_bounded_coalesced_and_evicts_oldest() {
        let observer = Observer::default();
        let first = Id::from([0xD4; 20]);
        let second = Id::from([0xD5; 20]);
        observer.note_query_retired(first);
        observer.note_query_retired(first);
        {
            let retired = observer
                .inner
                .retired_queries
                .lock()
                .expect("publication observer retired queries poisoned");
            assert_eq!(retired.len(), 1, "consecutive duplicates coalesce");
        }
        observer.note_query_retired(second);
        observer.note_query_retired(first);
        {
            let retired = observer
                .inner
                .retired_queries
                .lock()
                .expect("publication observer retired queries poisoned");
            assert_eq!(retired.len(), 3, "non-consecutive targets stay recorded");
        }
        for index in 0..=RETIRED_QUERY_CAPACITY {
            let mut bytes = [0_u8; 20];
            bytes[0] = index as u8;
            observer.note_query_retired(Id::from(bytes));
        }
        let retired = observer
            .inner
            .retired_queries
            .lock()
            .expect("publication observer retired queries poisoned");
        assert_eq!(retired.len(), RETIRED_QUERY_CAPACITY, "history stays bounded");
        assert!(!retired.contains(&first), "oldest entries are evicted");
        assert!(!retired.contains(&second), "oldest entries are evicted");
    }
}
