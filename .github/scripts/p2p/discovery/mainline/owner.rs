// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Retained ownership for a numeric-address Mainline DHT actor.
//!
//! The owner keeps the spawned task join handle so shutdown is observable.
#![forbid(unsafe_code)]

use std::io;
use std::net::SocketAddrV4;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::actor;
use crate::actor::ActorMessage;
use crate::resource::{
    OwnedQueryCompletion, RequestBudget, RequestLease, RequestReply, ResourceError,
};

/// A cloneable, limited capability for using an owned DHT actor.
///
/// Clones retain only the actor message sender and cannot retain its socket.
#[derive(Clone)]
pub struct OwnedDhtHandle {
    sender: mpsc::Sender<ActorMessage>,
    failure: Arc<OnceLock<ResourceError>>,
    request_budget: Arc<RequestBudget>,
    publication_observer: crate::resource::Observer,
}

impl OwnedDhtHandle {
    /// Return a bounded cleanup observer for owned publication operations.
    pub fn publication_observer(&self) -> crate::resource::Observer {
        self.publication_observer.clone()
    }

    fn failure(&self) -> ResourceError {
        self.failure
            .get()
            .copied()
            .unwrap_or(ResourceError::QueryCancelled)
    }

    /// Resolve a mutable target and return its network-completion receipt.
    /// cancel-safe: NO — cancellation requests actor cleanup but does not join it.
    pub async fn resolve_mutable(
        &self,
        target: crate::Id,
    ) -> Result<OwnedQueryCompletion, ResourceError> {
        self.resolve_mutable_until(
            target,
            tokio::time::Instant::now() + Duration::from_secs(10),
        )
        .await
    }

    /// Use the caller's absolute deadline, capped at ten seconds from execution entry.
    /// cancel-safe: NO — cancellation requests actor cleanup but does not join it.
    pub async fn resolve_mutable_until(
        &self,
        target: crate::Id,
        deadline: tokio::time::Instant,
    ) -> Result<OwnedQueryCompletion, ResourceError> {
        let entry = tokio::time::Instant::now();
        if let Some(error) = self.failure.get() {
            return Err(*error);
        }
        let deadline = deadline.min(entry + Duration::from_secs(10));
        if tokio::time::Instant::now() >= deadline {
            return Err(ResourceError::DeadlineExceeded);
        }
        let request_lease = self
            .request_budget
            .acquire()
            .ok_or(ResourceError::OperationLimit)?;
        let _cancellation = self.request_budget.cancellation_guard();
        let (admission_sender, admission_receiver) = oneshot::channel();
        let permit = tokio::time::timeout_at(deadline, self.sender.reserve())
            .await
            .map_err(|_| ResourceError::DeadlineExceeded)?
            .map_err(|_| self.failure())?;
        if tokio::time::Instant::now() >= deadline {
            return Err(ResourceError::DeadlineExceeded);
        }
        permit.send(ActorMessage::OwnedAdmission(
            target,
            admission_sender,
            deadline,
            request_lease,
        ));
        let result_receiver = match tokio::time::timeout_at(deadline, admission_receiver)
            .await
            .map_err(|_| ResourceError::DeadlineExceeded)?
            .map_err(|_| self.failure())?
        {
            RequestReply::Ready(receiver) => receiver,
            RequestReply::Error(error) => return Err(error),
        };
        let result = tokio::time::timeout_at(deadline, result_receiver)
            .await
            .map_err(|_| ResourceError::DeadlineExceeded)?
            .map_err(|_| self.failure())?;
        if tokio::time::Instant::now() >= deadline {
            return Err(ResourceError::DeadlineExceeded);
        }
        result
    }

    /// Start a mutable PUT using the caller's deadline, capped at 10 seconds from entry.
    pub fn put_mutable_until(
        &self,
        item: crate::MutableItem,
        deadline: tokio::time::Instant,
    ) -> Result<crate::resource::OwnedPutAdmission, crate::resource::OwnedPutAdmissionError> {
        let entry = tokio::time::Instant::now();
        let deadline = deadline.min(entry + Duration::from_secs(10));
        let clean = |error| crate::resource::OwnedPutAdmissionError {
            error,
            cleanup: crate::resource::OwnedPutCleanup::Clean,
        };
        let unknown = |error| crate::resource::OwnedPutAdmissionError {
            error,
            cleanup: crate::resource::OwnedPutCleanup::Unknown,
        };
        if let Some(error) = self.failure.get() {
            return Err(unknown(*error));
        }
        if item.salt().is_some() || item.value().len() > 1000 || item.seq() < 0 {
            return Err(clean(ResourceError::InvalidMutableItem));
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(clean(ResourceError::DeadlineExceeded));
        }
        let item = item
            .into_owned_put()
            .map_err(|_| clean(ResourceError::InvalidMutableItem))?;
        let lease = self
            .request_budget
            .acquire()
            .ok_or_else(|| clean(ResourceError::OperationLimit))?;
        let (admitted_tx, admitted_rx) = oneshot::channel();
        let (cancel_tx, mut cancel_rx) = oneshot::channel();
        let (cleanup_tx, cleanup_rx) = oneshot::channel();
        let sender = self.sender.clone();
        let wake = self.request_budget.cancellation_wake();
        let failure_status = Arc::clone(&self.failure);
        let send = async move {
            tokio::select! {
                biased;
                _ = &mut cancel_rx => {
                    drop(item);
                    drop(lease);
                    let _ = admitted_tx.send(Err(ResourceError::QueryCancelled));
                    let _ = cleanup_tx.send(());
                }
                permit = tokio::time::timeout_at(deadline, sender.reserve()) => {
                    match permit {
                        Ok(Ok(permit)) if tokio::time::Instant::now() < deadline => {
                            permit.send(ActorMessage::OwnedPut(
                                *item.target(), item, admitted_tx, cleanup_tx, cancel_rx,
                                deadline, lease,
                            ));
                        }
                        Err(_) => {
                            drop(item);
                            drop(lease);
                            let _ = admitted_tx.send(Err(ResourceError::DeadlineExceeded));
                            let _ = cleanup_tx.send(());
                        }
                        Ok(Err(_)) => {
                            drop(item);
                            drop(lease);
                            let error = failure_status
                                .get()
                                .copied()
                                .unwrap_or(ResourceError::QueryCancelled);
                            let _ = admitted_tx.send(Err(error));
                            let _ = cleanup_tx.send(());
                        }
                        Ok(Ok(permit)) => {
                            drop(permit);
                            drop(item);
                            drop(lease);
                            let _ = admitted_tx.send(Err(ResourceError::DeadlineExceeded));
                            let _ = cleanup_tx.send(());
                        }
                    }
                }
            }
        };
        Ok(crate::resource::OwnedPutAdmission::new(
            Box::pin(send), admitted_rx, cancel_tx, cleanup_rx, wake, deadline,
        ))
    }

    /// Await admission while retaining cancellation and cleanup ownership.
    pub async fn put_mutable(
        &self,
        item: crate::MutableItem,
    ) -> Result<crate::resource::OwnedPutOperation, ResourceError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut admission = self.put_mutable_until(item, deadline).map_err(|failure| failure.error)?;
        admission.wait().await.map_err(|failure| failure.error)?;
        admission.take_operation().ok_or(ResourceError::QueryCancelled)
    }

    #[cfg(test)]
    pub(crate) async fn test_put_control(
        &self,
        target: crate::Id,
        jitter: u8,
    ) -> Result<(), ResourceError> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(ActorMessage::OwnedPutTestControl(target, jitter, tx))
            .await
            .map_err(|_| self.failure())?;
        rx.await.map_err(|_| self.failure())
    }

    /// Retrieve actor information.
    pub async fn info(&self) -> Result<actor::Info, ResourceError> {
        if let Some(error) = self.failure.get() {
            return Err(*error);
        }
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(ActorMessage::Info(sender))
            .await
            .map_err(|_| self.failure())?;
        receiver.await.map_err(|_| self.failure())
    }
}

#[cfg(test)]
mod failed_admission_tests {
    use super::*;
    use std::sync::Arc;
    use std::task::Poll;
    use std::future::Future;

    #[tokio::test]
    async fn cancel_before_first_poll_releases_local_admission_cleanly() {
        let (sender, mut receiver) = mpsc::channel(1);
        let budget = Arc::new(RequestBudget::default());
        let handle = OwnedDhtHandle {
            sender,
            failure: Arc::new(OnceLock::new()),
            request_budget: Arc::clone(&budget),
            publication_observer: crate::resource::Observer::default(),
        };
        let item = crate::MutableItem::new(
            &ed25519_dalek::SigningKey::from_bytes(&[0x52; 32]),
            b"cancel-before-poll",
            1,
            None,
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut admission = handle
            .put_mutable_until(item, deadline)
            .expect("admission");
        assert_eq!(
            admission.cancel_and_wait().await,
            crate::resource::OwnedPutCleanup::Clean
        );
        assert!(
            receiver.try_recv().is_err(),
            "cancelled reservation must not enqueue"
        );
        assert_eq!(
            admission.cancel_and_wait().await,
            crate::resource::OwnedPutCleanup::Clean
        );
        assert!(
            budget.acquire().is_some(),
            "pre-enqueue cancellation released the request lease"
        );
    }

    #[tokio::test]
    async fn absolute_deadline_fails_before_enqueue_with_clean_provenance() {
        let (sender, mut receiver) = mpsc::channel(1);
        let budget = Arc::new(RequestBudget::default());
        let handle = OwnedDhtHandle {
            sender,
            failure: Arc::new(OnceLock::new()),
            request_budget: Arc::clone(&budget),
            publication_observer: crate::resource::Observer::default(),
        };
        let item = crate::MutableItem::new(
            &ed25519_dalek::SigningKey::from_bytes(&[0x54; 32]),
            b"expired-deadline",
            1,
            None,
        );
        let deadline = tokio::time::Instant::now();
        let error = handle
            .put_mutable_until(item, deadline)
            .expect_err("expired absolute deadline");
        assert_eq!(error.error, ResourceError::DeadlineExceeded);
        assert_eq!(
            error.cleanup,
            crate::resource::OwnedPutCleanup::Clean
        );
        assert!(receiver.try_recv().is_err());
        assert!(budget.acquire().is_some());
    }

    #[tokio::test]
    async fn cancelled_wait_can_resume_cleanup_without_repolling_submission() {
        let (sender, mut receiver) = mpsc::channel(1);
        let budget = Arc::new(RequestBudget::default());
        let handle = OwnedDhtHandle {
            sender,
            failure: Arc::new(OnceLock::new()),
            request_budget: Arc::clone(&budget),
            publication_observer: crate::resource::Observer::default(),
        };
        let item = crate::MutableItem::new(
            &ed25519_dalek::SigningKey::from_bytes(&[0x53; 32]),
            b"cancelled-wait",
            1,
            None,
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut admission = handle
            .put_mutable_until(item, deadline)
            .expect("admission");
        let mut wait = Box::pin(admission.wait());
        std::future::poll_fn(|cx| {
            assert!(wait.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let message = receiver.recv().await.expect("PUT message");
        let ActorMessage::OwnedPut(_, _, admitted, cleanup, mut cancel, _, lease) = message else {
            panic!("expected owned PUT");
        };
        let admitted = admitted
            .send(Err(ResourceError::OperationLimit));
        admitted.expect("reject admission");
        drop(wait);
        let mut cleanup_wait = Box::pin(admission.cancel_and_wait());
        std::future::poll_fn(|cx| {
            assert!(cleanup_wait.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(cancel.try_recv(), Ok(()));
        drop(lease);
        cleanup.send(()).expect("complete actor cleanup");
        assert_eq!(
            (&mut cleanup_wait).await,
            crate::resource::OwnedPutCleanup::Clean
        );
        drop(cleanup_wait);
        assert_eq!(
            admission.cancel_and_wait().await,
            crate::resource::OwnedPutCleanup::Clean
        );
    }

    #[tokio::test]
    async fn lost_cleanup_receipt_is_classified_unknown() {
        let (sender, mut receiver) = mpsc::channel(1);
        let budget = Arc::new(RequestBudget::default());
        let handle = OwnedDhtHandle {
            sender,
            failure: Arc::new(OnceLock::new()),
            request_budget: Arc::clone(&budget),
            publication_observer: crate::resource::Observer::default(),
        };
        let item = crate::MutableItem::new(
            &ed25519_dalek::SigningKey::from_bytes(&[0x55; 32]),
            b"lost-cleanup-receipt",
            1,
            None,
        );
        let mut admission = handle
            .put_mutable_until(item, tokio::time::Instant::now() + Duration::from_secs(5))
            .expect("admission");
        let mut waiting = Box::pin(admission.wait());
        std::future::poll_fn(|cx| {
            assert!(waiting.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let message = receiver.recv().await.expect("PUT actor message");
        let ActorMessage::OwnedPut(_, _, admitted, cleanup, _, _, lease) = message else {
            panic!("expected owned PUT message");
        };
        admitted
            .send(Err(ResourceError::OperationLimit))
            .expect("reject actor admission");
        drop(cleanup);
        drop(lease);
        let error = waiting.await.expect_err("admission must fail");
        assert_eq!(error.error, ResourceError::OperationLimit);
        assert_eq!(
            error.cleanup,
            crate::resource::OwnedPutCleanup::Unknown
        );
    }

    #[tokio::test]
    async fn rejected_admission_waits_for_actor_cleanup_receipt() {
        let (sender, mut receiver) = mpsc::channel(1);
        let budget = Arc::new(RequestBudget::default());
        let handle = OwnedDhtHandle {
            sender,
            failure: Arc::new(OnceLock::new()),
            request_budget: Arc::clone(&budget),
            publication_observer: crate::resource::Observer::default(),
        };
        let item = crate::MutableItem::new(
            &ed25519_dalek::SigningKey::from_bytes(&[0x51; 32]),
            b"rejected-admission",
            1,
            None,
        );
        let mut request = Box::pin(handle.put_mutable(item));
        std::future::poll_fn(|cx| {
            assert!(request.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let message = receiver.recv().await.expect("PUT actor message");
        let ActorMessage::OwnedPut(_, _, admitted, cleanup, mut cancel, _, lease) = message else {
            panic!("expected owned PUT message");
        };
        admitted
            .send(Err(ResourceError::OperationLimit))
            .expect("report rejection");
        std::future::poll_fn(|cx| {
            assert!(request.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(cancel.try_recv(), Ok(()));

        drop(lease);
        cleanup.send(()).expect("report completed cleanup");
        assert!(matches!(request.await, Err(ResourceError::OperationLimit)));
        let leases: Vec<_> = (0..24)
            .map(|_| budget.acquire().expect("released request-budget slot"))
            .collect();
        assert!(
            budget.acquire().is_none(),
            "request budget has 24 slots"
        );
        drop(leases);
    }
}

/// A DHT handle paired with ownership of its actor task and shutdown signal.
pub struct OwnedDht {
    handle: OwnedDhtHandle,
    stop: Option<oneshot::Sender<()>>,
    join: Option<JoinHandle<()>>,
    terminal: Option<(io::ErrorKind, String)>,
}

impl OwnedDht {
    /// Bind a numeric IPv4 address and start an actor using numeric bootstrap addresses.
    ///
    /// All bootstrap addresses are validated before the actor is constructed. Must be
    /// called inside a Tokio runtime because the UDP socket is registered with it.
    pub fn new(bind: SocketAddrV4, bootstrap: &[SocketAddrV4]) -> io::Result<Self> {
        if bootstrap.is_empty()
            || bootstrap.len() > 4
            || bootstrap.iter().any(|addr| addr.port() == 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid numeric bootstrap",
            ));
        }
        let bootstrap = bootstrap.to_vec().into_boxed_slice();
        let mut actor = actor::Actor::new_numeric(bind, bootstrap)?;
        actor
            .enable_owned_resources()
            .map_err(|error| io::Error::new(error.io_kind(), error))?;
        Ok(Self::from_actor(actor))
    }

    pub(crate) fn from_actor(mut actor: actor::Actor) -> Self {
        actor
            .enable_owned_resources()
            .expect("validated owned actor resource initialization");
        let failure = actor.owned_failure_status();
        let request_budget = actor.owned_request_budget();
        let publication_observer = actor.owned_publication_observer();
        let (sender, receiver) = mpsc::channel(16);
        let (stop, stop_receiver) = oneshot::channel();
        let join = tokio::spawn(actor::run_owned(actor, receiver, stop_receiver));
        Self {
            handle: OwnedDhtHandle {
                sender,
                failure,
                request_budget,
                publication_observer,
            },
            stop: Some(stop),
            join: Some(join),
            terminal: None,
        }
    }

    /// Return a cloneable, limited capability for actor requests.
    pub fn handle(&self) -> OwnedDhtHandle {
        self.handle.clone()
    }

    /// Complete an owned mutable lookup with an explicit network-completion receipt.
    pub async fn resolve_mutable(
        &self,
        target: crate::Id,
    ) -> Result<OwnedQueryCompletion, ResourceError> {
        self.handle.resolve_mutable(target).await
    }

    /// Request actor shutdown without waiting. Repeated calls are harmless.
    pub fn request_stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }

    /// Request shutdown and wait up to five seconds for the retained actor task.
    ///
    /// This method is cancellation-safe: if its future is cancelled, the join handle
    /// remains stored in this owner and a later call can continue waiting. A timeout
    /// also retains the handle, allowing another call to observe eventual completion.
    pub async fn close(&mut self) -> io::Result<()> {
        self.request_stop();
        if let Some((kind, message)) = &self.terminal {
            return Err(io::Error::new(*kind, message.clone()));
        }
        let Some(join) = self.join.as_mut() else {
            return Ok(());
        };
        match tokio::time::timeout(Duration::from_secs(5), join).await {
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "DHT actor shutdown timed out",
            )),
            Ok(result) => {
                self.join.take();
                match result {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        let message = error.to_string();
                        let kind = if error.is_cancelled() {
                            io::ErrorKind::Interrupted
                        } else {
                            io::ErrorKind::Other
                        };
                        self.terminal = Some((kind, message.clone()));
                        Err(io::Error::new(kind, message))
                    }
                }
            }
        }
    }
}

impl Drop for OwnedDht {
    fn drop(&mut self) {
        self.request_stop();
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}
