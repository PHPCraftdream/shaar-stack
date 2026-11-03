// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use crate::MutableItem;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use tokio::sync::Notify;

const RESULT_LIMIT: usize = 8;
const REQUEST_LIMIT: usize = 24;

/// Whether actor-side cleanup is confirmed or unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnedPutCleanup {
    /// Actor acknowledged cleanup after rejecting or cancelling admission.
    Clean,
    /// No cleanup receipt was observed; actor-side work may remain.
    Unknown,
}

/// A PUT admission failure with explicit cleanup provenance.
#[derive(Clone, Debug)]
pub struct OwnedPutAdmissionError {
    /// The resource cause of admission failure.
    pub error: crate::resource::ResourceError,
    /// Whether actor-side cleanup is confirmed.
    pub cleanup: OwnedPutCleanup,
}

/// Typed terminal failure of a bounded mutable-item PUT.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum OwnedPutError {
    /// The operation exceeded an owned resource or deadline bound.
    Resource(crate::resource::ResourceError),
    /// The native PUT query failed, preserving its actual error.
    Put(crate::core::PutError),
}

/// Successful receipt for this PUT's actual transaction set.
#[derive(Clone, Debug)]
pub struct OwnedPutCompletion {
    target: crate::Id,
    operation: crate::resource::OperationId,
    transactions: Arc<[u32]>,
    _lease: Arc<ResultLease>,
}

impl OwnedPutCompletion {
    pub(crate) fn new(
        target: crate::Id,
        operation: crate::resource::OperationId,
        transactions: Vec<u32>,
        lease: Arc<ResultLease>,
    ) -> Self {
        Self {
            target,
            operation,
            transactions: transactions.into(),
            _lease: lease,
        }
    }

    /// Return the bounded actor operation identifier.
    pub fn operation_id(&self) -> u64 {
        self.operation.value()
    }

    /// Return the DHT target associated with this PUT.
    pub fn target(&self) -> crate::Id {
        self.target
    }

    /// Return this PUT's transaction identifiers (at most sixteen).
    pub fn transaction_ids(&self) -> &[u32] {
        &self.transactions
    }
}

/// A retained admission attempt, including cancellation and cleanup ownership.
pub struct OwnedPutAdmission {
    admitted: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    admission_result: tokio::sync::oneshot::Receiver<
        Result<ChargedPutReceiver, crate::resource::ResourceError>,
    >,
    cancel: Option<tokio::sync::oneshot::Sender<()>>,
    cleanup: Option<tokio::sync::oneshot::Receiver<()>>,
    wake: Arc<Notify>,
    deadline: tokio::time::Instant,
    operation: Option<OwnedPutOperation>,
    outcome: Option<Result<(), OwnedPutAdmissionError>>,
    cleanup_result: Option<OwnedPutCleanup>,
    pending_error: Option<crate::resource::ResourceError>,
}

impl std::fmt::Debug for OwnedPutAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("OwnedPutAdmission")
            .field("deadline", &self.deadline)
            .field("has_operation", &self.operation.is_some())
            .field("cleanup_result", &self.cleanup_result)
            .finish()
    }
}

impl OwnedPutAdmission {
    pub(crate) fn new(
        admitted: Pin<Box<dyn Future<Output = ()> + Send>>,
        admission_result: tokio::sync::oneshot::Receiver<
            Result<ChargedPutReceiver, crate::resource::ResourceError>,
        >,
        cancel: tokio::sync::oneshot::Sender<()>,
        cleanup: tokio::sync::oneshot::Receiver<()>,
        wake: Arc<Notify>,
        deadline: tokio::time::Instant,
    ) -> Self {
        Self {
            admitted: Some(admitted),
            admission_result,
            cancel: Some(cancel),
            cleanup: Some(cleanup),
            wake,
            deadline,
            operation: None,
            outcome: None,
            cleanup_result: None,
            pending_error: None,
        }
    }

    /// Await admission while retaining cancellation and cleanup ownership.
    pub async fn wait(&mut self) -> Result<(), OwnedPutAdmissionError> {
        loop {
            if let Some(outcome) = &self.outcome {
                return outcome.clone();
            }
            if let Some(error) = self.pending_error {
                self.signal_cancel();
                self.submit().await;
                let cleanup = self.wait_cleanup().await;
                let failure = OwnedPutAdmissionError { error, cleanup };
                self.outcome = Some(Err(failure.clone()));
                return Err(failure);
            }

            let deadline = self.deadline;
            let expired = tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline) => true,
                _ = self.submit() => false,
            };
            if expired {
                self.pending_error = Some(crate::resource::ResourceError::DeadlineExceeded);
                continue;
            }

            match tokio::time::timeout_at(self.deadline, &mut self.admission_result).await {
                Ok(Ok(Ok(receiver))) if tokio::time::Instant::now() < self.deadline => {
                    self.operation = Some(OwnedPutOperation::new(
                        receiver,
                        self.cancel
                            .take()
                            .expect("cancel handle retained until admission"),
                        self.cleanup
                            .take()
                            .expect("cleanup receiver retained until admission"),
                        Arc::clone(&self.wake),
                    ));
                    self.outcome = Some(Ok(()));
                    return Ok(());
                }
                Ok(Ok(Err(error))) => {
                    self.signal_cancel();
                    self.pending_error = Some(error);
                }
                Ok(Err(_)) => {
                    self.signal_cancel();
                    self.pending_error = Some(crate::resource::ResourceError::QueryCancelled);
                }
                _ => {
                    self.signal_cancel();
                    self.pending_error = Some(crate::resource::ResourceError::DeadlineExceeded);
                }
            }
        }
    }

    async fn submit(&mut self) {
        if let Some(future) = self.admitted.as_mut() {
            future.as_mut().await;
            self.admitted = None;
        }
    }

    /// Take the admitted operation after `wait` succeeds.
    pub fn take_operation(&mut self) -> Option<OwnedPutOperation> {
        let operation = self.operation.take();
        if operation.is_some() {
            self.cleanup_result = Some(OwnedPutCleanup::Unknown);
        }
        operation
    }

    /// Cancel admission or admitted operation and wait for actor cleanup.
    pub async fn cancel_and_wait(&mut self) -> OwnedPutCleanup {
        if let Some(result) = self.cleanup_result {
            return result;
        }
        if self.operation.is_none() && matches!(self.outcome, Some(Ok(()))) {
            return OwnedPutCleanup::Unknown;
        }
        if let Some(operation) = self.operation.as_mut() {
            let status = match operation.cancel_and_wait().await {
                Ok(()) => OwnedPutCleanup::Clean,
                Err(_) => OwnedPutCleanup::Unknown,
            };
            self.cleanup_result = Some(status);
            return status;
        }
        self.signal_cancel();
        self.submit().await;
        self.wait_cleanup().await
    }

    fn signal_cancel(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
            self.wake.notify_one();
        }
    }

    async fn wait_cleanup(&mut self) -> OwnedPutCleanup {
        match self.cleanup.as_mut() {
            Some(cleanup) => {
                let status = match cleanup.await {
                    Ok(()) => OwnedPutCleanup::Clean,
                    Err(_) => OwnedPutCleanup::Unknown,
                };
                self.cleanup.take();
                self.cleanup_result = Some(status);
                status
            }
            None => self.cleanup_result.unwrap_or(OwnedPutCleanup::Unknown),
        }
    }
}

impl Drop for OwnedPutAdmission {
    fn drop(&mut self) {
        if self.outcome.is_none() || self.operation.is_some() {
            self.signal_cancel();
        }
    }
}

/// A cancellable admitted PUT retaining its bounded result charge.
#[derive(Debug)]
pub struct OwnedPutOperation {
    receiver: ChargedPutReceiver,
    cancel: Option<tokio::sync::oneshot::Sender<()>>,
    cleanup: tokio::sync::oneshot::Receiver<()>,
    wake: Arc<Notify>,
    result: Option<Result<OwnedPutCompletion, OwnedPutError>>,
    result_consumed: bool,
    cleanup_done: bool,
    cleanup_result: Option<Result<(), crate::resource::ResourceError>>,
}

impl OwnedPutOperation {
    pub(crate) fn new(
        receiver: ChargedPutReceiver,
        cancel: tokio::sync::oneshot::Sender<()>,
        cleanup: tokio::sync::oneshot::Receiver<()>,
        wake: Arc<Notify>,
    ) -> Self {
        Self {
            receiver,
            cancel: Some(cancel),
            cleanup,
            wake,
            result: None,
            result_consumed: false,
            cleanup_done: false,
            cleanup_result: None,
        }
    }

    /// Await the terminal PUT result while retaining its bounded result charge.
    pub async fn wait(&mut self) -> Result<OwnedPutCompletion, OwnedPutError> {
        if self.result.is_none() {
            self.result = Some(match (&mut self.receiver).await {
                Ok(result) => result,
                Err(_) => Err(OwnedPutError::Resource(
                    crate::resource::ResourceError::QueryCancelled,
                )),
            });
        }
        self.result_consumed = true;
        self.result.as_ref().expect("result stored").clone()
    }

    /// Cancel future PUT work and wait until actor-side transaction cleanup finishes.
    pub async fn cancel_and_wait(&mut self) -> Result<(), crate::resource::ResourceError> {
        if let Some(result) = self.cleanup_result {
            return result;
        }
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
            self.wake.notify_one();
        }
        let result = (&mut self.cleanup)
            .await
            .map_err(|_| crate::resource::ResourceError::QueryCancelled);
        self.cleanup_done = result.is_ok();
        self.cleanup_result = Some(result);
        result
    }
}

impl Drop for OwnedPutOperation {
    fn drop(&mut self) {
        if !self.cleanup_done {
            if let Some(cancel) = self.cancel.take() {
                let _ = cancel.send(());
                self.wake.notify_one();
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct ChargedPutReceiver {
    receiver: tokio::sync::oneshot::Receiver<Result<OwnedPutCompletion, OwnedPutError>>,
    _lease: Arc<ResultLease>,
}

impl ChargedPutReceiver {
    pub(crate) fn new(
        receiver: tokio::sync::oneshot::Receiver<Result<OwnedPutCompletion, OwnedPutError>>,
        lease: Arc<ResultLease>,
    ) -> Self {
        Self { receiver, _lease: lease }
    }
}

impl Future for ChargedPutReceiver {
    type Output = Result<
        Result<OwnedPutCompletion, OwnedPutError>,
        tokio::sync::oneshot::error::RecvError,
    >;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.receiver).poll(cx)
    }
}

#[derive(Debug, Default)]
pub(crate) struct RequestBudget {
    count: AtomicUsize,
    wake: Arc<Notify>,
}

impl RequestBudget {
    pub(crate) fn acquire(self: &Arc<Self>) -> Option<Arc<RequestLease>> {
        let mut current = self.count.load(Ordering::Relaxed);
        loop {
            if current >= REQUEST_LIMIT {
                return None;
            }
            match self.count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(Arc::new(RequestLease(Arc::clone(self)))),
                Err(actual) => current = actual,
            }
        }
    }

    pub(crate) fn cancellation_guard(self: &Arc<Self>) -> RequestCancellation {
        RequestCancellation(Arc::clone(&self.wake))
    }

    pub(crate) fn cancellation_wake(&self) -> Arc<Notify> {
        Arc::clone(&self.wake)
    }
}

pub(crate) struct RequestCancellation(Arc<Notify>);

impl Drop for RequestCancellation {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

#[derive(Debug)]
pub(crate) struct RequestLease(Arc<RequestBudget>);

impl Drop for RequestLease {
    fn drop(&mut self) {
        self.0.count.fetch_sub(1, Ordering::AcqRel);
        self.0.wake.notify_one();
    }
}

#[derive(Debug)]
pub(crate) struct ChargedResultReceiver {
    receiver: tokio::sync::oneshot::Receiver<
        Result<OwnedQueryCompletion, crate::resource::ResourceError>,
    >,
    _lease: Arc<ResultLease>,
}

impl ChargedResultReceiver {
    pub(crate) fn new(
        receiver: tokio::sync::oneshot::Receiver<
            Result<OwnedQueryCompletion, crate::resource::ResourceError>,
        >,
        lease: Arc<ResultLease>,
    ) -> Self {
        Self {
            receiver,
            _lease: lease,
        }
    }
    pub(crate) fn try_recv(
        &mut self,
    ) -> Result<
        Result<OwnedQueryCompletion, crate::resource::ResourceError>,
        tokio::sync::oneshot::error::TryRecvError,
    > {
        self.receiver.try_recv()
    }
}

impl Future for ChargedResultReceiver {
    type Output = Result<
        Result<OwnedQueryCompletion, crate::resource::ResourceError>,
        tokio::sync::oneshot::error::RecvError,
    >;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.receiver).poll(cx)
    }
}

#[derive(Debug)]
pub(crate) enum RequestReply {
    Ready(ChargedResultReceiver),
    Error(crate::resource::ResourceError),
}

#[derive(Debug)]
pub(crate) struct ResultBudget {
    count: AtomicUsize,
    wake: Arc<Notify>,
}

impl Default for ResultBudget {
    fn default() -> Self {
        Self::new(Arc::new(Notify::new()))
    }
}

impl ResultBudget {
    pub(crate) fn new(wake: Arc<Notify>) -> Self {
        Self {
            count: AtomicUsize::new(0),
            wake,
        }
    }

    pub(crate) fn acquire(self: &Arc<Self>) -> Option<Arc<ResultLease>> {
        let mut current = self.count.load(Ordering::Relaxed);
        loop {
            if current >= RESULT_LIMIT {
                return None;
            }
            match self.count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(Arc::new(ResultLease(Arc::clone(self)))),
                Err(actual) => current = actual,
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct ResultLease(Arc<ResultBudget>);

impl Drop for ResultLease {
    fn drop(&mut self) {
        self.0.count.fetch_sub(1, Ordering::AcqRel);
        self.0.wake.notify_one();
    }
}

/// Verified mutable records observed by the bounded actor query.
/// Network completion means this query's GET transaction received an accepted response.
#[derive(Clone, Debug)]
pub struct OwnedQueryCompletion {
    pub(crate) items: Arc<[MutableItem]>,
    pub(crate) network_completed: bool,
    pub(crate) result_lease: Option<Arc<ResultLease>>,
}

impl PartialEq for OwnedQueryCompletion {
    fn eq(&self, other: &Self) -> bool {
        self.items == other.items && self.network_completed == other.network_completed
    }
}

impl OwnedQueryCompletion {
    /// Return the verified mutable records observed by this query.
    pub fn items(&self) -> &[MutableItem] {
        &self.items[..]
    }

    /// Whether the socket accepted a response or error for this query's GET transaction.
    /// This does not imply that records were found or that every request succeeded.
    pub fn network_completed(&self) -> bool {
        self.network_completed
    }
}
