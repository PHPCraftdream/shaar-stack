// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use crate::MutableItem;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Notify;

const RESULT_LIMIT: usize = 8;
const REQUEST_LIMIT: usize = 24;

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
    }
}

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

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

#[derive(Debug, Default)]
pub(crate) struct ResultBudget(AtomicUsize);

impl ResultBudget {
    pub(crate) fn acquire(self: &Arc<Self>) -> Option<Arc<ResultLease>> {
        let mut current = self.0.load(Ordering::Relaxed);
        loop {
            if current >= RESULT_LIMIT {
                return None;
            }
            match self.0.compare_exchange_weak(
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
        self.0.0.fetch_sub(1, Ordering::AcqRel);
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
