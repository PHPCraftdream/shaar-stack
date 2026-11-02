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
}

impl OwnedDhtHandle {
    fn failure(&self) -> ResourceError {
        self.failure
            .get()
            .copied()
            .unwrap_or(ResourceError::QueryCancelled)
    }

    /// Resolve a mutable target and return its network-completion receipt.
    pub async fn resolve_mutable(
        &self,
        target: crate::Id,
    ) -> Result<OwnedQueryCompletion, ResourceError> {
        if let Some(error) = self.failure.get() {
            return Err(*error);
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
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
        let (sender, receiver) = mpsc::channel(16);
        let (stop, stop_receiver) = oneshot::channel();
        let join = tokio::spawn(actor::run_owned(actor, receiver, stop_receiver));
        Self {
            handle: OwnedDhtHandle {
                sender,
                failure,
                request_budget,
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
