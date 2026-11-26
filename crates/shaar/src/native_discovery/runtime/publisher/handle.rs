// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use iroh_base::TransportAddr;
use tokio::sync::{mpsc, oneshot};

use super::super::owner::{Command, PUBLISH_BOUND, RuntimeError, bounded_replace};
use super::super::publisher::{PublicationStatus, PublishError};

#[derive(Clone)]
pub(crate) struct PublicationHandle {
    pub(super) commands: mpsc::Sender<Command>,
    pub(super) clock_fault: Arc<AtomicBool>,
}

impl PublicationHandle {
    /// cancel-safe: NO — queue admission can precede response delivery; publisher retains cleanup.
    pub(crate) async fn replace_with_admission(
        &self,
        snapshot: Vec<TransportAddr>,
        admitted: oneshot::Sender<()>,
    ) -> Result<(), RuntimeError> {
        self.replace_inner(
            snapshot,
            tokio::time::Instant::now() + PUBLISH_BOUND,
            Some(admitted),
        )
        .await
    }

    async fn replace_inner(
        &self,
        snapshot: Vec<TransportAddr>,
        deadline: tokio::time::Instant,
        admitted: Option<oneshot::Sender<()>>,
    ) -> Result<(), RuntimeError> {
        let result = self.send_replacement(snapshot, deadline, admitted).await;
        if matches!(
            result,
            Err(RuntimeError::Clock | RuntimeError::Publish(PublishError::ClockFault))
        ) {
            self.clock_fault.store(true, Ordering::Release);
        }
        result
    }

    async fn send_replacement(
        &self,
        snapshot: Vec<TransportAddr>,
        deadline: tokio::time::Instant,
        admitted: Option<oneshot::Sender<()>>,
    ) -> Result<(), RuntimeError> {
        if self.clock_fault.load(Ordering::Acquire) {
            return Err(RuntimeError::Publish(PublishError::ClockFault));
        }
        let (reply, response) = oneshot::channel();
        tokio::time::timeout_at(
            deadline,
            self.commands.send(Command::Replace(
                bounded_replace(snapshot),
                deadline,
                reply,
                admitted,
            )),
        )
        .await
        .map_err(|_| RuntimeError::DeadlineExceeded)?
        .map_err(|_| RuntimeError::Closed)?;
        let result = tokio::time::timeout_at(deadline, response)
            .await
            .map_err(|_| RuntimeError::DeadlineExceeded)?
            .map_err(|_| RuntimeError::Closed)?;
        if matches!(
            result,
            Err(RuntimeError::Clock | RuntimeError::Publish(PublishError::ClockFault))
        ) {
            self.clock_fault.store(true, Ordering::Release);
        }
        result
    }

    pub(crate) async fn query_publication_status(&self) -> Option<PublicationStatus> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::PublicationStatus(reply))
            .await
            .ok()?;
        response.await.ok()
    }
}
