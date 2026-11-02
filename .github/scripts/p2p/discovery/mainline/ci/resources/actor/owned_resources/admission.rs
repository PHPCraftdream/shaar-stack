// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::*;

impl Actor {
    pub(crate) fn owned_admission_until(
        &mut self,
        target: Id,
        sender: tokio::sync::oneshot::Sender<RequestReply>,
        deadline: tokio::time::Instant,
        request_lease: Arc<RequestLease>,
    ) {
        if let Some(error) = self.owned_error() {
            let _ = sender.send(RequestReply::Error(error));
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            let _ = sender.send(RequestReply::Error(ResourceError::DeadlineExceeded));
            return;
        }
        self.admit_request(PendingAdmission {
            target,
            sender,
            deadline,
            request_lease,
        });
    }

    fn admit_request(&mut self, request: PendingAdmission) {
        self.admit_request_at(request, tokio::time::Instant::now());
    }

    pub(super) fn admit_request_at(
        &mut self,
        request: PendingAdmission,
        now: tokio::time::Instant,
    ) {
        let PendingAdmission {
            target,
            sender,
            deadline,
            request_lease,
        } = request;
        if sender.is_closed() {
            return;
        }
        if now >= deadline {
            let _ = sender.send(RequestReply::Error(ResourceError::DeadlineExceeded));
            return;
        }
        let Some(owner) = self.owned_resources.as_ref() else {
            let _ = sender.send(RequestReply::Error(ResourceError::NotOwnedProfile));
            return;
        };
        if let Some(error) = owner.terminal {
            let _ = sender.send(RequestReply::Error(error));
            return;
        }
        for waiters in self
            .owned_resources
            .as_mut()
            .expect("owned actor initialized")
            .completions
            .values_mut()
        {
            OwnedActor::prune_waiters(waiters, now);
        }
        let Some(lease) = self
            .owned_resources
            .as_ref()
            .expect("owned actor initialized")
            .result_budget
            .acquire()
        else {
            self.owned_resources
                .as_mut()
                .expect("owned actor initialized")
                .enqueue_admission(target, sender, deadline, request_lease);
            return;
        };
        let request = GetRequestSpecific::GetValue(crate::common::GetValueRequestArguments {
            target,
            seq: None,
            salt: None,
        });
        match self.owned_get_until(request, None, deadline) {
            Err(ResourceError::OperationLimit) => {
                drop(lease);
                self.owned_resources
                    .as_mut()
                    .expect("owned actor initialized")
                    .enqueue_admission(target, sender, deadline, request_lease);
            }
            Err(error) => {
                let _ = sender.send(RequestReply::Error(error));
            }
            Ok(_) => {
                let (result_sender, result_receiver) = tokio::sync::oneshot::channel();
                self.owned_resources
                    .as_mut()
                    .expect("owned actor initialized")
                    .completions
                    .entry(target)
                    .or_default()
                    .push(OwnedWaiter {
                        sender: result_sender,
                        deadline,
                        lease: Arc::clone(&lease),
                        request_lease: Some(request_lease),
                    });
                let _ = sender.send(RequestReply::Ready(
                    crate::resource::ChargedResultReceiver::new(result_receiver, lease),
                ));
            }
        }
    }

    pub(crate) fn owned_mutable(
        &mut self,
        target: Id,
        sender: tokio::sync::oneshot::Sender<Result<OwnedQueryCompletion, ResourceError>>,
    ) -> Result<(), ResourceError> {
        self.owned_mutable_until(
            target,
            sender,
            tokio::time::Instant::now() + std::time::Duration::from_secs(10),
        )
    }

    pub(crate) fn owned_mutable_until(
        &mut self,
        target: Id,
        sender: tokio::sync::oneshot::Sender<Result<OwnedQueryCompletion, ResourceError>>,
        deadline: tokio::time::Instant,
    ) -> Result<(), ResourceError> {
        if sender.is_closed() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            let _ = sender.send(Err(ResourceError::DeadlineExceeded));
            return Ok(());
        }
        if let Some(owner) = self.owned_resources.as_mut() {
            for waiters in owner.completions.values_mut() {
                OwnedActor::prune_waiters(waiters, tokio::time::Instant::now());
            }
        }
        let lease = if let Some(owner) = self.owned_resources.as_ref() {
            match owner.result_budget.acquire() {
                Some(lease) => lease,
                None => {
                    let _ = sender.send(Err(ResourceError::ResultLimit));
                    return Ok(());
                }
            }
        } else {
            return Err(ResourceError::NotOwnedProfile);
        };
        let waiter = OwnedWaiter {
            sender,
            deadline,
            lease,
            request_lease: None,
        };
        if let Some(error) = self.owned_error() {
            let _ = waiter.sender.send(Err(error));
            return Err(error);
        }
        let request = GetRequestSpecific::GetValue(crate::common::GetValueRequestArguments {
            target,
            seq: None,
            salt: None,
        });
        match self.owned_get_until(request, None, deadline) {
            Ok(_) => self
                .owned_resources
                .as_mut()
                .expect("owned actor initialized")
                .completions
                .entry(target)
                .or_default()
                .push(waiter),
            Err(ResourceError::OperationLimit) => {
                let OwnedWaiter { sender, lease, .. } = waiter;
                drop(lease);
                let _ = sender.send(Err(ResourceError::OperationLimit));
                return Err(ResourceError::OperationLimit);
            }
            Err(error) => {
                let _ = waiter.sender.send(Err(error));
                return Err(error);
            }
        }
        Ok(())
    }
}
