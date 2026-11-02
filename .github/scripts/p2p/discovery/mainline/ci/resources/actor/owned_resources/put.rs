// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::*;

impl Actor {
    pub(crate) fn owned_put_admission_until(
        &mut self,
        target: Id,
        item: crate::MutableItem,
        reply: tokio::sync::oneshot::Sender<
            Result<crate::resource::ChargedPutReceiver, ResourceError>,
        >,
        cleanup: tokio::sync::oneshot::Sender<()>,
        mut cancel: tokio::sync::oneshot::Receiver<()>,
        deadline: tokio::time::Instant,
        request_lease: Arc<RequestLease>,
    ) {
        let Some(owner) = self.owned_resources.as_ref() else {
            drop(item);
            drop(request_lease);
            let _ = reply.send(Err(ResourceError::NotOwnedProfile));
            let _ = cleanup.send(());
            return;
        };
        let canceled = match cancel.try_recv() {
            Ok(()) | Err(tokio::sync::oneshot::error::TryRecvError::Closed) => true,
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => false,
        };
        let early_error = owner.terminal.or_else(|| {
            if reply.is_closed() || canceled {
                Some(ResourceError::QueryCancelled)
            } else if tokio::time::Instant::now() >= deadline {
                Some(ResourceError::DeadlineExceeded)
            } else if owner.pending.len() + owner.admissions.len() + owner.put_admissions.len() >= 16 {
                Some(ResourceError::OperationLimit)
            } else if owner.active_puts.contains_key(&target)
                || owner.put_admissions.iter().any(|pending| pending.target == target)
            {
                Some(ResourceError::OperationLimit)
            } else {
                None
            }
        });
        if let Some(error) = early_error {
            drop(item);
            drop(request_lease);
            let _ = reply.send(Err(error));
            let _ = cleanup.send(());
            return;
        }
        self.owned_resources
            .as_mut()
            .expect("owned actor initialized")
            .put_admissions
            .push_back(PendingPut {
                target,
                request: crate::common::PutMutableRequestArguments::from(item, None),
                reply,
                cleanup,
                cancel,
                request_lease,
                deadline,
            });
    }

    pub(crate) fn owned_finish_put(
        &mut self,
        target: Id,
        result: Result<(), PutError>,
        tids: Vec<u32>,
    ) {
        let Some(active) = self
            .owned_resources
            .as_mut()
            .and_then(|owner| owner.active_puts.remove(&target))
        else {
            return;
        };
        let operation = active.operation;
        let owner = self.owned_resources.as_mut().expect("active PUT owner exists");
        let has_get = self.core.iterative_queries.contains_key(&target)
            || owner.completions.get(&target).is_some_and(|waiters| !waiters.is_empty());
        if !has_get && owner.maintenance != Some(operation) {
            owner.operations.remove(&target);
            owner.response_operations.remove(&operation);
            self.socket.cancel_owned_operation(operation);
        }
        drop(active.request_lease);
        let result = if result.is_ok() && tokio::time::Instant::now() >= active.deadline {
            Err(crate::resource::OwnedPutError::Resource(
                ResourceError::DeadlineExceeded,
            ))
        } else {
            result.map_err(crate::resource::OwnedPutError::Put)
        };
        let completion = result.and_then(|()| {
            Ok(crate::resource::OwnedPutCompletion::new(
                target,
                active.operation,
                tids,
                Arc::clone(&active.result_lease),
            ))
        });
        let _ = active.result.send(completion);
        drop(active.result_lease);
        let _ = active.cleanup.send(());
    }

    pub(crate) fn maintain_owned_puts_at(&mut self, now: tokio::time::Instant) {
        let Some(owner) = self.owned_resources.as_mut() else {
            return;
        };
        let mut queued = std::mem::take(&mut owner.put_admissions);
        let mut retry = VecDeque::new();

        while let Some(mut put) = queued.pop_front() {
            let canceled = put.reply.is_closed()
                || match put.cancel.try_recv() {
                    Ok(()) | Err(tokio::sync::oneshot::error::TryRecvError::Closed) => true,
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty) => false,
                };
            if canceled || now >= put.deadline {
                let error = if now >= put.deadline {
                    ResourceError::DeadlineExceeded
                } else {
                    ResourceError::QueryCancelled
                };
                drop(put.request);
                drop(put.request_lease);
                let _ = put.reply.send(Err(error));
                let _ = put.cleanup.send(());
                continue;
            }

            // A legacy core PUT owns this target already. Keep the admission queued
            // until that query is gone; do not spend a result lease or allocate a
            // second operation while waiting.
            if self.core.put_queries.contains_key(&put.target) {
                retry.push_back(put);
                continue;
            }

            let owner = self.owned_resources.as_ref().expect("owner checked");
            let charged = owner.operations.values().copied().collect::<HashSet<_>>();
            let total = charged.len()
                + usize::from(owner.maintenance.is_some_and(|id| !charged.contains(&id)));
            if !owner.operations.contains_key(&put.target) && total >= 8 {
                retry.push_back(put);
                continue;
            }

            let Some(lease) = self
                .owned_resources
                .as_ref()
                .expect("owner checked")
                .result_budget
                .acquire()
            else {
                retry.push_back(put);
                continue;
            };
            let operation = match self
                .owned_resources
                .as_mut()
                .expect("owner checked")
                .operation_for(put.target, &mut self.socket, put.deadline)
            {
                Ok(operation) => operation,
                Err(ResourceError::OperationLimit) => {
                    drop(lease);
                    retry.push_back(put);
                    continue;
                }
                Err(error) => {
                    drop(lease);
                    drop(put.request);
                    drop(put.request_lease);
                    let _ = put.reply.send(Err(error));
                    let _ = put.cleanup.send(());
                    continue;
                }
            };
            let (result_tx, result_rx) = tokio::sync::oneshot::channel();
            let request = crate::common::PutRequestSpecific::PutMutable(put.request);
            if let Err(error) = self.owned_put_until(request, None, put.deadline) {
                let typed = match error {
                    PutError::Query(PutQueryError::Resource(resource)) => {
                        crate::resource::OwnedPutError::Resource(resource)
                    }
                    other => crate::resource::OwnedPutError::Put(other),
                };
                let _ = result_tx.send(Err(typed));
                drop(put.request_lease);
                let _ = put
                    .reply
                    .send(Ok(crate::resource::ChargedPutReceiver::new(
                        result_rx, lease,
                    )));

                // Retire only a newly allocated operation which did not acquire
                // query/PUT ownership. A shared GET or maintenance operation must
                // remain alive for its other owner.
                let owner = self.owned_resources.as_mut().expect("owner checked");
                let has_iterative_query = self.core.iterative_queries.contains_key(&put.target);
                let has_put_query = self.core.put_queries.contains_key(&put.target);
                let is_maintenance = owner.maintenance == Some(operation);
                let has_shared_get = owner
                    .completions
                    .get(&put.target)
                    .is_some_and(|waiters| !waiters.is_empty());
                if !has_iterative_query && !has_put_query && !is_maintenance && !has_shared_get {
                    self.socket.cancel_owned_operation(operation);
                    owner.operations.remove(&put.target);
                    owner.response_operations.remove(&operation);
                    self.socket.retire_owned_deadline(operation);
                }
                let _ = put.cleanup.send(());
                continue;
            }

            let active = ActivePut {
                operation,
                result: result_tx,
                cleanup: put.cleanup,
                cancel: put.cancel,
                result_lease: Arc::clone(&lease),
                request_lease: put.request_lease,
                deadline: put.deadline,
            };
            self.owned_resources
                .as_mut()
                .expect("owner checked")
                .active_puts
                .insert(put.target, active);
            let _ = put
                .reply
                .send(Ok(crate::resource::ChargedPutReceiver::new(
                    result_rx, lease,
                )));
        }
        self.owned_resources
            .as_mut()
            .expect("owner checked")
            .put_admissions = retry;

        let targets: Vec<Id> = self
            .owned_resources
            .as_mut()
            .expect("owner checked")
            .active_puts
            .iter_mut()
            .filter_map(|(target, active)| {
                let canceled = match active.cancel.try_recv() {
                    Ok(()) | Err(tokio::sync::oneshot::error::TryRecvError::Closed) => true,
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty) => false,
                };
                (active.result.is_closed() || now >= active.deadline || canceled)
                    .then_some(*target)
            })
            .collect();

        for target in targets {
            let Some(active) = self
                .owned_resources
                .as_mut()
                .expect("owner checked")
                .active_puts
                .remove(&target)
            else {
                continue;
            };
            let tids = self
                .core
                .put_queries
                .remove(&target)
                .map(|put| put.transaction_ids().to_vec())
                .unwrap_or_default();
            self.socket.cancel_owned_transactions(&tids);
            let owner = self.owned_resources.as_mut().expect("owner checked");
            let shared_get = owner
                .completions
                .get(&target)
                .is_some_and(|waiters| !waiters.is_empty());
            if !shared_get && owner.maintenance != Some(active.operation) {
                self.core.iterative_queries.remove(&target);
                self.socket.cancel_owned_operation(active.operation);
                owner.operations.remove(&target);
                owner.response_operations.remove(&active.operation);
                self.socket.retire_owned_deadline(active.operation);
            }
            let error = if now >= active.deadline {
                ResourceError::DeadlineExceeded
            } else {
                ResourceError::QueryCancelled
            };
            let _ = active.result.send(Err(crate::resource::OwnedPutError::Resource(error)));
            drop(active.request_lease);
            drop(active.result_lease);
            let _ = active.cleanup.send(());
        }
    }
}
