// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::*;

impl Actor {
    pub(crate) fn owned_note_response(&mut self, transaction_id: u32) {
        if let Some((tid, operation)) = self.socket.owned_response_operation()
            && tid == transaction_id
        {
            if let Some(owner) = self.owned_resources.as_mut() {
                owner.response_operations.insert(operation);
            }
            for query in self.core.iterative_queries.values_mut() {
                if query.inflight(transaction_id) {
                    query.owned_note_network_response();
                    break;
                }
            }
        }
    }

    pub(crate) fn maintain_owned_admissions_at(&mut self, now: tokio::time::Instant) {
        if let Some(owner) = self.owned_resources.as_mut() {
            owner
                .maintenance_nodes
                .retain(|(_, tid, _, _)| self.socket.inflight(tid));
            owner.completions.retain(|target, waiters| {
                OwnedActor::prune_waiters(waiters, now);
                if waiters.is_empty()
                    && !self.core.put_queries.contains_key(target)
                    && *target != *self.core.routing_table.id()
                    && !self.get_senders.contains_key(target)
                {
                    if let Some(operation) = owner.operations.remove(target) {
                        self.socket.cancel_owned_operation(operation);
                        owner.response_operations.remove(&operation);
                    }
                    self.core.iterative_queries.remove(target);
                    false
                } else {
                    true
                }
            });
        }
        let admissions = self
            .owned_resources
            .as_mut()
            .map(|owner| std::mem::take(&mut owner.admissions))
            .unwrap_or_default();
        for request in admissions {
            self.admit_request_at(request, now);
        }
    }

    pub(crate) fn expire_owned_operations_at(&mut self, now: tokio::time::Instant) {
        let Some(owner) = self.owned_resources.as_ref() else {
            return;
        };
        let expired: Vec<OperationId> = owner
            .operations
            .values()
            .copied()
            .chain(owner.maintenance)
            .collect::<HashSet<_>>()
            .into_iter()
            .filter(|operation| {
                self.socket
                    .owned_deadline(*operation)
                    .is_some_and(|deadline| deadline <= now)
            })
            .collect();
        for operation in expired {
            let targets: Vec<Id> = self
                .owned_resources
                .as_ref()
                .expect("checked actor owner")
                .operations
                .iter()
                .filter_map(|(target, existing)| (*existing == operation).then_some(*target))
                .collect();
            self.socket.cancel_owned_operation(operation);
            let owner = self.owned_resources.as_mut().expect("checked actor owner");
            for target in targets {
                self.core.iterative_queries.remove(&target);
                self.core.put_queries.remove(&target);
                if let Some(senders) = self.put_senders.remove(&target) {
                    for sender in senders {
                        let _ = sender.send(Err(PutQueryError::Resource(
                            ResourceError::DeadlineExceeded,
                        )
                        .into()));
                    }
                }
                if let Some(waiters) = owner.completions.remove(&target) {
                    for waiter in waiters {
                        let _ = waiter.sender.send(Err(ResourceError::DeadlineExceeded));
                    }
                }
                owner.operations.remove(&target);
            }
            owner.response_operations.remove(&operation);
            if owner.maintenance == Some(operation) {
                owner.maintenance = None;
            }
            owner
                .maintenance_nodes
                .retain(|(_, tid, _, _)| self.socket.inflight(tid));
        }
    }

    pub(crate) fn owned_next_deadline(&self) -> Option<tokio::time::Instant> {
        let owner = self.owned_resources.as_ref()?;
        owner
            .operations
            .values()
            .copied()
            .chain(owner.maintenance)
            .filter_map(|operation| self.socket.owned_deadline(operation))
            .chain(
                owner
                    .completions
                    .values()
                    .flatten()
                    .map(|waiter| waiter.deadline),
            )
            .chain(owner.admissions.iter().map(|request| request.deadline))
            .chain(
                self.core
                    .iterative_queries
                    .values()
                    .filter_map(|query| query.owned_next_round()),
            )
            .chain(
                self.core
                    .put_queries
                    .values()
                    .filter_map(|query| query.owned_retry_at()),
            )
            .min()
    }
}
