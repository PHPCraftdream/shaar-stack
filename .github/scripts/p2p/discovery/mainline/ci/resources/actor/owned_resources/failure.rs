// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::*;

impl Actor {
    pub(super) fn owned_failure(&self) -> Option<ResourceError> {
        let owner = self.owned_resources.as_ref()?;
        owner.terminal.or_else(|| self.socket.owned_failure())
    }

    pub(crate) fn retire_owned_operation_errors(&mut self) {
        let mut errors = self.socket.take_owned_operation_errors();

        for (target, query) in &self.core.iterative_queries {
            if let Some(error) = query.owner_error() {
                if let Some(operation) = self
                    .owned_resources
                    .as_ref()
                    .and_then(|owner| owner.operations.get(target).copied())
                {
                    errors.push((operation, error));
                }
            }
        }

        for (target, query) in &self.core.put_queries {
            if let Some(error) = query.owner_error() {
                if let Some(operation) = self
                    .owned_resources
                    .as_ref()
                    .and_then(|owner| owner.operations.get(target).copied())
                {
                    errors.push((operation, error));
                }
            }
        }

        for (operation, error) in errors {
            if matches!(error, ResourceError::NotOwnedProfile | ResourceError::TransactionSpaceExhausted) {
                self.owned_fail(error);
                return;
            }

            let owned = self.owned_resources.as_ref().is_some_and(|owner| {
                owner
                    .operations
                    .values()
                    .any(|candidate| *candidate == operation)
                    || owner.maintenance == Some(operation)
                    || owner
                        .active_puts
                        .values()
                        .any(|active| active.operation == operation)
            });

            if owned {
                self.fail_owned_operation(operation, error);
            }
        }
    }

    pub(crate) fn fail_owned_operation(
        &mut self,
        operation: OperationId,
        error: ResourceError,
    ) {
        self.socket.cancel_owned_operation(operation);

        let targets = self
            .owned_resources
            .as_ref()
            .map(|owner| {
                owner
                    .operations
                    .iter()
                    .filter_map(|(target, candidate)| {
                        (*candidate == operation).then_some(*target)
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        for target in targets {
            let has_active = self.owned_resources.as_ref().is_some_and(|owner| {
                owner.active_puts.contains_key(&target)
            });

            if !has_active {
                self.core.iterative_queries.remove(&target);
                self.core.put_queries.remove(&target);
            }

            if let Some(owner) = self.owned_resources.as_mut() {
                if !has_active {
                    owner.operations.remove(&target);
                }
                owner.response_operations.remove(&operation);
                if let Some(waiters) = owner.completions.remove(&target) {
                    for waiter in waiters {
                        let _ = waiter.sender.send(Err(error));
                    }
                }
            }

            if let Some(senders) = self.put_senders.remove(&target) {
                for sender in senders {
                    let _ = sender.send(Err(PutQueryError::Resource(error).into()));
                }
            }

            if !has_active {
                self.socket.retire_owned_put_deadline(target);
            }
        }

        if let Some(owner) = self.owned_resources.as_mut() {
            owner.response_operations.remove(&operation);

            if owner.maintenance == Some(operation) {
                owner.maintenance = None;
                owner.maintenance_nodes.clear();
            }
        }

        let active_target = self.owned_resources.as_ref().and_then(|owner| {
            owner.active_puts.iter().find_map(|(target, active)| {
                (active.operation == operation).then_some(*target)
            })
        });
        if let Some(target) = active_target {
            let held = self.owned_resources.as_ref().is_some_and(|owner| {
                owner.publication_observer.cleanup_is_held_for(target)
            });
            if held {
                if let Some(active) = self
                    .owned_resources
                    .as_mut()
                    .and_then(|owner| owner.active_puts.get_mut(&target))
                {
                    active.pending_error.get_or_insert(error);
                }
                if let Some(put) = self.core.put_queries.remove(&target) {
                    self.socket.cancel_owned_transactions(&put.transaction_ids().to_vec());
                }
                let shared_get = self.owned_resources.as_ref().is_some_and(|owner| {
                    owner
                        .completions
                        .get(&target)
                        .is_some_and(|waiters| !waiters.is_empty())
                });
                if !shared_get {
                    self.core.iterative_queries.remove(&target);
                    self.socket.retire_owned_deadline(operation);
                }
                if let Some(owner) = self.owned_resources.as_ref() {
                    owner.publication_observer.note_cleanup_entered(target);
                }
                return;
            }
            if let Some(active) = self
                .owned_resources
                .as_mut()
                .and_then(|owner| owner.active_puts.remove(&target))
            {
                self.core.iterative_queries.remove(&target);
                self.core.put_queries.remove(&target);
                if let Some(owner) = self.owned_resources.as_mut() {
                    owner.operations.remove(&target);
                    owner.response_operations.remove(&operation);
                }
                self.socket.retire_owned_put_deadline(target);
                let _ = active
                    .result
                    .send(Err(crate::resource::OwnedPutError::Resource(error)));
                drop(active.request_lease);
                drop(active.result_lease);
                let _ = active.cleanup.send(());
            }
        }
    }

    pub(crate) fn owned_fail(&mut self, error: ResourceError) {
        let Some(owner) = self.owned_resources.as_mut() else {
            return;
        };
        let first = *owner.terminal.get_or_insert(error);
        let _ = owner.failure_status.set(first);

        for (_, waiters) in owner.completions.drain() {
            for waiter in waiters {
                let _ = waiter.sender.send(Err(first));
            }
        }

        for request in owner.pending.drain(..) {
            let _ = request.sender.send(Err(first));
        }

        for request in owner.admissions.drain(..) {
            let _ = request.sender.send(RequestReply::Error(first));
        }

        for request in owner.put_admissions.drain(..) {
            let PendingPut {
                request,
                request_lease,
                reply,
                cleanup,
                ..
            } = request;
            drop(request);
            drop(request_lease);
            let _ = reply.send(Err(first));
            let _ = cleanup.send(());
        }

        for operation in owner.operations.values().copied().collect::<Vec<_>>() {
            self.socket.cancel_owned_operation(operation);
        }

        if let Some(operation) = owner.maintenance {
            self.socket.cancel_owned_operation(operation);
        }

        for (_, senders) in self.put_senders.drain() {
            for sender in senders {
                let _ = sender.send(Err(PutQueryError::Resource(first).into()));
            }
        }
        self.get_senders.clear();

        let mut targets = owner.operations.keys().copied().collect::<HashSet<Id>>();
        targets.extend(self.core.put_queries.keys().copied());
        targets.extend(owner.active_puts.keys().copied());

        for target in targets {
            if owner.active_puts.contains_key(&target) {
                continue;
            }

            owner.operations.remove(&target);
            self.socket.retire_owned_put_deadline(target);
        }
        owner.maintenance = None;
        owner.response_operations.clear();
        owner.maintenance_nodes.clear();
        self.core.iterative_queries.clear();
        self.core.put_queries.clear();

        for target in owner.active_puts.keys().copied().collect::<Vec<_>>() {
            let held = owner.publication_observer.cleanup_is_held_for(target);
            if held {
                if let Some(active) = owner.active_puts.get_mut(&target) {
                    active.pending_error.get_or_insert(first);
                }
                owner.publication_observer.note_cleanup_entered(target);
            } else if let Some(active) = owner.active_puts.remove(&target) {
                owner.operations.remove(&target);
                self.socket.retire_owned_put_deadline(target);
                let _ = active
                    .result
                    .send(Err(crate::resource::OwnedPutError::Resource(first)));
                drop(active.request_lease);
                drop(active.result_lease);
                let _ = active.cleanup.send(());
            }
        }

        self.core.cached_iterative_queries.clear();
        self.core.routing_table = crate::common::RoutingTable::new(*self.core.routing_table.id());
        self.core.signed_peers_routing_table =
            crate::common::RoutingTable::new(*self.core.signed_peers_routing_table.id());
    }

    pub(crate) fn owned_error(&self) -> Option<ResourceError> {
        self.owned_resources
            .as_ref()
            .and_then(|owner| owner.terminal)
    }
}
