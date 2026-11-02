// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::*;

impl Actor {
    pub(crate) fn tick_owned(&mut self) {
        self.expire_owned_operations_at(tokio::time::Instant::now());
        if let Some(error) = self.owned_failure() {
            self.owned_fail(error);
            return;
        }
        if self.owned_error().is_some() {
            return;
        }
        self.maintain_owned_admissions_at(tokio::time::Instant::now());
        self.periodic_node_maintaenance();
        if let Some(error) = self.owned_failure() {
            self.owned_fail(error);
            return;
        }
        for query in self.core.iterative_queries.values_mut() {
            query.visit_closest(&mut self.socket);
        }
        self.expire_owned_operations_at(tokio::time::Instant::now());
        if let Some(error) = self.owned_failure() {
            self.owned_fail(error);
            return;
        }
        self.socket.maintain_owned_requests();
        if let Some(error) = self.owned_failure() {
            self.owned_fail(error);
            return;
        }

        let done: Vec<Id> = self
            .core
            .iterative_queries
            .iter()
            .filter_map(|(id, query)| query.is_done(&self.socket).then_some(*id))
            .collect();
        for target in done {
            if self.get_senders.contains_key(&target) {
                self.owned_fail(ResourceError::NotOwnedProfile);
                return;
            }
            let Some(operation) = self
                .owned_resources
                .as_ref()
                .and_then(|owner| owner.operations.get(&target).copied())
            else {
                self.owned_fail(ResourceError::RpcLimit);
                return;
            };
            if let Some(error) = self.owned_failure() {
                self.owned_fail(error);
                return;
            }
            let pending_put = self.core.put_queries.contains_key(&target);
            let leases = if pending_put {
                let count = self
                    .core
                    .iterative_queries
                    .get(&target)
                    .map_or(0, |query| query.responders().len());
                let budget = Arc::clone(
                    &self
                        .owned_resources
                        .as_ref()
                        .expect("owned actor initialized")
                        .budget,
                );
                let mut leases = Vec::with_capacity(count);
                for _ in 0..count {
                    if let Some(error) = self.owned_failure() {
                        self.owned_fail(error);
                        return;
                    }
                    match budget.reserve_holder() {
                        Ok(lease) => leases.push(lease),
                        Err(error) => {
                            self.owned_fail(error);
                            return;
                        }
                    }
                }
                leases
            } else {
                Vec::new()
            };
            let mut query = self
                .core
                .iterative_queries
                .remove(&target)
                .expect("completed query retained");
            if pending_put {
                if let Some(error) = self.owned_failure() {
                    self.owned_fail(error);
                    return;
                }
                let closest = self.core.closest_nodes_from_done_iterative_query(&query);
                #[cfg(test)]
                if self
                    .owned_resources
                    .as_mut()
                    .expect("owned actor initialized")
                    .put_start_deadline_operation
                    .take()
                    == Some(operation)
                {
                    self.socket
                        .register_owned_deadline(operation, tokio::time::Instant::now())
                        .expect("cross PUT-start deadline after expiry sweep");
                }
                let start_result = self
                    .core
                    .put_queries
                    .get_mut(&target)
                    .expect("pending PUT retained")
                    .start(&mut self.socket, &closest);
                drop(closest);
                if let Err(error) = start_result {
                    let resource_error = self
                        .core
                        .put_queries
                        .get(&target)
                        .and_then(|put| put.owner_error());
                    if let Some(put) = self.core.put_queries.get(&target) {
                        self.socket
                            .cancel_owned_transactions(&put.transaction_ids().to_vec());
                    }
                    if let Some(error) = resource_error {
                        if error == ResourceError::DeadlineExceeded {
                            self.expire_owned_operations_at(tokio::time::Instant::now());
                            continue;
                        }
                        self.owned_fail(error);
                        return;
                    }
                    self.core.put_queries.remove(&target);
                    if let Some(senders) = self.put_senders.remove(&target) {
                        for sender in senders {
                            let _ = sender.send(Err(error.clone()));
                        }
                    }
                }
                if let Some(error) = self.owned_failure() {
                    self.owned_fail(error);
                    return;
                }
            }
            let items: Arc<[crate::MutableItem]> = query
                .take_owned_responses()
                .into_iter()
                .filter_map(|response| match response {
                    crate::core::Response::Mutable(item) => Some(item),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .into();
            let network_completed = query.owned_network_completed();
            if let Some(owner) = self.owned_resources.as_mut() {
                owner.response_operations.remove(&operation);
                if let Some(waiters) = owner.completions.remove(&target) {
                    for waiter in waiters {
                        let now = tokio::time::Instant::now();
                        let result = if now < waiter.deadline
                            && self
                                .socket
                                .owned_deadline(operation)
                                .is_none_or(|deadline| now < deadline)
                        {
                            Ok(OwnedQueryCompletion {
                                items: Arc::clone(&items),
                                network_completed,
                                result_lease: Some(Arc::clone(&waiter.lease)),
                            })
                        } else {
                            Err(ResourceError::DeadlineExceeded)
                        };
                        let _ = waiter.sender.send(result);
                    }
                }
                if !self.core.put_queries.contains_key(&target) {
                    owner.operations.remove(&target);
                    if owner.maintenance != Some(operation) {
                        self.socket.retire_owned_deadline(operation);
                    } else {
                        owner.maintenance_retry_at = self.socket.owned_deadline(operation);
                    }
                }
            }
            drop(query);
            drop(leases);
        }
        let now = tokio::time::Instant::now();
        let mut retry_deadline = false;
        let mut retry_error = None;
        for query in self.core.put_queries.values_mut() {
            if query.owned_retry_at().is_some() {
                if let Err(error) = query.retry_owned_at(&mut self.socket, now) {
                    match error {
                        PutError::Query(PutQueryError::Resource(
                            ResourceError::DeadlineExceeded,
                        )) => {
                            retry_deadline = true;
                        }
                        PutError::Query(PutQueryError::Resource(error)) => {
                            retry_error = Some(error);
                        }
                        _ => retry_error = Some(ResourceError::RpcLimit),
                    }
                }
            } else {
                query.schedule_owned_retry(&self.socket, now);
            }
        }
        if retry_deadline {
            self.expire_owned_operations_at(now);
        }
        if let Some(error) = retry_error {
            self.owned_fail(error);
            return;
        }
        let done_put: Vec<(Id, Result<bool, PutError>, Vec<u32>)> = self
            .core
            .put_queries
            .iter()
            .filter_map(|(id, query)| {
                if query.owned_retry_at().is_some() {
                    return None;
                }
                match query.check(&self.socket) {
                    Ok(true) => Some((*id, Ok(true), query.transaction_ids().to_vec())),
                    Err(error) => Some((*id, Err(error), query.transaction_ids().to_vec())),
                    _ => None,
                }
            })
            .collect();
        for (target, result, tids) in done_put {
            self.socket.cancel_owned_transactions(&tids);
            self.core.put_queries.remove(&target);
            if let Some(senders) = self.put_senders.remove(&target) {
                let result = match result {
                    Ok(_)
                        if self
                            .owned_resources
                            .as_ref()
                            .and_then(|owner| owner.operations.get(&target))
                            .and_then(|operation| self.socket.owned_deadline(*operation))
                            .is_some_and(|deadline| tokio::time::Instant::now() >= deadline) =>
                    {
                        Err(PutError::Query(PutQueryError::Resource(
                            ResourceError::DeadlineExceeded,
                        )))
                    }
                    Ok(_) => Ok(target),
                    Err(error) => Err(error),
                };
                for sender in senders {
                    let _ = sender.send(result.clone());
                }
            }
            let has_get = self.core.iterative_queries.contains_key(&target);
            if !has_get {
                if let Some(owner) = self.owned_resources.as_mut() {
                    if let Some(operation) = owner.operations.remove(&target) {
                        owner.response_operations.remove(&operation);
                        self.socket.retire_owned_deadline(operation);
                    }
                }
            }
        }
        if let Some(error) = self.owned_failure() {
            self.owned_fail(error);
        }
    }
}
