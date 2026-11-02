// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::*;

impl Actor {
    pub(super) fn owned_failure(&self) -> Option<ResourceError> {
        let owner = self.owned_resources.as_ref()?;
        owner
            .terminal
            .or_else(|| self.socket.owned_failure())
            .or_else(|| owner.budget.peek_error())
            .or_else(|| {
                self.core
                    .iterative_queries
                    .values()
                    .find_map(|query| query.owner_error())
            })
            .or_else(|| {
                self.core
                    .put_queries
                    .values()
                    .find_map(|query| query.owner_error())
            })
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
        owner.operations.clear();
        owner.response_operations.clear();
        owner.maintenance_nodes.clear();
        self.core.iterative_queries.clear();
        self.core.put_queries.clear();
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
