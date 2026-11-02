// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::*;

impl Actor {
    pub(crate) fn owned_get(
        &mut self,
        request: GetRequestSpecific,
        extra_nodes: Option<&[SocketAddrV4]>,
    ) -> Result<Vec<crate::core::Response>, ResourceError> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        self.owned_get_until(request, extra_nodes, deadline)
    }

    pub(crate) fn owned_get_until(
        &mut self,
        request: GetRequestSpecific,
        extra_nodes: Option<&[SocketAddrV4]>,
        deadline: tokio::time::Instant,
    ) -> Result<Vec<crate::core::Response>, ResourceError> {
        if tokio::time::Instant::now() >= deadline {
            return Err(ResourceError::DeadlineExceeded);
        }
        let target = request.target();
        if let Some(error) = self
            .owned_resources
            .as_ref()
            .ok_or(ResourceError::NotOwnedProfile)?
            .terminal
        {
            return Err(error);
        }
        if let Some(query) = self.core.iterative_queries.get(&target) {
            if let Some(error) = query.owner_error() {
                return Err(error);
            }
            return Ok(Vec::new());
        }
        let requester = *self.core.routing_table.id();
        let operation = {
            let owner = self
                .owned_resources
                .as_mut()
                .expect("owned actor initialized");
            if target == requester {
                owner.maintenance_operation(&mut self.socket, deadline)?
            } else {
                owner.operation_for(target, &mut self.socket, deadline)?
            }
        };
        if self.socket.owned_get_rounds(operation) >= 3 {
            return Err(ResourceError::DeadlineExceeded);
        }
        self.owned_resources
            .as_mut()
            .expect("owned actor initialized")
            .operations
            .insert(target, operation);
        let budget = Arc::clone(
            &self
                .owned_resources
                .as_ref()
                .expect("owned actor initialized")
                .budget,
        );
        let mut query = IterativeQuery::new(requester, target, request);
        query.enable_owned(operation, budget);
        match query.request.request_type {
            RequestTypeSpecific::FindNode(_) => {
                for node in self
                    .core
                    .routing_table
                    .nodes()
                    .chain(self.core.signed_peers_routing_table.nodes())
                {
                    query.add_candidate(node);
                    if query.owner_error().is_some() {
                        break;
                    }
                }
            }
            RequestTypeSpecific::GetSignedPeers(_) => {
                for node in self.core.signed_peers_routing_table.nodes() {
                    query.add_candidate(node);
                    if query.owner_error().is_some() {
                        break;
                    }
                }
            }
            _ => {
                for node in self.core.routing_table.nodes() {
                    query.add_candidate(node);
                    if query.owner_error().is_some() {
                        break;
                    }
                }
            }
        }
        if let Some(error) = query.owner_error() {
            self.socket.cancel_owned_operation(operation);
            self.owned_resources
                .as_mut()
                .expect("owned actor initialized")
                .operations
                .remove(&target);
            return Err(error);
        }
        let bootstrap_needed =
            query.closest().is_empty() || query.closest().len() < self.core.bootstrap.len();
        for address in query.closest_candidates() {
            query.visit(&mut self.socket, address);
            if query.owner_error().is_some() {
                break;
            }
        }
        if query.owner_error().is_none() && bootstrap_needed {
            for address in self.core.bootstrap.iter().copied() {
                query.visit(&mut self.socket, address);
                if query.owner_error().is_some() {
                    break;
                }
            }
        }
        if query.owner_error().is_none() {
            if let Some(extra) = extra_nodes {
                for address in extra.iter().copied() {
                    query.visit(&mut self.socket, address);
                    if query.owner_error().is_some() {
                        break;
                    }
                }
            }
        }
        if let Some(error) = query.owner_error() {
            self.socket.cancel_owned_operation(operation);
            self.owned_resources
                .as_mut()
                .expect("owned actor initialized")
                .operations
                .remove(&target);
            return Err(error);
        }
        self.core.iterative_queries.insert(target, query);
        Ok(Vec::new())
    }

    pub(crate) fn owned_put(
        &mut self,
        request: crate::common::PutRequestSpecific,
        extra_nodes: Option<Box<[Node]>>,
    ) -> Result<(), PutError> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        self.owned_put_until(request, extra_nodes, deadline)
    }

    pub(crate) fn owned_put_until(
        &mut self,
        request: crate::common::PutRequestSpecific,
        extra_nodes: Option<Box<[Node]>>,
        deadline: tokio::time::Instant,
    ) -> Result<(), PutError> {
        if tokio::time::Instant::now() >= deadline {
            return Err(PutQueryError::Resource(ResourceError::DeadlineExceeded).into());
        }
        let target = *request.target();
        let had_put = self.core.put_queries.contains_key(&target);
        let previous = self
            .owned_resources
            .as_ref()
            .and_then(|owner| owner.operations.get(&target).copied());
        self.core.check_concurrency_errors(&request)?;
        if self.core.put_queries.contains_key(&target) {
            return Ok(());
        }
        if had_put {
            if let Some(operation) = previous {
                self.socket.cancel_owned_operation(operation);
                self.core.iterative_queries.remove(&target);
                let owner = self
                    .owned_resources
                    .as_mut()
                    .expect("owned actor initialized");
                owner.operations.remove(&target);
                owner.response_operations.remove(&operation);
                self.socket.retire_owned_deadline(operation);
            }
        }
        let owner = self
            .owned_resources
            .as_mut()
            .ok_or(ResourceError::NotOwnedProfile)
            .map_err(PutQueryError::Resource)?;
        if let Some(error) = owner.terminal {
            return Err(PutQueryError::Resource(error).into());
        }
        let operation = owner
            .operation_for(target, &mut self.socket, deadline)
            .map_err(PutQueryError::Resource)?;
        let has_active_get = self.core.iterative_queries.contains_key(&target);
        let query = match PutQuery::new_owned(
            request.clone(),
            extra_nodes,
            operation,
            Arc::clone(&owner.budget),
        ) {
            Ok(query) => query,
            Err(error) => {
                if !has_active_get {
                    owner.operations.remove(&target);
                    self.socket.retire_owned_deadline(operation);
                }
                return Err(PutQueryError::Resource(error).into());
            }
        };
        self.core.put_queries.insert(target, query);
        if let Err(error) = self.owned_get_until(GetRequestSpecific::from(&request), None, deadline)
        {
            if let Some(put) = self.core.put_queries.remove(&target) {
                self.socket
                    .cancel_owned_transactions(&put.transaction_ids().to_vec());
            }
            if !has_active_get {
                self.socket.cancel_owned_operation(operation);
                let owner = self
                    .owned_resources
                    .as_mut()
                    .expect("owned actor initialized");
                owner.operations.remove(&target);
                owner.response_operations.remove(&operation);
            }
            return Err(PutQueryError::Resource(error).into());
        }
        Ok(())
    }

    pub(crate) fn owned_ping(&mut self, address: SocketAddrV4) -> Result<(), ResourceError> {
        let owner = self
            .owned_resources
            .as_mut()
            .ok_or(ResourceError::NotOwnedProfile)?;
        if let Some(error) = owner.terminal {
            return Err(error);
        }
        if owner
            .maintenance_nodes
            .iter()
            .any(|(known, tid, _, _)| *known == address && self.socket.inflight(tid))
        {
            return Ok(());
        }
        let operation = owner.maintenance_operation(
            &mut self.socket,
            tokio::time::Instant::now() + std::time::Duration::from_secs(10),
        )?;
        let holder = owner.budget.reserve_holder()?;
        let visited = owner.budget.reserve_visited()?;
        let tid = self.socket.request_owned(
            address,
            RequestSpecific {
                requester_id: *self.core.routing_table.id(),
                request_type: RequestTypeSpecific::Ping,
            },
            operation,
        )?;
        self.owned_resources
            .as_mut()
            .expect("owned actor initialized")
            .maintenance_nodes
            .push((address, tid, holder, visited));
        Ok(())
    }
}
