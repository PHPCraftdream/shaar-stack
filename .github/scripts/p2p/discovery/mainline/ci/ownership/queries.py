# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Reversible edits wiring iterative GET/PUT queries to their actual owner."""
from __future__ import annotations


def edits() -> dict[str, list[tuple[str, str]]]:
    return {
        "src/common/mutable.rs": [
            ("    // === Getters ===\n", "    pub(crate) fn into_owned_put(self) -> Result<Self, MutableError> {\n        let Self { target, key, value, seq, signature, salt } = self;\n        Self::from_dht_message(target, &key, value, seq, &signature, salt)\n    }\n\n    // === Getters ===\n"),
        ],
        "src/core/iterative_query.rs": [
            ("use std::collections::HashSet;\n", "use std::collections::HashSet;\nuse std::sync::Arc;\n"),
            ("use crate::core::Response;\n", "use crate::core::Response;\nuse crate::resource::{OperationId, ResourceError, StoreBudget, VisitedStore};\n"),
            ("    visited: HashSet<SocketAddrV4>,\n", "    visited: HashSet<SocketAddrV4>,\n    owned_visited: Option<VisitedStore>,\n    operation: Option<OperationId>,\n    owner_budget: Option<Arc<StoreBudget>> ,\n    owner_error: Option<ResourceError>,\n    owned_network_completed: bool,\n    owned_rounds: u8,\n    owned_next_round: Option<tokio::time::Instant>,\n"),
            ("            visited: HashSet::new(),\n", "            visited: HashSet::new(),\n            owned_visited: None,\n            operation: None,\n            owner_budget: None,\n            owner_error: None,\n            owned_network_completed: false,\n            owned_rounds: 0,\n            owned_next_round: None,\n"),
            ("    // === Getters ===\n", "    pub(crate) fn owned_next_round(&self) -> Option<tokio::time::Instant> { self.owned_next_round }\n    pub(crate) fn owned_note_network_response(&mut self) { self.owned_network_completed = true; }\n    pub(crate) fn owned_network_completed(&self) -> bool { self.owned_network_completed }\n\n    pub(crate) fn enable_owned(&mut self, operation: OperationId, budget: Arc<StoreBudget>) {\n        self.closest.enable_owner_budget(Arc::clone(&budget));\n        self.responders.enable_owner_budget(Arc::clone(&budget));\n        self.owned_visited = Some(VisitedStore::new(Arc::clone(&budget)));\n        self.owner_budget = Some(budget);\n        self.operation = Some(operation);\n    }\n\n    pub(crate) fn owner_error(&self) -> Option<ResourceError> { self.owner_error }\n    pub(crate) fn operation(&self) -> Option<OperationId> { self.operation }\n    pub(crate) fn take_owned_responses(&mut self) -> Vec<Response> { std::mem::take(&mut self.responses) }\n\n    // === Getters ===\n"),
            ("        self.closest.add(node);\n", "        self.closest.add(node);\n        if self.owner_error.is_none() { self.owner_error = self.closest.owner_error(); }\n"),
            ("        self.responders.add(node)\n", "        self.responders.add(node);\n        if self.owner_error.is_none() { self.owner_error = self.responders.owner_error(); }\n"),
            ("        let tid = socket.request(address, self.request.clone());\n        self.inflight_requests.push(tid);\n        self.visited.insert(address);\n", "        if self.owner_error.is_some() { return; }\n        if let Some(operation) = self.operation {\n            if self.owned_rounds == 0 { self.owned_rounds = 1; }\n            let visited = self.owned_visited.as_mut().expect(\"owned query visited store\");\n            match visited.insert(address) {\n                Ok(false) => return,\n                Err(error) => { self.owner_error = Some(error); return; }\n                Ok(true) => (),\n            }\n            match socket.request_owned(address, self.request.clone(), operation) {\n                Ok(tid) => { self.inflight_requests.retain(|tid| socket.inflight(tid)); self.inflight_requests.push(tid); }\n                Err(error) => self.owner_error = Some(error),\n            }\n        } else {\n            let tid = socket.request(address, self.request.clone());\n            self.inflight_requests.push(tid);\n            self.visited.insert(address);\n        }\n"),
            ("        let to_visit = self.closest_candidates();\n\n        for address in to_visit {\n            self.visit(socket, address);\n        }\n", "        self.visit_closest_at(socket, tokio::time::Instant::now());\n    }\n\n    pub(crate) fn visit_closest_at(&mut self, socket: &mut KrpcSocket, now: tokio::time::Instant) {\n        if self.owner_error.is_some() { return; }\n        let candidates = self.closest_candidates();\n        if let Some(operation) = self.operation {\n            if socket.owned_deadline(operation).is_some_and(|deadline| deadline <= now) { self.owner_error = Some(ResourceError::DeadlineExceeded); return; }\n            if self.inflight_requests.iter().any(|tid| socket.inflight(tid)) { return; }\n            if candidates.is_empty() || self.owned_rounds >= 3 { self.owned_next_round = None; return; }\n            if self.owned_rounds > 0 {\n                if self.owned_next_round.is_none() {\n                    let cap: u8 = if self.owned_rounds == 1 { 100 } else { 200 };\n                    let mut jitter = rand::random::<u8>();\n                    while jitter > cap { jitter = rand::random::<u8>(); }\n                    self.owned_next_round = Some(now + std::time::Duration::from_millis(jitter as u64));\n                }\n                if now < self.owned_next_round.expect(\"scheduled owned round\") { return; }\n            }\n            self.owned_rounds += 1;\n            self.owned_next_round = None;\n        }\n        for address in candidates {\n            if self.owner_error.is_some() { break; }\n            self.visit(socket, address);\n        }\n"),
            ("            .filter(|node| !self.visited.contains(&node.address()))\n", "            .filter(|node| !self.visited.contains(&node.address()) && !self.owned_visited.as_ref().is_some_and(|visited| visited.contains(&node.address())))\n"),
            ("        self.responses.push(response.to_owned());\n", "        if self.operation.is_some() {\n            if let Response::Mutable(item) = &response {\n                if self.responses.len() >= 32 || item.value().len() > 1000 || item.salt().is_some() {\n                    self.owner_error=Some(ResourceError::ResultLimit);\n                    return;\n                }\n            } else {\n                return;\n            }\n        }\n        self.responses.push(response.to_owned());\n"),
            ("    pub fn is_done(&self, socket: &KrpcSocket) -> bool {\n", "    pub fn is_done(&self, socket: &KrpcSocket) -> bool {\n        if self.owner_error.is_some(){return true;}\n        if self.operation.is_some() && self.owned_rounds < 3 && (!self.closest_candidates().is_empty() || self.owned_next_round.is_some()) { return false; }\n"),
            ("    owned_next_round: Option<tokio::time::Instant>,\n", "    owned_next_round: Option<tokio::time::Instant>,\n    #[cfg(test)]\n    owned_next_jitter: Option<u8>,\n"),
            ("            owned_next_round: None,\n", "            owned_next_round: None,\n            #[cfg(test)]\n            owned_next_jitter: None,\n"),
            ("                    let mut jitter = rand::random::<u8>();\n                    while jitter > cap { jitter = rand::random::<u8>(); }\n                    self.owned_next_round = Some(now + std::time::Duration::from_millis(jitter as u64));\n", "                    let jitter = self.sample_owned_jitter(cap);\n                    self.owned_next_round = Some(now + std::time::Duration::from_millis(jitter as u64));\n"),
            ("            if self.owned_rounds == 0 { self.owned_rounds = 1; }\n", "            if self.owned_rounds == 0 {\n                match socket.admit_owned_get_round(operation) {\n                    Ok(round) => self.owned_rounds = round,\n                    Err(error) => { self.owner_error = Some(error); return; }\n                }\n            }\n"),
            ("    pub(crate) fn owned_next_round(&self)", '''    fn sample_owned_jitter(&mut self, cap: u8) -> u8 {
        #[cfg(test)]
        if let Some(value) = self.owned_next_jitter.take() { assert!(value <= cap, "injected jitter exceeds retry cap"); return value; }
        let mut jitter = rand::random::<u8>();
        while jitter > cap { jitter = rand::random::<u8>(); }
        jitter
    }
    #[cfg(test)]
    pub(crate) fn set_owned_next_jitter(&mut self, value: u8) { self.owned_next_jitter = Some(value); }

    pub(crate) fn owned_next_round(&self)'''),
            ("            self.owned_rounds += 1;\n", "            {\n                let admitted_round = socket.admit_owned_get_round(operation);\n                match admitted_round {\n                    Ok(round) => self.owned_rounds = round,\n                    Err(error) => { self.owner_error = Some(error); return; }\n                }\n            }\n"),
            ("            if candidates.is_empty() || self.owned_rounds >= 3 { self.owned_next_round = None; return; }\n", "            if self.owned_rounds > 0 { self.owned_rounds = socket.owned_get_rounds(operation); }\n            if candidates.is_empty() || self.owned_rounds >= 3 { self.owned_next_round = None; return; }\n"),
        ],
        "src/core/put_query.rs": [
            ("use tracing::{debug, trace};\n", "use tracing::{debug, trace};\nuse std::collections::HashSet;\nuse std::sync::Arc;\nuse crate::resource::{HolderLease, OperationId, ResourceError, StoreBudget, VisitedStore};\n"),
            ("    extra_nodes: Box<[Node]>,\n", "    extra_nodes: Box<[Node]>,\n    operation: Option<OperationId>,\n    owner_budget: Option<Arc<StoreBudget>> ,\n    extra_node_leases: Vec<HolderLease>,\n    owned_visited: Option<VisitedStore>,\n    owner_error: Option<ResourceError>,\n    owned_attempts: u8,\n    owned_retry_at: Option<tokio::time::Instant>,\n    #[cfg(test)]\n    owned_next_jitter: Option<u8>,\n"),
            ("            extra_nodes: extra_nodes.unwrap_or(Box::new([])),\n", "            extra_nodes: extra_nodes.unwrap_or(Box::new([])),\n            operation: None,\n            owner_budget: None,\n            extra_node_leases: Vec::new(),\n            owned_visited: None,\n            owner_error: None,\n            owned_attempts: 0,\n            owned_retry_at: None,\n            #[cfg(test)]\n            owned_next_jitter: None,\n"),
            ("    pub fn start(\n", '''    pub(crate) fn new_owned(
        request: PutRequestSpecific,
        extra_nodes: Option<Box<[Node]>>,
        operation: OperationId,
        budget: Arc<StoreBudget>,
    ) -> Result<Self, ResourceError> {
        let nodes = extra_nodes.unwrap_or_default();
        let mut leases = Vec::new();
        for _ in nodes.iter() { leases.push(budget.reserve_holder()?); }
        let mut query = Self::new(request, Some(nodes));
        query.operation = Some(operation);
        query.owner_budget = Some(Arc::clone(&budget));
        query.extra_node_leases = leases;
        query.owned_visited = Some(VisitedStore::new(budget));
        Ok(query)
    }

    pub(crate) fn owner_error(&self) -> Option<ResourceError> { self.owner_error }
    fn sample_owned_jitter(&mut self, cap: u8) -> u8 {
        #[cfg(test)]
        if let Some(value) = self.owned_next_jitter.take() { assert!(value <= cap, "injected jitter exceeds retry cap"); return value; }
        let mut jitter = rand::random::<u8>();
        while jitter > cap { jitter = rand::random::<u8>(); }
        jitter
    }
    #[cfg(test)]
    pub(crate) fn set_owned_next_jitter(&mut self, value: u8) { self.owned_next_jitter = Some(value); }
    pub(crate) fn owned_retry_at(&self) -> Option<tokio::time::Instant> { self.owned_retry_at }

    pub(crate) fn schedule_owned_retry(&mut self, socket: &KrpcSocket, now: tokio::time::Instant) -> bool {
        if self.owned_retry_at.is_some() { return true; }
        if self.operation.is_none() || !(1..=2).contains(&self.owned_attempts)
            || !matches!(self.check(socket), Err(PutError::Query(PutQueryError::Timeout)))
        {
            return false;
        }
        let Some(operation) = self.operation else { return false; };
        let Some(deadline) = socket.owned_deadline(operation) else { return false; };
        if now >= deadline { return false; }
        let cap: u8 = if self.owned_attempts == 1 { 100 } else { 200 };
        let jitter = self.sample_owned_jitter(cap);
        let retry_at = now + std::time::Duration::from_millis(jitter as u64);
        if retry_at >= deadline { return false; }
        self.owned_retry_at = Some(retry_at);
        true
    }

    pub(crate) fn operation(&self) -> Option<OperationId> { self.operation }
    pub(crate) fn transaction_ids(&self) -> &[u32] { &self.inflight_requests }

    pub(crate) fn retry_owned_at(&mut self, socket: &mut KrpcSocket, now: tokio::time::Instant) -> Result<(), PutError> {
        let Some(retry_at) = self.owned_retry_at else { return Ok(()); };
        if now < retry_at { return Ok(()); }
        let Some(operation) = self.operation else { return Ok(()); };
        if socket.owned_deadline(operation).is_some_and(|deadline| now >= deadline) {
            return Err(PutQueryError::Resource(ResourceError::DeadlineExceeded).into());
        }
        if self.owned_attempts >= 3 { self.owned_retry_at = None; return Ok(()); }
        socket.cancel_owned_transactions(&self.inflight_requests);
        self.inflight_requests.clear();
        self.owned_attempts += 1;
        self.owned_retry_at = None;
        let mut seen = HashSet::new();
        for node in &self.extra_nodes {
            if !seen.insert(node.address()) { continue; }
            if let Some(token) = node.token() {
                let retry_request = RequestSpecific {
                    requester_id: Id::random(),
                    request_type: RequestTypeSpecific::Put(PutRequest {
                        token,
                        put_request_type: self.request.clone(),
                    }),
                };
                let tid = socket.request_owned(node.address(), retry_request, operation)
                    .map_err(PutQueryError::Resource)?;
                self.inflight_requests.push(tid);
            }
        }
        Ok(())
    }

    pub fn start(
'''),
            ("        let target = self.target;\n        debug!(?target, closest_secure_nodes = ?closest_nodes.len(), \"PutQuery start\");", '''        let target = self.target;
        debug!(?target, closest_secure_nodes = ?closest_nodes.len(), "PutQuery start");
        if self.operation.is_some() && self.owned_attempts == 0 {
            let budget = Arc::clone(self.owner_budget.as_ref().expect("owned PUT budget"));
            if self.operation.is_some_and(|operation| socket.owned_deadline(operation).is_some_and(|deadline| deadline <= tokio::time::Instant::now())) {
                self.owner_error = Some(ResourceError::DeadlineExceeded);
                return Err(PutQueryError::Resource(ResourceError::DeadlineExceeded).into());
            }
            let mut retained = std::mem::take(&mut self.extra_nodes).into_vec();
            for node in closest_nodes {
                match budget.reserve_holder() {
                    Ok(lease) => {
                        retained.push(node.clone());
                        self.extra_node_leases.push(lease);
                    }
                    Err(error) => {
                        self.extra_nodes = retained.into_boxed_slice();
                        self.owner_error = Some(error);
                        return Err(PutQueryError::Resource(error).into());
                    }
                }
            }
            self.extra_nodes = retained.into_boxed_slice();
        }'''),
            ("            // Set correct values to the request placeholders\n            if let Some(token) = node.token() {\n", "            // Set correct values to the request placeholders\n            if let Some(token) = node.token() {\n                if let Some(visited) = self.owned_visited.as_mut() {\n                    match visited.insert(node.address()) {\n                        Ok(false) => continue,\n                        Ok(true) => (),\n                        Err(error) => { self.owner_error = Some(error); return Err(PutQueryError::Resource(error).into()); }\n                    }\n                }\n"),
            ("                let tid = socket.request(\n                    node.address(),\n                    RequestSpecific {\n", "                let request = RequestSpecific {\n"),
            ("                    },\n                );\n\n                self.inflight_requests.push(tid);\n", "                    };\n                let result = if let Some(operation) = self.operation {\n                    socket.request_owned(node.address(), request, operation)\n                } else {\n                    Ok(socket.request(node.address(), request))\n                };\n                match result {\n                    Ok(tid) => { if self.operation.is_some() && self.owned_attempts == 0 { self.owned_attempts = 1; } self.inflight_requests.push(tid); },\n                    Err(error) => { self.owner_error = Some(error); return Err(PutQueryError::Resource(error).into()); }\n                }\n"),
            (
                "                302 => Some((*count, PutError::from(ConcurrencyError::NotMostRecent))),\n                _ => None,\n",
                "                302 => Some((*count, PutError::from(ConcurrencyError::NotMostRecent))),\n                _ if self.operation.is_some() => Some((*count, PutQueryError::ErrorResponse(error.clone()).into())),\n                _ => None,\n",
            ),
            ("    #[error(\"DHT actor task has shut down\")]\n    Shutdown,\n", "    #[error(\"DHT actor task has shut down\")]\n    Shutdown,\n\n    /// The bounded owner could not admit or complete a resource-backed query.\n    #[error(\"Mainline resource admission failed\")]\n    Resource(ResourceError),\n"),
        ],
    }
