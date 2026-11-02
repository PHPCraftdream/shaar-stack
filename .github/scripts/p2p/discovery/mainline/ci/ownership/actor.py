# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Wire bounded actor operations to the actor-owned resource implementation."""
from __future__ import annotations


def edits() -> dict[str, list[tuple[str, str]]]:
    return {
        "src/actor.rs": [
            (
                "pub use info::Info;",
                'pub use info::Info;\n#[path = "actor/owned_resources.rs"]\nmod owned_resources;\nuse owned_resources::OwnedActor;',
            ),
            (
                "    hard_client_only: bool,\n",
                "    hard_client_only: bool,\n    owned_resources: Option<OwnedActor>,\n    #[cfg(test)]\n    owned_maintenance_after_operations: Option<(usize, tokio::sync::oneshot::Sender<()>)>,\n",
            ),
            (
                "            hard_client_only,\n",
                "            hard_client_only,\n            owned_resources: None,\n            #[cfg(test)]\n            owned_maintenance_after_operations: None,\n",
            ),
            (
                "    fn tick(&mut self) {\n        self.periodic_node_maintaenance();",
                "    fn tick(&mut self) {\n        if self.owned_resources.is_some() { self.expire_owned_operations_at(tokio::time::Instant::now()); }\n        if let Some(error) = self.socket.take_owned_failure() { self.owned_fail(error); }\n        if self.owned_resources.is_some() { self.retire_owned_operation_errors(); }\n        if self.owned_error().is_some() { return; }\n        if self.owned_resources.is_some() { self.tick_owned(); return; }\n        self.periodic_node_maintaenance();",
            ),
            (
                "    ) -> Result<(), PutError> {\n        self.core.check_concurrency_errors(&request)?;\n\n        let mut query = PutQuery::new(request.clone(), extra_nodes);",
                "    ) -> Result<(), PutError> {\n        if self.owned_resources.is_some() { return self.owned_put(request, extra_nodes); }\n        self.core.check_concurrency_errors(&request)?;\n\n        let mut query = PutQuery::new(request.clone(), extra_nodes);",
            ),
            (
                "    ) -> Vec<Response> {\n        let target = request.target();\n\n        let mut responses = vec![];",
                "    ) -> Vec<Response> {\n        let target = request.target();\n        if self.owned_resources.is_some() {\n            return self.owned_get(request, extra_nodes).unwrap_or_else(|error| { self.owned_fail(error); Vec::new() });\n        }\n\n        let mut responses = vec![];",
            ),
            (
                "    fn periodic_node_maintaenance(&mut self) {\n        // Bootstrap if necessary",
                '''    fn periodic_node_maintaenance(&mut self) {
        if self.owned_resources.is_some() {
            #[cfg(test)]
            if self.owned_disable_maintenance_for_test { return; }
            #[cfg(test)]
            if let Some((threshold, _)) = self.owned_maintenance_after_operations.as_ref() {
                if self.owned_resources.as_ref().is_some_and(|owner| owner.operations.len() < *threshold) { return; }
            }
            #[cfg(test)]
            if let Some((_, signal)) = self.owned_maintenance_after_operations.take() { let _ = signal.send(()); }
            let now = tokio::time::Instant::now();
            let owner = self.owned_resources.as_mut().expect("owned actor initialized");
            if owner.maintenance_retry_at.is_some_and(|next| now < next) { return; }
            owner.maintenance_retry_at = Some(now + std::time::Duration::from_secs(1));
            let maintenance_target = *self.core.routing_table.id();
            if self.core.should_refresh_table() {
                self.core.update_last_table_refresh();
                if let Err(error) = self.owned_get(crate::core::iterative_query::GetRequestSpecific::FindNode(crate::common::FindNodeRequestArguments { target: maintenance_target }), None) {
                    if error != crate::resource::ResourceError::OperationLimit { if error == crate::resource::ResourceError::NotOwnedProfile { self.owned_fail(error); } else if let Some(operation) = self.owned_resources.as_ref().and_then(|owner| owner.maintenance) { self.fail_owned_operation(operation, error); } return; }
                }
            } else if self.core.routing_table.is_empty() {
                if let Err(error) = self.owned_get(crate::core::iterative_query::GetRequestSpecific::FindNode(crate::common::FindNodeRequestArguments { target: maintenance_target }), None) {
                    if error != crate::resource::ResourceError::OperationLimit { if error == crate::resource::ResourceError::NotOwnedProfile { self.owned_fail(error); } else if let Some(operation) = self.owned_resources.as_ref().and_then(|owner| owner.maintenance) { self.fail_owned_operation(operation, error); } return; }
                }
            }
            if self.owned_error().is_some() { return; }
            if self.core.should_ping_table() {
                self.core.update_last_table_ping();
                for address in self.core.check_nodes_to_ping_and_remove_stale_nodes() {
                    if let Err(error) = self.owned_ping(address) {
                        if error != crate::resource::ResourceError::OperationLimit { if error == crate::resource::ResourceError::NotOwnedProfile { self.owned_fail(error); } else if let Some(operation) = self.owned_resources.as_ref().and_then(|owner| owner.maintenance) { self.fail_owned_operation(operation, error); } return; }
                    }
                    if self.owned_error().is_some() { return; }
                }
            }
            return;
        }
        // Bootstrap if necessary''',
            ),
            (
                "    fn ping(&mut self, address: SocketAddrV4) {\n        self.socket.request(",
                "    fn ping(&mut self, address: SocketAddrV4) {\n        if self.owned_resources.is_some() {\n            if let Err(error) = self.owned_ping(address) { self.owned_fail(error); }\n            return;\n        }\n        self.socket.request(",
            ),
            (
                "        actor.tick();\n    }\n    #[cfg(test)]\n    if let Some((entered, release)) = actor.owned_cleanup_gate.take() {",
                "        actor.tick();\n        if actor.owned_error().is_some() { break; }\n    }\n    #[cfg(test)]\n    if let Some((entered, release)) = actor.owned_cleanup_gate.take() {",
            ),
        ],
    }
