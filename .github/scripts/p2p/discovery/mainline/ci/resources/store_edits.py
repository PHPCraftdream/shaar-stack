# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Reversible aggregate-holder edits for n0-mainline candidate containers."""
from __future__ import annotations


def edits() -> dict[str, list[tuple[str, str]]]:
    closest_add_old = '''    pub fn add(&mut self, node: Node) {
        let seek = node.id().xor(&self.target);

        if node.already_exists(&self.nodes) {
            return;
        }

        if let Err(pos) = self.nodes.binary_search_by(|prope| {'''
    closest_add_new = '''    pub fn add(&mut self, node: Node) {
        if let Err(error) = self.add_owned(node) {
            self.owner_error = Some(error);
        }
    }

    pub(crate) fn enable_owner_budget(&mut self, budget: std::sync::Arc<crate::resource::StoreBudget>) {
        assert!(self.nodes.is_empty(), "enable owner accounting before inserting candidates");
        self.nodes.shrink_to_fit();
        self.owner_budget = Some(budget);
    }

    pub(crate) fn owner_error(&mut self) -> Option<crate::resource::ResourceError> {
        self.owner_error.take()
    }

    pub(crate) fn try_clone_owned(&self) -> Result<Self, crate::resource::ResourceError> {
        let mut clone = Self {
            target: self.target,
            nodes: Vec::new(),
            owner_budget: self.owner_budget.clone(),
            holder_leases: Vec::new(),
            owner_error: None,
        };
        for node in &self.nodes { clone.add_owned(node.clone())?; }
        Ok(clone)
    }

    pub(crate) fn add_owned(&mut self, node: Node) -> Result<(), crate::resource::ResourceError> {
        let seek = node.id().xor(&self.target);
        if node.already_exists(&self.nodes) { return Ok(()); }
        if let Err(pos) = self.nodes.binary_search_by(|prope| {'''
    closest_add_end_old = '''        }) {
            self.nodes.insert(pos, node)
        }
    }'''
    closest_add_end_new = '''        }) {
            let lease = match &self.owner_budget {
                Some(budget) => Some(budget.reserve_holder()?),
                None => None,
            };
            self.nodes.insert(pos, node);
            if let Some(lease) = lease { self.holder_leases.push(lease); }
        }
        Ok(())
    }'''
    routing_add_old = '''    pub fn add(&mut self, node: Node) -> bool {
        let distance = self.id.distance(node.id());'''
    routing_add_new = '''    pub fn add(&mut self, node: Node) -> bool {
        match self.add_owned(node) {
            Ok(added) => added,
            Err(error) => {
                self.owner_error = Some(error);
                false
            }
        }
    }

    pub(crate) fn enable_owner_budget(&mut self, budget: std::sync::Arc<crate::resource::StoreBudget>) {
        assert!(self.is_empty(), "enable owner accounting before inserting routing nodes");
        self.owner_budget = Some(budget);
    }

    pub(crate) fn owner_error(&mut self) -> Option<crate::resource::ResourceError> {
        self.owner_error.take()
    }

    pub(crate) fn add_owned(&mut self, node: Node) -> Result<bool, crate::resource::ResourceError> {
        let distance = self.id.distance(node.id());'''
    reset_old = '''        let old_nodes = self.to_owned_nodes();
        self.buckets = Default::default();
        self.id = id;

        for node in old_nodes {
            self.add(node);
        }'''
    reset_new = '''        let old_buckets = std::mem::take(&mut self.buckets);
        let mut old_leases = std::mem::take(&mut self.holder_leases);
        self.id = id;

        for (_, bucket) in old_buckets {
            for node in bucket.nodes {
                let node_id = *node.id();
                let distance = self.id.distance(node.id());
                if distance == 0 { continue; }
                if self.buckets.entry(distance).or_default().add(node) {
                    if let Some(lease) = old_leases.remove(&node_id) {
                        self.holder_leases.insert(node_id, lease);
                    }
                } else {
                    old_leases.remove(&node_id);
                }
            }
        }
        self.holder_leases.retain(|node_id, _| {
            self.buckets.values().any(|bucket| bucket.nodes.iter().any(|node| node.id() == node_id))
        });
    '''
    routing_add_body_old = '''        if distance == 0 {
            // Do not add self to the routing_table
            return false;
        }

        if self
            .buckets()
            .values()
            .any(|bucket| node.already_exists(&bucket.nodes))
        {
            return false;
        };

        let bucket = self.buckets.entry(distance).or_default();

        bucket.add(node)'''
    routing_add_body_new = '''        if distance == 0 { return Ok(false); }

        if self.buckets.values().any(|bucket| node.already_exists(&bucket.nodes)) {
            return Ok(false);
        }

        let existing_id = self.buckets.values().flat_map(|bucket| bucket.nodes.iter())
            .find(|existing| existing.id() == node.id()).map(|existing| *existing.id());
        let stale_id = self.buckets.get(&distance)
            .filter(|bucket| existing_id.is_none() && bucket.nodes.len() >= MAX_BUCKET_SIZE_K && bucket.nodes[0].is_stale())
            .map(|bucket| *bucket.nodes[0].id());
        let bucket_full = self.buckets.get(&distance)
            .is_some_and(|bucket| bucket.nodes.len() >= MAX_BUCKET_SIZE_K);
        if bucket_full && existing_id.is_none() && stale_id.is_none() { return Ok(false); }
        let lease = if existing_id.is_some() || stale_id.is_some() { None }
            else { self.owner_budget.as_ref().map(|budget| budget.reserve_holder()).transpose()? };
        let node_id = *node.id();
        let added = self.buckets.entry(distance).or_default().add(node);
        if added {
            let transferred = stale_id.and_then(|stale_id| self.holder_leases.remove(&stale_id));
            if let Some(lease) = lease.or(transferred) { self.holder_leases.insert(node_id, lease); }
        }
        Ok(added)'''
    routing_remove_old = '''    pub fn remove(&mut self, node_id: &Id) {
        let distance = self.id.distance(node_id);

        if let Some(bucket) = self.buckets.get_mut(&distance) {
            bucket.remove(node_id)
        }
    }'''
    routing_remove_new = '''    pub fn remove(&mut self, node_id: &Id) {
        let distance = self.id.distance(node_id);
        if let Some(bucket) = self.buckets.get_mut(&distance) { bucket.remove(node_id); }
        self.holder_leases.remove(node_id);
    }'''
    routing_clone = '''impl Clone for RoutingTable {
    fn clone(&self) -> Self {
        let mut clone = Self::new(self.id);
        clone.dht_size_estimates_count = self.dht_size_estimates_count;
        clone.dht_size_estimates_sum = self.dht_size_estimates_sum;
        clone.responders_samples_count = self.responders_samples_count;
        clone.responders_size_estimates_sum = self.responders_size_estimates_sum;
        clone.responders_subnets_sum = self.responders_subnets_sum;
        clone.owner_budget = self.owner_budget.clone();
        for node in self.nodes() {
            match clone.add_owned(node) {
                Ok(_) => (),
                Err(error) => { clone.owner_error = Some(error); break; }
            }
        }
        clone
    }
}

impl RoutingTable {'''
    return {
        "src/common/closest_nodes.rs": [
            ("#[derive(Debug, Clone)]\n/// Manage closest nodes", "#[derive(Debug)]\n/// Manage closest nodes"),
            ("    nodes: Vec<Node>,\n", "    nodes: Vec<Node>,\n    owner_budget: Option<std::sync::Arc<crate::resource::StoreBudget>>,\n    holder_leases: Vec<crate::resource::HolderLease>,\n    owner_error: Option<crate::resource::ResourceError>,\n"),
            ("        Self {\n            target,\n            nodes: Vec::with_capacity(200),\n        }", "        Self {\n            target,\n            nodes: Vec::with_capacity(200),\n            owner_budget: None,\n            holder_leases: Vec::new(),\n            owner_error: None,\n        }"),
            (closest_add_old, closest_add_new),
            (closest_add_end_old, closest_add_end_new),
            ('''impl ClosestNodes {''', '''impl Clone for ClosestNodes {
    fn clone(&self) -> Self {
        match self.try_clone_owned() {
            Ok(clone) => clone,
            Err(error) => Self {
                target: self.target,
                nodes: Vec::new(),
                owner_budget: self.owner_budget.clone(),
                holder_leases: Vec::new(),
                owner_error: Some(error),
            },
        }
    }
}

impl ClosestNodes {'''),
        ],
        "src/common/routing_table.rs": [
            ("#[derive(Debug, Clone)]\n/// Simplified Kademlia routing table", "#[derive(Debug)]\n/// Simplified Kademlia routing table"),
            ("    buckets: BTreeMap<u8, KBucket>,\n", "    buckets: BTreeMap<u8, KBucket>,\n    owner_budget: Option<std::sync::Arc<crate::resource::StoreBudget>>,\n    holder_leases: BTreeMap<Id, crate::resource::HolderLease>,\n    owner_error: Option<crate::resource::ResourceError>,\n"),
            ("            buckets,\n", "            buckets,\n            owner_budget: None,\n            holder_leases: BTreeMap::new(),\n            owner_error: None,\n"),
            (routing_add_old, routing_add_new),
            (routing_add_body_old, routing_add_body_new),
            (routing_remove_old, routing_remove_new),
            (reset_old, reset_new),
            ('''impl RoutingTable {''', routing_clone),
        ],
    }
