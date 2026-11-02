// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use crate::resource::{OperationId, ResourceError};

#[derive(Debug)]
struct RpcOwner {
    operation: OperationId,
    to: SocketAddrV4,
    queued: bool,
    sent_at: Option<Instant>,
}

#[derive(Debug, Default)]
pub(crate) struct SocketResources {
    rpc: HashMap<u32, RpcOwner>,
    per_operation: HashMap<OperationId, usize>,
    deadlines: HashMap<OperationId, (tokio::time::Instant, u8)>,
    next_operation: u64,
    datagrams: usize,
    bytes: usize,
}

impl SocketResources {
    pub(crate) fn register_owned_deadline(
        &mut self,
        operation: OperationId,
        deadline: tokio::time::Instant,
    ) -> Result<(), ResourceError> {
        if let Some(existing) = self.deadlines.get_mut(&operation) {
            existing.0 = existing.0.min(deadline);
            return Ok(());
        }
        if self.deadlines.len() >= 8 {
            return Err(ResourceError::OperationLimit);
        }
        self.deadlines.insert(operation, (deadline, 0));
        Ok(())
    }

    pub(crate) fn owned_deadline(&self, operation: OperationId) -> Option<tokio::time::Instant> {
        self.deadlines
            .get(&operation)
            .map(|(deadline, _)| *deadline)
    }

    pub(crate) fn owned_get_rounds(&self, operation: OperationId) -> u8 {
        self.deadlines
            .get(&operation)
            .map(|(_, rounds)| *rounds)
            .unwrap_or(0)
    }

    pub(crate) fn admit_owned_get_round(
        &mut self,
        operation: OperationId,
    ) -> Result<u8, ResourceError> {
        let Some((_, rounds)) = self.deadlines.get_mut(&operation) else {
            return Err(ResourceError::DeadlineExceeded);
        };
        if *rounds >= 3 {
            return Err(ResourceError::DeadlineExceeded);
        }
        *rounds += 1;
        Ok(*rounds)
    }

    pub(crate) fn retire_owned_deadline(&mut self, operation: OperationId) {
        self.deadlines.remove(&operation);
    }

    pub(crate) fn allocate_operation(&mut self) -> Result<OperationId, ResourceError> {
        let value = self.next_operation;
        self.next_operation = self
            .next_operation
            .checked_add(1)
            .ok_or(ResourceError::RpcLimit)?;
        Ok(OperationId::new(value))
    }

    pub(crate) fn admit_rpc(
        &mut self,
        tid: u32,
        operation: OperationId,
        to: SocketAddrV4,
    ) -> Result<(), ResourceError> {
        if self.rpc.contains_key(&tid) {
            return Err(ResourceError::RpcLimit);
        }
        let operation_count = self.per_operation.get(&operation).copied().unwrap_or(0);
        if self.rpc.len() >= 128 || operation_count >= 16 {
            return Err(ResourceError::RpcLimit);
        }

        self.rpc.insert(
            tid,
            RpcOwner {
                operation,
                to,
                queued: true,
                sent_at: None,
            },
        );
        *self.per_operation.entry(operation).or_default() += 1;
        Ok(())
    }

    pub(crate) fn rpc_sent(&mut self, tid: u32) -> bool {
        let Some(owner) = self.rpc.get_mut(&tid) else {
            return false;
        };
        owner.queued = false;
        owner.sent_at = Some(Instant::now());
        true
    }

    pub(crate) fn matches_response(&self, tid: u32, from: SocketAddrV4) -> bool {
        self.rpc
            .get(&tid)
            .is_some_and(|owner| !owner.queued && owner.to == from)
    }

    pub(crate) fn complete_rpc(&mut self, tid: u32, from: SocketAddrV4) -> bool {
        if !self.matches_response(tid, from) {
            return false;
        }
        self.release_rpc(tid)
    }

    pub(crate) fn rollback_rpc(&mut self, tid: u32) -> bool {
        self.release_rpc(tid)
    }

    fn release_rpc(&mut self, tid: u32) -> bool {
        let Some(owner) = self.rpc.remove(&tid) else {
            return false;
        };
        if let Some(count) = self.per_operation.get_mut(&owner.operation) {
            *count -= 1;
            if *count == 0 {
                self.per_operation.remove(&owner.operation);
            }
        }
        true
    }

    pub(crate) fn expired(&self, timeout: Duration) -> Vec<u32> {
        let now = Instant::now();
        self.rpc
            .iter()
            .filter_map(|(&tid, owner)| {
                (!owner.queued
                    && owner
                        .sent_at
                        .is_some_and(|sent_at| now.duration_since(sent_at) >= timeout))
                .then_some(tid)
            })
            .collect()
    }

    pub(crate) fn operation(&self, tid: u32) -> Option<OperationId> {
        self.rpc.get(&tid).map(|owner| owner.operation)
    }

    pub(crate) fn cancel_operation(&self, operation: OperationId) -> Vec<u32> {
        self.rpc
            .iter()
            .filter_map(|(&tid, owner)| (owner.operation == operation).then_some(tid))
            .collect()
    }

    pub(crate) fn enqueue(&mut self, bytes: usize) -> Result<(), ResourceError> {
        if bytes > 2048 {
            return Err(ResourceError::DatagramTooLarge);
        }
        if self.datagrams >= 128 {
            return Err(ResourceError::OutboxFull);
        }
        let total_bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or(ResourceError::OutboxFull)?;
        self.datagrams += 1;
        self.bytes = total_bytes;
        Ok(())
    }

    pub(crate) fn sent(&mut self, bytes: usize) {
        self.datagrams = self
            .datagrams
            .checked_sub(1)
            .expect("outbox datagram charge invariant");
        self.bytes = self
            .bytes
            .checked_sub(bytes)
            .expect("outbox byte charge invariant");
    }

    pub(crate) fn datagram_count(&self) -> usize {
        self.datagrams
    }

    pub(crate) fn byte_count(&self) -> usize {
        self.bytes
    }

    pub(crate) fn rpc_len(&self) -> usize {
        self.rpc.len()
    }

    pub(crate) fn operation_rpc_len(&self, operation: OperationId) -> usize {
        self.per_operation.get(&operation).copied().unwrap_or(0)
    }

    #[cfg(test)]
    pub(crate) fn outbox_len(&self) -> usize {
        self.datagrams
    }
}
