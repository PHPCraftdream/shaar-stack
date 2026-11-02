// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use super::resources::SocketResources;
use crate::common::{ErrorSpecific, MessageType, RequestSpecific, ResponseSpecific};
use crate::resource::{OperationId, ResourceError};

#[derive(Debug)]
struct OwnedPacket {
    bytes: Vec<u8>,
    to: SocketAddrV4,
    tid: Option<u32>,
}

#[derive(Debug, Default)]
pub(super) struct OwnedSocket {
    pub(super) resources: SocketResources,
    outbox: VecDeque<OwnedPacket>,
    pub(super) last_response: Option<(u32, OperationId)>,
    pub(super) failure: Option<ResourceError>,
    transaction_exhausted: bool,
    #[cfg(test)]
    enqueue_failure: bool,
    #[cfg(test)]
    encode_failure: bool,
    #[cfg(test)]
    send_failure: bool,
    #[cfg(test)]
    send_gate: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    )>,
    #[cfg(test)]
    persistent_send_gate: Option<(
        Option<tokio::sync::oneshot::Sender<()>>,
        tokio::sync::oneshot::Receiver<()>,
        Option<u32>,
    )>,
    #[cfg(test)]
    charge_probe: Option<
        tokio::sync::mpsc::Receiver<tokio::sync::oneshot::Sender<(usize, usize, usize, usize)>>,
    >,
}

impl super::KrpcSocket {
    pub(crate) fn enable_owned_resources(&mut self) {
        self.owned.get_or_insert_with(OwnedSocket::default);
    }

    pub(crate) fn is_owned_profile(&self) -> bool {
        self.owned.is_some()
    }

    pub(crate) fn allocate_operation(&mut self) -> Result<OperationId, ResourceError> {
        self.owned
            .as_mut()
            .ok_or(ResourceError::RpcLimit)?
            .resources
            .allocate_operation()
    }

    pub(crate) fn register_owned_deadline(
        &mut self,
        operation: OperationId,
        deadline: tokio::time::Instant,
    ) -> Result<(), ResourceError> {
        self.owned
            .as_mut()
            .ok_or(ResourceError::RpcLimit)?
            .resources
            .register_owned_deadline(operation, deadline)
    }

    pub(crate) fn owned_deadline(&self, operation: OperationId) -> Option<tokio::time::Instant> {
        self.owned.as_ref()?.resources.owned_deadline(operation)
    }

    pub(crate) fn retire_owned_deadline(&mut self, operation: OperationId) {
        if let Some(owned) = self.owned.as_mut() {
            owned.resources.retire_owned_deadline(operation);
        }
    }

    pub(crate) fn owned_get_rounds(&self, operation: OperationId) -> u8 {
        self.owned
            .as_ref()
            .map_or(0, |owned| owned.resources.owned_get_rounds(operation))
    }

    pub(crate) fn admit_owned_get_round(
        &mut self,
        operation: OperationId,
    ) -> Result<u8, ResourceError> {
        self.owned
            .as_mut()
            .ok_or(ResourceError::NotOwnedProfile)?
            .resources
            .admit_owned_get_round(operation)
    }

    pub(crate) fn request_owned(
        &mut self,
        address: SocketAddrV4,
        request: RequestSpecific,
        operation: OperationId,
    ) -> Result<u32, ResourceError> {
        let owned = self.owned.as_mut().ok_or(ResourceError::RpcLimit)?;
        if owned
            .resources
            .owned_deadline(operation)
            .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
        {
            return Err(ResourceError::DeadlineExceeded);
        }
        if owned.transaction_exhausted {
            return Err(ResourceError::TransactionSpaceExhausted);
        }
        let tid = self.inflight_requests.next_tid;
        owned.resources.admit_rpc(tid, operation, address)?;

        #[cfg(test)]
        if std::mem::replace(
            &mut self.owned.as_mut().expect("admitted owner").encode_failure,
            false,
        ) {
            self.owned
                .as_mut()
                .expect("admitted owner")
                .resources
                .rollback_rpc(tid);
            return Err(ResourceError::Encode);
        }

        let message = self.request_message(tid, request);
        let bytes = match message.to_bytes() {
            Ok(bytes) => bytes,
            Err(_) => {
                self.owned
                    .as_mut()
                    .expect("admitted owner")
                    .resources
                    .rollback_rpc(tid);
                return Err(ResourceError::Encode);
            }
        };

        #[cfg(test)]
        if std::mem::replace(
            &mut self.owned.as_mut().expect("admitted owner").enqueue_failure,
            false,
        ) {
            self.owned
                .as_mut()
                .expect("admitted owner")
                .resources
                .rollback_rpc(tid);
            return Err(ResourceError::Enqueue);
        }

        if let Err(error) = self
            .owned
            .as_mut()
            .expect("admitted owner")
            .resources
            .enqueue(bytes.len())
        {
            self.owned
                .as_mut()
                .expect("admitted owner")
                .resources
                .rollback_rpc(tid);
            return Err(error);
        }
        let actual_tid = self.inflight_requests.add(address);
        if actual_tid != tid {
            let owned = self.owned.as_mut().expect("admitted owner");
            owned.resources.sent(bytes.len());
            owned.resources.rollback_rpc(tid);
            self.inflight_requests.remove(actual_tid);
            return Err(ResourceError::RpcLimit);
        }
        if tid == u32::MAX {
            self.owned
                .as_mut()
                .expect("admitted owner")
                .transaction_exhausted = true;
        }
        self.owned
            .as_mut()
            .expect("admitted owner")
            .outbox
            .push_back(OwnedPacket {
                bytes,
                to: address,
                tid: Some(tid),
            });
        Ok(tid)
    }

    pub(crate) fn send_datagram_owned(
        &mut self,
        bytes: Vec<u8>,
        address: SocketAddrV4,
    ) -> Result<(), ResourceError> {
        let owned = self.owned.as_mut().ok_or(ResourceError::RpcLimit)?;
        owned.resources.enqueue(bytes.len())?;
        owned.outbox.push_back(OwnedPacket {
            bytes,
            to: address,
            tid: None,
        });
        Ok(())
    }

    pub(crate) fn response_owned(
        &mut self,
        address: SocketAddrV4,
        transaction_id: u32,
        response: ResponseSpecific,
    ) -> Result<(), ResourceError> {
        self.enqueue_owned_message(address, transaction_id, MessageType::Response(response))
    }

    pub(crate) fn error_owned(
        &mut self,
        address: SocketAddrV4,
        transaction_id: u32,
        error: ErrorSpecific,
    ) -> Result<(), ResourceError> {
        self.enqueue_owned_message(address, transaction_id, MessageType::Error(error))
    }

    fn enqueue_owned_message(
        &mut self,
        address: SocketAddrV4,
        transaction_id: u32,
        message_type: MessageType,
    ) -> Result<(), ResourceError> {
        let message = self.response_message(message_type, address, transaction_id);
        let bytes = message.to_bytes().map_err(|_| ResourceError::Encode)?;
        let owned = self.owned.as_mut().ok_or(ResourceError::RpcLimit)?;
        owned.resources.enqueue(bytes.len())?;
        owned.outbox.push_back(OwnedPacket {
            bytes,
            to: address,
            tid: None,
        });
        Ok(())
    }

    pub(crate) async fn flush_owned(&mut self) {
        loop {
            let Some(owned) = self.owned.as_mut() else {
                return;
            };
            let Some(packet) = owned.outbox.front() else {
                return;
            };
            let tid = packet.tid;
            let byte_len = packet.bytes.len();
            let destination = packet.to;

            let deadline = tid
                .and_then(|tid| owned.resources.operation(tid))
                .and_then(|operation| owned.resources.owned_deadline(operation));

            #[cfg(test)]
            if owned.persistent_send_gate.is_some() {
                let released = {
                    let gate = owned
                        .persistent_send_gate
                        .as_mut()
                        .expect("persistent gate checked");
                    if gate.2.is_none() {
                        gate.2 = tid;
                    }
                    if let Some(entered) = gate.0.take() {
                        let _ = entered.send(());
                    }
                    loop {
                        tokio::select! {
                            released = &mut gate.1 => break released,
                            request = async {
                                match &mut owned.charge_probe {
                                    Some(probe) => probe.recv().await,
                                    None => std::future::pending().await,
                                }
                            } => {
                                let Some(reply) = request else {
                                    owned.charge_probe = None;
                                    continue;
                                };
                                let state = (owned.resources.datagram_count(), owned.resources.byte_count(), owned.resources.rpc_len(), self.inflight_requests.requests.len());
                                let _ = reply.send(state);
                            }
                        }
                    }
                };
                owned.persistent_send_gate = None;
                if released.is_err() {
                    return;
                }
            }

            #[cfg(test)]
            if let Some((entered, mut release)) = owned.send_gate.take() {
                let _ = entered.send(());
                loop {
                    tokio::select! {
                        released = &mut release => {
                            if released.is_err() { return; }
                            break;
                        }
                        request = async {
                            match &mut owned.charge_probe {
                                Some(probe) => probe.recv().await,
                                None => std::future::pending().await,
                            }
                        } => {
                            let Some(reply) = request else {
                                owned.charge_probe = None;
                                continue;
                            };
                            let state = (owned.resources.datagram_count(), owned.resources.byte_count(), owned.resources.rpc_len(), self.inflight_requests.requests.len());
                            let _ = reply.send(state);
                        }
                    }
                }
            }

            #[cfg(test)]
            let result = if std::mem::replace(&mut owned.send_failure, false) {
                Err(std::io::Error::other("injected owned send failure"))
            } else {
                self.io
                    .send_to_owned(&packet.bytes, destination.into(), deadline)
                    .await
            };
            #[cfg(not(test))]
            let result = self
                .io
                .send_to_owned(&packet.bytes, destination.into(), deadline)
                .await;

            let owned = self
                .owned
                .as_mut()
                .expect("owned socket remains enabled during flush");
            match result {
                Ok(()) => {
                    owned.outbox.pop_front();
                    owned.resources.sent(byte_len);
                    if let Some(tid) = tid {
                        owned.resources.rpc_sent(tid);
                        if let Some(request) = self
                            .inflight_requests
                            .requests
                            .iter_mut()
                            .find(|request| request.tid == tid)
                        {
                            request.sent_at = Instant::now();
                        }
                    }
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::TimedOut && deadline.is_some() =>
                {
                    owned.outbox.pop_front();
                    owned.resources.sent(byte_len);
                    if let Some(tid) = tid {
                        self.inflight_requests.remove(tid);
                        owned.resources.rollback_rpc(tid);
                    }
                    continue;
                }
                Err(_) => {
                    owned.outbox.pop_front();
                    owned.resources.sent(byte_len);
                    if let Some(tid) = tid {
                        self.inflight_requests.remove(tid);
                        owned.resources.rollback_rpc(tid);
                    }
                    owned.failure = Some(ResourceError::Send);
                    return;
                }
            }
        }
    }

    pub(crate) fn cancel_owned_operation(&mut self, operation: OperationId) {
        let tids = self.owned.as_ref().map_or_else(Vec::new, |owned| {
            owned.resources.cancel_operation(operation)
        });
        self.cancel_owned_transactions(&tids);
        self.retire_owned_deadline(operation);
    }

    /// Remove queued datagrams and transaction records before dropping their leases.
    /// This method requires exclusive socket access, so it cannot race a live flush future.
    pub(crate) fn cancel_owned_transactions(&mut self, tids: &[u32]) {
        let Some(owned) = self.owned.as_mut() else {
            return;
        };
        let resources = &mut owned.resources;
        owned.outbox.retain(|packet| {
            if packet.tid.is_some_and(|tid| tids.contains(&tid)) {
                resources.sent(packet.bytes.len());
                false
            } else {
                true
            }
        });
        #[cfg(test)]
        if owned
            .persistent_send_gate
            .as_ref()
            .is_some_and(|gate| gate.2.is_some_and(|tid| tids.contains(&tid)))
        {
            owned.persistent_send_gate = None;
        }
        for &tid in tids {
            self.inflight_requests.remove(tid);
            resources.rollback_rpc(tid);
        }
    }

    pub(crate) fn expire_owned_requests(&mut self, timeout: Duration) {
        let Some(owned) = self.owned.as_mut() else {
            return;
        };
        for tid in owned.resources.expired(timeout) {
            self.inflight_requests.remove(tid);
            owned.resources.rollback_rpc(tid);
        }
    }

    pub(crate) fn maintain_owned_requests(&mut self) {
        let timeout = self.inflight_requests.request_timeout();
        self.expire_owned_requests(timeout);
    }

    pub(crate) fn accept_owned_response(&mut self, tid: u32, from: SocketAddrV4) -> bool {
        self.maintain_owned_requests();
        let Some(operation) = self
            .owned
            .as_ref()
            .and_then(|owned| owned.resources.operation(tid))
        else {
            return false;
        };
        if self
            .owned_deadline(operation)
            .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
        {
            return false;
        }
        if !self
            .owned
            .as_ref()
            .is_some_and(|owned| owned.resources.matches_response(tid, from))
        {
            return false;
        }
        if self.inflight_requests.remove(tid).is_none() {
            self.owned
                .as_mut()
                .expect("owned response owner retained")
                .resources
                .rollback_rpc(tid);
            return false;
        }
        let completed = self
            .owned
            .as_mut()
            .expect("owned response owner retained")
            .resources
            .complete_rpc(tid, from);
        debug_assert!(
            completed,
            "validated owned response remains admitted until completion"
        );
        self.owned
            .as_mut()
            .expect("owned response owner retained")
            .last_response = Some((tid, operation));
        true
    }

    pub(crate) fn owned_inflight(&self, tid: u32) -> bool {
        self.owned
            .as_ref()
            .is_some_and(|owned| owned.resources.operation(tid).is_some())
    }

    pub(crate) fn owned_response_operation(&self) -> Option<(u32, OperationId)> {
        self.owned.as_ref()?.last_response
    }

    pub(crate) fn owned_failure(&self) -> Option<ResourceError> {
        self.owned.as_ref()?.failure
    }

    pub(crate) fn take_owned_failure(&mut self) -> Option<ResourceError> {
        self.owned.as_mut()?.failure.take()
    }

    #[cfg(test)]
    pub(crate) fn owned_test_state(&self) -> Option<(usize, usize, usize, usize)> {
        let owned = self.owned.as_ref()?;
        Some((
            owned.resources.datagram_count(),
            owned.resources.byte_count(),
            owned.resources.rpc_len(),
            self.inflight_requests.requests.len(),
        ))
    }

    #[cfg(test)]
    pub(crate) fn fail_next_encode_for_test(&mut self) {
        self.owned
            .get_or_insert_with(OwnedSocket::default)
            .encode_failure = true;
    }

    #[cfg(test)]
    pub(crate) fn fail_next_enqueue_for_test(&mut self) {
        self.owned
            .get_or_insert_with(OwnedSocket::default)
            .enqueue_failure = true;
    }

    #[cfg(test)]
    pub(crate) fn fail_next_send_for_test(&mut self) {
        self.owned
            .get_or_insert_with(OwnedSocket::default)
            .send_failure = true;
    }

    #[cfg(test)]
    pub(crate) fn install_owned_charge_probe_for_test(
        &mut self,
        receiver: tokio::sync::mpsc::Receiver<
            tokio::sync::oneshot::Sender<(usize, usize, usize, usize)>,
        >,
    ) {
        self.owned
            .get_or_insert_with(OwnedSocket::default)
            .charge_probe = Some(receiver);
    }

    #[cfg(test)]
    pub(crate) fn hold_next_persistent_send_for_test(
        &mut self,
        entered: tokio::sync::oneshot::Sender<()>,
        release: tokio::sync::oneshot::Receiver<()>,
    ) {
        self.owned
            .get_or_insert_with(OwnedSocket::default)
            .persistent_send_gate = Some((Some(entered), release, None));
    }

    #[cfg(test)]
    pub(crate) fn hold_next_send_for_test(
        &mut self,
        entered: tokio::sync::oneshot::Sender<()>,
        release: tokio::sync::oneshot::Receiver<()>,
    ) {
        self.owned
            .get_or_insert_with(OwnedSocket::default)
            .send_gate = Some((entered, release));
    }

    #[cfg(test)]
    pub(crate) fn owned_counts(&self) -> Option<(usize, usize, usize)> {
        let owned = self.owned.as_ref()?;
        Some((
            owned.resources.datagram_count(),
            owned.resources.byte_count(),
            owned.resources.rpc_len(),
        ))
    }

    #[cfg(test)]
    pub(crate) fn operation_rpc_len(&self, operation: OperationId) -> usize {
        self.owned
            .as_ref()
            .map_or(0, |owned| owned.resources.operation_rpc_len(operation))
    }
}
