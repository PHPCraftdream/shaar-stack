// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::*;

impl super::super::KrpcSocket {
    pub(crate) fn owned_test_state(&self) -> Option<(usize, usize, usize, usize)> {
        let owned = self.owned.as_ref()?;
        Some((
            owned.resources.datagram_count(),
            owned.resources.byte_count(),
            owned.resources.rpc_len(),
            self.inflight_requests.requests.len(),
        ))
    }

    pub(crate) fn fail_next_encode_for_test(&mut self) {
        self.owned
            .get_or_insert_with(OwnedSocket::default)
            .encode_failure = true;
    }

    pub(crate) fn fail_next_enqueue_for_test(&mut self) {
        self.owned
            .get_or_insert_with(OwnedSocket::default)
            .enqueue_failure = true;
    }

    pub(crate) fn fail_next_send_for_test(&mut self) {
        self.owned
            .get_or_insert_with(OwnedSocket::default)
            .send_failure = true;
    }

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

    pub(crate) fn hold_next_persistent_send_for_test(
        &mut self,
        entered: tokio::sync::oneshot::Sender<()>,
        release: tokio::sync::oneshot::Receiver<()>,
    ) {
        self.owned
            .get_or_insert_with(OwnedSocket::default)
            .persistent_send_gate = Some((Some(entered), release, None));
    }

    pub(crate) fn hold_next_send_for_test(
        &mut self,
        entered: tokio::sync::oneshot::Sender<()>,
        release: tokio::sync::oneshot::Receiver<()>,
    ) {
        self.owned
            .get_or_insert_with(OwnedSocket::default)
            .send_gate = Some((entered, release));
    }

    pub(crate) fn owned_counts(&self) -> Option<(usize, usize, usize)> {
        let owned = self.owned.as_ref()?;
        Some((
            owned.resources.datagram_count(),
            owned.resources.byte_count(),
            owned.resources.rpc_len(),
        ))
    }

    pub(crate) fn owned_put_deadline_for_test(
        &self,
        target: crate::Id,
    ) -> Option<tokio::time::Instant> {
        self.owned.as_ref()?.resources.owned_put_deadline(target)
    }

    pub(crate) fn exhaust_owned_transactions_for_test(&mut self) {
        self.inflight_requests.next_tid = u32::MAX - 1;
    }

    pub(crate) fn operation_rpc_len(&self, operation: OperationId) -> usize {
        self.owned
            .as_ref()
            .map_or(0, |owned| owned.resources.operation_rpc_len(operation))
    }
}
