// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

// Shared wire behavior stays test-only; production-codec conversion stays here.
#[path = "fixture/wire.rs"]
mod wire;

use std::net::SocketAddr;

pub(crate) use wire::{CapturedPut, LoopbackPeer};

impl LoopbackPeer {
    pub(crate) async fn capture_put_record(
        &mut self,
    ) -> (
        SocketAddr,
        Vec<u8>,
        iroh_dns::pkarr::SignedPacket,
        n0_mainline::MutableItem,
    ) {
        let (source, transaction, captured) = self.capture_put().await;
        (
            source,
            transaction,
            captured.signed_packet(),
            captured.to_mutable_item(),
        )
    }
}

impl CapturedPut {
    pub(crate) fn to_mutable_item(&self) -> n0_mainline::MutableItem {
        super::super::to_mutable(
            &crate::native_discovery::runtime::publisher::SignedSnapshot {
                timestamp_us: self.sequence,
                bytes: self.signed_envelope(),
            },
        )
        .expect("captured signed packet converts through production helper")
    }
}
