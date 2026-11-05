// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test composition for bounded signaling before a native recovery attempt.

use tokio::time::{Instant, timeout_at};

use super::owner::{DialError, Dialer};

pub(crate) trait Negotiation: Dialer {
    /// Negotiate control only; any control session must close before returning.
    /// cancel-safe: NO — admitted work remains backend-owned until joined shutdown.
    async fn negotiate(&mut self, deadline: Instant) -> Result<(), DialError>;
}

pub(crate) struct Negotiating<D> {
    inner: D,
    // Loss history, not current liveness; healthy payload never triggers another dial.
    down: bool,
}

impl<D> Negotiating<D> {
    pub(crate) fn new(inner: D) -> Self {
        Self { inner, down: false }
    }
}

impl<D: Negotiation> Dialer for Negotiating<D> {
    type Link = D::Link;

    async fn dial(&mut self, deadline: Instant) -> Result<Self::Link, DialError> {
        let now = Instant::now();
        if now >= deadline {
            return Err(DialError);
        }
        if self.down {
            let limit = now + deadline.duration_since(now) / 2;
            // Signaling is best effort; its failure never skips the native phase.
            let _ = timeout_at(limit, self.inner.negotiate(limit)).await;
        }
        self.inner.dial(deadline).await
    }

    async fn lost(&mut self, link: &Self::Link) {
        self.inner.lost(link).await;
        self.down = true;
    }

    async fn close(&mut self) -> Result<(), DialError> {
        self.inner.close().await
    }
}
