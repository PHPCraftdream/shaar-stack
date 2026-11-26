// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

//! The read side of the relay protocol (leaf PKARR-4): one `GET` of a signed record per public
//! pkarr relay, started beside the DHT lookup of the same key.
//!
//! A relay does the DHT walk from a well-connected host and answers with the signed packet, which
//! the caller verifies as any other record, so an untrusted relay can withhold a record or serve
//! an old one but never forge one. Nothing here decodes a packet: an answer is bytes and a class.
//! A request lives in the `RelayRead` of one lookup and ends with it (no task, no detach). The
//! per-relay budget lives in the reader, which the owner (a single task) holds by `&mut`.

use std::time::Duration;

use futures::future::BoxFuture;
use futures::stream::{FuturesUnordered, StreamExt};
use iroh_base::EndpointId;
use tokio::time::Instant;

use super::client::{Fetched, RelayClient, http_client};
use super::{MAX_RELAYS, MirrorSpec, RelayUrl};
use crate::network::observe::emit;

/// Requests to one relay per window (the window is the interval of the mirror's timing): the
/// bound of the mirror's own traffic, far below the smallest limit a relay announces.
const READS_PER_WINDOW: usize = 3;

/// The budget of one relay: the window it was opened in and the requests spent in it, and the
/// time until which a `429` silences it.
#[derive(Default)]
pub(super) struct Budget {
    opened: Option<Instant>,
    spent: usize,
    silenced_until: Option<Instant>,
}

impl Budget {
    /// Whether one more request may go to this relay now, and the spending of it.
    fn admit(&mut self, now: Instant, window: Duration) -> bool {
        if self.silenced_until.is_some_and(|until| now < until) {
            return false;
        }
        match self.opened {
            Some(opened) if now < opened + window => {}
            _ => {
                self.opened = Some(now);
                self.spent = 0;
            }
        }
        if self.spent >= READS_PER_WINDOW {
            return false;
        }
        self.spent += 1;
        true
    }

    fn silence(&mut self, now: Instant, window: Duration) {
        self.silenced_until = Some(now + window);
    }
}

/// One answer of one relay, with the position of the relay in the configured list and the time
/// since the request started.
pub(in crate::native_discovery::runtime) struct Answer {
    pub(in crate::native_discovery::runtime) index: usize,
    pub(in crate::native_discovery::runtime) fetched: Fetched,
    pub(in crate::native_discovery::runtime) elapsed: Duration,
}

/// The payload-free trace line of one answer: the relay's position, the class (`token`) and the
/// time. Never a key, an address, a body or remote text.
pub(in crate::native_discovery::runtime) fn read_line(
    index: usize,
    token: &str,
    elapsed: Duration,
) -> String {
    format!(
        "shaar: pkarr read relay={index} result={token} ms={}",
        elapsed.as_millis()
    )
}

/// The reads of one lookup. Dropping it cancels every request still in flight.
pub(in crate::native_discovery::runtime) struct RelayRead {
    pending: FuturesUnordered<BoxFuture<'static, Answer>>,
}

impl RelayRead {
    /// The next answer, or `None` once every request is answered.
    pub(in crate::native_discovery::runtime) async fn next(&mut self) -> Option<Answer> {
        self.pending.next().await
    }

    /// Whether no request is left in flight.
    pub(in crate::native_discovery::runtime) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

/// The relays a Client may read its record from, with their budgets.
pub(in crate::native_discovery::runtime) struct RelayReader {
    pub(super) http: reqwest::Client,
    pub(super) relays: Vec<RelayUrl>,
    pub(super) budgets: Vec<Budget>,
    window: Duration,
}

impl RelayReader {
    /// `None` when there is no relay or no client could be built: nothing is created.
    pub(in crate::native_discovery::runtime) fn start(spec: MirrorSpec<'_>) -> Option<Self> {
        let MirrorSpec { relays, timing } = spec;
        if relays.is_empty() {
            return None;
        }
        let Some(http) = http_client(timing.request_bound) else {
            emit("shaar: pkarr read off reason=client".to_owned());
            return None;
        };
        let relays: Vec<RelayUrl> = relays.iter().take(MAX_RELAYS).cloned().collect();
        let budgets = relays.iter().map(|_| Budget::default()).collect();
        Some(Self {
            http,
            relays,
            budgets,
            window: timing.interval,
        })
    }

    /// Starts one `GET` of `key` at every relay whose budget admits it. The requests run when the
    /// returned `RelayRead` is polled.
    pub(in crate::native_discovery::runtime) fn begin(
        &mut self,
        key: EndpointId,
        now: Instant,
    ) -> RelayRead {
        let pending = FuturesUnordered::new();
        for (index, (relay, budget)) in self.relays.iter().zip(&mut self.budgets).enumerate() {
            if !budget.admit(now, self.window) {
                continue;
            }
            let client = RelayClient::new(self.http.clone(), relay, key);
            pending.push(Box::pin(async move {
                let started = Instant::now();
                let fetched = client.get().await;
                Answer {
                    index,
                    fetched,
                    elapsed: started.elapsed(),
                }
            }) as BoxFuture<'static, Answer>);
        }
        RelayRead { pending }
    }

    /// A relay said `429`: no request goes to it for one window.
    pub(in crate::native_discovery::runtime) fn silence(&mut self, index: usize, now: Instant) {
        if let Some(budget) = self.budgets.get_mut(index) {
            budget.silence(now, self.window);
        }
    }
}
