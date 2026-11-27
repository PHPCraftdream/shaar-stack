// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

//! Adaptive departure pacing of the owned requests (leaf PACE-1). A device whose answers come
//! back is never slowed. When the answered share of a window of requests collapses, requests
//! leave on a token-bucket schedule, and the rate recovers as the answers do. Pure state: the
//! socket asks when the next request may leave and reports what became of the ones that left.

use std::time::Duration;

use tokio::time::Instant;
use tracing::debug;

/// Outcomes judged together.
pub(super) const WINDOW: u32 = 16;
/// An answered share below this percentage engages the pacing.
const ENGAGE_BELOW_PCT: u32 = 20;
/// An answered share at or above this percentage speeds a paced schedule up.
const RELEASE_AT_PCT: u32 = 60;
/// Requests per second a first collapse starts at.
const START_RATE: u32 = 25;
/// Lowest rate, requests per second.
const FLOOR_RATE: u32 = 10;
/// Requests per second added for each good window.
const STEP_RATE: u32 = 5;
/// A rate above this, requests per second, is unpaced again.
const UNPACED_ABOVE: u32 = 45;
/// Requests that may leave together at a paced rate.
const BURST: u32 = 4;

#[derive(Debug, Default)]
pub(super) struct Pacer {
    /// Requests per second; `None` while unpaced.
    rate: Option<u32>,
    /// Theoretical arrival time of the next request (the cell-rate algorithm); `None` while unpaced.
    theoretical: Option<Instant>,
    seen: u32,
    answered: u32,
}

fn interval(rate: u32) -> Duration {
    Duration::from_micros(1_000_000 / u64::from(rate))
}

impl Pacer {
    #[cfg(test)]
    pub(super) fn rate(&self) -> Option<u32> {
        self.rate
    }

    /// When the next request may leave; `None` when it may leave now.
    pub(super) fn wait_until(&self, now: Instant) -> Option<Instant> {
        let (rate, theoretical) = (self.rate?, self.theoretical?);
        let earliest = theoretical
            .checked_sub(interval(rate) * (BURST - 1))
            .unwrap_or(now);
        (now < earliest).then_some(earliest)
    }

    /// Records that one request left at `now`.
    pub(super) fn departed(&mut self, now: Instant) {
        if let Some(rate) = self.rate {
            let base = self
                .theoretical
                .map_or(now, |theoretical| theoretical.max(now));
            self.theoretical = Some(base + interval(rate));
        }
    }

    /// Records what became of one request that left; `true` when the rate changed.
    pub(super) fn observe(&mut self, answered: bool) -> bool {
        self.seen += 1;
        self.answered += u32::from(answered);
        if self.seen < WINDOW {
            return false;
        }
        let share = self.answered * 100 / self.seen;
        self.seen = 0;
        self.answered = 0;
        let before = self.rate;
        self.rate = if share < ENGAGE_BELOW_PCT {
            Some(
                self.rate
                    .map_or(START_RATE, |rate| (rate / 2).max(FLOOR_RATE)),
            )
        } else if share >= RELEASE_AT_PCT {
            self.rate
                .map(|rate| rate + STEP_RATE)
                .filter(|rate| *rate <= UNPACED_ABOVE)
        } else {
            self.rate
        };
        if self.rate.is_none() {
            self.theoretical = None;
        }
        let changed = self.rate != before;
        if changed {
            debug!(rate = ?self.rate.unwrap_or(0), share_pct = ?share, "Owned pace");
        }
        changed
    }
}
