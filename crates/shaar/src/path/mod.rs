// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
//! Path policy of the first version: which path carries payload and when to retry.
//!
//! The policy is a pure state machine with an injected monotonic clock and no I/O,
//! so every deadline and interleaving is checked by event traces. In `signal` mode
//! payload stays on the native path; in `standby` mode Yggdrasil may carry it while
//! the native path is unavailable. libp2p never carries application data and is not
//! a payload path here. The owner drives the policy with real time and a native dialer;
//! signaling and Yggdrasil are wired by later leaves.

mod model;
mod owner;
mod policy;

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use owner::{DialError, Dialer, PathOwner};

#[cfg(test)]
pub(crate) use model::{ConfigError, Decision, Event, Millis, Mode, PathKind, PolicyConfig};
#[cfg(test)]
use policy::PathPolicy;
