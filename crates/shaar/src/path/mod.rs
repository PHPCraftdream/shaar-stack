// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
//! Path policy of the first version: which path carries payload and when to retry.
//!
//! The policy is a pure state machine with an injected monotonic clock and no I/O,
//! so every deadline and interleaving is checked by event traces. In `signal` mode
//! payload stays on the native path; in `standby` mode Yggdrasil may carry it while
//! the native path is unavailable. libp2p never carries application data and is not
//! a payload path here. The owner drives the policy with real time, a native dialer
//! and, in standby, a fallback (Yggdrasil) dialer behind the same `Dialer` seam.
//! Startup and discovery composition and the efficiency acceptance are later leaves.

mod model;
mod owner;
mod policy;
mod standby;

#[cfg(test)]
mod negotiation;
#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) use negotiation::{Negotiating, Negotiation};

#[cfg(test)]
pub(crate) use owner::PathOwner;
pub(crate) use owner::{DialError, Dialer};
// The startup role modules consume these through this re-export; the standby
// child module itself stays private.
#[cfg(test)]
pub(crate) use standby::NativeObservation;
pub(crate) use standby::{Route, StandbyError, StandbyOwner};

pub(crate) use model::{ConfigError, Mode, PathKind, PolicyConfig};
// Used only by the path trace fixtures via this re-export; kept gated so the
// production build does not carry the unused re-export.
#[cfg(test)]
pub(crate) use model::{Decision, Event, Millis};
#[cfg(test)]
use policy::PathPolicy;
