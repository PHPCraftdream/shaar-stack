// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

//! Validated in-memory options for the opt-in native discovery endpoint.
//! Validation is pure: it binds nothing and never echoes values or key material.

use std::fmt;
use std::net::SocketAddrV4;
use std::time::Duration;

use crate::identity::Identity;

const MAX_BOOTSTRAP: usize = 4;

/// Longest one record lookup may run. A live lookup needs 6 to 10 s: with a 10 s bound it failed
/// with `deadline` every time (live attempt of 2026-11-17).
pub(crate) const LOOKUP_BOUND: Duration = Duration::from_secs(30);
/// Longest one publication may run: the closest-nodes phase of a put takes as long as a lookup and
/// the put round follows it; with a 10 s bound five publications in a row failed with `deadline`.
pub(crate) const PUBLISH_BOUND: Duration = Duration::from_secs(45);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::native_discovery) enum NativeOptionField {
    Bootstrap,
    BootstrapPort,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::native_discovery) enum NativeOptionReason {
    Empty,
    TooMany,
    ZeroPort,
    Unusable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::native_discovery) struct InvalidOption {
    pub(in crate::native_discovery) field: NativeOptionField,
    pub(in crate::native_discovery) reason: NativeOptionReason,
}

/// One identity serves both backends; numeric IPv4 endpoints only, no DNS names.
pub(in crate::native_discovery) struct NativeDiscoveryOptions {
    identity: Identity,
    bind: SocketAddrV4,
    bootstrap: Vec<SocketAddrV4>,
}

impl fmt::Debug for NativeDiscoveryOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeDiscoveryOptions")
            .field("bootstrap", &self.bootstrap.len())
            .finish_non_exhaustive()
    }
}

impl NativeDiscoveryOptions {
    /// Bootstrap needs 1 to 4 raw entries (counted before any deduplication),
    /// each with a nonzero port and a usable destination; the bind port may be 0.
    pub(in crate::native_discovery) fn new(
        identity: Identity,
        bind: SocketAddrV4,
        bootstrap: &[SocketAddrV4],
    ) -> Result<Self, InvalidOption> {
        let invalid = |field, reason| InvalidOption { field, reason };
        if bootstrap.is_empty() {
            return Err(invalid(
                NativeOptionField::Bootstrap,
                NativeOptionReason::Empty,
            ));
        }
        if bootstrap.len() > MAX_BOOTSTRAP {
            return Err(invalid(
                NativeOptionField::Bootstrap,
                NativeOptionReason::TooMany,
            ));
        }
        for address in bootstrap {
            if address.port() == 0 {
                return Err(invalid(
                    NativeOptionField::BootstrapPort,
                    NativeOptionReason::ZeroPort,
                ));
            }
            let ip = address.ip();
            if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
                return Err(invalid(
                    NativeOptionField::Bootstrap,
                    NativeOptionReason::Unusable,
                ));
            }
        }
        Ok(Self {
            identity,
            bind,
            bootstrap: bootstrap.to_vec(),
        })
    }

    pub(super) fn identity(&self) -> &Identity {
        &self.identity
    }

    pub(super) fn bind(&self) -> SocketAddrV4 {
        self.bind
    }

    pub(super) fn bootstrap(&self) -> &[SocketAddrV4] {
        &self.bootstrap
    }
}

#[cfg(test)]
mod bound_tests {
    use super::*;

    #[test]
    fn the_live_dht_bounds_outlast_a_live_lookup_and_a_publication_outlasts_a_lookup() {
        // A live lookup needs 6 to 10 s; the old 10 s bound failed every live attempt.
        assert!(LOOKUP_BOUND >= Duration::from_secs(20));
        assert!(PUBLISH_BOUND > LOOKUP_BOUND);
    }
}
