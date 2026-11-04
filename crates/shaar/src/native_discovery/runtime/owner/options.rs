// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

//! Validated in-memory options for the opt-in native discovery endpoint.
//! Validation is pure: it binds nothing and never echoes values or key material.

use std::fmt;
use std::net::SocketAddrV4;

use crate::identity::Identity;

const MAX_BOOTSTRAP: usize = 4;

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
