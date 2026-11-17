//! Mainline bootstrap entries: numeric IPv4 endpoints or DNS host names.
//!
//! Host names are checked syntactically here and resolved once by the
//! composed startup (`startup::resolve`); configuration loading stays free
//! of network I/O.

use std::net::SocketAddrV4;
use std::str::FromStr;

use super::super::error::{ConfigError, ValidationKind};

/// RFC 1035 bounds on a whole name and on one label.
const MAX_NAME: usize = 253;
const MAX_LABEL: usize = 63;

/// One bootstrap host name with its port, resolved at composed startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapHost {
    name: String,
    port: u16,
}

impl BootstrapHost {
    /// The DNS name as written in the configuration.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The nonzero UDP port of the bootstrap node.
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// A parsed entry before it is sorted into numeric endpoints and host names.
pub(super) enum Entry {
    Addr(SocketAddrV4),
    Host(BootstrapHost),
}

/// Parses one `ip:port` or `host:port` entry; values are never echoed.
pub(super) fn parse_entry(field: &'static str, text: &str) -> Result<Entry, ConfigError> {
    let invalid = |kind| ConfigError::validation(field, kind);
    if let Ok(addr) = SocketAddrV4::from_str(text) {
        if addr.port() == 0 {
            return Err(invalid(ValidationKind::InvalidPort));
        }
        let ip = *addr.ip();
        if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
            return Err(invalid(ValidationKind::InvalidAddress));
        }
        return Ok(Entry::Addr(addr));
    }
    let (name, port) = text
        .rsplit_once(':')
        .ok_or_else(|| invalid(ValidationKind::InvalidAddress))?;
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(ValidationKind::InvalidAddress));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| invalid(ValidationKind::InvalidAddress))?;
    if port == 0 {
        return Err(invalid(ValidationKind::InvalidPort));
    }
    if !host_name_wellformed(name) {
        return Err(invalid(ValidationKind::InvalidAddress));
    }
    Ok(Entry::Host(BootstrapHost {
        name: name.to_owned(),
        port,
    }))
}

/// LDH host name: labels of ASCII letters, digits and inner hyphens, at most
/// 63 bytes each and 253 in total. An all-digit last label is refused, so a
/// malformed IPv4 literal never passes as a name.
fn host_name_wellformed(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_NAME {
        return false;
    }
    let mut last = "";
    for label in name.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty()
            || bytes.len() > MAX_LABEL
            || bytes[0] == b'-'
            || bytes[bytes.len() - 1] == b'-'
            || !bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return false;
        }
        last = label;
    }
    !last.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
pub(super) fn host_for_tests(name: &str, port: u16) -> BootstrapHost {
    BootstrapHost {
        name: name.to_owned(),
        port,
    }
}
