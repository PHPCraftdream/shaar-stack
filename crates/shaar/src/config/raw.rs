//! Internal raw schemas and shared validation helpers.
//!
//! The raw shapes deserialize leniently (all fields `Option`), then
//! explicit merge-and-validate constructors produce the public,
//! validated config types. Raw shapes are crate-private, so raw
//! deserialization alone cannot yield a public config value.
//!
//! Raw fields are optional strings, not an untyped document AST. Syntax,
//! field types, and unknown fields must pass deserialization before merging.
//! Semantic string validation follows the CLI override, so `fallback: bogus`
//! can be repaired by a typed override through [`parse_fallback`].

use super::error::{ConfigError, ValidationKind};

/// Fallback transport selection.
///
/// Meaning of the two modes:
/// - [`Fallback::Signal`] selects alternative-path *negotiation only*:
///   it arranges a signaling path but never carries application data.
/// - [`Fallback::Standby`] (the default) permits the Yggdrasil
///   DATA-path fallback when the direct transport is unavailable.
///
/// libp2p is never an application-data fallback under either mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Fallback {
    /// Alternative-path negotiation only; carries no application data.
    Signal,
    /// Permits the Yggdrasil DATA fallback when direct is unavailable.
    #[default]
    Standby,
}

/// Validate and convert a fallback selection after merging.
///
/// `raw` is the unvalidated file value (if present), `over` the typed
/// CLI override (if present). The typed override wins outright; only
/// a file value actually chosen for use is validated here, so an
/// invalid file value is repairable by a valid override. An invalid
/// chosen value yields `ConfigError::Validation { field: "fallback",
/// kind: InvalidEnum }`.
pub(crate) fn parse_fallback(
    raw: Option<&str>,
    over: Option<Fallback>,
) -> Result<Fallback, ConfigError> {
    match over {
        Some(f) => Ok(f),
        None => match raw {
            None => Ok(Fallback::default()),
            Some("signal") => Ok(Fallback::Signal),
            Some("standby") => Ok(Fallback::Standby),
            Some(_) => Err(ConfigError::validation(
                "fallback",
                ValidationKind::InvalidEnum,
            )),
        },
    }
}

/// Parse a socket address string for the given schema field.
pub(crate) fn parse_socket_addr(
    field: &'static str,
    value: &str,
) -> Result<std::net::SocketAddr, ConfigError> {
    value
        .parse()
        .map_err(|_| ConfigError::validation(field, ValidationKind::InvalidAddress))
}

/// Require that the address is loopback for the given schema field.
pub(crate) fn require_loopback(
    field: &'static str,
    addr: std::net::SocketAddr,
) -> Result<(), ConfigError> {
    if addr.ip().is_loopback() {
        Ok(())
    } else {
        Err(ConfigError::validation(field, ValidationKind::NotLoopback))
    }
}

/// Require that a numeric destination is usable by the SDK dial boundary.
pub(crate) fn require_dial_destination(
    field: &'static str,
    addr: std::net::SocketAddr,
) -> Result<(), ConfigError> {
    let ip = addr.ip().to_canonical();
    if addr.port() != 0
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && ip != std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
        && match ip {
            std::net::IpAddr::V4(_) => true,
            std::net::IpAddr::V6(ip) => ip.octets()[..6] != [0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b],
        }
    {
        Ok(())
    } else {
        Err(ConfigError::validation(
            field,
            ValidationKind::InvalidAddress,
        ))
    }
}

/// Reject empty path values after merging (a present-but-empty path is
/// semantically invalid, not a missing field).
pub(crate) fn require_nonempty_path(
    field: &'static str,
    path: &std::path::Path,
) -> Result<(), ConfigError> {
    if path.as_os_str().is_empty() {
        Err(ConfigError::validation(field, ValidationKind::EmptyPath))
    } else {
        Ok(())
    }
}

/// Merge an explicitly supplied override over the file value.
pub(crate) fn merge<T: Clone>(file: Option<T>, over: Option<T>) -> Option<T> {
    over.or(file)
}
