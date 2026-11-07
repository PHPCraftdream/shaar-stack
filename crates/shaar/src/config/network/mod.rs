//! Optional shared network settings schema (ktav 0.8.*) for both roles.
//!
//! One optional `network` object may appear in either the server or the
//! client file. Its absence keeps the legacy direct-only contract and is
//! NOT an error at parse level (composed startup in a later leaf requires
//! it). No public default peers are provided or contacted; validation is
//! pure, happens before any network I/O, and never echoes rejected values.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;

use libp2p_identity::PeerId;
use serde::Deserialize;
use url::Url;

use super::error::{ConfigError, ValidationKind};
use super::raw::{parse_socket_addr, require_dial_destination};

/// Matches `native_discovery/runtime/owner/options.rs`: bootstrap
/// accepts 1..=4 raw entries (counted before deduplication).
const MAX_BOOTSTRAP: usize = 4;
/// Yggdrasil peer list bound, mirroring the bootstrap bound above.
const MAX_YGG_PEERS: usize = 4;

// ---------------------------------------------------------------------------
// Raw file shapes (crate-private, unvalidated)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkFile {
    #[serde(default)]
    mainline: Option<MainlineFile>,
    #[serde(default)]
    signaling: Option<SignalingFile>,
    #[serde(default)]
    ygg: Option<YggFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MainlineFile {
    #[serde(default)]
    bind: Option<String>,
    #[serde(default)]
    bootstrap: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignalingFile {
    #[serde(default)]
    bind: Option<String>,
    #[serde(default)]
    relay: Option<String>,
    #[serde(default)]
    relay_address: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct YggFile {
    #[serde(default)]
    peers: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Validated public types
// ---------------------------------------------------------------------------

/// Validated shared network settings.
#[derive(Clone, PartialEq, Eq)]
pub struct NetworkSettings {
    mainline: Option<MainlineNetwork>,
    signaling: Option<SignalingNetwork>,
    ygg: Option<YggNetwork>,
}

impl fmt::Debug for NetworkSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Yggdrasil peer URIs can carry secrets: render only a count.
        f.debug_struct("NetworkSettings")
            .field("mainline", &self.mainline)
            .field("signaling", &self.signaling)
            .field("ygg", &self.ygg.as_ref().map(|y| y.peers.len()))
            .finish()
    }
}

impl NetworkSettings {
    /// Mainline (DHT discovery) settings, when present.
    pub fn mainline(&self) -> Option<&MainlineNetwork> {
        self.mainline.as_ref()
    }

    /// Signaling relay settings, when present.
    pub fn signaling(&self) -> Option<&SignalingNetwork> {
        self.signaling.as_ref()
    }

    /// Yggdrasil peer settings, when present.
    pub fn ygg(&self) -> Option<&YggNetwork> {
        self.ygg.as_ref()
    }
}

/// Validated Mainline discovery settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainlineNetwork {
    bind: SocketAddrV4,
    bootstrap: Vec<SocketAddrV4>,
}

impl MainlineNetwork {
    /// Mainline bind address (IPv4 only); port 0 requests an OS port.
    pub fn bind(&self) -> SocketAddrV4 {
        self.bind
    }

    /// Bootstrap node endpoints (1..=4 entries).
    pub fn bootstrap(&self) -> &[SocketAddrV4] {
        &self.bootstrap
    }
}

/// Validated signaling relay settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalingNetwork {
    bind: SocketAddr,
    relay_peer_id: PeerId,
    relay_address: SocketAddr,
}

impl SignalingNetwork {
    /// Signaling bind address; port 0 requests an OS port.
    pub fn bind(&self) -> SocketAddr {
        self.bind
    }

    /// Public peer id of the relay node.
    pub fn relay_peer_id(&self) -> &PeerId {
        &self.relay_peer_id
    }

    /// Numeric relay destination address.
    pub fn relay_address(&self) -> SocketAddr {
        self.relay_address
    }
}

/// Validated Yggdrasil peer settings; URIs are pre-checked only and are
/// never echoed in diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct YggNetwork {
    peers: Vec<String>,
}

impl fmt::Debug for YggNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Peer URIs can carry secrets: render only the count.
        write!(f, "YggNetwork {{ peers: {} }}", self.peers.len())
    }
}

impl YggNetwork {
    /// Supported Yggdrasil peer URIs (1..=4 entries).
    pub fn peers(&self) -> &[String] {
        &self.peers
    }
}

// ---------------------------------------------------------------------------
// Pure validation (no network I/O; values are never echoed)
// ---------------------------------------------------------------------------

/// Parse an IPv4-only socket address for `field` (a v6 spelling is
/// rejected as `InvalidAddress`).
fn parse_socket_addr_v4(field: &'static str, value: &str) -> Result<SocketAddrV4, ConfigError> {
    match SocketAddrV4::from_str(value) {
        Ok(addr) => Ok(addr),
        Err(_) => Err(ConfigError::validation(
            field,
            ValidationKind::InvalidAddress,
        )),
    }
}

/// Validate the shared network object; `None` keeps the legacy
/// direct-only contract.
pub(crate) fn parse(raw: Option<NetworkFile>) -> Result<Option<NetworkSettings>, ConfigError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let mainline = match raw.mainline {
        Some(mainline) => Some(parse_mainline(mainline)?),
        None => {
            return Err(ConfigError::validation(
                "network.mainline",
                ValidationKind::MissingRequired,
            ));
        }
    };
    let signaling = match raw.signaling {
        Some(signaling) => Some(parse_signaling(signaling)?),
        None => {
            return Err(ConfigError::validation(
                "network.signaling",
                ValidationKind::MissingRequired,
            ));
        }
    };
    let ygg = match raw.ygg {
        Some(ygg) => Some(parse_ygg(ygg)?),
        None => {
            return Err(ConfigError::validation(
                "network.ygg",
                ValidationKind::MissingRequired,
            ));
        }
    };
    Ok(Some(NetworkSettings {
        mainline,
        signaling,
        ygg,
    }))
}

fn parse_mainline(raw: MainlineFile) -> Result<MainlineNetwork, ConfigError> {
    const FIELD_BIND: &str = "network.mainline.bind";
    const FIELD_BOOTSTRAP: &str = "network.mainline.bootstrap";

    let bind = match &raw.bind {
        Some(text) => parse_socket_addr_v4(FIELD_BIND, text)?,
        // Port 0 and the wildcard address are allowed here.
        None => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
    };

    let entries = raw
        .bootstrap
        .as_ref()
        .ok_or_else(|| ConfigError::validation(FIELD_BOOTSTRAP, ValidationKind::MissingRequired))?;
    if entries.is_empty() {
        return Err(ConfigError::validation(
            FIELD_BOOTSTRAP,
            ValidationKind::TooFew,
        ));
    }
    if entries.len() > MAX_BOOTSTRAP {
        return Err(ConfigError::validation(
            FIELD_BOOTSTRAP,
            ValidationKind::TooMany,
        ));
    }
    let mut bootstrap = Vec::with_capacity(entries.len());
    for entry in entries {
        let addr = parse_socket_addr_v4(FIELD_BOOTSTRAP, entry)?;
        if addr.port() == 0 {
            return Err(ConfigError::validation(
                FIELD_BOOTSTRAP,
                ValidationKind::InvalidPort,
            ));
        }
        let ip = *addr.ip();
        if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
            return Err(ConfigError::validation(
                FIELD_BOOTSTRAP,
                ValidationKind::InvalidAddress,
            ));
        }
        bootstrap.push(addr);
    }
    Ok(MainlineNetwork { bind, bootstrap })
}

fn parse_signaling(raw: SignalingFile) -> Result<SignalingNetwork, ConfigError> {
    const FIELD_BIND: &str = "network.signaling.bind";
    const FIELD_RELAY: &str = "network.signaling.relay";
    const FIELD_RELAY_ADDRESS: &str = "network.signaling.relay_address";

    let bind = match &raw.bind {
        Some(text) => parse_socket_addr(FIELD_BIND, text)?,
        None => SocketAddr::from_str("0.0.0.0:0").expect("static wildcard literal parses"),
    };

    let relay_text = raw
        .relay
        .as_deref()
        .ok_or_else(|| ConfigError::validation(FIELD_RELAY, ValidationKind::MissingRequired))?;
    let relay_peer_id = PeerId::from_str(relay_text)
        .map_err(|_| ConfigError::validation(FIELD_RELAY, ValidationKind::InvalidKey))?;

    let relay_text = raw.relay_address.as_deref().ok_or_else(|| {
        ConfigError::validation(FIELD_RELAY_ADDRESS, ValidationKind::MissingRequired)
    })?;
    let relay_address = parse_socket_addr(FIELD_RELAY_ADDRESS, relay_text)?;
    require_dial_destination(FIELD_RELAY_ADDRESS, relay_address)?;

    Ok(SignalingNetwork {
        bind,
        relay_peer_id,
        relay_address,
    })
}

/// Composed-infrastructure peer-URI validation using the SAME URL parser the
/// pinned backend uses (`url::Url`, locked 2.5.8): a full URL parse, scheme
/// `tcp`/`tls`, a required nonempty host, and an explicit nonzero port — the
/// backend's `port_or_known_default()` is `None` for these schemes and port 0
/// can never be dialed. Query options are checked on DECODED `query_pairs()`
/// values, exactly what the backend's `parse_link_options` observes: names and
/// values are percent-decoded, `+` becomes a space, valueless keys arrive as
/// empty values, and fragments never enter the query. Only backend-internal
/// DNS resolution of the host stays out of scope. This layer is deliberately
/// stricter than the backend on raw whitespace/control characters (the URL
/// parser would strip or encode them silently) and on empty hosts. Values
/// never reach diagnostics.
fn peer_uri_wellformed(uri: &str) -> bool {
    if uri.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let Ok(parsed) = Url::parse(uri) else {
        return false;
    };
    if !matches!(parsed.scheme(), "tcp" | "tls") {
        return false;
    }
    match parsed.host_str() {
        Some(host) if !host.is_empty() => {}
        _ => return false,
    }
    match parsed.port() {
        Some(port) if port != 0 => {}
        _ => return false,
    }
    parsed
        .query_pairs()
        .all(|(key, value)| query_option_wellformed(&key, &value))
}

/// One decoded `query_pairs()` pair, mirroring the pinned backend's
/// `parse_link_options`: `key` must hex-decode to exactly 32 bytes (64 hex
/// chars), `priority` parses as u8, `password` is at most 64 UTF-8 BYTES (the
/// backend checks `String::len`, not character count), `maxbackoff` follows
/// the backend duration grammar with the 5-second minimum, `sni` takes any
/// value, and unknown keys are ignored. A valueless known key arrives as an
/// empty value and is rejected like any other invalid value.
fn query_option_wellformed(key: &str, value: &str) -> bool {
    match key {
        "key" => {
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f' | b'A'..=b'F'))
        }
        "priority" => value.parse::<u8>().is_ok(),
        "password" => value.len() <= 64,
        "maxbackoff" => {
            matches!(duration_seconds_wellformed(value), Some(seconds) if seconds >= 5)
        }
        "sni" => true,
        _ => true,
    }
}

/// Mirror of the backend's `parse_duration_string` grammar: a plain whole-string u64 of seconds (a leading `+` is accepted, as by `u64::from_str`), or a composition of `[0-9]+` runs each followed by one of
/// `h`/`m`/`s` (a trailing digit-run without a unit is invalid, e.g. `5m30`),
/// accumulated with u64 checked arithmetic. Returns the total seconds, or
/// `None` if the value is malformed or overflows.
fn duration_seconds_wellformed(value: &str) -> Option<u64> {
    // Plain whole-string seconds first, exactly like the backend's
    // `parse_duration_string` (this also accepts a leading `+`).
    if let Ok(secs) = value.parse::<u64>() {
        return Some(secs);
    }
    if value.is_empty() {
        return None;
    }
    let mut total: u64 = 0;
    let mut digits_start = 0;
    let mut bytes = value.as_bytes();
    while !bytes.is_empty() {
        let digit_run = bytes
            .iter()
            .position(|b| !b.is_ascii_digit())
            .unwrap_or(bytes.len());
        if digit_run == 0 {
            return None; // unit without digits
        }
        let amount: u64 = value[digits_start..digits_start + digit_run].parse().ok()?;
        let unit = *bytes.get(digit_run)?;
        let factor = match unit {
            b'h' => 3600,
            b'm' => 60,
            b's' => 1,
            _ => return None,
        };
        let consumed = digit_run + 1;
        total = total.checked_add(amount.checked_mul(factor)?)?;
        digits_start += consumed;
        bytes = &bytes[consumed..];
    }
    Some(total)
}

fn parse_ygg(raw: YggFile) -> Result<YggNetwork, ConfigError> {
    const FIELD_PEERS: &str = "network.ygg.peers";

    let entries = raw
        .peers
        .as_ref()
        .ok_or_else(|| ConfigError::validation(FIELD_PEERS, ValidationKind::MissingRequired))?;
    if entries.is_empty() {
        return Err(ConfigError::validation(FIELD_PEERS, ValidationKind::TooFew));
    }
    if entries.len() > MAX_YGG_PEERS {
        return Err(ConfigError::validation(
            FIELD_PEERS,
            ValidationKind::TooMany,
        ));
    }
    for uri in entries {
        // Structural pre-check against the pinned backend grammar; never a connection attempt.
        if !peer_uri_wellformed(uri) {
            return Err(ConfigError::validation(
                FIELD_PEERS,
                ValidationKind::InvalidUri,
            ));
        }
    }
    Ok(YggNetwork {
        peers: entries.clone(),
    })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod uri_tests;
