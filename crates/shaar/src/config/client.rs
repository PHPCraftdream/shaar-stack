//! Client configuration schema, merge, and validation.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::error::{ConfigError, ValidationKind};
use super::raw::{
    Fallback, merge, parse_fallback, parse_socket_addr, require_dial_destination, require_loopback,
    require_nonempty_path,
};
use super::server::DEFAULT_KEY_FILE;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientFile {
    #[serde(default)]
    server: Option<String>,
    #[serde(default)]
    server_address: Option<String>,
    #[serde(default)]
    listen: Option<String>,
    #[serde(default)]
    key_file: Option<String>,
    /// Unvalidated raw file value; enum validation happens after the
    /// CLI override has had its chance to replace it (`parse_fallback`).
    #[serde(default)]
    fallback: Option<String>,
}

/// Explicit client CLI overrides; supplied values win over file values
/// and defaults, and are merged before semantic validation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientOverrides {
    /// Override for the server endpoint public key (hex or base32).
    pub server: Option<String>,
    /// Override for the loopback listen address.
    pub listen: Option<String>,
    /// Override for the identity key file path.
    pub key_file: Option<PathBuf>,
    /// Override for the fallback transport selection.
    pub fallback: Option<Fallback>,
}
/// Optional endpoint override kept separate to preserve exhaustive legacy override literals.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientEndpointOverrides {
    /// Override for the numeric server destination address.
    pub server_address: Option<String>,
}

/// Validated client startup configuration.
///
/// The server endpoint key is validated at construction via the real
/// upstream parse path (`"…".parse::<iroh_base::PublicKey>()`, i.e.
/// `FromStr` → hex/base32 decode → Ed25519 point-decompression check)
/// and stored as raw bytes; no unstable iroh networking type appears
/// in this public API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientConfig {
    server_key: [u8; 32],
    listen: SocketAddr,
    server_address: Option<SocketAddr>,
    key_file: PathBuf,
    fallback: Fallback,
}

impl ClientConfig {
    /// Server endpoint public key (32 raw bytes).
    pub fn server_key_bytes(&self) -> &[u8; 32] {
        &self.server_key
    }

    /// Loopback listen address; port 0 means an OS ephemeral port.
    pub fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// Optional numeric server destination; present values must be usable by the SDK dial boundary.
    pub fn server_address(&self) -> Option<SocketAddr> {
        self.server_address
    }

    /// Identity key file path (borrowed view).
    pub fn key_file(&self) -> &Path {
        &self.key_file
    }

    /// Fallback transport selection.
    pub fn fallback(&self) -> Fallback {
        self.fallback
    }

    /// Merge file values with legacy and endpoint overrides before validation.
    /// Syntax and schema errors are rejected before merging.
    pub fn from_text(text: &str, over: &ClientOverrides) -> Result<ClientConfig, ConfigError> {
        Self::from_text_with_endpoint_overrides(text, over, &ClientEndpointOverrides::default())
    }

    pub fn from_text_with_endpoint_overrides(
        text: &str,
        over: &ClientOverrides,
        endpoint_overrides: &ClientEndpointOverrides,
    ) -> Result<ClientConfig, ConfigError> {
        if text.len() > super::MAX_CONFIG_BYTES {
            // Same byte bound as file loading; the path is empty
            // because the text never came from a file.
            return Err(ConfigError::loading(
                PathBuf::new(),
                super::LoadKind::TooLarge,
            ));
        }
        let file: ClientFile = ktav::from_str(text).map_err(|e| ConfigError::from_ktav(&e))?;
        let server_raw = merge(file.server, over.server.clone());
        let listen_raw = merge(file.listen, over.listen.clone());
        let server_address_raw = merge(
            file.server_address,
            endpoint_overrides.server_address.clone(),
        );
        let key_raw = merge(file.key_file.map(PathBuf::from), over.key_file.clone());
        let fallback = parse_fallback(file.fallback.as_deref(), over.fallback)?;

        let server_text = server_raw
            .ok_or_else(|| ConfigError::validation("server", ValidationKind::MissingRequired))?;
        // Turbofish form: `FromStr` stays out of scope by design.
        let key = server_text
            .parse::<iroh_base::PublicKey>()
            .map_err(|_| ConfigError::validation("server", ValidationKind::InvalidKey))?;

        let listen_text: &str = listen_raw.as_deref().unwrap_or("127.0.0.1:2222");
        let listen = parse_socket_addr("listen", listen_text)?;
        require_loopback("listen", listen)?;

        let server_address = server_address_raw
            .map(|value| {
                let address = parse_socket_addr("server_address", &value)?;
                require_dial_destination("server_address", address)?;
                Ok(address)
            })
            .transpose()?;

        let key_file = key_raw.unwrap_or_else(|| PathBuf::from(DEFAULT_KEY_FILE));
        require_nonempty_path("key_file", &key_file)?;

        Ok(ClientConfig {
            server_key: *key.as_bytes(),
            listen,
            server_address,
            key_file,
            fallback,
        })
    }
}
