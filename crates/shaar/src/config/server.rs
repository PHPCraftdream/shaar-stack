//! Server configuration schema, merge, and validation.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::error::{ConfigError, ValidationKind};
use super::raw::{
    Fallback, merge, parse_fallback, parse_socket_addr, require_loopback, require_nonempty_path,
};

/// Default key file path used when the schema field is absent.
pub const DEFAULT_KEY_FILE: &str = "shaar.key";
/// Default allowlist path used when the schema field is absent.
pub const DEFAULT_ALLOWLIST_PATH: &str = "allowed.txt";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerFile {
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    bind: Option<String>,
    #[serde(default)]
    key_file: Option<String>,
    #[serde(default)]
    allowlist_path: Option<String>,
    /// Unvalidated raw file value; enum validation happens after the
    /// CLI override has had its chance to replace it (`parse_fallback`).
    #[serde(default)]
    fallback: Option<String>,
}

/// Explicit server CLI overrides; supplied values win over file values
/// and defaults, and are merged before semantic validation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerOverrides {
    /// Override for the loopback forward target address.
    pub target: Option<String>,
    /// Override for the identity key file path.
    pub key_file: Option<PathBuf>,
    /// Override for the allowlist file path.
    pub allowlist_path: Option<PathBuf>,
    /// Override for the fallback transport selection.
    pub fallback: Option<Fallback>,
}

/// Optional bind override kept separate to preserve exhaustive legacy override literals.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerEndpointOverrides {
    /// Override for the server bind address.
    pub bind: Option<String>,
}

/// Validated server startup configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    target: SocketAddr,
    bind: SocketAddr,
    key_file: PathBuf,
    allowlist_path: PathBuf,
    fallback: Fallback,
}

impl ServerConfig {
    /// Loopback address the forwarded traffic is directed at.
    pub fn target(&self) -> SocketAddr {
        self.target
    }

    /// Server bind address; port zero requests an OS-selected port.
    pub fn bind(&self) -> SocketAddr {
        self.bind
    }

    /// Identity key file path (borrowed view).
    pub fn key_file(&self) -> &Path {
        &self.key_file
    }

    /// Allowlist file path (borrowed view).
    pub fn allowlist_path(&self) -> &Path {
        &self.allowlist_path
    }

    /// Fallback transport selection.
    pub fn fallback(&self) -> Fallback {
        self.fallback
    }

    /// Merge file values (already deserialized from `text`) with
    /// overrides, then validate. Syntax and schema errors are rejected
    /// before merging, even when overrides supply every required field.
    pub fn from_text(text: &str, over: &ServerOverrides) -> Result<ServerConfig, ConfigError> {
        Self::from_text_with_endpoint_overrides(text, over, &ServerEndpointOverrides::default())
    }

    pub fn from_text_with_endpoint_overrides(
        text: &str,
        over: &ServerOverrides,
        endpoint_overrides: &ServerEndpointOverrides,
    ) -> Result<ServerConfig, ConfigError> {
        if text.len() > super::MAX_CONFIG_BYTES {
            // Same byte bound as file loading; the path is empty
            // because the text never came from a file.
            return Err(ConfigError::loading(
                PathBuf::new(),
                super::LoadKind::TooLarge,
            ));
        }
        let file: ServerFile = ktav::from_str(text).map_err(|e| ConfigError::from_ktav(&e))?;
        let target_raw = merge(file.target, over.target.clone());
        let bind_raw = merge(file.bind, endpoint_overrides.bind.clone());
        let key_raw = merge(file.key_file.map(PathBuf::from), over.key_file.clone());
        let allow_raw = merge(
            file.allowlist_path.map(PathBuf::from),
            over.allowlist_path.clone(),
        );
        let fallback = parse_fallback(file.fallback.as_deref(), over.fallback)?;

        let target_text = target_raw
            .ok_or_else(|| ConfigError::validation("target", ValidationKind::MissingRequired))?;
        let target = parse_socket_addr("target", &target_text)?;
        require_loopback("target", target)?;
        if target.port() == 0 {
            return Err(ConfigError::validation(
                "target",
                ValidationKind::InvalidPort,
            ));
        }

        let bind_text = bind_raw.as_deref().unwrap_or("0.0.0.0:0");
        let bind = parse_socket_addr("bind", bind_text)?;

        let key_file = key_raw.unwrap_or_else(|| PathBuf::from(DEFAULT_KEY_FILE));
        require_nonempty_path("key_file", &key_file)?;
        let allowlist_path = allow_raw.unwrap_or_else(|| PathBuf::from(DEFAULT_ALLOWLIST_PATH));
        require_nonempty_path("allowlist_path", &allowlist_path)?;

        Ok(ServerConfig {
            target,
            bind,
            key_file,
            allowlist_path,
            fallback,
        })
    }
}
