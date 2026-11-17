//! Server configuration schema, merge, and validation.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::error::{ConfigError, ValidationKind};
use super::network::NetworkSettings;
use super::raw::{
    Fallback, PublishAddress, merge, parse_fallback, parse_publish_address, parse_socket_addr,
    require_loopback, require_nonempty_path,
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
    /// Unvalidated raw value of the opt-in public-address publication (`off|plain|encrypted`).
    #[serde(default)]
    publish_address: Option<String>,
    /// File with the key that seals the published address (`publish_address: encrypted`).
    #[serde(default)]
    address_key_file: Option<String>,
    #[serde(default)]
    network: Option<super::network::NetworkFile>,
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
    publish_address: PublishAddress,
    address_key_file: Option<PathBuf>,
    network: Option<NetworkSettings>,
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

    /// Whether the DHT record also carries the NAT-observed public address, and whether it is sealed.
    pub fn publish_address(&self) -> PublishAddress {
        self.publish_address
    }

    /// Key file that seals the published address; present exactly when `publish_address` is
    /// `encrypted`.
    pub fn address_key_file(&self) -> Option<&Path> {
        self.address_key_file.as_deref()
    }

    /// Optional shared network settings; absence keeps the legacy
    /// direct-only contract.
    pub fn network(&self) -> Option<&NetworkSettings> {
        self.network.as_ref()
    }

    /// Swaps in network settings derived from the validated ones (resolved
    /// bootstrap host names); never called with unvalidated settings.
    pub(crate) fn set_network(&mut self, network: NetworkSettings) {
        self.network = Some(network);
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
        let composed = file.network.is_some();
        let target_raw = merge(file.target, over.target.clone());
        let bind_raw = merge(file.bind, endpoint_overrides.bind.clone());
        let key_raw = merge(file.key_file.map(PathBuf::from), over.key_file.clone());
        let allow_raw = merge(
            file.allowlist_path.map(PathBuf::from),
            over.allowlist_path.clone(),
        );
        let fallback = parse_fallback(file.fallback.as_deref(), over.fallback)?;
        let publish_address = parse_publish_address(file.publish_address.as_deref())?;
        let address_key_file = file.address_key_file.map(PathBuf::from);
        if let Some(path) = &address_key_file {
            require_nonempty_path("address_key_file", path)?;
        }
        match (publish_address, &address_key_file) {
            (PublishAddress::Encrypted, None) => {
                return Err(ConfigError::validation(
                    "address_key_file",
                    ValidationKind::MissingRequired,
                ));
            }
            (PublishAddress::Encrypted, Some(_)) | (_, None) => {}
            (_, Some(_)) => {
                return Err(ConfigError::validation(
                    "address_key_file",
                    ValidationKind::NotApplicable,
                ));
            }
        }

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
        // The composed startup binds its own native sockets (IPv4 wildcard
        // plus optional IPv6); an explicit `bind` there would be ignored.
        if composed && bind_raw.is_some() {
            return Err(ConfigError::validation(
                "bind",
                ValidationKind::NotApplicable,
            ));
        }

        let key_file = key_raw.unwrap_or_else(|| PathBuf::from(DEFAULT_KEY_FILE));
        require_nonempty_path("key_file", &key_file)?;
        let allowlist_path = allow_raw.unwrap_or_else(|| PathBuf::from(DEFAULT_ALLOWLIST_PATH));
        require_nonempty_path("allowlist_path", &allowlist_path)?;

        let network = super::network::parse(file.network)?;

        Ok(ServerConfig {
            target,
            bind,
            key_file,
            allowlist_path,
            fallback,
            publish_address,
            address_key_file,
            network,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(extra: &str) -> Result<ServerConfig, ConfigError> {
        let text = format!("target: 127.0.0.1:9\n{extra}");
        ServerConfig::from_text(&text, &ServerOverrides::default())
    }

    #[test]
    fn publish_address_defaults_to_off_and_accepts_both_modes() {
        assert_eq!(parse("").unwrap().publish_address(), PublishAddress::Off);
        assert_eq!(
            parse("publish_address: off\n").unwrap().publish_address(),
            PublishAddress::Off
        );
        assert_eq!(
            parse("publish_address: plain\n").unwrap().publish_address(),
            PublishAddress::Plain
        );
    }

    #[test]
    fn encrypted_needs_its_key_file_and_names_the_field_when_it_is_missing() {
        let config =
            parse("publish_address: encrypted\naddress_key_file:: /keys/address.key\n").unwrap();
        assert_eq!(config.publish_address(), PublishAddress::Encrypted);
        assert_eq!(
            config.address_key_file(),
            Some(Path::new("/keys/address.key"))
        );
        let error = parse("publish_address: encrypted\n").unwrap_err();
        assert!(matches!(
            error,
            ConfigError::Validation {
                field: "address_key_file",
                kind: ValidationKind::MissingRequired
            }
        ));
        assert!(error.to_string().contains("address_key_file"));
        let empty = parse("publish_address: encrypted\naddress_key_file: \n").unwrap_err();
        assert!(matches!(
            empty,
            ConfigError::Validation {
                field: "address_key_file",
                ..
            }
        ));
    }

    #[test]
    fn a_key_file_without_encrypted_publication_is_not_applicable() {
        for mode in ["", "publish_address: off\n", "publish_address: plain\n"] {
            let error =
                parse(&format!("{mode}address_key_file:: /keys/address.key\n")).unwrap_err();
            assert!(
                matches!(
                    error,
                    ConfigError::Validation {
                        field: "address_key_file",
                        kind: ValidationKind::NotApplicable
                    }
                ),
                "{mode:?}: {error}"
            );
        }
        assert_eq!(parse("").unwrap().address_key_file(), None);
        assert_eq!(
            parse("publish_address: plain\n")
                .unwrap()
                .address_key_file(),
            None
        );
    }

    #[test]
    fn unknown_values_and_bad_syntax_are_rejected_without_echoing_input() {
        for value in ["Plain", "bogus"] {
            let error = parse(&format!("publish_address: {value}\n")).unwrap_err();
            assert!(
                matches!(
                    error,
                    ConfigError::Validation {
                        field: "publish_address",
                        kind: ValidationKind::InvalidEnum
                    }
                ),
                "{value:?}: {error}"
            );
            assert!(!error.to_string().contains("Plain"));
        }
        assert!(matches!(
            parse("publish_address: [\n").unwrap_err(),
            ConfigError::Parsing { .. }
        ));
    }
}
