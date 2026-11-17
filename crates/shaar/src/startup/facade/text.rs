//! Network choice and the ktav text the builders hand to the configuration
//! parser, so a builder value is validated by exactly the rules of a file.

use std::net::SocketAddr;
use std::path::Path;

use super::SdkError;
use crate::identity::public_network_text;

/// The network shape of a Server or Client.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Network {
    /// One native QUIC socket and no discovery: the Client needs the Server's
    /// address (`server_address`).
    #[default]
    Direct,
    /// The Mainline DHT and Yggdrasil with the public bootstrap hosts and peers
    /// that `init` writes; no libp2p relay.
    Public,
    /// The Mainline DHT and Yggdrasil with your own hosts, peers and optional relay.
    Custom(NetworkSpec),
}

/// Bootstrap hosts, Yggdrasil peers and an optional relay for [`Network::Custom`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkSpec {
    /// One to four `ip:port` or `host:port` Mainline bootstrap entries.
    pub bootstrap: Vec<String>,
    /// One to four Yggdrasil peer URIs (`tcp://host:port`, `tls://host:port`).
    pub ygg_peers: Vec<String>,
    /// A pinned libp2p relay: its PeerId text and numeric address; optional.
    pub relay: Option<(String, SocketAddr)>,
}

/// Builds one configuration text; values are written as literal strings.
pub(super) struct Text(String);

impl Text {
    pub(super) fn new() -> Self {
        Self(String::new())
    }

    /// `key:: value`; a value with a control character cannot be one line.
    pub(super) fn value(&mut self, key: &str, value: &str) -> Result<(), SdkError> {
        self.entry(0, key, value)
    }

    pub(super) fn path(&mut self, key: &str, path: &Path) -> Result<(), SdkError> {
        let value = path
            .to_str()
            .ok_or(SdkError::Setup("a path is not valid UTF-8"))?;
        self.entry(0, key, value)
    }

    fn entry(&mut self, depth: usize, key: &str, value: &str) -> Result<(), SdkError> {
        if value.chars().any(char::is_control) {
            return Err(SdkError::Setup("a value contains a control character"));
        }
        self.0.push_str(&"    ".repeat(depth));
        self.0.push_str(&format!("{key}:: {value}\n"));
        Ok(())
    }

    fn list(&mut self, depth: usize, key: &str, items: &[String]) -> Result<(), SdkError> {
        let pad = "    ".repeat(depth);
        self.0.push_str(&format!("{pad}{key}: [\n"));
        for item in items {
            if item.chars().any(char::is_control) {
                return Err(SdkError::Setup("a value contains a control character"));
            }
            self.0.push_str(&format!("{pad}    :: {item}\n"));
        }
        self.0.push_str(&format!("{pad}]\n"));
        Ok(())
    }

    pub(super) fn network(&mut self, network: &Network) -> Result<(), SdkError> {
        match network {
            Network::Direct => Ok(()),
            Network::Public => {
                self.0.push_str(public_network_text());
                Ok(())
            }
            Network::Custom(spec) => {
                self.0.push_str("network: {\n    mainline: {\n");
                self.list(2, "bootstrap", &spec.bootstrap)?;
                self.0.push_str("    }\n    signaling: {\n");
                self.entry(2, "bind", "0.0.0.0:0")?;
                if let Some((peer_id, address)) = &spec.relay {
                    self.entry(2, "relay", peer_id)?;
                    self.entry(2, "relay_address", &address.to_string())?;
                }
                self.0.push_str("    }\n    ygg: {\n");
                self.list(2, "peers", &spec.ygg_peers)?;
                self.0.push_str("    }\n}\n");
                Ok(())
            }
        }
    }

    pub(super) fn finish(&self) -> &str {
        &self.0
    }
}
