//! The SDK facade: typed builders and handles over the composed roles.
//!
//! - [`PeerKey`] is the public key that addresses a Server or names a Client;
//!   [`AllowList`] is the set of client keys a Server admits, with the file format.
//! - [`Server::builder`] and [`Client::builder`] collect typed settings;
//!   [`Server::from_config_file`] and [`Client::from_config_file`] load a ktav file.
//! - [`Server::start`] and [`Client::start`] run a role on a thread of its own
//!   (the roles are not `Send`) and return `Send` handles; [`Server::run`] serves
//!   on the caller's runtime.
//! - [`Handler`] serves the streams of admitted clients in the application;
//!   [`ServiceStream`](crate::network::ServiceStream) is the byte stream.
//!
//! Both network shapes are supported: [`Network::Direct`] (one QUIC socket, the
//! Client needs the Server's address) and the composed shape
//! ([`Network::Public`], [`Network::Custom`]: Mainline DHT, signaling, Yggdrasil).

mod client;
mod peers;
mod runtime;
mod server;
mod text;

#[cfg(test)]
mod tests;

use std::fmt;

pub use client::{Client, ClientBuilder, RunningClient};
pub use peers::{AllowAction, AllowList, AllowListError, KeyError, PeerKey, allowlist_command};
pub use server::{Handler, RunningServer, Server, ServerBuilder, Service};
pub use text::{Network, NetworkSpec};

use crate::config::ConfigError;
use crate::identity::IdentityError;
use crate::network::{ForwardError, NetworkError};
use crate::startup::StartupError;

/// Everything the facade can fail with. Messages name stages and fields and never
/// carry key material or peer text.
#[derive(Debug)]
pub enum SdkError {
    /// A setting or configuration file was rejected.
    Config(ConfigError),
    /// The identity key file could not be used.
    Identity(IdentityError),
    /// The allowlist could not be read or parsed.
    AllowList(AllowListError),
    /// Starting or running a composed role failed.
    Startup(StartupError),
    /// A direct endpoint failed.
    Network(NetworkError),
    /// Opening or serving a stream failed.
    Forward(ForwardError),
    /// A local socket operation failed.
    Io(std::io::Error),
    /// The builder was misused; the text names what is missing.
    Setup(&'static str),
    /// The Server or Client has already ended.
    Closed,
}

macro_rules! sdk_error_from {
    ($($source:ty => $variant:ident),+ $(,)?) => {$(
        impl From<$source> for SdkError {
            fn from(error: $source) -> Self {
                Self::$variant(error)
            }
        }
    )+};
}

sdk_error_from! {
    ConfigError => Config,
    IdentityError => Identity,
    AllowListError => AllowList,
    StartupError => Startup,
    NetworkError => Network,
    ForwardError => Forward,
    std::io::Error => Io,
}

impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(f, "configuration: {error}"),
            Self::Identity(error) => write!(f, "identity: {error}"),
            Self::AllowList(error) => write!(f, "{error}"),
            Self::Startup(error) => write!(f, "startup: {error}"),
            Self::Network(error) => write!(f, "network: {error}"),
            Self::Forward(error) => write!(f, "stream: {error}"),
            Self::Io(error) => write!(f, "local I/O: {}", error.kind()),
            Self::Setup(message) => f.write_str(message),
            Self::Closed => f.write_str("the Server or Client has ended"),
        }
    }
}

impl std::error::Error for SdkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::Identity(error) => Some(error),
            Self::AllowList(error) => Some(error),
            Self::Startup(error) => Some(error),
            Self::Network(error) => Some(error),
            Self::Forward(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Setup(_) | Self::Closed => None,
        }
    }
}
