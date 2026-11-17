#![forbid(unsafe_code)]
//! Identity, startup configuration and bounded native endpoints for Sha'ar Stack.

// The guide example is compiled as part of the crate and names it `shaar`, as a user would.
extern crate self as shaar;

pub mod config;
pub mod identity;
mod native_discovery;
pub mod network;
mod path;
pub mod startup;

pub use network::ServiceStream;
pub use startup::facade::{
    AllowAction, AllowList, AllowListError, Client, ClientBuilder, Handler, KeyError, Network,
    NetworkSpec, PeerKey, RunningClient, RunningServer, SdkError, Server, ServerBuilder, Service,
    allowlist_command,
};
