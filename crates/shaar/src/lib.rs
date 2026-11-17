#![forbid(unsafe_code)]
//! Identity, startup configuration and bounded native endpoints for Sha'ar Stack.

pub mod config;
pub mod identity;
mod native_discovery;
pub mod network;
mod path;
pub mod startup;

pub use startup::facade::{
    AllowList, AllowListError, Client, ClientBuilder, Handler, KeyError, Network, NetworkSpec,
    PeerKey, RunningClient, RunningServer, SdkError, Server, ServerBuilder, Service,
};
