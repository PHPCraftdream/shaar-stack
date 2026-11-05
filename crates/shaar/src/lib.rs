#![forbid(unsafe_code)]
//! Identity, startup configuration and bounded native endpoints for Sha'ar Stack.

pub mod config;
pub mod identity;
mod native_discovery;
pub mod network;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "P10 path policy wiring is pending")
)]
mod path;
