//! Retained-role lifecycle regressions, split by scenario.

#[path = "endpoints/addresses.rs"]
mod addresses;
mod cancellation;
mod capacity;
mod client_starting;
mod efficiency;
mod helpers;
#[path = "endpoints/ipv6.rs"]
mod ipv6;
#[path = "endpoints/listener.rs"]
mod listener;
