//! Retained-role lifecycle regressions, split by scenario.

mod cancellation;
mod capacity;
mod client_starting;
mod efficiency;
mod helpers;
#[path = "endpoints/ipv6.rs"]
mod ipv6;
#[path = "endpoints/listener.rs"]
mod listener;
