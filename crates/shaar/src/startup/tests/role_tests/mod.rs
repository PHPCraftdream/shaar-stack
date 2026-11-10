//! Controlled 5c role fixtures through the same production entrypoints the
//! binaries invoke ([`crate::startup::role::serve_server`] and
//! [`crate::startup::role::serve_client`] via their cfg(test)
//! `_with_events` wrappers). Infrastructure is real everywhere: a loopback
//! Mainline peer, a real Yggdrasil transit core, the real libp2p signaling
//! relay fixture and an owned echo target. No fake publisher, no fake
//! endpoint, no legacy server-address shortcut.

mod denial_cases;
mod fixtures;
mod lifecycle_cases;
mod location_cases;
mod signal_cases;
mod standby_cases;
