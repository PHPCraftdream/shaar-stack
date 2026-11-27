//! Server-role support split from server.rs for the 700-line rule: the
//! joined close, bounded session serving, and since leaf L4 the punch
//! responders: Yggdrasil for relay-less compositions, the carrier side channel with a pinned relay (L4b).

mod carrier_punch;
mod close;
mod punch;
mod spray;
#[cfg(test)]
mod spray_tests;

pub(super) use carrier_punch::spawn_carrier_responder;
pub(super) use close::{close_parts, reap_session, spawn_session};
#[cfg(test)]
pub(crate) use punch::set_punch_candidates_for_tests;
pub(super) use punch::spawn_responder;
