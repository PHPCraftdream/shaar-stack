//! Server-role support split from server.rs for the 700-line rule: the
//! joined close, bounded session serving, and since leaf L4 the punch
//! responder (relay-less compositions only).

mod close;
mod punch;

pub(super) use close::{close_parts, reap_session, spawn_session};
#[cfg(test)]
pub(crate) use punch::set_punch_candidates_for_tests;
pub(super) use punch::spawn_responder;
