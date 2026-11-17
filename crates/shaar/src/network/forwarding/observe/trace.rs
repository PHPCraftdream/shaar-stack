//! Further operator trace lines (leaf FIX-2): the record lookup, the direct attempts of one
//! dial and the NAT port mapping. Counts and typed tokens only: never keys or addresses.

/// The client's line when one record lookup has finished. `outcome` is `found`, `not-found` or
/// `failed:<token>`; `record` counts the addresses the record held; `late` says that the route
/// decision had already stopped waiting for this lookup.
pub fn client_lookup(outcome: &str, record: usize, late: bool, elapsed_ms: u64) -> String {
    format!(
        "shaar-client: record lookup outcome={outcome} record={record} late={} elapsed_ms={elapsed_ms}",
        yes_no(late)
    )
}

/// The client's line after the direct-candidate phase of one dial attempt: how many candidates
/// it tried, how many of them were private or local, and whether one of them connected.
pub fn client_direct(listed: usize, local: usize, connected: bool, elapsed_ms: u64) -> String {
    format!(
        "shaar-client: direct attempts candidates={listed} local={local} connected={} elapsed_ms={elapsed_ms}",
        yes_no(connected)
    )
}

/// The Server's line when one publication of its signed record has finished. `outcome` is `ok`
/// or `failed:<token>`; `retries` counts the failed publications before this one.
pub fn server_publication(outcome: &str, retries: usize) -> String {
    format!("shaar-server: record publication outcome={outcome} retries={retries}")
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

/// Whether the NAT kept the local port in the address the DHT nodes saw for the Mainline
/// socket. A trace token: the ports themselves are never printed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortMapping {
    Unknown,
    Kept,
    Changed,
}

impl PortMapping {
    /// Compares the address the DHT nodes saw with the socket's own address.
    pub fn of(seen: Option<std::net::SocketAddrV4>, local: std::net::SocketAddrV4) -> Self {
        match seen {
            Some(seen) if seen.port() == local.port() => Self::Kept,
            Some(_) => Self::Changed,
            None => Self::Unknown,
        }
    }

    /// The trace line, or `None` while nothing was observed.
    pub fn line(self) -> Option<&'static str> {
        match self {
            Self::Unknown => None,
            Self::Kept => Some("shaar: reflexive port mapping=kept"),
            Self::Changed => Some("shaar: reflexive port mapping=changed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn the_lookup_line_carries_tokens_counts_and_a_time_only() {
        assert_eq!(
            client_lookup("found", 2, true, 8_410),
            "shaar-client: record lookup outcome=found record=2 late=yes elapsed_ms=8410"
        );
        assert_eq!(
            client_lookup("failed:undecodable", 0, false, 640),
            "shaar-client: record lookup outcome=failed:undecodable record=0 late=no elapsed_ms=640"
        );
    }

    #[test]
    fn the_publication_line_names_the_outcome_and_the_retries() {
        assert_eq!(
            server_publication("ok", 0),
            "shaar-server: record publication outcome=ok retries=0"
        );
        assert_eq!(
            server_publication("failed:resource:CandidateLimit", 2),
            "shaar-server: record publication outcome=failed:resource:CandidateLimit retries=2"
        );
    }

    #[test]
    fn the_direct_attempts_line_counts_candidates_and_the_result() {
        assert_eq!(
            client_direct(3, 1, false, 2_990),
            "shaar-client: direct attempts candidates=3 local=1 connected=no elapsed_ms=2990"
        );
        assert_eq!(
            client_direct(1, 0, true, 40),
            "shaar-client: direct attempts candidates=1 local=0 connected=yes elapsed_ms=40"
        );
    }

    #[test]
    fn the_port_mapping_is_kept_changed_or_unknown_and_prints_no_port() {
        let local = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 49_142);
        let seen = |port| Some(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), port));
        assert_eq!(PortMapping::of(seen(49_142), local), PortMapping::Kept);
        assert_eq!(PortMapping::of(seen(61_000), local), PortMapping::Changed);
        assert_eq!(PortMapping::of(None, local), PortMapping::Unknown);
        let kept = PortMapping::Kept.line().unwrap();
        assert_eq!(kept, "shaar: reflexive port mapping=kept");
        assert!(!kept.contains("49142") && !kept.contains("61000"));
        assert_eq!(PortMapping::Unknown.line(), None);
    }
}
