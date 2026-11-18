//! PCP codec (RFC 6887): the MAP opcode for UDP.

use std::net::{IpAddr, Ipv6Addr};

const VERSION: u8 = 2;
const OPCODE_MAP: u8 = 1;
const RESPONSE: u8 = 0x80;
const PROTOCOL_UDP: u8 = 17;
const HEADER_LEN: usize = 24;
const MAP_LEN: usize = 60;
const UNSUPPORTED_VERSION: u8 = 1;

/// The nonce that ties the answers, renewals and deletions of one mapping together.
pub(super) type Nonce = [u8; 12];

/// What the gateway granted for a mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Granted {
    pub external_ip: IpAddr,
    pub external_port: u16,
    pub lifetime: u32,
}

/// What a datagram from the gateway says about a MAP request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Reply {
    Granted(Granted),
    /// The gateway refused with this result code.
    Refused(u8),
    /// The gateway speaks only NAT-PMP (it answered a newer version with "unsupported version").
    NatPmpOnly,
}

fn mapped(address: IpAddr) -> [u8; 16] {
    match address {
        IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
        IpAddr::V6(ip) => ip.octets(),
    }
}

/// The MAP request for a UDP mapping of `internal` to `suggested` (zero: any) for `lifetime`
/// seconds, made by the host with address `client`; a lifetime of zero deletes the mapping.
pub(super) fn map_request(
    client: IpAddr,
    nonce: &Nonce,
    internal: u16,
    suggested: u16,
    lifetime: u32,
) -> [u8; MAP_LEN] {
    let mut request = [0_u8; MAP_LEN];
    request[0] = VERSION;
    request[1] = OPCODE_MAP;
    request[4..8].copy_from_slice(&lifetime.to_be_bytes());
    request[8..24].copy_from_slice(&mapped(client));
    request[24..36].copy_from_slice(nonce);
    request[36] = PROTOCOL_UDP;
    request[40..42].copy_from_slice(&internal.to_be_bytes());
    request[42..44].copy_from_slice(&suggested.to_be_bytes());
    request
}

/// Reads a datagram as the answer to the MAP request with this `nonce` and `internal` port;
/// `None` when it is anything else.
pub(super) fn decode(reply: &[u8], nonce: &Nonce, internal: u16) -> Option<Reply> {
    let version = *reply.first()?;
    if version == 0 {
        let unsupported = reply.len() >= 4 && u16::from_be_bytes([reply[2], reply[3]]) == 1;
        return unsupported.then_some(Reply::NatPmpOnly);
    }
    if version != VERSION || reply.len() < HEADER_LEN || reply[1] != RESPONSE | OPCODE_MAP {
        return None;
    }
    match reply[3] {
        0 => {}
        UNSUPPORTED_VERSION => return Some(Reply::NatPmpOnly),
        code => return Some(Reply::Refused(code)),
    }
    if reply.len() < MAP_LEN
        || reply[24..36] != nonce[..]
        || reply[36] != PROTOCOL_UDP
        || u16::from_be_bytes([reply[40], reply[41]]) != internal
    {
        return None;
    }
    let mut external = [0_u8; 16];
    external.copy_from_slice(&reply[44..60]);
    Some(Reply::Granted(Granted {
        external_ip: Ipv6Addr::from(external).to_canonical(),
        external_port: u16::from_be_bytes([reply[42], reply[43]]),
        lifetime: u32::from_be_bytes([reply[4], reply[5], reply[6], reply[7]]),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const NONCE: Nonce = [9; 12];
    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 20));

    fn reply(code: u8, internal: u16, external: u16) -> [u8; MAP_LEN] {
        let mut reply = map_request(CLIENT, &NONCE, internal, external, 7200);
        reply[1] = RESPONSE | OPCODE_MAP;
        reply[3] = code;
        reply[44..60].copy_from_slice(&Ipv4Addr::new(203, 0, 113, 7).to_ipv6_mapped().octets());
        reply
    }

    #[test]
    fn the_request_matches_the_layout_of_the_rfc() {
        let request = map_request(CLIENT, &NONCE, 48_896, 48_896, 7200);
        assert_eq!(request.len(), 60);
        assert_eq!(&request[..8], [2, 1, 0, 0, 0, 0, 0x1c, 0x20]);
        assert_eq!(
            &request[8..24],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 20]
        );
        assert_eq!(&request[24..36], NONCE);
        assert_eq!(&request[36..44], [17, 0, 0, 0, 0xbf, 0x00, 0xbf, 0x00]);
        assert_eq!(&request[44..60], [0; 16], "no preferred external address");
    }

    #[test]
    fn a_grant_names_the_external_endpoint_and_the_lifetime() {
        assert_eq!(
            decode(&reply(0, 48_896, 50_001), &NONCE, 48_896),
            Some(Reply::Granted(Granted {
                external_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
                external_port: 50_001,
                lifetime: 7200,
            }))
        );
    }

    #[test]
    fn a_refusal_names_its_code_and_a_version_error_means_nat_pmp_only() {
        assert_eq!(
            decode(&reply(2, 48_896, 0), &NONCE, 48_896),
            Some(Reply::Refused(2))
        );
        assert_eq!(
            decode(&reply(1, 48_896, 0), &NONCE, 48_896),
            Some(Reply::NatPmpOnly)
        );
        // The reply of a gateway that speaks NAT-PMP only: version 0, result 1.
        assert_eq!(
            decode(&[0, 129, 0, 1, 0, 0, 0, 0], &NONCE, 48_896),
            Some(Reply::NatPmpOnly)
        );
        assert_eq!(decode(&[0, 129, 0, 0, 0, 0, 0, 0], &NONCE, 48_896), None);
    }

    #[test]
    fn a_datagram_that_is_not_the_answer_is_ignored() {
        let good = reply(0, 48_896, 50_001);
        assert_eq!(decode(&[], &NONCE, 48_896), None);
        assert_eq!(decode(&good[..59], &NONCE, 48_896), None, "short grant");
        assert_eq!(decode(&good, &[1; 12], 48_896), None, "other nonce");
        assert_eq!(decode(&good, &NONCE, 1), None, "other internal port");
        let mut other_protocol = good;
        other_protocol[36] = 6;
        assert_eq!(decode(&other_protocol, &NONCE, 48_896), None);
        let mut request = good;
        request[1] = OPCODE_MAP;
        assert_eq!(
            decode(&request, &NONCE, 48_896),
            None,
            "a request, not an answer"
        );
        let mut other_version = good;
        other_version[0] = 3;
        assert_eq!(decode(&other_version, &NONCE, 48_896), None);
    }
}
