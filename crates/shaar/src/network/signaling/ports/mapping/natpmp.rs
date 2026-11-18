//! NAT-PMP codec (RFC 6886): the external-address request and UDP port mappings.

use std::net::Ipv4Addr;

const VERSION: u8 = 0;
const OP_EXTERNAL_ADDRESS: u8 = 0;
const OP_MAP_UDP: u8 = 1;
const REPLY_BIT: u8 = 128;

/// What the gateway granted for a mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Granted {
    pub external_port: u16,
    pub lifetime: u32,
}

/// The request for the external address of the gateway.
pub(super) const fn external_address_request() -> [u8; 2] {
    [VERSION, OP_EXTERNAL_ADDRESS]
}

/// The request for a UDP mapping of `internal` to `suggested` (zero: any) for `lifetime` seconds;
/// a lifetime of zero with a suggested port of zero deletes the mapping.
pub(super) fn map_request(internal: u16, suggested: u16, lifetime: u32) -> [u8; 12] {
    let mut request = [0_u8; 12];
    request[0] = VERSION;
    request[1] = OP_MAP_UDP;
    request[4..6].copy_from_slice(&internal.to_be_bytes());
    request[6..8].copy_from_slice(&suggested.to_be_bytes());
    request[8..12].copy_from_slice(&lifetime.to_be_bytes());
    request
}

fn result_code(reply: &[u8]) -> u16 {
    u16::from_be_bytes([reply[2], reply[3]])
}

/// The answer to a mapping request for `internal`: `None` for a datagram that is not that answer,
/// `Some(Err(code))` for a refusal, `Some(Ok(_))` for a grant.
pub(super) fn decode_map(reply: &[u8], internal: u16) -> Option<Result<Granted, u16>> {
    if reply.len() != 16 || reply[0] != VERSION || reply[1] != REPLY_BIT | OP_MAP_UDP {
        return None;
    }
    match result_code(reply) {
        0 => {}
        code => return Some(Err(code)),
    }
    if u16::from_be_bytes([reply[8], reply[9]]) != internal {
        return None;
    }
    Some(Ok(Granted {
        external_port: u16::from_be_bytes([reply[10], reply[11]]),
        lifetime: u32::from_be_bytes([reply[12], reply[13], reply[14], reply[15]]),
    }))
}

/// The answer to the external-address request, with the same `None` and `Err` meanings.
pub(super) fn decode_external(reply: &[u8]) -> Option<Result<Ipv4Addr, u16>> {
    if reply.len() != 12 || reply[0] != VERSION || reply[1] != REPLY_BIT | OP_EXTERNAL_ADDRESS {
        return None;
    }
    match result_code(reply) {
        0 => Some(Ok(Ipv4Addr::new(reply[8], reply[9], reply[10], reply[11]))),
        code => Some(Err(code)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map_reply(code: u16, internal: u16, external: u16, lifetime: u32) -> [u8; 16] {
        let mut reply = [0_u8; 16];
        reply[1] = 129;
        reply[2..4].copy_from_slice(&code.to_be_bytes());
        reply[8..10].copy_from_slice(&internal.to_be_bytes());
        reply[10..12].copy_from_slice(&external.to_be_bytes());
        reply[12..16].copy_from_slice(&lifetime.to_be_bytes());
        reply
    }

    #[test]
    fn the_requests_match_the_bytes_of_the_rfc() {
        assert_eq!(external_address_request(), [0, 0]);
        assert_eq!(
            map_request(48_896, 48_896, 7200),
            [0, 1, 0, 0, 0xbf, 0x00, 0xbf, 0x00, 0, 0, 0x1c, 0x20]
        );
        assert_eq!(map_request(1, 0, 0), [0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn a_grant_names_the_external_port_and_the_lifetime() {
        assert_eq!(
            decode_map(&map_reply(0, 48_896, 50_001, 3600), 48_896),
            Some(Ok(Granted {
                external_port: 50_001,
                lifetime: 3600
            }))
        );
    }

    #[test]
    fn a_refusal_names_its_result_code() {
        for code in [2_u16, 3, 4, 5] {
            assert_eq!(
                decode_map(&map_reply(code, 48_896, 0, 0), 48_896),
                Some(Err(code))
            );
        }
    }

    #[test]
    fn a_datagram_that_is_not_the_answer_is_ignored() {
        let good = map_reply(0, 48_896, 50_001, 3600);
        assert!(decode_map(&good[..15], 48_896).is_none(), "short");
        assert!(decode_map(&good, 1).is_none(), "other internal port");
        let mut wrong_version = good;
        wrong_version[0] = 2;
        assert!(decode_map(&wrong_version, 48_896).is_none());
        let mut wrong_opcode = good;
        wrong_opcode[1] = 128;
        assert!(decode_map(&wrong_opcode, 48_896).is_none());
        assert!(decode_map(&[], 48_896).is_none());
    }

    #[test]
    fn the_external_address_answer_is_decoded() {
        let mut reply = [0_u8; 12];
        reply[1] = 128;
        reply[8..12].copy_from_slice(&[203, 0, 113, 7]);
        assert_eq!(
            decode_external(&reply),
            Some(Ok(Ipv4Addr::new(203, 0, 113, 7)))
        );
        reply[3] = 3;
        assert_eq!(decode_external(&reply), Some(Err(3)));
        assert!(decode_external(&reply[..11]).is_none());
        reply[1] = 129;
        assert!(decode_external(&reply).is_none());
    }
}
