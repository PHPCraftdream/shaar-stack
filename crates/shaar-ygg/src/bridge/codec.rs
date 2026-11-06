//! Carrier envelopes, distinct from unchanged readiness probes.

const MAGIC: &[u8; 8] = b"shaar-qg";
const VERSION: u8 = 1;
const KIND: u8 = 1;
pub(super) const HEADER: usize = 12;

pub(super) fn max_len(mtu: usize) -> usize {
    mtu.saturating_sub(HEADER).min(usize::from(u16::MAX))
}

pub(super) fn encode(payload: &[u8]) -> Option<Vec<u8>> {
    let length = u16::try_from(payload.len()).ok()?;
    let mut bytes = Vec::with_capacity(HEADER + payload.len());
    bytes.extend_from_slice(MAGIC);
    bytes.push(VERSION);
    bytes.push(KIND);
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(payload);
    Some(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.len() < HEADER || &bytes[..8] != MAGIC || bytes[8] != VERSION || bytes[9] != KIND {
        return None;
    }
    let length = usize::from(u16::from_le_bytes([bytes[10], bytes[11]]));
    (bytes.len() == HEADER + length).then_some(&bytes[HEADER..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{Frame, Kind};

    #[test]
    fn golden_bytes_and_empty_payload_are_exact() {
        let golden = b"shaar-qg\x01\x01\x02\x00\x00\xff";
        assert_eq!(encode(&[0, 255]).as_deref(), Some(golden.as_slice()));
        assert_eq!(decode(golden), Some([0, 255].as_slice()));
        assert_eq!(
            encode(&[]).as_deref(),
            Some(b"shaar-qg\x01\x01\x00\x00".as_slice())
        );
        assert_eq!(decode(b"shaar-qg\x01\x01\x00\x00"), Some([].as_slice()));
    }

    #[test]
    fn arbitrary_and_probe_shaped_bytes_round_trip_without_reinterpretation() {
        let probe = Frame {
            kind: Kind::Ping,
            nonce: [42; 16],
        }
        .encode();
        let binary: Vec<u8> = (0..=255).collect();
        for payload in [probe.as_slice(), binary.as_slice(), &[0; 32], &[]] {
            let encoded = encode(payload).expect("bounded payload");
            assert_eq!(decode(&encoded), Some(payload));
            assert!(Frame::decode(&encoded).is_none());
        }
        assert!(Frame::decode(&probe).is_some());
        assert!(decode(&probe).is_none());
    }

    #[test]
    fn malformed_headers_lengths_prefixes_and_trailing_bytes_fail_closed() {
        let encoded = encode(b"carrier").expect("small payload");
        for prefix in 0..encoded.len() {
            assert!(decode(&encoded[..prefix]).is_none(), "prefix {prefix}");
        }
        for index in 0..10 {
            let mut bad = encoded.clone();
            bad[index] ^= 0x80;
            assert!(decode(&bad).is_none(), "header byte {index}");
        }
        let mut bad = encoded.clone();
        bad[10] += 1;
        assert!(decode(&bad).is_none());
        bad = encoded;
        bad.push(0);
        assert!(decode(&bad).is_none());
    }

    #[test]
    fn length_and_mtu_limits_include_the_envelope() {
        let largest = vec![0xA5; usize::from(u16::MAX)];
        let encoded = encode(&largest).expect("maximum length field");
        assert_eq!(decode(&encoded), Some(largest.as_slice()));
        assert!(encode(&vec![0; usize::from(u16::MAX) + 1]).is_none());
        assert_eq!(max_len(1280), 1268);
        assert_eq!(max_len(0), 0);
        assert_eq!(max_len(HEADER), 0);
        assert_eq!(max_len(usize::MAX), usize::from(u16::MAX));
        for (mtu, payload_len) in [
            (65535, 65523),
            (65536, 65524),
            (65547, 65535),
            (65548, 65535),
        ] {
            assert_eq!(max_len(mtu), payload_len);
            let frame = encode(&vec![0; payload_len]).expect("length field fits");
            assert!(frame.len() <= mtu, "envelope fits mtu {mtu}");
        }
    }
}
