#![forbid(unsafe_code)]
//! Exact, prefix-free packet identity; coalesced datagrams are consumed completely.

use std::{collections::BTreeMap, fs::File, io::Read, ops::Bound, path::Path};

const MAX_TRACE: usize = 16 * 1024 * 1024;
const MAX_PACKET: usize = 65535;
const MAX_RECORDS: usize = 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub packets: u64,
    pub streams: u64,
    pub datagrams: u64,
}

impl Counts {
    pub fn add(&mut self, other: Self) {
        // Every contribution is bounded by trace/record/capture limits in this fixture.
        self.packets += other.packets;
        self.streams += other.streams;
        self.datagrams += other.datagrams;
    }
}

#[derive(Debug)]
struct Packet {
    id: usize,
    frames: Counts,
}

#[derive(Debug, Default)]
pub struct Index {
    packets: BTreeMap<Vec<u8>, Packet>,
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    if text.is_empty() || text.len() > MAX_PACKET * 2 || text.len() % 2 != 0 {
        return Err("invalid ciphertext hex length".into());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(|_| "non-ASCII ciphertext")?;
            u8::from_str_radix(pair, 16).map_err(|_| "invalid ciphertext hex".into())
        })
        .collect()
}

impl Index {
    pub fn parse_file(path: &Path) -> Result<Self, String> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|e| e.to_string())?
            .take((MAX_TRACE + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        Self::parse(&bytes)
    }

    fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_TRACE {
            return Err("trace size limit".into());
        }
        let mut index = Self::default();
        for record in bytes.split(|byte| *byte == 0x1e) {
            for line in record
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
            {
                let event: serde_json::Value =
                    serde_json::from_slice(line).map_err(|e| e.to_string())?;
                if event["name"] != "quic:packet_sent" {
                    continue;
                }
                let data = &event["data"];
                let raw = &data["raw"];
                let encoded = raw["data"].as_str().ok_or("missing sent ciphertext")?;
                let packet = decode_hex(encoded)?;
                if raw["length"].as_u64() != Some(packet.len() as u64) {
                    return Err("ciphertext length mismatch".into());
                }
                let frames = data["frames"].as_array().ok_or("missing decoded frames")?;
                let mut counts = Counts {
                    packets: 1,
                    ..Counts::default()
                };
                for frame in frames {
                    match frame["frame_type"].as_str().ok_or("missing frame type")? {
                        "stream" => counts.streams += 1,
                        "datagram" => counts.datagrams += 1,
                        _ => {}
                    }
                }
                index.insert(packet, counts)?;
            }
        }
        if index.packets.is_empty() {
            return Err("no sent packet identities".into());
        }
        Ok(index)
    }

    fn insert(&mut self, packet: Vec<u8>, frames: Counts) -> Result<(), String> {
        if self.packets.len() == MAX_RECORDS || packet.is_empty() || packet.len() > MAX_PACKET {
            return Err("packet identity limit".into());
        }
        let key = packet.as_slice();
        let preceding = self
            .packets
            .range::<[u8], _>((Bound::Unbounded, Bound::Included(key)))
            .next_back();
        let following = self
            .packets
            .range::<[u8], _>((Bound::Included(key), Bound::Unbounded))
            .next();
        if preceding.is_some_and(|(p, _)| key.starts_with(p))
            || following.is_some_and(|(p, _)| p.starts_with(key))
        {
            return Err("duplicate or prefix-ambiguous packet identity".into());
        }
        let id = self.packets.len();
        self.packets.insert(packet, Packet { id, frames });
        Ok(())
    }

    pub fn seen(&self) -> Vec<bool> {
        vec![false; self.packets.len()]
    }

    pub fn observe(&self, mut datagram: &[u8], seen: &mut [bool]) -> Result<Counts, String> {
        if datagram.is_empty() || datagram.len() > MAX_PACKET || seen.len() != self.packets.len() {
            return Err("invalid capture shape".into());
        }
        let mut counts = Counts::default();
        while !datagram.is_empty() {
            // Prefix-free keys make the lexical predecessor the only possible packet prefix.
            let (bytes, packet) = self
                .packets
                .range::<[u8], _>((Bound::Unbounded, Bound::Included(datagram)))
                .next_back()
                .ok_or("captured packet has no qlog identity")?;
            if !datagram.starts_with(bytes) {
                return Err("captured ciphertext mismatch".into());
            }
            counts.add(packet.frames);
            seen[packet.id] = true;
            datagram = &datagram[bytes.len()..];
        }
        Ok(counts)
    }

    pub fn unobserved(&self, seen: &[bool]) -> Counts {
        assert_eq!(seen.len(), self.packets.len());
        let mut counts = Counts::default();
        for packet in self.packets.values().filter(|packet| !seen[packet.id]) {
            counts.add(packet.frames);
        }
        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index() -> Index {
        // External qlog raw.data is full encrypted packet bytes encoded as hex.
        Index::parse(br#"{"name":"quic:packet_sent","data":{"raw":{"length":2,"data":"1020"},"frames":[{"frame_type":"ping"}]}}
{"name":"quic:packet_sent","data":{"raw":{"length":3,"data":"304050"},"frames":[{"frame_type":"stream"},{"frame_type":"datagram"}]}}"#).expect("schema fixture")
    }

    #[test]
    fn exact_coalesced_packets_and_repeated_capture_are_accounted() {
        let index = index();
        let mut seen = index.seen();
        assert_eq!(
            index
                .observe(&[0x10, 0x20, 0x30, 0x40, 0x50], &mut seen)
                .unwrap(),
            Counts {
                packets: 2,
                streams: 1,
                datagrams: 1
            }
        );
        assert_eq!(
            index
                .observe(&[0x30, 0x40, 0x50], &mut seen)
                .unwrap()
                .streams,
            1
        );
        assert_eq!(index.unobserved(&seen), Counts::default());
    }

    #[test]
    fn corrupt_truncated_unknown_and_trailing_bytes_never_match() {
        let index = index();
        for bytes in [
            &[0x10, 0x21][..],
            &[0x10][..],
            &[0x90][..],
            &[0x10, 0x20, 0xff][..],
            &[][..],
        ] {
            assert!(
                index.observe(bytes, &mut index.seen()).is_err(),
                "must reject {bytes:?}"
            );
        }
    }

    #[test]
    fn duplicates_prefixes_and_record_limit_fail_closed() {
        let mut index = Index::default();
        index.insert(vec![1, 2], Counts::default()).unwrap();
        for key in [vec![1], vec![1, 2], vec![1, 2, 3]] {
            assert!(index.insert(key, Counts::default()).is_err());
        }
        let mut index = Index::default();
        for number in 0..MAX_RECORDS {
            index
                .insert(number.to_be_bytes().to_vec(), Counts::default())
                .unwrap();
        }
        assert!(index.insert(vec![0xff; 32], Counts::default()).is_err());
    }

    #[test]
    fn missing_raw_malformed_hex_length_and_frames_are_rejected() {
        for raw in ["", "0", "gg", "é0"] {
            assert!(decode_hex(raw).is_err());
        }
        for event in [
            r#"{"name":"quic:packet_sent","data":{}}"#,
            r#"{"name":"quic:packet_sent","data":{"raw":{"length":3,"data":"1020"},"frames":[]}}"#,
            r#"{"name":"quic:packet_sent","data":{"raw":{"length":2,"data":"1020"}}}"#,
        ] {
            assert!(Index::parse(event.as_bytes()).is_err());
        }
        assert!(Index::parse(b"{broken").is_err());
        assert!(Index::parse(b"").is_err());
    }
}
