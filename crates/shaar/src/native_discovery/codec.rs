// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use crate::native_discovery::address::{SnapshotError, validate_addresses_with_snapshot};
use iroh_base::EndpointId;
use iroh_dns::pkarr::SignedPacket;
use simple_dns::{CLASS, OPCODE, Packet, PacketFlag, RCODE, header_buffer, rdata::RData};
use std::net::SocketAddr;

const SIGNED_HEADER_BYTES: usize = 104;
const MAX_DNS_BYTES: usize = 1000;
const MAX_TXT_RECORDS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DecodedRecord {
    pub(super) key: EndpointId,
    pub(super) signed_sequence: i64,
    pub(super) signed_at_us: i64,
    pub(super) signed_bytes: Vec<u8>,
    raw_addresses: Vec<SocketAddr>,
    canonical_addresses: Vec<SocketAddr>,
    metadata: Vec<(String, String)>,
}
impl DecodedRecord {
    pub(super) fn addresses(&self) -> &[SocketAddr] {
        &self.canonical_addresses
    }
    pub(super) fn raw_addresses(&self) -> &[SocketAddr] {
        &self.raw_addresses
    }
    pub(super) fn metadata(&self) -> &[(String, String)] {
        &self.metadata
    }
    pub(super) fn into_policy_parts(
        self,
    ) -> (
        EndpointId,
        i64,
        i64,
        Vec<u8>,
        Vec<SocketAddr>,
        Vec<(String, String)>,
    ) {
        let DecodedRecord {
            key,
            signed_sequence,
            signed_at_us,
            signed_bytes,
            canonical_addresses,
            metadata,
            ..
        } = self;
        (
            key,
            signed_sequence,
            signed_at_us,
            signed_bytes,
            canonical_addresses,
            metadata,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DecodeError {
    InvalidPacket,
    WrongKey,
    MalformedAddress,
    InvalidAddress,
    InvalidSequence,
    OverLimit,
}
impl From<SnapshotError> for DecodeError {
    fn from(error: SnapshotError) -> Self {
        match error {
            SnapshotError::InvalidAddress | SnapshotError::UnsupportedTransport => {
                Self::InvalidAddress
            }
            SnapshotError::TooManyAddresses | SnapshotError::Oversize => Self::OverLimit,
        }
    }
}

/// Verify the upstream signed envelope, then enforce this leaf's strict DNS/TXT profile.
pub(super) fn decode_record(
    bytes: &[u8],
    expected: EndpointId,
) -> Result<DecodedRecord, DecodeError> {
    if bytes.len() < SIGNED_HEADER_BYTES || bytes.len() > SignedPacket::MAX_BYTES {
        return Err(DecodeError::InvalidPacket);
    }
    let dns = bytes
        .get(SIGNED_HEADER_BYTES..)
        .filter(|dns| !dns.is_empty() && dns.len() <= MAX_DNS_BYTES)
        .ok_or(DecodeError::InvalidPacket)?;
    if dns.len() < 12 || dns[..2] != [0, 0] || dns[2..4] != [0x80, 0] {
        return Err(DecodeError::InvalidPacket);
    }
    // The pinned parser reserves section counts before parsing; reject other sections and bound answers.
    let questions = header_buffer::questions(dns).map_err(|_| DecodeError::InvalidPacket)?;
    let answers = header_buffer::answers(dns).map_err(|_| DecodeError::InvalidPacket)?;
    let authorities = header_buffer::name_servers(dns).map_err(|_| DecodeError::InvalidPacket)?;
    let additionals =
        header_buffer::additional_records(dns).map_err(|_| DecodeError::InvalidPacket)?;
    if questions != 0
        || answers == 0
        || usize::from(answers) > MAX_TXT_RECORDS
        || authorities != 0
        || additionals != 0
    {
        return Err(DecodeError::OverLimit);
    }
    let signed = SignedPacket::from_bytes(bytes).map_err(|_| DecodeError::InvalidPacket)?;
    let key = EndpointId::from_bytes(signed.public_key().as_bytes())
        .map_err(|_| DecodeError::InvalidPacket)?;
    if key != expected {
        return Err(DecodeError::WrongKey);
    }
    let timestamp =
        i64::try_from(signed.timestamp().as_micros()).map_err(|_| DecodeError::InvalidSequence)?;
    if timestamp < 0 {
        return Err(DecodeError::InvalidSequence);
    }

    let (raw_addresses, canonical_addresses, metadata) = parse_dns_profile(dns, key)?;
    Ok(DecodedRecord {
        key,
        signed_sequence: timestamp,
        signed_at_us: timestamp,
        signed_bytes: bytes.to_vec(),
        raw_addresses,
        canonical_addresses,
        metadata,
    })
}

/// Parse a message with the dependency's strict parser, which rejects trailing bytes.
fn parse_complete_dns(dns: &[u8]) -> Result<Packet<'_>, DecodeError> {
    Packet::parse_exact(dns).map_err(|_| DecodeError::InvalidPacket)
}

/// Parse and validate DNS profile bytes; this helper does not authenticate signatures.
pub(super) fn parse_dns_profile(
    dns: &[u8],
    key: EndpointId,
) -> Result<(Vec<SocketAddr>, Vec<SocketAddr>, Vec<(String, String)>), DecodeError> {
    if dns.len() > MAX_DNS_BYTES || dns.len() < 12 || dns[..2] != [0, 0] || dns[2..4] != [0x80, 0] {
        return Err(DecodeError::InvalidPacket);
    }
    let questions = header_buffer::questions(dns).map_err(|_| DecodeError::InvalidPacket)?;
    let answers = header_buffer::answers(dns).map_err(|_| DecodeError::InvalidPacket)?;
    let authorities = header_buffer::name_servers(dns).map_err(|_| DecodeError::InvalidPacket)?;
    let additionals =
        header_buffer::additional_records(dns).map_err(|_| DecodeError::InvalidPacket)?;
    if questions != 0
        || answers == 0
        || usize::from(answers) > MAX_TXT_RECORDS
        || authorities != 0
        || additionals != 0
    {
        return Err(DecodeError::OverLimit);
    }
    let packet = parse_complete_dns(dns)?;
    if packet.id() != 0
        || packet.opcode() != OPCODE::StandardQuery
        || packet.rcode() != RCODE::NoError
        || !packet.has_flags(PacketFlag::RESPONSE)
        || packet.opt().is_some()
        || !packet.questions.is_empty()
        || packet.answers.len() != usize::from(answers)
        || !packet.name_servers.is_empty()
        || !packet.additional_records.is_empty()
    {
        return Err(DecodeError::InvalidPacket);
    }
    let origin = key.to_z32();
    let mut addresses = Vec::new();
    let mut metadata = Vec::new();
    for record in &packet.answers {
        if record.class != CLASS::IN || record.cache_flush {
            return Err(DecodeError::InvalidPacket);
        }
        let labels: Vec<&[u8]> = record.name.as_bytes().collect();
        if labels.len() != 2
            || !labels[0].eq_ignore_ascii_case(b"_iroh")
            || !labels[1].eq_ignore_ascii_case(origin.as_bytes())
        {
            return Err(DecodeError::InvalidPacket);
        }
        let RData::TXT(txt) = &record.rdata else {
            return Err(DecodeError::InvalidPacket);
        };
        let full_txt = String::try_from(txt.clone()).map_err(|_| DecodeError::MalformedAddress)?;
        if txt.iter_raw().next().is_none() {
            return Err(DecodeError::MalformedAddress);
        }
        let (key, value) = full_txt
            .split_once('=')
            .ok_or(DecodeError::MalformedAddress)?;
        if value.is_empty() {
            return Err(DecodeError::MalformedAddress);
        }
        match key {
            "addr" => {
                let parsed = value
                    .parse::<SocketAddr>()
                    .map_err(|_| DecodeError::MalformedAddress)?;
                if addresses.len() == 4 {
                    return Err(DecodeError::OverLimit);
                }
                addresses.push(parsed);
            }
            "relay" => return Err(DecodeError::InvalidAddress),
            "user-data" => {
                if value.len() > 245 || !metadata.is_empty() {
                    return Err(DecodeError::OverLimit);
                }
                metadata.push((key.to_owned(), value.to_owned()));
            }
            _ => return Err(DecodeError::MalformedAddress),
        }
    }
    if addresses.is_empty() {
        return Err(DecodeError::MalformedAddress);
    }
    let (raw_addresses, canonical_addresses) =
        validate_addresses_with_snapshot(&addresses).map_err(DecodeError::from)?;
    Ok((raw_addresses, canonical_addresses, metadata))
}
