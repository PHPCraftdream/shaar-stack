#![forbid(unsafe_code)]

use std::{io, str};

use hickory_resolver::{lookup::Lookup, proto::rr::RData};
use libp2p_core::multiaddr::{Multiaddr, Protocol};
use smallvec::SmallVec;

use crate::{Error, MAX_TXT_RECORDS, Resolver};

pub(crate) const MAX_PENDING: usize = 32;
pub(crate) const MAX_ADDRESS_BYTES: usize = 256;
pub(crate) const MAX_NUMERIC: usize = 4;
pub(crate) const MAX_ERRORS: usize = 16;
// Independent textual budget, including the dnsaddr= prefix.
pub(crate) const MAX_TXT_BYTES: usize = 1024;

type Pending = SmallVec<[Multiaddr; 1]>;

pub(crate) fn has_dns(address: &Multiaddr) -> bool {
    address.iter().any(|protocol| {
        matches!(
            protocol,
            Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_)
        )
    })
}

pub(crate) fn retain_error<E>(errors: &mut Vec<Error<E>>, error: Error<E>) {
    if errors.len() < MAX_ERRORS {
        errors.push(error);
    }
}

// Reuse the upstream codec with fixed output storage, never a growing address buffer.
pub(crate) struct Encoded {
    bytes: [u8; MAX_ADDRESS_BYTES],
    len: usize,
}

impl Encoded {
    pub(crate) fn new() -> Self {
        Self {
            bytes: [0; MAX_ADDRESS_BYTES],
            len: 0,
        }
    }

    pub(crate) fn push(&mut self, protocol: Protocol<'_>) -> io::Result<()> {
        let mut remaining = &mut self.bytes[self.len..];
        protocol
            .write_bytes(&mut remaining)
            .map_err(crate::invalid_data)?;
        self.len = MAX_ADDRESS_BYTES - remaining.len();
        Ok(())
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn address(&self) -> io::Result<Multiaddr> {
        Multiaddr::try_from(self.bytes().to_vec()).map_err(crate::invalid_data)
    }
}

pub(crate) fn push_numeric(
    pending: &mut Pending,
    original: &Multiaddr,
    index: usize,
    ip: Protocol<'_>,
    resolver: &impl Resolver,
) {
    if pending.len() >= MAX_PENDING {
        return;
    }
    let mut encoded = Encoded::new();
    for protocol in original
        .iter()
        .take(index)
        .chain(std::iter::once(ip))
        .chain(original.iter().skip(index + 1))
    {
        if encoded.push(protocol).is_err() {
            return;
        }
    }
    if pending
        .iter()
        .any(|address| address.as_ref() == encoded.bytes())
    {
        return;
    }
    if !resolver.permits_address(encoded.bytes()) {
        return;
    }
    if let Ok(address) = encoded.address() {
        pending.push(address);
    }
}

pub(crate) fn push_txt(
    pending: &mut Pending,
    original: &Multiaddr,
    index: usize,
    lookup: Lookup,
    resolver: &impl Resolver,
) {
    let mut suffix = Encoded::new();
    for protocol in original.iter().skip(index + 1) {
        if suffix.push(protocol).is_err() {
            return;
        }
    }
    let mut accepted = 0;
    for record in lookup.answers() {
        if accepted == MAX_TXT_RECORDS || pending.len() >= MAX_PENDING {
            break;
        }
        let RData::TXT(txt) = &record.data else {
            continue;
        };
        // Bound the whole decoded TXT before inspecting its first character-string.
        let size = txt.txt_data.iter().try_fold(0usize, |size, part| {
            size.checked_add(part.len())
                .filter(|size| *size <= MAX_TXT_BYTES)
        });
        if size.is_none() {
            continue;
        }
        let Some(text) = txt.txt_data.first() else {
            continue;
        };
        let Ok(encoded) = parse_txt(text, original, index) else {
            continue;
        };
        // Match the candidate alone, not bytes inherited from its outer prefix.
        if !encoded.0.bytes()[encoded.1..].ends_with(suffix.bytes())
            || pending
                .iter()
                .any(|address| address.as_ref() == encoded.0.bytes())
        {
            continue;
        }
        if !resolver.permits_address(encoded.0.bytes()) {
            continue;
        }
        if let Ok(address) = encoded.0.address() {
            accepted += 1;
            pending.push(address);
        }
    }
}

pub(crate) fn parse_txt(
    text: &[u8],
    original: &Multiaddr,
    index: usize,
) -> io::Result<(Encoded, usize)> {
    if text.len() > MAX_TXT_BYTES {
        return Err(crate::invalid_data("DNS TXT exceeds the textual budget"));
    }
    let text = str::from_utf8(text).map_err(crate::invalid_data)?;
    let address = text
        .strip_prefix("dnsaddr=")
        .ok_or_else(|| crate::invalid_data("Missing dnsaddr= prefix"))?;
    let mut encoded = Encoded::new();
    for protocol in original.iter().take(index) {
        encoded.push(protocol)?;
    }
    let prefix_len = encoded.len;
    // Same component parser and slash grammar as Multiaddr::from_str.
    let mut parts = address.split('/').peekable();
    if parts.next() != Some("") {
        return Err(crate::invalid_data("Multiaddr must start with /"));
    }
    while parts.peek().is_some() {
        let protocol = Protocol::from_str_parts(&mut parts).map_err(crate::invalid_data)?;
        encoded.push(protocol)?;
    }
    Ok((encoded, prefix_len))
}
