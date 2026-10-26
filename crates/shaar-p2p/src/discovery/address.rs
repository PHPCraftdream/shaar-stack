use std::io;

use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};

use super::{absolute_name, invalid, scope::discovery_ip_allowed};

const MAX_ENCODED: usize = 256;

/// Borrows the complete encoding; the returned host borrows its DNS text from `bytes`.
/// This is scope/grammar classification, not peer authorization or DNS resolution.
pub(super) fn classify_complete(
    bytes: &[u8],
    expected: PeerId,
) -> io::Result<(Protocol<'_>, Option<u16>)> {
    if bytes.len() > MAX_ENCODED {
        return Err(invalid("discovery.seeds address exceeds 256 encoded bytes"));
    }
    let (host, mut rest) = decode(bytes)?;
    match &host {
        Protocol::Ip4(ip) if discovery_ip_allowed((*ip).into()) => {}
        Protocol::Ip6(ip) if discovery_ip_allowed((*ip).into()) => {}
        Protocol::Dns(name)
        | Protocol::Dns4(name)
        | Protocol::Dns6(name)
        | Protocol::Dnsaddr(name) => {
            if name.bytes().any(|byte| byte.is_ascii_uppercase()) {
                return Err(invalid("discovery DNS name is not canonical"));
            }
            absolute_name(name)?;
            if matches!(host, Protocol::Dnsaddr(_)) {
                absolute_name(&format!("_dnsaddr.{name}"))?;
            }
        }
        Protocol::Ip4(_) | Protocol::Ip6(_) => {
            return Err(invalid("discovery.seeds contains a forbidden IP scope"));
        }
        _ => {
            return Err(invalid(
                "discovery.seeds requires a supported TCP/DNS address",
            ));
        }
    }
    let port = if matches!(host, Protocol::Dnsaddr(_)) {
        None
    } else {
        let (transport, remaining) = decode(rest)?;
        rest = remaining;
        match transport {
            Protocol::Tcp(port) if port != 0 => Some(port),
            _ => return Err(invalid("discovery.seeds requires a nonzero TCP port")),
        }
    };
    let (suffix, trailing) = decode(rest)?;
    if !matches!(suffix, Protocol::P2p(peer) if peer == expected) || !trailing.is_empty() {
        return Err(invalid(
            "discovery.seeds contains an inconsistent peer suffix or grammar",
        ));
    }
    Ok((host, port))
}

fn decode(bytes: &[u8]) -> io::Result<(Protocol<'_>, &[u8])> {
    Protocol::from_bytes(bytes)
        .map_err(|_| invalid("discovery.seeds contains an invalid complete address"))
}

pub(super) fn seed_address(peer: PeerId, address: &Multiaddr) -> io::Result<Multiaddr> {
    if address.as_ref().len() > MAX_ENCODED {
        return Err(invalid("discovery.seeds address exceeds 256 encoded bytes"));
    }
    let mut parts = address.iter();
    let first = parts
        .next()
        .ok_or_else(|| invalid("discovery.seeds address is empty"))?;
    let first = match first {
        Protocol::Dns(name) => Protocol::Dns(absolute_name(&name)?.to_ascii().into()),
        Protocol::Dns4(name) => Protocol::Dns4(absolute_name(&name)?.to_ascii().into()),
        Protocol::Dns6(name) => Protocol::Dns6(absolute_name(&name)?.to_ascii().into()),
        Protocol::Dnsaddr(name) => Protocol::Dnsaddr(absolute_name(&name)?.to_ascii().into()),
        other => other,
    };
    // Qualify into bounded scratch, not an inspection-only owned Multiaddr.
    let mut scratch = [0; MAX_ENCODED];
    let mut writer = scratch.as_mut_slice();
    let mut had_suffix = false;
    for part in std::iter::once(first).chain(parts) {
        had_suffix = matches!(part, Protocol::P2p(_));
        part.write_bytes(&mut writer)
            .map_err(|_| invalid("discovery.seeds address exceeds 256 encoded bytes"))?;
    }
    if !had_suffix {
        Protocol::P2p(peer)
            .write_bytes(&mut writer)
            .map_err(|_| invalid("discovery.seeds address exceeds 256 encoded bytes"))?;
    }
    let length = MAX_ENCODED - writer.len();
    let (host, port) = classify_complete(&scratch[..length], peer)?;
    let mut normalized = Multiaddr::empty().with(host);
    if let Some(port) = port {
        normalized.push(Protocol::Tcp(port));
    }
    if had_suffix {
        normalized.push(Protocol::P2p(peer));
    }
    Ok(normalized)
}
