//! Constructor-owned infrastructure reservations; no bootstrap or discovery commands yet.

use std::{io, net::SocketAddr};

use hickory_resolver::proto::rr::Name;
use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};

use crate::dns::Lifetime;

/// Explicit in-memory discovery inputs. Construction does not query DNS or bootstrap.
/// Application startup, not the carrier, is responsible for loading OS configuration.
#[derive(Clone, Debug)]
pub struct DiscoveryConfig {
    seeds: Box<[(PeerId, Multiaddr)]>,
    nameservers: Box<[SocketAddr]>,
}

impl DiscoveryConfig {
    /// Validates counts before deduplication, seed grammar, identities and numeric resolvers.
    /// Names must be absolute; ASCII case is normalized. No system defaults are consulted.
    pub fn new(
        mut seeds: Vec<(PeerId, Multiaddr)>,
        mut nameservers: Vec<SocketAddr>,
    ) -> io::Result<Self> {
        if !(1..=4).contains(&seeds.len()) {
            return Err(invalid(
                "discovery.seeds must contain one to four descriptors",
            ));
        }
        if !(1..=4).contains(&nameservers.len()) {
            return Err(invalid(
                "discovery.nameservers must contain one to four endpoints",
            ));
        }
        for (peer, address) in &mut seeds {
            *address = seed_address(*peer, address)?;
        }
        for endpoint in &nameservers {
            if !usable(*endpoint) {
                return Err(invalid(
                    "discovery.nameservers contains an unusable endpoint",
                ));
            }
        }
        // At most four elements: reuse the input storage and preserve preference order.
        for index in (0..seeds.len()).rev() {
            if seeds[..index].contains(&seeds[index]) {
                seeds.remove(index);
            }
        }
        for index in (0..nameservers.len()).rev() {
            if nameservers[..index].contains(&nameservers[index]) {
                nameservers.remove(index);
            }
        }
        Ok(Self {
            seeds: seeds.into_boxed_slice(),
            nameservers: nameservers.into_boxed_slice(),
        })
    }

    pub(crate) fn validate_identities(&self, local: PeerId, allowed: &[PeerId]) -> io::Result<()> {
        if allowed.contains(&local) {
            return Err(invalid(
                "discovery application and local identities must be distinct",
            ));
        }
        if self
            .seeds
            .iter()
            .any(|(peer, _)| *peer == local || allowed.contains(peer))
        {
            return Err(invalid(
                "discovery seed, application and local identities must be distinct",
            ));
        }
        Ok(())
    }

    pub(crate) fn nameservers(&self) -> &[SocketAddr] {
        &self.nameservers
    }

    fn is_seed(&self, peer: &PeerId) -> bool {
        self.seeds.iter().any(|(seed, _)| seed == peer)
    }
}

/// Retains the descriptors as infrastructure reservations, never application authority.
/// The later discovery owner will consume these same bounded descriptors.
pub(crate) struct State {
    pub(crate) lifetime: Lifetime,
    config: DiscoveryConfig,
}

impl State {
    pub(crate) fn new(config: DiscoveryConfig, lifetime: Lifetime) -> Self {
        Self { lifetime, config }
    }

    pub(crate) fn is_seed(&self, peer: &PeerId) -> bool {
        self.config.is_seed(peer)
    }
}

pub(crate) fn absolute_name(value: &str) -> io::Result<Name> {
    if !value.ends_with('.') || value.len() > 253 || !value.is_ascii() {
        return Err(invalid("discovery DNS names must be absolute ASCII names"));
    }
    let name = Name::from_ascii(value)
        .map_err(|_| invalid("discovery DNS name is invalid"))?
        .to_lowercase();
    if name.num_labels() == 0 || name.to_ascii() != value.to_ascii_lowercase() {
        return Err(invalid("discovery DNS name is not canonical"));
    }
    Ok(name)
}

fn seed_address(peer: PeerId, address: &Multiaddr) -> io::Result<Multiaddr> {
    if address.as_ref().len() > 256 {
        return Err(invalid("discovery.seeds address exceeds 256 encoded bytes"));
    }
    let mut parts = address.iter();
    let first = parts
        .next()
        .ok_or_else(|| invalid("discovery.seeds address is empty"))?;
    let dnsaddr = matches!(first, Protocol::Dnsaddr(_));
    let first = match first {
        Protocol::Dns(name) => Protocol::Dns(absolute_name(&name)?.to_ascii().into()),
        Protocol::Dns4(name) => Protocol::Dns4(absolute_name(&name)?.to_ascii().into()),
        Protocol::Dns6(name) => Protocol::Dns6(absolute_name(&name)?.to_ascii().into()),
        Protocol::Dnsaddr(name) => {
            let name = absolute_name(&name)?.to_ascii();
            absolute_name(&format!("_dnsaddr.{name}"))?;
            Protocol::Dnsaddr(name.into())
        }
        Protocol::Ip4(ip) if usable(SocketAddr::new(ip.into(), 1)) => Protocol::Ip4(ip),
        Protocol::Ip6(ip) if usable(SocketAddr::new(ip.into(), 1)) => Protocol::Ip6(ip),
        _ => {
            return Err(invalid(
                "discovery.seeds requires a supported TCP/DNS address",
            ));
        }
    };
    let mut normalized = Multiaddr::empty().with(first);
    if !dnsaddr {
        match parts.next() {
            Some(Protocol::Tcp(port)) if port != 0 => normalized.push(Protocol::Tcp(port)),
            _ => return Err(invalid("discovery.seeds requires a nonzero TCP port")),
        }
    }
    match parts.next() {
        Some(Protocol::P2p(expected)) if expected == peer => normalized.push(Protocol::P2p(peer)),
        None => {}
        _ => {
            return Err(invalid(
                "discovery.seeds contains an inconsistent peer suffix or grammar",
            ));
        }
    }
    if parts.next().is_some() || normalized.as_ref().len() > 256 {
        return Err(invalid(
            "discovery.seeds contains unsupported components or exceeds 256 bytes",
        ));
    }
    Ok(normalized)
}

fn usable(endpoint: SocketAddr) -> bool {
    if endpoint.port() == 0 || endpoint.ip().is_unspecified() || endpoint.ip().is_multicast() {
        return false;
    }
    match endpoint {
        SocketAddr::V4(endpoint) => !endpoint.ip().is_broadcast() && endpoint.ip().octets()[0] != 0,
        SocketAddr::V6(endpoint) => {
            endpoint.scope_id() == 0
                && endpoint.flowinfo() == 0
                && !endpoint.ip().is_unicast_link_local()
                && endpoint.ip().to_ipv4_mapped().is_none()
        }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests;
