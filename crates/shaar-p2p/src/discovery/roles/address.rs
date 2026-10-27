use std::{io, net::SocketAddr};

use libp2p::{PeerId, multiaddr::Protocol};
use tokio::time::Instant;

use super::{AttemptKey, Lease, LeaseKind, Owner, Role, View, denied, live, numeric_usable};

const ENCODED_LIMIT: usize = 256;

/// One authority constraint, not an address-hint cache: at most 2048 bytes across attempts.
/// Construction parses before locking and never materializes an inspection-only Multiaddr.
pub(crate) struct Root {
    bytes: [u8; ENCODED_LIMIT],
    length: usize,
    parsed: Parsed,
    #[cfg(test)]
    fixture_endpoint: Option<SocketAddr>,
}

#[derive(Clone, Copy)]
struct Parsed {
    peer: PeerId,
    endpoint: Option<SocketAddr>,
    strict: bool,
}

impl Root {
    pub(crate) fn new(encoded: &[u8], expected: PeerId) -> io::Result<Self> {
        let parsed = parse(encoded)?;
        if parsed.peer != expected {
            return Err(denied());
        }
        let mut bytes = [0; ENCODED_LIMIT];
        bytes[..encoded.len()].copy_from_slice(encoded);
        Ok(Self {
            bytes,
            length: encoded.len(),
            parsed,
            #[cfg(test)]
            fixture_endpoint: None,
        })
    }

    fn matches(&self, encoded: &[u8]) -> bool {
        &self.bytes[..self.length] == encoded
    }
}

fn decode(bytes: &[u8]) -> io::Result<(Protocol<'_>, &[u8])> {
    Protocol::from_bytes(bytes).map_err(|_| denied())
}

fn parse(encoded: &[u8]) -> io::Result<Parsed> {
    if encoded.len() > ENCODED_LIMIT {
        return Err(denied());
    }
    let (host, mut rest) = decode(encoded)?;
    let port = if matches!(host, Protocol::Dnsaddr(_)) {
        None
    } else {
        let (part, remaining) = decode(rest)?;
        rest = remaining;
        match part {
            Protocol::Tcp(port) if port != 0 => Some(port),
            _ => return Err(denied()),
        }
    };
    let (Protocol::P2p(peer), trailing) = decode(rest)? else {
        return Err(denied());
    };
    if !trailing.is_empty() {
        return Err(denied());
    }
    let endpoint = match host {
        Protocol::Ip4(ip) => Some(SocketAddr::new(ip.into(), port.ok_or_else(denied)?)),
        Protocol::Ip6(ip) => Some(SocketAddr::new(ip.into(), port.ok_or_else(denied)?)),
        Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_) => None,
        _ => return Err(denied()),
    };
    let strict = match endpoint {
        Some(endpoint) => super::super::scope::discovery_ip_allowed(endpoint.ip()),
        None => super::super::address::classify_complete(encoded, peer).is_ok(),
    };
    if endpoint.is_some_and(|value| !numeric_usable(value)) || (endpoint.is_none() && !strict) {
        return Err(denied());
    }
    Ok(Parsed {
        peer,
        endpoint,
        strict,
    })
}

fn permitted(role: Role, root: &Root, parsed: Parsed) -> bool {
    match role {
        Role::Application => parsed.endpoint.is_some() && parsed.endpoint == root.parsed.endpoint,
        Role::ExplicitRelay(endpoint) => parsed.endpoint == Some(endpoint),
        Role::Infrastructure => {
            parsed.strict
                && root
                    .parsed
                    .endpoint
                    .is_none_or(|endpoint| parsed.endpoint == Some(endpoint))
        }
    }
}

impl Owner {
    #[cfg(test)]
    pub(crate) fn pin_fixture_root(
        &mut self,
        key: AttemptKey,
        mut root: Root,
        endpoint: SocketAddr,
        now: Instant,
    ) -> io::Result<()> {
        let mut state = self.view.lock();
        if state.closed {
            return Err(denied());
        }
        let attempt = state.attempts.get_mut(&key.connection).ok_or_else(denied)?;
        if attempt.key != key
            || attempt.revoked
            || attempt.terminal
            || now >= attempt.deadline
            || attempt.role != Role::ExplicitRelay(endpoint)
            || root.parsed.peer != key.peer
            || root.parsed.endpoint.is_some()
            || attempt.root.is_some()
        {
            return Err(denied());
        }
        root.fixture_endpoint = Some(endpoint);
        attempt.root = Some(root);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn allow_infrastructure_fixture(
        &mut self,
        key: AttemptKey,
        encoded: &[u8],
        endpoint: SocketAddr,
        now: Instant,
    ) -> io::Result<()> {
        let mut state = self.view.lock();
        if state.closed
            || !endpoint.ip().is_loopback()
            || endpoint.port() == 0
            || !state
                .infrastructure
                .iter()
                .flatten()
                .any(|row| row.key == key)
        {
            return Err(denied());
        }
        let attempt = state.attempts.get_mut(&key.connection).ok_or_else(denied)?;
        if attempt.key != key
            || attempt.revoked
            || attempt.terminal
            || now >= attempt.deadline
            || attempt.role != Role::Infrastructure
        {
            return Err(denied());
        }
        let root = attempt.root.as_mut().ok_or_else(denied)?;
        if root.parsed.endpoint.is_some() || !root.matches(encoded) {
            return Err(denied());
        }
        root.fixture_endpoint = Some(endpoint);
        Ok(())
    }

    /// Pin the trusted, fully peer-qualified selected root before transport invocation.
    /// A staged attempt without this owner-only step grants no address authority.
    pub(crate) fn pin_root(&mut self, key: AttemptKey, root: Root, now: Instant) -> io::Result<()> {
        let mut state = self.view.lock();
        if state.closed {
            return Err(denied());
        }
        let attempt = state.attempts.get_mut(&key.connection).ok_or_else(denied)?;
        if attempt.key != key
            || attempt.revoked
            || attempt.terminal
            || now >= attempt.deadline
            || root.parsed.peer != key.peer
            || attempt.root.is_some()
            || !permitted(attempt.role, &root, root.parsed)
        {
            return Err(denied());
        }
        attempt.root = Some(root);
        Ok(())
    }
}

impl View {
    pub(crate) fn matches_root(&self, key: AttemptKey, encoded: &[u8], now: Instant) -> bool {
        let state = self.lock();
        state.attempts.get(&key.connection).is_some_and(|attempt| {
            attempt.key == key
                && live(&state, attempt, now)
                && attempt
                    .root
                    .as_ref()
                    .is_some_and(|root| root.matches(encoded))
        })
    }

    fn address_key(
        &self,
        encoded: &[u8],
        initial: bool,
        now: Instant,
    ) -> io::Result<(AttemptKey, Option<SocketAddr>)> {
        let parsed = parse(encoded)?;
        let state = self.lock();
        let attempt = state
            .attempts
            .values()
            .find(|entry| entry.key.peer == parsed.peer)
            .ok_or_else(denied)?;
        let root = attempt.root.as_ref().ok_or_else(denied)?;
        let fixture_authorized = {
            #[cfg(test)]
            {
                match (root.fixture_endpoint, attempt.role) {
                    (Some(endpoint), Role::Infrastructure) => {
                        if initial {
                            parsed.endpoint.is_none() && root.matches(encoded)
                        } else {
                            parsed.endpoint == Some(endpoint)
                        }
                    }
                    (Some(endpoint), Role::ExplicitRelay(pinned)) if endpoint == pinned => {
                        if initial {
                            parsed.endpoint.is_none() && root.matches(encoded)
                        } else {
                            parsed.endpoint == Some(endpoint)
                        }
                    }
                    _ => false,
                }
            }
            #[cfg(not(test))]
            {
                false
            }
        };
        if !live(&state, attempt, now)
            || (!permitted(attempt.role, root, parsed) && !fixture_authorized)
            || (initial && !root.matches(encoded))
            || (!initial && attempt.roots == 0)
        {
            return Err(denied());
        }
        Ok((attempt.key, parsed.endpoint))
    }

    pub(crate) fn permits_address(&self, encoded: &[u8]) -> bool {
        self.address_key(encoded, false, Instant::now()).is_ok()
    }

    pub(crate) fn root_lease(&self, encoded: &[u8]) -> io::Result<Lease> {
        let (key, _) = self.address_key(encoded, true, Instant::now())?;
        self.lease(key, LeaseKind::Root, Instant::now())
    }

    pub(crate) fn numeric_lease(&self, encoded: &[u8]) -> io::Result<(Lease, SocketAddr)> {
        let (key, endpoint) = self.address_key(encoded, false, Instant::now())?;
        let endpoint = endpoint.ok_or_else(denied)?;
        Ok((
            self.lease(key, LeaseKind::Numeric, Instant::now())?,
            endpoint,
        ))
    }

    pub(super) fn pinned_numeric(role: Role, root: &Root, endpoint: SocketAddr) -> bool {
        #[cfg(test)]
        if role == Role::Infrastructure && root.fixture_endpoint.is_some() {
            return root.fixture_endpoint == Some(endpoint);
        }
        permitted(
            role,
            root,
            Parsed {
                peer: root.parsed.peer,
                endpoint: Some(endpoint),
                strict: super::super::scope::discovery_ip_allowed(endpoint.ip()),
            },
        )
    }
}
