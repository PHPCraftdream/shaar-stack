//! Asking the gateway for a UDP port mapping (leaf PORT-1, owner decision of 2026-11-18).
//!
//! A device that binds its QUIC socket on a port of the fixed set ([`super`]) asks its gateway to
//! forward the same external port to it, so the endpoint it publishes is known in advance. Two
//! protocols are tried on the gateway's UDP port 5351: PCP (RFC 6887) first, and NAT-PMP
//! (RFC 6886) when the gateway answers a PCP request with "unsupported version" or not at all.
//! UPnP IGD ([`upnp`]) is the third, tried by [`map_any`] when both failed.
//! The gateway is a parameter: the caller finds it (the home router) and tests give a fake one.
//! One mapping is made and released by one call each; keeping it alive is the caller's task.

mod keeper;
mod natpmp;
mod pcp;
mod probe;
#[cfg(test)]
mod tests;
mod upnp;

pub use keeper::{DEFAULT_TIMING, Keeper, State, Timing};
pub use probe::{
    Gateway, MEASURE_BUDGET, MEASURE_LIFETIME, home_gateway, measure, measure_upnp, measure_within,
};

use std::{
    fmt,
    hash::{BuildHasher, RandomState},
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use tokio::{
    net::UdpSocket,
    time::{Instant, timeout_at},
};

/// The UDP port that PCP and NAT-PMP use on the gateway.
pub const GATEWAY_PORT: u16 = 5351;
/// Wait for the first answer; it doubles with every resend of the same request.
const FIRST_WAIT: Duration = Duration::from_millis(250);
/// Bound of the request for the external address that follows a NAT-PMP grant.
const EXTERNAL_BUDGET: Duration = Duration::from_millis(500);
/// Bound of the deletion of a mapping.
const RELEASE_BUDGET: Duration = Duration::from_millis(500);

/// The protocol that the gateway answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Pcp,
    NatPmp,
    Upnp,
}

impl Protocol {
    /// The token of the diagnostic lines.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Pcp => "pcp",
            Self::NatPmp => "nat-pmp",
            Self::Upnp => "upnp",
        }
    }
}

/// A mapping that the gateway granted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub protocol: Protocol,
    pub internal_port: u16,
    /// The external port the gateway assigned; it may differ from the one asked for.
    pub external_port: u16,
    /// The external address of the gateway when it told it.
    pub external_ip: Option<IpAddr>,
    /// How long the gateway keeps the mapping without a renewal.
    pub lifetime: Duration,
    nonce: pcp::Nonce,
    /// The control endpoint of a UPnP mapping.
    igd: Option<Arc<upnp::Igd>>,
}

/// Why no mapping was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    /// The gateway answered with this result code.
    Refused(u16),
    /// No answer in time, or nothing listens on the gateway's port.
    Silent,
    /// The gateway answered but offers no mapping service, or its answer cannot be used.
    Unsupported,
    /// The socket failed.
    Io,
}

impl MapError {
    /// How much the error says about the gateway; the more telling of two is reported.
    const fn weight(self) -> u8 {
        match self {
            Self::Refused(_) => 3,
            Self::Unsupported => 2,
            Self::Io => 1,
            Self::Silent => 0,
        }
    }
}

impl fmt::Display for MapError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(code) => write!(out, "refused:{code}"),
            Self::Silent => out.write_str("silent"),
            Self::Unsupported => out.write_str("unsupported"),
            Self::Io => out.write_str("io"),
        }
    }
}

/// A fresh nonce from the random keys the standard library seeds its hashers with.
fn fresh_nonce() -> pcp::Nonce {
    let mut nonce = [0_u8; 12];
    nonce[..8].copy_from_slice(&RandomState::new().hash_one(0_u8).to_be_bytes());
    nonce[8..].copy_from_slice(&RandomState::new().hash_one(1_u8).to_be_bytes()[..4]);
    nonce
}

async fn socket_for(gateway: SocketAddr) -> Result<UdpSocket, MapError> {
    let any = match gateway {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let socket = UdpSocket::bind((any, 0)).await.map_err(|_| MapError::Io)?;
    // A connected socket only receives from the gateway.
    socket.connect(gateway).await.map_err(|_| MapError::Io)?;
    Ok(socket)
}

/// Sends `request` and resends it with doubling waits until a datagram that `decode` accepts
/// arrives or `deadline` passes; datagrams that `decode` does not accept are ignored.
async fn exchange<T>(
    socket: &UdpSocket,
    request: &[u8],
    deadline: Instant,
    decode: impl Fn(&[u8]) -> Option<T>,
) -> Result<T, MapError> {
    let mut wait = FIRST_WAIT;
    let mut buffer = [0_u8; 128];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(MapError::Silent);
        }
        socket.send(request).await.map_err(|_| MapError::Io)?;
        let until = deadline.min(now + wait);
        loop {
            match timeout_at(until, socket.recv(&mut buffer)).await {
                Ok(Ok(length)) => {
                    if let Some(answer) = decode(&buffer[..length]) {
                        return Ok(answer);
                    }
                }
                // An ICMP error from a gateway that has no mapping service.
                Ok(Err(error))
                    if matches!(
                        error.kind(),
                        ErrorKind::ConnectionReset | ErrorKind::ConnectionRefused
                    ) =>
                {
                    return Err(MapError::Silent);
                }
                Ok(Err(_)) => return Err(MapError::Io),
                Err(_) => break,
            }
        }
        wait *= 2;
    }
}

/// Asks `gateway` (its address with [`GATEWAY_PORT`]) to forward UDP `external_port` to
/// `internal_port` of this host, whose address on the gateway's network is `local`, for
/// `lifetime`. Gives up after `budget`; PCP gets two fifths of it, NAT-PMP the rest.
/// cancel-safe: yes — a cancelled call may leave a mapping that the gateway expires.
pub async fn map_udp(
    gateway: SocketAddr,
    local: IpAddr,
    internal_port: u16,
    external_port: u16,
    lifetime: Duration,
    budget: Duration,
) -> Result<Mapping, MapError> {
    let ports = (internal_port, external_port);
    map_with(fresh_nonce(), gateway, local, ports, lifetime, budget).await
}

/// Maps `port` to the same external port at `gateway` by PCP or NAT-PMP, and when both fail by
/// UPnP; each stage gets `budget`. The error reported is the most telling of the two.
/// cancel-safe: yes — a cancelled call may leave a mapping that the gateway expires.
pub async fn map_any(
    gateway: Gateway,
    port: u16,
    lifetime: Duration,
    budget: Duration,
) -> Result<Mapping, MapError> {
    let first = match map_udp(gateway.address, gateway.local, port, port, lifetime, budget).await {
        Ok(mapping) => return Ok(mapping),
        Err(error) => error,
    };
    match map_upnp(gateway, port, lifetime, budget).await {
        Ok(mapping) => Ok(mapping),
        Err(second) if second.weight() > first.weight() => Err(second),
        Err(_) => Err(first),
    }
}

/// Maps `port` to the same external port by UPnP only: finds the gateway at `gateway.upnp` and
/// asks it. Gives up after `budget`.
/// cancel-safe: yes — a cancelled call may leave a mapping that the gateway expires.
pub async fn map_upnp(
    gateway: Gateway,
    port: u16,
    lifetime: Duration,
    budget: Duration,
) -> Result<Mapping, MapError> {
    let (igd, external_ip) =
        upnp::map(gateway.upnp, gateway.local, (port, port), lifetime, budget).await?;
    Ok(Mapping {
        protocol: Protocol::Upnp,
        internal_port: port,
        external_port: port,
        external_ip,
        lifetime,
        nonce: [0; 12],
        igd: Some(Arc::new(igd)),
    })
}

/// Renews `mapping` for `lifetime` more. A PCP or NAT-PMP mapping gets the same request with the
/// same nonce, asking for the external port the gateway assigned, and the answer replaces the
/// mapping; a UPnP mapping gets its request again at the endpoint it was made at.
/// cancel-safe: yes.
pub async fn renew(
    gateway: SocketAddr,
    local: IpAddr,
    mapping: &Mapping,
    lifetime: Duration,
    budget: Duration,
) -> Result<Mapping, MapError> {
    let ports = (mapping.internal_port, mapping.external_port);
    if let Some(igd) = &mapping.igd {
        upnp::renew(igd, local, ports, lifetime, budget).await?;
        return Ok(Mapping {
            lifetime,
            ..mapping.clone()
        });
    }
    map_with(mapping.nonce, gateway, local, ports, lifetime, budget).await
}

async fn map_with(
    nonce: pcp::Nonce,
    gateway: SocketAddr,
    local: IpAddr,
    (internal_port, external_port): (u16, u16),
    lifetime: Duration,
    budget: Duration,
) -> Result<Mapping, MapError> {
    let socket = socket_for(gateway).await?;
    let seconds = u32::try_from(lifetime.as_secs()).unwrap_or(u32::MAX);
    let started = Instant::now();
    let request = pcp::map_request(local, &nonce, internal_port, external_port, seconds);
    let pcp_deadline = started + budget * 2 / 5;
    match exchange(&socket, &request, pcp_deadline, |reply| {
        pcp::decode(reply, &nonce, internal_port)
    })
    .await
    {
        Ok(pcp::Reply::Granted(granted)) => {
            return Ok(Mapping {
                protocol: Protocol::Pcp,
                internal_port,
                external_port: granted.external_port,
                external_ip: Some(granted.external_ip).filter(|ip| !ip.is_unspecified()),
                lifetime: Duration::from_secs(granted.lifetime.into()),
                nonce,
                igd: None,
            });
        }
        Ok(pcp::Reply::Refused(code)) => return Err(MapError::Refused(code.into())),
        Ok(pcp::Reply::NatPmpOnly) | Err(MapError::Silent) => {}
        Err(error) => return Err(error),
    }
    let request = natpmp::map_request(internal_port, external_port, seconds);
    let granted = exchange(&socket, &request, started + budget, |reply| {
        natpmp::decode_map(reply, internal_port)
    })
    .await?
    .map_err(MapError::Refused)?;
    let external_ip = exchange(
        &socket,
        &natpmp::external_address_request(),
        Instant::now() + EXTERNAL_BUDGET,
        natpmp::decode_external,
    )
    .await
    .ok()
    .and_then(Result::ok)
    .map(IpAddr::V4);
    Ok(Mapping {
        protocol: Protocol::NatPmp,
        internal_port,
        external_port: granted.external_port,
        external_ip,
        lifetime: Duration::from_secs(granted.lifetime.into()),
        nonce,
        igd: None,
    })
}

/// Deletes `mapping` at `gateway`, once, within a short bound; a gateway that does not answer
/// still expires the mapping by itself after its lifetime.
/// cancel-safe: yes.
pub async fn release(
    gateway: SocketAddr,
    local: IpAddr,
    mapping: &Mapping,
) -> Result<(), MapError> {
    if let Some(igd) = &mapping.igd {
        return upnp::delete(igd, mapping.external_port, RELEASE_BUDGET).await;
    }
    let socket = socket_for(gateway).await?;
    let deadline = Instant::now() + RELEASE_BUDGET;
    let internal = mapping.internal_port;
    match mapping.protocol {
        Protocol::Pcp => {
            let request = pcp::map_request(local, &mapping.nonce, internal, 0, 0);
            match exchange(&socket, &request, deadline, |reply| {
                pcp::decode(reply, &mapping.nonce, internal)
            })
            .await?
            {
                pcp::Reply::Granted(_) => Ok(()),
                pcp::Reply::Refused(code) => Err(MapError::Refused(code.into())),
                pcp::Reply::NatPmpOnly => Err(MapError::Refused(1)),
            }
        }
        Protocol::NatPmp => {
            let request = natpmp::map_request(internal, 0, 0);
            exchange(&socket, &request, deadline, |reply| {
                natpmp::decode_map(reply, internal)
            })
            .await?
            .map(|_| ())
            .map_err(MapError::Refused)
        }
        // A UPnP mapping carries its endpoint and was released above.
        Protocol::Upnp => Err(MapError::Unsupported),
    }
}
