//! Operator measurement of the NAT in front of this machine (leaf NAT-3a): the external UDP port
//! that a few fresh sockets get when they talk to the Mainline bootstrap hosts, the pattern of
//! those ports and whether they depend on the destination. Ports and counts only unless the
//! operator asks for the external address (`show_address`): no key is read, and the traffic is one
//! ping per socket and host.
//!
//! With `map` (leaf NAT-6) the sockets sit on ports of the fixed set and the home router is asked
//! to map each port to itself for the length of the run; the run then says whether the external
//! port the DHT hosts see is the mapped one, which tells the router's NAT from the one behind it.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout, timeout_at};

use crate::config::MainlineNetwork;
use crate::network::ports::PORTS;
use crate::network::ports::mapping::{
    Gateway, MEASURE_BUDGET, MEASURE_LIFETIME, Mapping, home_gateway, map_any, release,
};

/// Sockets measured when the operator names no number.
pub const DEFAULT_SOCKETS: u8 = 6;
/// Most sockets one run may open.
pub const MAX_SOCKETS: u8 = 16;
/// How long one socket waits for the answers to its pings.
pub const ANSWER_WAIT: Duration = Duration::from_secs(2);
/// Bound for resolving the bootstrap host names.
const RESOLVE_WAIT: Duration = Duration::from_secs(5);
/// Distinct bootstrap hosts each socket pings (two, to see whether the port depends on the host).
const HOSTS: usize = 2;
const MAX_PACKET: usize = 1500;
/// Ping rounds of [`learn_external`] before it gives up.
const ROUNDS: u8 = 3;
/// Deepest nesting the reply walker follows.
const MAX_DEPTH: u8 = 8;

/// Measures `sockets` fresh sockets against the bootstrap hosts of `network` and returns the lines
/// to print. With `map` the sockets sit on ports of the fixed set and the home router is asked to
/// map each of them until the run ends.
pub async fn nat_ports(
    network: &MainlineNetwork,
    sockets: u8,
    show_address: bool,
    map: bool,
) -> Result<Vec<String>, String> {
    let hosts = bootstrap_hosts(network).await;
    if map {
        let gateway = home_gateway().await;
        measure_mapped(&hosts, sockets, ANSWER_WAIT, show_address, gateway, &PORTS).await
    } else {
        measure(&hosts, sockets, ANSWER_WAIT, show_address).await
    }
}

/// The first `HOSTS` distinct bootstrap hosts: numeric entries first, then resolved names.
pub(crate) async fn bootstrap_hosts(network: &MainlineNetwork) -> Vec<SocketAddrV4> {
    let mut found: Vec<SocketAddrV4> = network.bootstrap().to_vec();
    for host in network.hosts() {
        let looked_up = timeout(
            RESOLVE_WAIT,
            tokio::net::lookup_host((host.name(), host.port())),
        )
        .await;
        if let Ok(Ok(addresses)) = looked_up {
            found.extend(addresses.filter_map(|address| match address {
                SocketAddr::V4(v4) if !v4.ip().is_unspecified() && v4.port() != 0 => Some(v4),
                _ => None,
            }));
        }
    }
    distinct_hosts(found)
}

/// The first `HOSTS` endpoints that sit on different addresses.
fn distinct_hosts(found: Vec<SocketAddrV4>) -> Vec<SocketAddrV4> {
    let mut distinct: Vec<SocketAddrV4> = Vec::with_capacity(HOSTS);
    for address in found {
        if distinct.len() < HOSTS && distinct.iter().all(|seen| seen.ip() != address.ip()) {
            distinct.push(address);
        }
    }
    distinct
}

/// Opens `sockets` sockets, then lets each ping every host in turn and records the port the host
/// reports for it. `wait` bounds the answers of one socket.
pub(crate) async fn measure(
    hosts: &[SocketAddrV4],
    sockets: u8,
    wait: Duration,
    show_address: bool,
) -> Result<Vec<String>, String> {
    run(hosts, sockets, wait, show_address, Router::Ignored).await
}

/// [`measure`] on the first free of `ports` (the fixed set): each port is asked of `gateway`
/// (`None`: the system names no home router) before its socket pings, and the mappings are held
/// until every socket has been measured and then deleted.
pub(crate) async fn measure_mapped(
    hosts: &[SocketAddrV4],
    sockets: u8,
    wait: Duration,
    show_address: bool,
    gateway: Option<Gateway>,
    ports: &[u16],
) -> Result<Vec<String>, String> {
    run(
        hosts,
        sockets,
        wait,
        show_address,
        Router::Asked(gateway, ports),
    )
    .await
}

/// Whether a run asks a router for mappings.
#[derive(Clone, Copy)]
enum Router<'a> {
    /// No mapping: fresh sockets on ports the system picks.
    Ignored,
    /// Sockets on the first free of these ports, each asked of this gateway.
    Asked(Option<Gateway>, &'a [u16]),
}

async fn bind_fresh(count: u8) -> Result<Vec<UdpSocket>, String> {
    let mut bound = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .map_err(|error| format!("could not open a UDP socket: {error}"))?;
        bound.push(socket);
    }
    Ok(bound)
}

/// `count` sockets on the first free ports of the fixed set, in the order of the set.
async fn bind_fixed(count: u8, candidates: &[u16]) -> Result<Vec<UdpSocket>, String> {
    let mut bound = Vec::with_capacity(usize::from(count));
    for &port in candidates {
        if bound.len() == usize::from(count) {
            break;
        }
        if let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).await {
            bound.push(socket);
        }
    }
    if bound.len() < usize::from(count) {
        return Err(format!(
            "could not open {count} UDP sockets on ports of the fixed set"
        ));
    }
    Ok(bound)
}

/// Asks `gateway` to map `port` to itself; the line says what came of it and the mapping is
/// returned when one was granted.
async fn ask_router(
    gateway: Option<Gateway>,
    index: usize,
    port: u16,
) -> (String, Option<Mapping>) {
    let head = format!("nat-ports socket={} local_port={port}", index + 1);
    let Some(gateway) = gateway else {
        return (format!("{head} map=no-gateway"), None);
    };
    match map_any(gateway, port, MEASURE_LIFETIME, MEASURE_BUDGET).await {
        Ok(mapping) => (
            format!(
                "{head} map=granted protocol={} mapped_port={}",
                mapping.protocol.token(),
                mapping.external_port
            ),
            Some(mapping),
        ),
        Err(error) => (format!("{head} map={error}"), None),
    }
}

/// Deletes the held mappings at `gateway`; returns how many it deleted.
async fn release_all(gateway: Option<Gateway>, held: &[Option<Mapping>]) -> usize {
    let Some(gateway) = gateway else {
        return 0;
    };
    let mut released = 0;
    for mapping in held.iter().flatten() {
        if release(gateway.address, gateway.local, mapping)
            .await
            .is_ok()
        {
            released += 1;
        }
    }
    released
}

async fn run(
    hosts: &[SocketAddrV4],
    sockets: u8,
    wait: Duration,
    show_address: bool,
    router: Router<'_>,
) -> Result<Vec<String>, String> {
    if hosts.is_empty() {
        return Err(
            "no DHT bootstrap hosts are available (see `config network public`)".to_owned(),
        );
    }
    if sockets == 0 || sockets > MAX_SOCKETS {
        return Err(format!("sockets must be 1 to {MAX_SOCKETS}"));
    }
    let bound = match router {
        Router::Ignored => bind_fresh(sockets).await?,
        Router::Asked(_, candidates) => bind_fixed(sockets, candidates).await?,
    };
    let mut locals = Vec::with_capacity(bound.len());
    let mut seen = Vec::with_capacity(bound.len());
    let mut held = Vec::with_capacity(bound.len());
    let mut lines = Vec::new();
    for (index, socket) in bound.iter().enumerate() {
        let local = socket
            .local_addr()
            .map_err(|error| format!("could not read a socket port: {error}"))?
            .port();
        if let Router::Asked(gateway, _) = router {
            let (line, mapping) = ask_router(gateway, index, local).await;
            lines.push(line);
            held.push(mapping);
        }
        let answers = ask(socket, hosts, index, wait).await;
        for (host, answer) in answers.iter().enumerate() {
            let external = answer.map_or_else(|| "none".to_owned(), |seen| seen.port().to_string());
            let address = match answer {
                Some(seen) if show_address => format!(" external_ip={}", seen.ip()),
                _ => String::new(),
            };
            lines.push(format!(
                "nat-ports socket={} local_port={local} host={} external_port={external}{address}",
                index + 1,
                host + 1
            ));
        }
        locals.push(local);
        seen.push(
            answers
                .iter()
                .map(|answer| answer.map(|a| a.port()))
                .collect(),
        );
    }
    lines.push(summary(&locals, &seen));
    if let Router::Asked(gateway, _) = router {
        let released = release_all(gateway, &held).await;
        let mapped: Vec<Option<u16>> = held
            .iter()
            .map(|mapping| mapping.as_ref().map(|granted| granted.external_port))
            .collect();
        lines.push(map_summary(&mapped, &seen, released));
    }
    Ok(lines)
}

/// Pings every host from `socket` and collects the reported endpoints, in host order.
async fn ask(
    socket: &UdpSocket,
    hosts: &[SocketAddrV4],
    index: usize,
    wait: Duration,
) -> Vec<Option<SocketAddrV4>> {
    let id = random_id();
    for (host, address) in hosts.iter().enumerate() {
        // A failed send only leaves that host unanswered.
        let _ = socket
            .send_to(&ping_packet(&id, transaction(index, host)), address)
            .await;
    }
    let mut answers = vec![None; hosts.len()];
    let deadline = Instant::now() + wait;
    let mut buffer = [0_u8; MAX_PACKET];
    while answers.iter().any(Option::is_none) {
        let Ok(Ok((length, from))) = timeout_at(deadline, socket.recv_from(&mut buffer)).await
        else {
            break;
        };
        let SocketAddr::V4(from) = from else {
            continue;
        };
        if let Some(host) = hosts.iter().position(|address| *address == from)
            && let Some(seen) = external_endpoint(&buffer[..length], transaction(index, host))
        {
            answers[host] = Some(seen);
        }
    }
    answers
}

/// The endpoint a bootstrap host reports for `socket`: pings every host, up to `ROUNDS` times, and
/// returns the first valid report; `None` when no host answers.
pub(crate) async fn learn_external(
    socket: &UdpSocket,
    hosts: &[SocketAddrV4],
    wait: Duration,
) -> Option<SocketAddrV4> {
    let id = random_id();
    let mut buffer = [0_u8; MAX_PACKET];
    for _ in 0..ROUNDS {
        for (host, address) in hosts.iter().enumerate() {
            let _ = socket
                .send_to(&ping_packet(&id, transaction(0, host)), address)
                .await;
        }
        let deadline = Instant::now() + wait;
        while let Ok(Ok((length, from))) = timeout_at(deadline, socket.recv_from(&mut buffer)).await
        {
            let SocketAddr::V4(from) = from else {
                continue;
            };
            if let Some(host) = hosts.iter().position(|address| *address == from)
                && let Some(seen) = external_endpoint(&buffer[..length], transaction(0, host))
            {
                return Some(seen);
            }
        }
    }
    None
}

/// One socket and one host name a distinct two-byte transaction.
fn transaction(index: usize, host: usize) -> [u8; 2] {
    [
        u8::try_from(index).unwrap_or(u8::MAX),
        u8::try_from(host).unwrap_or(u8::MAX),
    ]
}

/// A random-looking node id from the keyed hasher of the standard library; it only has to differ.
fn random_id() -> [u8; 20] {
    let mut id = [0_u8; 20];
    for chunk in id.chunks_mut(8) {
        let word = RandomState::new().build_hasher().finish().to_be_bytes();
        chunk.copy_from_slice(&word[..chunk.len()]);
    }
    id
}

/// A Mainline `ping` query (BEP 5): `d1:ad2:id20:<id>e1:q4:ping1:t2:<tid>1:y1:qe`.
pub(crate) fn ping_packet(id: &[u8; 20], transaction: [u8; 2]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(56);
    packet.extend_from_slice(b"d1:ad2:id20:");
    packet.extend_from_slice(id);
    packet.extend_from_slice(b"e1:q4:ping1:t2:");
    packet.extend_from_slice(&transaction);
    packet.extend_from_slice(b"1:y1:qe");
    packet
}

/// The external endpoint a response reports for the sender (BEP 42 `ip`: four address bytes and a
/// big-endian port); `None` unless the packet is a response to this transaction.
pub(crate) fn external_endpoint(packet: &[u8], transaction: [u8; 2]) -> Option<SocketAddrV4> {
    // Only a whole, well-formed bencoded value is read: a cut or padded packet is refused.
    if skip(packet, 0, 0)? != packet.len() {
        return None;
    }
    if top_level_bytes(packet, b"y")? != b"r" || top_level_bytes(packet, b"t")? != transaction {
        return None;
    }
    let ip = top_level_bytes(packet, b"ip")?;
    let port = u16::from_be_bytes([*ip.get(4)?, *ip.get(5)?]);
    (ip.len() == 6 && port != 0)
        .then(|| SocketAddrV4::new(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]), port))
}

/// The byte-string value of `key` in the top-level dictionary of a bencoded packet.
pub(crate) fn top_level_bytes<'a>(packet: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    if packet.first() != Some(&b'd') {
        return None;
    }
    let mut at = 1;
    while *packet.get(at)? != b'e' {
        let (name, after) = byte_string(packet, at)?;
        if name == key {
            return byte_string(packet, after).map(|(value, _)| value);
        }
        at = skip(packet, after, 0)?;
    }
    None
}

/// A `<length>:<bytes>` string at `at`: the bytes and the position after them.
fn byte_string(buffer: &[u8], at: usize) -> Option<(&[u8], usize)> {
    let rest = buffer.get(at..)?;
    let colon = rest.iter().take(6).position(|byte| *byte == b':')?;
    let digits = &rest[..colon];
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let length: usize = std::str::from_utf8(digits).ok()?.parse().ok()?;
    let start = at + colon + 1;
    let end = start.checked_add(length)?;
    Some((buffer.get(start..end)?, end))
}

/// The position after the bencoded value at `at`.
fn skip(buffer: &[u8], at: usize, depth: u8) -> Option<usize> {
    if depth > MAX_DEPTH {
        return None;
    }
    match *buffer.get(at)? {
        b'i' => {
            let end = buffer.get(at..)?.iter().position(|byte| *byte == b'e')?;
            Some(at + end + 1)
        }
        b'l' => {
            let mut next = at + 1;
            while *buffer.get(next)? != b'e' {
                next = skip(buffer, next, depth + 1)?;
            }
            Some(next + 1)
        }
        b'd' => {
            let mut next = at + 1;
            while *buffer.get(next)? != b'e' {
                let (_, after) = byte_string(buffer, next)?;
                next = skip(buffer, after, depth + 1)?;
            }
            Some(next + 1)
        }
        b'0'..=b'9' => byte_string(buffer, at).map(|(_, end)| end),
        _ => None,
    }
}

/// The last line: how many pings were answered, whether the port is the same for every host, how
/// many sockets kept their local port and the steps between the ports of consecutive sockets.
pub(crate) fn summary(locals: &[u16], seen: &[Vec<Option<u16>>]) -> String {
    let answered: usize = seen.iter().flatten().flatten().count();
    let mut compared = false;
    let mut independent = true;
    for answers in seen {
        let ports: Vec<u16> = answers.iter().flatten().copied().collect();
        if ports.len() >= 2 {
            compared = true;
            independent &= ports.windows(2).all(|pair| pair[0] == pair[1]);
        }
    }
    let independent = match (compared, independent) {
        (false, _) => "unknown",
        (true, true) => "yes",
        (true, false) => "no",
    };
    let first: Vec<Option<u16>> = seen
        .iter()
        .map(|answers| answers.iter().flatten().next().copied())
        .collect();
    let preserved = first
        .iter()
        .zip(locals)
        .filter(|(port, local)| **port == Some(**local))
        .count();
    let steps: Vec<String> = first
        .windows(2)
        .map(|pair| match (pair[0], pair[1]) {
            (Some(before), Some(after)) => (i32::from(after) - i32::from(before)).to_string(),
            _ => "?".to_owned(),
        })
        .collect();
    format!(
        "nat-ports summary sockets={} answered={answered} endpoint_independent={independent} \
         preserved_ports={preserved} external_steps=[{}]",
        locals.len(),
        steps.join(",")
    )
}

/// The line after a mapped run: how many ports the router mapped, for how many sockets every
/// host that answered saw the mapped external port, and how many mappings were deleted again.
pub(crate) fn map_summary(
    mapped: &[Option<u16>],
    seen: &[Vec<Option<u16>>],
    released: usize,
) -> String {
    let granted = mapped.iter().flatten().count();
    let at_mapped = mapped
        .iter()
        .zip(seen)
        .filter(|(port, answers)| {
            let mut ports = answers.iter().flatten().peekable();
            port.is_some() && ports.peek().is_some() && ports.all(|value| Some(*value) == **port)
        })
        .count();
    format!(
        "nat-ports map-summary sockets={} mapped={granted} seen_at_mapped_port={at_mapped} \
         released={released}",
        mapped.len()
    )
}

#[cfg(test)]
#[path = "nat_ports_tests.rs"]
mod nat_ports_tests;
