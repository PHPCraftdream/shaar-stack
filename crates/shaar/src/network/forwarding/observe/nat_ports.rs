//! Operator measurement of the NAT in front of this machine (leaf NAT-3a): the external UDP port
//! that a few fresh sockets get when they talk to the Mainline bootstrap hosts, the pattern of
//! those ports and whether they depend on the destination. Ports and counts only unless the
//! operator asks for the external address (`show_address`): no key is read, and the traffic is one
//! ping per socket and host.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout, timeout_at};

use crate::config::MainlineNetwork;

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
/// to print.
pub async fn nat_ports(
    network: &MainlineNetwork,
    sockets: u8,
    show_address: bool,
) -> Result<Vec<String>, String> {
    let hosts = bootstrap_hosts(network).await;
    measure(&hosts, sockets, ANSWER_WAIT, show_address).await
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
    if hosts.is_empty() {
        return Err(
            "no DHT bootstrap hosts are available (see `config network public`)".to_owned(),
        );
    }
    if sockets == 0 || sockets > MAX_SOCKETS {
        return Err(format!("sockets must be 1 to {MAX_SOCKETS}"));
    }
    let mut bound = Vec::with_capacity(usize::from(sockets));
    for _ in 0..sockets {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .map_err(|error| format!("could not open a UDP socket: {error}"))?;
        bound.push(socket);
    }
    let mut locals = Vec::with_capacity(bound.len());
    let mut seen = Vec::with_capacity(bound.len());
    let mut lines = Vec::new();
    for (index, socket) in bound.iter().enumerate() {
        let local = socket
            .local_addr()
            .map_err(|error| format!("could not read a socket port: {error}"))?
            .port();
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

#[cfg(test)]
#[path = "nat_ports_tests.rs"]
mod nat_ports_tests;
