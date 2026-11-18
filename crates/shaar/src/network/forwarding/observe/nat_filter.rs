//! Operator measurement of the filtering of the NAT in front of this machine (leaf NAT-3b). One
//! device listens on a fresh UDP socket whose external endpoint a bootstrap host reports, and after
//! a delay sends a few datagrams to the address of the other device; the other device probes the
//! listener's external endpoint from fresh sockets before and after that delay. Which probes
//! arrive names the filtering: from any address, from an address the listener has sent to, or
//! only from an address and port it has sent to. The traffic is a few dozen bytes per datagram.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::{Instant, sleep, timeout_at};

use super::nat_ports::{bootstrap_hosts, learn_external};
use crate::config::MainlineNetwork;

/// Start of every probe and knock datagram.
const TAG: &[u8] = b"shaar-nat-filter/1 ";
/// Label of the probes sent before the knock.
const PHASE_A: u8 = b'A';
/// Label of the probes sent after the knock.
const PHASE_B: u8 = b'B';
/// Label of the knocks the listener sends.
const KNOCK: u8 = b'K';
/// Port a knock is addressed to when the operator names none (the discard port: it opens the
/// listener's filter for the other device's address and needs no service there).
pub const KNOCK_PORT: u16 = 9;
/// Probes per phase, each from its own fresh socket.
pub const PROBES_PER_PHASE: u8 = 3;
/// Longest listening window, in seconds (a run adds a few seconds to learn the external endpoint,
/// and a live process is stopped at 120 s).
pub const MAX_LISTEN_SECONDS: u16 = 110;
/// Listening window when the operator names none, in seconds.
pub const DEFAULT_LISTEN_SECONDS: u16 = 90;
/// Delay before the first knock when the operator names none, in seconds.
pub const DEFAULT_KNOCK_AFTER_SECONDS: u16 = 30;
/// Longest pause between the two probe phases, in seconds.
pub const MAX_PROBE_WAIT_SECONDS: u16 = 100;
/// Pause between the two probe phases when the operator names none, in seconds.
pub const DEFAULT_PROBE_WAIT_SECONDS: u16 = 40;
/// Pause between two knocks.
pub const KNOCK_EVERY: Duration = Duration::from_secs(2);
const MAX_PACKET: usize = 1500;

/// Where and when the listener knocks.
#[derive(Clone, Copy, Debug)]
pub struct Knock {
    pub target: SocketAddrV4,
    /// Delay from the start of the window to the first knock.
    pub after: Duration,
    /// Pause between knocks.
    pub every: Duration,
}

/// What the listener does.
#[derive(Clone, Copy, Debug)]
pub struct Listen {
    /// How long it waits for a bootstrap host to report its external endpoint, per ping round.
    pub answer_wait: Duration,
    /// How long it listens after it learned its external endpoint.
    pub window: Duration,
    pub knock: Option<Knock>,
    /// Whether the external address is printed next to the external port.
    pub show_address: bool,
}

/// How many datagrams the listener took, by label.
#[derive(Default)]
struct Counts {
    a: u32,
    b: u32,
    other: u32,
    knocks: u32,
}

impl Counts {
    fn received(&self) -> u32 {
        self.a + self.b + self.other
    }

    fn record(&mut self, label: u8) {
        match label {
            PHASE_A => self.a += 1,
            PHASE_B => self.b += 1,
            _ => self.other += 1,
        }
    }
}

/// One probe or knock: the tag, a label letter and a sequence number.
pub(crate) fn datagram(label: u8, seq: u8) -> Vec<u8> {
    let mut packet = TAG.to_vec();
    packet.push(label);
    packet.push(b' ');
    packet.extend_from_slice(seq.to_string().as_bytes());
    packet
}

/// The label and the sequence number of a probe or knock; `None` for any other datagram.
pub(crate) fn parse(packet: &[u8]) -> Option<(u8, u8)> {
    let rest = packet.strip_prefix(TAG)?;
    let (&label, rest) = rest.split_first()?;
    let digits = rest.strip_prefix(b" ")?;
    if !label.is_ascii_uppercase()
        || digits.is_empty()
        || digits.len() > 3
        || !digits.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    let seq = std::str::from_utf8(digits).ok()?.parse().ok()?;
    Some((label, seq))
}

/// Listens against the bootstrap hosts of `network` (see [`listen_on`]).
pub async fn listen(
    network: &MainlineNetwork,
    options: &Listen,
    emit: &mut (dyn FnMut(String) + Send),
) -> Result<(), String> {
    listen_on(&bootstrap_hosts(network).await, options, emit).await
}

/// Listens on a fresh socket, prints its external endpoint through `emit` as soon as one of
/// `hosts` has reported it, then prints one line per probe taken and a summary at the end of the
/// window. With a knock configured it sends datagrams to the knock target from the same socket.
pub(crate) async fn listen_on(
    hosts: &[SocketAddrV4],
    options: &Listen,
    emit: &mut (dyn FnMut(String) + Send),
) -> Result<(), String> {
    if hosts.is_empty() {
        return Err(
            "no DHT bootstrap hosts are available (see `config network public`)".to_owned(),
        );
    }
    if options.window.is_zero() {
        return Err("the listening window must not be empty".to_owned());
    }
    if let Some(knock) = &options.knock
        && (knock.every.is_zero() || knock.after >= options.window)
    {
        return Err("knocks need a pause and a first knock inside the listening window".to_owned());
    }
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|error| format!("could not open a UDP socket: {error}"))?;
    let local = socket
        .local_addr()
        .map_err(|error| format!("could not read a socket port: {error}"))?
        .port();
    let external = learn_external(&socket, hosts, options.answer_wait)
        .await
        .ok_or_else(|| "no bootstrap host answered, so the external port is unknown".to_owned())?;
    let address = if options.show_address {
        format!(" external_ip={}", external.ip())
    } else {
        String::new()
    };
    emit(format!(
        "nat-filter listen local_port={local} external_port={}{address}",
        external.port()
    ));

    let started = Instant::now();
    let deadline = started + options.window;
    let mut next_knock = options.knock.map(|knock| started + knock.after);
    let mut counts = Counts::default();
    let mut buffer = [0_u8; MAX_PACKET];
    loop {
        let wake = next_knock.map_or(deadline, |at| at.min(deadline));
        match timeout_at(wake, socket.recv_from(&mut buffer)).await {
            Ok(Ok((length, from))) => {
                if let Some((label, seq)) = parse(&buffer[..length]) {
                    counts.record(label);
                    emit(format!(
                        "nat-filter recv label={} seq={seq} from_port={} at_ms={}",
                        char::from(label),
                        from.port(),
                        started.elapsed().as_millis()
                    ));
                }
            }
            // An unreachable knock target can surface as a reset on the next receive.
            Ok(Err(error)) if error.kind() == ErrorKind::ConnectionReset => {}
            Ok(Err(error)) => return Err(format!("could not receive: {error}")),
            Err(_) => {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                if let (Some(at), Some(knock)) = (next_knock, options.knock) {
                    let seq = u8::try_from(counts.knocks + 1).unwrap_or(u8::MAX);
                    if socket
                        .send_to(&datagram(KNOCK, seq), knock.target)
                        .await
                        .is_ok()
                    {
                        counts.knocks += 1;
                    }
                    let next = at + knock.every;
                    next_knock = (next < deadline).then_some(next);
                }
            }
        }
    }
    emit(format!(
        "nat-filter listen summary received={} a={} b={} other={} knocks_sent={}",
        counts.received(),
        counts.a,
        counts.b,
        counts.other,
        counts.knocks
    ));
    Ok(())
}

/// Sends the probes of phase A, waits `wait`, then the probes of phase B, each probe from its own
/// fresh socket (a fresh external port behind a NAT); the sockets stay open until the end.
pub async fn probe(
    target: SocketAddrV4,
    wait: Duration,
    emit: &mut (dyn FnMut(String) + Send),
) -> Result<(), String> {
    let ip = target.ip();
    if target.port() == 0 || ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
        return Err("the target must be a unicast IPv4 address and a port".to_owned());
    }
    let mut held = Vec::with_capacity(2 * usize::from(PROBES_PER_PHASE));
    send_phase(PHASE_A, target, &mut held).await?;
    emit(format!("nat-filter probe phase=A sent={PROBES_PER_PHASE}"));
    sleep(wait).await;
    send_phase(PHASE_B, target, &mut held).await?;
    emit(format!("nat-filter probe phase=B sent={PROBES_PER_PHASE}"));
    Ok(())
}

async fn send_phase(
    label: u8,
    target: SocketAddrV4,
    held: &mut Vec<UdpSocket>,
) -> Result<(), String> {
    for seq in 1..=PROBES_PER_PHASE {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .map_err(|error| format!("could not open a UDP socket: {error}"))?;
        socket
            .send_to(&datagram(label, seq), target)
            .await
            .map_err(|error| format!("could not send a probe: {error}"))?;
        held.push(socket);
    }
    Ok(())
}

#[cfg(test)]
#[path = "nat_filter_tests.rs"]
mod nat_filter_tests;
