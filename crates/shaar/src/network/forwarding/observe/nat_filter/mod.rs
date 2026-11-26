//! Operator measurements of the NAT in front of this machine. Leaf NAT-3b: one device listens on a
//! fresh UDP socket whose external endpoint a bootstrap host reports, and after a delay sends a few
//! datagrams to the address of the other device; the other device probes the listener's external
//! endpoint from fresh sockets before and after that delay. Which probes arrive names the
//! filtering: from any address, from an address the listener has sent to, or only from an address
//! and port it has sent to. Leaf NAT-3c: the listener sweeps one datagram to every port of the other
//! device's address while a catcher on that device keeps one socket talking to the listener's
//! endpoint, so that the sweep can hit the port the catcher's NAT picked and open the way back.
//! The traffic is a few dozen bytes per datagram; a full sweep is about 3.3 MiB.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::{Instant, sleep, timeout_at};

use super::nat_ports::{bootstrap_hosts, learn_external};
use crate::config::MainlineNetwork;

/// Start of every probe, knock and sweep datagram.
const TAG: &[u8] = b"shaar-nat-filter/1 ";
/// Label of the probes sent before the knock (and by the catcher before it caught a sweep datagram).
const PHASE_A: u8 = b'A';
/// Label of the probes sent after the knock.
const PHASE_B: u8 = b'B';
/// Label of the probes the catcher sends after it caught a sweep datagram.
const PHASE_C: u8 = b'C';
/// Label of the knocks the listener sends.
const KNOCK: u8 = b'K';
/// Label of the sweep datagrams; the sequence number is the destination port.
const SWEEP: u8 = b'S';
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
/// Highest sweep rate, in datagrams per second.
pub const MAX_SWEEP_RATE: u16 = 5000;
/// Sweep rate when the operator names none, in datagrams per second.
pub const DEFAULT_SWEEP_RATE: u16 = 1500;
/// First port of a sweep when the operator names none (the ports below are system ports).
pub const DEFAULT_SWEEP_FROM: u16 = 1024;
/// Last port of a sweep when the operator names none.
pub const DEFAULT_SWEEP_TO: u16 = u16::MAX;
/// Delay before the sweep when the operator names none, in seconds.
pub const DEFAULT_SWEEP_AFTER_SECONDS: u16 = 8;
/// Longest catching window, in seconds.
pub const MAX_CATCH_SECONDS: u16 = 110;
/// Catching window when the operator names none, in seconds.
pub const DEFAULT_CATCH_SECONDS: u16 = 75;
/// Pause between two probes of the catcher.
pub const CATCH_EVERY: Duration = Duration::from_secs(1);
/// How often the sweep checks how many datagrams are due.
const SWEEP_TICK: Duration = Duration::from_millis(10);
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

/// A sweep of one datagram to every port of the other device's address, from the listening socket.
#[derive(Clone, Copy, Debug)]
pub struct Sweep {
    pub ip: Ipv4Addr,
    /// First and last port, both included.
    pub from: u16,
    pub to: u16,
    /// Delay from the start of the window to the first datagram.
    pub after: Duration,
    /// Datagrams per second.
    pub rate: u16,
}

impl Sweep {
    fn ports(&self) -> u32 {
        u32::from(self.to) - u32::from(self.from) + 1
    }

    /// Refuses a sweep that cannot work: a bad range or rate, or one that would not finish inside
    /// the listening window.
    pub fn check(&self, window: Duration) -> Result<(), String> {
        if self.ip.is_unspecified() || self.ip.is_multicast() || self.ip.is_broadcast() {
            return Err("the sweep needs a unicast IPv4 address".to_owned());
        }
        if self.from == 0 || self.from > self.to {
            return Err(
                "the sweep needs a first port from 1 up that is not above the last".to_owned(),
            );
        }
        if self.rate == 0 || self.rate > MAX_SWEEP_RATE {
            return Err(format!(
                "the sweep rate must be 1 to {MAX_SWEEP_RATE} datagrams per second"
            ));
        }
        let length = Duration::from_millis(u64::from(self.ports()) * 1000 / u64::from(self.rate));
        if self.after.saturating_add(length) >= window {
            return Err("the sweep must finish inside the listening window".to_owned());
        }
        Ok(())
    }
}

/// What the listener does.
#[derive(Clone, Copy, Debug)]
pub struct Listen {
    /// How long it waits for a bootstrap host to report its external endpoint, per ping round.
    pub answer_wait: Duration,
    /// How long it listens after it learned its external endpoint.
    pub window: Duration,
    pub knock: Option<Knock>,
    pub sweep: Option<Sweep>,
    /// Whether the external address is printed next to the external port.
    pub show_address: bool,
}

/// What the catcher does.
#[derive(Clone, Copy, Debug)]
pub struct Catch {
    /// The listener's external endpoint.
    pub target: SocketAddrV4,
    pub window: Duration,
    /// Pause between probes.
    pub every: Duration,
}

/// How many datagrams the listener took, by label.
#[derive(Default)]
struct Counts {
    a: u32,
    b: u32,
    c: u32,
    other: u32,
    knocks: u32,
    swept: u32,
}

impl Counts {
    fn received(&self) -> u32 {
        self.a + self.b + self.c + self.other
    }

    fn record(&mut self, label: u8) {
        match label {
            PHASE_A => self.a += 1,
            PHASE_B => self.b += 1,
            PHASE_C => self.c += 1,
            _ => self.other += 1,
        }
    }
}

/// The progress of a sweep.
struct Progress {
    sweep: Sweep,
    begun: Option<Instant>,
    sent: u32,
    errors: u32,
}

impl Progress {
    fn new(sweep: Sweep) -> Self {
        Self {
            sweep,
            begun: None,
            sent: 0,
            errors: 0,
        }
    }

    /// Sends the datagrams that are due at `now`, at most 100 ms worth at a time (a stalled task
    /// never turns into one large burst). Returns whether the sweep is complete.
    async fn step(
        &mut self,
        socket: &UdpSocket,
        now: Instant,
        emit: &mut (dyn FnMut(String) + Send),
    ) -> bool {
        let begun = *self.begun.get_or_insert(now);
        let total = self.sweep.ports();
        let elapsed_ms = now.duration_since(begun).as_millis();
        let due = (elapsed_ms * u128::from(self.sweep.rate) / 1000 + 1).min(u128::from(total));
        let due = u32::try_from(due).unwrap_or(total);
        let burst = u32::from(self.sweep.rate / 10).max(1);
        let stop = due.min(self.sent + self.errors + burst);
        while self.sent + self.errors < stop {
            let offset = u16::try_from(self.sent + self.errors).unwrap_or(u16::MAX);
            let port = self.sweep.from.saturating_add(offset);
            let target = SocketAddrV4::new(self.sweep.ip, port);
            match socket.send_to(&datagram(SWEEP, port), target).await {
                Ok(_) => self.sent += 1,
                Err(_) => self.errors += 1,
            }
        }
        let complete = self.sent + self.errors >= total;
        if complete {
            emit(format!(
                "nat-filter listen swept from={} to={} sent={} errors={} elapsed_ms={}",
                self.sweep.from,
                self.sweep.to,
                self.sent,
                self.errors,
                begun.elapsed().as_millis()
            ));
        }
        complete
    }
}

/// One probe, knock or sweep datagram: the tag, a label letter and a sequence number.
pub(crate) fn datagram(label: u8, seq: u16) -> Vec<u8> {
    let mut packet = TAG.to_vec();
    packet.push(label);
    packet.push(b' ');
    packet.extend_from_slice(seq.to_string().as_bytes());
    packet
}

/// The label and the sequence number of a probe, knock or sweep datagram; `None` for any other
/// datagram.
pub(crate) fn parse(packet: &[u8]) -> Option<(u8, u16)> {
    let rest = packet.strip_prefix(TAG)?;
    let (&label, rest) = rest.split_first()?;
    let digits = rest.strip_prefix(b" ")?;
    if !label.is_ascii_uppercase()
        || digits.is_empty()
        || digits.len() > 5
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
/// window. With a knock or a sweep configured it sends from the same socket.
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
    if let Some(sweep) = &options.sweep {
        sweep.check(options.window)?;
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
    let mut progress = options.sweep.map(Progress::new);
    let mut next_sweep = options.sweep.map(|sweep| started + sweep.after);
    let mut counts = Counts::default();
    let mut buffer = [0_u8; MAX_PACKET];
    loop {
        let wake = [Some(deadline), next_knock, next_sweep]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(deadline);
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
            // An unreachable target can surface as a reset on the next receive.
            Ok(Err(error)) if error.kind() == ErrorKind::ConnectionReset => {}
            Ok(Err(error)) => return Err(format!("could not receive: {error}")),
            Err(_) => {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                if let (Some(at), Some(knock)) = (next_knock, options.knock)
                    && now >= at
                {
                    let seq = u16::try_from(counts.knocks + 1).unwrap_or(u16::MAX);
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
                if let (Some(at), Some(progress)) = (next_sweep, progress.as_mut())
                    && now >= at
                {
                    next_sweep = if progress.step(&socket, now, emit).await {
                        None
                    } else {
                        Some(now + SWEEP_TICK)
                    };
                }
            }
        }
    }
    counts.swept = progress.map_or(0, |progress| progress.sent);
    emit(format!(
        "nat-filter listen summary received={} a={} b={} c={} other={} knocks_sent={} sweep_sent={}",
        counts.received(),
        counts.a,
        counts.b,
        counts.c,
        counts.other,
        counts.knocks,
        counts.swept
    ));
    Ok(())
}

/// Refuses a target that cannot be probed.
fn check_target(target: SocketAddrV4) -> Result<(), String> {
    let ip = target.ip();
    if target.port() == 0 || ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
        return Err("the target must be a unicast IPv4 address and a port".to_owned());
    }
    Ok(())
}

/// Sends the probes of phase A, waits `wait`, then the probes of phase B, each probe from its own
/// fresh socket (a fresh external port behind a NAT); the sockets stay open until the end.
pub async fn probe(
    target: SocketAddrV4,
    wait: Duration,
    emit: &mut (dyn FnMut(String) + Send),
) -> Result<(), String> {
    check_target(target)?;
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
            .send_to(&datagram(label, u16::from(seq)), target)
            .await
            .map_err(|error| format!("could not send a probe: {error}"))?;
        held.push(socket);
    }
    Ok(())
}

/// Talks to the listener from one socket: a probe `A` every `every` (this makes the NAT of this
/// machine map the socket toward the listener and keeps the mapping alive) while it listens on the
/// same socket. The first sweep datagram that arrives names the external port this NAT uses
/// toward the listener; from then on the probes are labelled `C`.
pub async fn catch(options: &Catch, emit: &mut (dyn FnMut(String) + Send)) -> Result<(), String> {
    check_target(options.target)?;
    if options.window.is_zero() || options.every.is_zero() {
        return Err(
            "the catching window and the pause between probes must not be empty".to_owned(),
        );
    }
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|error| format!("could not open a UDP socket: {error}"))?;
    let started = Instant::now();
    let deadline = started + options.window;
    let mut next_probe = started;
    let mut caught: Option<u16> = None;
    let (mut a_sent, mut c_sent, mut seen) = (0_u16, 0_u16, 0_u32);
    let mut buffer = [0_u8; MAX_PACKET];
    loop {
        match timeout_at(next_probe.min(deadline), socket.recv_from(&mut buffer)).await {
            Ok(Ok((length, from))) => {
                if let Some((SWEEP, port)) = parse(&buffer[..length]) {
                    seen += 1;
                    if caught.is_none() {
                        caught = Some(port);
                        emit(format!(
                            "nat-filter catch caught external_port={port} from_port={} from_target={} at_ms={}",
                            from.port(),
                            from == SocketAddr::V4(options.target),
                            started.elapsed().as_millis()
                        ));
                    }
                }
            }
            // An unreachable target can surface as a reset on the next receive.
            Ok(Err(error)) if error.kind() == ErrorKind::ConnectionReset => {}
            Ok(Err(error)) => return Err(format!("could not receive: {error}")),
            Err(_) => {
                if Instant::now() >= deadline {
                    break;
                }
                let (label, sent) = if caught.is_some() {
                    (PHASE_C, &mut c_sent)
                } else {
                    (PHASE_A, &mut a_sent)
                };
                *sent = sent.saturating_add(1);
                // A probe that cannot be sent is not a failure of the measurement.
                let _ = socket
                    .send_to(&datagram(label, *sent), options.target)
                    .await;
                next_probe += options.every;
            }
        }
    }
    let port = caught.map_or_else(|| "none".to_owned(), |port| port.to_string());
    emit(format!(
        "nat-filter catch summary caught={} external_port={port} sweep_seen={seen} a_sent={a_sent} c_sent={c_sent}",
        caught.is_some()
    ));
    Ok(())
}

#[cfg(test)]
mod tests;
