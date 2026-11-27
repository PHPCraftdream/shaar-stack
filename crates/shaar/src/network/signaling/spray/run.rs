//! The two sides of the birthday trial. Both run over the small [`Datagrams`] interface, so the
//! contract cases drive them against a model NAT and the products drive them over real UDP
//! sockets. Every send is booked against the caps first; the trial ends at its deadline, on a
//! cancellation, or at the first hit.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep_until, timeout_at};

use super::negotiate::Agreement;
use super::{
    Counters, DATAGRAM_LEN, MAX_PROBES, MAX_SOCKETS, Mark, Report, Rng, Role, TRIAL_WINDOW, Token,
    datagram, random_ports, read_datagram,
};
use crate::network::signaling::punch::peer_claimed_probe_allowed;

/// Receive buffer of one socket; the datagrams of the trial are 21 bytes.
const RECV_BUFFER: usize = 128;
/// Copies of an acknowledgement sent back.
const ACKS: usize = 2;
/// Sockets the hard side opens per tick: 500 a second.
pub(crate) const HARD_PER_TICK: usize = 50;
/// Probes the easy side writes per tick: 100 a second, under the rate at which the phone's
/// carrier started to lose the datagrams of a sweep (leaf NAT-9).
pub(crate) const EASY_PER_TICK: usize = 10;
/// Length of one tick.
pub(crate) const TICK: Duration = Duration::from_millis(100);

/// What the trial needs from a UDP socket. `recv_from` must be cancel-safe.
pub(crate) trait Datagrams: Send {
    fn send_to(
        &mut self,
        bytes: &[u8],
        to: SocketAddrV4,
    ) -> impl Future<Output = io::Result<()>> + Send;

    fn recv_from(
        &mut self,
        buffer: &mut [u8],
    ) -> impl Future<Output = io::Result<(usize, SocketAddrV4)>> + Send;
}

impl Datagrams for tokio::net::UdpSocket {
    async fn send_to(&mut self, bytes: &[u8], to: SocketAddrV4) -> io::Result<()> {
        tokio::net::UdpSocket::send_to(self, bytes, to)
            .await
            .map(|_| ())
    }

    async fn recv_from(&mut self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddrV4)> {
        loop {
            let (length, from) = tokio::net::UdpSocket::recv_from(self, buffer).await?;
            if let SocketAddr::V4(from) = from {
                return Ok((length, from));
            }
        }
    }
}

/// Opens the sockets of the hard side.
pub(crate) trait Opener: Send {
    type Port: Datagrams + 'static;

    fn open(&mut self) -> impl Future<Output = io::Result<Self::Port>> + Send;
}

/// Fresh UDP sockets on ephemeral ports of the unspecified address.
pub(crate) struct UdpOpener;

impl Opener for UdpOpener {
    type Port = tokio::net::UdpSocket;

    async fn open(&mut self) -> io::Result<Self::Port> {
        tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await
    }
}

/// How fast a side sends: `per_tick` sockets or probes every `tick`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Schedule {
    pub per_tick: usize,
    pub tick: Duration,
}

/// The hard side's plan, clamped to the caps.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HardPlan {
    pub sockets: usize,
    pub schedule: Schedule,
}

impl HardPlan {
    pub(crate) fn new(sockets: usize) -> Self {
        Self {
            sockets: sockets.min(MAX_SOCKETS),
            schedule: Schedule {
                per_tick: HARD_PER_TICK,
                tick: TICK,
            },
        }
    }
}

/// The easy side's plan, clamped to the caps.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EasyPlan {
    pub probes: usize,
    pub schedule: Schedule,
}

impl EasyPlan {
    pub(crate) fn new(probes: usize) -> Self {
        Self {
            probes: probes.min(MAX_PROBES),
            schedule: Schedule {
                per_tick: EASY_PER_TICK,
                tick: TICK,
            },
        }
    }
}

/// What a trial shares: the agreed token, the counters, the deadline and the cancellation (the
/// sender going away counts as a cancellation).
#[derive(Clone)]
pub(crate) struct Trial {
    pub token: Token,
    pub counters: Arc<Counters>,
    pub deadline: Instant,
    pub cancel: watch::Receiver<bool>,
}

async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow() {
            return;
        }
        if cancel.changed().await.is_err() {
            return;
        }
    }
}

/// A socket of the hard side on which the easy side was heard, and the endpoint it was heard from.
pub(crate) struct Hit<P> {
    pub port: P,
    pub peer: SocketAddrV4,
}

/// Answers a probe with acknowledgements; an acknowledgement needs none.
async fn acknowledge<P: Datagrams>(
    port: &mut P,
    to: SocketAddrV4,
    token: &Token,
    counters: &Counters,
) {
    let ack = datagram(token, Mark::Ack);
    for _ in 0..ACKS {
        if counters.reserve_send(ack.len(), false) {
            let _ = port.send_to(&ack, to).await;
        }
    }
}

/// One socket of the hard side: writes one probe to the easy endpoint, then listens until the
/// deadline for the token from that endpoint.
async fn drive<P: Datagrams>(
    mut port: P,
    easy: SocketAddrV4,
    token: Token,
    counters: Arc<Counters>,
    deadline: Instant,
) -> Option<Hit<P>> {
    let probe = datagram(&token, Mark::Probe);
    if counters.reserve_send(probe.len(), true) {
        let _ = port.send_to(&probe, easy).await;
    }
    let mut buffer = [0_u8; RECV_BUFFER];
    loop {
        match timeout_at(deadline, port.recv_from(&mut buffer)).await {
            Ok(Ok((length, from))) => {
                counters.note_recv(length);
                if from != easy {
                    continue;
                }
                match read_datagram(&buffer[..length], &token) {
                    Some(Mark::Probe) => {
                        acknowledge(&mut port, from, &token, &counters).await;
                        return Some(Hit { port, peer: from });
                    }
                    Some(Mark::Ack) => return Some(Hit { port, peer: from }),
                    None => {}
                }
            }
            Ok(Err(error)) if error.kind() == io::ErrorKind::ConnectionReset => {}
            Ok(Err(_)) | Err(_) => return None,
        }
    }
}

/// The hard side: opens up to `plan.sockets` sockets, paced by the schedule, each writing once to
/// `easy`, and returns the first socket on which the token arrived from `easy`. A socket that
/// cannot be opened ends the opening (the sockets already open keep listening). `None` when the
/// endpoint is one the probe policy denies, at the deadline, or on a cancellation.
pub(crate) async fn run_hard<O: Opener>(
    opener: &mut O,
    easy: SocketAddrV4,
    plan: HardPlan,
    mut trial: Trial,
) -> Option<Hit<O::Port>> {
    if !peer_claimed_probe_allowed(SocketAddr::V4(easy)) {
        return None;
    }
    let mut wanted = plan.sockets.min(MAX_SOCKETS);
    let mut opened = 0_usize;
    let mut tasks = JoinSet::new();
    loop {
        if *trial.cancel.borrow() || Instant::now() >= trial.deadline {
            return None;
        }
        let batch = wanted.saturating_sub(opened).min(plan.schedule.per_tick);
        for _ in 0..batch {
            match opener.open().await {
                Ok(port) => {
                    trial.counters.note_socket();
                    opened += 1;
                    tasks.spawn(drive(
                        port,
                        easy,
                        trial.token,
                        Arc::clone(&trial.counters),
                        trial.deadline,
                    ));
                }
                Err(_) => {
                    wanted = opened;
                    break;
                }
            }
        }
        let wake = if opened < wanted {
            (Instant::now() + plan.schedule.tick).min(trial.deadline)
        } else {
            trial.deadline
        };
        tokio::select! {
            biased;
            _ = cancelled(&mut trial.cancel) => return None,
            finished = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Ok(Some(hit))) = finished {
                    return Some(hit);
                }
            }
            _ = sleep_until(wake) => {}
        }
        if opened >= wanted && tasks.is_empty() {
            return None;
        }
    }
}

/// The easy side: writes one probe to each of `plan.probes` random ports of `hard_ip`, paced by
/// the schedule, from its own socket, and listens until the deadline for the token from that
/// address. Returns the endpoint it was heard from. `None` when the address is one the probe
/// policy denies, at the deadline, or on a cancellation.
pub(crate) async fn run_easy<P: Datagrams>(
    port: &mut P,
    hard_ip: Ipv4Addr,
    plan: EasyPlan,
    rng: &mut Rng,
    mut trial: Trial,
) -> Option<SocketAddrV4> {
    if !peer_claimed_probe_allowed(SocketAddr::new(IpAddr::V4(hard_ip), 1)) {
        return None;
    }
    let ports = random_ports(rng, plan.probes);
    let probe = datagram(&trial.token, Mark::Probe);
    let mut next = 0_usize;
    let mut buffer = [0_u8; RECV_BUFFER];
    loop {
        if *trial.cancel.borrow() || Instant::now() >= trial.deadline {
            return None;
        }
        let end = ports.len().min(next.saturating_add(plan.schedule.per_tick));
        while next < end {
            if !trial.counters.reserve_send(probe.len(), true) {
                next = ports.len();
                break;
            }
            let _ = port
                .send_to(&probe, SocketAddrV4::new(hard_ip, ports[next]))
                .await;
            next += 1;
        }
        let wake = if next < ports.len() {
            (Instant::now() + plan.schedule.tick).min(trial.deadline)
        } else {
            trial.deadline
        };
        loop {
            tokio::select! {
                biased;
                _ = cancelled(&mut trial.cancel) => return None,
                received = port.recv_from(&mut buffer) => match received {
                    Ok((length, from)) => {
                        trial.counters.note_recv(length);
                        if *from.ip() != hard_ip {
                            continue;
                        }
                        if let Some(mark) = read_datagram(&buffer[..length], &trial.token) {
                            if mark == Mark::Probe {
                                acknowledge(port, from, &trial.token, &trial.counters).await;
                            }
                            return Some(from);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
                    Err(_) => return None,
                },
                _ = sleep_until(wake) => break,
            }
        }
    }
}

/// What one side found when its trial ended, with what it used.
pub(crate) struct Finished<T> {
    /// The hit: the socket and the peer endpoint (hard side) or the endpoint heard (easy side).
    pub found: Option<T>,
    pub report: Report,
    pub elapsed: Duration,
}

impl<T> Finished<T> {
    /// A trial that did not run: nothing found, nothing used.
    fn idle() -> Self {
        Self {
            found: None,
            report: Counters::new().report(),
            elapsed: Duration::ZERO,
        }
    }

    /// The operator line of this device and trial: counts only, no address and no token.
    pub(crate) fn line(&self, role: Role) -> String {
        self.report.line(role, self.found.is_some(), self.elapsed)
    }
}

/// The trial of an agreement: its token, fresh counters and the window from now.
fn agreed_trial(
    agreement: &Agreement,
    cancel: watch::Receiver<bool>,
) -> (Trial, Arc<Counters>, Instant) {
    let started = Instant::now();
    let counters = Arc::new(Counters::new());
    let trial = Trial {
        token: agreement.token,
        counters: Arc::clone(&counters),
        deadline: started + TRIAL_WINDOW,
        cancel,
    };
    (trial, counters, started)
}

/// Runs the hard side of an agreement to its end: the sockets the agreement plans, each writing
/// once to the easy endpoint it names. An agreement of the other role runs nothing.
pub(crate) async fn run_hard_agreed<O: Opener>(
    opener: &mut O,
    agreement: &Agreement,
    cancel: watch::Receiver<bool>,
) -> Finished<Hit<O::Port>> {
    if agreement.role != Role::Hard {
        return Finished::idle();
    }
    let (trial, counters, started) = agreed_trial(agreement, cancel);
    let plan = HardPlan::new(usize::from(agreement.planned));
    let found = run_hard(opener, agreement.peer, plan, trial).await;
    Finished {
        found,
        report: counters.report(),
        elapsed: started.elapsed(),
    }
}

/// Runs the easy side of an agreement to its end: the probes the agreement plans, from `port`
/// (the socket whose endpoint the agreement named) to random ports of the hard side's address.
/// An agreement of the other role runs nothing.
pub(crate) async fn run_easy_agreed<P: Datagrams>(
    port: &mut P,
    agreement: &Agreement,
    rng: &mut Rng,
    cancel: watch::Receiver<bool>,
) -> Finished<SocketAddrV4> {
    if agreement.role != Role::Easy {
        return Finished::idle();
    }
    let (trial, counters, started) = agreed_trial(agreement, cancel);
    let plan = EasyPlan::new(usize::from(agreement.planned));
    let found = run_easy(port, *agreement.peer.ip(), plan, rng, trial).await;
    Finished {
        found,
        report: counters.report(),
        elapsed: started.elapsed(),
    }
}

const _: () = assert!(DATAGRAM_LEN <= RECV_BUFFER);
