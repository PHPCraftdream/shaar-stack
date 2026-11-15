//! NAT hole punching coordinated over the authenticated Yggdrasil bridge.
//!
//! Punch coordination datagrams ride the bridge control capability, which is
//! authenticated and allowlisted per 32-byte peer key. Peer-claimed endpoints
//! are probe targets only for such allowlisted peers; datagrams never carry
//! application payload. Candidate validity mirrors the dial policy
//! (`crate::network::admission::policy::dial_address`), including denial of
//! the synthetic fabric prefix `fd15:070a:510b::/48`; the mirror exists
//! because `policy` is private to the admission module. The codec ACCEPTS
//! loopback candidates for dial parity with the dialer (a Client legitimately
//! dials loopback record hints), but peer-claimed addresses are additionally
//! gated at the probe decision: a server never fires QUIC probes at a
//! candidate an authenticated peer merely CLAIMED when that candidate is its
//! own loopback, link-local or otherwise special target (leaf
//! L4 review Finding 2 — see `peer_claimed_probe_allowed`).

use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    time::Duration,
};

use iroh_base::PublicKey;
use tokio::time::{Instant, timeout_at};

use crate::network::{NetworkError, Session};
use shaar_ygg::DatagramError;

/// Maximum candidates carried per punch message and probe burst.
pub(crate) const MAX_CANDIDATES: usize = 4;
/// Hard wire-size cap for one encoded punch datagram.
pub(crate) const MAX_MESSAGE_BYTES: usize = 96;
/// Budget for opening the bridge control datagram pair.
pub(crate) const OPEN_BUDGET: Duration = Duration::from_secs(1);
/// Budget for one offer/answer exchange.
pub(crate) const EXCHANGE_BUDGET: Duration = Duration::from_millis(1500);
/// Interval between copies of the same Offer inside one exchange window: the
/// first datagram to a cold Yggdrasil path (or to a peer that has not yet
/// registered its control capability) can be lost.
pub(crate) const OFFER_RESEND: Duration = Duration::from_millis(500);
/// Window bounding the whole probe burst.
pub(crate) const PROBE_WINDOW: Duration = Duration::from_secs(2);
/// Per-candidate probe slice on the server side.
pub(crate) const PROBE_SLICE: Duration = Duration::from_millis(500);
/// Maximum concurrently running server-side probe bursts (leaf L4 review
/// Finding 1c): the responder reaps a completed burst before admitting a new
/// batch past this cap, bounding the burst load off the accept loop.
pub(crate) const BURST_CONCURRENCY_CAP: usize = 2;
/// Minimum interval between two probe bursts for the SAME peer (leaf L4
/// review Finding 1a): a fresh offer epoch inside the window is answered but
/// starts no new burst. Monotonic per peer, measured from the burst handover.
pub(crate) const BURST_MIN_INTERVAL: Duration = Duration::from_secs(5);

/// Role of the sender inside the offer/answer exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Offer,
    Answer,
}

/// One typed punch coordination datagram: role, epoch and candidate set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PunchMessage {
    pub kind: Kind,
    pub epoch: u32,
    pub candidates: Vec<SocketAddr>,
}

/// Wire magic: `"pnc1"` + version byte 1.
const MAGIC: [u8; 5] = [b'p', b'n', b'c', b'1', 1];

/// Serializes a punch message; `None` when it exceeds `MAX_MESSAGE_BYTES`, carries
/// too many candidates, or carries a candidate the codec policy denies.
pub(crate) fn encode(message: &PunchMessage) -> Option<Vec<u8>> {
    if message.candidates.len() > MAX_CANDIDATES
        || message
            .candidates
            .iter()
            .any(|candidate| !candidate_allowed(*candidate))
    {
        return None;
    }
    let mut bytes = Vec::with_capacity(MAGIC.len() + 6 + 18 * MAX_CANDIDATES);
    bytes.extend_from_slice(&MAGIC);
    bytes.push(match message.kind {
        Kind::Offer => 1,
        Kind::Answer => 2,
    });
    bytes.extend_from_slice(&message.epoch.to_le_bytes());
    bytes.push(message.candidates.len() as u8);
    for candidate in &message.candidates {
        match candidate {
            SocketAddr::V4(v4) => {
                bytes.push(4);
                bytes.extend_from_slice(&v4.ip().octets());
                bytes.extend_from_slice(&v4.port().to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                bytes.push(6);
                bytes.extend_from_slice(&v6.ip().octets());
                bytes.extend_from_slice(&v6.port().to_be_bytes());
            }
        }
    }
    if bytes.len() > MAX_MESSAGE_BYTES {
        return None;
    }
    Some(bytes)
}

/// Parses an encoded punch message; `None` (never panics) on any malformed,
/// oversized, hostile or policy-violating input.
pub(crate) fn decode(bytes: &[u8]) -> Option<PunchMessage> {
    if bytes.len() < MAGIC.len() + 2 || bytes[..MAGIC.len()] != MAGIC {
        return None;
    }
    let kind = match bytes[MAGIC.len()] {
        1 => Kind::Offer,
        2 => Kind::Answer,
        _ => return None,
    };
    // Fixed header after magic: kind + epoch + count.
    if bytes.len() < 11 {
        return None;
    }
    let mut cursor = MAGIC.len() + 1;
    let epoch = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().ok()?);
    cursor += 4;
    let count = bytes[cursor] as usize;
    cursor += 1;
    if count > MAX_CANDIDATES {
        return None;
    }
    let mut candidates = Vec::with_capacity(count);
    for _ in 0..count {
        // family byte + address bytes + big-endian port, per family size.
        let family = *bytes.get(cursor)?;
        let (item_len, address) = match family {
            4 => {
                let octets = bytes.get(cursor + 1..cursor + 5)?;
                (
                    5usize,
                    IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])),
                )
            }
            6 => {
                let mut segments = [0u16; 8];
                for (index, segment) in segments.iter_mut().enumerate() {
                    let raw = bytes.get(cursor + 1 + index * 2..cursor + 3 + index * 2)?;
                    *segment = u16::from_be_bytes(raw.try_into().ok()?);
                }
                (17usize, IpAddr::V6(std::net::Ipv6Addr::from(segments)))
            }
            _ => return None,
        };
        let raw = bytes.get(cursor + item_len..cursor + item_len + 2)?;
        let port = u16::from_be_bytes(raw.try_into().ok()?);
        cursor += item_len + 2;
        candidates.push(SocketAddr::new(address, port));
    }
    // Count lie / trailing bytes: the items must consume the buffer exactly.
    if cursor != bytes.len() {
        return None;
    }
    if candidates.iter().any(|c| !candidate_allowed(*c)) {
        return None;
    }
    // Canonicalized duplicate rejection: a v4-mapped v6 equals its v4 twin.
    let mut canonical = candidates
        .iter()
        .map(|c| SocketAddr::new(c.ip().to_canonical(), c.port()))
        .collect::<Vec<_>>();
    canonical.sort();
    if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return None;
    }
    Some(PunchMessage {
        kind,
        epoch,
        candidates,
    })
}

/// Mirror of `crate::network::admission::policy::dial_address` (that function
/// is private to the admission module, so the predicate is duplicated here;
/// keep both in sync). Denies port 0, unspecified/multicast/broadcast and the
/// synthetic fabric prefix `fd15:070a:510b::/48`; allows loopback and
/// documentation ranges (dial parity with the dialer).
pub(crate) fn candidate_allowed(address: SocketAddr) -> bool {
    let ip = address.ip().to_canonical();
    address.port() != 0
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && ip != IpAddr::V4(Ipv4Addr::BROADCAST)
        && native_ip(ip)
}

/// Production denials for candidates a server probes from a peer-claimed
/// Offer (leaf L4 review Finding 2): loopback, unspecified, multicast,
/// broadcast, v4 link-local (169.254/16), v6 link-local (fe80::/10) and the
/// synthetic fabric prefix. Private LAN ranges stay allowed: same-LAN
/// punching is legitimate. Documentation ranges are allowed too: they are not
/// routed on the public internet, so a probe to them reaches nothing, and the
/// controlled-network matrix uses TEST-NET-3 as its WAN.
pub(crate) fn peer_claimed_probe_denied(canonical: IpAddr) -> bool {
    canonical.is_loopback()
        || canonical.is_unspecified()
        || canonical.is_multicast()
        || canonical == IpAddr::V4(Ipv4Addr::BROADCAST)
        || matches!(&canonical, IpAddr::V4(v4) if v4.is_link_local())
        || matches!(&canonical, IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80)
        || !native_ip(canonical)
}

/// Gate applied wherever a probe target comes from a PEER-CLAIMED
/// candidate. Test builds additionally allow loopback so the fake-NAT
/// role test can probe the server's injected mapped endpoint; production
/// builds never probe peer-claimed loopback.
pub(crate) fn peer_claimed_probe_allowed(address: SocketAddr) -> bool {
    let canonical = address.ip().to_canonical();
    if canonical.is_loopback() {
        #[cfg(test)]
        return address.port() != 0;
        #[cfg(not(test))]
        return false;
    }
    !peer_claimed_probe_denied(canonical)
}

/// Mirror of `policy::native_ip`: conservative fabric-prefix denial only.
fn native_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => true,
        IpAddr::V6(ip) => ip.octets()[..6] != [0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b],
    }
}

/// Builds the local candidate list: the reflexive guess leads (when present
/// and valid), the bound local address follows when allowed; canonicalized
/// dedupe, capped at `MAX_CANDIDATES`; may be empty (wildcard or zero port).
pub(crate) fn local_candidates(local: SocketAddr, reflexive: Option<IpAddr>) -> Vec<SocketAddr> {
    let mut candidates = Vec::with_capacity(MAX_CANDIDATES);
    let push = |candidate: SocketAddr, candidates: &mut Vec<SocketAddr>| {
        let canonical = SocketAddr::new(candidate.ip().to_canonical(), candidate.port());
        if candidate_allowed(candidate) && !candidates.contains(&canonical) {
            candidates.push(canonical);
        }
    };
    if let Some(ip) = reflexive {
        push(SocketAddr::new(ip, local.port()), &mut candidates);
    }
    push(local, &mut candidates);
    candidates.truncate(MAX_CANDIDATES);
    candidates
}

/// Why one punch datagram was not sent. `Refused` is transient (request
/// queue or carrier budget full, no route yet on a cold Yggdrasil path): the
/// sender retries inside its window. `Closed` is permanent for this link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SendError {
    Refused,
    Closed,
}

/// Bidirectional punch transport: typed sends and raw receives with budgets.
pub(crate) trait PunchLink {
    fn send(
        &self,
        message: &PunchMessage,
        budget: Duration,
    ) -> impl Future<Output = Result<(), SendError>> + Send;
    /// Receives one raw datagram; `None` when the link is closed. Must be
    /// cancel-safe: callers bound it with timeouts and call it again.
    fn recv_raw(&mut self) -> impl Future<Output = Option<Vec<u8>>> + Send;
}

/// Punch channel over the Yggdrasil bridge control datagrams.
pub(crate) struct PunchChannel {
    sender: shaar_ygg::DatagramSender,
    receiver: shaar_ygg::PeerDatagrams,
}

impl PunchChannel {
    /// Opens the control datagram pair to an allowlisted peer.
    pub(crate) async fn open(
        bridge: &shaar_ygg::YggBridge,
        peer: [u8; 32],
    ) -> Result<Self, shaar_ygg::DatagramError> {
        let datagrams = bridge.open_control_datagrams(peer, OPEN_BUDGET).await?;
        Ok(Self {
            sender: datagrams.sender(),
            receiver: datagrams,
        })
    }
}

impl PunchLink for PunchChannel {
    async fn send(&self, message: &PunchMessage, budget: Duration) -> Result<(), SendError> {
        let bytes = encode(message).ok_or(SendError::Closed)?;
        self.sender
            .send(&bytes, budget)
            .await
            .map_err(|error| match error {
                DatagramError::Busy | DatagramError::TimedOut | DatagramError::Transport(_) => {
                    SendError::Refused
                }
                _ => SendError::Closed,
            })
    }

    async fn recv_raw(&mut self) -> Option<Vec<u8>> {
        self.receiver.recv().await.ok()
    }
}

/// One client-side punch attempt payload: the peer and its answer candidates.
pub(crate) struct OfferBatch {
    pub peer: [u8; 32],
    pub candidates: Vec<SocketAddr>,
}

/// Why one punch attempt ended: the `reason` token of the trace line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EndReason {
    /// A probe completed a session.
    Direct,
    /// No time was left: the attempt deadline had passed or cut the exchange window.
    Deadline,
    /// No matching Answer arrived inside the exchange window.
    NoAnswer,
    /// The control link is closed (permanent send failure or closed receive end).
    Closed,
    /// An Answer arrived but no probe completed (none passed the gate, or all failed).
    Probe,
}

impl EndReason {
    pub(crate) const fn token(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Deadline => "deadline",
            Self::NoAnswer => "no-answer",
            Self::Closed => "closed",
            Self::Probe => "probe",
        }
    }
}

/// Client-side punch state machine for one attempt.
///
/// Sends the Offer, waits for a matching Answer, then probes the answered
/// candidates that pass the peer-claimed gate; the first completed session
/// wins. The gate is the uniform production rule on both sides (Finding 2):
/// the client applies it exactly where the server does on answered peers.
/// Every exit path traces exactly once with its [`EndReason`]; the success
/// path returns the session, everything else returns `None`.
pub(crate) async fn client_attempt<L, C, Fut>(
    channel: &mut L,
    connect: C,
    candidates: Vec<SocketAddr>,
    epoch: u32,
    deadline: Instant,
    role: &'static str,
) -> Option<Session>
where
    L: PunchLink,
    C: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = Result<Session, NetworkError>>,
{
    let started = Instant::now();
    let offered = candidates.len();
    let (session, reason) = client_exchange(channel, connect, candidates, epoch, deadline).await;
    trace_attempt(role, offered, reason, started);
    session
}

/// The attempt itself; returns the session (if any) and why the attempt ended.
async fn client_exchange<L, C, Fut>(
    channel: &mut L,
    connect: C,
    candidates: Vec<SocketAddr>,
    epoch: u32,
    deadline: Instant,
) -> (Option<Session>, EndReason)
where
    L: PunchLink,
    C: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = Result<Session, NetworkError>>,
{
    let started = Instant::now();
    if started >= deadline {
        return (None, EndReason::Deadline);
    }
    let offer = PunchMessage {
        kind: Kind::Offer,
        epoch,
        candidates,
    };
    let exchange_end = deadline.min(started + EXCHANGE_BUDGET);
    // Why the window ends without an Answer: the attempt deadline cut it short, or the full budget ran out.
    let window_end = if deadline <= started + EXCHANGE_BUDGET {
        EndReason::Deadline
    } else {
        EndReason::NoAnswer
    };
    // The Offer is repeated every `OFFER_RESEND` until the matching Answer or
    // the end of the window; the responder answers every copy and starts at
    // most one probe burst per epoch, so copies are idempotent.
    let mut resend_at = started;
    let answer = loop {
        if Instant::now() >= resend_at {
            let sent = timeout_at(exchange_end, channel.send(&offer, EXCHANGE_BUDGET)).await;
            // A refused copy is lost like any other: the next one follows after
            // `OFFER_RESEND` while the window lasts; only a closed link ends it.
            if sent.is_err() {
                return (None, window_end);
            }
            if matches!(sent, Ok(Err(SendError::Closed))) {
                return (None, EndReason::Closed);
            }
            resend_at = Instant::now() + OFFER_RESEND;
        }
        match timeout_at(resend_at.min(exchange_end), channel.recv_raw()).await {
            Err(_) if Instant::now() >= exchange_end => return (None, window_end),
            // Resend interval elapsed inside the window: send the next copy.
            Err(_) => continue,
            Ok(None) => return (None, EndReason::Closed),
            Ok(Some(raw)) => match decode(&raw) {
                Some(PunchMessage {
                    kind: Kind::Answer,
                    epoch: answer_epoch,
                    candidates: answer_candidates,
                }) if answer_epoch == epoch => break answer_candidates,
                _ => continue,
            },
        }
    };
    let burst_end = deadline.min(Instant::now() + PROBE_WINDOW);
    // Peer-claimed gate (Finding 2): the same production rule applies where
    // the client probes candidates an authenticated server ANSWERED. The
    // codec still accepts special ranges for dial parity; the probe decision
    // is where the gate lives.
    let gated: Vec<SocketAddr> = answer
        .into_iter()
        .filter(|candidate| peer_claimed_probe_allowed(*candidate))
        .collect();
    // The window bounds the whole burst: select_all is wrapped in one
    // timeout_at, so probes that never complete still exit by `burst_end`.
    let mut probes = gated
        .into_iter()
        .map(|addr| Box::pin(connect(addr)) as Pin<Box<Fut>>)
        .collect::<Vec<_>>();
    while !probes.is_empty() {
        match timeout_at(burst_end, futures::future::select_all(probes)).await {
            Ok((Ok(session), _index, _rest)) => return (Some(session), EndReason::Direct),
            Ok((Err(_), _index, rest)) => probes = rest,
            Err(_) => break,
        }
    }
    (None, EndReason::Probe)
}

/// Server-side bounded probe burst over PEER-CLAIMED candidates (Finding 2),
/// run inside the responder task (off the accept loop).
///
/// For at most `MAX_CANDIDATES` probe-gated candidates in order, one
/// [`crate::network::ProbeHandle::probe`] per candidate, each bounded by its
/// own `PROBE_SLICE` deadline inside the handle (a silent candidate cannot
/// starve the rest); the whole burst is thus bounded by
/// `MAX_CANDIDATES * PROBE_SLICE` (2 s), matching the client's
/// `PROBE_WINDOW`. Stops on the first completed handshake. Completed
/// connections are closed by the handle (they only open the NAT mapping; the
/// accept loop owns the real session). Traces exactly once and returns
/// whether any probe completed.
pub(crate) async fn probe_burst_sequential(
    probes: &crate::network::admission::ProbeHandle,
    peer: PublicKey,
    candidates: &[SocketAddr],
    role: &'static str,
) -> bool {
    let started = Instant::now();
    let mut completed = false;
    for candidate in candidates.iter().take(MAX_CANDIDATES) {
        // Peer-claimed gate (Finding 2): special ranges never become probes.
        if !peer_claimed_probe_allowed(*candidate) {
            continue;
        }
        if probes.probe(peer, *candidate).await {
            completed = true;
            break;
        }
    }
    let reason = if completed {
        EndReason::Direct
    } else {
        EndReason::Probe
    };
    trace_attempt(role, candidates.len(), reason, started);
    completed
}

/// The attempt trace line: counts, a reason and timing only, no addresses.
pub(crate) fn trace_line(
    role: &str,
    candidates: usize,
    reason: EndReason,
    elapsed_ms: u128,
) -> String {
    format!(
        "shaar: {role} punch candidates={candidates} outcome={} reason={} elapsed_ms={elapsed_ms}",
        if reason == EndReason::Direct {
            "direct"
        } else {
            "fallback"
        },
        reason.token()
    )
}

fn trace_attempt(role: &'static str, candidates: usize, reason: EndReason, started: Instant) {
    eprintln!(
        "{}",
        trace_line(role, candidates, reason, started.elapsed().as_millis())
    );
}

#[cfg(test)]
mod punch_tests;

#[cfg(test)]
mod punch_rules_tests;

#[cfg(test)]
mod punch_resend_tests;

#[cfg(test)]
mod punch_reason_tests;
