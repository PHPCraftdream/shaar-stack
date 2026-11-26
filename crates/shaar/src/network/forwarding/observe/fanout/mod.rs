//! Fan-out measurement of the NAT in front of this machine (leaf NAT-9): one socket sends one
//! Mainline `find_node` to each of many distinct nodes, and the answers are counted per bucket of
//! destinations in send order. A NAT that limits the sessions of one subscriber shows as answers
//! that stop at a fixed index; dead nodes show as a smooth decline. The run prints counts only,
//! never an address, a key or a node list, and it is no step of the products.
//!
//! The nodes come from the bootstrap hosts and from the replies themselves (the crawl of the
//! network is the load), so the run needs no server of ours. Every node gets at most one datagram.

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::{Instant, MissedTickBehavior, interval};

use super::nat_ports::{bootstrap_hosts, plausible, random_id, reply_nodes, top_level_bytes};
use crate::config::MainlineNetwork;

/// Destinations contacted when the operator names no number.
pub const DEFAULT_DESTINATIONS: u16 = 2000;
/// Most destinations one run may contact (a transaction is the two bytes of the send index).
pub const MAX_DESTINATIONS: u16 = 8000;
/// Datagrams per second when the operator names no rate.
pub const DEFAULT_RATE: u16 = 100;
/// Most datagrams per second.
pub const MAX_RATE: u16 = 200;
/// Destinations per line of the table.
const BUCKET: u16 = 100;
/// The whole run, sends and the wait for the last answers, never lasts longer.
const RUN_LIMIT: Duration = Duration::from_secs(100);
/// How long the run waits for a late answer once nothing more is sent.
const TAIL: Duration = Duration::from_secs(3);
/// Nodes known at once (queued or contacted); a reply cannot grow the run past it.
const KNOWN_CAP: usize = 32_000;
const MAX_PACKET: usize = 1500;
/// Length of a `find_node` query with 20-byte ids and a two-byte transaction.
const QUERY_LEN: usize = 92;
/// Receive failures in a row after which the run gives up. Windows reports the ICMP error of an
/// earlier send as one failure, so a few in a run are normal.
const MAX_RECEIVE_FAILURES: u16 = 1000;

/// What one run is asked to do.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Fanout {
    pub(crate) destinations: u16,
    pub(crate) rate: u16,
    pub(crate) bucket: u16,
    pub(crate) limit: Duration,
    pub(crate) tail: Duration,
}

impl Fanout {
    /// The bounded run of the operator's numbers; a number outside its range is refused.
    pub(crate) fn new(destinations: u16, rate: u16) -> Result<Self, String> {
        if !(1..=MAX_DESTINATIONS).contains(&destinations) {
            return Err(format!("destinations must be 1 to {MAX_DESTINATIONS}"));
        }
        if !(1..=MAX_RATE).contains(&rate) {
            return Err(format!("rate must be 1 to {MAX_RATE} per second"));
        }
        Ok(Self {
            destinations,
            rate,
            bucket: BUCKET,
            limit: RUN_LIMIT,
            tail: TAIL,
        })
    }
}

/// The counts of one run: per bucket of destinations in send order, how many were sent and how
/// many answered.
#[derive(Debug, Default)]
pub(crate) struct Outcome {
    pub(crate) sent: u16,
    pub(crate) errors: u16,
    pub(crate) sent_by_bucket: Vec<u16>,
    pub(crate) answered_by_bucket: Vec<u16>,
    pub(crate) elapsed: Duration,
    /// The crawl ran out of nodes before the asked number was reached.
    pub(crate) dry: bool,
}

/// A node the run knows: queued until its send sets `index`.
struct Slot {
    index: Option<u16>,
    answered: bool,
}

impl Slot {
    const fn queued() -> Self {
        Self {
            index: None,
            answered: false,
        }
    }
}

/// Measures the fan-out of one socket against the nodes of `network` and returns the lines to
/// print: one per bucket and a closing line.
pub async fn nat_fanout(
    network: &MainlineNetwork,
    destinations: u16,
    rate: u16,
) -> Result<Vec<String>, String> {
    let options = Fanout::new(destinations, rate)?;
    let hosts = bootstrap_hosts(network).await;
    let outcome = walk(&hosts, options, plausible).await?;
    Ok(lines(&outcome, options))
}

/// Walks the network from `hosts` on one socket: one `find_node` per distinct node at the asked
/// rate until `options.destinations` were contacted, the crawl ran dry or the limit passed.
/// `admit` says which node addresses a reply may add.
pub(crate) async fn walk(
    hosts: &[SocketAddrV4],
    options: Fanout,
    admit: fn(Ipv4Addr) -> bool,
) -> Result<Outcome, String> {
    if hosts.is_empty() {
        return Err("no bootstrap host to start from".to_owned());
    }
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|error| format!("socket: {error}"))?;
    let bucket = options.bucket.max(1);
    let buckets = usize::from(options.destinations.div_ceil(bucket));
    let mut outcome = Outcome {
        sent_by_bucket: vec![0; buckets],
        answered_by_bucket: vec![0; buckets],
        ..Outcome::default()
    };
    let wanted = usize::from(options.destinations);
    let mut known: HashMap<SocketAddrV4, Slot> = HashMap::with_capacity(wanted * 2);
    let mut queue: VecDeque<SocketAddrV4> = VecDeque::with_capacity(wanted);
    for host in hosts {
        if known.insert(*host, Slot::queued()).is_none() {
            queue.push_back(*host);
        }
    }
    let id = random_id();
    let started = Instant::now();
    let mut last_event = started;
    let mut ticker = interval(Duration::from_micros(
        1_000_000 / u64::from(options.rate.max(1)),
    ));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut buffer = [0_u8; MAX_PACKET];
    let mut failures = 0_u16;
    while started.elapsed() < options.limit {
        tokio::select! {
            _ = ticker.tick() => {
                let now = Instant::now();
                let next = if outcome.sent < options.destinations {
                    queue.pop_front()
                } else {
                    None
                };
                match next {
                    Some(node) => {
                        let index = outcome.sent;
                        if let Some(slot) = known.get_mut(&node) {
                            slot.index = Some(index);
                        }
                        outcome.sent += 1;
                        if let Some(count) = outcome.sent_by_bucket.get_mut(usize::from(index / bucket)) {
                            *count += 1;
                        }
                        let packet = query(&id, &random_id(), index.to_be_bytes());
                        if socket.send_to(&packet, node).await.is_err() {
                            outcome.errors = outcome.errors.saturating_add(1);
                        }
                        last_event = now;
                    }
                    None if now.duration_since(last_event) >= options.tail => {
                        outcome.dry = outcome.sent < options.destinations;
                        break;
                    }
                    None => {}
                }
            }
            received = socket.recv_from(&mut buffer) => match received {
                Ok((length, SocketAddr::V4(from))) => {
                    failures = 0;
                    answer(&buffer[..length], from, &mut known, &mut queue, &mut outcome, bucket, admit);
                }
                Ok(_) => failures = 0,
                Err(_) => {
                    failures += 1;
                    if failures >= MAX_RECEIVE_FAILURES {
                        return Err("the socket keeps failing to receive".to_owned());
                    }
                }
            },
        }
    }
    outcome.elapsed = started.elapsed();
    Ok(outcome)
}

/// Counts the answer of a contacted node once and queues the nodes it names (`admit` decides which
/// addresses count, and the number of known nodes is bounded).
fn answer(
    packet: &[u8],
    from: SocketAddrV4,
    known: &mut HashMap<SocketAddrV4, Slot>,
    queue: &mut VecDeque<SocketAddrV4>,
    outcome: &mut Outcome,
    bucket: u16,
    admit: fn(Ipv4Addr) -> bool,
) {
    let Some(slot) = known.get_mut(&from) else {
        return;
    };
    let Some(index) = slot.index else {
        return;
    };
    let transaction = index.to_be_bytes();
    if slot.answered || top_level_bytes(packet, b"t") != Some(&transaction[..]) {
        return;
    }
    slot.answered = true;
    if let Some(count) = outcome
        .answered_by_bucket
        .get_mut(usize::from(index / bucket))
    {
        *count += 1;
    }
    let Some(nodes) = reply_nodes(packet, transaction) else {
        return;
    };
    for node in nodes {
        if admit(*node.ip()) && known.len() < KNOWN_CAP && !known.contains_key(&node) {
            known.insert(node, Slot::queued());
            queue.push_back(node);
        }
    }
}

/// A Mainline `find_node` query (BEP 5), built on the stack: the same bytes as the learning step.
pub(crate) fn query(id: &[u8; 20], target: &[u8; 20], transaction: [u8; 2]) -> [u8; QUERY_LEN] {
    let parts: [&[u8]; 7] = [
        b"d1:ad2:id20:",
        id,
        b"6:target20:",
        target,
        b"e1:q9:find_node1:t2:",
        &transaction,
        b"1:y1:qe",
    ];
    let mut packet = [0_u8; QUERY_LEN];
    let mut at = 0;
    for part in parts {
        packet[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    packet
}

/// One line per bucket that was sent to and a closing line; counts only.
pub(crate) fn lines(outcome: &Outcome, options: Fanout) -> Vec<String> {
    let mut lines = Vec::with_capacity(outcome.sent_by_bucket.len() + 1);
    let table = outcome
        .sent_by_bucket
        .iter()
        .zip(&outcome.answered_by_bucket);
    for (bucket, (sent, answered)) in table.enumerate() {
        if *sent > 0 {
            lines.push(format!(
                "fanout bucket={bucket} sent={sent} answered={answered}"
            ));
        }
    }
    let answered: u32 = outcome
        .answered_by_bucket
        .iter()
        .map(|n| u32::from(*n))
        .sum();
    let last = outcome
        .answered_by_bucket
        .iter()
        .rposition(|count| *count > 0)
        .map_or_else(|| "none".to_owned(), |bucket| bucket.to_string());
    lines.push(format!(
        "fanout destinations={} answered={answered} errors={} dry={} last_replying_bucket={last} \
         elapsed_ms={} rate={} bucket_size={}",
        outcome.sent,
        outcome.errors,
        if outcome.dry { "yes" } else { "no" },
        outcome.elapsed.as_millis(),
        options.rate,
        options.bucket,
    ));
    lines
}

#[cfg(test)]
mod tests;
