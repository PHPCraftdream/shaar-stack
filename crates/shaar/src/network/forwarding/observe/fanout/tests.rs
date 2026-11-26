//! Tests of the fan-out measurement: the query bytes, the walk against a fake network of nodes on
//! the loopback (distinct destinations, one datagram each, the table, a quota that stops the answers,
//! a crawl that runs dry, the rate and the limit, forged and repeated answers) and the printed lines.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use super::{Fanout, MAX_DESTINATIONS, MAX_RATE, Outcome, lines, query, walk};
use crate::network::forwarding::observe::nat_ports::{find_node_packet, top_level_bytes};

const NODES_PER_REPLY: usize = 16;

fn options(destinations: u16, bucket: u16) -> Fanout {
    Fanout {
        destinations,
        rate: 2000,
        bucket,
        limit: Duration::from_secs(10),
        tail: Duration::from_millis(250),
    }
}

/// The loopback is not a public address, so the tests admit every named node.
fn admit_all(_: Ipv4Addr) -> bool {
    true
}

/// A response that names the compact `nodes` and carries `transaction`.
fn reply(transaction: [u8; 2], names: &[SocketAddrV4]) -> Vec<u8> {
    let mut nodes = Vec::with_capacity(names.len() * 26);
    for name in names {
        nodes.extend_from_slice(&[5_u8; 20]);
        nodes.extend_from_slice(&name.ip().octets());
        nodes.extend_from_slice(&name.port().to_be_bytes());
    }
    let mut packet = b"d1:rd2:id20:".to_vec();
    packet.extend_from_slice(&[7; 20]);
    packet.extend_from_slice(format!("5:nodes{}:", nodes.len()).as_bytes());
    packet.extend_from_slice(&nodes);
    packet.extend_from_slice(b"e1:t2:");
    packet.extend_from_slice(&transaction);
    packet.extend_from_slice(b"1:y1:re");
    packet
}

/// How a fake node treats the query that carries send index `index`.
#[derive(Clone, Copy)]
enum Behaviour {
    /// Answers every query once.
    Answers,
    /// Answers only the first `n` send indexes: a quota in front of the sender.
    Quota(u16),
    /// Answers every query twice.
    Twice,
    /// Answers with a transaction that is not the query's.
    Forges,
}

/// A fake network of nodes on the loopback: node `i` names the next sixteen nodes of a ring and
/// counts the datagrams it receives.
struct Swarm {
    addresses: Vec<SocketAddrV4>,
    received: Arc<Vec<AtomicU16>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Swarm {
    async fn new(count: usize, behaviour: Behaviour) -> Self {
        let mut sockets = Vec::with_capacity(count);
        let mut addresses = Vec::with_capacity(count);
        for _ in 0..count {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("node");
            let SocketAddr::V4(address) = socket.local_addr().expect("node address") else {
                panic!("an IPv4 socket");
            };
            addresses.push(address);
            sockets.push(socket);
        }
        let received: Arc<Vec<AtomicU16>> =
            Arc::new((0..count).map(|_| AtomicU16::new(0)).collect());
        let mut tasks = Vec::with_capacity(count);
        for (node, socket) in sockets.into_iter().enumerate() {
            let names: Vec<SocketAddrV4> = (1..=NODES_PER_REPLY)
                .map(|step| addresses[(node + step) % count])
                .collect();
            let counts = Arc::clone(&received);
            tasks.push(tokio::spawn(async move {
                let mut buffer = [0_u8; 1500];
                while let Ok((length, from)) = socket.recv_from(&mut buffer).await {
                    counts[node].fetch_add(1, Ordering::SeqCst);
                    let Some(&[high, low]) = top_level_bytes(&buffer[..length], b"t") else {
                        continue;
                    };
                    let index = u16::from_be_bytes([high, low]);
                    let packet = match behaviour {
                        Behaviour::Quota(n) if index >= n => continue,
                        Behaviour::Forges => reply([high ^ 0xFF, low], &names),
                        _ => reply([high, low], &names),
                    };
                    let _ = socket.send_to(&packet, from).await;
                    if matches!(behaviour, Behaviour::Twice) {
                        let _ = socket.send_to(&packet, from).await;
                    }
                }
            }));
        }
        Self {
            addresses,
            received,
            tasks,
        }
    }

    /// The datagrams each node received.
    fn counts(&self) -> Vec<u16> {
        self.received
            .iter()
            .map(|count| count.load(Ordering::SeqCst))
            .collect()
    }
}

impl Drop for Swarm {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn total(counts: &[u16]) -> u16 {
    counts.iter().sum()
}

#[test]
fn the_query_has_the_bytes_of_the_learning_query() {
    let (id, target) = ([1_u8; 20], [2_u8; 20]);
    let built = query(&id, &target, [3, 4]);
    assert_eq!(built[..], find_node_packet(&id, &target, [3, 4])[..]);
}

#[tokio::test]
async fn the_walk_reaches_the_asked_number_of_distinct_nodes_with_one_datagram_each() {
    let swarm = Swarm::new(60, Behaviour::Answers).await;
    let outcome = walk(&swarm.addresses[..1], options(40, 10), admit_all)
        .await
        .expect("walk");
    assert_eq!(outcome.sent, 40);
    assert!(!outcome.dry);
    assert_eq!(outcome.errors, 0);
    assert_eq!(outcome.sent_by_bucket, vec![10; 4]);
    assert_eq!(outcome.answered_by_bucket, vec![10; 4]);
    let counts = swarm.counts();
    assert_eq!(total(&counts), 40, "one datagram per destination, no more");
    assert!(counts.iter().all(|count| *count <= 1), "no node got two");
}

#[tokio::test]
async fn a_quota_in_front_of_the_sender_shows_as_a_cliff_in_the_table() {
    let swarm = Swarm::new(60, Behaviour::Quota(20)).await;
    let outcome = walk(&swarm.addresses[..1], options(30, 10), admit_all)
        .await
        .expect("walk");
    assert_eq!(outcome.sent, 30);
    assert_eq!(outcome.sent_by_bucket, vec![10; 3]);
    assert_eq!(outcome.answered_by_bucket, vec![10, 10, 0]);
    let printed = lines(&outcome, options(30, 10));
    assert!(
        printed
            .last()
            .expect("closing")
            .contains("last_replying_bucket=1")
    );
}

#[tokio::test]
async fn a_dry_crawl_ends_after_the_tail_and_says_so() {
    let swarm = Swarm::new(12, Behaviour::Answers).await;
    let asked = options(50, 10);
    let outcome = walk(&swarm.addresses[..1], asked, admit_all)
        .await
        .expect("walk");
    assert_eq!(outcome.sent, 12, "every reachable node and no more");
    assert!(outcome.dry);
    assert!(outcome.elapsed >= asked.tail);
    assert_eq!(outcome.answered_by_bucket.iter().sum::<u16>(), 12);
}

#[tokio::test]
async fn the_rate_spaces_the_datagrams_and_the_limit_stops_the_run() {
    let swarm = Swarm::new(60, Behaviour::Answers).await;
    let slow = Fanout {
        rate: 50,
        ..options(30, 10)
    };
    let outcome = walk(&swarm.addresses[..1], slow, admit_all)
        .await
        .expect("walk");
    assert_eq!(outcome.sent, 30);
    assert!(
        outcome.elapsed >= Duration::from_millis(500),
        "29 gaps of 20 ms, got {:?}",
        outcome.elapsed
    );
    let short = Fanout {
        limit: Duration::from_millis(300),
        ..slow
    };
    let outcome = walk(&swarm.addresses[..1], short, admit_all)
        .await
        .expect("walk");
    assert!(
        outcome.sent < 30,
        "the limit cut the run, sent {}",
        outcome.sent
    );
    assert!(outcome.elapsed < Duration::from_secs(2));
}

#[tokio::test]
async fn a_repeated_answer_counts_once_and_a_wrong_transaction_never() {
    let twice = Swarm::new(20, Behaviour::Twice).await;
    let outcome = walk(&twice.addresses[..1], options(10, 10), admit_all)
        .await
        .expect("walk");
    assert_eq!(outcome.sent, 10);
    assert_eq!(outcome.answered_by_bucket, vec![10]);

    let forged = Swarm::new(20, Behaviour::Forges).await;
    let outcome = walk(&forged.addresses[..1], options(10, 10), admit_all)
        .await
        .expect("walk");
    assert_eq!(outcome.sent, 1, "no forged answer names a further node");
    assert_eq!(outcome.answered_by_bucket, vec![0]);
}

#[tokio::test]
async fn a_run_with_no_host_is_an_error() {
    assert!(walk(&[], options(10, 10), admit_all).await.is_err());
}

#[test]
fn the_lines_hold_counts_only_and_skip_buckets_never_sent_to() {
    let outcome = Outcome {
        sent: 250,
        errors: 1,
        sent_by_bucket: vec![100, 100, 50, 0],
        answered_by_bucket: vec![30, 28, 0, 0],
        elapsed: Duration::from_millis(2500),
        dry: false,
    };
    let printed = lines(&outcome, options(300, 100));
    assert_eq!(printed.len(), 4, "three buckets and the closing line");
    assert_eq!(printed[0], "fanout bucket=0 sent=100 answered=30");
    assert_eq!(printed[2], "fanout bucket=2 sent=50 answered=0");
    let closing = &printed[3];
    assert!(closing.contains("destinations=250 answered=58 errors=1 dry=no"));
    assert!(closing.contains("last_replying_bucket=1"));
    assert!(closing.contains("elapsed_ms=2500"));
    for line in &printed {
        assert!(
            !line.contains('.') && !line.contains(':'),
            "counts only: {line}"
        );
    }
    let silent = Outcome {
        sent_by_bucket: vec![100],
        answered_by_bucket: vec![0],
        ..Outcome::default()
    };
    assert!(
        lines(&silent, options(100, 100))[1].contains("last_replying_bucket=none"),
        "no answer at all"
    );
}

#[test]
fn numbers_outside_the_range_are_refused() {
    assert!(Fanout::new(1, 1).is_ok());
    assert!(Fanout::new(MAX_DESTINATIONS, MAX_RATE).is_ok());
    assert!(Fanout::new(0, 100).is_err());
    assert!(Fanout::new(MAX_DESTINATIONS + 1, 100).is_err());
    assert!(Fanout::new(100, 0).is_err());
    assert!(Fanout::new(100, MAX_RATE + 1).is_err());
}
