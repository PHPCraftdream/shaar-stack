//! The external endpoint of a spray socket, learned from one DHT node (leaf BDAY-1b-2). An easy
//! side must tell the hard side where to write, and the DHT votes describe the Mainline socket,
//! not this one. A DHT node names the endpoint it saw in the `ip` field of its answers (BEP 42,
//! the same field the votes of the product are made of), so one `ping` from the spray socket to a
//! configured bootstrap host is enough. At most [`MAX_PINGS`] datagrams of [`PING_LEN`] bytes go
//! out, in [`DISCOVER_WINDOW`] at most, to the hosts the operator configured for the DHT; it is
//! not a probe of ports and not a probe of the peer.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::time::{Instant, timeout_at};

use super::run::Datagrams;
use super::{Counters, Rng};
use crate::network::signaling::punch::peer_claimed_probe_allowed;

/// Most pings one discovery sends.
pub(crate) const MAX_PINGS: usize = 3;
/// Longest one discovery runs.
pub(crate) const DISCOVER_WINDOW: Duration = Duration::from_secs(3);
/// How long one node gets to answer before the next one is asked.
const PER_NODE: Duration = Duration::from_secs(1);
/// Length of the node id and of the transaction id in a ping.
const ID_LEN: usize = 20;
const TX_LEN: usize = 2;
/// Exact length of a ping: `d1:ad2:id20:<id>e1:q4:ping1:t2:<tx>1:y1:qe`.
pub(crate) const PING_LEN: usize = 56;
/// Most bytes of an answer that are read.
const ANSWER_MAX: usize = 512;

/// A ping query with the given node id and transaction id.
pub(crate) fn ping(id: &[u8; ID_LEN], tx: [u8; TX_LEN]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(PING_LEN);
    bytes.extend_from_slice(b"d1:ad2:id20:");
    bytes.extend_from_slice(id);
    bytes.extend_from_slice(b"e1:q4:ping1:t2:");
    bytes.extend_from_slice(&tx);
    bytes.extend_from_slice(b"1:y1:qe");
    bytes
}

/// Reads one bencoded item at `at`, returning its end. Only what an answer holds is understood:
/// byte strings, integers, lists and dictionaries; depth and length are bounded, anything else is
/// `None`.
fn skip(bytes: &[u8], at: usize, depth: u8) -> Option<usize> {
    if depth > 4 {
        return None;
    }
    match *bytes.get(at)? {
        b'i' => {
            let end = at + 1 + bytes.get(at + 1..)?.iter().position(|b| *b == b'e')?;
            (end > at + 1).then_some(end + 1)
        }
        b'l' | b'd' => {
            let mut cursor = at + 1;
            while *bytes.get(cursor)? != b'e' {
                cursor = skip(bytes, cursor, depth + 1)?;
            }
            Some(cursor + 1)
        }
        b'0'..=b'9' => {
            let (start, length) = string(bytes, at)?;
            start.checked_add(length)
        }
        _ => None,
    }
}

/// The start and the length of the byte string at `at`.
fn string(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
    let colon = at + bytes.get(at..)?.iter().position(|b| *b == b':')?;
    let digits = bytes.get(at..colon)?;
    if digits.is_empty() || digits.len() > 4 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let length: usize = std::str::from_utf8(digits).ok()?.parse().ok()?;
    let start = colon + 1;
    (start.checked_add(length)? <= bytes.len()).then_some((start, length))
}

/// The endpoint a DHT node named in its answer to the ping with transaction id `tx`: the `ip`
/// field of the top-level dictionary, six bytes (an IPv4 address and a big-endian port) that the
/// probe policy allows. `None` for anything else; never panics.
pub(crate) fn read_endpoint(bytes: &[u8], tx: [u8; TX_LEN]) -> Option<SocketAddrV4> {
    if bytes.len() > ANSWER_MAX || *bytes.first()? != b'd' {
        return None;
    }
    let mut cursor = 1;
    let mut endpoint = None;
    let mut answers = false;
    let mut replied = false;
    while *bytes.get(cursor)? != b'e' {
        let (key_start, key_length) = string(bytes, cursor)?;
        let key = &bytes[key_start..key_start + key_length];
        let value = key_start + key_length;
        let end = skip(bytes, value, 1)?;
        let item = &bytes[value..end];
        match key {
            b"ip" => {
                let (start, length) = string(item, 0)?;
                if length == 6 && start + length == item.len() {
                    let octets = &item[start..start + 6];
                    endpoint = Some(SocketAddrV4::new(
                        Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]),
                        u16::from_be_bytes([octets[4], octets[5]]),
                    ));
                }
            }
            b"t" => {
                let (start, length) = string(item, 0)?;
                answers = length == TX_LEN && item[start..start + length] == tx;
            }
            b"y" => {
                let (start, length) = string(item, 0)?;
                replied = length == 1 && item[start] == b'r';
            }
            _ => {}
        }
        cursor = end;
    }
    let endpoint = endpoint?;
    (answers
        && replied
        && endpoint.port() != 0
        && peer_claimed_probe_allowed(SocketAddr::V4(endpoint)))
    .then_some(endpoint)
}

/// Asks the configured DHT nodes, one after the other, for the endpoint this socket has outside:
/// a ping to each of at most [`MAX_PINGS`] nodes, each given [`PER_NODE`] to answer, the whole
/// run ending at `deadline` or after [`DISCOVER_WINDOW`], whichever is earlier. Only an answer
/// from the node that was asked, with the transaction id that was sent, counts. Every datagram
/// is booked against the caps.
pub(crate) async fn discover<P: Datagrams>(
    port: &mut P,
    nodes: &[SocketAddrV4],
    rng: &mut Rng,
    counters: &Counters,
    deadline: Instant,
) -> Option<SocketAddrV4> {
    let end = deadline.min(Instant::now() + DISCOVER_WINDOW);
    let mut buffer = [0_u8; ANSWER_MAX];
    for node in nodes.iter().take(MAX_PINGS) {
        if Instant::now() >= end || !peer_claimed_probe_allowed((*node).into()) {
            continue;
        }
        let mut id = [0_u8; ID_LEN];
        for chunk in id.chunks_mut(8) {
            chunk.copy_from_slice(&rng.next_u64().to_be_bytes()[..chunk.len()]);
        }
        let word = rng.next_u64();
        let tx = [word as u8, (word >> 8) as u8];
        let query = ping(&id, tx);
        // A ping is not a probe of the trial: it books bytes but not a probe.
        if !counters.reserve_send(query.len(), false) {
            return None;
        }
        if port.send_to(&query, *node).await.is_err() {
            continue;
        }
        let until = end.min(Instant::now() + PER_NODE);
        while let Ok(Ok((length, from))) = timeout_at(until, port.recv_from(&mut buffer)).await {
            counters.note_recv(length);
            if from == *node
                && let Some(endpoint) = read_endpoint(&buffer[..length], tx)
            {
                return Some(endpoint);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;

    use super::*;

    const PUBLIC_NODE: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 6881);
    const OTHER_NODE: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 8), 6881);
    const SEEN: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 9), 40_001);

    /// An answer of a DHT node: the `ip` field names `seen`, the transaction id is `tx`.
    fn answer(seen: SocketAddrV4, tx: [u8; 2]) -> Vec<u8> {
        let mut bytes = b"d2:ip6:".to_vec();
        bytes.extend_from_slice(&seen.ip().octets());
        bytes.extend_from_slice(&seen.port().to_be_bytes());
        bytes.extend_from_slice(b"1:rd2:id20:");
        bytes.extend_from_slice(&[7_u8; 20]);
        bytes.extend_from_slice(b"e1:t2:");
        bytes.extend_from_slice(&tx);
        bytes.extend_from_slice(b"1:y1:re");
        bytes
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Quirk {
        None,
        /// The answer comes from another address than the one asked.
        OtherSource,
        /// The answer carries another transaction id.
        OtherTransaction,
    }

    /// A model of the DHT nodes: those in `answering` name `SEEN`, the others stay silent.
    struct Dht {
        answering: Vec<SocketAddrV4>,
        quirk: Quirk,
        inbox: VecDeque<(Vec<u8>, SocketAddrV4)>,
        sent: Vec<(Vec<u8>, SocketAddrV4)>,
    }

    impl Dht {
        fn new(answering: &[SocketAddrV4], quirk: Quirk) -> Self {
            Self {
                answering: answering.to_vec(),
                quirk,
                inbox: VecDeque::new(),
                sent: Vec::new(),
            }
        }
    }

    impl Datagrams for Dht {
        async fn send_to(&mut self, bytes: &[u8], to: SocketAddrV4) -> io::Result<()> {
            self.sent.push((bytes.to_vec(), to));
            if self.answering.contains(&to) {
                let at = bytes.len() - 7 - 2;
                let mut tx = [bytes[at], bytes[at + 1]];
                if self.quirk == Quirk::OtherTransaction {
                    tx[0] ^= 0xff;
                }
                let from = if self.quirk == Quirk::OtherSource {
                    OTHER_NODE
                } else {
                    to
                };
                self.inbox.push_back((answer(SEEN, tx), from));
            }
            Ok(())
        }

        async fn recv_from(&mut self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddrV4)> {
            match self.inbox.pop_front() {
                Some((bytes, from)) => {
                    buffer[..bytes.len()].copy_from_slice(&bytes);
                    Ok((bytes.len(), from))
                }
                None => std::future::pending().await,
            }
        }
    }

    fn later() -> Instant {
        Instant::now() + Duration::from_secs(20)
    }

    #[test]
    fn a_ping_has_the_exact_wire_form() {
        let bytes = ping(&[9; 20], [1, 2]);
        let mut expected = b"d1:ad2:id20:".to_vec();
        expected.extend_from_slice(&[9; 20]);
        expected.extend_from_slice(b"e1:q4:ping1:t2:\x01\x021:y1:qe");
        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), PING_LEN);
    }

    #[test]
    fn the_endpoint_is_read_from_an_answer_for_its_transaction_only() {
        assert_eq!(read_endpoint(&answer(SEEN, [3, 4]), [3, 4]), Some(SEEN));
        assert_eq!(read_endpoint(&answer(SEEN, [3, 4]), [3, 5]), None);
    }

    #[test]
    fn hostile_answers_give_no_endpoint_and_never_panic() {
        let good = answer(SEEN, [3, 4]);
        // Every prefix of a good answer is cut short.
        for length in 0..good.len() {
            assert_eq!(read_endpoint(&good[..length], [3, 4]), None, "{length}");
        }
        let cases: [&[u8]; 9] = [
            b"",
            b"le",
            b"d2:ip5:abcde1:t2:\x03\x041:y1:re",
            b"d2:ip7:abcdefg1:t2:\x03\x041:y1:re",
            b"d1:rd2:id20:aaaaaaaaaaaaaaaaaaaae1:t2:\x03\x041:y1:re",
            b"d2:ip6:\xc6\x33\x64\x09\x9c\x411:t2:\x03\x041:y1:ee",
            b"d2:ip6:\xc6\x33\x64\x09\x00\x001:t2:\x03\x041:y1:re",
            b"d2:ip6:\xe0\x00\x00\x01\x9c\x411:t2:\x03\x041:y1:re",
            b"d2:ip6:\x00\x00\x00\x00\x9c\x411:t2:\x03\x041:y1:re",
        ];
        for case in cases {
            assert_eq!(read_endpoint(case, [3, 4]), None, "{case:?}");
        }
        let mut nested = b"d1:x".to_vec();
        nested.extend(std::iter::repeat_n(b'l', 200));
        assert_eq!(read_endpoint(&nested, [3, 4]), None);
        let mut long = good.clone();
        long.resize(ANSWER_MAX + 1, b'0');
        assert_eq!(read_endpoint(&long, [3, 4]), None);
        let mut rng = Rng::seeded(21);
        for _ in 0..5000 {
            let length = rng.below(80) as usize;
            let bytes: Vec<u8> = (0..length).map(|_| rng.next_u64() as u8).collect();
            let _ = read_endpoint(&bytes, [3, 4]);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_node_that_names_the_endpoint_gives_it_back_for_one_ping() {
        let mut dht = Dht::new(&[PUBLIC_NODE], Quirk::None);
        let counters = Counters::new();
        let found = discover(
            &mut dht,
            &[PUBLIC_NODE],
            &mut Rng::seeded(1),
            &counters,
            later(),
        )
        .await;
        assert_eq!(found, Some(SEEN));
        assert_eq!(dht.sent.len(), 1);
        let report = counters.report();
        assert_eq!(
            report.sent_bytes,
            (PING_LEN + super::super::UDP_IPV4_HEADER) as u64
        );
        assert_eq!(report.probes, 0, "a ping is not a probe of the trial");
        assert_eq!(report.recv_datagrams, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_node_gets_a_second_and_then_the_next_one_is_asked() {
        let mut dht = Dht::new(&[OTHER_NODE], Quirk::None);
        let counters = Counters::new();
        let started = Instant::now();
        let found = discover(
            &mut dht,
            &[PUBLIC_NODE, OTHER_NODE],
            &mut Rng::seeded(2),
            &counters,
            later(),
        )
        .await;
        assert_eq!(found, Some(SEEN));
        assert_eq!(dht.sent.len(), 2);
        assert_eq!(Instant::now() - started, PER_NODE);
    }

    #[tokio::test(start_paused = true)]
    async fn with_no_answer_at_most_three_pings_go_out_in_three_seconds() {
        let mut dht = Dht::new(&[], Quirk::None);
        let counters = Counters::new();
        let started = Instant::now();
        let nodes = [
            PUBLIC_NODE,
            OTHER_NODE,
            PUBLIC_NODE,
            OTHER_NODE,
            PUBLIC_NODE,
        ];
        let found = discover(&mut dht, &nodes, &mut Rng::seeded(3), &counters, later()).await;
        assert_eq!(found, None);
        assert_eq!(dht.sent.len(), MAX_PINGS);
        assert!(Instant::now() - started <= DISCOVER_WINDOW);
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_from_another_address_or_for_another_transaction_does_not_count() {
        for quirk in [Quirk::OtherSource, Quirk::OtherTransaction] {
            let mut dht = Dht::new(&[PUBLIC_NODE], quirk);
            let found = discover(
                &mut dht,
                &[PUBLIC_NODE],
                &mut Rng::seeded(4),
                &Counters::new(),
                later(),
            )
            .await;
            assert_eq!(found, None);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_node_the_probe_policy_denies_is_never_pinged_and_the_deadline_is_kept() {
        let multicast = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 1), 6881);
        let mut dht = Dht::new(&[multicast], Quirk::None);
        let found = discover(
            &mut dht,
            &[multicast],
            &mut Rng::seeded(5),
            &Counters::new(),
            later(),
        )
        .await;
        assert_eq!(found, None);
        assert!(dht.sent.is_empty());
        let mut dht = Dht::new(&[PUBLIC_NODE], Quirk::None);
        let past = Instant::now();
        let found = discover(
            &mut dht,
            &[PUBLIC_NODE],
            &mut Rng::seeded(6),
            &Counters::new(),
            past,
        )
        .await;
        assert_eq!(found, None);
        assert!(dht.sent.is_empty(), "no ping after the deadline");
    }

    #[tokio::test(start_paused = true)]
    async fn the_byte_cap_stops_the_pings() {
        let mut dht = Dht::new(&[PUBLIC_NODE], Quirk::None);
        let cap = (PING_LEN + super::super::UDP_IPV4_HEADER) as u64 - 1;
        let counters = Counters::with_cap(cap);
        let found = discover(
            &mut dht,
            &[PUBLIC_NODE],
            &mut Rng::seeded(7),
            &counters,
            later(),
        )
        .await;
        assert_eq!(found, None);
        assert!(dht.sent.is_empty());
        assert_eq!(counters.report().sent_bytes, 0);
    }
}
