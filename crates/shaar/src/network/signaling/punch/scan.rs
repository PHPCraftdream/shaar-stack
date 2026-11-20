//! Walk over the key-ordered port set of the peer (leaf SET-1, owner decision of 2026-11-18, which
//! replaced the ring scan of leaf NAT-2). A peer that could not tell its port, or whose port was
//! moved by a router mapping, still uses a port of the fixed set ([`crate::network::ports`]), and
//! the order in which it prefers them is a function of its own public key, which this side knows. So
//! the ports of the peer's set are probed on the peer's public address in that order, in slices of
//! [`SCAN_PORTS_PER_ATTEMPT`], one slice per attempt; nothing else is tried. A probe is the slotless
//! QUIC handshake of [`crate::network::admission::ProbeHandle`]; the first one that completes names
//! the address and the ordinary dial follows.
//!
//! The Server walks the same way in the other direction (leaf SET-1d): a burst of its probes also
//! covers one slice of the Client's order on the public addresses the Client offered, so a Client
//! that took a port of its own order, or got one mapped by a router, is found without a message.

use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use futures::{StreamExt, stream::FuturesUnordered};

use super::{MAX_CANDIDATES, peer_claimed_probe_allowed};
use crate::network::NetworkError;
use crate::network::signaling::ports;

/// Ports of the peer's ordered set probed by one attempt.
pub(crate) const SCAN_PORTS_PER_ATTEMPT: usize = 20;
/// Slices of the ordered set, one per attempt: slice `r` holds the ports `(r-1)*20 .. r*20` of the
/// peer's order, so the slices together are the whole set once.
pub(crate) const SCAN_RINGS: u32 = 5;
const _: () = assert!(SCAN_PORTS_PER_ATTEMPT * SCAN_RINGS as usize == ports::PORT_COUNT);
/// Bound of one probe: below one QUIC initial retransmission, so one datagram of about 1.2 KB.
pub(crate) const SCAN_SLICE: Duration = Duration::from_millis(300);

/// Whether the address of a peer may be walked: a public IPv4 address with a port. Private,
/// loopback, link-local, shared (100.64/10), unspecified, multicast and broadcast addresses are
/// never walked; a mapped IPv6 address counts as its IPv4 form, other IPv6 addresses are not walked.
fn scan_centre(address: SocketAddr) -> bool {
    let IpAddr::V4(ip) = address.ip().to_canonical() else {
        return false;
    };
    let shared = ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64;
    address.port() != 0
        && !shared
        && !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && ip != Ipv4Addr::BROADCAST
}

/// The epoch of the first attempt that reached a scan, zero until then.
static FIRST_SCAN_EPOCH: AtomicU32 = AtomicU32::new(0);

/// The slice of the attempt with punch epoch `epoch`: the first attempt that reaches a scan (one
/// that received an Answer) is slice 1, the next slice 2, and so on. Counting from the first
/// answered attempt, not from epoch 1, keeps the first slice from being lost to attempts that
/// never got an Answer; one attempt has one slice however many candidates it scans.
pub(crate) fn scan_ring(epoch: u32) -> u32 {
    ring_after(&FIRST_SCAN_EPOCH, epoch)
}

fn ring_after(first: &AtomicU32, epoch: u32) -> u32 {
    let start = match first.compare_exchange(0, epoch, Ordering::Relaxed, Ordering::Relaxed) {
        Ok(_) => epoch,
        Err(existing) => existing,
    };
    epoch.wrapping_sub(start).wrapping_add(1)
}

/// The addresses of slice `ring` of the set that the peer with public key `peer_key` prefers, on
/// the address of `centre`, in the peer's order; the port of `centre` itself is left out because it
/// is dialed anyway. Empty outside slices `1..=SCAN_RINGS` or for an address that is not walked.
pub(crate) fn ring_addresses(
    centre: SocketAddr,
    peer_key: &[u8; 32],
    ring: u32,
) -> Vec<SocketAddr> {
    if !(1..=SCAN_RINGS).contains(&ring) || !scan_centre(centre) {
        return Vec::new();
    }
    let first = usize::try_from(ring - 1).unwrap_or(0) * SCAN_PORTS_PER_ATTEMPT;
    ports::order(peer_key)[first..first + SCAN_PORTS_PER_ATTEMPT]
        .iter()
        .filter(|&&port| port != centre.port())
        .map(|&port| SocketAddr::new(centre.ip(), port))
        .collect()
}

/// The counts-only trace line of one scan.
pub(crate) fn scan_line(role: &str, ring: u32, probed: usize, found: bool) -> String {
    format!(
        "shaar: {role} punch scan ring={ring} probed={probed} found={}",
        if found { "yes" } else { "no" }
    )
}

/// Slice walked by the `burst`-th probe burst of one peer (counted from 1): the slices are taken
/// in turn and then again, so a peer that keeps trying covers the whole set over and over.
pub(crate) fn walk_ring(burst: u32) -> u32 {
    (burst.max(1) - 1) % SCAN_RINGS + 1
}

/// Distinct public IP addresses of one peer that a burst walks; one more would only add probes.
const WALK_ADDRESSES: usize = 2;

/// The addresses a Server burst walks for slice `ring`: that slice of the peer's order on each of
/// the first [`WALK_ADDRESSES`] distinct public IP addresses among the peer's `candidates`, except
/// the candidates themselves (they are probed anyway).
pub(crate) fn walk_addresses(
    candidates: &[SocketAddr],
    peer_key: &[u8; 32],
    ring: u32,
) -> Vec<SocketAddr> {
    let mut hosts: Vec<IpAddr> = Vec::with_capacity(WALK_ADDRESSES);
    let mut walked = Vec::new();
    for &candidate in candidates {
        let host = candidate.ip().to_canonical();
        if hosts.len() == WALK_ADDRESSES || hosts.contains(&host) || !scan_centre(candidate) {
            continue;
        }
        hosts.push(host);
        walked.extend(
            ring_addresses(candidate, peer_key, ring)
                .into_iter()
                .filter(|address| !candidates.contains(address)),
        );
    }
    walked
}

/// The first of `addresses` whose probe completes, each probe bounded by `slice`; `None` when none
/// does. The probes run all at once and the rest are dropped at the first completion.
pub(crate) async fn first_to_answer<P, PFut>(
    addresses: impl IntoIterator<Item = SocketAddr>,
    slice: Duration,
    probe: &P,
) -> Option<SocketAddr>
where
    P: Fn(SocketAddr) -> PFut,
    PFut: Future<Output = bool>,
{
    let mut probes: FuturesUnordered<_> = addresses
        .into_iter()
        .map(|address| {
            let probe = probe(address);
            async move {
                tokio::time::timeout(slice, probe)
                    .await
                    .unwrap_or(false)
                    .then_some(address)
            }
        })
        .collect();
    while let Some(result) = probes.next().await {
        if result.is_some() {
            return result;
        }
    }
    None
}

/// One Server probe burst for a peer: the peer's candidates one after another, up to
/// [`MAX_CANDIDATES`] and only those that pass the peer-claimed gate, and at the same time slice
/// [`walk_ring`] of the peer's order on its public addresses ([`walk_addresses`]); `burst` 0 walks
/// nothing and probes the candidates only (leaf BURST-1). Returns whether any probe completed. The walk probes are bounded by `slice` and run at once; a candidate probe
/// bounds itself, so the burst ends within `MAX_CANDIDATES` of those bounds.
/// cancel-safe: yes — a cancelled burst only drops its pending probes.
pub(crate) async fn server_burst<P, PFut>(
    peer_key: &[u8; 32],
    candidates: &[SocketAddr],
    burst: u32,
    slice: Duration,
    probe: P,
) -> bool
where
    P: Fn(SocketAddr) -> PFut,
    PFut: Future<Output = bool>,
{
    let listed = async {
        for candidate in candidates.iter().take(MAX_CANDIDATES) {
            if peer_claimed_probe_allowed(*candidate) && probe(*candidate).await {
                return true;
            }
        }
        false
    };
    let walked = async {
        if burst == 0 {
            return false;
        }
        let ring = walk_ring(burst);
        let addresses = walk_addresses(candidates, peer_key, ring);
        if addresses.is_empty() {
            return false;
        }
        let probed = addresses.len();
        let found = first_to_answer(addresses, slice, &probe).await.is_some();
        eprintln!("{}", scan_line("server", ring, probed, found));
        found
    };
    let (listed, walked) = tokio::join!(listed, walked);
    listed || walked
}

/// Dials `centre`. In an attempt that scans (`ring` from [`scan_ring`]), the centre and the slice
/// of the peer's ordered set are probed first (all at once, each bounded by [`SCAN_SLICE`]) and the
/// first address whose handshake completed is dialed; with none, the attempt ends with
/// [`NetworkError::Deadline`]. Outside a scanning attempt this is exactly `connect(centre)`.
/// cancel-safe: NO — the dial that follows a found address is not cancel-safe.
pub(crate) async fn scan_then_connect<T, P, PFut, C, CFut>(
    centre: SocketAddr,
    peer_key: &[u8; 32],
    ring: u32,
    probe: P,
    connect: C,
) -> Result<T, NetworkError>
where
    P: Fn(SocketAddr) -> PFut,
    PFut: Future<Output = bool>,
    C: FnOnce(SocketAddr) -> CFut,
    CFut: Future<Output = Result<T, NetworkError>>,
{
    let addresses = ring_addresses(centre, peer_key, ring);
    if addresses.is_empty() {
        return connect(centre).await;
    }
    let probed = addresses.len() + 1;
    let found = first_to_answer(std::iter::once(centre).chain(addresses), SCAN_SLICE, &probe).await;
    eprintln!("{}", scan_line("client", ring, probed, found.is_some()));
    match found {
        Some(address) => connect(address).await,
        None => Err(NetworkError::Deadline),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const KEY: [u8; 32] = [7; 32];

    fn public(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), port)
    }

    #[test]
    fn a_slice_is_the_next_ports_of_the_peers_order_on_the_peers_address() {
        let order = ports::order(&KEY);
        let first = ring_addresses(public(40_000), &KEY, 1);
        let expected: Vec<SocketAddr> = order[..SCAN_PORTS_PER_ATTEMPT]
            .iter()
            .map(|&port| public(port))
            .collect();
        assert_eq!(first, expected);
        let second = ring_addresses(public(40_000), &KEY, 2);
        assert_eq!(second[0], public(order[SCAN_PORTS_PER_ATTEMPT]));
        // Another peer key is another order.
        assert_ne!(ring_addresses(public(40_000), &[9; 32], 1), first);
    }

    #[test]
    fn rings_count_from_the_first_attempt_that_scanned_not_from_epoch_one() {
        let first = AtomicU32::new(0);
        assert_eq!(ring_after(&first, 2), 1);
        assert_eq!(ring_after(&first, 2), 1);
        assert_eq!(ring_after(&first, 3), 2);
        assert_eq!(ring_after(&first, 6), 5);
        assert!(ring_after(&first, 7) > SCAN_RINGS);
        // An epoch before the first answered one is no slice in range, so nothing is scanned.
        let earlier = ring_after(&first, 1);
        assert!(!(1..=SCAN_RINGS).contains(&earlier), "ring {earlier}");
        assert!(ring_addresses(public(40_000), &KEY, earlier).is_empty());
    }

    #[test]
    fn the_slices_of_all_attempts_tile_the_set_without_overlap() {
        let mut seen = std::collections::BTreeSet::new();
        for epoch in 1..=SCAN_RINGS {
            for address in ring_addresses(public(40_000), &KEY, epoch) {
                assert!(seen.insert(address.port()), "port probed twice: {address}");
            }
        }
        let whole: std::collections::BTreeSet<u16> = ports::PORTS.iter().copied().collect();
        assert_eq!(
            seen, whole,
            "after the last slice every port of the set was probed once"
        );
    }

    #[test]
    fn the_port_of_the_centre_is_not_probed_a_second_time() {
        let order = ports::order(&KEY);
        let centre = public(order[3]);
        let slice = ring_addresses(centre, &KEY, 1);
        assert_eq!(slice.len(), SCAN_PORTS_PER_ATTEMPT - 1);
        assert!(!slice.contains(&centre));
    }

    #[test]
    fn nothing_is_scanned_outside_the_scanning_attempts_or_on_a_non_public_address() {
        assert!(ring_addresses(public(40_000), &KEY, 0).is_empty());
        assert!(ring_addresses(public(40_000), &KEY, SCAN_RINGS + 1).is_empty());
        for text in [
            "10.0.0.5",
            "192.168.1.9",
            "172.16.3.4",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.7.7",
            "100.127.255.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            let centre = SocketAddr::new(text.parse().unwrap(), 40_000);
            assert!(ring_addresses(centre, &KEY, 1).is_empty(), "{text}");
        }
        let v6 = SocketAddr::new("2001:db8::1".parse().unwrap(), 40_000);
        assert!(ring_addresses(v6, &KEY, 1).is_empty());
        assert!(ring_addresses(SocketAddr::new(public(1).ip(), 0), &KEY, 1).is_empty());
        let mapped = SocketAddr::new("::ffff:203.0.113.7".parse().unwrap(), 40_000);
        assert_eq!(
            ring_addresses(mapped, &KEY, 1).len(),
            SCAN_PORTS_PER_ATTEMPT
        );
        let outside = SocketAddr::new("100.128.0.1".parse().unwrap(), 40_000);
        assert_eq!(
            ring_addresses(outside, &KEY, 1).len(),
            SCAN_PORTS_PER_ATTEMPT
        );
    }

    #[test]
    fn the_trace_line_carries_counts_and_a_verdict_only() {
        assert_eq!(
            scan_line("client", 3, 21, false),
            "shaar: client punch scan ring=3 probed=21 found=no"
        );
        assert_eq!(
            scan_line("server", 1, 40, true),
            "shaar: server punch scan ring=1 probed=40 found=yes"
        );
    }

    fn at(host: &str, port: u16) -> SocketAddr {
        SocketAddr::new(host.parse().unwrap(), port)
    }

    // Ports below the set (it starts at 30000), so a candidate never collides with a walked port.
    const OFF_SET: u16 = 20_001;

    #[test]
    fn the_burst_number_turns_the_slices_round_and_round() {
        let rings: Vec<u32> = (1..=7).map(walk_ring).collect();
        assert_eq!(rings, [1, 2, 3, 4, 5, 1, 2]);
        assert_eq!(walk_ring(0), 1);
        assert!((1..=SCAN_RINGS).contains(&walk_ring(u32::MAX)));
    }

    #[test]
    fn a_walk_covers_the_slice_on_the_first_two_public_hosts_of_the_candidates() {
        let candidates = [
            at("192.168.1.5", OFF_SET),
            at("203.0.113.7", OFF_SET + 1),
            at("203.0.113.7", OFF_SET + 2),
            at("198.51.100.9", OFF_SET + 3),
            at("192.0.2.77", OFF_SET + 4),
        ];
        let order = ports::order(&KEY);
        let slice = &order[..SCAN_PORTS_PER_ATTEMPT];
        let expected: Vec<SocketAddr> = ["203.0.113.7", "198.51.100.9"]
            .iter()
            .flat_map(|host| slice.iter().map(move |&port| at(host, port)))
            .collect();
        assert_eq!(walk_addresses(&candidates, &KEY, 1), expected);
    }

    #[test]
    fn a_walk_leaves_out_the_ports_of_the_candidates_and_other_slices_are_other_ports() {
        let order = ports::order(&KEY);
        let candidates = [at("203.0.113.7", order[2])];
        let first = walk_addresses(&candidates, &KEY, 1);
        assert_eq!(first.len(), SCAN_PORTS_PER_ATTEMPT - 1);
        assert!(!first.contains(&candidates[0]));
        let second = walk_addresses(&candidates, &KEY, 2);
        assert_eq!(second[0], at("203.0.113.7", order[SCAN_PORTS_PER_ATTEMPT]));
    }

    #[test]
    fn nothing_is_walked_without_a_public_candidate_or_outside_the_slices() {
        let private = [at("192.168.1.5", OFF_SET), at("10.0.0.2", OFF_SET + 1)];
        assert!(walk_addresses(&private, &KEY, 1).is_empty());
        assert!(walk_addresses(&[], &KEY, 1).is_empty());
        assert!(walk_addresses(&[at("203.0.113.7", OFF_SET)], &KEY, SCAN_RINGS + 1).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn the_first_probe_that_completes_names_the_address() {
        let wanted = at("203.0.113.7", 31_000);
        let found = first_to_answer(
            [at("203.0.113.7", 30_999), wanted, at("203.0.113.7", 31_001)],
            SCAN_SLICE,
            &|address| async move { address == wanted },
        )
        .await;
        assert_eq!(found, Some(wanted));
    }

    #[tokio::test(start_paused = true)]
    async fn silent_probes_end_at_their_bound_with_no_address() {
        let started = tokio::time::Instant::now();
        let found = first_to_answer(
            [at("203.0.113.7", 31_000), at("203.0.113.7", 31_001)],
            SCAN_SLICE,
            &|_| std::future::pending::<bool>(),
        )
        .await;
        assert_eq!(found, None);
        let elapsed = started.elapsed();
        assert!(
            elapsed >= SCAN_SLICE && elapsed < SCAN_SLICE * 2,
            "{elapsed:?}"
        );
        assert_eq!(
            first_to_answer([], SCAN_SLICE, &|_| async { true }).await,
            None
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_walks_the_slice_while_the_candidates_are_tried_one_by_one() {
        let walked_port = ports::order(&KEY)[3];
        let seen = std::sync::Mutex::new(Vec::new());
        let completed = server_burst(
            &KEY,
            &[at("203.0.113.7", OFF_SET), at("198.51.100.9", OFF_SET + 1)],
            1,
            SCAN_SLICE,
            |address| {
                seen.lock().unwrap().push(address);
                async move { address.port() == walked_port }
            },
        )
        .await;
        assert!(completed, "a walked port answered");
        let seen = seen.lock().unwrap();
        for candidate in [at("203.0.113.7", OFF_SET), at("198.51.100.9", OFF_SET + 1)] {
            assert!(seen.contains(&candidate), "candidate probed: {candidate}");
        }
        assert_eq!(seen.len(), 2 + 2 * SCAN_PORTS_PER_ATTEMPT);
    }

    /// Leaf BURST-1: burst number 0 is the burst without a walk, the candidates are still probed.
    #[tokio::test(start_paused = true)]
    async fn burst_zero_probes_the_candidates_and_walks_nothing() {
        let seen = std::sync::Mutex::new(Vec::new());
        let completed = server_burst(
            &KEY,
            &[at("203.0.113.7", OFF_SET), at("198.51.100.9", OFF_SET + 1)],
            0,
            SCAN_SLICE,
            |address| {
                seen.lock().unwrap().push(address);
                async { false }
            },
        )
        .await;
        assert!(!completed);
        assert_eq!(
            *seen.lock().unwrap(),
            [at("203.0.113.7", OFF_SET), at("198.51.100.9", OFF_SET + 1)]
        );
        let answering = server_burst(
            &KEY,
            &[at("203.0.113.7", OFF_SET)],
            0,
            SCAN_SLICE,
            |address| async move { address.port() == OFF_SET },
        )
        .await;
        assert!(answering, "the listed candidate answered without a walk");
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_that_hears_nothing_is_bounded_and_one_candidate_alone_still_counts() {
        let started = tokio::time::Instant::now();
        let none = server_burst(
            &KEY,
            &[at("203.0.113.7", OFF_SET)],
            2,
            SCAN_SLICE,
            |_| async { false },
        )
        .await;
        assert!(!none);
        let only_candidate = server_burst(
            &KEY,
            &[at("203.0.113.7", OFF_SET), at("192.168.1.5", OFF_SET + 1)],
            3,
            SCAN_SLICE,
            |address| async move { address.port() == OFF_SET },
        )
        .await;
        assert!(only_candidate, "the listed candidate answered");
        assert!(started.elapsed() < SCAN_SLICE * 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_never_probes_a_special_range_candidate_nor_walks_a_private_host() {
        let seen = std::sync::Mutex::new(Vec::new());
        let completed = server_burst(
            &KEY,
            &[at("169.254.1.1", OFF_SET), at("192.168.1.5", OFF_SET + 1)],
            1,
            SCAN_SLICE,
            |address| {
                seen.lock().unwrap().push(address);
                async { false }
            },
        )
        .await;
        assert!(!completed);
        // Only the private candidate itself was probed: the link-local one is gated out and a
        // private host is never walked.
        assert_eq!(*seen.lock().unwrap(), [at("192.168.1.5", OFF_SET + 1)]);
    }

    #[tokio::test]
    async fn outside_a_scanning_attempt_the_centre_is_dialed_without_any_probe() {
        let probes = AtomicUsize::new(0);
        let dialed = scan_then_connect(
            public(40_000),
            &KEY,
            SCAN_RINGS + 1,
            |_| {
                probes.fetch_add(1, Ordering::SeqCst);
                async { false }
            },
            |address| async move { Ok::<_, NetworkError>(address) },
        )
        .await;
        assert_eq!(dialed.unwrap(), public(40_000));
        assert_eq!(probes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn the_address_whose_probe_completes_is_the_one_that_is_dialed() {
        let probes = AtomicUsize::new(0);
        let real = public(ports::order(&KEY)[7]);
        let dialed = scan_then_connect(
            public(40_000),
            &KEY,
            1,
            |address| {
                probes.fetch_add(1, Ordering::SeqCst);
                async move { address == real }
            },
            |address| async move { Ok::<_, NetworkError>(address) },
        )
        .await;
        assert_eq!(dialed.unwrap(), real);
        assert_eq!(probes.load(Ordering::SeqCst), SCAN_PORTS_PER_ATTEMPT + 1);
    }

    #[tokio::test]
    async fn a_centre_that_answers_is_dialed_in_the_scanning_attempt_too() {
        let dialed = scan_then_connect(
            public(40_000),
            &KEY,
            1,
            |address| async move { address == public(40_000) },
            |address| async move { Ok::<_, NetworkError>(address) },
        )
        .await;
        assert_eq!(dialed.unwrap(), public(40_000));
    }

    #[tokio::test]
    async fn a_scan_that_finds_nothing_ends_typed_within_one_slice_and_never_dials() {
        let started = tokio::time::Instant::now();
        let dialed: Result<SocketAddr, NetworkError> = scan_then_connect(
            public(40_000),
            &KEY,
            1,
            |_| std::future::pending::<bool>(),
            |_| async { panic!("no address was found: nothing may be dialed") },
        )
        .await;
        assert!(matches!(dialed, Err(NetworkError::Deadline)));
        let elapsed = started.elapsed();
        assert!(
            elapsed >= SCAN_SLICE && elapsed < SCAN_SLICE * 4,
            "{elapsed:?}"
        );
    }

    #[tokio::test]
    async fn a_failed_dial_of_the_found_address_is_reported_as_it_is() {
        let dialed: Result<SocketAddr, NetworkError> = scan_then_connect(
            public(40_000),
            &KEY,
            2,
            |_| async { true },
            |_| async { Err(NetworkError::Closed) },
        )
        .await;
        assert!(matches!(dialed, Err(NetworkError::Closed)));
    }
}
