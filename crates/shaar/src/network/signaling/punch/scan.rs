//! Walk over the key-ordered port set of the peer (leaf SET-1, owner decision of 2026-11-18, which
//! replaced the ring scan of leaf NAT-2). A peer that could not tell its port, or whose port was
//! moved by a router mapping, still uses a port of the fixed set ([`crate::network::ports`]), and
//! the order in which it prefers them is a function of its own public key, which this side knows. So
//! the ports of the peer's set are probed on the peer's public address in that order, in slices of
//! [`SCAN_PORTS_PER_ATTEMPT`], one slice per attempt; nothing else is tried. A probe is the slotless
//! QUIC handshake of [`crate::network::admission::ProbeHandle`]; the first one that completes names
//! the address and the ordinary dial follows.

use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use futures::{StreamExt, stream::FuturesUnordered};

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
pub(crate) fn scan_line(ring: u32, probed: usize, found: bool) -> String {
    format!(
        "shaar: client punch scan ring={ring} probed={probed} found={}",
        if found { "yes" } else { "no" }
    )
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
    let mut probes: FuturesUnordered<_> = std::iter::once(centre)
        .chain(addresses)
        .map(|address| {
            let probe = probe(address);
            async move {
                tokio::time::timeout(SCAN_SLICE, probe)
                    .await
                    .unwrap_or(false)
                    .then_some(address)
            }
        })
        .collect();
    let mut found = None;
    while let Some(result) = probes.next().await {
        if result.is_some() {
            found = result;
            break;
        }
    }
    drop(probes);
    eprintln!("{}", scan_line(ring, probed, found.is_some()));
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
            scan_line(3, 21, false),
            "shaar: client punch scan ring=3 probed=21 found=no"
        );
        assert_eq!(
            scan_line(1, 21, true),
            "shaar: client punch scan ring=1 probed=21 found=yes"
        );
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
