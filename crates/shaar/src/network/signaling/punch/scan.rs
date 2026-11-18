//! Bounded port scan around an answered public candidate (leaf NAT-2, owner decision of
//! 2026-11-18). A NAT that rewrites the source port leaves the Client without the peer's real
//! QUIC port; the port the DHT nodes saw for the peer's Mainline socket is a sample of the same
//! carrier port block, so the real port is probed in rings of growing distance around it. A
//! probe is the slotless QUIC handshake of [`crate::network::admission::ProbeHandle`]; the first
//! one that completes names the address and the ordinary dial follows.

use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use futures::{StreamExt, stream::FuturesUnordered};

use crate::network::NetworkError;

/// Ports probed on each side of the centre by one attempt.
pub(crate) const SCAN_RING_WIDTH: u16 = 24;
/// Rings scanned: ring `r` lies at distance `(r-1)*WIDTH+1 ..= r*WIDTH`.
pub(crate) const SCAN_RINGS: u32 = 10;
/// Bound of one probe: below one QUIC initial retransmission, so one datagram of about 1.2 KB.
pub(crate) const SCAN_SLICE: Duration = Duration::from_millis(300);
/// Most scan addresses one attempt probes next to the centre.
pub(crate) const SCAN_PORTS_PER_ATTEMPT: usize = 2 * SCAN_RING_WIDTH as usize;

/// Whether an address may be the centre of a scan: a public IPv4 address. Private, loopback,
/// link-local, shared (100.64/10), unspecified, multicast and broadcast addresses are never
/// scanned; a mapped IPv6 address counts as its IPv4 form, other IPv6 addresses are not scanned.
fn scan_centre(address: SocketAddr) -> bool {
    // Test builds also scan loopback: the only address two local endpoints share.
    #[cfg(test)]
    if address.ip().to_canonical().is_loopback() {
        return address.port() != 0;
    }
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

/// The ring of the attempt with punch epoch `epoch`: the first attempt that reaches a scan (one
/// that received an Answer) is ring 1, the next ring 2, and so on. Counting from the first
/// answered attempt, not from epoch 1, keeps the nearest ring from being lost to attempts that
/// never got an Answer; one attempt has one ring however many candidates it scans.
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

/// The scan addresses of ring `ring` around `centre`, nearest first, both sides of a distance
/// together; empty outside rings `1..=SCAN_RINGS` or for a centre that is not scannable. Ports
/// outside `1..=65535` are skipped.
pub(crate) fn ring_addresses(centre: SocketAddr, ring: u32) -> Vec<SocketAddr> {
    if !(1..=SCAN_RINGS).contains(&ring) || !scan_centre(centre) {
        return Vec::new();
    }
    let width = u32::from(SCAN_RING_WIDTH);
    let port = i64::from(centre.port());
    let mut addresses = Vec::with_capacity(SCAN_PORTS_PER_ATTEMPT);
    for distance in ((ring - 1) * width + 1)..=(ring * width) {
        for candidate in [port + i64::from(distance), port - i64::from(distance)] {
            match u16::try_from(candidate) {
                Ok(candidate) if candidate != 0 => {
                    addresses.push(SocketAddr::new(centre.ip(), candidate));
                }
                _ => {}
            }
        }
    }
    addresses
}

/// The counts-only trace line of one scan.
pub(crate) fn scan_line(ring: u32, probed: usize, found: bool) -> String {
    format!(
        "shaar: client punch scan ring={ring} probed={probed} found={}",
        if found { "yes" } else { "no" }
    )
}

/// Dials `centre`. In an attempt that scans (`ring` from [`scan_ring`]), the centre and its ring
/// are probed first (all at once, each bounded by [`SCAN_SLICE`]) and the first probe that
/// completed names the address that answered, which is dialed; with none, the attempt ends with
/// [`NetworkError::Deadline`]. A probe returns the address that answered, which need not be the
/// one it was given: the backend dials a peer by key through any address it knows, so with many
/// probes in flight a probe of a dead port can complete through the live one. Outside a scanning
/// attempt this is exactly `connect(centre)`.
/// cancel-safe: NO — the dial that follows a found address is not cancel-safe.
pub(crate) async fn scan_then_connect<T, P, PFut, C, CFut>(
    centre: SocketAddr,
    ring: u32,
    probe: P,
    connect: C,
) -> Result<T, NetworkError>
where
    P: Fn(SocketAddr) -> PFut,
    PFut: Future<Output = Option<SocketAddr>>,
    C: FnOnce(SocketAddr) -> CFut,
    CFut: Future<Output = Result<T, NetworkError>>,
{
    scan_within(SCAN_SLICE, centre, ring, probe, connect).await
}

/// [`scan_then_connect`] with an explicit bound per probe (a real-endpoint test runs on loaded
/// CI machines where one slice is too tight for 49 simultaneous handshakes).
pub(super) async fn scan_within<T, P, PFut, C, CFut>(
    slice: Duration,
    centre: SocketAddr,
    ring: u32,
    probe: P,
    connect: C,
) -> Result<T, NetworkError>
where
    P: Fn(SocketAddr) -> PFut,
    PFut: Future<Output = Option<SocketAddr>>,
    C: FnOnce(SocketAddr) -> CFut,
    CFut: Future<Output = Result<T, NetworkError>>,
{
    let addresses = ring_addresses(centre, ring);
    if addresses.is_empty() {
        return connect(centre).await;
    }
    let probed = addresses.len() + 1;
    let mut probes: FuturesUnordered<_> = std::iter::once(centre)
        .chain(addresses)
        .map(|address| {
            let probe = probe(address);
            async move { tokio::time::timeout(slice, probe).await.ok().flatten() }
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

    fn public(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), port)
    }

    #[test]
    fn a_ring_covers_the_distances_of_its_attempt_on_both_sides_nearest_first() {
        let ring = ring_addresses(public(40_000), 1);
        assert_eq!(ring.len(), SCAN_PORTS_PER_ATTEMPT);
        assert_eq!(ring[0], public(40_001));
        assert_eq!(ring[1], public(39_999));
        assert_eq!(ring[ring.len() - 2], public(40_024));
        assert_eq!(ring[ring.len() - 1], public(39_976));
        let second = ring_addresses(public(40_000), 2);
        assert_eq!(second[0], public(40_025));
        assert_eq!(second[1], public(39_975));
    }

    #[test]
    fn rings_count_from_the_first_attempt_that_scanned_not_from_epoch_one() {
        let first = AtomicU32::new(0);
        assert_eq!(ring_after(&first, 2), 1);
        assert_eq!(ring_after(&first, 2), 1);
        assert_eq!(ring_after(&first, 3), 2);
        assert_eq!(ring_after(&first, 11), 10);
        assert!(ring_after(&first, 12) > SCAN_RINGS);
        // An epoch before the first answered one is no ring in range, so nothing is scanned.
        let earlier = ring_after(&first, 1);
        assert!(!(1..=SCAN_RINGS).contains(&earlier), "ring {earlier}");
        assert!(ring_addresses(public(40_000), earlier).is_empty());
    }

    #[test]
    fn the_rings_of_all_attempts_tile_the_window_without_overlap() {
        let mut seen = std::collections::BTreeSet::new();
        for epoch in 1..=SCAN_RINGS {
            for address in ring_addresses(public(40_000), epoch) {
                assert!(seen.insert(address.port()), "port probed twice: {address}");
            }
        }
        let distance = u16::try_from(SCAN_RINGS).unwrap() * SCAN_RING_WIDTH;
        assert_eq!(seen.len(), 2 * usize::from(distance));
        assert!(seen.contains(&(40_000 - distance)) && seen.contains(&(40_000 + distance)));
    }

    #[test]
    fn ports_outside_the_valid_range_are_skipped() {
        let low = ring_addresses(public(10), 1);
        assert!(low.iter().all(|address| address.port() >= 1));
        assert_eq!(low.len(), SCAN_PORTS_PER_ATTEMPT - (24 - 9));
        let high = ring_addresses(public(65_530), 1);
        assert!(high.iter().all(|address| address.port() >= 1));
        assert_eq!(high.len(), SCAN_PORTS_PER_ATTEMPT - (24 - 5));
    }

    #[test]
    fn nothing_is_scanned_outside_the_scanning_attempts_or_around_a_non_public_centre() {
        assert!(ring_addresses(public(40_000), 0).is_empty());
        assert!(ring_addresses(public(40_000), SCAN_RINGS + 1).is_empty());
        // Loopback is scanned in test builds only (see `scan_centre`), so it is not listed.
        for text in [
            "10.0.0.5",
            "192.168.1.9",
            "172.16.3.4",
            "169.254.1.1",
            "100.64.7.7",
            "100.127.255.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            let centre = SocketAddr::new(text.parse().unwrap(), 40_000);
            assert!(ring_addresses(centre, 1).is_empty(), "{text}");
        }
        let v6 = SocketAddr::new("2001:db8::1".parse().unwrap(), 40_000);
        assert!(ring_addresses(v6, 1).is_empty());
        assert!(ring_addresses(SocketAddr::new(public(1).ip(), 0), 1).is_empty());
        let mapped = SocketAddr::new("::ffff:203.0.113.7".parse().unwrap(), 40_000);
        assert_eq!(ring_addresses(mapped, 1).len(), SCAN_PORTS_PER_ATTEMPT);
        let outside = SocketAddr::new("100.128.0.1".parse().unwrap(), 40_000);
        assert_eq!(ring_addresses(outside, 1).len(), SCAN_PORTS_PER_ATTEMPT);
    }

    #[test]
    fn the_trace_line_carries_counts_and_a_verdict_only() {
        assert_eq!(
            scan_line(3, 49, false),
            "shaar: client punch scan ring=3 probed=49 found=no"
        );
        assert_eq!(
            scan_line(1, 49, true),
            "shaar: client punch scan ring=1 probed=49 found=yes"
        );
    }

    #[tokio::test]
    async fn outside_a_scanning_attempt_the_centre_is_dialed_without_any_probe() {
        let probes = AtomicUsize::new(0);
        let dialed = scan_then_connect(
            public(40_000),
            SCAN_RINGS + 1,
            |_| {
                probes.fetch_add(1, Ordering::SeqCst);
                async { None::<SocketAddr> }
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
        let real = public(40_017);
        let dialed = scan_then_connect(
            public(40_000),
            1,
            |address| {
                probes.fetch_add(1, Ordering::SeqCst);
                async move { (address == real).then_some(address) }
            },
            |address| async move { Ok::<_, NetworkError>(address) },
        )
        .await;
        assert_eq!(dialed.unwrap(), real);
        assert_eq!(probes.load(Ordering::SeqCst), SCAN_PORTS_PER_ATTEMPT + 1);
    }

    /// Regression (CI run 44252966182): the backend dials a peer by key through any address it
    /// knows, so the probe of a dead port completed through the live one and the scan dialed the
    /// dead port. The address that answered is dialed, whatever address the probe was given.
    #[tokio::test]
    async fn the_address_that_answered_is_dialed_not_the_one_that_was_probed() {
        let real = public(40_017);
        let dialed = scan_then_connect(
            public(40_000),
            1,
            |_| async move { Some(real) },
            |address| async move { Ok::<_, NetworkError>(address) },
        )
        .await;
        assert_eq!(dialed.unwrap(), real);
    }

    #[tokio::test]
    async fn a_centre_that_answers_is_dialed_in_the_scanning_attempt_too() {
        let dialed = scan_then_connect(
            public(40_000),
            1,
            |address| async move { (address == public(40_000)).then_some(address) },
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
            1,
            |_| std::future::pending::<Option<SocketAddr>>(),
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
            2,
            |address| async move { Some(address) },
            |_| async { Err(NetworkError::Closed) },
        )
        .await;
        assert!(matches!(dialed, Err(NetworkError::Closed)));
    }
}
