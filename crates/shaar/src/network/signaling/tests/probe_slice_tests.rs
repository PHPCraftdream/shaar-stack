//! Leaf BURST-2: what a probe of a slice of addresses puts on the wire. The silent addresses are
//! loopback sockets that never answer, so every datagram the prober sends to them is counted.

use super::*;
use std::time::Duration;
use tokio::{net::UdpSocket, sync::oneshot};

/// Addresses of one slice, as many as one slice of the walk holds.
const SLICE: usize = 20;
/// What one silent address may receive during one slice probe: the first flight and room for one
/// transport probe of the path. A probe per address sent about `SLICE` datagrams to each.
const PER_ADDRESS_MAX: usize = 4;

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn public(identity: &Identity) -> PublicKey {
    identity.transport_key().public()
}

async fn silent_sockets(count: usize) -> Vec<UdpSocket> {
    let mut sockets = Vec::with_capacity(count);
    for _ in 0..count {
        sockets.push(UdpSocket::bind(loopback()).await.unwrap());
    }
    sockets
}

fn addresses_of(sockets: &[UdpSocket]) -> Vec<SocketAddr> {
    sockets
        .iter()
        .map(|socket| socket.local_addr().unwrap())
        .collect()
}

/// The datagrams that reached `socket`, taken out of its queue.
fn drained(socket: &UdpSocket) -> usize {
    let mut buffer = [0_u8; 2048];
    let mut count = 0;
    while socket.try_recv_from(&mut buffer).is_ok() {
        count += 1;
    }
    count
}

async fn prober() -> SignaledEndpoint {
    SignaledEndpoint::bind(
        &Identity::generate(),
        loopback(),
        loopback(),
        &[],
        Limits::default(),
    )
    .await
    .unwrap()
}

/// The contract of the leaf: one probe of a slice reaches every address of it and costs about one
/// flight per address, not one flight per address per probe.
#[tokio::test]
async fn a_slice_probe_reaches_every_silent_address_with_about_one_flight() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let endpoint = prober().await;
        let sockets = silent_sockets(SLICE).await;
        let answered = endpoint
            .probe_handle()
            .probe_any(public(&Identity::generate()), addresses_of(&sockets))
            .await;
        assert_eq!(answered, None, "no silent address answers");
        let counts: Vec<usize> = sockets.iter().map(drained).collect();
        assert!(
            counts.iter().all(|&count| count >= 1),
            "every address of the slice is covered: {counts:?}"
        );
        assert!(
            counts.iter().all(|&count| count <= PER_ADDRESS_MAX),
            "about one flight per address: {counts:?}"
        );
        endpoint.close().await.unwrap();
    })
    .await
    .expect("slice probe deadline");
}

/// The measurement behind finding DIAG-1: the same addresses probed one connect each, all at once
/// (the walk before this leaf) cost many times more datagrams, because the connects to one peer
/// key share one set of paths and each sends its flight to all of them.
#[tokio::test]
async fn one_probe_per_address_costs_many_times_the_datagrams_of_one_probe_per_slice() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let endpoint = prober().await;
        let probes = endpoint.probe_handle();
        let peer = public(&Identity::generate());
        let sliced = silent_sockets(SLICE).await;
        probes.probe_any(peer, addresses_of(&sliced)).await;
        let sliced_total: usize = sliced.iter().map(drained).sum();

        let singles = silent_sockets(SLICE).await;
        let other_peer = public(&Identity::generate());
        futures::future::join_all(
            addresses_of(&singles)
                .into_iter()
                .map(|address| probes.probe_any(other_peer, vec![address])),
        )
        .await;
        let singles_total: usize = singles.iter().map(drained).sum();
        assert!(
            singles_total >= 3 * sliced_total,
            "one probe per address sent {singles_total} datagrams, one probe per slice {sliced_total}"
        );
        endpoint.close().await.unwrap();
    })
    .await
    .expect("fan-out measurement deadline");
}

/// The address that answers is the one named, among silent ones, and the handle names it in the
/// form it was offered.
#[tokio::test]
async fn the_address_that_answered_is_named_among_silent_ones() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let server_identity = Identity::generate();
        let mut server = SignaledEndpoint::bind(
            &server_identity,
            loopback(),
            loopback(),
            &[],
            Limits::default(),
        )
        .await
        .unwrap();
        let wanted = server.local_addr();
        let (stop, stopped) = oneshot::channel::<()>();
        let responder = tokio::spawn(async move {
            tokio::select! {
                () = async { loop { let _ = server.accept().await; } } => {}
                _ = stopped => {}
            }
            server.close().await.unwrap();
        });

        let endpoint = prober().await;
        let sockets = silent_sockets(SLICE).await;
        let mut offered = addresses_of(&sockets);
        offered.insert(SLICE / 2, wanted);
        let answered = endpoint
            .probe_handle()
            .probe_any(public(&server_identity), offered)
            .await;
        assert_eq!(answered, Some(wanted));
        endpoint.close().await.unwrap();
        let _ = stop.send(());
        responder.await.unwrap();
    })
    .await
    .expect("answering address deadline");
}

#[tokio::test]
async fn a_slice_with_no_dialable_address_is_not_probed() {
    let endpoint = prober().await;
    let probes = endpoint.probe_handle();
    let peer = public(&Identity::generate());
    let refused = vec![
        "0.0.0.0:40000".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
        "224.0.0.1:40000".parse().unwrap(),
    ];
    let started = tokio::time::Instant::now();
    assert_eq!(probes.probe_any(peer, refused).await, None);
    assert_eq!(probes.probe_any(peer, Vec::new()).await, None);
    assert!(
        started.elapsed() < Duration::from_millis(250),
        "refused addresses cost no connect: {:?}",
        started.elapsed()
    );
    endpoint.close().await.unwrap();
}
