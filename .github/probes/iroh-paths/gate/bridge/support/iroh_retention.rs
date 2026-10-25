#![forbid(unsafe_code)]

//! Exercises native retention through the real Iroh path actor and fixed APP gate.

use std::{
    net::SocketAddr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use futures_lite::StreamExt;
use iroh::{
    Endpoint, EndpointAddr, SecretKey, TransportAddr,
    address_lookup::memory::MemoryLookup,
    endpoint::{
        Connection, PathEvent, PathEventStream, QuicTransportConfig, presets,
        transports::{FourTuple, PathSelection, PathSelectionContext, PathSelector},
    },
};
use iroh_paths_probe::{MemTransport, harness, qlog_oracle};
use noq::PathId;

use super::mixed_fixture::native_only;

#[derive(Debug, Default)]
struct FixtureSelector {
    prefer_ipv6: AtomicBool,
}

impl PathSelector for FixtureSelector {
    fn select(&self, context: &PathSelectionContext<'_>) -> PathSelection {
        let mut selected = PathSelection::none();
        let prefer_ipv6 = self.prefer_ipv6.load(Ordering::SeqCst);
        for candidate in context.paths() {
            let wanted = match candidate.network_path() {
                FourTuple::Custom { .. } => !prefer_ipv6,
                FourTuple::Ip { remote, .. } => prefer_ipv6 && remote.ip().to_canonical().is_ipv6(),
                _ => false,
            };
            if wanted {
                selected.set(&candidate);
                break;
            }
        }
        selected
    }
}

/// cancel-safe: NO — the outer deadline terminates the fixture, not a bind retry.
async fn bind(
    key: SecretKey,
    transport: Arc<MemTransport>,
    lookup: MemoryLookup,
    directory: &Path,
    prefix: &str,
    selector: Arc<FixtureSelector>,
) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .alpns(vec![harness::ALPN.to_vec()])
        .address_lookup(lookup)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .expect("IPv4 loopback configuration")
        .bind_addr("[::1]:0")
        .expect("IPv6 loopback configuration")
        .add_custom_transport(transport)
        // Test-only selection makes pruning independent of RTT and scheduling.
        .path_selector(selector)
        .transport_config(
            QuicTransportConfig::builder()
                .application_data_filter(native_only)
                .spike_disable_nat_traversal()
                .send_observed_address_reports(false)
                .receive_observed_address_reports(false)
                .qlog_from_path(directory, prefix)
                .build(),
        )
        .bind()
        .await
        .expect("bind dual-loopback retention endpoint")
}

fn native_address(endpoint: &Endpoint, ipv6: bool) -> SocketAddr {
    endpoint
        .bound_sockets()
        .into_iter()
        .find(|address| address.is_ipv6() == ipv6 && address.ip().is_loopback())
        .expect("owned native loopback socket")
}

fn matches_native(actual: &TransportAddr, expected: SocketAddr) -> bool {
    matches!(actual, TransportAddr::Ip(address)
        if address.ip().to_canonical() == expected.ip().to_canonical()
            && address.port() == expected.port())
}

fn assert_retained(connection: &Connection, retained: PathId, remote: SocketAddr) {
    let paths = connection.paths();
    let path = paths
        .get(retained)
        .expect("exact retained ID still established");
    assert!(matches_native(path.remote_addr(), remote));
    assert!(
        !path.is_selected(),
        "retained A remains the non-selected native path"
    );
    assert!(connection.close_reason().is_none());
}

fn assert_selected(connection: &Connection, selected: PathId, remote: SocketAddr) {
    let paths = connection.paths();
    let path = paths.get(selected).expect("selected native ID established");
    assert!(path.is_selected());
    assert!(matches_native(path.remote_addr(), remote));
    assert!(!harness::custom_path_selected(connection));
}

/// cancel-safe: YES — snapshots are observations, not admission operations.
async fn await_established(connection: &Connection, id: PathId, remote: SocketAddr) {
    let mut snapshots = connection.paths_stream();
    loop {
        tokio::select! {
            error = connection.closed() => panic!("connection closed before establishment: {error:?}"),
            snapshot = snapshots.next() => {
                let snapshot = snapshot.expect("path snapshots remain open");
                if let Some(path) = snapshot.get(id) {
                    assert!(matches_native(path.remote_addr(), remote));
                    return;
                }
            }
        }
    }
}

/// cancel-safe: NO — the outer deadline fails the fixture without replaying events.
async fn await_competitor_pruned(
    connection: &Connection,
    events: &mut PathEventStream,
    protected: &[PathId],
    competing: PathId,
    remote: SocketAddr,
    selected_native: Option<PathId>,
) {
    let mut opened = false;
    loop {
        tokio::select! {
            error = connection.closed() => panic!("connection closed before pruning: {error:?}"),
            event = events.next() => match event.expect("path event stream remains open") {
                PathEvent::Opened { id, remote_addr, .. } => {
                    if id == competing {
                        assert!(matches_native(&remote_addr, remote));
                        opened = true;
                    }
                }
                PathEvent::Closed { id, .. } => {
                    assert!(!protected.contains(&id), "actor pruned protected path {id:?}");
                    if id == competing {
                        assert!(opened, "competitor must reach the normal Established actor handler");
                        return;
                    }
                    panic!("unexpected path closed: {id:?}");
                }
                PathEvent::Selected { id, remote_addr, .. } => {
                    if let Some(expected) = selected_native {
                        assert_eq!(id, expected);
                    } else {
                        assert!(matches!(remote_addr, TransportAddr::Custom(_)));
                    }
                }
                PathEvent::Lagged { missed, .. } => panic!("lost {missed} actor path events"),
                other => panic!("unexpected actor path event: {other:?}"),
            }
        }
    }
}

/// cancel-safe: NO — the outer deadline fails the fixture without replaying events.
async fn await_native_selected(
    connection: &Connection,
    events: &mut PathEventStream,
    retained: PathId,
    selected: PathId,
    remote: SocketAddr,
) {
    let mut opened = false;
    loop {
        tokio::select! {
            error = connection.closed() => panic!("connection closed before selection: {error:?}"),
            event = events.next() => match event.expect("path event stream remains open") {
                PathEvent::Opened { id, remote_addr, .. } => {
                    if id == selected {
                        assert!(matches_native(&remote_addr, remote));
                        opened = true;
                    }
                }
                PathEvent::Selected { id, remote_addr, .. } => {
                    assert_eq!(id, selected);
                    assert!(matches_native(&remote_addr, remote));
                    assert!(opened, "selection follows the actual Established handler");
                    return;
                }
                PathEvent::Closed { id, .. } => {
                    assert_ne!(id, retained, "actor pruned retained A while selecting C");
                    panic!("unexpected path closed before selection: {id:?}");
                }
                PathEvent::Lagged { missed, .. } => panic!("lost {missed} actor path events"),
                other => panic!("unexpected actor path event: {other:?}"),
            }
        }
    }
}

/// cancel-safe: NO — partial application traffic is never retried by this fixture.
async fn exchange(client: &Connection, server: &Connection) {
    const PAYLOAD: &[u8] = b"retained native path carries application bytes";
    let request = async {
        let (mut send, mut receive) = client.open_bi().await.expect("open native request");
        send.write_all(PAYLOAD).await.expect("write native request");
        send.finish().expect("finish native request");
        assert_eq!(
            receive
                .read_to_end(PAYLOAD.len())
                .await
                .expect("read native echo"),
            PAYLOAD
        );
        client
            .send_datagram(PAYLOAD.to_vec().into())
            .expect("send native datagram");
        assert_eq!(
            client.read_datagram().await.expect("receive datagram echo"),
            PAYLOAD
        );
    };
    let response = async {
        let (mut send, mut receive) = server.accept_bi().await.expect("accept native request");
        let bytes = receive
            .read_to_end(PAYLOAD.len())
            .await
            .expect("read native request");
        assert_eq!(bytes, PAYLOAD);
        send.write_all(&bytes).await.expect("write native echo");
        send.finish().expect("finish native echo");
        let datagram = server
            .read_datagram()
            .await
            .expect("receive native datagram");
        assert_eq!(datagram, PAYLOAD);
        server
            .send_datagram(datagram)
            .expect("echo native datagram");
    };
    tokio::join!(request, response);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_native_path_survives_actual_actor_pruning_across_selection_changes() {
    // Qlog filesystem work stays off the async executor; both bounded tasks are joined.
    let directory = tokio::task::spawn_blocking(|| harness::qlog_dir("native-retention"))
        .await
        .expect("create trace directory");
    let peers = tokio::time::timeout(Duration::from_secs(30), scenario(&directory))
        .await
        .expect("native retention actor deadline");
    tokio::task::spawn_blocking(move || assert_native_trace(&directory, peers))
        .await
        .expect("inspect retention traces");
}

/// cancel-safe: NO — the outer deadline terminates the fixture without retries.
async fn scenario(directory: &Path) -> [[SocketAddr; 2]; 2] {
    let (client_transport, server_transport, network) = MemTransport::pair();
    let client_key = SecretKey::from([31u8; 32]);
    let server_key = SecretKey::from([32u8; 32]);
    let (client_id, server_id) = (client_key.public(), server_key.public());
    let lookup = MemoryLookup::new();
    for (id, side) in [(client_id, 0), (server_id, 1)] {
        lookup.add_endpoint_info(EndpointAddr::from_parts(
            id,
            [TransportAddr::Custom(network.local_addr(side))],
        ));
    }
    let selector = Arc::new(FixtureSelector::default());
    let client_endpoint = bind(
        client_key,
        client_transport,
        lookup.clone(),
        directory,
        "a",
        selector.clone(),
    )
    .await;
    let server_endpoint = bind(
        server_key,
        server_transport,
        lookup,
        directory,
        "b",
        selector.clone(),
    )
    .await;
    let client_address = native_address(&client_endpoint, false);
    let server_address = native_address(&server_endpoint, false);
    let client_v6 = native_address(&client_endpoint, true);
    let server_v6 = native_address(&server_endpoint, true);
    let accept = async {
        server_endpoint
            .accept()
            .await
            .expect("incoming custom connection")
            .await
            .expect("authenticate custom connection")
    };
    let (client, server) = tokio::join!(client_endpoint.connect(server_id, harness::ALPN), accept);
    let client = client.expect("dial custom bootstrap");
    assert_eq!(client.remote_id(), server_id);
    assert_eq!(server.remote_id(), client_id);
    for connection in [&client, &server] {
        assert!(harness::custom_path_selected(connection));
        assert!(!connection.paths().iter().any(|path| path.is_ip()));
    }

    client
        .ensure_native_path(server_address)
        .await
        .expect("retain native A");
    let retained = client
        .paths()
        .iter()
        .find(|path| matches_native(path.remote_addr(), server_address))
        .expect("native A in the established Iroh snapshot")
        .id();
    assert_ne!(retained, PathId::ZERO);
    await_established(&server, retained, client_address).await;
    assert_retained(&client, retained, server_address);
    assert_retained(&server, retained, client_address);
    let mut client_events = client.path_events();

    // NEW, not ensure: duplicate A's physical tuple with an unretained ID.
    // Returning an ID drops OpenPath but does not cancel validation.
    let competing = client
        .spike_open_competing_native_path(server_address, client_address.ip())
        .await
        .expect("admit competing native B");
    assert_ne!(competing, retained);
    await_competitor_pruned(
        &client,
        &mut client_events,
        &[retained],
        competing,
        server_address,
        None,
    )
    .await;
    assert!(client.paths().get(competing).is_none());
    assert_eq!(client.paths().iter().filter(|path| path.is_ip()).count(), 1);
    assert!(harness::custom_path_selected(&client));
    assert!(harness::custom_path_selected(&server));
    assert_retained(&client, retained, server_address);
    assert_retained(&server, retained, client_address);
    exchange(&client, &server).await;

    // A different tuple is essential: selecting another ID on A's tuple cannot test retention.
    selector.prefer_ipv6.store(true, Ordering::SeqCst);
    let selected = client
        .spike_open_competing_native_path(server_v6, client_v6.ip())
        .await
        .expect("admit selected native C");
    assert_ne!(selected, retained);
    assert_ne!(selected, competing);
    await_native_selected(&client, &mut client_events, retained, selected, server_v6).await;
    await_established(&server, selected, client_v6).await;

    // Selected(C) precedes processing any queued Abandoned(A). D's Closed event
    // is a later actor barrier, so a stale snapshot cannot hide missing retention.
    let barrier = client
        .spike_open_competing_native_path(server_address, client_address.ip())
        .await
        .expect("admit pruning barrier D");
    assert_ne!(barrier, retained);
    assert_ne!(barrier, selected);
    assert_ne!(barrier, competing);
    await_competitor_pruned(
        &client,
        &mut client_events,
        &[retained, selected],
        barrier,
        server_address,
        Some(selected),
    )
    .await;
    assert!(client.paths().get(barrier).is_none());
    assert_eq!(client.paths().iter().filter(|path| path.is_ip()).count(), 2);
    assert_selected(&client, selected, server_v6);
    assert_retained(&client, retained, server_address);
    assert_retained(&server, retained, client_address);
    exchange(&client, &server).await;
    assert_selected(&client, selected, server_v6);
    assert_retained(&client, retained, server_address);
    assert_retained(&server, retained, client_address);
    assert!(network.stats(0).wire_packets() > 0);
    assert!(network.stats(1).wire_packets() > 0);
    tokio::join!(client_endpoint.close(), server_endpoint.close());
    assert!(client.close_reason().is_some());
    assert!(server.close_reason().is_some());
    drop(client_events);
    drop(client);
    drop(server);
    drop(client_endpoint);
    drop(server_endpoint);
    [[server_address, server_v6], [client_address, client_v6]]
}

fn trace_has_remote(addresses: &str, peer: SocketAddr) -> bool {
    addresses.starts_with(&format!("{peer} | "))
        || addresses.starts_with(&format!("{}:{} | ", peer.ip(), peer.port()))
        || (peer.is_ipv4()
            && addresses.starts_with(&format!("::ffff:{}:{} | ", peer.ip(), peer.port())))
}

fn assert_native_trace(directory: &Path, peers: [[SocketAddr; 2]; 2]) {
    let traces = qlog_oracle::parse_dir_named(directory);
    for (prefix, peers) in ["a", "b"].into_iter().zip(peers) {
        let selected = qlog_oracle::traces_with_prefix(&traces, prefix);
        assert_eq!(
            selected.len(),
            1,
            "one original authenticated connection per endpoint"
        );
        let trace = &selected[0].trace;
        assert_eq!(trace.sent_without_tuple.stream_frames, 0);
        assert_eq!(trace.sent_without_tuple.datagram_frames, 0);
        assert_eq!(trace.unknown_path_packets_sent, 0);
        let (mut streams, mut datagrams, mut custom_control) = ([0; 2], [0; 2], 0);
        for (tuple, counts) in &trace.sent_by_tuple {
            let addresses = trace.tuple_map.get(tuple).expect("assigned packet tuple");
            if let Some(index) = peers
                .iter()
                .position(|peer| trace_has_remote(addresses, *peer))
            {
                streams[index] += counts.stream_frames;
                datagrams[index] += counts.datagram_frames;
            } else {
                assert_eq!(counts.stream_frames, 0, "APP STREAM on non-native tuple");
                assert_eq!(
                    counts.datagram_frames, 0,
                    "APP DATAGRAM on non-native tuple"
                );
                custom_control += counts.packets;
            }
        }
        assert!(
            streams[0] > 0 && datagrams[0] > 0,
            "native APP while custom selected"
        );
        if prefix == "a" {
            assert!(
                streams[1] > 0 && datagrams[1] > 0,
                "client APP on selected native C"
            );
        }
        assert!(custom_control > 0, "custom control remains available");
    }
}
