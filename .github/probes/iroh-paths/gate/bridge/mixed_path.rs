#![forbid(unsafe_code)]
//! Conservative custom exclusion with a later native route on the original connection.

use std::{net::SocketAddr, time::Duration};

#[path = "support/mixed_fixture.rs"]
mod mixed_fixture;
use iroh::{
    Endpoint, EndpointAddr, SecretKey, TransportAddr, address_lookup::memory::MemoryLookup,
};
use iroh_paths_probe::{MemTransport, harness, qlog_oracle};
use mixed_fixture::{bind, native_only};

#[test]
fn reserved_fabric_is_denied_regardless_of_subnet_or_port() {
    for subnet in [0, 1, 2, 3, u16::MAX] {
        for port in [0, 12345, u16::MAX] {
            let remote = SocketAddr::new(
                std::net::Ipv6Addr::new(0xfd15, 0x070a, 0x510b, subnet, 0, 0, 0, 1).into(),
                port,
            );
            assert!(!native_only(noq_proto::FourTuple::new(remote, None)));
        }
    }
    for remote in ["127.0.0.1:4000", "[::ffff:127.0.0.1]:4000", "[::1]:4000"] {
        assert!(native_only(noq_proto::FourTuple::new(
            remote.parse().expect("fixture address"),
            None
        )));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn queued_payload_waits_for_native_path_without_reconnecting() {
    tokio::time::timeout(Duration::from_secs(120), scenario())
        .await
        .expect("mixed-path deadline");
}

/// cancel-safe: NO — queued test traffic is not retried after the outer deadline.
async fn scenario() {
    let (ta, tb, network) = MemTransport::pair();
    let ka = SecretKey::from([7u8; 32]);
    let kb = SecretKey::from([8u8; 32]);
    let lookup = MemoryLookup::new();
    for (id, side) in [(ka.public(), 0), (kb.public(), 1)] {
        lookup.add_endpoint_info(EndpointAddr::from_parts(
            id,
            [TransportAddr::Custom(network.local_addr(side))],
        ));
    }
    let directory = harness::qlog_dir("mixed-path");
    let a = bind(ka, ta, lookup.clone(), &directory, "a").await;
    let b = bind(kb.clone(), tb, lookup, &directory, "b").await;
    let address = |endpoint: &Endpoint| {
        endpoint
            .bound_sockets()
            .into_iter()
            .find(|addr| addr.is_ipv4() && addr.ip().is_loopback())
            .expect("owned IPv4 loopback socket")
    };
    let (a_ip, b_ip) = (address(&a), address(&b));
    let accept = async {
        b.accept()
            .await
            .expect("incoming")
            .await
            .expect("handshake")
    };
    let (ca, cb) = tokio::join!(a.connect(kb.public(), harness::ALPN), accept);
    let ca = ca.expect("dial custom bootstrap");
    assert!(harness::custom_path_selected(&ca));
    assert!(
        !ca.paths()
            .iter()
            .any(|p| matches!(p.remote_addr(), TransportAddr::Ip(_))),
        "native route must not exist before admission"
    );
    let mut sa = ca.open_uni().await.expect("open a stream");
    let mut sb = cb.open_uni().await.expect("open b stream");
    for (sender, stream) in [(&ca, &mut sa), (&cb, &mut sb)] {
        stream
            .write_all(b"queued!!")
            .await
            .expect("queue STREAM once");
        stream.finish().expect("queue FIN");
        sender
            .send_datagram(b"queued!!".to_vec().into())
            .expect("queue DATAGRAM once");
    }
    for (receiver, side) in [(&cb, 0), (&ca, 1)] {
        let before = network.stats(side).wire_packets();
        assert!(
            tokio::time::timeout(Duration::from_millis(160), receiver.accept_uni())
                .await
                .is_err(),
            "STREAM must remain queued before native admission"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(160), receiver.read_datagram())
                .await
                .is_err(),
            "DATAGRAM must remain queued before native admission"
        );
        assert!(
            network.stats(side).wire_packets() > before,
            "custom control must continue"
        );
    }
    // NAT discovery is disabled; candidate insertion alone cannot probe/open an IP path.
    eprintln!("mixed-path: queues retained; opening native Backup {b_ip}");
    assert!(
        ca.spike_open_ip_path(b_ip).await,
        "validate native Backup on original connection"
    );
    eprintln!("mixed-path: native Backup validated; draining original queues");
    for receiver in [&ca, &cb] {
        assert_eq!(
            receiver
                .accept_uni()
                .await
                .expect("accept queued stream")
                .read_to_end(8)
                .await
                .expect("read exact queued bytes"),
            b"queued!!"
        );
        assert_eq!(
            receiver
                .read_datagram()
                .await
                .expect("read queued datagram"),
            b"queued!!".as_slice()
        );
    }
    assert!(
        ca.paths()
            .iter()
            .any(|p| matches!(p.remote_addr(), TransportAddr::Ip(_))),
        "original connection must acquire a native path"
    );
    ca.close(0u32.into(), b"done");
    drop(sa);
    drop(sb);
    drop(ca);
    drop(cb);
    a.close().await;
    b.close().await;
    drop(a);
    drop(b);
    let traces = qlog_oracle::parse_dir_named(&directory);
    for (prefix, peer) in [("a", b_ip), ("b", a_ip)] {
        let selected = qlog_oracle::traces_with_prefix(&traces, prefix);
        assert_eq!(selected.len(), 1, "no replacement connection trace");
        let trace = &selected[0].trace;
        assert_eq!(trace.sent_without_tuple.stream_frames, 0);
        assert_eq!(trace.sent_without_tuple.datagram_frames, 0);
        assert_eq!(trace.unknown_path_packets_sent, 0);
        let (mut native_streams, mut native_datagrams, mut forbidden_packets) = (0, 0, 0);
        for (tuple, counts) in &trace.sent_by_tuple {
            let endpoints = trace.tuple_map.get(tuple).expect("assigned tuple");
            // Qlog may retain IPv4-mapped IPv6, but the socket and port must match exactly.
            if endpoints.starts_with(&format!("{peer} | "))
                || endpoints.starts_with(&format!("::ffff:{}:{} | ", peer.ip(), peer.port()))
            {
                native_streams += counts.stream_frames;
                native_datagrams += counts.datagram_frames;
            } else {
                forbidden_packets += counts.packets;
                assert_eq!(counts.stream_frames, 0, "non-native STREAM on {endpoints}");
                assert_eq!(
                    counts.datagram_frames, 0,
                    "non-native DATAGRAM on {endpoints}"
                );
            }
        }
        assert!(
            native_streams > 0 && native_datagrams > 0,
            "native payload calibration"
        );
        assert!(forbidden_packets > 0, "custom control calibration");
    }
}
