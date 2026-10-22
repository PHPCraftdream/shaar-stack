#![forbid(unsafe_code)]
//! Exact ciphertext correlation at custom enqueue and independent native UDP receive boundaries.

use iroh::{
    Endpoint, EndpointAddr, SecretKey, TransportAddr, address_lookup::memory::MemoryLookup,
};
use iroh_paths_probe::{MemTransport, harness, qlog_oracle};
use std::time::Duration;

#[path = "support/mixed_fixture.rs"]
mod mixed_fixture;
#[path = "support/udp_capture.rs"]
mod udp_capture;
#[path = "support/wire_oracle.rs"]
mod wire_oracle;
use wire_oracle::{Counts, Index};

#[tokio::test(flavor = "multi_thread")]
async fn captured_ciphertext_proves_custom_exclusion_and_native_payload() {
    tokio::time::timeout(Duration::from_secs(120), scenario())
        .await
        .expect("wire oracle deadline");
}

/// cancel-safe: NO — timeout terminates the fixture and aborts its owned capture task.
async fn scenario() {
    let (ta, tb, network) = MemTransport::pair();
    network
        .enable_capture()
        .expect("enable bounded custom capture");
    let ka = SecretKey::from([9u8; 32]);
    let kb = SecretKey::from([10u8; 32]);
    let lookup = MemoryLookup::new();
    for (id, side) in [(ka.public(), 0), (kb.public(), 1)] {
        lookup.add_endpoint_info(EndpointAddr::from_parts(
            id,
            [TransportAddr::Custom(network.local_addr(side))],
        ));
    }
    let directory = harness::qlog_dir("wire-oracle");
    let a = mixed_fixture::bind(ka, ta, lookup.clone(), &directory, "a").await;
    let b = mixed_fixture::bind(kb.clone(), tb, lookup, &directory, "b").await;
    let address = |endpoint: &Endpoint| {
        endpoint
            .bound_sockets()
            .into_iter()
            .find(|addr| addr.is_ipv4() && addr.ip().is_loopback())
            .expect("owned native socket")
    };
    let proxy = udp_capture::UdpCapture::bind([address(&a), address(&b)])
        .await
        .expect("bind capture forwarder");
    let accept = async {
        b.accept()
            .await
            .expect("incoming")
            .await
            .expect("handshake")
    };
    let (ca, cb) = tokio::join!(a.connect(kb.public(), harness::ALPN), accept);
    let ca = ca.expect("custom bootstrap");
    assert!(harness::custom_path_selected(&ca));
    let mut sa = ca.open_uni().await.expect("open a stream");
    let mut sb = cb.open_uni().await.expect("open b stream");
    for (sender, stream) in [(&ca, &mut sa), (&cb, &mut sb)] {
        stream
            .write_all(b"wire!!!!")
            .await
            .expect("queue STREAM once");
        stream.finish().expect("queue FIN");
        sender
            .send_datagram(b"wire!!!!".to_vec().into())
            .expect("queue DATAGRAM once");
    }
    for receiver in [&ca, &cb] {
        assert!(
            tokio::time::timeout(Duration::from_millis(120), receiver.read_datagram())
                .await
                .is_err(),
            "no payload before native path exists"
        );
    }
    assert!(
        ca.spike_open_ip_path(proxy.addr).await,
        "validate native capture path"
    );
    for receiver in [&ca, &cb] {
        assert_eq!(
            receiver
                .accept_uni()
                .await
                .expect("queued stream")
                .read_to_end(8)
                .await
                .expect("exact STREAM bytes"),
            b"wire!!!!"
        );
        assert_eq!(
            receiver
                .read_datagram()
                .await
                .expect("exact DATAGRAM bytes"),
            b"wire!!!!".as_slice()
        );
    }
    ca.close(0u32.into(), b"done");
    drop(sa);
    drop(sb);
    drop(ca);
    drop(cb);
    a.close().await;
    b.close().await;
    drop(a);
    drop(b);
    let native = proxy.finish().await.expect("join native capture task");
    let custom = network
        .take_capture()
        .expect("capture lock")
        .expect("capture enabled");
    let traces = qlog_oracle::parse_dir_named(&directory);
    for (side, prefix) in [(0, "a"), (1, "b")] {
        let selected = qlog_oracle::traces_with_prefix(&traces, prefix);
        assert_eq!(selected.len(), 1, "one original connection trace");
        let index = Index::parse_file(&directory.join(&selected[0].file_name))
            .expect("exact qlog packet identities");
        let mut seen = index.seen();
        let mut custom_frames = Counts::default();
        let mut native_frames = Counts::default();
        assert!(
            !custom[side].is_empty() && !native[side].is_empty(),
            "both boundaries must observe traffic"
        );
        for datagram in &custom[side] {
            custom_frames.add(
                index
                    .observe(datagram, &mut seen)
                    .expect("complete custom datagram correlation"),
            );
        }
        for datagram in &native[side] {
            native_frames.add(
                index
                    .observe(datagram, &mut seen)
                    .expect("complete native datagram correlation"),
            );
        }
        assert_eq!(custom_frames.streams, 0, "captured custom STREAM exclusion");
        assert_eq!(
            custom_frames.datagrams, 0,
            "captured custom DATAGRAM exclusion"
        );
        assert!(
            native_frames.streams > 0 && native_frames.datagrams > 0,
            "captured native positive calibration"
        );
        let unobserved = index.unobserved(&seen);
        assert_eq!(
            unobserved.streams, 0,
            "no payload construction silently missed by capture"
        );
        assert_eq!(
            unobserved.datagrams, 0,
            "no payload construction silently missed by capture"
        );
        eprintln!(
            "wire side {side}: custom={custom_frames:?} native={native_frames:?} constructed_not_observed={unobserved:?}"
        );
    }
}
