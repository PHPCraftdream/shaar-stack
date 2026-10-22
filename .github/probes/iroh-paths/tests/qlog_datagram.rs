#![forbid(unsafe_code)]
//! Real iroh DATAGRAM/qlog calibration on one custom transport, not multipath proof.

use std::time::Duration;

use iroh::{EndpointAddr, SecretKey, TransportAddr, address_lookup::memory::MemoryLookup};
use iroh_paths_probe::{MemTransport, harness, qlog_oracle};

#[tokio::test(flavor = "multi_thread")]
async fn datagram_frames_have_real_tuple_labels_in_both_directions() {
    tokio::time::timeout(Duration::from_secs(120), calibrate())
        .await
        .expect("datagram calibration deadline");
}

// cancel-safe: NO — deadline terminates this entire fixture; no retry is supported.
async fn calibrate() {
    let (left_transport, right_transport, network) = MemTransport::pair();
    let left_key = SecretKey::from([3u8; 32]);
    let right_key = SecretKey::from([4u8; 32]);
    let lookup = MemoryLookup::new();
    lookup.add_endpoint_info(EndpointAddr::from_parts(
        left_key.public(),
        [TransportAddr::Custom(network.local_addr(0))],
    ));
    lookup.add_endpoint_info(EndpointAddr::from_parts(
        right_key.public(),
        [TransportAddr::Custom(network.local_addr(1))],
    ));
    let directory = harness::qlog_dir("datagram-calibration");
    let left = harness::build_endpoint(harness::EndpointConfig {
        mem_transport: Some(left_transport),
        custom_only: true,
        qlog: Some((directory.clone(), "left".into())),
        address_lookup: Some(lookup.clone()),
        ..harness::EndpointConfig::new(left_key)
    })
    .await
    .expect("bind left");
    let right = harness::build_endpoint(harness::EndpointConfig {
        mem_transport: Some(right_transport),
        custom_only: true,
        qlog: Some((directory.clone(), "right".into())),
        address_lookup: Some(lookup),
        ..harness::EndpointConfig::new(right_key.clone())
    })
    .await
    .expect("bind right");
    let accept = async {
        right
            .accept()
            .await
            .expect("incoming connection")
            .await
            .expect("accept handshake")
    };
    let (dialed, accepted) = tokio::join!(left.connect(right_key.public(), harness::ALPN), accept);
    let dialed = dialed.expect("dial handshake");
    for message in [b"".as_slice(), b"nonempty-datagram".as_slice()] {
        dialed
            .send_datagram(message.to_vec().into())
            .expect("send left datagram");
        assert_eq!(
            accepted.read_datagram().await.expect("receive right"),
            message
        );
        accepted
            .send_datagram(message.to_vec().into())
            .expect("send right datagram");
        assert_eq!(dialed.read_datagram().await.expect("receive left"), message);
    }
    for side in 0..2 {
        assert!(network.stats(side).wire_packets() > 0);
        assert!(network.stats(side).delivered_packets() > 0);
    }
    dialed.close(0u32.into(), b"done");
    drop(dialed);
    drop(accepted);
    left.close().await;
    right.close().await;
    drop(left);
    drop(right);

    let traces = qlog_oracle::parse_dir_named(&directory);
    for prefix in ["left", "right"] {
        let selected = qlog_oracle::traces_with_prefix(&traces, prefix);
        assert_eq!(selected.len(), 1, "one trace per endpoint");
        let trace = &selected[0].trace;
        assert_eq!(trace.sent_without_tuple.datagram_frames, 0);
        assert_eq!(trace.received_without_tuple.datagram_frames, 0);
        assert_eq!(trace.unknown_path_packets_sent, 0);
        assert_eq!(trace.unknown_path_packets_received, 0);
        assert_eq!(trace.datagram_frames_sent_by_path.values().sum::<u64>(), 2);
        assert_eq!(
            trace.datagram_frames_received_by_path.values().sum::<u64>(),
            2
        );
        assert_eq!(
            trace
                .sent_by_tuple
                .values()
                .map(|c| c.datagram_frames)
                .sum::<u64>(),
            2
        );
        assert_eq!(
            trace
                .received_by_tuple
                .values()
                .map(|c| c.datagram_frames)
                .sum::<u64>(),
            2
        );
        for tuple in trace
            .sent_by_tuple
            .keys()
            .chain(trace.received_by_tuple.keys())
        {
            assert!(
                trace.tuple_map.contains_key(tuple),
                "unassigned tuple {tuple}"
            );
        }
    }
}
