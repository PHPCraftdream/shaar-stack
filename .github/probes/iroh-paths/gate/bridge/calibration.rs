#![forbid(unsafe_code)]
//! Wrapper propagation only: no synthetic-prefix or transport-provenance policy.

use std::time::Duration;

use iroh::endpoint::{QuicTransportConfig, presets};
use iroh::{
    Endpoint, EndpointAddr, SecretKey, TransportAddr, address_lookup::memory::MemoryLookup,
};
use iroh_paths_probe::{MemTransport, harness, qlog_oracle};

fn deny(_: noq_proto::FourTuple) -> bool {
    false
}
fn allow(_: noq_proto::FourTuple) -> bool {
    true
}

#[tokio::test(flavor = "multi_thread")]
async fn wrapper_policy_preserves_control_and_gates_both_payload_types() {
    tokio::time::timeout(Duration::from_secs(120), calibrate())
        .await
        .expect("wrapper calibration deadline");
}

/// cancel-safe: NO — a deadline terminates the entire fixture without retry.
async fn calibrate() {
    for permitted in [false, true] {
        let (ta, tb, network) = MemTransport::pair();
        let a_key = SecretKey::from([5u8; 32]);
        let b_key = SecretKey::from([6u8; 32]);
        let lookup = MemoryLookup::new();
        for (key, side) in [(a_key.public(), 0), (b_key.public(), 1)] {
            lookup.add_endpoint_info(EndpointAddr::from_parts(
                key,
                [TransportAddr::Custom(network.local_addr(side))],
            ));
        }
        let directory = harness::qlog_dir(if permitted {
            "bridge-allow"
        } else {
            "bridge-deny"
        });
        let policy: fn(noq_proto::FourTuple) -> bool = if permitted { allow } else { deny };
        let transport_config = |prefix: &str| {
            QuicTransportConfig::builder()
                .application_data_filter(policy)
                .send_window(8)
                .datagram_send_buffer_size(8)
                .keep_alive_interval(Duration::from_millis(40))
                .qlog_from_path(&directory, prefix)
                .build()
        };
        let a = Endpoint::builder(presets::Minimal)
            .secret_key(a_key)
            .alpns(vec![harness::ALPN.to_vec()])
            .address_lookup(lookup.clone())
            .add_custom_transport(ta)
            .clear_ip_transports()
            .transport_config(transport_config("a"))
            .bind()
            .await
            .expect("bind a");
        let b = Endpoint::builder(presets::Minimal)
            .secret_key(b_key.clone())
            .alpns(vec![harness::ALPN.to_vec()])
            .address_lookup(lookup)
            .add_custom_transport(tb)
            .clear_ip_transports()
            .transport_config(transport_config("b"))
            .bind()
            .await
            .expect("bind b");
        let incoming = async { b.accept().await.expect("incoming").await.expect("accept") };
        let (outgoing, incoming) = tokio::join!(a.connect(b_key.public(), harness::ALPN), incoming);
        let outgoing = outgoing.expect("dial");
        for (sender, receiver, side) in [(&outgoing, &incoming, 0), (&incoming, &outgoing, 1)] {
            let mut stream = sender.open_uni().await.expect("open stream");
            stream.write_all(b"payload!").await.expect("queue stream");
            sender
                .send_datagram(b"payload!".to_vec().into())
                .expect("queue datagram");
            if permitted {
                stream.finish().expect("finish stream");
                let bytes = receiver
                    .accept_uni()
                    .await
                    .expect("accept stream")
                    .read_to_end(8)
                    .await
                    .expect("read stream");
                assert_eq!(bytes, b"payload!");
                assert_eq!(
                    receiver.read_datagram().await.expect("read datagram"),
                    b"payload!".as_slice()
                );
            } else {
                assert!(
                    tokio::time::timeout(Duration::from_millis(80), stream.write_all(b"x"))
                        .await
                        .is_err(),
                    "denied stream must retain send-window backpressure"
                );
                let before = network.stats(side).wire_packets();
                assert!(
                    tokio::time::timeout(Duration::from_millis(240), receiver.read_datagram())
                        .await
                        .is_err(),
                    "denied datagram must not be delivered"
                );
                assert!(
                    network.stats(side).wire_packets() > before,
                    "control traffic must continue after payload is queued"
                );
                stream.reset(0u32.into()).expect("reset blocked stream");
            }
        }
        outgoing.close(0u32.into(), b"done");
        drop(outgoing);
        drop(incoming);
        a.close().await;
        b.close().await;
        drop(a);
        drop(b);
        let traces = qlog_oracle::parse_dir_named(&directory);
        for prefix in ["a", "b"] {
            let selected = qlog_oracle::traces_with_prefix(&traces, prefix);
            assert_eq!(selected.len(), 1, "one trace for {prefix}");
            let trace = &selected[0].trace;
            assert_eq!(trace.sent_without_tuple.stream_frames, 0);
            assert_eq!(trace.sent_without_tuple.datagram_frames, 0);
            assert_eq!(trace.unknown_path_packets_sent, 0);
            let streams = trace
                .sent_by_tuple
                .values()
                .map(|c| c.stream_frames)
                .sum::<u64>();
            let datagrams = trace
                .sent_by_tuple
                .values()
                .map(|c| c.datagram_frames)
                .sum::<u64>();
            if permitted {
                assert!(streams > 0, "allow STREAM calibration");
                assert!(datagrams > 0, "allow DATAGRAM calibration");
            } else {
                assert_eq!(streams, 0, "deny STREAM on every tuple");
                assert_eq!(datagrams, 0, "deny DATAGRAM on every tuple");
            }
        }
    }
}
