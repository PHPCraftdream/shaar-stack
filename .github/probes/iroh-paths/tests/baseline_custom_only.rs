#![forbid(unsafe_code)]
//! The ONE integration test of this substage: custom-only baseline.
//!
//! Proves (same-host, single in-memory transport):
//! - two endpoints bound with `clear_ip_transports` (custom-only baseline;
//!   allowed ONLY here) connect over the custom transport (id 0x20),
//! - the selected path is the custom path,
//! - N >= 3 sequential echo round trips succeed through the REAL accept
//!   loop of the Echo handler (each await under an absolute timeout),
//! - bytes flow on the wire AND are delivered, in both directions, observed
//!   at the transport (enqueued + dequeued counters),
//! - positive calibration, properly scoped: the CLIENT qlog trace (file
//!   identified by the prefix passed to `qlog_from_path`) contains decoded
//!   SENT STREAM frames, sent-vs-received reported separately, and no
//!   unknown-path packets silently counted as path 0.
//!
//! SCOPE: the single-transport topology is what makes this attribution
//! valid (every packet must have used the custom transport). This does NOT
//! prove multipath egress mapping.
//!
//! Explicitly NOT proven here, and blocking dependent implementation:
//! strict signaling-only behavior, path migration, NAT traversal.

use std::time::Duration;

use iroh::{EndpointAddr, SecretKey, TransportAddr};
use iroh_base::CustomAddr;
use iroh_paths_probe::{
    MemTransport, TEST_TRANSPORT_ID,
    harness::{self},
    qlog_oracle,
};

/// Overall test deadline.
const OVERALL_DEADLINE: Duration = Duration::from_secs(120);

const ROUNTRIPS: usize = 4;

#[tokio::test(flavor = "multi_thread")]
async fn baseline_echo_over_custom_only_path() {
    let deadline = tokio::time::Instant::now() + OVERALL_DEADLINE;
    tokio::time::timeout_at(deadline, run_baseline(deadline))
        .await
        .expect("overall baseline deadline exceeded");
}

// Cancellation ends this fixture; it does not establish production shutdown safety.
async fn run_baseline(deadline: tokio::time::Instant) {
    let (ta, tb, network) = MemTransport::pair();
    let sa = SecretKey::from([1u8; 32]);
    let sb = SecretKey::from([2u8; 32]);
    let qlog = harness::qlog_dir("baseline-custom-only");

    let ep_b = harness::build_endpoint(harness::EndpointConfig {
        mem_transport: Some(tb),
        custom_only: true,
        qlog: Some((qlog.clone(), "server".into())),
        ..harness::EndpointConfig::new(sb.clone())
    })
    .await
    .expect("bind endpoint b");
    let router = harness::spawn_echo(&ep_b);

    let ep_a = harness::build_endpoint(harness::EndpointConfig {
        mem_transport: Some(ta),
        custom_only: true,
        qlog: Some((qlog.clone(), "client".into())),
        ..harness::EndpointConfig::new(sa.clone())
    })
    .await
    .expect("bind endpoint a");

    // Dial the custom address ONLY (CustomAddr::from_parts(u64, &[u8])).
    let peer_custom = CustomAddr::from_parts(TEST_TRANSPORT_ID, &[1]);
    let target = EndpointAddr::from_parts(sb.public(), [TransportAddr::Custom(peer_custom)]);
    let conn = tokio::time::timeout_at(deadline, ep_a.connect(target, harness::ALPN))
        .await
        .expect("overall deadline hit during connect")
        .expect("connect over custom-only path");

    assert!(
        harness::custom_path_selected(&conn),
        "custom path must be selected, paths: {:?}",
        harness::snapshot_paths("baseline", &conn)
    );

    for i in 0..ROUNTRIPS {
        let msg = format!("baseline-custom-only-{i}");
        tokio::time::timeout_at(deadline, harness::echo_roundtrip(&conn, msg.as_bytes()))
            .await
            .expect("overall deadline hit during echo")
            .expect("echo round trip");
    }

    // Wire-level: bytes enqueued AND delivered, both directions.
    let (ab, ba) = (network.stats(0), network.stats(1));
    eprintln!(
        "wire a->b: {} B / {} pkts, delivered {} B / {} pkts | b->a: {} B / {} pkts, delivered {} B / {} pkts",
        ab.wire_bytes(),
        ab.wire_packets(),
        ab.delivered_bytes(),
        ab.delivered_packets(),
        ba.wire_bytes(),
        ba.wire_packets(),
        ba.delivered_bytes(),
        ba.delivered_packets()
    );
    assert!(ab.wire_bytes() > 0 && ab.delivered_bytes() > 0, "a->b flow");
    assert!(ba.wire_bytes() > 0 && ba.delivered_bytes() > 0, "b->a flow");

    harness::snapshot_paths("baseline-final", &conn);
    conn.close(0u32.into(), b"done");
    drop(conn);
    ep_a.close().await;
    router.shutdown().await.expect("router shutdown");
    drop(router);
    drop(ep_a);
    drop(ep_b);

    // Endpoint close joins drivers; dropping application handles releases the
    // qlog streamer, whose Drop flushes the BufWriter (pinned upstream sources).
    let traces = qlog_oracle::parse_dir_named(&qlog);
    let clients = qlog_oracle::traces_with_prefix(&traces, "client");
    assert_eq!(clients.len(), 1, "expected exactly one client trace");
    let client = &clients[0].trace;
    eprintln!("oracle (client trace): {}", client.summary());
    // Sent vs received reported separately, both nonzero for an echo client.
    assert!(client.total_stream_frames_sent() > 0, "sent STREAM frames");
    assert!(
        client.packets_sent_by_path.values().sum::<u64>() > 0
            && client.packets_received_by_path.values().sum::<u64>() > 0,
        "sent and received packets counted separately, both nonzero"
    );
    // No unknown-path packets silently counted as path 0.
    assert_eq!(
        client.unknown_path_packets_sent, 0,
        "no unknown-path sent packets expected on the custom-only baseline"
    );
    assert_eq!(client.unknown_path_packets_received, 0);

    // echo_roundtrip checks plaintext equality. Transport counters above
    // measure encrypted datagrams, not application payload bytes.
}
