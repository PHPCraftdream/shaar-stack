#![forbid(unsafe_code)]
//! Product dependency wiring: real native UDP, without probe transport or qlog hooks.

use std::time::Duration;

use iroh::endpoint::{Connection, NetReportConfig, PortmapperConfig, QuicTransportConfig, presets};
use iroh::{Endpoint, EndpointAddr, SecretKey, TransportAddr};

const PAYLOAD: &[u8] = b"product!";
const ALPN: &[u8] = b"shaar/dependency-gate/1";

#[tokio::test(flavor = "multi_thread")]
async fn product_dependency_gate_preserves_control_and_bounds_payload() {
    tokio::time::timeout(Duration::from_secs(30), async {
        exercise(false).await;
        exercise(true).await;
    })
    .await
    .expect("product dependency calibration deadline");
}

/// cancel-safe: NO — deadline terminates the fixture; writes and reads are never retried.
async fn exercise(permitted: bool) {
    let build = |seed| {
        Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from([seed; 32]))
            .alpns(vec![ALPN.to_vec()])
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .expect("loopback bind configuration")
            .portmapper_config(PortmapperConfig::Disabled)
            .net_report_config(NetReportConfig::minimal())
            .transport_config(
                QuicTransportConfig::builder()
                    .application_data_filter(if permitted { |_| true } else { |_| false })
                    .send_window(8)
                    .datagram_send_buffer_size(8)
                    .keep_alive_interval(Duration::from_millis(40))
                    .build(),
            )
            .bind()
    };
    let a = build(31).await.expect("bind peer A");
    let b = build(32).await.expect("bind peer B");
    let sockets = b.bound_sockets();
    assert_eq!(sockets.len(), 1);
    assert!(sockets[0].ip().is_loopback());
    let address = EndpointAddr::from_parts(b.id(), [TransportAddr::Ip(sockets[0])]);
    let (outgoing, incoming) = tokio::join!(a.connect(address, ALPN), async {
        b.accept().await.expect("incoming connection").await
    });
    let outgoing = outgoing.expect("connect over native UDP");
    let incoming = incoming.expect("accept native UDP");
    assert_eq!(outgoing.remote_id(), b.id());
    assert_eq!(incoming.remote_id(), a.id());
    for connection in [&outgoing, &incoming] {
        let mut stream = connection.open_uni().await.expect("open STREAM");
        stream.write_all(PAYLOAD).await.expect("queue eight bytes");
        stream.finish().expect("queue FIN");
        connection
            .send_datagram(PAYLOAD.to_vec().into())
            .expect("queue DATAGRAM");
        // Finished send handles need not stay alive for QUIC retransmission/ACK.
    }
    for receiver in [&outgoing, &incoming] {
        if permitted {
            let bytes = receiver
                .accept_uni()
                .await
                .expect("native STREAM")
                .read_to_end(8)
                .await
                .expect("exact bytes and FIN");
            assert_eq!(bytes, PAYLOAD);
            assert_eq!(
                receiver
                    .read_datagram()
                    .await
                    .expect("native DATAGRAM")
                    .as_ref(),
                PAYLOAD
            );
        } else {
            let before = receiver.stats();
            assert!(
                tokio::time::timeout(Duration::from_millis(150), receiver.accept_uni())
                    .await
                    .is_err()
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(150), receiver.read_datagram())
                    .await
                    .is_err()
            );
            let mut blocked = receiver.open_uni().await.expect("second STREAM");
            assert!(
                tokio::time::timeout(Duration::from_millis(100), blocked.write_all(b"x"))
                    .await
                    .is_err()
            );
            blocked
                .reset(0u32.into())
                .expect("reset empty blocked STREAM");
            assert!(receiver.stats().udp_tx.datagrams > before.udp_tx.datagrams);
        }
    }
    for connection in [&outgoing, &incoming] {
        assert_frames(connection, permitted);
    }
    outgoing.close(0u32.into(), b"fixture done");
    incoming.close(0u32.into(), b"fixture done");
    tokio::join!(a.close(), b.close());
}

fn assert_frames(connection: &Connection, permitted: bool) {
    let stats = connection.stats();
    assert!(stats.udp_tx.datagrams > 0);
    assert!(stats.udp_rx.datagrams > 0);
    if permitted {
        assert!(stats.frame_tx.stream > 0);
        assert!(stats.frame_tx.datagram > 0);
    } else {
        assert_eq!(stats.frame_tx.stream, 0);
        assert_eq!(stats.frame_tx.datagram, 0);
        assert_eq!(stats.frame_rx.stream, 0);
        assert_eq!(stats.frame_rx.datagram, 0);
    }
}
