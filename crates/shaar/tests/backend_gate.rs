#![forbid(unsafe_code)]
//! Product dependency wiring: real native UDP, without probe transport or qlog hooks.

#[path = "../../../.github/scripts/backend/actor_shutdown.rs"]
mod actor_shutdown;

use std::time::Duration;

use iroh::endpoint::{
    Builder, ConnectError, ConnectWithOptsError, Connection, NetReportConfig, PortmapperConfig,
    QuicConnectError, QuicTransportConfig, ReadError, ReadToEndError, presets,
};
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

fn native_builder(seed: u8) -> Builder {
    Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from([seed; 32]))
        .alpns(vec![ALPN.to_vec()])
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .expect("loopback bind configuration")
        .portmapper_config(PortmapperConfig::Disabled)
        .net_report_config(NetReportConfig::minimal())
}

#[tokio::test(flavor = "multi_thread")]
async fn local_connection_limit_rejects_before_any_initial_is_sent() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let endpoint = native_builder(32)
            .connection_limit(0)
            .bind()
            .await
            .expect("bind limited endpoint");
        endpoint.set_alpns(vec![ALPN.to_vec()]);
        let observer = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind UDP observer");
        let peer = SecretKey::from([31; 32]).public();
        let remote =
            EndpointAddr::from_parts(peer, [TransportAddr::Ip(observer.local_addr().unwrap())]);
        let error = endpoint
            .connect(remote, ALPN)
            .await
            .expect_err("zero allocation budget");
        assert!(matches!(
            error,
            ConnectError::Connect {
                source: ConnectWithOptsError::Noq {
                    source: QuicConnectError::TooManyConnections,
                    ..
                },
                ..
            }
        ));
        let mut packet = [0u8; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), observer.recv_from(&mut packet))
                .await
                .is_err()
        );
        assert!(!endpoint.is_closed());
        endpoint.close().await;
    })
    .await
    .expect("local connection budget deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn incoming_budget_is_applied_before_accept_and_survives_alpn_updates() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for update_alpns in [false, true] {
            for count in [0, 1] {
                incoming_probe(count, update_alpns).await;
            }
        }
    })
    .await
    .expect("incoming budget calibration deadline");
}

/// cancel-safe: NO — terminal fixture deadline; no Initial is replayed by this helper.
async fn incoming_probe(count: usize, update_alpns: bool) {
    let (per_incoming, total) = if update_alpns { (16384, 32768) } else { (0, 0) };
    let server = native_builder(31)
        .incoming_limits(count, per_incoming, total)
        .bind()
        .await
        .expect("bind server");
    if update_alpns {
        server.set_alpns(vec![ALPN.to_vec()]);
    }
    // Inspect the external Noq config factory as well as the native admission outcome.
    let configured = format!(
        "{:#?}",
        server
            .create_server_config_builder(vec![ALPN.to_vec()])
            .build()
    );
    assert!(configured.contains(&format!("max_incoming: {count},")));
    assert!(configured.contains(&format!("incoming_buffer_size: {per_incoming},")));
    assert!(configured.contains(&format!("incoming_buffer_size_total: {total},")));
    let client = native_builder(32).bind().await.expect("bind client");
    let server_socket = server.bound_sockets()[0];
    let proxy = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind owned UDP observer");
    let remote = EndpointAddr::from_parts(
        server.id(),
        [TransportAddr::Ip(proxy.local_addr().unwrap())],
    );
    let mut connect = Box::pin(client.connect(remote, ALPN));
    let mut buffer = [0u8; 2048];
    let packet = tokio::select! {
        _ = &mut connect => panic!("connect completed before the Initial was forwarded"),
        packet = proxy.recv_from(&mut buffer) => packet.expect("observe real Initial"),
    };
    assert!((1200..buffer.len()).contains(&packet.0));
    assert_eq!(
        proxy
            .send_to(&buffer[..packet.0], server_socket)
            .await
            .expect("forward complete Initial"),
        packet.0
    );
    let incoming = tokio::time::timeout(Duration::from_millis(300), server.accept()).await;
    if count == 0 {
        assert!(incoming.is_err(), "zero-count budget admitted an Initial");
        assert!(!server.is_closed());
    } else {
        incoming
            .expect("positive Initial admission deadline")
            .expect("live server")
            .refuse();
    }
    // The first Initial is not charged to byte buffers; zero byte budgets still admit it.
    drop(connect);
    tokio::join!(server.close(), client.close());
}

/// cancel-safe: NO — deadline terminates the fixture; writes and reads are never retried.
async fn exercise(permitted: bool) {
    let build = |seed| {
        native_builder(seed)
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
            assert!(receiver.stats().udp_tx.datagrams > before.udp_tx.datagrams);
        }
    }
    if !permitted {
        // Reset control may expose lower stream IDs without carrying STREAM data.
        reset_control(&outgoing, &incoming).await;
        reset_control(&incoming, &outgoing).await;
    }
    for connection in [&outgoing, &incoming] {
        assert_frames(connection, permitted);
    }
    outgoing.close(0u32.into(), b"fixture done");
    incoming.close(0u32.into(), b"fixture done");
    tokio::join!(a.close(), b.close());
}

/// cancel-safe: NO — terminal fixture deadline; no write/read is retried after cancellation.
async fn reset_control(sender: &Connection, receiver: &Connection) {
    let mut blocked = sender.open_uni().await.expect("second STREAM");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), blocked.write_all(b"x"))
            .await
            .is_err()
    );
    let reset_id = blocked.id();
    blocked
        .reset(0u32.into())
        .expect("reset empty blocked STREAM");
    let mut pending = receiver
        .accept_uni()
        .await
        .expect("implicitly opened lower STREAM");
    assert!(u64::from(pending.id()) < u64::from(reset_id));
    assert!(
        tokio::time::timeout(Duration::from_millis(150), pending.read_to_end(8))
            .await
            .is_err()
    );
    let mut reset = receiver.accept_uni().await.expect("reset STREAM control");
    assert_eq!(reset.id(), reset_id);
    assert_eq!(
        reset.read_to_end(8).await,
        Err(ReadToEndError::Read(ReadError::Reset(0u32.into())))
    );
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
