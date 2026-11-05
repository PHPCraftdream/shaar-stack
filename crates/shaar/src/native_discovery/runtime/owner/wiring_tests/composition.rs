// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

//! The path owner over a real resolve-and-dial: the server key alone leads, through an
//! owned loopback Mainline fixture, to an exact-key QUIC session that carries exact bytes.

use super::super::endpoint::{NativeDiscoveredEndpoint, NativeEndpointError};
use super::super::endpoint_key;
use super::super::tests::fixture::LoopbackPeer;
use super::connect::{server, signed_record};
use super::{bind, free_port, options, peer_v4};
use crate::identity::Identity;
use crate::network::ForwardStats;
use crate::network::Session;
use crate::path::{DialError, Dialer, PathKind, PathOwner, PolicyConfig};
use iroh_base::PublicKey;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;

const PAYLOAD: &[u8] = b"composed native path";

/// The native dialer of the path owner: resolve the server key's signed record, then dial
/// the published addresses with the exact-key `Endpoint::connect` under one deadline.
/// Product wiring of this adapter belongs to the startup leaf.
struct DiscoveredDial {
    endpoint: NativeDiscoveredEndpoint,
    expected: PublicKey,
}

impl Dialer for DiscoveredDial {
    type Link = Session;

    async fn dial(&mut self, deadline: tokio::time::Instant) -> Result<Session, DialError> {
        self.endpoint
            .connect_until(self.expected, deadline)
            .await
            .map_err(|_: NativeEndpointError| DialError)
    }

    async fn close(&mut self) -> Result<(), DialError> {
        self.endpoint.close().await.map_err(|_| DialError)
    }
}

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("pair listener binds");
    let address = listener.local_addr().expect("pair address");
    let (local, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
    (
        local.expect("pair connects"),
        accepted.expect("pair accepts").0,
    )
}

#[tokio::test]
async fn the_owner_resolves_the_key_dials_exactly_forwards_bytes_and_shuts_down_joined() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut peer = LoopbackPeer::bind().await;
        let client = bind(
            free_port().await,
            options(free_port().await, peer_v4(&peer)),
        )
        .await
        .expect("client binds");
        let (client_id, client_address) = (client.id(), client.local_addr());
        let identity_b = Identity::from_seed([0x62; 32]);
        let key_b = endpoint_key(&identity_b).expect("key");
        let mut server_b = server(0x62, client_id).await;
        let server_address = server_b.local_addr();
        let item = signed_record(&identity_b, server_address);
        let config = PolicyConfig {
            attempt_timeout: 15_000,
            ..PolicyConfig::default()
        };
        let mut owner =
            PathOwner::new(
            DiscoveredDial {
                endpoint: client,
                expected: key_b,
            },
            config,
        )
        .expect("valid parameters");

        let (established, accepted) = tokio::join!(
            async {
                tokio::select! {
                    result = owner.establish() => result,
                    _ = peer.serve_record(&item) => unreachable!("the record server runs until the owner finishes"),
                }
            },
            server_b.accept(),
        );
        assert_eq!(established, Ok(()));
        let mut accepted = accepted.expect("allowlisted client accepted");
        assert_eq!(accepted.peer_id(), client_id);
        assert_eq!(owner.active(), Some(PathKind::Native));

        let target = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("target binds");
        let target_address = target.local_addr().expect("target address");
        let (stop, stopped) = oneshot::channel::<()>();
        let (mut app, bridge) = tcp_pair().await;
        let session = owner.payload().expect("native payload");
        assert_eq!(session.peer_id(), key_b);
        let service = async {
            let (mut tcp, _) = target.accept().await.expect("target accepts");
            let mut bytes = Vec::new();
            tcp.read_to_end(&mut bytes).await.expect("target reads");
            tcp.write_all(&bytes).await.expect("target echoes");
            tcp.shutdown().await.expect("target half-closes");
        };
        let application = async {
            app.write_all(PAYLOAD).await.expect("app writes");
            app.shutdown().await.expect("app half-closes");
            let mut echoed = Vec::new();
            app.read_to_end(&mut echoed).await.expect("app reads");
            assert_eq!(echoed, PAYLOAD);
        };
        let exchange = async {
            let (stats, (), ()) = tokio::join!(session.forward(bridge), service, application);
            stop.send(()).expect("serve is waiting for the stop signal");
            stats
        };
        let (report, stats) = tokio::join!(
            accepted.serve(target_address, async {
                stopped.await.expect("stop signal");
            }),
            exchange,
        );
        let length = u64::try_from(PAYLOAD.len()).expect("small payload");
        assert_eq!(
            stats.expect("forwarded"),
            ForwardStats {
                to_peer: length,
                from_peer: length
            }
        );
        let report = report.expect("served");
        assert_eq!(report.completed + report.failed + report.cancelled, 1);

        owner.close().await.expect("owner backends joined");
        assert!(owner.payload().is_none(), "a closed owner holds no payload");
        drop(accepted);
        server_b.close().await;
        let _client_rebound = UdpSocket::bind(client_address)
            .await
            .expect("the client's native port is free again");
        let _server_rebound = UdpSocket::bind(server_address)
            .await
            .expect("the server's native port is free again");
    })
    .await
    .expect("composition deadline");
}
