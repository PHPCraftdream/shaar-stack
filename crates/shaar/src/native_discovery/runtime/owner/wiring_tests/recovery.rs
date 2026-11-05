// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::super::endpoint_key;
use super::super::tests::fixture::LoopbackPeer;
use super::composition::{DiscoveredDial, tcp_pair};
use super::connect::{server, signed_record_at};
use super::{RECORD_WALL_US, bind_controlled, free_port, options, peer_v4};
use crate::identity::Identity;
use crate::network::{ForwardStats, Session};
use crate::path::{DialError, Dialer, PathKind, PathOwner, PolicyConfig};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::oneshot;
use tokio::time::Instant;

/// A test gate controls only recovery admission, never QUIC or discovery results.
struct GatedDial {
    native: DiscoveredDial,
    resume: oneshot::Receiver<()>,
    loss_seen: Option<oneshot::Sender<()>>,
    initial: bool,
    released: bool,
}

impl Dialer for GatedDial {
    type Link = Session;

    async fn dial(&mut self, deadline: Instant) -> Result<Session, DialError> {
        if !self.initial && !self.released {
            (&mut self.resume).await.map_err(|_| DialError)?;
            self.released = true;
        }
        self.initial = false;
        self.native.dial(deadline).await
    }

    async fn lost(&mut self, link: &Session) {
        self.native.lost(link).await;
        if let Some(seen) = self.loss_seen.take() {
            seen.send(()).expect("loss observer waits");
        }
    }

    async fn close(&mut self) -> Result<(), DialError> {
        self.native.close().await
    }
}

async fn exchange(session: &Session, accepted: &mut Session, payload: &[u8]) {
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("target binds");
    let address = target.local_addr().expect("target address");
    let (mut app, bridge) = tcp_pair().await;
    let (stop, stopped) = oneshot::channel();
    let application = async {
        app.write_all(payload).await.expect("app writes");
        app.shutdown().await.expect("app half-closes");
        let mut echoed = Vec::new();
        app.read_to_end(&mut echoed).await.expect("app reads");
        assert_eq!(echoed, payload);
    };
    let service = async {
        let (mut tcp, _) = target.accept().await.expect("target accepts");
        let mut bytes = Vec::new();
        tcp.read_to_end(&mut bytes).await.expect("target reads");
        assert_eq!(bytes, payload);
        tcp.write_all(&bytes).await.expect("target echoes");
        tcp.shutdown().await.expect("target half-closes");
    };
    let forward = async {
        let (stats, (), ()) = tokio::join!(session.forward(bridge), application, service);
        stop.send(()).expect("server is waiting");
        stats.expect("forwarded")
    };
    let (report, stats) = tokio::join!(
        accepted.serve(address, async {
            stopped.await.expect("stop signal");
        }),
        forward,
    );
    let size = u64::try_from(payload.len()).expect("small payload");
    assert_eq!(
        stats,
        ForwardStats {
            to_peer: size,
            from_peer: size
        }
    );
    let report = report.expect("served");
    assert_eq!(report.completed + report.failed + report.cancelled, 1);
}

#[tokio::test]
async fn actual_peer_closure_recovers_a_new_stream_at_the_same_key_and_address() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut peer = LoopbackPeer::bind().await;
        let client = bind_controlled(
            free_port().await,
            options(free_port().await, peer_v4(&peer)),
        )
        .await
        .expect("client binds");
        let client_address = client.local_addr();
        let client_id = client.id();
        let identity = Identity::from_seed([0x65; 32]);
        let key = endpoint_key(&identity).expect("key");
        let mut server = server(0x65, client_id).await;
        let server_address = server.local_addr();
        let item = signed_record_at(&identity, server_address, RECORD_WALL_US);
        let (resume, resumed) = oneshot::channel();
        let (loss_seen, seen) = oneshot::channel();
        let mut owner = PathOwner::new(
            GatedDial {
                native: DiscoveredDial {
                    endpoint: client,
                    expected: key,
                },
                resume: resumed,
                loss_seen: Some(loss_seen),
                initial: true,
                released: false,
            },
            PolicyConfig {
                loss_grace: 200,
                attempt_timeout: 5_000,
                backoff_base: 100,
                backoff_cap: 1_000,
                max_attempts: 4,
                ..PolicyConfig::default()
            },
        )
        .expect("config");
        let (established, accepted) = tokio::join!(
            async {
                tokio::select! {
                    result = owner.establish() => result,
                    _ = peer.serve_record(&item) => unreachable!("record server stays live"),
                }
            },
            server.accept(),
        );
        established.expect("initial native path");
        let mut accepted = accepted.expect("initial session accepted");
        exchange(
            owner.payload().expect("initial payload"),
            &mut accepted,
            b"before loss",
        )
        .await;
        accepted.close();
        {
            let recovery = owner.maintain();
            tokio::pin!(recovery);
            tokio::select! {
                result = &mut recovery => panic!("recovery admission is gated: {result:?}"),
                result = seen => result.expect("real session closure observed"),
            }
        }
        assert!(
            owner.payload().is_none(),
            "lost session is no longer payload"
        );
        resume.send(()).expect("recovery gate is retained");
        let (recovered, accepted) = tokio::join!(
            async {
                tokio::select! {
                    result = owner.maintain() => result,
                    _ = peer.serve_record(&item) => unreachable!("same record server stays live"),
                }
            },
            server.accept(),
        );
        recovered.expect("native recovered");
        let mut accepted = accepted.expect("new session accepted");
        let session = owner.payload().expect("new native payload");
        assert_eq!(owner.active(), Some(PathKind::Native));
        assert_eq!(session.peer_id(), key);
        assert_eq!(accepted.peer_id(), client_id);
        assert_eq!(server.local_addr(), server_address);
        exchange(session, &mut accepted, b"after recovery: new stream").await;
        owner.close().await.expect("owner joined");
        drop(accepted);
        server.close().await;
        let _client_rebound = UdpSocket::bind(client_address)
            .await
            .expect("client port released");
        let _server_rebound = UdpSocket::bind(server_address)
            .await
            .expect("server port released");
    })
    .await
    .expect("bounded real recovery scenario");
}
