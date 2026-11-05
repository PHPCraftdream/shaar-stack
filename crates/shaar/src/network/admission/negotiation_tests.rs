// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use iroh_base::{PublicKey, TransportAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout, timeout_at};

use crate::identity::Identity;
use crate::network::signaling::SignaledEndpoint;
use crate::network::{ForwardStats, Limits, NetworkError, Session};
use crate::path::{DialError, Dialer, Negotiating, Negotiation, PathKind, PathOwner, PolicyConfig};

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().expect("loopback")
}

struct NativeDial {
    endpoint: Option<SignaledEndpoint>,
    closing: Option<JoinHandle<Result<(), NetworkError>>>,
    peer: PublicKey,
    native: SocketAddr,
    signaling: SocketAddr,
    negotiations: Arc<AtomicUsize>,
    completed: Arc<AtomicUsize>,
}

impl Dialer for NativeDial {
    type Link = Session;

    async fn dial(&mut self, deadline: Instant) -> Result<Session, DialError> {
        let endpoint = self.endpoint.as_ref().ok_or(DialError)?;
        timeout_at(deadline, endpoint.connect(self.peer, self.native))
            .await
            .map_err(|_| DialError)?
            .map_err(|_| DialError)
    }

    async fn lost(&mut self, link: &Session) {
        let _ = link.closed().await;
    }

    async fn close(&mut self) -> Result<(), DialError> {
        if let Some(endpoint) = self.endpoint.take() {
            // Retained across cancellation; Drop aborts, successful close joins.
            self.closing = Some(tokio::spawn(endpoint.close()));
        }
        if let Some(handle) = self.closing.as_mut() {
            let result = handle.await;
            self.closing = None;
            result.map_err(|_| DialError)?.map_err(|_| DialError)?;
        }
        Ok(())
    }
}

impl Negotiation for NativeDial {
    async fn negotiate(&mut self, deadline: Instant) -> Result<(), DialError> {
        self.negotiations.fetch_add(1, Ordering::SeqCst);
        let endpoint = self.endpoint.as_ref().ok_or(DialError)?;
        let control = timeout_at(
            deadline,
            endpoint.connect_signaling(self.peer, self.signaling),
        )
        .await
        .map_err(|_| DialError)?
        .map_err(|_| DialError)?;
        assert_eq!(control.peer_id(), self.peer);
        self.completed.fetch_add(1, Ordering::SeqCst);
        control.close();
        Ok(())
    }
}

impl Drop for NativeDial {
    fn drop(&mut self) {
        if let Some(handle) = self.closing.take() {
            handle.abort();
        }
    }
}

async fn endpoints() -> (SignaledEndpoint, SignaledEndpoint) {
    let a = Identity::from_seed([0x91; 32]);
    let b = Identity::from_seed([0x92; 32]);
    let pa = a.transport_key().public();
    let pb = b.transport_key().public();
    let server = SignaledEndpoint::bind(&b, loopback(), loopback(), &[pa], Limits::default())
        .await
        .expect("server binds");
    let client = SignaledEndpoint::bind(&a, loopback(), loopback(), &[pb], Limits::default())
        .await
        .expect("client binds");
    (client, server)
}

async fn exchange(session: &Session, accepted: &mut Session, payload: &[u8]) {
    let target = TcpListener::bind(loopback()).await.expect("target binds");
    let target_address = target.local_addr().expect("target address");
    let app_listener = TcpListener::bind(loopback())
        .await
        .expect("app listener binds");
    let app_address = app_listener.local_addr().expect("app address");
    let (app, bridge) = tokio::join!(TcpStream::connect(app_address), app_listener.accept());
    let mut app = app.expect("app connects");
    let bridge = bridge.expect("bridge accepts").0;
    let (stop, stopped) = oneshot::channel();
    let application = async {
        app.write_all(payload).await.expect("app writes");
        app.shutdown().await.expect("app half-closes");
        let mut bytes = Vec::new();
        app.read_to_end(&mut bytes).await.expect("app reads");
        assert_eq!(bytes, payload);
    };
    let service = async {
        let (mut socket, _) = target.accept().await.expect("target accepts");
        let mut bytes = Vec::new();
        socket.read_to_end(&mut bytes).await.expect("target reads");
        assert_eq!(bytes, payload);
        socket.write_all(&bytes).await.expect("target echoes");
        socket.shutdown().await.expect("target half-closes");
    };
    let forward = async {
        let (stats, (), ()) = tokio::join!(session.forward(bridge), application, service);
        stop.send(()).expect("serve waits");
        stats.expect("forwarded")
    };
    let (report, stats) = tokio::join!(
        accepted.serve(target_address, async {
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

async fn ports_released(native: [SocketAddr; 2], signaling: [SocketAddr; 2]) {
    for address in native {
        let _rebound = UdpSocket::bind(address).await.expect("joined UDP release");
    }
    for address in signaling {
        let _rebound = TcpListener::bind(address)
            .await
            .expect("joined TCP release");
    }
}

async fn recovery(valid_hint: bool) {
    timeout(Duration::from_secs(60), async {
        let (client, mut server) = endpoints().await;
        let client_id = client.id();
        let server_id = server.id();
        let native = [client.local_addr(), server.local_addr()];
        let signaling = [client.signaling_addr(), server.signaling_addr()];
        let hint = if valid_hint {
            signaling[1]
        } else {
            let unused = TcpListener::bind(loopback()).await.expect("unused hint");
            let hint = unused.local_addr().expect("unused address");
            drop(unused);
            hint
        };
        let negotiations = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let dial = NativeDial {
            endpoint: Some(client),
            closing: None,
            peer: server_id,
            native: native[1],
            signaling: hint,
            negotiations: Arc::clone(&negotiations),
            completed: Arc::clone(&completed),
        };
        let mut owner = PathOwner::new(
            Negotiating::new(dial),
            PolicyConfig {
                attempt_timeout: 10_000,
                ..PolicyConfig::default()
            },
        )
        .expect("config");
        let (connected, accepted) = tokio::join!(owner.establish(), server.accept());
        connected.expect("healthy native");
        let mut accepted = accepted.expect("native accepted");
        exchange(
            owner.payload().expect("healthy payload"),
            &mut accepted,
            b"healthy native",
        )
        .await;
        assert_eq!(
            negotiations.load(Ordering::SeqCst),
            0,
            "healthy path never negotiates"
        );
        accepted.close();
        let (recovered, accepted) = tokio::join!(owner.maintain(), async {
            if valid_hint {
                let control = server.accept().await.expect("control negotiation accepted");
                assert_eq!(control.peer_id(), client_id);
                assert!(matches!(control.closed().await, NetworkError::Closed));
                drop(control);
            }
            server.accept().await
        });
        recovered.expect("native recovers even if signaling fails");
        let mut accepted = accepted.expect("recovered native accepted");
        assert_eq!(owner.active(), Some(PathKind::Native));
        assert_eq!(
            owner.payload().expect("native payload").peer_id(),
            server_id
        );
        assert_eq!(accepted.peer_id(), client_id);
        assert_eq!(negotiations.load(Ordering::SeqCst), 1);
        assert_eq!(completed.load(Ordering::SeqCst), usize::from(valid_hint));
        exchange(
            owner.payload().expect("native payload"),
            &mut accepted,
            b"recovered native",
        )
        .await;
        owner.close().await.expect("client joined");
        drop(accepted);
        server.close().await.expect("server joined");
        ports_released(native, signaling).await;
    })
    .await
    .expect("bounded signaling recovery");
}

#[tokio::test]
async fn actual_down_window_negotiates_then_restores_native_only_payload() {
    recovery(true).await;
}

#[tokio::test]
async fn failed_signaling_hint_cannot_prevent_native_recovery() {
    recovery(false).await;
}

async fn no_application_bytes(sender: &Session, receiver: &Session) {
    assert!(
        sender
            .connection
            .paths()
            .iter()
            .any(|path| matches!(path.remote_addr(), TransportAddr::Custom(_))),
        "the control session must have a signaling path"
    );
    assert!(
        sender
            .connection
            .paths()
            .iter()
            .all(|path| matches!(path.remote_addr(), TransportAddr::Custom(_))),
        "the rejection oracle must have no native path"
    );
    enum Observation {
        NoStream,
        NoBytes(&'static str),
        Delivered(u8),
        Failed(String),
    }
    let response = timeout(Duration::from_secs(2), async {
        let (mut stream, response) = sender
            .connection
            .open_bi()
            .await
            .expect("bidi credit exists");
        stream
            .write_all(b"not allowed on signaling")
            .await
            .expect("local bidi write accepted");
        stream.finish().expect("local bidi finish accepted");
        response
    })
    .await
    .expect("the no-payload oracle must attempt an allowed bidi write");
    let observation =
        match timeout(Duration::from_millis(300), receiver.connection.accept_bi()).await {
            Err(_) => Observation::NoStream,
            Ok(Err(error)) => Observation::Failed(format!("accept: {error:?}")),
            Ok(Ok((reply, mut incoming))) => {
                let mut byte = [0u8; 1];
                let observed =
                    match timeout(Duration::from_millis(150), incoming.read(&mut byte)).await {
                        Err(_) => Observation::NoBytes("read pending"),
                        Ok(Ok(None)) => Observation::NoBytes("EOF"),
                        Ok(Ok(Some(0))) => Observation::NoBytes("empty read"),
                        Ok(Ok(Some(_))) => Observation::Delivered(byte[0]),
                        Ok(Err(error)) => Observation::Failed(format!("read: {error:?}")),
                    };
                drop(reply);
                observed
            }
        };
    assert!(
        timeout(Duration::from_millis(30), sender.closed())
            .await
            .is_err(),
        "sender control remains open"
    );
    assert!(
        timeout(Duration::from_millis(30), receiver.closed())
            .await
            .is_err(),
        "receiver control remains open"
    );
    drop(response);
    match observation {
        Observation::NoStream => eprintln!("signaling APP observation: no stream"),
        Observation::NoBytes(reason) => {
            eprintln!("signaling APP observation: stream without bytes ({reason})")
        }
        Observation::Delivered(byte) => panic!("signaling delivered an application byte: {byte}"),
        Observation::Failed(error) => panic!("no-payload observation failed: {error}"),
    }
}

#[tokio::test]
async fn live_signaling_control_delivers_zero_application_bytes_both_ways() {
    timeout(Duration::from_secs(30), async {
        let (client, mut server) = endpoints().await;
        let native = [client.local_addr(), server.local_addr()];
        let signaling = [client.signaling_addr(), server.signaling_addr()];
        let (control, accepted) = tokio::join!(
            client.connect_signaling(server.id(), server.signaling_addr()),
            server.accept(),
        );
        let control = control.expect("authenticated control");
        let accepted = accepted.expect("authenticated inbound control");
        assert_eq!(control.peer_id(), server.id());
        assert_eq!(accepted.peer_id(), client.id());
        no_application_bytes(&control, &accepted).await;
        no_application_bytes(&accepted, &control).await;
        let (direct, direct_accepted) =
            tokio::join!(client.connect(server.id(), native[1]), server.accept(),);
        let direct = direct.expect("native positive control connects");
        let mut direct_accepted = direct_accepted.expect("native positive control accepted");
        exchange(
            &direct,
            &mut direct_accepted,
            b"same endpoints: native bidi works",
        )
        .await;
        direct.close();
        direct_accepted.close();
        control.close();
        accepted.close();
        let (a, b) = tokio::join!(client.close(), server.close());
        a.expect("client joined");
        b.expect("server joined");
        ports_released(native, signaling).await;
    })
    .await
    .expect("bounded signaling-only rejection");
}
