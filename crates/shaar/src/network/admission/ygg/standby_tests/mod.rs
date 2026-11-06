// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
//! Real-transport fixture for the standby path owner: a native and a Yggdrasil
//! route to one server, counted dialers, an echo target and exact-forward helpers.
//! Seeds of this module stay inside 0xC1..0xC9; every task is owned and joined.

mod denial;
mod forwarding;
mod outage;
mod servers;
mod target;

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use iroh_base::{CustomAddr, PublicKey, TransportAddr};
use shaar_ygg::{YggBridge, YggTransport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout_at};

use super::fallback::YggFallback;
use super::tests::{config, dialer, identity, listener};
use crate::identity::Identity;
use crate::network::{Endpoint, ForwardStats, Session};
use crate::path::{DialError, Dialer, PolicyConfig};

use servers::{NativeServer, YggServer};
use target::Target;

/// Native client dialer toward one server address.
///
/// It owns the client endpoint. `close` is resumable without spawning: the
/// endpoint's by-value close future is retained in `closing` and re-polled by
/// later calls. Dropping the dialer is the abort-only path, like the SDK's. The
/// retained future is not `Send` on purpose: the owner polls it inline.
pub(super) struct NativeDial {
    endpoint: Option<Endpoint>,
    closing: Option<Pin<Box<dyn Future<Output = ()>>>>,
    peer: PublicKey,
    native: SocketAddr,
    dials: Arc<AtomicUsize>,
    dial_ok: Arc<Mutex<Vec<Instant>>>,
}

impl NativeDial {
    /// `dials` counts every `dial` call, including ones that later fail; `dial_ok`
    /// logs the completion instant of every dial that produced a session.
    pub(super) fn new(
        endpoint: Endpoint,
        peer: PublicKey,
        native: SocketAddr,
        dials: Arc<AtomicUsize>,
        dial_ok: Arc<Mutex<Vec<Instant>>>,
    ) -> Self {
        Self {
            endpoint: Some(endpoint),
            closing: None,
            peer,
            native,
            dials,
            dial_ok,
        }
    }
}

impl Dialer for NativeDial {
    type Link = Session;

    /// cancel-safe: yes — a cancelled connect only abandons the attempt.
    async fn dial(&mut self, deadline: Instant) -> Result<Session, DialError> {
        self.dials.fetch_add(1, Ordering::SeqCst);
        let endpoint = self.endpoint.as_ref().ok_or(DialError)?;
        let session = timeout_at(deadline, endpoint.connect(self.peer, self.native))
            .await
            .map_err(|_| DialError)?
            .map_err(|_| DialError)?;
        // Recorded before the link is handed over, so the owner's NativeUp
        // observation can never precede this instant. No await follows the lock.
        self.dial_ok
            .lock()
            .expect("dial log lock")
            .push(Instant::now());
        Ok(session)
    }

    /// cancel-safe: yes — level-triggered on the session.
    async fn lost(&mut self, link: &Session) {
        let _ = link.closed().await;
    }

    /// cancel-safe: yes — the retained close future resumes on the next call.
    async fn close(&mut self) -> Result<(), DialError> {
        if let Some(endpoint) = self.endpoint.take() {
            self.closing = Some(Box::pin(endpoint.close()));
        }
        if let Some(closing) = self.closing.as_mut() {
            closing.await;
            self.closing = None;
        }
        Ok(())
    }
}

/// Fallback dialer that counts dials by delegating to the real `YggFallback`.
pub(super) struct CountedFallback {
    inner: YggFallback,
    dials: Arc<AtomicUsize>,
}

/// Handles taken from the fallback before the owner takes it over.
pub(super) struct Probe {
    /// Endpoint admission semaphore, to prove charges are released.
    pub(super) slots: Arc<Semaphore>,
    /// Custom address of the peer, for path-frame oracles.
    pub(super) peer_address: CustomAddr,
    /// Local Yggdrasil endpoint identity.
    pub(super) endpoint_id: PublicKey,
}

/// Wraps `fallback` and captures its probe handles; the wrapper then moves into
/// the owner. `dials` counts every fallback dial.
pub(super) fn counted(
    fallback: YggFallback,
    peer: PublicKey,
    dials: Arc<AtomicUsize>,
) -> (CountedFallback, Probe) {
    let probe = Probe {
        slots: fallback.slots(),
        peer_address: fallback.peer_address(&peer).expect("peer custom address"),
        endpoint_id: fallback.endpoint_id(),
    };
    (
        CountedFallback {
            inner: fallback,
            dials,
        },
        probe,
    )
}

impl Dialer for CountedFallback {
    type Link = Session;

    /// cancel-safe: yes — as the inner fallback dial.
    async fn dial(&mut self, deadline: Instant) -> Result<Session, DialError> {
        self.dials.fetch_add(1, Ordering::SeqCst);
        self.inner.dial(deadline).await
    }

    /// cancel-safe: yes — as the inner fallback.
    async fn lost(&mut self, link: &Session) {
        self.inner.lost(link).await
    }

    /// cancel-safe: yes — the inner close is resumable.
    async fn close(&mut self) -> Result<(), DialError> {
        self.inner.close().await
    }
}

/// Short, valid policy timings so outage scenarios finish in seconds.
pub(super) fn test_config() -> PolicyConfig {
    let config = PolicyConfig {
        loss_grace: 300,
        attempt_timeout: 1500,
        backoff_base: 100,
        backoff_cap: 400,
        max_attempts: 6,
        stable_hold: 1200,
    };
    config.validate().expect("test policy config is valid");
    config
}

/// Connected loopback TCP pair `(app side, bridge side)`; the caller owns both.
/// cancel-safe: yes — nothing outlives a cancelled call.
pub(super) async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("pair listener binds");
    let address = listener.local_addr().expect("pair address");
    let (app, bridge) = tokio::join!(TcpStream::connect(address), listener.accept());
    (
        app.expect("app connects"),
        bridge.expect("bridge accepts").0,
    )
}

/// Forwards `payload` through `session` to the echo target behind the server and
/// asserts the exact echo and byte counts. The app half-closes after writing and
/// reads concurrently, so any payload size is safe. cancel-safe: NO.
pub(super) async fn forward_exact(session: &Session, payload: &[u8]) -> ForwardStats {
    let (app, bridge) = tcp_pair().await;
    let (mut read, mut write) = app.into_split();
    let writing = async {
        write.write_all(payload).await.expect("app writes");
        write.shutdown().await.expect("app half-closes");
    };
    let reading = async {
        let mut bytes = Vec::new();
        read.read_to_end(&mut bytes).await.expect("app reads");
        assert_eq!(bytes.as_slice(), payload);
    };
    let (stats, (), ()) = tokio::join!(session.forward(bridge), writing, reading);
    let stats = stats.expect("forwarded");
    let size = u64::try_from(payload.len()).expect("payload length");
    assert_eq!(stats.to_peer, size);
    assert_eq!(stats.from_peer, size);
    stats
}

/// Two connected Yggdrasil bridges `(server, client, listener port)`; the caller
/// closes both bridges last, after every endpoint and pump has closed.
/// cancel-safe: NO — a cancelled call drops started transports.
pub(super) async fn ygg_pair(server_seed: u8, client_seed: u8) -> (YggBridge, YggBridge, u16) {
    let (server_transport, port) = listener(server_seed).await;
    let client_transport = dialer(client_seed, port).await;
    let server_bridge =
        YggBridge::new(server_transport, [identity(client_seed).public_key_bytes()]);
    let client_bridge =
        YggBridge::new(client_transport, [identity(server_seed).public_key_bytes()]);
    (server_bridge, client_bridge, port)
}

/// Proves the Yggdrasil listener port and key claim are released by starting a
/// fresh transport on them and closing it. cancel-safe: NO.
pub(super) async fn ygg_released(seed: u8, port: u16) {
    let transport = YggTransport::start(config(
        seed,
        vec![format!("tcp://127.0.0.1:{port}")],
        vec![],
    ))
    .await
    .expect("Ygg port and key are released");
    transport
        .close()
        .await
        .expect("replacement transport closes");
}

/// Proves each native UDP address can be rebound after a joined close.
pub(super) async fn native_released(addrs: &[SocketAddr]) {
    for address in addrs {
        let _rebound = UdpSocket::bind(address).await.expect("UDP released");
    }
}

/// One identity must be the native, the Yggdrasil and the transport key.
pub(super) fn assert_same_identity(identity: &Identity, native: &PublicKey, ygg: &PublicKey) {
    let expected = identity.transport_key().public();
    assert_eq!(native, &expected);
    assert_eq!(ygg, &expected);
}

/// Every path of `session` is a native IP path and carried STREAM frames both ways.
pub(super) fn native_only(session: &Session) {
    let (mut tx, mut rx) = (false, false);
    for path in session.connection.paths().iter() {
        let remote = path.remote_addr();
        assert!(
            matches!(remote, TransportAddr::Ip(_)),
            "non-native path {remote:?}"
        );
        let stats = path.stats();
        tx |= stats.frame_tx.stream > 0;
        rx |= stats.frame_rx.stream > 0;
    }
    assert!(tx && rx, "native path carried no STREAM frames");
}
