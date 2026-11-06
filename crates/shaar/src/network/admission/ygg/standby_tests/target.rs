// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
//! Loopback echo target standing in for the service behind the server.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};

const MAX_ECHOES: usize = 16;
const MAX_ECHO_BYTES: u64 = 128 * 1024;

/// Echo service on a fresh loopback port.
///
/// One owned task accepts and keeps every connection in its own `JoinSet`;
/// `stop` signals it and joins it, so nothing outlives the test. Accepted and
/// finished connections are published as counters on `watch` channels, so a test
/// waits for the event itself instead of guessing a delay.
pub(super) struct Target {
    /// Address the server's `serve` forwards to.
    pub(super) addr: SocketAddr,
    /// Connections accepted so far; proves which server path reached the target.
    pub(super) accepts: Arc<AtomicUsize>,
    accepted: watch::Receiver<usize>,
    closed: watch::Receiver<usize>,
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl Target {
    /// cancel-safe: yes — the task is spawned only after the bind completes, so a
    /// cancelled start leaves nothing behind.
    pub(super) async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("target binds");
        let addr = listener.local_addr().expect("target address");
        let accepts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepts);
        let (accepted_tx, accepted) = watch::channel(0usize);
        let (closed_tx, closed) = watch::channel(0usize);
        let closed_tx = Arc::new(closed_tx);
        let (stop, mut stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let mut echoes = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = &mut stopped => break,
                    Some(result) = echoes.join_next(), if !echoes.is_empty() => {
                        result.expect("echo task joins without panic");
                    }
                    incoming = listener.accept(), if echoes.len() < MAX_ECHOES => {
                        let (socket, _) = incoming.expect("target accepts");
                        counter.fetch_add(1, Ordering::SeqCst);
                        accepted_tx.send_modify(|count| *count += 1);
                        let closed_tx = Arc::clone(&closed_tx);
                        echoes.spawn(async move {
                            // A forced path outage may reset a connection; the
                            // application side is the oracle, not this echo.
                            let _ = echo(socket).await;
                            closed_tx.send_modify(|count| *count += 1);
                        });
                    }
                }
            }
            // Abort and join in-flight echoes so no connection outlives the target.
            echoes.shutdown().await;
        });
        Self {
            addr,
            accepts,
            accepted,
            closed,
            stop,
            task,
        }
    }

    /// Returns once at least `n` connections were accepted. The counter is
    /// level-triggered, so an accept that happened earlier is still observed.
    /// cancel-safe: yes — it holds a private receiver and consumes nothing.
    pub(super) async fn wait_accepted(&self, n: usize) {
        let mut seen = self.accepted.clone();
        seen.wait_for(|count| *count >= n)
            .await
            .expect("target task alive while waiting for accepts");
    }

    /// Returns once at least `n` accepted connections ended, whether the peer
    /// finished them or the path reset them. cancel-safe: yes, as `wait_accepted`.
    pub(super) async fn wait_closed(&self, n: usize) {
        let mut seen = self.closed.clone();
        seen.wait_for(|count| *count >= n)
            .await
            .expect("target task alive while waiting for closes");
    }

    /// Connections that ended so far.
    pub(super) fn closed_count(&self) -> usize {
        *self.closed.borrow()
    }

    /// Signals the task and joins it. cancel-safe: NO — a cancelled stop leaves the
    /// join handle dropped, which detaches the task until its stop signal is seen.
    pub(super) async fn stop(self) {
        let _ = self.stop.send(());
        self.task.await.expect("target task joins");
    }
}

#[tokio::test]
async fn echo_input_limit_accepts_boundary_and_rejects_one_extra_byte() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let target = Target::start().await;
        let limit = usize::try_from(MAX_ECHO_BYTES).expect("fixture limit fits usize");
        let payload = vec![0x5a; limit + 1];
        let mut valid = TcpStream::connect(target.addr)
            .await
            .expect("valid client connects");
        valid
            .write_all(&payload[..limit])
            .await
            .expect("boundary writes");
        valid.shutdown().await.expect("boundary half-closes");
        let mut echoed = Vec::new();
        valid
            .take(MAX_ECHO_BYTES + 1)
            .read_to_end(&mut echoed)
            .await
            .expect("boundary echoes");
        assert_eq!(echoed.as_slice(), &payload[..limit]);
        target.wait_closed(1).await;

        let mut oversized = TcpStream::connect(target.addr)
            .await
            .expect("oversize client connects");
        oversized
            .write_all(&payload)
            .await
            .expect("oversize writes");
        let _ = oversized.shutdown().await;
        echoed.clear();
        let _ = oversized
            .take(MAX_ECHO_BYTES + 1)
            .read_to_end(&mut echoed)
            .await;
        assert!(echoed.is_empty(), "oversized input must not be echoed");
        target.wait_closed(2).await;
        assert_eq!(target.accepts.load(Ordering::SeqCst), 2);
        target.stop().await;
    })
    .await
    .expect("bounded echo fixture deadline");
}

/// Echoes one connection after the peer half-closes.
async fn echo(mut socket: TcpStream) -> io::Result<()> {
    let mut bytes = Vec::new();
    (&mut socket)
        .take(MAX_ECHO_BYTES + 1)
        .read_to_end(&mut bytes)
        .await?;
    if u64::try_from(bytes.len()).expect("bounded echo size") > MAX_ECHO_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "echo input limit",
        ));
    }
    socket.write_all(&bytes).await?;
    socket.shutdown().await
}
