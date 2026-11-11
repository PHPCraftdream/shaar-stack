// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
//! One-client loopback UDP gate for real silent native packet loss.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::Instant;

pub(in crate::network) struct NativeGate {
    pub(in crate::network) address: SocketAddr,
    blocked: Arc<AtomicBool>,
    stop: oneshot::Sender<()>,
    task: JoinHandle<(usize, usize)>,
}

impl NativeGate {
    /// cancel-safe: YES — no task exists until both owned loopback binds finish.
    pub(in crate::network) async fn start(upstream: SocketAddr) -> Self {
        assert!(upstream.ip().is_loopback() && upstream.is_ipv4());
        let front = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("gate front binds");
        let back = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("gate back binds");
        let address = front.local_addr().expect("gate address");
        let blocked = Arc::new(AtomicBool::new(false));
        let state = Arc::clone(&blocked);
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut from_client = vec![0_u8; 65_536];
            let mut from_server = vec![0_u8; 65_536];
            let mut client = None;
            let (mut passed, mut dropped) = (0, 0);
            loop {
                tokio::select! {
                    biased;
                    _ = &mut stopped => break,
                    received = front.recv_from(&mut from_client) => {
                        let (size, source) = received.expect("gate receives client packet");
                        assert!(source.ip().is_loopback());
                        assert_eq!(*client.get_or_insert(source), source, "one pinned client per gate");
                        if state.load(Ordering::SeqCst) {
                            dropped += 1;
                        } else {
                            back.send_to(&from_client[..size], upstream).await.expect("gate passes upstream");
                            passed += 1;
                        }
                    }
                    received = back.recv_from(&mut from_server) => {
                        let (size, source) = received.expect("gate receives server packet");
                        assert_eq!(source, upstream, "only the owned upstream may reply");
                        if state.load(Ordering::SeqCst) {
                            dropped += 1;
                        } else {
                            front.send_to(&from_server[..size], client.expect("client preceded reply")).await
                                .expect("gate passes downstream");
                            passed += 1;
                        }
                    }
                }
            }
            (passed, dropped)
        });
        Self {
            address,
            blocked,
            stop,
            task,
        }
    }

    /// Starts silent loss without closing either endpoint or emitting an error.
    pub(in crate::network) fn block(&self) -> Instant {
        let started = Instant::now();
        self.blocked.store(true, Ordering::SeqCst);
        started
    }

    /// cancel-safe: NO — consumes the join handle; callers retain this stop to completion.
    pub(in crate::network) async fn stop(self) -> (usize, usize) {
        let _ = self.stop.send(());
        self.task.await.expect("gate task joins")
    }
}
