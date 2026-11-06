// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
//! Server-side owned tasks for the standby fixture: a native and a Yggdrasil server.

use std::net::SocketAddr;
use std::time::Instant;

use iroh_base::PublicKey;
use shaar_ygg::YggPump;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};

use super::super::YggEndpoint;
use crate::identity::Identity;
use crate::network::{Allowlist, Endpoint, Limits, NetworkError, ServeReport, Session};

/// What a server task saw by the time it stopped.
#[derive(Debug)]
pub(super) struct ServerSummary {
    /// Sessions that passed the handshake and allowlist.
    pub(super) accepted: usize,
    /// Accept attempts that ended in an error other than closure.
    pub(super) denied: usize,
    /// Reports of the `serve` calls that ended without a protocol error.
    pub(super) reports: Vec<ServeReport>,
}

/// Per-session `serve` tasks of one server, all stopped by one watch signal.
struct Serving {
    tasks: JoinSet<Option<ServeReport>>,
    halt: watch::Sender<bool>,
    target: SocketAddr,
    events: mpsc::Sender<Instant>,
    accepted: usize,
    denied: usize,
}

impl Serving {
    fn new(target: SocketAddr, events: mpsc::Sender<Instant>) -> Self {
        Self {
            tasks: JoinSet::new(),
            halt: watch::channel(false).0,
            target,
            events,
            accepted: 0,
            denied: 0,
        }
    }

    /// Hands the session to a `JoinSet` task; a full event queue drops the event.
    fn admit(&mut self, mut session: Session) {
        self.accepted += 1;
        let _ = self.events.try_send(Instant::now());
        let mut halt = self.halt.subscribe();
        let target = self.target;
        self.tasks.spawn(async move {
            let stop = async {
                let _ = halt.wait_for(|stopped| *stopped).await;
            };
            session.serve(target, stop).await.ok()
        });
    }

    /// Signals every `serve` task and joins them; `serve` closes its own session.
    async fn finish(mut self) -> ServerSummary {
        self.halt.send_replace(true);
        let mut reports = Vec::new();
        while let Some(joined) = self.tasks.join_next().await {
            if let Some(report) = joined.expect("serve task joins") {
                reports.push(report);
            }
        }
        ServerSummary {
            accepted: self.accepted,
            denied: self.denied,
            reports,
        }
    }
}

/// Native-path server: one owned task over a native `Endpoint`.
pub(super) struct NativeServer {
    stop: oneshot::Sender<()>,
    task: JoinHandle<ServerSummary>,
}

impl NativeServer {
    /// Binds with an allowlist and starts the accept task.
    /// cancel-safe: NO — a cancelled bind must not be treated as startup; the task
    /// is spawned only after the bind completed.
    pub(super) async fn start(
        identity: &Identity,
        bind: SocketAddr,
        allowed: &[PublicKey],
        target: SocketAddr,
    ) -> (Self, SocketAddr, mpsc::Receiver<Instant>) {
        let mut endpoint = Endpoint::bind(
            identity,
            bind,
            Allowlist::new(allowed).expect("allowlist"),
            Limits::new(4).expect("limits"),
        )
        .await
        .expect("native server binds");
        let local = endpoint.local_addr();
        let (events, accepted) = mpsc::channel(16);
        let (stop, mut stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let mut serving = Serving::new(target, events);
            loop {
                tokio::select! {
                    biased;
                    _ = &mut stopped => break,
                    // A handshake consumed by a cancelled accept is not replayed;
                    // acceptable because the server is stopping.
                    result = endpoint.accept() => match result {
                        Ok(session) => serving.admit(session),
                        Err(NetworkError::Closed) => break,
                        Err(_) => serving.denied += 1,
                    },
                }
            }
            let summary = serving.finish().await;
            endpoint.close().await;
            summary
        });
        (Self { stop, task }, local, accepted)
    }

    /// Signals the task and joins it for the summary.
    /// cancel-safe: NO — dropping the future drops the join handle and detaches.
    pub(super) async fn stop(self) -> ServerSummary {
        let _ = self.stop.send(());
        self.task.await.expect("native server task joins")
    }
}

/// Yggdrasil-path server: one owned task over a `YggEndpoint` and its pump.
pub(super) struct YggServer {
    stop: oneshot::Sender<()>,
    task: JoinHandle<ServerSummary>,
}

impl YggServer {
    /// Takes both owners; the task polls `pump.run()` so the carrier writer runs.
    /// A finished pump panics the task, which `stop` surfaces when joining.
    pub(super) fn start(
        endpoint: YggEndpoint,
        pump: YggPump,
        target: SocketAddr,
    ) -> (Self, mpsc::Receiver<Instant>) {
        let (events, accepted) = mpsc::channel(16);
        let (stop, mut stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let mut endpoint = endpoint;
            let mut pump = pump;
            let mut serving = Serving::new(target, events);
            loop {
                tokio::select! {
                    biased;
                    _ = &mut stopped => break,
                    _ = pump.run() => panic!("ygg server writer stopped"),
                    result = endpoint.accept() => match result {
                        Ok(session) => serving.admit(session),
                        Err(NetworkError::Closed) => break,
                        Err(_) => serving.denied += 1,
                    },
                }
            }
            let summary = serving.finish().await;
            endpoint.close(&mut pump).await.expect("ygg server closes");
            summary
        });
        (Self { stop, task }, accepted)
    }

    /// Signals the task and joins it for the summary.
    /// cancel-safe: NO — dropping the future drops the join handle and detaches.
    pub(super) async fn stop(self) -> ServerSummary {
        let _ = self.stop.send(());
        self.task.await.expect("ygg server task joins")
    }
}
