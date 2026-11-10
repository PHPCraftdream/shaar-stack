// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
//! Exact application-frame attribution across open and closed paths of one session.

use std::future::Future;

use futures::{FutureExt, StreamExt};
use iroh::endpoint::{PathEvent, PathEventStream, PathStats};
use iroh_base::TransportAddr;
use tokio::time::{Duration, Instant, sleep_until};

use crate::network::Session;

pub(super) struct Frames {
    events: PathEventStream,
    custom_seen: bool,
    native_tx: bool,
    native_rx: bool,
}

impl Frames {
    pub(super) fn new(session: &Session) -> Self {
        // Subscribe first so a path closing before the snapshot cannot disappear.
        let mut frames = Self {
            events: session.connection.path_events(),
            custom_seen: false,
            native_tx: false,
            native_rx: false,
        };
        frames.checkpoint(session);
        assert!(
            frames.custom_seen,
            "the oracle must observe a real custom path"
        );
        frames
    }

    fn sample(&mut self, remote: &TransportAddr, stats: &PathStats) {
        match remote {
            TransportAddr::Custom(_) | TransportAddr::Relay(_) => {
                self.custom_seen |= matches!(remote, TransportAddr::Custom(_));
                assert_eq!(
                    [
                        stats.frame_tx.stream,
                        stats.frame_tx.datagram,
                        stats.frame_rx.stream,
                        stats.frame_rx.datagram
                    ],
                    [0; 4],
                    "application frames crossed signaling path {remote:?}",
                );
            }
            TransportAddr::Ip(address) => {
                assert!(
                    super::policy::native_ip(address.ip()),
                    "native evidence must be eligible"
                );
                self.native_tx |= stats.frame_tx.stream > 0;
                self.native_rx |= stats.frame_rx.stream > 0;
            }
            _ => panic!("unclassified transport in frame oracle: {remote:?}"),
        }
    }

    fn event(&mut self, event: Option<PathEvent>) {
        match event.expect("path event history ended before joined close") {
            PathEvent::Closed {
                remote_addr,
                last_stats,
                ..
            } => {
                self.sample(&remote_addr, &last_stats);
            }
            PathEvent::Opened { .. } | PathEvent::Selected { .. } => {}
            PathEvent::Lagged { missed, .. } => panic!("lost {missed} path events"),
            other => panic!("unclassified path event: {other:?}"),
        }
    }

    fn drain(&mut self) {
        while let Some(event) = self.events.next().now_or_never() {
            self.event(event);
        }
    }

    pub(super) fn checkpoint(&mut self, session: &Session) {
        self.drain();
        for path in session.connection.paths().iter() {
            self.sample(path.remote_addr(), &path.stats());
        }
        self.drain();
    }

    pub(super) async fn finish(mut self) {
        while let Some(event) = self.events.next().await {
            self.event(Some(event));
        }
        assert!(
            self.custom_seen,
            "custom path evidence retained through close"
        );
    }
}

pub(super) async fn observe<F: Future>(
    a: &mut Frames,
    b: &mut Frames,
    sender: &Session,
    receiver: &Session,
    future: F,
) -> F::Output {
    tokio::pin!(future);
    loop {
        a.checkpoint(sender);
        b.checkpoint(receiver);
        tokio::select! {
            biased;
            event = a.events.next() => a.event(event),
            event = b.events.next() => b.event(event),
            result = &mut future => {
                a.checkpoint(sender);
                b.checkpoint(receiver);
                return result;
            }
        }
    }
}

pub(super) async fn require_native_delivery(
    a: &mut Frames,
    b: &mut Frames,
    sender: &Session,
    receiver: &Session,
) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        a.checkpoint(sender);
        b.checkpoint(receiver);
        if a.native_tx && b.native_rx {
            eprintln!(
                "APP attribution: native STREAM tx/rx observed; custom STREAM/DATAGRAM tx/rx zero"
            );
            return;
        }
        tokio::select! {
            biased;
            event = a.events.next() => a.event(event),
            event = b.events.next() => b.event(event),
            () = sleep_until(deadline) => panic!("delivered byte has no native STREAM attribution"),
        }
    }
}

/// Test-only capture of the actual role sessions before application forwarding.
/// Tasks retain observation streams and registered weak close receipts, not connections.
pub(crate) struct RoleFrames(std::sync::Mutex<RoleCapture>);

struct RoleCapture {
    tasks: tokio::task::JoinSet<()>,
    count: usize,
    sealed: bool,
}

impl RoleFrames {
    pub(crate) fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self(std::sync::Mutex::new(RoleCapture {
            tasks: tokio::task::JoinSet::new(),
            count: 0,
            sealed: false,
        })))
    }

    pub(crate) fn capture(&self, session: &Session) {
        let mut capture = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            !capture.sealed,
            "session appeared after joined role shutdown"
        );
        assert!(
            capture.count < 4,
            "role-session observation capacity exceeded"
        );
        capture.count += 1;
        capture.tasks.spawn(role_observer(session));
    }

    /// cancel-safe: NO — cancelling this final check aborts its owned observation tasks.
    /// Called only after both roles have joined, so no later sessions can be captured.
    pub(crate) async fn finish(&self) {
        let mut tasks = {
            let mut capture = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(!capture.sealed, "frame capture finished twice");
            capture.sealed = true;
            assert_eq!(capture.count, 1, "expected one actual session on this role");
            std::mem::take(&mut capture.tasks)
        };
        while let Some(result) = tasks.join_next().await {
            result.expect("role frame observation failed");
        }
    }
}

struct RolePath {
    id: iroh::endpoint::PathId,
    // None marks a terminal path for which no transport event was observed.
    remote: Option<TransportAddr>,
    final_stats: Option<PathStats>,
    terminal_seen: bool,
}

struct RoleHistory {
    paths: Vec<RolePath>,
    custom: bool,
    native_tx: bool,
    native_rx: bool,
}

impl RoleHistory {
    fn new() -> Self {
        Self {
            paths: Vec::new(),
            custom: false,
            native_tx: false,
            native_rx: false,
        }
    }

    fn path(&mut self, id: iroh::endpoint::PathId, remote: &TransportAddr) -> usize {
        if let Some(index) = self.paths.iter().position(|path| path.id == id) {
            assert_eq!(
                self.paths[index].remote.as_ref(),
                Some(remote),
                "path identity changed"
            );
            return index;
        }
        assert!(self.paths.len() < 16, "path-history bound exceeded");
        match remote {
            TransportAddr::Custom(_) => self.custom = true,
            TransportAddr::Relay(_) => {}
            TransportAddr::Ip(address) => assert!(
                super::policy::native_ip(address.ip()),
                "ineligible native path in observation"
            ),
            other => panic!("unclassified role path: {other:?}"),
        }
        self.paths.push(RolePath {
            id,
            remote: Some(remote.clone()),
            final_stats: None,
            terminal_seen: false,
        });
        self.paths.len() - 1
    }

    fn stats(&mut self, index: usize, stats: &PathStats) {
        match self.paths[index].remote.as_ref() {
            Some(TransportAddr::Custom(_)) | Some(TransportAddr::Relay(_)) => assert_eq!(
                [
                    stats.frame_tx.stream,
                    stats.frame_tx.datagram,
                    stats.frame_rx.stream,
                    stats.frame_rx.datagram
                ],
                [0; 4],
                "application frames crossed signaling path"
            ),
            Some(TransportAddr::Ip(_)) => {
                self.native_tx |= stats.frame_tx.stream > 0;
                self.native_rx |= stats.frame_rx.stream > 0;
            }
            None => assert_eq!(
                [
                    stats.frame_tx.stream,
                    stats.frame_tx.datagram,
                    stats.frame_rx.stream,
                    stats.frame_rx.datagram
                ],
                [0; 4],
                "application frames crossed unclassified path"
            ),
            Some(other) => panic!("unclassified role transport: {other:?}"),
        }
    }

    fn event(&mut self, event: PathEvent) {
        match event {
            PathEvent::Opened {
                id, remote_addr, ..
            }
            | PathEvent::Selected {
                id, remote_addr, ..
            } => {
                self.path(id, &remote_addr);
            }
            PathEvent::Closed {
                id,
                remote_addr,
                last_stats,
                ..
            } => {
                let index = self.path(id, &remote_addr);
                self.stats(index, &last_stats);
                self.paths[index].final_stats = Some(*last_stats);
            }
            PathEvent::Lagged { missed, .. } => panic!("lost {missed} role path events"),
            other => panic!("unclassified path event: {other:?}"),
        }
    }

    fn terminal_parts(
        &mut self,
        terminal_paths: impl IntoIterator<Item = (iroh::endpoint::PathId, PathStats)>,
        expected_stream_tx: u64,
        expected_datagram_tx: u64,
    ) {
        // Noq terminal receipts can contain IDs without an iroh address event; keep
        // those paths unclassified and require zero APP frames.
        for (id, stats) in terminal_paths {
            let index = if let Some(index) = self.paths.iter().position(|path| path.id == id) {
                index
            } else {
                assert!(self.paths.len() < 16, "path-history bound exceeded");
                self.paths.push(RolePath {
                    id,
                    remote: None,
                    final_stats: None,
                    terminal_seen: false,
                });
                self.paths.len() - 1
            };
            assert!(
                !self.paths[index].terminal_seen,
                "duplicate terminal path statistics"
            );
            self.stats(index, &stats);
            if let Some(previous) = &self.paths[index].final_stats {
                assert_eq!(
                    previous.frame_tx.stream, stats.frame_tx.stream,
                    "TX changed after path close"
                );
                assert_eq!(
                    previous.frame_tx.datagram, stats.frame_tx.datagram,
                    "TX changed after path close"
                );
            }
            self.paths[index].final_stats = Some(stats);
            self.paths[index].terminal_seen = true;
        }
        assert!(
            self.paths.iter().all(|path| path.final_stats.is_some()),
            "observed path has no final statistics"
        );

        let mut stream_tx = 0_u64;
        let mut datagram_tx = 0_u64;
        for path in &self.paths {
            let stats = path
                .final_stats
                .as_ref()
                .expect("observed path has no final statistics");
            stream_tx = stream_tx
                .checked_add(stats.frame_tx.stream)
                .expect("bounded TX total");
            datagram_tx = datagram_tx
                .checked_add(stats.frame_tx.datagram)
                .expect("bounded TX total");
        }
        assert_eq!(
            stream_tx, expected_stream_tx,
            "incomplete STREAM TX history"
        );
        assert_eq!(
            datagram_tx, expected_datagram_tx,
            "incomplete DATAGRAM TX history"
        );
        assert!(self.custom, "no actual custom signaling path was observed");
        assert!(
            self.native_tx && self.native_rx,
            "no native STREAM round trip observed"
        );
    }
}

fn role_observer(session: &Session) -> impl Future<Output = ()> + Send + 'static + use<> {
    // Subscribe and register while the real session is alive, before it can forward APP.
    let mut events = session.connection.path_events();
    let weak = session.connection.weak_handle();
    // Register now and erase any edition-2024 opaque capture of the local weak handle.
    let closed: std::pin::Pin<
        Box<dyn Future<Output = Option<iroh::endpoint::Closed>> + Send + 'static>,
    > = Box::pin(weak.closed());
    let mut history = RoleHistory::new();
    for path in session.connection.paths().iter() {
        let index = history.path(path.id(), path.remote_addr());
        history.stats(index, &path.stats());
    }
    async move {
        let mut closed = std::pin::pin!(closed);
        let mut terminal = None;
        let mut events_done = false;
        while terminal.is_none() || !events_done {
            tokio::select! {
                receipt = &mut closed, if terminal.is_none() => {
                    terminal = Some(receipt.expect("registered weak close receipt was lost"));
                }
                event = events.next(), if !events_done => match event {
                    Some(event) => history.event(event),
                    None => events_done = true,
                }
            }
        }
        // Noq's Closed snapshots CLOSE, not RX drain. Its closed transmit branch emits
        // only ACK/CONNECTION_CLOSE. Both controlled endpoints must pass this TX check,
        // so a delayed receiver packet cannot hide an APP emission on either side.
        let terminal = terminal.expect("genuine terminal close receipt");
        let expected_stream_tx = terminal.stats.frame_tx.stream;
        let expected_datagram_tx = terminal.stats.frame_tx.datagram;
        history.terminal_parts(
            terminal.path_stats,
            expected_stream_tx,
            expected_datagram_tx,
        );
    }
}

// Oracle unit checks, not substitutes for the real two-session forwarding case.
fn role_history_with_controls() -> RoleHistory {
    let mut history = RoleHistory::new();
    history.path(
        iroh::endpoint::PathId::ZERO,
        &TransportAddr::Relay("https://relay.invalid".parse().expect("fixture relay URL")),
    );
    history.path(
        iroh::endpoint::PathId::from(1_u32),
        &TransportAddr::Custom(iroh_base::CustomAddr::from_parts(7, &[1])),
    );
    let native = history.path(
        iroh::endpoint::PathId::from(2_u32),
        &TransportAddr::Ip("127.0.0.1:443".parse().expect("fixture native address")),
    );
    let mut stats = PathStats::default();
    stats.frame_tx.stream = 1;
    stats.frame_rx.stream = 1;
    history.stats(native, &stats);
    history
}

fn terminal_paths_with_control_native() -> Vec<(iroh::endpoint::PathId, PathStats)> {
    let mut relay = PathStats::default();
    relay.frame_tx.crypto = 1;
    let mut native = PathStats::default();
    native.frame_tx.stream = 1;
    native.frame_rx.stream = 1;
    vec![
        (iroh::endpoint::PathId::ZERO, relay),
        (iroh::endpoint::PathId::from(1_u32), PathStats::default()),
        (iroh::endpoint::PathId::from(2_u32), native),
    ]
}

#[test]
fn unknown_terminal_control_path_is_retained_with_independent_controls() {
    let mut history = role_history_with_controls();
    let mut unknown = PathStats::default();
    unknown.frame_tx.crypto = 1;
    history.terminal_parts(
        terminal_paths_with_control_native()
            .into_iter()
            .chain([(iroh::endpoint::PathId::from(3_u32), unknown)]),
        1,
        0,
    );
    assert_eq!(history.paths.len(), 4);
    let unclassified = history
        .paths
        .iter()
        .find(|path| path.id == iroh::endpoint::PathId::from(3_u32))
        .expect("terminal receipt path retained");
    assert!(unclassified.remote.is_none());
    assert!(unclassified.terminal_seen);
    assert!(history.custom && history.native_tx && history.native_rx);
}

#[test]
#[should_panic(expected = "application frames crossed unclassified path")]
fn unknown_terminal_stream_tx_is_rejected() {
    let mut history = role_history_with_controls();
    let mut unknown = PathStats::default();
    unknown.frame_tx.stream = 1;
    history.terminal_parts(
        terminal_paths_with_control_native()
            .into_iter()
            .chain([(iroh::endpoint::PathId::from(3_u32), unknown)]),
        2,
        0,
    );
}

#[test]
#[should_panic(expected = "application frames crossed unclassified path")]
fn unknown_terminal_datagram_tx_is_rejected() {
    let mut history = role_history_with_controls();
    let mut unknown = PathStats::default();
    unknown.frame_tx.datagram = 1;
    history.terminal_parts(
        terminal_paths_with_control_native()
            .into_iter()
            .chain([(iroh::endpoint::PathId::from(3_u32), unknown)]),
        1,
        1,
    );
}

#[test]
#[should_panic(expected = "application frames crossed unclassified path")]
fn unknown_terminal_stream_rx_is_rejected() {
    let mut history = role_history_with_controls();
    let mut unknown = PathStats::default();
    unknown.frame_rx.stream = 1;
    history.terminal_parts(
        terminal_paths_with_control_native()
            .into_iter()
            .chain([(iroh::endpoint::PathId::from(3_u32), unknown)]),
        1,
        0,
    );
}

#[test]
#[should_panic(expected = "application frames crossed unclassified path")]
fn unknown_terminal_datagram_rx_is_rejected() {
    let mut history = role_history_with_controls();
    let mut unknown = PathStats::default();
    unknown.frame_rx.datagram = 1;
    history.terminal_parts(
        terminal_paths_with_control_native()
            .into_iter()
            .chain([(iroh::endpoint::PathId::from(3_u32), unknown)]),
        1,
        0,
    );
}

#[test]
#[should_panic(expected = "duplicate terminal path statistics")]
fn duplicate_terminal_path_id_is_rejected() {
    let mut history = role_history_with_controls();
    let receipt = terminal_paths_with_control_native();
    history.terminal_parts(
        receipt
            .into_iter()
            .chain([(iroh::endpoint::PathId::from(2_u32), PathStats::default())]),
        1,
        0,
    );
}

#[test]
#[should_panic(expected = "observed path has no final statistics")]
fn observed_path_without_any_final_stats_is_rejected() {
    let mut history = role_history_with_controls();
    history.terminal_parts(
        terminal_paths_with_control_native().into_iter().take(2),
        1,
        0,
    );
}

#[test]
#[should_panic(expected = "incomplete STREAM TX history")]
fn terminal_path_tx_must_conserve_connection_stream_total() {
    let mut history = role_history_with_controls();
    history.terminal_parts(terminal_paths_with_control_native(), 2, 0);
}

#[test]
#[should_panic(expected = "no actual custom signaling path was observed")]
fn unknown_terminal_control_stats_cannot_supply_custom_evidence() {
    let mut history = RoleHistory::new();
    history.path(
        iroh::endpoint::PathId::ZERO,
        &TransportAddr::Relay("https://relay.invalid".parse().expect("fixture relay URL")),
    );
    let native_index = history.path(
        iroh::endpoint::PathId::from(1_u32),
        &TransportAddr::Ip("127.0.0.1:443".parse().expect("fixture native address")),
    );
    let mut native_stats = PathStats::default();
    native_stats.frame_tx.stream = 1;
    native_stats.frame_rx.stream = 1;
    history.stats(native_index, &native_stats);
    let mut unknown = PathStats::default();
    unknown.frame_tx.crypto = 1;
    history.terminal_parts(
        [
            (iroh::endpoint::PathId::ZERO, PathStats::default()),
            (iroh::endpoint::PathId::from(1_u32), native_stats),
            (iroh::endpoint::PathId::from(2_u32), unknown),
        ],
        1,
        0,
    );
}

#[test]
#[should_panic(expected = "no native STREAM round trip observed")]
fn unknown_terminal_control_stats_cannot_supply_native_evidence() {
    let mut history = RoleHistory::new();
    history.path(
        iroh::endpoint::PathId::ZERO,
        &TransportAddr::Custom(iroh_base::CustomAddr::from_parts(7, &[1])),
    );
    history.path(
        iroh::endpoint::PathId::from(1_u32),
        &TransportAddr::Relay("https://relay.invalid".parse().expect("fixture relay URL")),
    );
    let mut unknown = PathStats::default();
    unknown.frame_tx.crypto = 1;
    history.terminal_parts(
        [
            (iroh::endpoint::PathId::ZERO, PathStats::default()),
            (iroh::endpoint::PathId::from(1_u32), PathStats::default()),
            (iroh::endpoint::PathId::from(2_u32), unknown),
        ],
        0,
        0,
    );
}

#[test]
fn closed_event_final_stats_cover_path_absent_from_terminal_receipt() {
    let mut history = role_history_with_controls();
    let mut closed = PathStats::default();
    closed.frame_tx.crypto = 1;
    let closed_index = history.path(
        iroh::endpoint::PathId::from(3_u32),
        &TransportAddr::Relay("https://closed.invalid".parse().expect("fixture relay URL")),
    );
    history.stats(closed_index, &closed);
    history.paths[closed_index].final_stats = Some(closed);
    let receipt = terminal_paths_with_control_native();
    history.terminal_parts(receipt, 1, 0);
    assert_eq!(
        history.paths[closed_index].final_stats,
        Some(closed),
        "previous close-event stats remain available when terminal receipt omits that ID"
    );
}

#[test]
#[should_panic(expected = "incomplete DATAGRAM TX history")]
fn terminal_path_tx_must_conserve_connection_datagram_total() {
    let mut history = role_history_with_controls();
    history.terminal_parts(terminal_paths_with_control_native(), 1, 1);
}

#[test]
#[should_panic(expected = "path-history bound exceeded")]
fn terminal_history_bound_includes_unknown_paths() {
    let mut history = role_history_with_controls();
    let paths = terminal_paths_with_control_native()
        .into_iter()
        .chain((3_u32..17_u32).map(|id| (iroh::endpoint::PathId::from(id), PathStats::default())))
        .collect::<Vec<_>>();
    history.terminal_parts(paths, 1, 0);
}

#[test]
#[should_panic(expected = "application frames crossed signaling path")]
fn role_frame_oracle_rejects_relay_stream_tx() {
    let mut stats = PathStats::default();
    stats.frame_tx.stream = 1;
    role_history_with_controls().stats(0, &stats);
}

#[test]
#[should_panic(expected = "application frames crossed signaling path")]
fn role_frame_oracle_rejects_relay_datagram_rx() {
    let mut stats = PathStats::default();
    stats.frame_rx.datagram = 1;
    role_history_with_controls().stats(0, &stats);
}

#[test]
fn role_frame_oracle_accepts_control_only_stats() {
    let mut stats = PathStats::default();
    stats.frame_tx.crypto = 1;
    stats.frame_rx.acks = 1;
    role_history_with_controls().stats(0, &stats);
}
