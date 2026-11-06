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
