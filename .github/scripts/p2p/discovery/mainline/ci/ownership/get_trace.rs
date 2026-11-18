// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The operator trace of one owned GET: where it waited and how it ended, as counts only.
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};

use crate::resource::{OwnedQueryCompletion, ResourceError};

static GET_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// One owned GET for the operator trace: where it waited and how it ended, as counts only. It
/// reports even when the caller drops the future, which is how a caller-side timeout shows up.
/// Stages: 1 reserving the actor channel, 2 awaiting admission, 3 awaiting the result.
pub(super) struct GetTrace {
    op: u64,
    entry: tokio::time::Instant,
    pub(super) stage: u8,
    finished: bool,
}

impl GetTrace {
    pub(super) fn start() -> Self {
        Self {
            op: GET_SEQUENCE.fetch_add(1, Ordering::Relaxed),
            entry: tokio::time::Instant::now(),
            stage: 0,
            finished: false,
        }
    }

    fn total_ms(&self) -> u64 {
        u64::try_from(self.entry.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    pub(super) fn finish(&mut self, result: &Result<OwnedQueryCompletion, ResourceError>) {
        self.finished = true;
        match result {
            Ok(done) => tracing::debug!(
                op = self.op,
                total_ms = self.total_ms(),
                items = done.items().len(),
                completed = u8::from(done.network_completed()),
                "Owned GET finished"
            ),
            Err(_) => tracing::debug!(
                op = self.op,
                stage = self.stage,
                total_ms = self.total_ms(),
                "Owned GET failed"
            ),
        }
    }
}

impl Drop for GetTrace {
    fn drop(&mut self) {
        if !self.finished {
            tracing::debug!(
                op = self.op,
                stage = self.stage,
                total_ms = self.total_ms(),
                "Owned GET dropped"
            );
        }
    }
}

#[cfg(test)]
mod get_trace_tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    #[derive(Default)]
    struct Line {
        message: String,
        fields: String,
    }

    impl Visit for Line {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.message = format!("{value:?}");
            } else {
                self.fields.push_str(&format!(" {}={value:?}", field.name()));
            }
        }
    }

    struct Capture(Arc<Mutex<Vec<String>>>);

    impl Subscriber for Capture {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _: &Id, _: &Record<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn event(&self, event: &Event<'_>) {
            let mut line = Line::default();
            event.record(&mut line);
            self.0
                .lock()
                .unwrap()
                .push(format!("{}{}", line.message, line.fields));
        }
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
    }

    fn captured(run: impl FnOnce()) -> Vec<String> {
        let lines = Arc::new(Mutex::new(Vec::new()));
        tracing::subscriber::with_default(Capture(Arc::clone(&lines)), run);
        let guard = lines.lock().unwrap();
        guard.clone()
    }

    #[test]
    fn an_unfinished_get_reports_the_stage_it_was_dropped_in() {
        let lines = captured(|| {
            let mut trace = GetTrace::start();
            trace.stage = 3;
        });
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with("Owned GET dropped"), "{lines:?}");
        assert!(lines[0].contains(" stage=3"), "{lines:?}");
    }

    #[test]
    fn a_failed_get_reports_once_with_its_stage_and_is_not_reported_again_on_drop() {
        let lines = captured(|| {
            let mut trace = GetTrace::start();
            trace.stage = 2;
            trace.finish(&Err(ResourceError::DeadlineExceeded));
        });
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with("Owned GET failed"), "{lines:?}");
        assert!(lines[0].contains(" stage=2"), "{lines:?}");
    }

    #[test]
    fn a_finished_get_reports_how_many_records_it_found() {
        let lines = captured(|| {
            let mut trace = GetTrace::start();
            let done = OwnedQueryCompletion {
                items: Arc::from(Vec::<crate::MutableItem>::new()),
                network_completed: true,
                result_lease: None,
            };
            trace.finish(&Ok(done));
        });
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with("Owned GET finished"), "{lines:?}");
        assert!(lines[0].contains(" items=0"), "{lines:?}");
        assert!(lines[0].contains(" completed=1"), "{lines:?}");
    }

    #[test]
    fn every_get_gets_its_own_operation_number() {
        let first = GetTrace::start();
        let second = GetTrace::start();
        assert_ne!(first.op, second.op);
    }
}
