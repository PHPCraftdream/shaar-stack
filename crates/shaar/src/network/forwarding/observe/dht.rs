//! The DHT library's own query counters as operator lines (leaf FIX-3b), so a live run shows
//! how far a lookup went and how many nodes took a store. Counts only: the library's targets,
//! addresses and error details are never printed, whatever else its events carry; the one
//! exception is the name of a payload-free error variant of a failed GET.

use std::fmt::{Debug, Write as _};
use std::time::Instant;

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};

/// The pinned DHT library, by the target its events carry.
const LIBRARY: &str = "n0_mainline";

/// The library messages worth a line, with the label each one prints under.
const MESSAGES: [(&str, &str); 9] = [
    ("Owned GET finished", "get-finished"),
    ("Owned GET failed", "get-failed"),
    ("Owned GET dropped", "get-dropped"),
    ("Done query", "query-done"),
    ("PutQuery start", "put-start"),
    ("PutQuery Done successfully", "put-done"),
    ("Put Query: failed", "put-failed"),
    ("Owned GET round", "get-round"),
    ("Owned GET deadline", "get-deadline"),
];

/// The numeric fields printed, in this order, when an event carries them.
const COUNTERS: [&str; 18] = [
    "op",
    "stage",
    "total_ms",
    "items",
    "completed",
    "closest",
    "visited",
    "responders",
    "voted",
    "voted_addresses",
    "voted_ports",
    "closest_secure_nodes",
    "stored_at",
    "nodes_count",
    "round",
    "candidates",
    "inflight",
    "room",
];

/// Longest error variant name printed.
const ERROR_TOKEN_MAX: usize = 32;

#[derive(Default)]
struct Pick {
    message: String,
    counters: [Option<usize>; COUNTERS.len()],
    error: Option<String>,
}

/// Whether a debug rendering is a bare variant name: letters, digits and underscores only, so
/// a value that carries data (parentheses, quotes, addresses) is never printed.
fn is_variant_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= ERROR_TOKEN_MAX
        && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl Visit for Pick {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else if field.name() == "error" {
            let text = format!("{value:?}");
            self.error = is_variant_name(&text).then_some(text);
        } else if let Some(at) = COUNTERS.iter().position(|name| *name == field.name()) {
            self.counters[at] = format!("{value:?}").parse().ok();
        }
    }
}

/// The line for one library event, or `None` when the event is not one of the counted ones.
fn event_line(event: &Event<'_>, since_ms: u64) -> Option<String> {
    let mut pick = Pick::default();
    event.record(&mut pick);
    let label = MESSAGES
        .iter()
        .find(|(message, _)| *message == pick.message)?
        .1;
    let mut line = format!("shaar: dht {label} t={since_ms}");
    for (name, value) in COUNTERS.iter().zip(pick.counters) {
        if let Some(value) = value {
            let _ = write!(line, " {name}={value}");
        }
    }
    if let Some(error) = pick.error {
        let _ = write!(line, " error={error}");
    }
    Some(line)
}

/// Turns the library's debug events into operator lines; everything else stays disabled.
struct DhtTrace<S> {
    start: Instant,
    sink: S,
}

impl<S: Fn(String) + Send + Sync + 'static> Subscriber for DhtTrace<S> {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.is_event()
            && *metadata.level() <= Level::DEBUG
            && metadata.target().starts_with(LIBRARY)
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        if let Some(line) = event_line(event, super::elapsed_ms(self.start)) {
            (self.sink)(line);
        }
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

/// Prints the DHT counters on stderr as `shaar: dht <label> t=<MS> <name>=<N>...`. A no-op when
/// the process already has a global tracing subscriber: the embedding application keeps its own.
pub fn install_dht_trace() {
    let _ = tracing::subscriber::set_global_default(DhtTrace {
        start: Instant::now(),
        sink: super::emit,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn captured(emit: impl FnOnce()) -> Vec<String> {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&lines);
        let trace = DhtTrace {
            start: Instant::now(),
            sink: move |line: String| sink.lock().unwrap().push(line),
        };
        tracing::subscriber::with_default(trace, emit);
        let guard = lines.lock().unwrap();
        guard.clone()
    }

    #[test]
    fn a_finished_query_prints_its_depth_counters_and_nothing_else() {
        let lines = captured(|| {
            tracing::debug!(
                target: "n0_mainline::core::iterative_query",
                id = ?"0123456789abcdef", closest = ?20_usize, visited = ?37_usize, responders = ?8_usize,
                voted = ?30_u32, voted_addresses = ?3_usize, voted_ports = ?3_usize, "Done query"
            );
        });
        assert_eq!(lines.len(), 1);
        let line = &lines[0];
        assert!(line.starts_with("shaar: dht query-done t="), "{line}");
        assert!(
            line.ends_with(
                " closest=20 visited=37 responders=8 voted=30 voted_addresses=3 voted_ports=3"
            ),
            "{line}"
        );
        assert!(!line.contains("0123456789abcdef"), "{line}");
    }

    #[test]
    fn an_owned_get_prints_how_it_ended_and_where_it_waited() {
        let lines = captured(|| {
            tracing::debug!(
                target: "n0_mainline::owner",
                op = 4_u64, total_ms = 3_827_u64, items = 0_usize, completed = 1_u8, "Owned GET finished"
            );
            tracing::debug!(
                target: "n0_mainline::owner",
                op = 5_u64, stage = 3_u8, total_ms = 30_001_u64, "Owned GET dropped"
            );
            tracing::debug!(
                target: "n0_mainline::owner",
                op = 6_u64, stage = 2_u8, total_ms = 45_000_u64, "Owned GET failed"
            );
        });
        let tails: Vec<&str> = lines
            .iter()
            .map(|line| line.split_once(" t=").unwrap().1.split_once(' ').unwrap().1)
            .collect();
        assert_eq!(
            tails,
            [
                "op=4 total_ms=3827 items=0 completed=1",
                "op=5 stage=3 total_ms=30001",
                "op=6 stage=2 total_ms=45000",
            ]
        );
        assert!(lines[0].starts_with("shaar: dht get-finished "));
        assert!(lines[1].starts_with("shaar: dht get-dropped "));
        assert!(lines[2].starts_with("shaar: dht get-failed "));
    }

    #[test]
    fn a_get_round_and_a_get_deadline_print_their_counts() {
        let lines = captured(|| {
            tracing::debug!(
                target: "n0_mainline::core::iterative_query",
                round = ?2_u8, candidates = ?17_usize, room = ?160_usize, "Owned GET round"
            );
            tracing::debug!(
                target: "n0_mainline::core::iterative_query",
                round = ?1_u8, closest = ?20_usize, candidates = ?3_usize, visited = ?20_usize,
                inflight = ?4_usize, room = ?0_usize, "Owned GET deadline"
            );
        });
        let tails: Vec<&str> = lines
            .iter()
            .map(|line| line.split_once(" t=").unwrap().1.split_once(' ').unwrap().1)
            .collect();
        assert_eq!(
            tails,
            [
                "round=2 candidates=17 room=160",
                "closest=20 visited=20 round=1 candidates=3 inflight=4 room=0",
            ]
        );
        assert!(lines[0].starts_with("shaar: dht get-round "));
        assert!(lines[1].starts_with("shaar: dht get-deadline "));
    }

    #[test]
    fn a_failed_get_prints_only_a_bare_error_variant_name() {
        // The library's error is an enum, whose debug rendering is its bare variant name.
        #[derive(Debug)]
        enum Failure {
            DeadlineExceeded,
        }
        let lines = captured(|| {
            tracing::debug!(
                target: "n0_mainline::owner",
                op = 7_u64, stage = 2_u8, total_ms = 0_u64, error = ?Failure::DeadlineExceeded, "Owned GET failed"
            );
            tracing::debug!(
                target: "n0_mainline::owner",
                op = 8_u64, stage = 3_u8, total_ms = 1_u64, error = ?("Busy", "203.0.113.7:6881"), "Owned GET failed"
            );
        });
        assert_eq!(lines.len(), 2);
        assert!(
            lines[0].ends_with(" op=7 stage=2 total_ms=0 error=DeadlineExceeded"),
            "{}",
            lines[0]
        );
        assert!(
            lines[1].ends_with(" op=8 stage=3 total_ms=1"),
            "{}",
            lines[1]
        );
        assert!(!lines[1].contains("203.0.113.7"), "{}", lines[1]);
    }

    #[test]
    fn a_store_prints_how_many_nodes_took_it_and_how_many_it_asked() {
        let lines = captured(|| {
            tracing::debug!(
                target: "n0_mainline::core::put_query",
                closest_secure_nodes = ?8_usize, "PutQuery start"
            );
            tracing::debug!(
                target: "n0_mainline::core::put_query",
                target = ?"cafe", stored_at = ?3_u8, "PutQuery Done successfully"
            );
            tracing::debug!(
                target: "n0_mainline::core::put_query",
                most_common_error = ?"Timeout", nodes_count = ?5_usize, "Put Query: failed"
            );
        });
        let tails: Vec<&str> = lines
            .iter()
            .map(|line| line.split_once(" t=").unwrap().1.split_once(' ').unwrap().1)
            .collect();
        assert_eq!(
            tails,
            ["closest_secure_nodes=8", "stored_at=3", "nodes_count=5"]
        );
        assert!(lines[0].starts_with("shaar: dht put-start "));
        assert!(lines[1].starts_with("shaar: dht put-done "));
        assert!(lines[2].starts_with("shaar: dht put-failed "));
        assert!(
            lines
                .iter()
                .all(|line| !line.contains("cafe") && !line.contains("Timeout"))
        );
    }

    #[test]
    fn events_with_addresses_or_other_messages_print_nothing() {
        let lines = captured(|| {
            tracing::debug!(
                target: "n0_mainline::core::handle_response",
                from = ?"203.0.113.7:6881", "Invalid mutable record"
            );
            tracing::debug!(target: "n0_mainline::core::iterative_query", "Some other message");
        });
        assert!(lines.is_empty(), "{lines:?}");
    }

    #[test]
    fn only_the_library_and_only_debug_or_above_is_enabled() {
        let lines = captured(|| {
            tracing::debug!(target: "libp2p_swarm", closest = ?1_usize, "Done query");
            tracing::trace!(target: "n0_mainline::core::iterative_query", closest = ?1_usize, "Done query");
        });
        assert!(lines.is_empty(), "{lines:?}");
    }

    #[test]
    fn a_non_numeric_counter_is_skipped_instead_of_printed() {
        let lines = captured(|| {
            tracing::debug!(
                target: "n0_mainline::core::iterative_query",
                closest = ?"203.0.113.7:6881", visited = ?4_usize, "Done query"
            );
        });
        assert_eq!(lines.len(), 1);
        assert!(lines[0].ends_with(" visited=4"), "{}", lines[0]);
        assert!(!lines[0].contains("203.0.113.7"), "{}", lines[0]);
    }
}
