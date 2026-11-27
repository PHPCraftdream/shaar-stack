//! The DHT library's own query counters as operator lines (leaf FIX-3b), so a live run shows
//! how far a lookup went and how many nodes took a store. Counts only: the library's targets,
//! addresses and error details are never printed, whatever else its events carry; the one
//! exception is the name of a payload-free error variant of a failed GET.

use std::fmt::{Debug, Write as _};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};

/// The pinned DHT library, by the target its events carry.
const LIBRARY: &str = "n0_mainline";

/// The library messages worth a line, with the label each one prints under.
const MESSAGES: [(&str, &str); 12] = [
    ("Owned GET finished", "get-finished"),
    ("Owned GET failed", "get-failed"),
    ("Owned GET dropped", "get-dropped"),
    ("Done query", "query-done"),
    ("PutQuery start", "put-start"),
    ("PutQuery Done successfully", "put-done"),
    ("Put Query: failed", "put-failed"),
    ("Owned GET round", "get-round"),
    ("Owned GET deadline", "get-deadline"),
    ("Owned pace", "pace"),
    ("Owned pace outcome", "pace-outcome"),
    ("Owned put wait", "put-wait"),
];

/// The numeric fields printed, in this order, when an event carries them.
const COUNTERS: [&str; 27] = [
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
    "age_ms",
    "inflight",
    "room",
    "timeout_ms",
    "rate",
    "share_pct",
    "queued",
    "attempts",
    "rpc",
    "sent",
    "kind",
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

/// The label and the fields of a library event, or `None` when it is not one of the counted ones.
fn pick_event(event: &Event<'_>) -> Option<(&'static str, Pick)> {
    let mut pick = Pick::default();
    event.record(&mut pick);
    let label = MESSAGES
        .iter()
        .find(|(message, _)| *message == pick.message)?
        .1;
    Some((label, pick))
}

/// The operator line of one counted event.
fn line_of(label: &str, pick: &Pick, since_ms: u64) -> String {
    let mut line = format!("shaar: dht {label} t={since_ms}");
    for (name, value) in COUNTERS.iter().zip(pick.counters) {
        if let Some(value) = value {
            let _ = write!(line, " {name}={value}");
        }
    }
    if let Some(error) = &pick.error {
        let _ = write!(line, " error={error}");
    }
    line
}

/// A numeric field of a picked event by its name.
fn counter(pick: &Pick, name: &str) -> Option<u32> {
    let at = COUNTERS.iter().position(|counter| *counter == name)?;
    u32::try_from(pick.counters[at]?).ok()
}

/// Fewest votes a finished query must have collected to say anything about the NAT.
pub(crate) const MIN_VOTES: u32 = 8;

/// The votes of the latest finished query that collected enough of them: how many nodes told this
/// device its address (`voted`) and under how many different ports (`voted_ports`). A NAT that
/// picks a port per destination shows many ports, one that keeps a port shows one (leaf BDAY-1b).
/// Both numbers sit in one word, so a reader never sees two different queries mixed.
#[derive(Debug, Default)]
pub(crate) struct Votes(AtomicU64);

impl Votes {
    pub(crate) const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// Keeps the pair when the query collected enough votes; a thin query changes nothing.
    fn note(&self, voted: u32, ports: u32) {
        if voted >= MIN_VOTES {
            self.0
                .store(u64::from(voted) << 32 | u64::from(ports), Ordering::Relaxed);
        }
    }

    /// `(voted, ports)` of the latest qualifying query; `None` before one has finished.
    pub(crate) fn latest(&self) -> Option<(u32, u32)> {
        match self.0.load(Ordering::Relaxed) {
            0 => None,
            packed => Some(((packed >> 32) as u32, packed as u32)),
        }
    }
}

/// The process-wide record that the installed trace feeds.
pub(crate) static VOTES: Votes = Votes::new();

/// Turns the library's debug events into operator lines; everything else stays disabled.
struct DhtTrace<S> {
    start: Instant,
    sink: S,
    votes: &'static Votes,
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
        let Some((label, pick)) = pick_event(event) else {
            return;
        };
        if label == "query-done"
            && let (Some(voted), Some(ports)) =
                (counter(&pick, "voted"), counter(&pick, "voted_ports"))
        {
            self.votes.note(voted, ports);
        }
        (self.sink)(line_of(label, &pick, super::elapsed_ms(self.start)));
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
        votes: &VOTES,
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
            votes: Box::leak(Box::new(Votes::new())),
        };
        tracing::subscriber::with_default(trace, emit);
        let guard = lines.lock().unwrap();
        guard.clone()
    }

    /// Runs `emit` under a trace that feeds `votes` and prints nothing.
    fn feeding(votes: &'static Votes, emit: impl FnOnce()) {
        let trace = DhtTrace {
            start: Instant::now(),
            sink: |_: String| {},
            votes,
        };
        tracing::subscriber::with_default(trace, emit);
    }

    #[test]
    fn the_latest_query_with_enough_votes_is_kept_for_the_role_of_the_device() {
        let votes: &'static Votes = Box::leak(Box::new(Votes::new()));
        assert_eq!(votes.latest(), None, "nothing before a query finished");
        feeding(votes, || {
            tracing::debug!(
                target: "n0_mainline::core::iterative_query",
                voted = ?30_u32, voted_addresses = ?1_usize, voted_ports = ?1_usize, "Done query"
            );
        });
        assert_eq!(votes.latest(), Some((30, 1)));
        feeding(votes, || {
            tracing::debug!(
                target: "n0_mainline::core::iterative_query",
                voted = ?7_u32, voted_addresses = ?7_usize, voted_ports = ?7_usize, "Done query"
            );
        });
        assert_eq!(
            votes.latest(),
            Some((30, 1)),
            "a thin query changes nothing"
        );
        feeding(votes, || {
            tracing::debug!(
                target: "n0_mainline::owner",
                voted = ?35_u32, voted_ports = ?35_usize, "Owned GET finished"
            );
            tracing::debug!(
                target: "n0_mainline::core::iterative_query",
                voted = ?35_u32, "Done query"
            );
            tracing::debug!(
                target: "another_library",
                voted = ?35_u32, voted_ports = ?35_usize, "Done query"
            );
        });
        assert_eq!(
            votes.latest(),
            Some((30, 1)),
            "another message, a query without ports and another library change nothing"
        );
        feeding(votes, || {
            tracing::debug!(
                target: "n0_mainline::core::iterative_query",
                voted = ?35_u32, voted_addresses = ?35_usize, voted_ports = ?35_usize, "Done query"
            );
        });
        assert_eq!(
            votes.latest(),
            Some((35, 35)),
            "the latest qualifying query wins"
        );
        assert_eq!(MIN_VOTES, 8);
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
                round = ?2_u8, candidates = ?17_usize, room = ?160_usize, timeout_ms = ?2_000_u128,
                "Owned GET round"
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
                "round=2 candidates=17 room=160 timeout_ms=2000",
                "closest=20 visited=20 round=1 candidates=3 inflight=4 room=0",
            ]
        );
        assert!(lines[0].starts_with("shaar: dht get-round "));
        assert!(lines[1].starts_with("shaar: dht get-deadline "));
    }

    #[test]
    fn a_change_of_the_pacing_rate_prints_the_rate_and_the_answered_share() {
        let lines = captured(|| {
            tracing::debug!(
                target: "n0_mainline::actor::socket::pacer",
                rate = ?25_u32, share_pct = ?18_u32, "Owned pace"
            );
            tracing::debug!(
                target: "n0_mainline::actor::socket::pacer",
                rate = ?0_u32, share_pct = ?100_u32, "Owned pace"
            );
        });
        let tails: Vec<&str> = lines
            .iter()
            .map(|line| line.split_once(" t=").unwrap().1.split_once(' ').unwrap().1)
            .collect();
        assert_eq!(tails, ["rate=25 share_pct=18", "rate=0 share_pct=100"]);
        assert!(lines[0].starts_with("shaar: dht pace "), "{}", lines[0]);
    }

    #[test]
    fn a_request_outcome_and_a_put_wait_print_their_numbers_in_a_fixed_order() {
        let lines = captured(|| {
            tracing::debug!(
                target: "n0_mainline::actor::socket::socket_resources",
                kind = ?1_u8, sent = ?42_u64, "Owned pace outcome"
            );
            tracing::debug!(
                target: "n0_mainline::actor::owned_resources::put",
                rpc = ?9_usize, attempts = ?2_u8, queued = ?3_usize, inflight = ?4_usize,
                age_ms = ?10_001_u128, "Owned put wait"
            );
        });
        let tails: Vec<&str> = lines
            .iter()
            .map(|line| line.split_once(" t=").unwrap().1.split_once(' ').unwrap().1)
            .collect();
        assert_eq!(
            tails,
            [
                "sent=42 kind=1",
                "age_ms=10001 inflight=4 queued=3 attempts=2 rpc=9"
            ]
        );
        assert!(
            lines[0].starts_with("shaar: dht pace-outcome "),
            "{}",
            lines[0]
        );
        assert!(lines[1].starts_with("shaar: dht put-wait "), "{}", lines[1]);
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
