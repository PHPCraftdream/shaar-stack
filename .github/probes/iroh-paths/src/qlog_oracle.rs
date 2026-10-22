//! Qlog JSON-SEQ oracle: per-file, per-connection, per-path, per-direction.
//!
//! Parses the `.qlog` JSON-SEQ output produced by noq (via iroh's public
//! `QuicTransportConfig::builder().qlog_from_path(dir, prefix)`, iroh v1.3.0
//! feature `qlog`).
//!
//! IDENTITY: [`parse_file`] and [`parse_dir`] NEVER merge files. Every
//! `.qlog` file is one connection trace and keeps its own per-path packet
//! counts, per-direction STREAM frame counts, and tuple map. Colliding path
//! ids across files stay distinct by construction.
//!
//! DIRECTION: `packet_sent` and `packet_received` are counted SEPARATELY,
//! including separate per-path STREAM frame counters.
//!
//! UNKNOWN PATHS: a packet whose `header.path_id` is missing/absent is
//! recorded in `unknown_path_packets_sent/received` — it is NEVER defaulted
//! to path 0.
//!
//! Schema (fetched and verified):
//! - https://raw.githubusercontent.com/n0-computer/n0-qlog/7deeea19303dd032b944696af7bd4890e6d0c31e/src/events/mod.rs
//!   — envelope `{"time": f64, "name": "quic:packet_sent", "data": {...}}`
//!   (adjacent tag `name`/`data` via `EventData`).
//! - https://raw.githubusercontent.com/n0-computer/n0-qlog/7deeea19303dd032b944696af7bd4890e6d0c31e/src/events/quic.rs
//!   — `PacketHeader.path_id: Option<u64>`; frames are tagged
//!   `{"frame_type": "stream", "stream_id": .., "offset": .., "fin": ..}`;
//!   `TupleAssigned { tuple_id, tuple_remote, tuple_local }` with
//!   `TupleEndpointInfo { ip_v4, port_v4, ip_v6, port_v6, connection_ids }`.
//! - https://raw.githubusercontent.com/n0-computer/noq/noq-v1.3.0/noq-proto/src/connection/qlog.rs
//!   — noq v1.3.0 writes these events via n0-qlog (same shapes).
//!
//! SCOPE CLAIM: this oracle attributes frames per connection trace and path
//! id. The custom-only CALIBRATION test uses topology (a single transport)
//! to bind decoded SENT STREAM frames to the custom transport; it does NOT
//! prove multipath egress attribution. Also: no payload bytes are logged
//! (frames carry metadata-only `raw`), so plaintext equality is verified
//! by the echo helper; transport counters measure encrypted datagrams.
//!
//! JSON-SEQ records may be prefixed with the RS byte (0x1E); unknown events
//! are counted (`unknown_events`) and skipped; memory stays bounded (one
//! event parsed at a time).

use std::{collections::BTreeMap, fs, io, path::Path};

/// One parsed connection trace (ONE .qlog file, never merged).
#[derive(Debug, Default, Clone)]
pub struct ConnectionTrace {
    /// Per-path STREAM frame counts on `packet_sent` events.
    pub stream_frames_sent_by_path: BTreeMap<u64, u64>,
    /// Per-path STREAM frame counts on `packet_received` events.
    pub stream_frames_received_by_path: BTreeMap<u64, u64>,
    /// Per-path packet counts for `packet_sent`.
    pub packets_sent_by_path: BTreeMap<u64, u64>,
    /// Per-path packet counts for `packet_received`.
    pub packets_received_by_path: BTreeMap<u64, u64>,
    /// Packets with an ABSENT `header.path_id` among `packet_sent`.
    /// Never folded into path 0.
    pub unknown_path_packets_sent: u64,
    /// Packets with an ABSENT `header.path_id` among `packet_received`.
    /// Never folded into path 0.
    pub unknown_path_packets_received: u64,
    /// `tuple_id -> "remote|local"` mapping from `tuple_assigned` events.
    pub tuple_map: BTreeMap<String, String>,
    /// Total JSON-SEQ records parsed (known + unknown events).
    pub events_parsed: u64,
    /// Records whose event name was not recognized.
    pub unknown_events: u64,
}

impl ConnectionTrace {
    /// Sum of SENT STREAM frames over all paths.
    pub fn total_stream_frames_sent(&self) -> u64 {
        self.stream_frames_sent_by_path.values().sum()
    }

    /// Sum of RECEIVED STREAM frames over all paths.
    pub fn total_stream_frames_received(&self) -> u64 {
        self.stream_frames_received_by_path.values().sum()
    }

    /// Number of distinct path ids seen carrying SENT or RECEIVED packets
    /// (absent path ids excluded — they are tracked separately).
    pub fn distinct_paths(&self) -> usize {
        let mut ids: Vec<u64> = self.packets_sent_by_path.keys().copied().collect();
        ids.extend(self.packets_received_by_path.keys().copied());
        ids.sort_unstable();
        ids.dedup();
        ids.len()
    }

    /// Human-readable summary for CI diagnostics.
    pub fn summary(&self) -> String {
        let fmt = |m: &BTreeMap<u64, u64>| {
            m.iter()
                .map(|(p, n)| format!("path {p}: {n}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        format!(
            "sent(pkts)={} [{}] STREAM sent: {} | received(pkts)={} [{}] STREAM received: {} | \
             unknown_path(sent/rcv)={}/{} | unknown_events={}",
            self.packets_sent_by_path.values().sum::<u64>(),
            fmt(&self.packets_sent_by_path),
            self.total_stream_frames_sent(),
            self.packets_received_by_path.values().sum::<u64>(),
            fmt(&self.packets_received_by_path),
            self.total_stream_frames_received(),
            self.unknown_path_packets_sent,
            self.unknown_path_packets_received,
            self.unknown_events,
        )
    }
}

/// Parse errors for the oracle.
#[derive(Debug)]
pub enum OracleError {
    /// Reading a qlog file failed.
    Io(io::Error),
    /// A JSON-SEQ record was not valid JSON.
    InvalidRecord(String),
}

impl std::fmt::Display for OracleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "qlog io error: {e}"),
            Self::InvalidRecord(s) => write!(f, "invalid qlog JSON-SEQ record: {s}"),
        }
    }
}

impl std::error::Error for OracleError {}

/// Parses one .qlog file into ONE connection trace. No merging.
pub fn parse_file(path: &Path) -> Result<ConnectionTrace, OracleError> {
    let bytes = fs::read(path).map_err(OracleError::Io)?;
    parse(&bytes)
}

/// Parses every `*.qlog` file in `dir` (one level; iroh/noq write flat
/// directories) into a Vec of per-file traces, sorted by file name. Files
/// are NEVER merged: each element keeps its own identity. Unreadable or
/// invalid files are skipped with a diagnostic on stderr.
pub fn parse_dir(dir: &Path) -> Vec<ConnectionTrace> {
    let Ok(entries) = fs::read_dir(dir) else {
        eprintln!("qlog oracle: cannot read dir {}", dir.display());
        return Vec::new();
    };
    let mut names: Vec<_> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "qlog").unwrap_or(false))
        .collect();
    names.sort();
    let mut traces = Vec::new();
    for path in names {
        match parse_file(&path) {
            Ok(t) => traces.push(t),
            Err(e) => eprintln!("qlog oracle: skipping {}: {e}", path.display()),
        }
    }
    if traces.is_empty() {
        eprintln!("qlog oracle: no .qlog traces parsed in {}", dir.display());
    }
    traces
}

/// Selects the traces whose source file name starts with `prefix`. The
/// caller passes the qlog file prefix given to `qlog_from_path` to identify
/// one endpoint's trace files (e.g. the client).
pub fn traces_with_prefix<'a>(traces: &'a [NamedTrace], prefix: &str) -> Vec<&'a NamedTrace> {
    traces
        .iter()
        .filter(|t| t.file_name.starts_with(prefix))
        .collect()
}

/// A connection trace together with the file name it was parsed from.
#[derive(Debug, Clone)]
pub struct NamedTrace {
    pub file_name: String,
    pub trace: ConnectionTrace,
}

/// Like [`parse_dir`], but keeps the file name for prefix-based selection.
pub fn parse_dir_named(dir: &Path) -> Vec<NamedTrace> {
    let Ok(entries) = fs::read_dir(dir) else {
        eprintln!("qlog oracle: cannot read dir {}", dir.display());
        return Vec::new();
    };
    let mut names: Vec<_> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "qlog").unwrap_or(false))
        .collect();
    names.sort();
    let mut traces = Vec::new();
    for path in names {
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        match parse_file(&path) {
            Ok(t) => traces.push(NamedTrace {
                file_name,
                trace: t,
            }),
            Err(e) => eprintln!("qlog oracle: skipping {}: {e}", path.display()),
        }
    }
    traces
}

/// Parses a raw JSON-SEQ byte stream (RS-separated, newline tolerated).
pub fn parse(bytes: &[u8]) -> Result<ConnectionTrace, OracleError> {
    let mut trace = ConnectionTrace::default();
    for record in bytes.split(|b| *b == 0x1E) {
        let record = String::from_utf8_lossy(record);
        for line in record.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let value: serde_json::Value = serde_json::from_str(line)
                .map_err(|e| OracleError::InvalidRecord(format!("{e}: {line}")))?;
            apply_event(&mut trace, &value);
        }
    }
    Ok(trace)
}

fn apply_event(trace: &mut ConnectionTrace, value: &serde_json::Value) {
    let Some(obj) = value.as_object() else {
        return;
    };
    let name = obj
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let data = obj.get("data").cloned().unwrap_or(serde_json::Value::Null);
    trace.events_parsed += 1;
    if name == "quic:tuple_assigned" {
        if let Some(tuple_id) = data.get("tuple_id").and_then(|v| v.as_str()) {
            let remote = endpoint_info(&data, "tuple_remote");
            let local = endpoint_info(&data, "tuple_local");
            trace
                .tuple_map
                .insert(tuple_id.to_string(), format!("{remote} | {local}"));
        }
        return;
    }
    match name.as_str() {
        "quic:packet_sent" => apply_packet(trace, &data, Direction::Sent),
        "quic:packet_received" => apply_packet(trace, &data, Direction::Received),
        _ => trace.unknown_events += 1,
    }
}

enum Direction {
    Sent,
    Received,
}

fn apply_packet(trace: &mut ConnectionTrace, data: &serde_json::Value, dir: Direction) {
    let frames = data
        .get("frames")
        .and_then(|v| v.as_array())
        .map(|fs| {
            fs.iter()
                .filter(|f| {
                    f.get("frame_type")
                        .and_then(|v| v.as_str())
                        .map(|s| s.eq_ignore_ascii_case("stream"))
                        .unwrap_or(false)
                })
                .count() as u64
        })
        .unwrap_or(0);
    // Absent path_id stays absent: accounted separately, never path 0.
    let path_id = data.pointer("/header/path_id").and_then(|v| v.as_u64());
    match (dir, path_id) {
        (Direction::Sent, Some(p)) => {
            *trace.packets_sent_by_path.entry(p).or_default() += 1;
            if frames > 0 {
                *trace.stream_frames_sent_by_path.entry(p).or_default() += frames;
            }
        }
        (Direction::Received, Some(p)) => {
            *trace.packets_received_by_path.entry(p).or_default() += 1;
            if frames > 0 {
                *trace.stream_frames_received_by_path.entry(p).or_default() += frames;
            }
        }
        (Direction::Sent, None) => trace.unknown_path_packets_sent += 1,
        (Direction::Received, None) => trace.unknown_path_packets_received += 1,
    }
}

fn endpoint_info(data: &serde_json::Value, key: &str) -> String {
    let Some(info) = data.get(key) else {
        return "?".to_string();
    };
    if info.is_null() {
        return "?".to_string();
    }
    let ip = info
        .get("ip_v4")
        .and_then(|v| v.as_str())
        .or_else(|| info.get("ip_v6").and_then(|v| v.as_str()));
    let port = info
        .get("port_v4")
        .and_then(|v| v.as_u64())
        .or_else(|| info.get("port_v6").and_then(|v| v.as_u64()));
    match (ip, port) {
        (Some(ip), Some(port)) => format!("{ip}:{port}"),
        (Some(ip), None) => ip.to_string(),
        _ => "?".to_string(),
    }
}

/// Hand-written JSON-SEQ fixtures shaped to the REAL pinned noq-v1.3.0 /
/// n0-qlog schema (sources listed in the module doc comment).
#[cfg(test)]
pub(crate) mod fixtures {
    /// A packet_sent with a STREAM frame on path 0.
    pub const SENT_STREAM_PATH0: &[u8] = b"\x1e{\"time\":1.0,\"name\":\"quic:tuple_assigned\",\"data\":\
{\"tuple_id\":\"p0\",\"tuple_remote\":{\"ip_v4\":\"127.0.0.1\",\"port_v4\":5001,\"ip_v6\":null,\"port_v6\":null,\"connection_ids\":null},\
\"tuple_local\":null}}\n\
\x1e{\"time\":2.0,\"name\":\"quic:packet_sent\",\"data\":{\"header\":{\"packet_type\":\"1RTT\",\
\"packet_number\":7,\"path_id\":0},\"frames\":[{\"frame_type\":\"stream\",\"stream_id\":0,\
\"offset\":0,\"fin\":false,\"raw\":null}]}}\n";

    /// A packet_received with a STREAM frame on a DIFFERENT path id.
    pub const RECEIVED_STREAM_PATH1: &[u8] =
        b"\x1e{\"time\":3.0,\"name\":\"quic:packet_received\",\"data\":\
{\"header\":{\"packet_type\":\"1RTT\",\"packet_number\":9,\"path_id\":1},\"frames\":\
[{\"frame_type\":\"stream\",\"stream_id\":0,\"offset\":0,\"fin\":true,\"raw\":null}]}}\n";

    /// A packet with a MISSING path_id (must not fold into path 0).
    pub const SENT_MISSING_PATH: &[u8] =
        b"\x1e{\"time\":4.0,\"name\":\"quic:packet_sent\",\"data\":\
{\"header\":{\"packet_type\":\"initial\",\"packet_number\":0},\"frames\":\
[{\"frame_type\":\"crypto\",\"offset\":0,\"raw\":null}]}}\n";

    /// An unknown event (counted, skipped).
    pub const UNKNOWN_EVENT: &[u8] =
        b"\x1e{\"time\":5.0,\"name\":\"connectivity:did_a_thing\",\"data\":{}}\n";
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    struct TraceDir(PathBuf);

    impl TraceDir {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let base = std::env::current_dir()
                .expect("current directory")
                .join("target/iroh-paths/oracle-tests");
            fs::create_dir_all(&base).expect("fixture parent");
            for _ in 0..64 {
                let id = NEXT.fetch_add(1, Ordering::Relaxed);
                let path = base.join(format!("{}-{id}", std::process::id()));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(err) => panic!("create trace fixture: {err}"),
                }
            }
            panic!("trace fixture namespace exhausted");
        }
    }

    impl Drop for TraceDir {
        fn drop(&mut self) {
            // Only a directory exclusively created by this fixture is removed.
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn direction_separation_and_path_accounting() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(fixtures::SENT_STREAM_PATH0);
        bytes.extend_from_slice(fixtures::RECEIVED_STREAM_PATH1);
        bytes.extend_from_slice(fixtures::SENT_MISSING_PATH);
        bytes.extend_from_slice(fixtures::UNKNOWN_EVENT);
        let t = parse(&bytes).expect("parse");
        // Direction separation.
        assert_eq!(t.total_stream_frames_sent(), 1);
        assert_eq!(t.total_stream_frames_received(), 1);
        assert_eq!(t.stream_frames_sent_by_path.get(&0), Some(&1));
        assert_eq!(t.stream_frames_received_by_path.get(&1), Some(&1));
        assert_eq!(t.stream_frames_received_by_path.get(&0), None);
        assert_eq!(t.stream_frames_sent_by_path.get(&1), None);
        assert_eq!(t.packets_sent_by_path.get(&0), Some(&1));
        assert_eq!(t.packets_received_by_path.get(&1), Some(&1));
        // Missing path_id is NOT folded into path 0.
        assert_eq!(t.unknown_path_packets_sent, 1);
        assert_eq!(t.packets_sent_by_path.get(&0), Some(&1));
        // Unknown event counted, not parsed as a packet.
        assert_eq!(t.unknown_events, 1);
        assert_eq!(t.events_parsed, 5);
        // Tuple map.
        assert_eq!(
            t.tuple_map.get("p0").map(String::as_str),
            Some("127.0.0.1:5001 | ?")
        );
    }

    #[test]
    fn colliding_path_ids_stay_distinct_across_files() {
        // Two files, both with path id 0 but different tuples: because files
        // are never merged, each trace keeps its own path-0 identity.
        let dir = TraceDir::new();
        fs::write(dir.0.join("client-a.qlog"), fixtures::SENT_STREAM_PATH0).expect("write a");
        fs::write(dir.0.join("ignored.txt"), fixtures::SENT_STREAM_PATH0).expect("write ignored");
        let other = b"\x1e{\"time\":1.0,\"name\":\"quic:tuple_assigned\",\"data\":\
{\"tuple_id\":\"p0\",\"tuple_remote\":{\"ip_v6\":\"[::1]\",\"port_v6\":6002,\"ip_v4\":null,\"port_v4\":null,\"connection_ids\":null},\
\"tuple_local\":null}}\n\
\x1e{\"time\":2.0,\"name\":\"quic:packet_sent\",\"data\":{\"header\":{\"packet_type\":\"1RTT\",\
\"packet_number\":1,\"path_id\":0},\"frames\":[]}}\n";
        fs::write(dir.0.join("server-b.qlog"), other).expect("write b");
        let traces = parse_dir_named(&dir.0);
        assert_eq!(traces.len(), 2, "only .qlog files must be loaded");
        let clients = traces_with_prefix(&traces, "client-");
        let servers = traces_with_prefix(&traces, "server-");
        assert_eq!(clients.len(), 1);
        assert_eq!(servers.len(), 1);
        assert_eq!(clients[0].file_name, "client-a.qlog");
        assert_eq!(servers[0].file_name, "server-b.qlog");
        let a = &clients[0].trace;
        let b = &servers[0].trace;
        assert_eq!(
            a.tuple_map.get("p0").map(String::as_str),
            Some("127.0.0.1:5001 | ?")
        );
        assert_eq!(
            b.tuple_map.get("p0").map(String::as_str),
            Some("[::1]:6002 | ?")
        );
        assert_ne!(a.tuple_map.get("p0"), b.tuple_map.get("p0"));
        assert_eq!(a.packets_sent_by_path.get(&0), Some(&1));
        assert_eq!(b.packets_sent_by_path.get(&0), Some(&1));
        // Frames stay separate per trace.
        assert_eq!(a.total_stream_frames_sent(), 1);
        assert_eq!(b.total_stream_frames_sent(), 0);
    }

    #[test]
    fn empty_input_is_empty_trace() {
        let t = parse(b"").expect("parse");
        assert_eq!(t.events_parsed, 0);
        assert_eq!(t.distinct_paths(), 0);
    }
}
