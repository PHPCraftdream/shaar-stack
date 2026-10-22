"""Exact, fail-closed edits for the isolated Noq 1.3.0 payload-policy spike."""
from pathlib import Path


def replace(text, old, new, count=1):
    actual = text.count(old)
    if actual != count:
        raise ValueError(f"source mismatch: expected {count}, got {actual}: {old[:80]!r}")
    return text.replace(old, new)


def transport(text):
    text = replace(text, "    pub(crate) send_fairness: bool,", """    pub(crate) send_fairness: bool,
    pub(crate) application_data_filter: Option<fn(crate::FourTuple) -> bool>,""")
    text = replace(text, "impl TransportConfig {", """impl TransportConfig {
    /// CI spike: immutable payload eligibility, independent of QUIC control traffic.
    /// The trusted callback must be pure, deterministic and nonblocking.
    pub fn application_data_filter(&mut self, filter: fn(crate::FourTuple) -> bool) -> &mut Self {
        self.application_data_filter = Some(filter);
        self
    }
""")
    text = replace(text, "            send_fairness: true,", """            send_fairness: true,
            application_data_filter: None,""")
    text = replace(text, "            send_fairness,", """            send_fairness,
            application_data_filter: _,""")
    for direction in ("send", "receive"):
        method = f"    pub fn datagram_{direction}_buffer_size"
        text = replace(text, method, "    /// Empty datagrams consume one budget unit; zero budgets admit none.\n" + method)
    return text


def spaces(text):
    text = replace(text, "    pub(super) other: bool,", """    pub(super) other: bool,
    /// Application STREAM/DATAGRAM readiness, separate from control frames.
    pub(super) application_data: bool,""")
    text = replace(text, "            space_specific,\n            other,", """            space_specific,
            other,
            application_data: false,""", count=1 + 3)
    # Three destructures bind the field; only the PacketSpace constructor is false.
    text = replace(text, "            application_data: false,\n        } =", """            application_data,
        } =""", count=3)
    text = replace(text, "            other: false,", """            other: false,
            application_data: false,""")
    text = replace(text, "        space_specific || other", "        space_specific || other || application_data")
    text = replace(text, "        !acks && !close && !space_specific && !other", "        !acks && !close && !space_specific && !other && !application_data")
    text = replace(text, "        self.other |= other;", """        self.other |= other;
        self.application_data |= application_data;""")
    return text


def connection(text):
    text = replace(text, "        // CONNECTION_CLOSE is allowed", """        // Prefer application-eligible paths without changing control preference.
        let may_send_application_data = match self.config.application_data_filter {
            None => may_send_data,
            Some(filter) => {
                has_cids
                    && !is_abandoned
                    && filter(path_data.network_path)
                    && (is_handshaking
                        || (validated
                            && (status == PathStatus::Available
                                || !self.paths.iter().any(|(id, candidate)| {
                                    self.remote_cids.contains_key(id)
                                        && !self.abandoned_paths.contains(id)
                                        && candidate.data.validated
                                        && candidate.data.local_status() == PathStatus::Available
                                        && filter(candidate.data.network_path)
                                }))))
            }
        };

        // CONNECTION_CLOSE is allowed""")
    text = replace(text, "            may_send_data,\n            may_send_close,", """            may_send_data,
            may_send_application_data,
            may_send_close,""")
    text = replace(text, "    may_send_data: bool,", """    may_send_data: bool,
    /// Payload permission never disables handshake, ACK or path-control frames.
    may_send_application_data: bool,""")
    text = replace(text, "                    !can_send.is_empty() && scheduling_info.may_send_data", """                    ((can_send.acks || can_send.other) && scheduling_info.may_send_data)
                        || (can_send.application_data && scheduling_info.may_send_application_data)""")
    text = replace(text, "&& (can_send.other || can_send.space_specific)", "&& (can_send.other || can_send.application_data || can_send.space_specific)")
    text = replace(text, "if can_send.other && !need_loss_probe && !can_send.close {", "if (can_send.other || can_send.application_data) && !need_loss_probe && !can_send.close {")
    text = replace(text, """        // DATAGRAM
        let mut sent_datagrams = false;
        while !scheduling_info.is_abandoned
            && scheduling_info.may_send_data""", """        // DATAGRAM
        let mut sent_datagrams = false;
        while !scheduling_info.is_abandoned
            && scheduling_info.may_send_application_data""")
    text = replace(text, """        // STREAM
        if !scheduling_info.is_abandoned
            && scheduling_info.may_send_data""", """        // STREAM
        if !scheduling_info.is_abandoned
            && scheduling_info.may_send_application_data""")
    text = replace(text, """        let other = self.streams.can_send_stream_data()
            || self
                .datagrams
                .outgoing
                .front()
                .is_some_and(|x| x.size(true) <= max_size);""", """        let payload_allowed = self.config.application_data_filter
            .is_none_or(|filter| filter(network_path));
        let application_data = payload_allowed
            && (self.streams.can_send_stream_data()
                || self.datagrams.outgoing.front().is_some_and(|x| x.size(true) <= max_size));""")
    text = replace(text, """            space_specific,
            other,
        }""", """            space_specific,
            other: false,
            application_data,
        }""")
    return text


def datagrams(text):
    text = replace(text, "if data.len() > Ord::min(max, send_buffer_size) {", "if data.len() > max || queued_len(data.len()) > send_buffer_size {")
    text = replace(text, ".any(|data| data.len() > Ord::min(max, send_buffer_size))", ".any(|data| data.len() > max || queued_len(data.len()) > send_buffer_size)")
    text = replace(text, "outgoing_total += data.len();", "outgoing_total += queued_len(data.len());", count=2)
    text = replace(text, "self.outgoing_total -= prev.data.len();", "self.outgoing_total -= queued_len(prev.data.len());")
    text = replace(text, "self.outgoing_total -= datagram.data.len();", "self.outgoing_total -= queued_len(datagram.data.len());", count=2)
    text = replace(text, "checked_add(datagram_len)", "checked_add(queued_len(datagram_len))")
    text = replace(text, "if datagram.data.len() > window {", "if queued_len(datagram.data.len()) > window {")
    text = replace(text, "while datagram.data.len() + self.recv_buffered > window {", "while self.recv_buffered > window - queued_len(datagram.data.len()) {")
    text = replace(text, "self.recv_buffered += datagram.data.len();", "self.recv_buffered += queued_len(datagram.data.len());")
    text = replace(text, "self.recv_buffered -= x.len();", "self.recv_buffered -= queued_len(x.len());")
    text = replace(text, "received_bytes += d.data.len();", "received_bytes += queued_len(d.data.len());")
    text = replace(text, "    /// Bytes available in the outgoing datagram buffer", "    /// Queue budget available; an empty datagram consumes one unit.")
    text = replace(text, "#[derive(Default)]\npub(super) struct DatagramState", """// A byte-only budget otherwise permits unbounded empty-datagram metadata.
fn queued_len(payload_len: usize) -> usize {
    payload_len.max(1)
}

#[derive(Default)]
pub(super) struct DatagramState""")
    text = replace(text, "    /// Number of bytes of datagrams that have been received by the local transport but not\n    /// delivered to the application", "    /// Received payload budget, charging at least one unit per queued datagram.")
    return text + '\n#[cfg(test)]\n#[path = "payload_policy_bounds.rs"]\nmod payload_policy_bounds;\n'


def apply(root: Path, test_source: Path):
    edits = {
        "src/config/transport.rs": transport,
        "src/connection/spaces.rs": spaces,
        "src/connection/mod.rs": connection,
        "src/connection/datagrams.rs": datagrams,
    }
    # Build every edited text before writing any file.
    outputs = {name: edit((root / name).read_text(encoding="utf-8")) for name, edit in edits.items()}
    tests = root / "src/tests/mod.rs"
    outputs["src/tests/mod.rs"] = replace(tests.read_text(encoding="utf-8"), "mod token;", "mod token;\nmod payload_policy;\nmod payload_policy_resources;")
    payload_tests = root / "src/tests/payload_policy.rs"
    budget_tests = root / "src/connection/payload_policy_bounds.rs"
    resource_tests = root / "src/tests/payload_policy_resources.rs"
    if any(p.exists() for p in (payload_tests, budget_tests, resource_tests)):
        raise ValueError("unexpected preexisting policy tests")
    test_bytes = test_source.read_bytes()
    budget_bytes = test_source.with_name("payload_policy_bounds.rs").read_bytes()
    resource_bytes = test_source.with_name("payload_policy_resources.rs").read_bytes()
    for name, text in outputs.items():
        (root / name).write_text(text, encoding="utf-8", newline="\n")
    payload_tests.write_bytes(test_bytes)
    budget_tests.write_bytes(budget_bytes)
    resource_tests.write_bytes(resource_bytes)
