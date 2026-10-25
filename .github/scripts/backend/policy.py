"""Reviewed Noq 1.3.0 payload policy; no fixture instrumentation."""
from pathlib import Path

NATIVE_SOCKET_HANDLE = """    pub(super) fn native_socket_handle(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }

"""
NATIVE_SOCKET_HANDLES = """    #[cfg(not(wasm_browser))]
    pub(crate) fn native_socket_handles(&self) -> Vec<Arc<netwatch::UdpSocket>> {
        self.ip.iter().map(|transport| transport.native_socket_handle()).collect()
    }

"""


NATIVE_CID_EVENT = """    /// The first usable remote connection ID was accepted for this path.
    #[non_exhaustive]
    RemoteCidsAvailable {
        /// Path whose remote connection IDs changed from absent to accepted.
        id: PathId,
    },
"""
NATIVE_CID_FIRST = "                    let first_for_path = !self.remote_cids.contains_key(&path_id);\n"
NATIVE_CID_READY = """                    if first_for_path {
                        self.events.push_back(PathEvent::RemoteCidsAvailable { id: path_id }.into());
                    }

"""


def native_cid_events(root: Path):
    paths_path = root / "src/connection/paths.rs"
    connection_path = root / "src/connection/mod.rs"
    paths = paths_path.read_text(encoding="utf-8")
    connection = connection_path.read_text(encoding="utf-8")
    if "RemoteCidsAvailable" in paths or "first_for_path" in connection:
        raise ValueError("unexpected existing native CID readiness bridge")
    paths = replace(paths, "pub enum PathEvent {\n", "pub enum PathEvent {\n" + NATIVE_CID_EVENT)
    connection = replace(connection, """                    let remote_cids = self
                        .remote_cids
                        .entry(path_id)
                        .or_insert_with(|| CidQueue::new(frame.id));""", NATIVE_CID_FIRST + """                    let remote_cids = self
                        .remote_cids
                        .entry(path_id)
                        .or_insert_with(|| CidQueue::new(frame.id));""")
    connection = replace(connection, """                    if self.side.is_server()
                        && path_id == PathId::ZERO""", NATIVE_CID_READY + """                    if self.side.is_server()
                        && path_id == PathId::ZERO""")
    paths_path.write_text(paths, encoding="utf-8", newline="\n")
    connection_path.write_text(connection, encoding="utf-8", newline="\n")


NATIVE_PATH_API = """    /// Establishes an explicit native path on this authenticated client connection.
    /// The caller bounds the wait and closes an unpublished connection on failure.
    /// cancel-safe: NO — cancellation stops waiting, not admitted path validation.
    pub async fn ensure_native_path(&self, remote: std::net::SocketAddr) -> std::io::Result<()> {
        use futures_util::StreamExt;
        use std::{io, net::{IpAddr, SocketAddr}};
        let ip = remote.ip().to_canonical();
        let synthetic = matches!(ip, IpAddr::V6(ip)
            if ip.octets()[..6] == [0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b]);
        if self.side().is_server() || remote.port() == 0 || ip.is_unspecified()
            || ip.is_multicast() || ip == IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
            || synthetic
        {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "a native client path is required"));
        }
        let remote = if ip.is_ipv4() { SocketAddr::new(ip, remote.port()) } else { remote };
        let mut events = self.inner.path_events();
        let mut snapshots = self.paths_stream();
        let (opening, id) = loop {
            let opening = self.inner.open_path_ensure_retained(noq::FourTuple::new(remote, None), noq::PathStatus::Backup);
            if let Some(id) = opening.path_id() { break (opening, id); }
            match opening.await {
                Err(noq::PathError::RemoteCidsExhausted) => {}
                Err(error) => return Err(io::Error::other(error)),
                Ok(_) => return Err(io::Error::other("path admission omitted its identifier")),
            }
            loop {
                tokio::select! {
                    biased;
                    error = self.inner.closed() => return Err(io::Error::new(io::ErrorKind::BrokenPipe, error)),
                    event = events.next() => match event {
                        Some(Ok(noq::PathEvent::RemoteCidsAvailable { .. })) => break,
                        Some(Ok(_)) => {},
                        Some(Err(_)) => return Err(io::Error::other("native path event history lost")),
                        None => return Err(io::ErrorKind::BrokenPipe.into()),
                    }
                }
            }
        };
        tokio::pin!(opening);
        let (mut opened, mut observed) = (false, false);
        loop {
            tokio::select! {
                biased;
                error = self.inner.closed() => return Err(io::Error::new(io::ErrorKind::BrokenPipe, error)),
                event = events.next() => match event {
                    Some(Ok(noq::PathEvent::Abandoned { id: abandoned, reason, .. })) if abandoned == id => {
                        return Err(io::Error::new(io::ErrorKind::NotConnected,
                            format!("native path {id:?} was abandoned: {reason:?}")));
                    }
                    Some(Err(_)) => return Err(io::Error::other("native path event history lost")),
                    None => return Err(io::ErrorKind::BrokenPipe.into()),
                    Some(Ok(_)) => {}
                },
                result = &mut opening, if !opened => {
                    let _path = result.map_err(|error| match error {
                        noq::PathError::ValidationFailed => io::Error::new(io::ErrorKind::NotConnected, error),
                        error => io::Error::other(error),
                    })?;
                    opened = true;
                }
                snapshot = snapshots.next() => {
                    let Some(snapshot) = snapshot else { return Err(io::ErrorKind::BrokenPipe.into()); };
                    observed = snapshot.get(id).is_some_and(|path| matches!(path.remote_addr(),
                        iroh_base::TransportAddr::Ip(address)
                            if address.ip().to_canonical() == ip && address.port() == remote.port()));
                }
            }
            if opened && observed { return Ok(()); }
        }
    }

"""


def native_path_bridge(root: Path):
    path = root / "src/endpoint/connection.rs"
    text = path.read_text(encoding="utf-8")
    if "pub async fn ensure_native_path(" in text:
        raise ValueError("unexpected existing native path bridge")
    text = replace(text, "impl Connection<HandshakeCompleted> {\n",
                   "impl Connection<HandshakeCompleted> {\n" + NATIVE_PATH_API)
    remote_path = root / "src/socket/remote_map/remote_state.rs"
    remote = replace(remote_path.read_text(encoding="utf-8"),
                     "NoqPathEvent::RemoteStatus { .. } | NoqPathEvent::ObservedAddr { .. } => {",
                     "NoqPathEvent::RemoteStatus { .. } | NoqPathEvent::ObservedAddr { .. } | NoqPathEvent::RemoteCidsAvailable { .. } => {")
    path.write_text(text, encoding="utf-8", newline="\n")
    remote_path.write_text(remote, encoding="utf-8", newline="\n")


NATIVE_RETENTION_PROTO_API = """    /// Ensures a path and retains its ID against automatic application pruning.
    /// Retention does not prevent explicit close, remote abandonment, or timeouts.
    pub fn open_path_ensure_retained(
        &mut self,
        network_path: FourTuple,
        initial_status: PathStatus,
        now: Instant,
    ) -> Result<(PathId, bool), PathError> {
        let (id, existed) = self.open_path_ensure(network_path, initial_status, now)?;
        self.paths.get_mut(&id).expect("an ensured path exists").retained_by_application = true;
        Ok((id, existed))
    }

    /// Atomically skips retained paths during automatic application pruning.
    /// Returns true only when the ordinary close operation was performed.
    pub fn close_path_if_unretained(
        &mut self,
        now: Instant,
        path_id: PathId,
        error_code: VarInt,
    ) -> Result<bool, ClosePathError> {
        if !self.abandoned_paths.contains(&path_id)
            && self.paths.get(&path_id).is_some_and(|path| path.retained_by_application)
        {
            return Ok(false);
        }
        self.close_path(now, path_id, error_code).map(|()| true)
    }

"""
NATIVE_RETENTION_FIELD = "    pub(super) retained_by_application: bool,\n"
NATIVE_RETENTION_INITIAL = "                    retained_by_application: false,\n"


def native_path_retention(root: Path):
    paths_path = root / "src/connection/paths.rs"
    connection_path = root / "src/connection/mod.rs"
    paths = paths_path.read_text(encoding="utf-8")
    connection = connection_path.read_text(encoding="utf-8")
    if "retained_by_application" in paths or "open_path_ensure_retained" in connection:
        raise ValueError("unexpected existing native path retention")
    paths = replace(paths, "pub(super) struct PathState {\n",
                    "pub(super) struct PathState {\n" + NATIVE_RETENTION_FIELD)
    connection = replace(connection, "                    prev: None,\n                },",
                         "                    prev: None,\n" + NATIVE_RETENTION_INITIAL + "                },")
    connection = replace(connection, "PathState { data, prev: None }",
                         "PathState { data, prev: None, retained_by_application: false }")
    anchor = "    /// Opens a new path only if no path on the same network path currently exists.\n"
    connection = replace(connection, anchor, NATIVE_RETENTION_PROTO_API + anchor)
    paths_path.write_text(paths, encoding="utf-8", newline="\n")
    connection_path.write_text(connection, encoding="utf-8", newline="\n")


def strip_native_path_retention(connection):
    connection = replace(connection, NATIVE_RETENTION_PROTO_API, "")
    connection = replace(connection, NATIVE_RETENTION_INITIAL, "")
    return replace(connection, "PathState { data, prev: None, retained_by_application: false }",
                   "PathState { data, prev: None }")


NATIVE_PRUNE_SURVIVOR = """            let native_survivor = conn_state.paths.iter()
                .filter(|(id, tuple)| tuple.is_ip() && conn.path(**id).is_some())
                .min_by_key(|(id, tuple)| (*tuple != &selected, **id))
                .map(|(id, _)| *id);

"""
NATIVE_PRUNE_SWAPS = (
    ("            for (path_id, path_fourtuple) in conn_state.paths.iter() {",
     NATIVE_PRUNE_SURVIVOR + "            for (path_id, path_fourtuple) in conn_state.paths.iter() {"),
    ("// Closes redundant IP paths so that at most one remains per connection.",
     "// Keep a live IP survivor and every explicitly retained path."),
    ("conn_state.paths.values().filter(|a| a.is_ip()).count() > 1",
     "Some(*path_id) != native_survivor"),
    ("match path.close() {", "match path.close_if_unretained() {"),
    ("                        Ok(()) => {}\n                    }\n                    continue;",
     "                        Ok(false) => self.state.set_path_status(*conn_id, &path, path_fourtuple),\n"
     "                        Ok(true) => {}\n                    }\n                    continue;"),
)


def native_path_retention_bridge(root: Path):
    path = root / "src/socket/remote_map/remote_state.rs"
    text = path.read_text(encoding="utf-8")
    if "native_survivor" in text or "close_if_unretained" in text:
        raise ValueError("unexpected existing native path pruning retention")
    for old, new in NATIVE_PRUNE_SWAPS:
        text = replace(text, old, new)
    path.write_text(text, encoding="utf-8", newline="\n")


def replace(text, old, new, count=1):
    actual = text.count(old)
    if actual != count:
        raise ValueError(f"source mismatch: expected {count}, got {actual}: {old[:80]!r}")
    return text.replace(old, new)


def transport(text):
    text = replace(text, "    pub(crate) send_fairness: bool,", """    pub(crate) send_fairness: bool,
    pub(crate) application_data_filter: Option<fn(crate::FourTuple) -> bool>,""")
    text = replace(text, "impl TransportConfig {", """impl TransportConfig {
    /// Immutable payload eligibility, independent of QUIC control traffic.
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
    text = replace(text, "        let pto_max = self.max_pto_for_space(self.highest_space);", """        let pto_max = self.max_pto_for_space(self.highest_space);
        trace!(?now, ?pto_max, close_deadline = ?(now + 3 * pto_max), "connection close timer");""")
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
    return text



def forwarder(text):
    method = "    pub fn send_fairness(mut self, value: bool) -> Self {\n        self.0.send_fairness(value);\n        self\n    }"
    return replace(text, method, method + """

    /// Immutable application-payload policy; control remains enabled.
    pub fn application_data_filter(mut self, filter: fn(noq_proto::FourTuple) -> bool) -> Self {
        self.0.application_data_filter(filter);
        self
    }""")


def listener_limits(root: Path):
    endpoint = root / "src/endpoint.rs"
    socket = root / "src/socket.rs"
    text = endpoint.read_text(encoding="utf-8")
    if "incoming_limits:" in text or "pub fn incoming_limits(" in text:
        raise ValueError("listener limits source already modified")
    text = replace(text, "    configured_addrs: BTreeSet<SocketAddr>,", "    configured_addrs: BTreeSet<SocketAddr>,\n    incoming_limits: Option<(usize, u64, u64)>,")
    text = replace(text, "            configured_addrs: Default::default(),", "            configured_addrs: Default::default(),\n            incoming_limits: None,")
    text = replace(text, "            transport_config: self.transport_config.clone(),", "            transport_config: self.transport_config.clone(),\n            incoming_limits: self.incoming_limits,")
    text = replace(text, "    // # The final constructor that everyone needs.", """    /// Sets queued incoming count and per-incoming/total buffered-byte limits.
    /// Byte limits exclude the first packet, whose storage is bounded by count.
    /// Excess Initials or buffered packets may be dropped. Omission preserves defaults.
    pub fn incoming_limits(mut self, count: usize, per_incoming: u64, total: u64) -> Self {
        self.incoming_limits = Some((count, per_incoming, total));
        self
    }

    // # The final constructor that everyone needs.""")
    shared = socket.read_text(encoding="utf-8")
    shared = replace(shared, "    pub(crate) transport_config: QuicTransportConfig,", "    pub(crate) transport_config: QuicTransportConfig,\n    pub(crate) incoming_limits: Option<(usize, u64, u64)>,")
    shared = replace(shared, "        inner.transport_config(self.transport_config.to_inner_arc());", """        inner.transport_config(self.transport_config.to_inner_arc());
        if let Some((count, per_incoming, total)) = self.incoming_limits {
            inner.max_incoming(count);
            inner.incoming_buffer_size(per_incoming);
            inner.incoming_buffer_size_total(total);
        }""")
    shared = replace(shared, "            transport_config: QuicTransportConfig::default(),", "            transport_config: QuicTransportConfig::default(),\n            incoming_limits: None,", count=2)
    # Validate both complete transforms before writing either source file.
    endpoint.write_text(text, encoding="utf-8", newline="\n")
    socket.write_text(shared, encoding="utf-8", newline="\n")


def endpoint_capacity(root: Path):
    config_path = root / "src/config/mod.rs"
    endpoint_path = root / "src/endpoint.rs"
    config = config_path.read_text(encoding="utf-8")
    if "max_connections:" in config:
        raise ValueError("endpoint capacity source already modified")
    config = replace(config, "    pub(crate) max_udp_payload_size: VarInt,", "    pub(crate) max_udp_payload_size: VarInt,\n    pub(crate) max_connections: Option<usize>,")
    config = replace(config, "            reset_key,\n            max_udp_payload_size:", "            reset_key,\n            max_connections: None,\n            max_udp_payload_size:")
    config = replace(config, "    /// Supply a custom connection ID generator factory", """    /// Bounds allocated connection metadata, including closing/draining entries.
    /// Capacity is returned only on Drained. Pending Incoming storage has separate limits.
    /// Zero disables new connections; omission preserves the upstream allocation policy.
    pub fn max_connections(&mut self, limit: usize) -> &mut Self {
        self.max_connections = Some(limit);
        self
    }

    /// Supply a custom connection ID generator factory""")
    endpoint = endpoint_path.read_text(encoding="utf-8")
    endpoint = replace(endpoint, """    ) -> Result<(ConnectionHandle, Connection), ConnectError> {
        if self.cids_exhausted() {""", """    ) -> Result<(ConnectionHandle, Connection), ConnectError> {
        if self.connection_limit_reached() {
            return Err(ConnectError::TooManyConnections);
        }
        if self.cids_exhausted() {""")
    endpoint = replace(endpoint, "if self.cids_exhausted() || self.incoming_buffers.len() >= server_config.max_incoming {", "if self.connection_limit_reached() || self.cids_exhausted() || self.incoming_buffers.len() >= server_config.max_incoming {")
    endpoint = replace(endpoint, '        if self.cids_exhausted() {\n            debug!("refusing connection");', """        if self.connection_limit_reached() {
            self.index.remove_initial(dst_cid);
            return Err(Box::new(AcceptError {
                cause: TransportError::CONNECTION_REFUSED("connection limit reached").into(),
                response: Some(self.initial_close(
                    version,
                    incoming.network_path,
                    &incoming.crypto,
                    src_cid,
                    TransportError::CONNECTION_REFUSED("connection limit reached"),
                    buf,
                )),
            }));
        }
        if self.cids_exhausted() {
            debug!("refusing connection");""")
    endpoint = replace(endpoint, "    /// Whether we've used up 3/4 of the available CID space", """    fn connection_limit_reached(&self) -> bool {
        self.config.max_connections.is_some_and(|limit| self.connections.len() >= limit)
    }

    /// Whether we've used up 3/4 of the available CID space""")
    endpoint = replace(endpoint, "pub enum ConnectError {", """pub enum ConnectError {
    /// The configured allocated-connection metadata limit was reached.
    #[error("connection limit reached")]
    TooManyConnections,""")
    config_path.write_text(config, encoding="utf-8", newline="\n")
    endpoint_path.write_text(endpoint, encoding="utf-8", newline="\n")


def connection_limit_bridge(root: Path):
    endpoint_path = root / "src/endpoint.rs"
    socket_path = root / "src/socket.rs"
    endpoint = endpoint_path.read_text(encoding="utf-8")
    if "connection_limit:" in endpoint:
        raise ValueError("connection limit bridge already modified")
    endpoint = replace(endpoint, "    incoming_limits: Option<(usize, u64, u64)>,", "    incoming_limits: Option<(usize, u64, u64)>,\n    connection_limit: Option<usize>,")
    endpoint = replace(endpoint, "            incoming_limits: None,", "            incoming_limits: None,\n            connection_limit: None,")
    endpoint = replace(endpoint, "            incoming_limits: self.incoming_limits,", "            incoming_limits: self.incoming_limits,\n            connection_limit: self.connection_limit,")
    endpoint = replace(endpoint, "    // # The final constructor that everyone needs.", """    /// Bounds all allocated connections, including closing/draining metadata.
    /// Pending Incoming count/byte storage is configured separately with incoming_limits.
    pub fn connection_limit(mut self, limit: usize) -> Self {
        self.connection_limit = Some(limit);
        self
    }

    // # The final constructor that everyone needs.""")
    socket = socket_path.read_text(encoding="utf-8")
    socket = replace(socket, "    pub(crate) incoming_limits: Option<(usize, u64, u64)>,", "    pub(crate) incoming_limits: Option<(usize, u64, u64)>,\n    pub(crate) connection_limit: Option<usize>,")
    socket = replace(socket, "            incoming_limits: None,", "            incoming_limits: None,\n            connection_limit: None,", count=2)
    socket = replace(socket, "        endpoint_config.grease_quic_bit(false);", """        endpoint_config.grease_quic_bit(false);
        if let Some(limit) = static_config.connection_limit {
            endpoint_config.max_connections(limit);
        }""")
    endpoint_path.write_text(endpoint, encoding="utf-8", newline="\n")
    socket_path.write_text(socket, encoding="utf-8", newline="\n")


def joined_actor_shutdown(root: Path):
    library_path = root / "src/lib.rs"
    socket_path = root / "src/socket.rs"
    module = root / "src/actor_shutdown.rs"
    if module.exists():
        raise ValueError("actor shutdown module already exists")
    library = replace(library_path.read_text(encoding="utf-8"), "pub(crate) mod runtime;", "mod actor_shutdown;\npub(crate) mod runtime;")
    socket = replace(socket_path.read_text(encoding="utf-8"), """        if let Some(task) = task {
            // give the tasks a moment to shutdown cleanly
            let shutdown_done = time::timeout(Duration::from_millis(100), async move {
                if let Err(err) = task.await {
                    warn!("unexpected error in task shutdown: {:?}", err);
                }
            })
            .await;
            match shutdown_done {
                Ok(_) => trace!("tasks finished in time, shutdown complete"),
                Err(time::Elapsed { .. }) => {
                    // Dropping the task will abort it
                    warn!("tasks didn't finish in time, aborting");
                }
            }
        }""", """        if let Some(task) = task {
            if let Err(err) = crate::actor_shutdown::finish_actor(task).await {
                warn!("actor joined after shutdown: {:?}", err);
            }
        }""")
    runtime_path = root / "src/runtime.rs"
    remote_path = root / "src/socket/remote_map.rs"
    child_path = root / "src/socket/remote_map/remote_state.rs"
    runtime = replace(runtime_path.read_text(encoding="utf-8"), "impl Runtime {", """impl Runtime {
    /// Tracks child destruction even when its parent JoinSet is aborted.
    pub(crate) fn track_child<F: Future>(
        &self,
        future: F,
    ) -> impl Future<Output = F::Output> + use<F> {
        #[cfg(not(wasm_browser))]
        { crate::actor_shutdown::track_child(&self.tasks, future) }
        #[cfg(wasm_browser)]
        { future }
    }
""")
    # Construct the runtime before RemoteMap, whose child leases share its tracker.
    socket = replace(socket, "        let remote_map = {", "        let runtime = Arc::new(Runtime::new(secret_key.public()));\n\n        let remote_map = {")
    socket = replace(socket, "                path_selector,\n                span.clone(),", "                path_selector,\n                runtime.clone(),\n                span.clone(),")
    socket = replace(socket, "        let runtime = Arc::new(Runtime::new(secret_key.public()));\n\n        let endpoint =", "        let endpoint =")
    remote = replace(remote_path.read_text(encoding="utf-8"), "    tasks: JoinSet<(EndpointId, Vec<RemoteStateMessage>)>,", "    tasks: JoinSet<(EndpointId, Vec<RemoteStateMessage>)>,\n    runtime: Arc<crate::runtime::Runtime>,")
    remote = replace(remote, "        path_selector: Arc<dyn PathSelector>,\n        span: Span,", "        path_selector: Arc<dyn PathSelector>,\n        runtime: Arc<crate::runtime::Runtime>,\n        span: Span,")
    remote = replace(remote, "                tasks: Default::default(),", "                tasks: Default::default(),\n                runtime,")
    remote = replace(remote, "            &mut self.tasks,\n            self.shutdown_token.clone(),", "            &mut self.tasks,\n            &self.runtime,\n            self.shutdown_token.clone(),")
    remote = replace(remote, "            Arc::new(BiasedRttPathSelector::default()),\n            Span::none(),", "            Arc::new(BiasedRttPathSelector::default()),\n            Arc::new(crate::runtime::Runtime::new(crate::SecretKey::from_bytes(&[0; 32]).public())),\n            Span::none(),")
    child = replace(child_path.read_text(encoding="utf-8"), "        tasks: &mut JoinSet<(EndpointId, Vec<RemoteStateMessage>)>,", "        tasks: &mut JoinSet<(EndpointId, Vec<RemoteStateMessage>)>,\n        runtime: &crate::runtime::Runtime,")
    child = replace(child, "        tasks.spawn(\n            self.run(initial_msgs, rx, shutdown_token)", "        tasks.spawn(runtime.track_child(\n            self.run(initial_msgs, rx, shutdown_token)")
    child = replace(child, "                    remote = %endpoint_id.fmt_short(),\n                )),\n        );", "                    remote = %endpoint_id.fmt_short(),\n                )),\n        ));")
    transports_path = root / "src/socket/transports.rs"
    ip_path = root / "src/socket/transports/ip.rs"
    transports = replace(transports_path.read_text(encoding="utf-8"),
                         "    pub(crate) fn create_sender(&self) -> TransportsSender {",
                         NATIVE_SOCKET_HANDLES + "    pub(crate) fn create_sender(&self) -> TransportsSender {")
    ip = replace(ip_path.read_text(encoding="utf-8"), "impl IpTransport {\n", "impl IpTransport {\n" + NATIVE_SOCKET_HANDLE)
    socket = replace(socket, "    // Runtime used by noq\n    runtime: Arc<Runtime>,",
                     "    // Runtime used by noq\n    runtime: Arc<Runtime>,\n    #[cfg(not(wasm_browser))]\n    native_sockets: Vec<Arc<netwatch::UdpSocket>>,")
    socket = replace(socket, "        let local_addrs_watch = transports.local_addrs_watch();",
                     "        #[cfg(not(wasm_browser))]\n        let native_sockets = transports.native_socket_handles();\n\n        let local_addrs_watch = transports.local_addrs_watch();")
    socket = replace(socket, "            runtime,\n            static_config,",
                     "            runtime,\n            #[cfg(not(wasm_browser))]\n            native_sockets,\n            static_config,")
    socket = replace(socket, "        self.runtime.shutdown().await;", """        trace!("endpoint actor joined");
        self.runtime.shutdown().await;
        trace!("endpoint runtime joined");
        #[cfg(not(wasm_browser))]
        crate::actor_shutdown::close_native_sockets(&self.native_sockets).await;
        trace!("endpoint native sockets closed");""")
    owned = Path(__file__).with_name("actor_shutdown.rs").read_bytes()
    for path, text in ((runtime_path, runtime), (remote_path, remote), (child_path, child),
                       (transports_path, transports), (ip_path, ip)):
        path.write_text(text, encoding="utf-8", newline="\n")
    library_path.write_text(library, encoding="utf-8", newline="\n")
    socket_path.write_text(socket, encoding="utf-8", newline="\n")
    module.write_bytes(owned)


def apply(root: Path):
    edits = {
        "src/config/transport.rs": transport,
        "src/connection/spaces.rs": spaces,
        "src/connection/mod.rs": connection,
        "src/connection/datagrams.rs": datagrams,
    }
    outputs = {name: edit((root / name).read_text(encoding="utf-8")) for name, edit in edits.items()}
    for name, text in outputs.items():
        (root / name).write_text(text, encoding="utf-8", newline="\n")
