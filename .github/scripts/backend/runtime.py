"""Reviewed backend transforms and the explicitly enabled SDK-test Native IP fault seam."""
from pathlib import Path

from policy import replace


def apply(root: Path):
    library = root / "src/lib.rs"
    endpoint = root / "src/endpoint.rs"
    connection = root / "src/connection.rs"
    module = root / "src/ingress_budget.rs"
    if module.exists():
        raise ValueError("unexpected existing ingress budget module")
    lib = replace(library.read_text(encoding="utf-8"), "mod incoming;", "mod incoming;\nmod ingress_budget;")
    lib = replace(lib, "    Proto(proto::ConnectionEvent),", "    Proto(proto::ConnectionEvent),\n    Datagram(ingress_budget::Queued<proto::ConnectionEvent>),")
    conn = replace(connection.read_text(encoding="utf-8"), """                Poll::Ready(Some(ConnectionEvent::Proto(event))) => {
                    self.inner.handle_event(event);
                }""", """                Poll::Ready(Some(ConnectionEvent::Proto(event))) => {
                    self.inner.handle_event(event);
                }
                Poll::Ready(Some(ConnectionEvent::Datagram(queued))) => {
                    self.inner.handle_event(queued.event);
                    // The remaining lease fields live through protocol processing.
                }""")
    conn = replace(conn, "    sender: Pin<Box<dyn UdpSender>>,\n    pub(crate) runtime:", "    sender: Option<Pin<Box<dyn UdpSender>>>,\n    pub(crate) runtime:")
    conn = replace(conn, "            sender,\n            runtime,\n            send_buffer:", "            sender: Some(sender),\n            runtime,\n            send_buffer:")
    conn = replace(conn, "                    self.sender = sender;", "                    self.sender = Some(sender);")
    conn = replace(conn, "impl Future for ConnectionDriver {", """impl Drop for ConnectionDriver {
    fn drop(&mut self) {
        // Handles may outlive the driver; release native I/O outside the state lock.
        let sender = self.0.lock_without_waking("drop_driver").sender.take();
        drop(sender);
    }
}

impl Future for ConnectionDriver {""")
    conn = replace(conn, """        let max_datagrams = self
            .sender
            .max_transmit_segments()
            .min(MAX_TRANSMIT_SEGMENTS);""", """        let Some(sender) = self.sender.as_mut() else {
            return Ok(false);
        };
        let max_datagrams = sender.max_transmit_segments().min(MAX_TRANSMIT_SEGMENTS);""")
    conn = replace(conn, """            match self
                .sender
                .as_mut()
                .poll_send""", """            match sender.as_mut().poll_send""")
    text = endpoint.read_text(encoding="utf-8")
    text = replace(text, "#[derive(Debug)]\nstruct ConnectionSet {", """use crate::ingress_budget::{Budget, BufferBatch, Queued};

const DATAGRAM_QUEUE_LIMIT: usize = 256;
const DATAGRAM_MEMORY_LIMIT: usize = 8 * 1024 * 1024;

#[derive(Debug)]
struct ConnectionSender {
    sender: mpsc::UnboundedSender<ConnectionEvent>,
    packets: Arc<Budget>,
}

impl ConnectionSender {
    fn new(sender: mpsc::UnboundedSender<ConnectionEvent>) -> Self {
        Self { sender, packets: Budget::new(DATAGRAM_QUEUE_LIMIT) }
    }

    fn send(&self, event: ConnectionEvent) -> Result<(), mpsc::error::SendError<ConnectionEvent>> {
        self.sender.send(event)
    }

    fn send_datagram(&self, event: proto::ConnectionEvent, buffer: &mut BufferBatch) {
        if let Some(queued) = Queued::new(event, &self.packets, buffer) {
            let _ = self.sender.send(ConnectionEvent::Datagram(queued));
        }
    }
}

#[derive(Debug)]
struct ConnectionSet {""")
    text = replace(text, "senders: FxHashMap<ConnectionHandle, mpsc::UnboundedSender<ConnectionEvent>>", "senders: FxHashMap<ConnectionHandle, ConnectionSender>")
    text = replace(text, "self.senders.insert(handle, send);", "self.senders.insert(handle, ConnectionSender::new(send));")
    text = replace(text, "    recv_limiter: WorkLimiter,", "    recv_limiter: WorkLimiter,\n    datagram_memory: Arc<Budget>,")
    text = replace(text, "            recv_limiter: WorkLimiter::new(RECV_TIME_BOUND),", "            recv_limiter: WorkLimiter::new(RECV_TIME_BOUND),\n            datagram_memory: Budget::new(DATAGRAM_MEMORY_LIMIT),")
    text = replace(text, """                        let mut data: BytesMut = buf[0..meta.len].into();
                        while !data.is_empty() {""", """                        let mut data: BytesMut = buf[0..meta.len].into();
                        let Some(lease) = self.datagram_memory.reserve(data.capacity()) else {
                            continue;
                        };
                        let mut memory = BufferBatch::new(lease, meta.stride < data.len());
                        while !data.is_empty() {""")
    text = replace(text, """                                    let _ = self
                                        .connections
                                        .senders
                                        .get_mut(&handle)
                                        .unwrap()
                                        .send(ConnectionEvent::Proto(event));""", """                                    self.connections
                                        .senders
                                        .get_mut(&handle)
                                        .unwrap()
                                        .send_datagram(event, &mut memory);""")
    owned = Path(__file__).with_name("ingress_budget.rs").read_bytes()
    # All anchors and the owned module are ready before modifying downloaded source.
    for path, value in ((library, lib), (endpoint, text), (connection, conn)):
        path.write_text(value, encoding="utf-8", newline="\n")
    module.write_bytes(owned)


NATIVE_RETENTION_CLOSE = """    /// Closes an automatically pruned path only if no application retained its ID.
    /// The check and close share the connection lock with retained admission.
    pub fn close_if_unretained(&self) -> Result<bool, ClosePathError> {
        let mut state = self.conn.lock_and_wake("prune_path");
        state.inner.close_path_if_unretained(
            crate::Instant::now(),
            self.id(),
            TransportErrorCode::APPLICATION_ABANDON_PATH.into(),
        )
    }

"""


def native_path_retention(root: Path):
    connection_path = root / "src/connection.rs"
    path_path = root / "src/path.rs"
    connection = connection_path.read_text(encoding="utf-8")
    path = path_path.read_text(encoding="utf-8")
    if "open_path_ensure_retained" in connection or "close_if_unretained" in path:
        raise ValueError("unexpected existing native runtime path retention")
    start = connection.index("    pub fn open_path_ensure(\n")
    end = connection.index("    /// Opens an additional path if the multipath extension is negotiated.", start)
    method = connection[start:end]
    retained = replace(method, "pub fn open_path_ensure(", "pub fn open_path_ensure_retained(")
    retained = replace(retained, ".open_path_ensure(network_path, initial_status, now)",
                       ".open_path_ensure_retained(network_path, initial_status, now)")
    retained = "    /// Ensures and retains the exact path ID against automatic pruning.\n" + retained
    connection = connection[:end] + retained + connection[end:]
    path = replace(path, "    /// Closes this path.\n", NATIVE_RETENTION_CLOSE + "    /// Closes this path.\n")
    connection_path.write_text(connection, encoding="utf-8", newline="\n")
    path_path.write_text(path, encoding="utf-8", newline="\n")


LOCAL_ABORT_API = """    /// Permanently stop local processing without sending a close packet.
    /// Preserves an existing terminal reason and emits terminal endpoint events once.
    /// The caller must forward pending events before destroying its driver.
    pub fn abort_local(&mut self, reason: ConnectionError) {
        if self.state.is_drained() {
            return;
        }
        if self.state.is_closed() {
            self.close_common();
            self.state.move_to_drained(None, &mut self.endpoint_events);
        } else {
            self.kill(reason);
        }
    }

"""
LOCAL_IO_VARIANT = """    /// Local transport I/O failed; detail remains in the runtime driver's I/O error.
    #[error("local transport I/O failed: {0}")]
    LocalIo(io::ErrorKind),
"""
PROTO_ABORT_SWAPS = (
    ("    /// Terminate the connection instantly, without sending a close packet\n",
     LOCAL_ABORT_API + "    /// Terminate the connection instantly, without sending a close packet\n"),
    ("pub enum ConnectionError {\n", "pub enum ConnectionError {\n" + LOCAL_IO_VARIANT),
    ("                ConnectionError::LocallyClosed => {",
     "                ConnectionError::LocalIo(_) | ConnectionError::LocallyClosed => {"),
    ("            TimedOut => io::ErrorKind::TimedOut,",
     "            LocalIo(kind) => kind,\n            TimedOut => io::ErrorKind::TimedOut,"),
)
DRIVER_ABORT = """    fn abort_driver(&mut self, reason: ConnectionError, shared: &Shared) {
        self.inner.abort_local(reason.clone());
        self.forward_endpoint_events();
        self.forward_app_events(shared);
        if self.error.is_none() {
            self.terminate(reason, shared);
        }
    }

"""
DRIVER_DROP_OLD = """        let sender = self.0.lock_without_waking("drop_driver").sender.take();
        drop(sender);"""
DRIVER_DROP_NEW = """        let resources = {
            let mut state = self.0.lock_without_waking("drop_driver");
            state.abort_driver(ConnectionError::LocallyClosed, &self.0.shared);
            (state.sender.take(), state.conn_events.take(), state.timer.take(), state.driver.take(),
             std::mem::take(&mut state.open_path))
        };
        // Queued Rebind senders and timer implementations can own foreign resources too.
        drop(resources);"""
RUNTIME_ABORT_SWAPS = (
    (DRIVER_DROP_OLD, DRIVER_DROP_NEW),
    ("            conn.terminate(e, &self.0.shared);\n            return Poll::Ready(Ok(()));",
     "            conn.abort_driver(e, &self.0.shared);\n            return Poll::Ready(Ok(()));"),
    ("        let mut keep_going = conn.drive_transmit(cx)?;", """        let mut keep_going = match conn.drive_transmit(cx) {
            Ok(keep_going) => keep_going,
            Err(error) => {
                conn.abort_driver(ConnectionError::LocalIo(error.kind()), &self.0.shared);
                return Poll::Ready(Err(error));
            }
        };"""),
    ("\n    conn_events: mpsc::UnboundedReceiver<ConnectionEvent>,",
     "\n    conn_events: Option<mpsc::UnboundedReceiver<ConnectionEvent>>,"),
    ("            conn_events,\n            endpoint_events,",
     "            conn_events: Some(conn_events),\n            endpoint_events,"),
    ("match self.conn_events.poll_recv(cx)",
     'match self.conn_events.as_mut().expect("live driver receiver").poll_recv(cx)'),
    ("    /// Used to wake up all blocked futures when the connection becomes closed for any reason\n",
     DRIVER_ABORT + "    /// Used to wake up all blocked futures when the connection becomes closed for any reason\n"),
)


def transform_abort(text, swaps, reverse=False):
    for old, new in (reversed(swaps) if reverse else swaps):
        text = replace(text, new if reverse else old, old if reverse else new)
    return text


def local_abort_proto(root: Path):
    path = root / "src/connection/mod.rs"
    text = path.read_text(encoding="utf-8")
    transformed = transform_abort(text, PROTO_ABORT_SWAPS)
    if transform_abort(transformed, PROTO_ABORT_SWAPS, reverse=True) != text:
        raise ValueError("protocol local abort reversal mismatch")
    path.write_text(transformed, encoding="utf-8", newline="\n")


ENDPOINT_ABORT_OLD = """        let mut endpoint = self.0.state.lock().unwrap();
        endpoint.driver_lost = true;
        self.0.shared.incoming.notify_waiters();
        // Drop all outgoing channels, signaling the termination of the endpoint to the associated
        // connections.
        endpoint.recv_state.connections.senders.clear();
        endpoint.recv_state.connections.active_connections = 0;"""
ENDPOINT_ABORT_NEW = """        let senders = {
            let mut endpoint = self.0.state.lock().unwrap();
            endpoint.driver_lost = true;
            endpoint.recv_state.connections.active_connections = 0;
            std::mem::take(&mut endpoint.recv_state.connections.senders)
        };
        // Release channels and wake observers outside the endpoint lock.
        drop(senders);
        self.0.shared.incoming.notify_waiters();
        self.0.shared.all_draining.notify_waiters();
        self.0.shared.idle.notify_waiters();"""


def local_abort_runtime(root: Path):
    path = root / "src/connection.rs"
    text = path.read_text(encoding="utf-8")
    transformed = transform_abort(text, RUNTIME_ABORT_SWAPS)
    restored = transform_abort(transformed, RUNTIME_ABORT_SWAPS, reverse=True)
    if restored != text:
        raise ValueError("runtime local abort reversal mismatch")
    endpoint_path = root / "src/endpoint.rs"
    endpoint = endpoint_path.read_text(encoding="utf-8")
    rewritten_endpoint = replace(endpoint, ENDPOINT_ABORT_OLD, ENDPOINT_ABORT_NEW)
    if replace(rewritten_endpoint, ENDPOINT_ABORT_NEW, ENDPOINT_ABORT_OLD) != endpoint:
        raise ValueError("endpoint local abort reversal mismatch")
    endpoint = rewritten_endpoint
    path.write_text(transformed, encoding="utf-8", newline="\n")
    endpoint_path.write_text(endpoint, encoding="utf-8", newline="\n")


def native_cid_events(root: Path):
    path = root / "src/connection.rs"
    text = replace(path.read_text(encoding="utf-8"),
                   "Path(evt @ PathEvent::RemoteStatus { .. }) => {",
                   "Path(evt @ (PathEvent::RemoteStatus { .. } | PathEvent::RemoteCidsAvailable { .. })) => {")
    path.write_text(text, encoding="utf-8", newline="\n")


NATIVE_GATE_FEATURE = "shaar-native-gate"
NATIVE_GATE_MODULE = '''// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
//! Explicitly enabled SDK-test packet loss; absent from default production builds.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Endpoint-scoped Native IP fault injection, including discovered alternate routes.
#[derive(Debug, Default)]
pub struct NativePacketGate {
    blocked: AtomicBool,
    tx_allowed: AtomicU64,
    rx_allowed: AtomicU64,
    tx_dropped: AtomicU64,
    rx_dropped: AtomicU64,
}

impl NativePacketGate {
    /// Enables or disables silent Native IP loss; never affects Custom or Relay.
    pub fn set_blocked(&self, blocked: bool) {
        self.blocked.store(blocked, Ordering::SeqCst);
    }

    /// Returns allowed TX/RX attempts and dropped TX/RX datagrams, in that order.
    /// Allowed TX counts are not claimed to be successfully delivered packets.
    pub fn counts(&self) -> [u64; 4] {
        [self.tx_allowed.load(Ordering::Relaxed), self.rx_allowed.load(Ordering::Relaxed),
         self.tx_dropped.load(Ordering::Relaxed), self.rx_dropped.load(Ordering::Relaxed)]
    }

    pub(crate) fn drop_tx(&self, count: usize) -> bool {
        self.record(count, &self.tx_allowed, &self.tx_dropped)
    }

    pub(crate) fn drop_rx(&self, count: usize) -> bool {
        self.record(count, &self.rx_allowed, &self.rx_dropped)
    }

    fn record(&self, count: usize, allowed: &AtomicU64, dropped: &AtomicU64) -> bool {
        let blocked = self.blocked.load(Ordering::SeqCst);
        let counter = if blocked { dropped } else { allowed };
        let count = u64::try_from(count).expect("bounded datagram batch fits u64");
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |old| Some(old.saturating_add(count)));
        blocked
    }
}
'''

NATIVE_GATE_SWAPS = {
    "Cargo.toml": [("[features]\n", '[features]\nshaar-native-gate = []\n')],
    "src/endpoint.rs": [("impl Endpoint {", '''#[cfg(feature = "shaar-native-gate")]
pub use crate::socket::native_gate::NativePacketGate;

impl Endpoint {
    /// Returns the endpoint-wide SDK-test IP packet gate.
    /// This API and its packet-hot-path checks do not exist unless explicitly enabled.
    #[cfg(feature = "shaar-native-gate")]
    pub fn native_packet_gate(&self) -> Arc<NativePacketGate> {
        self.inner.native_packet_gate.clone()
    }
''')],
    "src/socket.rs": [
        ("pub(crate) mod transports;", '''pub(crate) mod transports;
#[cfg(feature = "shaar-native-gate")]
pub(crate) mod native_gate;'''),
        ("pub(crate) struct Socket {", '''pub(crate) struct Socket {
    #[cfg(feature = "shaar-native-gate")]
    pub(crate) native_packet_gate: Arc<crate::endpoint::NativePacketGate>,'''),
        ("        let sock = Arc::new(Socket {", '''        let sock = Arc::new(Socket {
            #[cfg(feature = "shaar-native-gate")]
            native_packet_gate: transports.native_packet_gate.clone(),'''),
        ('''            self.metrics
                .socket
                .recv_datagrams''', '''            #[cfg(feature = "shaar-native-gate")]
            if matches!(remote_addr, transports::Addr::Ip(_))
                && self.native_packet_gate.drop_rx(datagram_count)
            {
                noq_meta.len = 0;
                continue;
            }
            self.metrics
                .socket
                .recv_datagrams'''),
    ],
    "src/socket/transports.rs": [
        ("pub(crate) struct Transports {", '''pub(crate) struct Transports {
    #[cfg(feature = "shaar-native-gate")]
    pub(super) native_packet_gate: Arc<crate::endpoint::NativePacketGate>,'''),
        ('''        Ok(Self {
            #[cfg(not(wasm_browser))]
            ip,
            relay,
            custom,
            poll_recv_counter:''', '''        Ok(Self {
            #[cfg(feature = "shaar-native-gate")]
            native_packet_gate: Arc::new(Default::default()),
            #[cfg(not(wasm_browser))]
            ip,
            relay,
            custom,
            poll_recv_counter:'''),
        ('''        TransportsSender {
            #[cfg(not(wasm_browser))]
            ip,''', '''        TransportsSender {
            #[cfg(feature = "shaar-native-gate")]
            native_packet_gate: self.native_packet_gate.clone(),
            #[cfg(not(wasm_browser))]
            ip,'''),
        ("pub(crate) struct TransportsSender {", '''pub(crate) struct TransportsSender {
    #[cfg(feature = "shaar-native-gate")]
    native_packet_gate: Arc<crate::endpoint::NativePacketGate>,'''),
        ('''        match network_path {
            #[cfg(wasm_browser)]''', '''        #[cfg(feature = "shaar-native-gate")]
        if network_path.is_ip() && self.native_packet_gate.drop_tx(transmit.datagram_count()) {
            return Poll::Ready(Ok(()));
        }
        match network_path {
            #[cfg(wasm_browser)]'''),
    ],
}


def native_gate_text(relative: str, text: str, *, reverse: bool = False) -> str:
    swaps = NATIVE_GATE_SWAPS.get(relative, ())
    for old, new in reversed(swaps) if reverse else swaps:
        text = replace(text, new if reverse else old, old if reverse else new)
    return text


def native_packet_gate(root: Path):
    module = root / "src/socket/native_gate.rs"
    if module.exists():
        raise ValueError("unexpected existing SDK-test native packet gate")
    # Validate every exact-count edit and its reversal before writing any source.
    transformed = {}
    for relative in NATIVE_GATE_SWAPS:
        before = (root / relative).read_text(encoding="utf-8")
        after = native_gate_text(relative, before)
        if native_gate_text(relative, after, reverse=True) != before:
            raise ValueError("SDK-test native packet gate reversal mismatch")
        transformed[relative] = after
    for relative, text in transformed.items():
        (root / relative).write_text(text, encoding="utf-8", newline="\n")
    module.write_text(NATIVE_GATE_MODULE, encoding="utf-8", newline="\n")
