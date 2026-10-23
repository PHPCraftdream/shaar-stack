"""Exact Noq 1.3.0 async raw-ingress admission; control delivery stays unchanged."""
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
