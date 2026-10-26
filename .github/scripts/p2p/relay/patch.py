"""Owned-operation injection into the pinned relay transport and behaviour."""
from .handler_patch import replace, section, patch as patch_handler


def transport(text):
    text = replace(text, "use crate::{", "use crate::operation_gate::{OperationCapability as Operation, OperationFactory, OperationKind, CancelOnDrop};\n\nuse crate::{")
    text = replace(text, "pub struct Transport {", "pub struct Transport {\n    pub(super) operation_factory: Option<OperationFactory>,")
    text = replace(text, "        let transport = Transport {", "        let transport = Transport {\n            operation_factory: None,")
    text = replace(text, "        let (to_listener, from_behaviour) = mpsc::channel(0);", '''        let operation = Operation::capture(self.operation_factory.as_ref(), relay_peer_id, &relay_addr, OperationKind::Reserve)
            .map_err(|error| TransportError::Other(Error::Operation(error)))?;
        let (to_listener, from_behaviour) = mpsc::channel(0);''')
    text = replace(text, "            .push_back(TransportToBehaviourMsg::ListenReq {", "            .push_back(TransportToBehaviourMsg::ListenReq {\n                operation: operation.clone(),")
    text = replace(text, "        let listener = Listener {", "        let listener = Listener {\n            operation,")
    text = replace(text, "        let mut to_behaviour = self.to_behaviour.clone();", '''        let operation = Operation::capture(self.operation_factory.as_ref(), relay_peer_id, &relay_addr, OperationKind::Connect { destination: dst_peer_id })
            .map_err(|error| TransportError::Other(Error::Operation(error)))?;
        let cancel = CancelOnDrop(Some(operation.clone()));
        let mut to_behaviour = self.to_behaviour.clone();''')
    text = replace(text, "        Ok(async move {\n            let (tx, rx)", "        Ok(async move {\n            let mut cancel = cancel;\n            if !operation.live() { return Err(Error::Operation(crate::operation_gate::denied())); }\n            let (tx, rx)")
    text = replace(text, "                    request_id: RequestId::new(),", "                    request_id: RequestId::new(),\n                    operation: operation.clone(),")
    text = replace(text, "            let stream = rx.await??;", "            let stream = rx.await??;\n            if !operation.live() { return Err(Error::Operation(crate::operation_gate::denied())); }\n            cancel.0 = None;")
    text = replace(text, "pub(crate) struct Listener {", "pub(crate) struct Listener {\n    operation: Operation,")
    text = replace(text, "        self.from_behaviour.close();", "        self.operation.cancel();\n        self.from_behaviour.close();\n        self.queued_events.clear();")
    # A dead operation must not mask a typed rejection already queued for the listener.
    text = replace(text, "                Poll::Pending => {\n                    self.waker = Some(cx.waker().clone());", '''                Poll::Pending => {
                    if !self.operation.live() {
                        // The operation ended without a queued typed rejection; close untyped.
                        self.close(Ok(()));
                        continue;
                    }
                    self.waker = Some(cx.waker().clone());''')
    # A canceled operation must not accept an in-flight success or inbound circuit.
    text = replace(text, "                ToListenerMsg::Reservation(Ok(Reservation { addrs })) => {", "                ToListenerMsg::Reservation(Ok(Reservation { addrs })) => {\n                    if !self.operation.live() { continue; }")
    text = replace(text, "                    let listener_id = self.listener_id;", "                    if !self.operation.live() { continue; }\n                    let listener_id = self.listener_id;")
    # Buffered events of a revoked operation must never be published.
    text = replace(text, "            if let Some(event) = self.queued_events.pop_front() {\n                self.waker = None;\n                return Poll::Ready(Some(event));\n            }", '''            if let Some(event) = self.queued_events.pop_front() {
                if self.is_closed || self.operation.live() {
                    self.waker = None;
                    return Poll::Ready(Some(event));
                }
                // A revoked operation loses buffered success publication, but a
                // queued typed rejection must still be drained from the channel;
                // the Pending branch then closes untyped if the channel is empty.
                self.queued_events.clear();
                continue;
            }''')
    text = replace(text, "impl Stream for Listener {", "impl Drop for Listener {\n    fn drop(&mut self) { self.operation.cancel(); }\n}\n\nimpl Stream for Listener {")
    text = replace(text, "    DialReq {\n", "    DialReq {\n        operation: Operation,\n")
    text = replace(text, "    ListenReq {\n", "    ListenReq {\n        operation: Operation,\n")
    text = replace(text, "pub enum Error {", "pub enum Error {\n    #[error(\"Relay operation is not eligible\")]\n    Operation(#[source] std::io::Error),")
    return text


def client(text):
    text = replace(text, "use crate::{", "use crate::operation_gate::{OperationCapability as Operation, OperationFactory};\n\nuse crate::{")
    for event in ("ReservationReqAccepted", "OutboundCircuitEstablished", "InboundCircuitEstablished"):
        text = replace(text, f"    {event} {{\n", f"    {event} {{\n        /// Exact operation lease; its generation is not peer-wide authority.\n        operation: Operation,\n")
    text = replace(text, "HashMap<ConnectionId, (Multiaddr, ReservationStatus)>", "HashMap<ConnectionId, (Multiaddr, ReservationStatus, Operation)>")
    text = replace(text, "HashMap<ListenerId, ConnectionId>", "HashMap<ListenerId, (ConnectionId, Operation)>")
    text = replace(text, "VecDeque<ToSwarm<Event, Either<handler::In, Infallible>>>", "VecDeque<(Option<Operation>, ToSwarm<Event, Either<handler::In, Infallible>>)>")
    text = replace(text, "impl Behaviour {", '''/// Construct an owner-gated client without changing legacy `new` semantics.
/// The factory runs at transport calls and must consume trusted staged intent.
pub fn new_with_operation_factory(local_peer_id: PeerId, factory: OperationFactory) -> (Transport, Behaviour) {
    let (mut transport, behaviour) = new(local_peer_id);
    transport.operation_factory = Some(factory);
    (transport, behaviour)
}

impl Behaviour {''')
    text = replace(text, ".retain(|_, cid| *cid != connection_id);", ".retain(|_, (cid, operation)| {\n                    if *cid == connection_id { operation.cancel(); false } else { true }\n                });")
    text = replace(text, "if let Some((addr, ReservationStatus::Confirmed)) =\n                self.reservation_addresses.remove(&connection_id)", "if let Some((addr, ReservationStatus::Confirmed, _)) =\n                self.reservation_addresses.remove(&connection_id)")
    text = replace(text, "                    .push_back(ToSwarm::ExternalAddrExpired(addr));", "                    .push_back((None, ToSwarm::ExternalAddrExpired(addr)));")
    text = section(text, "    fn on_listener_closed(", "    fn peer_for_connection(", '''    fn on_listener_closed(&mut self, ListenerClosed { listener_id, .. }: ListenerClosed) {
        let Some((connection_id, operation)) = self.listener_id_to_connection_id.remove(&listener_id) else { return; };
        operation.cancel();
        // A superseded listener must not expire or reset its successor.
        let current = self.reservation_addresses.get(&connection_id)
            .is_some_and(|(_, _, current)| current.same(&operation));
        if current {
            if let Some((addr, ReservationStatus::Confirmed, _)) = self.reservation_addresses.remove(&connection_id) {
                self.queued_actions.push_back((None, ToSwarm::ExternalAddrExpired(addr)));
            }
        }
        if let Some(peer_id) = self.peer_for_connection(connection_id) {
            self.queued_actions.push_back((None, ToSwarm::NotifyHandler {
                peer_id,
                handler: NotifyHandler::One(connection_id),
                event: Either::Left(handler::In::ResetReservation { operation }),
            }));
        }
    }

''')
    # Both established callbacks bind a pending command to its authenticated connection.
    old = "        if let Some(event) = pending_handler_command {\n            handler.on_behaviour_event(event)\n        }"
    if text.count(old) != 2:
        raise ValueError("relay operation established callback anchor changed")
    text = text.replace(old, "        if let Some(event) = pending_handler_command {\n            if event.operation().bind(connection_id) { handler.on_behaviour_event(event); }\n        }")
    text = section(text, "        let event = match handler_event {", "    #[tracing::instrument(level = \"trace\", name = \"NetworkBehaviour::poll\"", '''        let operation = match &handler_event {
            handler::Event::ReservationReqAccepted { operation, .. }
            | handler::Event::OutboundCircuitEstablished { operation, .. }
            | handler::Event::InboundCircuitEstablished { operation, .. } => operation.clone(),
        };
        if !operation.bind(connection) { return; }
        let event = match handler_event {
            handler::Event::ReservationReqAccepted { renewal, limit, expires_at, .. } => {
                let Some((addr, status, current)) = self.reservation_addresses.get_mut(&connection) else { return; };
                if !current.same(&operation) || !operation.live() { return; }
                if *status == ReservationStatus::Pending {
                    *status = ReservationStatus::Confirmed;
                    self.queued_actions.push_back((Some(operation.clone()), ToSwarm::ExternalAddrConfirmed(addr.clone())));
                }
                Event::ReservationReqAccepted {
                    operation: operation.clone(), relay_peer_id: event_source,
                    connection_id: connection, renewal, limit, expires_at,
                }
            }
            handler::Event::OutboundCircuitEstablished { limit, .. } => Event::OutboundCircuitEstablished {
                operation: operation.clone(), relay_peer_id: event_source, connection_id: connection, limit,
            },
            handler::Event::InboundCircuitEstablished { src_peer_id, limit, .. } => Event::InboundCircuitEstablished {
                operation: operation.clone(), relay_peer_id: event_source, connection_id: connection, src_peer_id, limit,
            },
        };
        self.queued_actions.push_back((Some(operation), ToSwarm::GenerateEvent(event)));
    }

''')
    text = replace(text, "        if let Some(action) = self.queued_actions.pop_front() {\n            return Poll::Ready(action);\n        }", '''        if let Some((operation, action)) = self.queued_actions.pop_front() {
            if operation.is_none_or(|op| op.live()) { return Poll::Ready(action); }
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }''')
    text = replace(text, "                listener_id,\n                relay_peer_id,", "                listener_id,\n                operation,\n                relay_peer_id,")
    # These two request arms share the admission anchor.
    old = "            }) => {\n                match self\n                    .directly_connected_peers"
    if text.count(old) != 2:
        raise ValueError("relay operation request dispatch anchors changed")
    text = text.replace(old, "            }) => {\n                if !operation.live() { cx.waker().wake_by_ref(); return Poll::Pending; }\n                match self\n                    .directly_connected_peers")
    text = replace(text, "                    Some(connection_id) => {\n                        self.listener_id_to_connection_id", "                    Some(connection_id) => {\n                        if !operation.bind(*connection_id) { cx.waker().wake_by_ref(); return Poll::Pending; }\n                        self.listener_id_to_connection_id")
    text = replace(text, ".insert(listener_id, *connection_id);", ".insert(listener_id, (*connection_id, operation.clone()));")
    text = replace(text, ".insert(listener_id, relayed_connection_id);", ".insert(listener_id, (relayed_connection_id, operation.clone()));")
    old = "                                ReservationStatus::Pending,\n"
    if text.count(old) != 2:
        raise ValueError("relay operation reservation registration anchors changed")
    text = text.replace(old, old + "                                operation.clone(),\n")
    text = replace(text, "handler::In::Reserve { to_listener }),", "handler::In::Reserve { to_listener, operation }),")
    text = replace(text, "handler::In::Reserve { to_listener });", "handler::In::Reserve { to_listener, operation });")
    text = replace(text, "            Some(transport::TransportToBehaviourMsg::DialReq {\n                relay_addr,", "            Some(transport::TransportToBehaviourMsg::DialReq {\n                operation,\n                relay_addr,")
    text = replace(text, "                    Some(connection_id) => ToSwarm::NotifyHandler {", "                    Some(connection_id) if operation.bind(*connection_id) => ToSwarm::NotifyHandler {")
    text = replace(text, "\n                            to_dial: send_back,\n", "\n                            operation: operation.clone(),\n                            to_dial: send_back,\n")
    text = replace(text, "\n                                to_dial: send_back,\n", "\n                                operation: operation.clone(),\n                                to_dial: send_back,\n")
    text = replace(text, "                        ToSwarm::Dial { opts }\n                    }\n                }\n            }\n            None => unreachable!", "                        ToSwarm::Dial { opts }\n                    }\n                    Some(_) => { cx.waker().wake_by_ref(); return Poll::Pending; }\n                }\n            }\n            None => unreachable!")
    return text


def patch(library, client_source, handler_source, transport_source):
    library = replace(library, "#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]", "#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]\n#![forbid(unsafe_code)]")
    library = replace(library, "mod bounded_lease;", "mod bounded_lease;\nmod operation_gate;")
    library = replace(library, "    pub use crate::priv_client::{Behaviour, Connection, Event, new, transport::Transport};", "    pub use crate::priv_client::{Behaviour, Connection, Event, new, new_with_operation_factory, transport::Transport};\n    pub use crate::operation_gate::{OperationCapability, OperationDescriptor, OperationFactory, OperationKind, OperationOwner};")
    handler_source, reservation_source = patch_handler(handler_source)
    handler_source = replace(handler_source, "impl fmt::Debug for In {", '''impl In {
    pub(crate) fn operation(&self) -> &Operation {
        match self {
            Self::Reserve { operation, .. } | Self::ResetReservation { operation }
            | Self::EstablishCircuit { operation, .. } => operation,
        }
    }
}

impl fmt::Debug for In {''')
    handler_source += '\n#[cfg(test)]\n#[path = "operation_handler_tests.rs"]\nmod operation_handler_tests;\n'
    client_source = client(client_source)
    client_source += '\n#[cfg(test)]\n#[path = "operation_client_tests.rs"]\nmod operation_client_tests;\n'
    transport_source = transport(transport_source)
    transport_source += '\n#[cfg(test)]\n#[path = "operation_transport_tests.rs"]\nmod operation_transport_tests;\n'
    return library, client_source, handler_source, transport_source, reservation_source
