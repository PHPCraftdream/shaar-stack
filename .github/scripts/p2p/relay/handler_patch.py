"""Exact-anchor transformation of the reviewed relay handler, after lease preparation."""


def replace(text, old, new):
    if text.count(old) != 1:
        raise ValueError("relay operation handler anchor changed: " + old[:80])
    return text.replace(old, new)


def section(text, start, end, new):
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError("relay operation handler section changed")
    left, right = text.index(start), text.index(end)
    return replace(text, text[left:right], new)


def patch(text):
    text = replace(text, "use crate::{", "use crate::operation_gate::{OperationCapability as Operation, OperationKind};\n\nuse crate::{")
    text = replace(text, "    Reserve {\n", "    Reserve {\n        operation: Operation,\n")
    text = replace(text, "    ResetReservation,", "    ResetReservation { operation: Operation },")
    text = replace(text, "    EstablishCircuit {\n", "    EstablishCircuit {\n        operation: Operation,\n")
    text = replace(text, "In::Reserve { to_listener: _ }", "In::Reserve { .. }")
    text = replace(text, "In::ResetReservation => f", "In::ResetReservation { .. } => f")
    text = replace(text, "                to_dial: _,\n", "                to_dial: _,\n                ..\n")
    text = replace(text, "    ReservationReqAccepted {\n", "    ReservationReqAccepted {\n        operation: Operation,\n")
    text = replace(text, "OutboundCircuitEstablished { limit: Option<protocol::Limit> }", "OutboundCircuitEstablished { operation: Operation, limit: Option<protocol::Limit> }")
    text = replace(text, "    InboundCircuitEstablished {\n", "    InboundCircuitEstablished {\n        operation: Operation,\n")
    text = replace(text, "            (),\n", "            u64,\n")
    text = replace(text, "    pending_streams: VecDeque<oneshot::Sender<Result<Stream, StreamUpgradeError<Infallible>>>>,", "    pending_streams: VecDeque<(u64, Operation, oneshot::Sender<Result<Stream, StreamUpgradeError<Infallible>>>)>,\n    next_stream: u64,\n    reservation_operation: Option<Operation>,")
    text = replace(text, "        mpsc::Sender<transport::ToListenerMsg>,\n    >,", "        (mpsc::Sender<transport::ToListenerMsg>, Operation),\n    >,")
    text = replace(text, "        oneshot::Sender<Result<priv_client::Connection, outbound_hop::ConnectError>>,\n    >,", "        (oneshot::Sender<Result<priv_client::Connection, outbound_hop::ConnectError>>, Operation),\n    >,")
    text = replace(text, "            pending_streams: Default::default(),", "            pending_streams: Default::default(),\n            next_stream: 0,\n            reservation_operation: None,")
    text = section(text, "    fn make_new_reservation(", "\n}\n\nimpl ConnectionHandler for Handler", '''    fn request_stream(&mut self, operation: &Operation) -> Option<oneshot::Receiver<Result<Stream, StreamUpgradeError<Infallible>>>> {
        if !operation.live() || self.pending_streams.len() >= MAX_CONCURRENT_STREAMS_PER_CONNECTION {
            return None;
        }
        let serial = self.next_stream.checked_add(1)?;
        self.next_stream = serial;
        let (sender, receiver) = oneshot::channel();
        self.pending_streams.push_back((serial, operation.clone(), sender));
        self.queued_events.push_back(ConnectionHandlerEvent::OutboundSubstreamRequest {
            protocol: SubstreamProtocol::new(ReadyUpgrade::new(HOP_PROTOCOL_NAME), serial),
        });
        Some(receiver)
    }

    fn make_new_reservation(&mut self, to_listener: Sender<ToListenerMsg>, operation: Operation) {
        let Some(receiver) = self.request_stream(&operation) else { return; };
        let future_operation = operation.clone();
        let result = self.inflight_reserve_requests.try_push(async move {
            future_operation.run(async move {
                let stream = receiver.await
                    .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?
                    .map_err(into_reserve_error)?;
                outbound_hop::make_reservation(stream).await
            }).await
        }, (to_listener, operation));
        if result.is_err() {
            self.pending_streams.pop_back();
            self.queued_events.pop_back();
            tracing::warn!("Dropping in-flight reservation request because we are at capacity");
        }
    }

    fn establish_new_circuit(&mut self, to_dial: oneshot::Sender<Result<Connection, outbound_hop::ConnectError>>, dst_peer_id: PeerId, operation: Operation) {
        let Some(receiver) = self.request_stream(&operation) else { return; };
        let future_operation = operation.clone();
        let result = self.inflight_outbound_connect_requests.try_push(async move {
            future_operation.run(async move {
                let stream = receiver.await
                    .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?
                    .map_err(into_connect_error)?;
                outbound_hop::open_circuit(stream, dst_peer_id).await
            }).await
        }, (to_dial, operation));
        if result.is_err() {
            self.pending_streams.pop_back();
            self.queued_events.pop_back();
            tracing::warn!("Dropping in-flight connect request because we are at capacity");
        }
    }

    fn current(&self, operation: &Operation) -> bool {
        self.reservation_operation.as_ref().is_some_and(|current| current.same(operation))
    }

    fn fail_reservation(&mut self, operation: &Operation) {
        if self.current(operation) {
            operation.cancel();
            self.reservation_operation = None;
            self.reservation.failed();
        }
    }

    fn finish_stream(&mut self, serial: u64, result: Result<Stream, StreamUpgradeError<Infallible>>) {
        if let Some(position) = self.pending_streams.iter().position(|(id, _, _)| *id == serial) {
            let (_, operation, sender) = self.pending_streams.remove(position).expect("position exists");
            if operation.live() {
                let _ = sender.send(result); // A canceled receiver no longer wants the stream.
            }
        }
    }
''')
    text = replace(text, "    type OutboundOpenInfo = ();", "    type OutboundOpenInfo = u64;")
    text = section(text, "    fn on_behaviour_event(", "    fn connection_keep_alive(", '''    fn on_behaviour_event(&mut self, event: Self::FromBehaviour) {
        match event {
            In::Reserve { to_listener, operation } => {
                if to_listener.is_closed() || !operation.matches(self.remote_peer_id, OperationKind::Reserve) || !operation.live() { return; }
                if let Some(old) = self.reservation_operation.replace(operation.clone()) {
                    if !old.same(&operation) { old.cancel(); self.reservation.failed(); }
                }
                self.make_new_reservation(to_listener, operation);
            }
            In::ResetReservation { operation } => self.fail_reservation(&operation),
            In::EstablishCircuit { to_dial, dst_peer_id, operation } => {
                if !to_dial.is_canceled() && operation.matches(self.remote_peer_id, OperationKind::Connect { destination: dst_peer_id }) && operation.live() {
                    self.establish_new_circuit(to_dial, dst_peer_id, operation);
                }
            }
        }
    }

''')
    text = replace(text, "Poll<ConnectionHandlerEvent<Self::OutboundProtocol, (), Self::ToBehaviour>>", "Poll<ConnectionHandlerEvent<Self::OutboundProtocol, u64, Self::ToBehaviour>>")
    text = replace(text, "        loop {\n            // Reservations", '''        loop {
            if self.reservation_operation.as_ref().is_some_and(|op| !op.poll_live(cx, false)) {
                self.reservation_operation = None;
                self.reservation.failed();
            }
            // Reservations''')
    text = replace(text, "                    to_listener,\n                )) => {\n                    return Poll::Ready", "                    (to_listener, operation),\n                )) => {\n                    if to_listener.is_closed() || !operation.live() || !self.current(&operation) { continue; }\n                    return Poll::Ready")
    text = replace(text, "                        self.reservation.accepted(\n", "                        self.reservation.accepted(\n                            operation,\n")
    text = replace(text, "Poll::Ready((Ok(Err(error)), mut to_listener))", "Poll::Ready((Ok(Err(error)), (mut to_listener, operation)))")
    text = replace(text, "Poll::Ready((Err(futures_bounded::Timeout { .. }), mut to_listener))", "Poll::Ready((Err(futures_bounded::Timeout { .. }), (mut to_listener, operation)))")
    # Only matching reservation errors may clear the current reservation.
    text = replace(text, "                    self.reservation.failed();\n                    continue;\n                }\n                Poll::Ready((Err(futures_bounded::Timeout", "                    self.fail_reservation(&operation);\n                    continue;\n                }\n                Poll::Ready((Err(futures_bounded::Timeout")
    text = replace(text, "                    self.reservation.failed();\n                    continue;\n                }\n                Poll::Pending => {}\n            }\n\n            // Circuits", "                    self.fail_reservation(&operation);\n                    continue;\n                }\n                Poll::Pending => {}\n            }\n\n            // Circuits")
    text = replace(text, "                    to_dialer,\n                )) => {", "                    (to_dialer, operation),\n                )) => {\n                    if !operation.live() { continue; }")
    text = replace(text, "Event::OutboundCircuitEstablished { limit }", "Event::OutboundCircuitEstablished { operation, limit }")
    text = replace(text, "Poll::Ready((Ok(Err(error)), to_dialer))", "Poll::Ready((Ok(Err(error)), (to_dialer, _operation)))")
    text = replace(text, "Poll::Ready((Err(futures_bounded::Timeout { .. }), to_dialer))", "Poll::Ready((Err(futures_bounded::Timeout { .. }), (to_dialer, _operation)))")
    text = replace(text, "                    self.reservation.failed();\n                    continue;\n                }\n                Poll::Pending => {}\n            }\n\n            // Return queued events.", "                    continue;\n                }\n                Poll::Pending => {}\n            }\n\n            // Return queued events.")
    text = replace(text, "            if let Some(event) = self.queued_events.pop_front() {\n                return Poll::Ready(event);\n            }", '''            while let Some(event) = self.queued_events.pop_front() {
                if let ConnectionHandlerEvent::OutboundSubstreamRequest { ref protocol } = event {
                    let serial = *protocol.info();
                    if let Some(position) = self.pending_streams.iter().position(|(id, _, _)| *id == serial) {
                        if !self.pending_streams[position].1.live() {
                            self.pending_streams.remove(position);
                            continue;
                        }
                    }
                }
                return Poll::Ready(event);
            }''')
    text = replace(text, "                        let src_peer_id = circuit.src_peer_id();", "                        let Some(operation) = self.reservation_operation.as_ref().filter(|op| op.live()).cloned() else {\n                            self.insert_to_deny_futs(circuit);\n                            continue;\n                        };\n                        let src_peer_id = circuit.src_peer_id();")
    text = replace(text, "Event::InboundCircuitEstablished { src_peer_id, limit }", "Event::InboundCircuitEstablished { operation, src_peer_id, limit }")
    text = replace(text, "                self.make_new_reservation(to_listener);", "                if let Some(operation) = self.reservation_operation.as_ref().filter(|op| op.live()).cloned() {\n                    self.make_new_reservation(to_listener, operation);\n                }")
    text = replace(text, "event: ConnectionEvent<Self::InboundProtocol, Self::OutboundProtocol>,", "event: ConnectionEvent<Self::InboundProtocol, Self::OutboundProtocol, (), u64>,")
    text = replace(text, "                if let Some(next) = self.pending_streams.pop_front() {\n                    let _ = next.send(Ok(ev.protocol));\n                }", "                self.finish_stream(ev.info, Ok(ev.protocol));")
    text = replace(text, "                if let Some(next) = self.pending_streams.pop_front() {\n                    let _ = next.send(Err(ev.error));\n                }", "                self.finish_stream(ev.info, Err(ev.error));")
    text = replace(text, "    fn accepted(\n        &mut self,", "    fn accepted(\n        &mut self,\n        operation: Operation,")
    text = replace(text, "Event::ReservationReqAccepted { renewal, limit, expires_at }", "Event::ReservationReqAccepted { operation, renewal, limit, expires_at }")
    start = text.index("enum Reservation {")
    end = text.index("fn into_reserve_error(")
    reservation = "#![forbid(unsafe_code)]\n\nuse super::*;\n\n" + text[start:end]
    reservation = replace(reservation, "enum Reservation {", "pub(super) enum Reservation {")
    for method in ("accepted", "is_some", "failed", "poll"):
        reservation = replace(reservation, f"    fn {method}(", f"    pub(super) fn {method}(")
    text = text[:start] + text[end:]
    text += '\n#[path = "handler/reservation.rs"]\nmod reservation;\nuse reservation::Reservation;\n'
    return text, reservation
