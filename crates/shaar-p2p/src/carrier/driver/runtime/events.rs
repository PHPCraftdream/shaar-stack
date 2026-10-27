use super::*;

impl Core {
    pub(super) fn event(&mut self, event: SwarmEvent<BehaviourEvent>) -> io::Result<()> {
        if self.infrastructure_event(&event) {
            return Ok(());
        }
        match event {
            SwarmEvent::NewListenAddr {
                listener_id,
                address,
            } if listener_id == self.native_listener => {
                let address = socket_address(&address)
                    .ok_or_else(|| io::Error::other("unexpected carrier listen address"))?;
                self.listening.send_replace(Some(address));
            }
            SwarmEvent::NewListenAddr {
                listener_id,
                address,
            } => self.relay_listen_address(listener_id, address),
            SwarmEvent::ListenerError { listener_id, error }
                if listener_id == self.native_listener =>
            {
                return Err(error);
            }
            SwarmEvent::ListenerError { listener_id, error } => {
                self.relay_listener_failed(listener_id, error)
            }
            SwarmEvent::ListenerClosed {
                listener_id,
                reason,
                ..
            } if listener_id == self.native_listener => {
                return Err(reason
                    .err()
                    .unwrap_or_else(|| io::Error::other("carrier listener closed")));
            }
            SwarmEvent::ListenerClosed {
                listener_id,
                reason,
                ..
            } => self.relay_listener_closed(listener_id, reason.err()),
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            } => {
                let pending = self.pending.remove(&connection_id);
                let intended = pending.as_ref().and_then(|pending| pending.route);
                let gated = pending.as_ref().and_then(|pending| pending.operation);
                let result = self.relay_connected(
                    peer_id,
                    connection_id,
                    endpoint.is_relayed(),
                    intended,
                    gated.map(|ticket| ticket.generation),
                    match &endpoint {
                        libp2p::core::ConnectedPoint::Listener { local_addr, .. } => {
                            Some(local_addr)
                        }
                        _ => None,
                    },
                );
                if result.is_err() {
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    self.relay.routes.remove(&connection_id);
                } else {
                    self.publish_links();
                }
                if let Some(pending) = pending {
                    if let Some(ticket) = pending.operation {
                        if result.is_ok() {
                            self.relay.gate.establish(ticket);
                        } else {
                            self.relay.gate.revoke_generation(
                                ticket.relay,
                                relay::gate::Slot::Connect,
                                ticket.generation,
                            );
                        }
                        self.relay.gate.terminal(ticket);
                    }
                    let _ = pending.reply.send(result.map(|()| connection_id));
                }
            }
            SwarmEvent::OutgoingConnectionError {
                connection_id,
                error,
                ..
            } => {
                if let Some(pending) = self.pending.remove(&connection_id) {
                    if let Some(attempt) = pending.attempt {
                        self.terminal(attempt, None);
                    }
                    if let Some(ticket) = pending.operation {
                        self.relay.gate.revoke_generation(
                            ticket.relay,
                            relay::gate::Slot::Connect,
                            ticket.generation,
                        );
                        self.relay.gate.terminal(ticket);
                    }
                    let _ = pending.reply.send(Err(io::Error::other(error)));
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                num_established,
                ..
            } => {
                self.relay_control_closed(peer_id, connection_id);
                self.publish_links();
                if num_established == 0
                    && let Some(Closing {
                        reply: Some(reply), ..
                    }) = self.closing.remove(&peer_id)
                {
                    let _ = reply.send(Ok(()));
                }
                // Request-response emits terminal failures; request charges stay until then.
            }
            SwarmEvent::Behaviour(BehaviourEvent::Relays(event)) => self.relay_event(event),
            SwarmEvent::Behaviour(BehaviourEvent::Packets(event)) => self.packet(event),
            SwarmEvent::Behaviour(BehaviourEvent::Admission(event)) => match event {},
            _ => {} // Other notifications add no carrier state.
        }
        Ok(())
    }
}
