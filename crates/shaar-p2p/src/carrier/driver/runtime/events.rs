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
            SwarmEvent::Behaviour(BehaviourEvent::Protocols(event)) => {
                self.discovery_protocol_event(event)
            }
            SwarmEvent::Behaviour(BehaviourEvent::Dial(options)) => {
                // Swarm reports synchronous rejection to every child via DialFailure.
                // Preserve the original connection ID, condition and address selection.
                let _ = self.swarm.dial(options);
            }
            _ => {} // Other notifications add no carrier state.
        }
        Ok(())
    }

    fn discovery_protocol_event(&mut self, event: protocols::Event) {
        match event {
            protocols::Event::Kad(event) => protocols::reject_unowned_query(
                &mut self.swarm.behaviour_mut().inner.protocols,
                event,
            ),
            protocols::Event::Identify(libp2p::identify::Event::Received {
                connection_id,
                peer_id,
                info,
            }) => {
                let advertised =
                    (info.public_key.to_peer_id() == peer_id).then_some(info.protocols.as_slice());
                self.discovery_identified(peer_id, connection_id, advertised);
            }
            protocols::Event::Identify(libp2p::identify::Event::Error {
                connection_id,
                peer_id,
                ..
            }) => {
                self.discovery_identified(peer_id, connection_id, None);
            }
            _ => {}
        }
    }

    fn discovery_identified(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
        advertised: Option<&[StreamProtocol]>,
    ) {
        let Some(capabilities) = self.record_infrastructure_protocols(peer, connection, advertised)
        else {
            return;
        };
        let address = self
            .discovery
            .as_ref()
            .and_then(|state| state.seed_address(peer));
        protocols::update_seed(
            &mut self.swarm.behaviour_mut().inner.protocols,
            peer,
            address,
            capabilities,
        );
    }
}
