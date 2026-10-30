use super::super::*;
use crate::discovery::roles::{DiscoveryEpoch, Role};
use libp2p::{Multiaddr, kad};
use tokio::time::Instant;

pub(in super::super) struct Operation {
    pub(in super::super) epoch: DiscoveryEpoch,
    pub(in super::super) deadline: Instant,
    query: Option<kad::QueryId>,
    query_done: bool,
    delivered: bool,
    next_seed: usize,
    reply: Option<Reply<Vec<DiscoveredRelay>>>,
}

impl Operation {
    /// cancel-safe: yes — observes receiver cancellation without mutating admission.
    pub(in super::super) async fn waiter_closed(&mut self) {
        if let Some(reply) = &mut self.reply {
            reply.closed().await;
        } else {
            std::future::pending::<()>().await;
        }
    }
}

#[derive(Clone, Copy)]
pub(in super::super) struct Control {
    pub(in super::super) key: AttemptKey,
    pub(in super::super) live: bool,
    pub(in super::super) pending: bool,
    pub(in super::super) identified: bool,
    pub(in super::super) protocols: u8,
}

impl Core {
    pub(in super::super) fn start_discovery(&mut self, reply: Reply<Vec<DiscoveredRelay>>) {
        if reply.is_closed() {
            return;
        }
        if self.discovery.is_none() {
            let _ = reply.send(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "discovery is not configured",
            )));
            return;
        }
        if self.discovery_operation.is_some() || !self.infrastructure_empty() {
            let _ = reply.send(Err(capacity()));
            return;
        }
        let now = Instant::now();
        let deadline = now + DEADLINE;
        let local = *self.swarm.local_peer_id();
        let epoch = self
            .swarm
            .behaviour_mut()
            .inner
            .admission
            .discovery_owner()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "discovery authority unavailable",
                )
            })
            .and_then(|owner| owner.begin_discovery_epoch(local, deadline, now));
        let epoch = match epoch {
            Ok(epoch) => epoch,
            Err(error) => {
                let _ = reply.send(Err(error));
                return;
            }
        };
        self.discovery_operation = Some(Operation {
            epoch,
            deadline,
            query: None,
            query_done: false,
            delivered: false,
            next_seed: 0,
            reply: Some(reply),
        });
        self.discovery_tick(now);
    }

    pub(in super::super) fn discovery_deadline(&self) -> Option<Instant> {
        self.discovery_operation
            .as_ref()
            .map(|operation| operation.deadline)
    }

    fn stop_discovery(&mut self, error: io::Error) {
        let Some(mut operation) = self.discovery_operation.take() else {
            return;
        };
        if let Some(owner) = self.swarm.behaviour_mut().inner.admission.discovery_owner() {
            owner.retire_discovery_epoch(operation.epoch);
        }
        if let Some(query) = operation.query {
            super::finish_query(&mut self.swarm.behaviour_mut().inner.protocols, query);
        }
        for control in self
            .discovery_owned_controls(operation.epoch)
            .into_iter()
            .flatten()
        {
            self.close_infrastructure(control.key, Instant::now());
        }
        if let Some(reply) = operation.reply.take() {
            let _ = reply.send(Err(error));
        }
    }

    pub(in super::super) fn retire_discovery_on_drop(&mut self) {
        self.stop_discovery(io::Error::new(
            io::ErrorKind::Interrupted,
            "discovery owner stopped",
        ));
    }

    pub(in super::super) fn discovery_tick(&mut self, now: Instant) {
        let Some(operation) = &self.discovery_operation else {
            return;
        };
        if now >= operation.deadline {
            self.stop_discovery(io::Error::new(
                io::ErrorKind::TimedOut,
                "discovery deadline",
            ));
            return;
        }
        if operation.reply.as_ref().is_some_and(oneshot_closed) {
            self.stop_discovery(io::Error::new(
                io::ErrorKind::Interrupted,
                "discovery waiter cancelled",
            ));
            return;
        }
        if operation.delivered {
            return;
        }
        let epoch = operation.epoch;
        let deadline = operation.deadline;
        if operation.query.is_none()
            && self
                .discovery_owned_controls(epoch)
                .iter()
                .all(Option::is_none)
        {
            // At most four configured descriptors; synchronous failures need no new wake.
            for _ in 0..4 {
                let Some(operation) = &mut self.discovery_operation else {
                    return;
                };
                let selected = self
                    .discovery
                    .as_ref()
                    .and_then(|state| state.seed_at(operation.next_seed));
                let Some((peer, address)) = selected else {
                    self.stop_discovery(io::Error::new(
                        io::ErrorKind::NotFound,
                        "no authenticated DHT seed",
                    ));
                    return;
                };
                operation.next_seed += 1;
                let options = DialOpts::peer_id(peer)
                    .addresses(vec![address.clone()])
                    .allocate_new_port()
                    .build();
                if let Ok(key) = self.stage_discovery_dial(&options, &address, epoch, deadline)
                    && self.submit_native(options, Some(key)).is_ok()
                {
                    break;
                }
            }
            if self
                .discovery_owned_controls(epoch)
                .iter()
                .all(Option::is_none)
            {
                self.stop_discovery(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no admitted discovery seed",
                ));
                return;
            }
        }
        self.complete_discovery_if_ready();
    }

    pub(in super::super) fn discovery_identified_control(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
    ) {
        let Some(operation) = &self.discovery_operation else {
            return;
        };
        if operation.delivered || operation.query_done {
            self.complete_discovery_if_ready();
            return;
        }
        let epoch = operation.epoch;
        let Some(control) = self.discovery_matching_control(epoch, peer, connection) else {
            return;
        };
        if !control.live || !control.identified {
            return;
        }
        if control.protocols & super::DHT == 0 {
            if self
                .swarm
                .behaviour()
                .inner
                .admission
                .roles_view()
                .is_some_and(|view| view.discovery_source(epoch, control.key))
            {
                self.stop_discovery(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "discovery source withdrew DHT",
                ));
            } else if control.protocols & super::HOP == 0 {
                self.close_infrastructure(control.key, Instant::now());
            } else {
                self.complete_discovery_if_ready();
            }
            return;
        }
        let bound = self
            .swarm
            .behaviour_mut()
            .inner
            .admission
            .discovery_owner()
            .ok_or_else(|| io::Error::other("discovery owner unavailable"))
            .and_then(|owner| owner.bind_discovery_source(epoch, control.key, Instant::now()));
        if bound.is_err() {
            self.stop_discovery(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "discovery source generation rejected",
            ));
            return;
        }
        if self
            .discovery_operation
            .as_ref()
            .is_some_and(|operation| operation.query.is_none())
        {
            let local = *self.swarm.local_peer_id();
            let Some(query) =
                super::start_query(&mut self.swarm.behaviour_mut().inner.protocols, local)
            else {
                self.stop_discovery(io::Error::other("discovery protocol unavailable"));
                return;
            };
            let bound = self
                .swarm
                .behaviour_mut()
                .inner
                .admission
                .discovery_owner()
                .ok_or_else(|| io::Error::other("discovery owner unavailable"))
                .and_then(|owner| owner.bind_discovery_query(epoch, query, Instant::now()));
            if bound.is_err() {
                super::finish_query(&mut self.swarm.behaviour_mut().inner.protocols, query);
                self.stop_discovery(io::Error::other("discovery query binding rejected"));
                return;
            }
            if let Some(operation) = &mut self.discovery_operation {
                operation.query = Some(query);
            }
        }
    }

    pub(in super::super) fn discovery_lost_control(&mut self, key: AttemptKey) {
        let Some(operation) = &self.discovery_operation else {
            return;
        };
        if !operation.delivered
            && self
                .swarm
                .behaviour()
                .inner
                .admission
                .roles_view()
                .is_some_and(|view| view.discovery_source(operation.epoch, key))
        {
            self.stop_discovery(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "discovery source control lost",
            ));
        }
    }

    pub(in super::super) fn discovery_dependency_dial(&mut self, options: DialOpts) {
        let selected = self
            .discovery_operation
            .as_ref()
            .filter(|operation| {
                !operation.delivered && !operation.query_done && operation.query.is_some()
            })
            .and_then(|operation| {
                let peer = options.get_peer_id()?;
                let view = self.swarm.behaviour().inner.admission.roles_view()?;
                if !view.discovery_epoch_active(operation.epoch, Instant::now()) {
                    return None;
                }
                let root = view.discovery_referral_root(operation.epoch, peer, Instant::now())?;
                Some((operation.epoch, operation.deadline, peer, root))
            });
        if let Some((epoch, deadline, peer, root)) = selected {
            let eligible = self
                .swarm
                .behaviour()
                .inner
                .admission
                .roles_view()
                .is_some_and(|view| {
                    view.role(peer)
                        .is_none_or(|role| role == Role::Infrastructure)
                });
            if eligible && let Ok(key) = self.stage_discovery_dial(&options, &root, epoch, deadline)
            {
                let _ = self.submit_native(options, Some(key));
                return;
            }
        }
        // Original options must reach Swarm so every child observes synchronous rejection.
        let _ = self.swarm.dial(options);
    }

    pub(in super::super) fn discovery_query_event(&mut self, event: kad::Event) {
        let kad::Event::OutboundQueryProgressed { id, step, .. } = &event else {
            return;
        };
        let owned = self.discovery_operation.as_ref().is_some_and(|operation| {
            !operation.delivered
                && operation.query == Some(*id)
                && self
                    .swarm
                    .behaviour()
                    .inner
                    .admission
                    .roles_view()
                    .is_some_and(|view| {
                        view.discovery_epoch_active(operation.epoch, Instant::now())
                    })
        });
        if !owned {
            super::reject_unowned_query(&mut self.swarm.behaviour_mut().inner.protocols, event);
            return;
        }
        if step.last {
            let operation = self.discovery_operation.as_mut().expect("same owner");
            operation.query_done = true;
            if let Some(owner) = self.swarm.behaviour_mut().inner.admission.discovery_owner() {
                owner.retire_discovery_epoch(operation.epoch);
            }
            self.complete_discovery_if_ready();
        }
    }

    fn complete_discovery_if_ready(&mut self) {
        let Some(operation) = &self.discovery_operation else {
            return;
        };
        if operation.delivered {
            return;
        }
        let epoch = operation.epoch;
        let controls = self.discovery_owned_controls(epoch);
        let ready = controls.map(|control| {
            control
                .filter(|control| {
                    control.live && control.identified && control.protocols & super::HOP != 0
                })
                .map(|control| control.key)
        });
        let has_ready = ready.iter().any(Option::is_some);
        let settled = controls
            .iter()
            .flatten()
            .all(|control| !control.pending && (control.identified || !control.live));
        if !operation.query_done && !(operation.query.is_none() && has_ready && settled) {
            return;
        }
        if !has_ready
            && controls
                .iter()
                .flatten()
                .any(|control| control.pending || (control.live && !control.identified))
        {
            return;
        }
        if let Some(owner) = self.swarm.behaviour_mut().inner.admission.discovery_owner() {
            owner.retire_discovery_epoch(epoch);
        }
        let Some(operation) = &mut self.discovery_operation else {
            return;
        };
        operation.delivered = true;
        if let Some(query) = operation.query {
            super::finish_query(&mut self.swarm.behaviour_mut().inner.protocols, query);
        }
        let reply = operation.reply.take();
        let result = ready
            .iter()
            .flatten()
            .copied()
            .map(|key| DiscoveredRelay { key })
            .collect();
        for control in controls
            .into_iter()
            .flatten()
            .filter(|control| !ready.contains(&Some(control.key)))
        {
            self.close_infrastructure(control.key, Instant::now());
        }
        if reply.is_some_and(|reply| reply.send(Ok(result)).is_err()) {
            self.stop_discovery(io::Error::new(
                io::ErrorKind::Interrupted,
                "discovery result cancelled",
            ));
        }
    }
}

fn oneshot_closed(reply: &Reply<Vec<DiscoveredRelay>>) -> bool {
    reply.is_closed()
}
