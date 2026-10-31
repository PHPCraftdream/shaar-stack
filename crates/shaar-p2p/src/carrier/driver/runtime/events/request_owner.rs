use std::{
    collections::{HashMap, VecDeque},
    io,
};

use libp2p::{PeerId, request_response::OutboundRequestId, swarm::ConnectionId};
use tokio::time::Instant;

use super::{Link, REQUEST_LIMIT};

pub(in crate::carrier::driver) struct Pending {
    pub(in crate::carrier::driver) peer: PeerId,
    pub(in crate::carrier::driver) expected: Link,
    pub(in crate::carrier::driver) packet: crate::Datagram,
    pub(in crate::carrier::driver) deadline: Instant,
    pub(in crate::carrier::driver) reply: Option<super::Reply<()>>,
}

#[derive(Default)]
pub(in crate::carrier::driver) struct Owner {
    queued: VecDeque<Pending>,
    submitted:
        HashMap<OutboundRequestId, (PeerId, ConnectionId, Instant, Option<super::Reply<()>>)>,
}

impl Owner {
    pub(in crate::carrier::driver) fn len(&self) -> usize {
        self.queued.len() + self.submitted.len()
    }

    pub(in crate::carrier::driver) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(in crate::carrier::driver) fn queued_len(&self) -> usize {
        self.queued.len()
    }

    pub(in crate::carrier::driver) fn submitted_len(&self) -> usize {
        self.submitted.len()
    }

    pub(in crate::carrier::driver) fn next_deadline(&self) -> impl Iterator<Item = Instant> + '_ {
        self.submitted
            .values()
            .filter_map(|(_, _, deadline, reply)| reply.as_ref().map(|_| *deadline))
    }

    pub(in crate::carrier::driver) fn queued(&self) -> impl Iterator<Item = &Pending> {
        self.queued.iter()
    }

    pub(in crate::carrier::driver) fn admit(&mut self, pending: Pending) -> Result<(), Pending> {
        if self.len() >= REQUEST_LIMIT {
            Err(pending)
        } else {
            self.queued.push_back(pending);
            Ok(())
        }
    }

    pub(in crate::carrier::driver) fn expire_queued(&mut self, now: Instant) {
        self.queued.retain_mut(|request| {
            if request.deadline <= now {
                reply_error(
                    request.reply.take(),
                    io::ErrorKind::TimedOut,
                    "carrier request deadline",
                );
                false
            } else {
                true
            }
        });
    }

    pub(in crate::carrier::driver) fn cancel_queued(&mut self) {
        self.queued.retain_mut(|request| {
            if request
                .reply
                .as_ref()
                .is_some_and(|reply| reply.is_closed())
            {
                request.reply.take();
                false
            } else {
                true
            }
        });
    }

    pub(in crate::carrier::driver) fn purge_stale(&mut self, now: Instant) {
        self.expire_queued(now);
        self.cancel_queued();
    }

    pub(in crate::carrier::driver) fn retain_links(&mut self, links: &[Link]) {
        self.queued.retain_mut(|request| {
            if links.contains(&request.expected) {
                true
            } else {
                reply_error(
                    request.reply.take(),
                    io::ErrorKind::NotConnected,
                    "carrier peer not connected",
                );
                false
            }
        });
    }

    pub(in crate::carrier::driver) fn remove_role(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
    ) {
        self.queued.retain_mut(|request| {
            if request.peer == peer && request.expected.connection == connection {
                reply_error(
                    request.reply.take(),
                    io::ErrorKind::PermissionDenied,
                    "carrier peer role withdrawn",
                );
                false
            } else {
                true
            }
        });
    }

    pub(in crate::carrier::driver) fn take_next_eligible(
        &mut self,
        now: Instant,
        mut is_current: impl FnMut(&Pending) -> bool,
    ) -> Option<Pending> {
        let mut index = 0;
        while index < self.queued.len() {
            let request = &self.queued[index];
            if request.deadline <= now
                || request
                    .reply
                    .as_ref()
                    .is_some_and(|reply| reply.is_closed())
            {
                let mut request = self.queued.remove(index).expect("bounded queue index");
                if request.deadline <= now {
                    reply_error(
                        request.reply.take(),
                        io::ErrorKind::TimedOut,
                        "carrier request deadline",
                    );
                } else {
                    request.reply.take();
                }
                continue;
            }
            if !is_current(request) {
                let mut request = self.queued.remove(index).expect("bounded queue index");
                reply_error(
                    request.reply.take(),
                    io::ErrorKind::NotConnected,
                    "carrier peer not connected",
                );
                continue;
            }
            if self
                .submitted
                .values()
                .any(|(peer, _, _, _)| *peer == request.peer)
            {
                index += 1;
                continue;
            }
            return self.queued.remove(index);
        }
        None
    }

    pub(in crate::carrier::driver) fn submitted(
        &mut self,
        id: OutboundRequestId,
        peer: PeerId,
        connection: ConnectionId,
        deadline: Instant,
        reply: Option<super::Reply<()>>,
    ) {
        self.submitted
            .insert(id, (peer, connection, deadline, reply));
    }

    pub(in crate::carrier::driver) fn finish(
        &mut self,
        id: &OutboundRequestId,
        result: io::Result<()>,
    ) -> bool {
        match self.submitted.remove(id) {
            Some((_, _, _, reply)) => {
                if let Some(reply) = reply {
                    let _ = reply.send(result);
                }
                true
            }
            None => false,
        }
    }

    pub(in crate::carrier::driver) fn retain_submitted(&mut self, now: Instant) -> Vec<PeerId> {
        let mut expired = Vec::new();
        for (peer, _, deadline, reply) in self.submitted.values_mut() {
            if *deadline <= now && reply.is_some() {
                expired.push(*peer);
                reply_error(
                    reply.take(),
                    io::ErrorKind::TimedOut,
                    "carrier request deadline",
                );
            }
        }
        expired
    }

    pub(in crate::carrier::driver) fn close_connection(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
    ) {
        self.queued.retain_mut(|request| {
            if request.peer == peer && request.expected.connection == connection {
                reply_error(
                    request.reply.take(),
                    io::ErrorKind::NotConnected,
                    "carrier connection closed",
                );
                false
            } else {
                true
            }
        });
    }

    pub(in crate::carrier::driver) fn shutdown(&mut self) {
        self.queued.clear();
        for (_, _, _, reply) in self.submitted.values_mut() {
            reply.take();
        }
    }
}

fn reply_error(reply: Option<super::Reply<()>>, kind: io::ErrorKind, message: &'static str) {
    if let Some(reply) = reply {
        let _ = reply.send(Err(io::Error::new(kind, message)));
    }
}

#[cfg(test)]
#[path = "request_owner_tests.rs"]
mod tests;
