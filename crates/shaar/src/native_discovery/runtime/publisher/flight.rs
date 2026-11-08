// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::time::Duration;

use n0_mainline::{OwnedDhtHandle, OwnedPutAdmission, OwnedPutCleanup, OwnedPutOperation};
use tokio::sync::{oneshot, watch};

use super::super::super::address::SnapshotError;
use super::super::clock::Clock;
use super::super::owner::{RuntimeError, to_mutable};
use super::super::publisher::{PublicationStatus, PublishError, PublisherState, SignedSnapshot};
use crate::identity::Identity;
use iroh_base::TransportAddr;

pub(super) type Queued = (
    Result<Vec<TransportAddr>, SnapshotError>,
    tokio::time::Instant,
    oneshot::Sender<Result<(), RuntimeError>>,
);

pub(super) enum Work {
    Admission(OwnedPutAdmission),
    Operation(OwnedPutOperation),
}

/// Ambient publication services the flight constructors share with the
/// owner loop; one stack bundle instead of parallel argument lists.
pub(super) struct PublicationServices<'a> {
    pub(super) timer: &'a mut tokio::time::Interval,
    pub(super) terminal: &'a mut bool,
    pub(super) clock: &'a Clock,
    pub(super) publication: &'a watch::Sender<PublicationStatus>,
}

pub(super) struct Flight {
    pub(super) generation: u64,
    pub(super) work: Work,
    pub(super) reply: Option<oneshot::Sender<Result<(), RuntimeError>>>,
    pub(super) initial: bool,
    pub(super) revoked: bool,
    pub(super) deadline: tokio::time::Instant,
    pub(super) signed_at: tokio::time::Instant,
}

/// Pre-admission flight record: exactly the fields a constructed Flight
/// carries before the Mainline admission is attached.
pub(super) struct FlightDraft {
    pub(super) generation: u64,
    pub(super) reply: Option<oneshot::Sender<Result<(), RuntimeError>>>,
    pub(super) initial: bool,
    pub(super) deadline: tokio::time::Instant,
    pub(super) signed_at: tokio::time::Instant,
}

#[cfg(test)]
impl super::RuntimeOwner {
    pub(in crate::native_discovery::runtime) fn publication_updates(
        &self,
    ) -> watch::Receiver<PublicationStatus> {
        self.publication.clone()
    }
}

pub(super) fn addresses_are_ready(snapshot: &Result<Vec<TransportAddr>, SnapshotError>) -> bool {
    matches!(snapshot, Ok(addresses) if !addresses.is_empty())
}

pub(super) fn finish_completed(
    state: &mut PublisherState,
    flight: &mut Flight,
    outcome: Result<(), RuntimeError>,
    before_deadline: bool,
    terminal: &mut bool,
    timer: &mut tokio::time::Interval,
    publication: &watch::Sender<PublicationStatus>,
) {
    let active = !flight.revoked && state.generation_is_active(flight.generation);
    if !active {
        if state.generation_is_active(flight.generation) {
            let generation = flight.generation;
            publication.send_replace(PublicationStatus::unavailable(generation));
        }
        if let Some(reply) = flight.reply.take() {
            let _ = reply.send(Err(RuntimeError::Closed));
        }
        return;
    }
    if !before_deadline {
        if let Some(reply) = flight.reply.take() {
            let _ = reply.send(Err(RuntimeError::DeadlineExceeded));
        }
        if flight.initial {
            revoke(state, terminal);
        }
        let generation = if flight.initial {
            state.generation()
        } else {
            flight.generation
        };
        publication.send_replace(PublicationStatus::unavailable(generation));
        timer.reset();
        return;
    }

    let successful = outcome.is_ok();
    if flight.initial {
        if let Some(reply) = flight.reply.take() {
            if reply.send(outcome).is_err() || !successful {
                revoke(state, terminal);
                let generation = state.generation();
                publication.send_replace(PublicationStatus::unavailable(generation));
            } else {
                timer.reset();
                publication.send_replace(PublicationStatus::published(
                    flight.generation,
                    flight.signed_at,
                ));
            }
        }
    } else {
        if !successful {
            publication.send_replace(PublicationStatus::unavailable(flight.generation));
            timer.reset();
        } else {
            publication.send_replace(PublicationStatus::published(
                flight.generation,
                flight.signed_at,
            ));
        }
    }
}

pub(super) fn replace_queued(
    queued: &mut Option<Queued>,
    snapshot: Result<Vec<TransportAddr>, SnapshotError>,
    deadline: tokio::time::Instant,
    reply: oneshot::Sender<Result<(), RuntimeError>>,
) {
    if let Some((_, _, old)) = queued.replace((snapshot, deadline, reply)) {
        let _ = old.send(Err(RuntimeError::Closed));
    }
}

pub(super) fn fail_queued(queued: &mut Option<Queued>) {
    if let Some((_, _, reply)) = queued.take() {
        let _ = reply.send(Err(RuntimeError::Closed));
    }
}

pub(super) fn expired(deadline: tokio::time::Instant) -> bool {
    tokio::time::Instant::now() >= deadline
}

pub(super) fn send_deadline(reply: oneshot::Sender<Result<(), RuntimeError>>) {
    let _ = reply.send(Err(RuntimeError::DeadlineExceeded));
}

pub(super) fn revoke(state: &mut PublisherState, terminal: &mut bool) {
    if state.revoke().is_err() {
        *terminal = true;
    }
}

pub(super) fn make_replacement(
    state: &mut PublisherState,
    identity: &Identity,
    handle: &OwnedDhtHandle,
    request: Queued,
    services: PublicationServices<'_>,
) -> Option<Flight> {
    let PublicationServices {
        timer,
        terminal,
        clock,
        publication,
    } = services;
    let (snapshot, deadline, reply) = request;
    if reply.is_closed() {
        revoke(state, terminal);
        let generation = state.generation();
        publication.send_replace(PublicationStatus::unavailable(generation));
        return None;
    }
    if *terminal {
        let generation = state.generation();
        publication.send_replace(PublicationStatus::unavailable(generation));
        let _ = reply.send(Err(RuntimeError::Closed));
        return None;
    }
    if expired(deadline) {
        let generation = state.generation();
        publication.send_replace(PublicationStatus::unavailable(generation));
        send_deadline(reply);
        return None;
    }
    let snapshot = match snapshot {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let generation = state.generation();
            publication.send_replace(PublicationStatus::unavailable(generation));
            let _ = reply.send(Err(RuntimeError::Publish(PublishError::Snapshot(error))));
            return None;
        }
    };
    let sample = match clock.sample() {
        Ok(sample) => sample,
        Err(error) => {
            *terminal = true;
            revoke(state, terminal);
            let generation = state.generation();
            publication.send_replace(PublicationStatus::unavailable(generation));
            let _ = reply.send(Err(error));
            return None;
        }
    };
    let (generation, packet) = match state.replace(identity, &snapshot, sample) {
        Ok(value) => value,
        Err(error) => {
            let generation = state.generation();
            if matches!(
                error,
                PublishError::ClockFault | PublishError::GenerationOverflow
            ) {
                *terminal = true;
                revoke(state, terminal);
            }
            publication.send_replace(PublicationStatus::unavailable(generation));
            let _ = reply.send(Err(RuntimeError::Publish(error)));
            return None;
        }
    };
    publication.send_replace(PublicationStatus::pending(generation));
    let Some(packet) = packet else {
        publication.send_replace(PublicationStatus::unavailable(generation));
        let _ = reply.send(Ok(()));
        timer.reset();
        return None;
    };
    let flight = make_flight(
        handle,
        packet,
        FlightDraft {
            generation,
            reply: Some(reply),
            initial: true,
            deadline,
            signed_at: state.signed_at(),
        },
        terminal,
    );
    if flight.is_none() {
        revoke(state, terminal);
        publication.send_replace(PublicationStatus::unavailable(generation));
    }
    flight
}

pub(super) fn make_refresh(
    state: &mut PublisherState,
    identity: &Identity,
    handle: &OwnedDhtHandle,
    services: PublicationServices<'_>,
) -> Option<Flight> {
    let PublicationServices {
        timer,
        terminal,
        clock,
        publication,
    } = services;
    let sample = match clock.sample() {
        Ok(sample) => sample,
        Err(_) => {
            *terminal = true;
            revoke(state, terminal);
            publication.send_replace(PublicationStatus::unavailable(state.generation()));
            return None;
        }
    };
    let (generation, packet) = match state.refresh(identity, sample) {
        Ok(value) => value,
        Err(error) => {
            if matches!(
                error,
                PublishError::ClockFault | PublishError::GenerationOverflow
            ) {
                *terminal = true;
                revoke(state, terminal);
            }
            let generation = state.generation();
            publication.send_replace(PublicationStatus::unavailable(generation));
            timer.reset();
            return None;
        }
    };
    let Some(packet) = packet else {
        publication.send_replace(PublicationStatus::unavailable(generation));
        timer.reset();
        return None;
    };
    timer.reset();
    let flight = make_flight(
        handle,
        packet,
        FlightDraft {
            generation,
            reply: None,
            initial: false,
            deadline: tokio::time::Instant::now() + Duration::from_secs(10),
            signed_at: state.signed_at(),
        },
        terminal,
    );
    if flight.is_none() {
        if *terminal {
            revoke(state, terminal);
        }
        publication.send_replace(PublicationStatus::unavailable(generation));
    }
    flight
}

fn make_flight(
    handle: &OwnedDhtHandle,
    packet: SignedSnapshot,
    draft: FlightDraft,
    terminal: &mut bool,
) -> Option<Flight> {
    let FlightDraft {
        generation,
        reply,
        initial,
        deadline,
        signed_at,
    } = draft;
    let item = match to_mutable(&packet) {
        Ok(item) => item,
        Err(error) => {
            if let Some(reply) = reply {
                let _ = reply.send(Err(error));
            }
            return None;
        }
    };
    if expired(deadline) {
        if let Some(reply) = reply {
            let _ = reply.send(Err(RuntimeError::DeadlineExceeded));
        }
        return None;
    }
    let admission = match handle.put_mutable_until(item, deadline) {
        Ok(admission) => admission,
        Err(error) => {
            if error.cleanup == OwnedPutCleanup::Unknown {
                *terminal = true;
            }
            if let Some(reply) = reply {
                if error.error == n0_mainline::ResourceError::DeadlineExceeded {
                    let _ = reply.send(Err(RuntimeError::DeadlineExceeded));
                } else {
                    let _ = reply.send(Err(RuntimeError::PutAdmission(error)));
                }
            }
            return None;
        }
    };
    Some(Flight {
        generation,
        work: Work::Admission(admission),
        reply,
        initial,
        revoked: false,
        deadline,
        signed_at,
    })
}
