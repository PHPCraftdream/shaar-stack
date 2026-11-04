// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::time::Duration;

use n0_mainline::{
    OwnedDhtHandle, OwnedPutAdmission, OwnedPutAdmissionError, OwnedPutCleanup, OwnedPutError,
    OwnedPutOperation,
};
use tokio::sync::{mpsc, oneshot};

use super::super::super::address::SnapshotError;
use super::super::clock::Clock;
use super::super::owner::{Command, RuntimeError, to_mutable};
#[cfg(test)]
use super::super::publisher::CleanupReceipt;
use super::super::publisher::{PublishError, PublisherState, SignedSnapshot};
use crate::identity::Identity;
use iroh_base::{EndpointId, TransportAddr};

const REFRESH: Duration = Duration::from_secs(60);
type Queued = (
    Result<Vec<TransportAddr>, SnapshotError>,
    tokio::time::Instant,
    oneshot::Sender<Result<(), RuntimeError>>,
);

enum Work {
    Admission(OwnedPutAdmission),
    Operation(OwnedPutOperation),
}

struct Flight {
    generation: u64,
    work: Work,
    reply: Option<oneshot::Sender<Result<(), RuntimeError>>>,
    initial: bool,
    revoked: bool,
    deadline: tokio::time::Instant,
}

enum Event {
    Command(Option<Command>),
    Stop,
    Admitted(Result<(), OwnedPutAdmissionError>),
    Work(Result<(), RuntimeError>),
    ReplyCancelled,
    Deadline,
}

pub(super) async fn publisher_loop(
    identity: Identity,
    key: EndpointId,
    handle: OwnedDhtHandle,
    mut commands: mpsc::Receiver<Command>,
    mut stop: oneshot::Receiver<()>,
    clock: Clock,
) {
    let mut state = PublisherState::new(key);
    let mut timer = tokio::time::interval(REFRESH);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    timer.tick().await;

    let mut flight: Option<Flight> = None;
    let mut queued: Option<Queued> = None;
    let mut withdrawal: Option<oneshot::Sender<Result<(), RuntimeError>>> = None;
    let mut stopping = false;
    let mut commands_closed = false;
    let mut terminal = false;
    let mut cleanup_count = 0_u64;
    let mut refresh_count = 0_u64;

    loop {
        if let Some(mut current) = flight.take() {
            if current.revoked {
                let cleanup = clean_work(&mut current.work).await;
                if cleanup.is_ok() {
                    cleanup_count = cleanup_count.saturating_add(1);
                } else {
                    terminal = true;
                }
                if !current.initial {
                    timer.reset();
                }
                if let Some(reply) = current.reply.take() {
                    let _ = reply.send(Err(RuntimeError::Closed));
                }
                if let Some(reply) = withdrawal.take() {
                    let result = if cleanup.is_ok() && !terminal {
                        Ok(())
                    } else {
                        Err(RuntimeError::Closed)
                    };
                    let _ = reply.send(result);
                }
                if stopping || commands_closed {
                    return;
                }
                if terminal {
                    fail_queued(&mut queued);
                    continue;
                }
                if let Some((snapshot, deadline, reply)) = queued.take() {
                    if expired(deadline) {
                        send_deadline(reply);
                        continue;
                    }
                    flight = make_replacement(
                        &mut state,
                        &identity,
                        &handle,
                        (snapshot, deadline, reply),
                        &mut timer,
                        &mut terminal,
                        &clock,
                    );
                }
                continue;
            }

            let has_reply = current.reply.is_some();
            let event = tokio::select! {
                biased;
                _ = &mut stop => Event::Stop,
                _ = reply_closed(&mut current.reply), if has_reply => Event::ReplyCancelled,
                command = commands.recv(), if !commands_closed => Event::Command(command),
                _ = tokio::time::sleep_until(current.deadline) => Event::Deadline,
                event = work_event(&mut current.work) => event,
            };
            match event {
                Event::Command(Some(Command::Replace(snapshot, deadline, reply))) => {
                    revoke(&mut state, &mut terminal);
                    current.revoked = true;
                    replace_queued(&mut queued, snapshot, deadline, reply);
                }
                Event::Command(Some(Command::Withdraw(reply))) => {
                    revoke(&mut state, &mut terminal);
                    current.revoked = true;
                    if let Some(old) = withdrawal.replace(reply) {
                        let _ = old.send(Err(RuntimeError::Closed));
                    }
                    fail_queued(&mut queued);
                }
                #[cfg(test)]
                Event::Command(Some(Command::Barrier(reply))) => {
                    let receipt = CleanupReceipt {
                        cleanup_count,
                        refresh_count,
                        active: state.has_active(),
                    };
                    let _ = reply.send(receipt);
                }
                Event::Command(None) => {
                    revoke(&mut state, &mut terminal);
                    current.revoked = true;
                    commands_closed = true;
                }
                Event::Stop => {
                    revoke(&mut state, &mut terminal);
                    current.revoked = true;
                    stopping = true;
                    fail_queued(&mut queued);
                }
                Event::Deadline => {
                    if current.initial {
                        revoke(&mut state, &mut terminal);
                    }
                    current.revoked = true;
                    if let Some(reply) = current.reply.take() {
                        let _ = reply.send(Err(RuntimeError::DeadlineExceeded));
                    }
                    fail_queued(&mut queued);
                }
                Event::ReplyCancelled => {
                    revoke(&mut state, &mut terminal);
                    current.revoked = true;
                    fail_queued(&mut queued);
                }
                Event::Admitted(Ok(())) => match current.work {
                    Work::Admission(mut admission) => match admission.take_operation() {
                        Some(operation) => current.work = Work::Operation(operation),
                        None => {
                            let cleanup = admission.cancel_and_wait().await;
                            if cleanup == OwnedPutCleanup::Clean {
                                cleanup_count = cleanup_count.saturating_add(1);
                            }
                            revoke(&mut state, &mut terminal);
                            terminal = true;
                            if let Some(reply) = current.reply.take() {
                                let _ = reply.send(Err(RuntimeError::Closed));
                            }
                            if let Some(reply) = withdrawal.take() {
                                let _ = reply.send(Err(RuntimeError::Closed));
                            }
                            fail_queued(&mut queued);
                            continue;
                        }
                    },
                    Work::Operation(operation) => current.work = Work::Operation(operation),
                },
                Event::Admitted(Err(error)) => {
                    let clean = error.cleanup == OwnedPutCleanup::Clean;
                    if clean {
                        cleanup_count = cleanup_count.saturating_add(1);
                    } else {
                        terminal = true;
                    }
                    if current.initial || !clean {
                        revoke(&mut state, &mut terminal);
                    }
                    if let Some(reply) = current.reply.take() {
                        let result = if error.error == n0_mainline::ResourceError::DeadlineExceeded
                        {
                            Err(RuntimeError::DeadlineExceeded)
                        } else {
                            Err(RuntimeError::PutAdmission(error))
                        };
                        let _ = reply.send(result);
                    }
                    if let Some(reply) = withdrawal.take() {
                        let result = if clean && !terminal {
                            Ok(())
                        } else {
                            Err(RuntimeError::Closed)
                        };
                        let _ = reply.send(result);
                    }
                    if terminal {
                        fail_queued(&mut queued);
                    }
                    timer.reset();
                    continue;
                }
                Event::Work(result) => {
                    let cleanup = clean_work(&mut current.work).await;
                    let clean = cleanup.is_ok();
                    if clean {
                        cleanup_count = cleanup_count.saturating_add(1);
                    } else {
                        terminal = true;
                    }
                    let before_deadline = tokio::time::Instant::now() < current.deadline;
                    if !before_deadline && current.initial {
                        revoke(&mut state, &mut terminal);
                    }
                    let outcome = cleanup.and(result);
                    finish_completed(
                        &mut state,
                        &mut current,
                        outcome,
                        before_deadline,
                        &mut terminal,
                        &mut timer,
                    );
                    if let Some(reply) = withdrawal.take() {
                        let result = if clean && !terminal {
                            Ok(())
                        } else {
                            Err(RuntimeError::Closed)
                        };
                        let _ = reply.send(result);
                    }
                    if stopping || commands_closed {
                        return;
                    }
                    if terminal {
                        fail_queued(&mut queued);
                    } else if let Some((snapshot, deadline, reply)) = queued.take() {
                        if expired(deadline) {
                            send_deadline(reply);
                        } else {
                            flight = make_replacement(
                                &mut state,
                                &identity,
                                &handle,
                                (snapshot, deadline, reply),
                                &mut timer,
                                &mut terminal,
                                &clock,
                            );
                        }
                    }
                    continue;
                }
            }
            flight = Some(current);
            continue;
        }

        if stopping || commands_closed {
            revoke(&mut state, &mut terminal);
            fail_queued(&mut queued);
            if let Some(reply) = withdrawal.take() {
                let _ = reply.send(if terminal {
                    Err(RuntimeError::Closed)
                } else {
                    Ok(())
                });
            }
            return;
        }
        if terminal {
            fail_queued(&mut queued);
        } else if let Some((snapshot, deadline, reply)) = queued.take() {
            if expired(deadline) {
                send_deadline(reply);
                continue;
            }
            flight = make_replacement(
                &mut state,
                &identity,
                &handle,
                (snapshot, deadline, reply),
                &mut timer,
                &mut terminal,
                &clock,
            );
            continue;
        }

        tokio::select! {
            biased;
            _ = &mut stop => {
                revoke(&mut state, &mut terminal);
                stopping = true;
            }
            command = commands.recv(), if !commands_closed => match command {
                Some(Command::Replace(snapshot, deadline, reply)) => {
                    revoke(&mut state, &mut terminal);
                    replace_queued(&mut queued, snapshot, deadline, reply);
                }
                Some(Command::Withdraw(reply)) => {
                    revoke(&mut state, &mut terminal);
                    let _ = reply.send(if terminal { Err(RuntimeError::Closed) } else { Ok(()) });
                }
                #[cfg(test)]
                Some(Command::Barrier(reply)) => {
                    let _ = reply.send(CleanupReceipt {
                        cleanup_count,
                        refresh_count,
                        active: state.has_active(),
                    });
                }
                None => {
                    revoke(&mut state, &mut terminal);
                    commands_closed = true;
                }
            },
            _ = timer.tick(), if state.has_active() && !terminal => {
                refresh_count = refresh_count.saturating_add(1);
                flight = make_refresh(&mut state, &identity, &handle, &mut timer, &mut terminal, &clock);
            }
        }
    }
}

async fn work_event(work: &mut Work) -> Event {
    match work {
        Work::Admission(admission) => Event::Admitted(admission.wait().await),
        Work::Operation(operation) => {
            Event::Work(operation.wait().await.map(|_| ()).map_err(map_put_error))
        }
    }
}

fn map_put_error(error: OwnedPutError) -> RuntimeError {
    match error {
        OwnedPutError::Resource(resource) => RuntimeError::Resource(resource),
        other => RuntimeError::Put(other),
    }
}

#[cfg(test)]
#[test]
fn resource_put_failures_preserve_their_typed_cause() {
    for cause in [
        n0_mainline::ResourceError::DeadlineExceeded,
        n0_mainline::ResourceError::OperationLimit,
    ] {
        match map_put_error(OwnedPutError::Resource(cause)) {
            RuntimeError::Resource(actual) => assert_eq!(actual, cause),
            other => panic!("resource cause was replaced: {other:?}"),
        }
    }
}

async fn clean_work(work: &mut Work) -> Result<(), RuntimeError> {
    match work {
        Work::Admission(admission) => match admission.cancel_and_wait().await {
            OwnedPutCleanup::Clean => Ok(()),
            OwnedPutCleanup::Unknown => Err(RuntimeError::Closed),
        },
        Work::Operation(operation) => operation
            .cancel_and_wait()
            .await
            .map_err(RuntimeError::Resource),
    }
}

async fn reply_closed(reply: &mut Option<oneshot::Sender<Result<(), RuntimeError>>>) {
    if let Some(sender) = reply.as_mut() {
        sender.closed().await;
    } else {
        std::future::pending::<()>().await;
    }
}

fn finish_completed(
    state: &mut PublisherState,
    flight: &mut Flight,
    outcome: Result<(), RuntimeError>,
    before_deadline: bool,
    terminal: &mut bool,
    timer: &mut tokio::time::Interval,
) {
    let active = !flight.revoked && state.generation_is_active(flight.generation);
    if !active {
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
        timer.reset();
        return;
    }

    let successful = outcome.is_ok();
    if flight.initial {
        if let Some(reply) = flight.reply.take() {
            if reply.send(outcome).is_err() || !successful {
                revoke(state, terminal);
            } else {
                timer.reset();
            }
        }
    } else if !successful {
        timer.reset();
    }
}

fn replace_queued(
    queued: &mut Option<Queued>,
    snapshot: Result<Vec<TransportAddr>, SnapshotError>,
    deadline: tokio::time::Instant,
    reply: oneshot::Sender<Result<(), RuntimeError>>,
) {
    if let Some((_, _, old)) = queued.replace((snapshot, deadline, reply)) {
        let _ = old.send(Err(RuntimeError::Closed));
    }
}

fn fail_queued(queued: &mut Option<Queued>) {
    if let Some((_, _, reply)) = queued.take() {
        let _ = reply.send(Err(RuntimeError::Closed));
    }
}

fn expired(deadline: tokio::time::Instant) -> bool {
    tokio::time::Instant::now() >= deadline
}

fn send_deadline(reply: oneshot::Sender<Result<(), RuntimeError>>) {
    let _ = reply.send(Err(RuntimeError::DeadlineExceeded));
}

fn revoke(state: &mut PublisherState, terminal: &mut bool) {
    if state.revoke().is_err() {
        *terminal = true;
    }
}

fn make_replacement(
    state: &mut PublisherState,
    identity: &Identity,
    handle: &OwnedDhtHandle,
    request: Queued,
    timer: &mut tokio::time::Interval,
    terminal: &mut bool,
    clock: &Clock,
) -> Option<Flight> {
    let (snapshot, deadline, reply) = request;
    if reply.is_closed() {
        revoke(state, terminal);
        return None;
    }
    if *terminal {
        let _ = reply.send(Err(RuntimeError::Closed));
        return None;
    }
    if expired(deadline) {
        send_deadline(reply);
        return None;
    }
    let snapshot = match snapshot {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let _ = reply.send(Err(RuntimeError::Publish(PublishError::Snapshot(error))));
            return None;
        }
    };
    let sample = match clock.sample() {
        Ok(sample) => sample,
        Err(error) => {
            *terminal = true;
            revoke(state, terminal);
            let _ = reply.send(Err(error));
            return None;
        }
    };
    let (generation, packet) = match state.replace(identity, &snapshot, sample) {
        Ok(value) => value,
        Err(error) => {
            if matches!(
                error,
                PublishError::ClockFault | PublishError::GenerationOverflow
            ) {
                *terminal = true;
                revoke(state, terminal);
            }
            let _ = reply.send(Err(RuntimeError::Publish(error)));
            return None;
        }
    };
    let Some(packet) = packet else {
        let _ = reply.send(Ok(()));
        timer.reset();
        return None;
    };
    let flight = make_flight(
        handle,
        generation,
        packet,
        Some(reply),
        true,
        deadline,
        terminal,
    );
    if flight.is_none() {
        revoke(state, terminal);
    }
    flight
}

fn make_refresh(
    state: &mut PublisherState,
    identity: &Identity,
    handle: &OwnedDhtHandle,
    timer: &mut tokio::time::Interval,
    terminal: &mut bool,
    clock: &Clock,
) -> Option<Flight> {
    let sample = match clock.sample() {
        Ok(sample) => sample,
        Err(_) => {
            *terminal = true;
            revoke(state, terminal);
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
            timer.reset();
            return None;
        }
    };
    timer.reset();
    let packet = packet?;
    let flight = make_flight(
        handle,
        generation,
        packet,
        None,
        false,
        tokio::time::Instant::now() + Duration::from_secs(10),
        terminal,
    );
    if flight.is_none() && *terminal {
        revoke(state, terminal);
    }
    flight
}

fn make_flight(
    handle: &OwnedDhtHandle,
    generation: u64,
    packet: SignedSnapshot,
    reply: Option<oneshot::Sender<Result<(), RuntimeError>>>,
    initial: bool,
    deadline: tokio::time::Instant,
    terminal: &mut bool,
) -> Option<Flight> {
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
    })
}
