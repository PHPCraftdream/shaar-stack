// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::net::SocketAddrV4;
use std::time::Duration;

#[cfg(test)]
use n0_mainline::OwnedDhtHandle;
use n0_mainline::{MutableItem, OwnedDht, OwnedPutAdmissionError, OwnedPutError};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use self::resolver::{ResolveError, ResolvedAddresses, ResolverState};
use super::super::address::SnapshotError;
#[cfg(test)]
use super::clock::TestClock;
use super::clock::{Clock, ClockSample};
#[cfg(test)]
use super::publisher::PublisherState;
use super::publisher::{PublishError, SignedSnapshot};
use crate::identity::Identity;
use iroh_base::{EndpointId, TransportAddr};
use iroh_dns::pkarr::SignedPacket;

const CLOSE_BOUND: Duration = Duration::from_secs(5);
const COMMANDS: usize = 8;

#[derive(Clone, Debug)]
pub(in crate::native_discovery) enum RuntimeError {
    Publish(PublishError),
    Resolve(ResolveError),
    Put(OwnedPutError),
    PutAdmission(OwnedPutAdmissionError),
    Resource(n0_mainline::ResourceError),
    DeadlineExceeded,
    Closed,
    CloseTimeout,
    Clock,
    PutFailed,
}

pub(super) enum Command {
    Replace(
        Result<Vec<TransportAddr>, SnapshotError>,
        tokio::time::Instant,
        oneshot::Sender<Result<(), RuntimeError>>,
    ),
    Withdraw(oneshot::Sender<Result<(), RuntimeError>>),
    Sample(
        tokio::time::Instant,
        oneshot::Sender<Result<ClockSample, RuntimeError>>,
    ),
    #[cfg(test)]
    Barrier(oneshot::Sender<super::publisher::CleanupReceipt>),
}

#[path = "../publisher/owner_loop.rs"]
mod loop_state;
mod resolver;

pub(in crate::native_discovery) struct RuntimeOwner {
    commands: mpsc::Sender<Command>,
    stop: Option<oneshot::Sender<()>>,
    publisher: Option<JoinHandle<()>>,
    dht: Option<OwnedDht>,
    close_error: Option<RuntimeError>,
    clock: Clock,
    resolver: ResolverState,
}

impl RuntimeOwner {
    pub(in crate::native_discovery) fn start(
        identity: Identity,
        bind: SocketAddrV4,
        bootstrap: &[SocketAddrV4],
    ) -> std::io::Result<Self> {
        Self::start_with_clock(identity, bind, bootstrap, Clock::system())
    }

    #[cfg(test)]
    pub(super) fn start_controlled(
        identity: Identity,
        bind: SocketAddrV4,
        bootstrap: &[SocketAddrV4],
        clock: TestClock,
    ) -> std::io::Result<Self> {
        Self::start_with_clock(identity, bind, bootstrap, clock.clock())
    }

    fn start_with_clock(
        identity: Identity,
        bind: SocketAddrV4,
        bootstrap: &[SocketAddrV4],
        clock: Clock,
    ) -> std::io::Result<Self> {
        let dht = OwnedDht::new(bind, bootstrap)?;
        let handle = dht.handle();
        let key = endpoint_key(&identity)?;
        let (commands, receiver) = mpsc::channel(COMMANDS);
        let (stop, stop_receiver) = oneshot::channel();
        // The owner keeps a clone of the shared clock authority so resolve
        // can sample the receipt locally, immediately after the backend
        // future returns.
        let owner_clock = clock.clone();
        let publisher = tokio::spawn(loop_state::publisher_loop(
            identity,
            key,
            handle,
            receiver,
            stop_receiver,
            clock,
        ));
        Ok(Self {
            commands,
            stop: Some(stop),
            publisher: Some(publisher),
            dht: Some(dht),
            close_error: None,
            clock: owner_clock.clone(),
            resolver: ResolverState::new(owner_clock),
        })
    }

    /// cancel-safe: NO — revocation is not rolled back; pre-ack cancellation cleans work.
    pub(super) async fn replace_until(
        &self,
        snapshot: Vec<TransportAddr>,
        deadline: tokio::time::Instant,
    ) -> Result<(), RuntimeError> {
        if tokio::time::Instant::now() >= deadline {
            return Err(RuntimeError::DeadlineExceeded);
        }
        let (reply, response) = oneshot::channel();
        tokio::time::timeout_at(
            deadline,
            self.commands
                .send(Command::Replace(bounded_replace(snapshot), deadline, reply)),
        )
        .await
        .map_err(|_| RuntimeError::DeadlineExceeded)?
        .map_err(|_| RuntimeError::Closed)?;
        tokio::time::timeout_at(deadline, response)
            .await
            .map_err(|_| RuntimeError::DeadlineExceeded)?
            .map_err(|_| RuntimeError::Closed)?
    }

    /// cancel-safe: NO — revocation is not rolled back; pre-ack cancellation cleans work.
    pub(in crate::native_discovery) async fn replace(
        &self,
        snapshot: Vec<TransportAddr>,
    ) -> Result<(), RuntimeError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        self.replace_until(snapshot, deadline).await
    }

    /// cancel-safe: NO — dropping GET requests backend cleanup; no detached cache writer exists.
    pub(in crate::native_discovery) async fn resolve_until(
        &mut self,
        key: EndpointId,
        deadline: tokio::time::Instant,
    ) -> Result<ResolvedAddresses, RuntimeError> {
        let deadline = deadline.min(tokio::time::Instant::now() + Duration::from_secs(10));
        let sample = self.sample_until(deadline).await?;
        if let Some(cached) = self
            .resolver
            .begin(key, sample)
            .map_err(RuntimeError::Resolve)?
        {
            if tokio::time::Instant::now() >= deadline {
                return Err(RuntimeError::DeadlineExceeded);
            }
            return Ok(cached);
        }
        let handle = self.dht.as_ref().ok_or(RuntimeError::Closed)?.handle();
        let target = MutableItem::target_from_key(key.as_bytes(), None);
        let completion = handle
            .resolve_mutable_until(target, deadline)
            .await
            .map_err(|error| match error {
                n0_mainline::ResourceError::DeadlineExceeded => RuntimeError::DeadlineExceeded,
                other => RuntimeError::Resource(other),
            })?;
        // Receipt sample: taken locally from the shared clock authority the
        // moment the backend future returns, so command-queue delay cannot
        // shift the receipt. The publisher task stays the mediated fault
        // gate; a rollback between samples faults the resolver policy on
        // this sample, and the commit-time current-use freshness check is
        // the safety net for any later verification or scheduling delay.
        let sample = match self.clock.sample() {
            Ok(sample) => sample,
            Err(error) => {
                // A local clock read failure is terminal, mirroring the
                // mediated sampling path.
                self.resolver.note_terminal_clock_fault();
                let _ = tokio::time::timeout_at(deadline, self.withdraw())
                    .await
                    .map_err(|_| RuntimeError::DeadlineExceeded)?;
                return Err(error);
            }
        };
        if tokio::time::Instant::now() >= deadline {
            return Err(RuntimeError::DeadlineExceeded);
        }
        self.resolver
            .complete(key, completion, sample, deadline)
            .await
            .map_err(|error| match error {
                ResolveError::DeadlineExceeded => RuntimeError::DeadlineExceeded,
                other => RuntimeError::Resolve(other),
            })
    }

    /// cancel-safe: NO — a proven clock fault remains terminal and revokes publication.
    async fn sample_until(
        &mut self,
        deadline: tokio::time::Instant,
    ) -> Result<ClockSample, RuntimeError> {
        if tokio::time::Instant::now() >= deadline {
            return Err(RuntimeError::DeadlineExceeded);
        }
        let (reply, response) = oneshot::channel();
        tokio::time::timeout_at(
            deadline,
            self.commands.send(Command::Sample(deadline, reply)),
        )
        .await
        .map_err(|_| RuntimeError::DeadlineExceeded)?
        .map_err(|_| RuntimeError::Closed)?;
        let result = tokio::time::timeout_at(deadline, response)
            .await
            .map_err(|_| RuntimeError::DeadlineExceeded)?
            .map_err(|_| RuntimeError::Closed)?;
        if matches!(
            result,
            Err(RuntimeError::Clock | RuntimeError::Publish(PublishError::ClockFault))
        ) {
            // Terminal clock fault: drop usable resolver cache deadlines
            // while the replay watermarks stay retained for the owner
            // lifetime.
            self.resolver.note_terminal_clock_fault();
            // The barrier cannot acknowledge until any revoked PUT has cleaned up.
            let _ = tokio::time::timeout_at(deadline, self.withdraw())
                .await
                .map_err(|_| RuntimeError::DeadlineExceeded)?;
        }
        result
    }

    #[cfg(test)]
    pub(super) fn dht_handle(&self) -> Option<OwnedDhtHandle> {
        self.dht.as_ref().map(OwnedDht::handle)
    }

    /// cancel-safe: NO — an admitted withdrawal remains effective.
    pub(in crate::native_discovery) async fn withdraw(&self) -> Result<(), RuntimeError> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::Withdraw(reply))
            .await
            .map_err(|_| RuntimeError::Closed)?;
        response.await.map_err(|_| RuntimeError::Closed)?
    }

    #[cfg(test)]
    pub(super) async fn barrier(&self) -> Result<super::publisher::CleanupReceipt, RuntimeError> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::Barrier(reply))
            .await
            .map_err(|_| RuntimeError::Closed)?;
        response.await.map_err(|_| RuntimeError::Closed)
    }

    /// cancel-safe: yes — actual join handles remain owned; shutdown stays requested.
    pub(in crate::native_discovery) async fn close(&mut self) -> Result<(), RuntimeError> {
        if self.publisher.is_none() && self.dht.is_none() {
            return self.close_error.clone().map_or(Ok(()), Err);
        }
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        match tokio::time::timeout(CLOSE_BOUND, self.close_inner()).await {
            Ok(result) => result,
            Err(_) => Err(RuntimeError::CloseTimeout),
        }
    }

    async fn close_inner(&mut self) -> Result<(), RuntimeError> {
        if let Some(publisher) = self.publisher.as_mut() {
            match publisher.await {
                Ok(()) => self.publisher = None,
                Err(_) => {
                    self.publisher = None;
                    self.close_error = Some(RuntimeError::Closed);
                }
            }
        }
        if let Some(dht) = self.dht.as_mut() {
            match dht.close().await {
                Ok(()) => self.dht = None,
                Err(_) => return Err(RuntimeError::CloseTimeout),
            }
        }
        self.close_error.clone().map_or(Ok(()), Err)
    }
}

impl Drop for RuntimeOwner {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(publisher) = self.publisher.take() {
            publisher.abort();
        }
        if let Some(mut dht) = self.dht.take() {
            dht.request_stop();
        }
    }
}

fn bounded_replace(snapshot: Vec<TransportAddr>) -> Result<Vec<TransportAddr>, SnapshotError> {
    if snapshot.len() > 4 {
        Err(SnapshotError::TooManyAddresses)
    } else if snapshot
        .iter()
        .any(|address| !matches!(address, TransportAddr::Ip(_)))
    {
        Err(SnapshotError::UnsupportedTransport)
    } else {
        // Discard caller excess capacity before queueing.
        Ok(snapshot.into_boxed_slice().into_vec())
    }
}

#[cfg(test)]
#[path = "resolver_regressions.rs"]
mod resolver_regressions;
#[cfg(test)]
#[path = "../tests.rs"]
mod tests;

pub(super) fn to_mutable(packet: &SignedSnapshot) -> Result<MutableItem, RuntimeError> {
    let bytes = &packet.bytes;
    let dns_bytes = bytes
        .len()
        .checked_sub(104)
        .ok_or(RuntimeError::PutFailed)?;
    if dns_bytes > 1000 || bytes.len() > 1104 {
        return Err(RuntimeError::PutFailed);
    }
    let signed = SignedPacket::from_bytes(bytes).map_err(|_| RuntimeError::PutFailed)?;
    let sequence =
        i64::try_from(signed.timestamp().as_micros()).map_err(|_| RuntimeError::PutFailed)?;
    if sequence != packet.timestamp_us {
        return Err(RuntimeError::PutFailed);
    }
    Ok(MutableItem::new_signed_unchecked(
        *signed.public_key().as_bytes(),
        signed.signature().to_bytes(),
        signed.encoded_packet(),
        sequence,
        None,
    ))
}

pub(super) fn endpoint_key(identity: &Identity) -> std::io::Result<EndpointId> {
    EndpointId::from_bytes(&identity.public_key_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid identity key"))
}
