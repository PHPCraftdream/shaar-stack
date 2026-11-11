// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::net::SocketAddrV4;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[cfg(test)]
use n0_mainline::OwnedDhtHandle;
use n0_mainline::{MutableItem, OwnedDht, OwnedPutAdmissionError, OwnedPutError};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

pub(crate) use self::resolver::ResolvedAddresses;
use self::resolver::{ResolveError, ResolverState};
use super::super::address::SnapshotError;
#[cfg(test)]
use super::clock::TestClock;
use super::clock::{Clock, ClockSample};
#[cfg(test)]
use super::publisher::PublisherState;
use super::publisher::{PublicationStatus, PublishError, SignedSnapshot};
use crate::identity::Identity;
use iroh_base::{EndpointId, TransportAddr};
use iroh_dns::pkarr::SignedPacket;

const CLOSE_BOUND: Duration = Duration::from_secs(5);
const COMMANDS: usize = 8;

#[derive(Clone, Debug)]
pub(crate) enum RuntimeError {
    Publish(PublishError),
    Resolve(ResolveError),
    Put(OwnedPutError),
    PutAdmission(OwnedPutAdmissionError),
    Resource(n0_mainline::ResourceError),
    ResolveBusy,
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
        Option<oneshot::Sender<()>>,
    ),
    PublicationStatus(oneshot::Sender<PublicationStatus>),
    Withdraw(oneshot::Sender<Result<(), RuntimeError>>),
    Sample(
        tokio::time::Instant,
        oneshot::Sender<Result<ClockSample, RuntimeError>>,
    ),
    #[cfg(test)]
    Barrier(oneshot::Sender<super::publisher::CleanupReceipt>),
}

mod endpoint;
#[path = "../publisher/flight.rs"]
mod flight;
#[path = "../publisher/owner_loop.rs"]
mod loop_state;
mod options;
mod resolver;

#[derive(Clone)]
pub(crate) struct PublicationHandle {
    commands: mpsc::Sender<Command>,
    clock_fault: Arc<AtomicBool>,
}

impl PublicationHandle {
    /// cancel-safe: NO — queue admission can precede response delivery; publisher retains cleanup.
    pub(crate) async fn replace_with_admission(
        &self,
        snapshot: Vec<TransportAddr>,
        admitted: oneshot::Sender<()>,
    ) -> Result<(), RuntimeError> {
        self.replace_inner(
            snapshot,
            tokio::time::Instant::now() + Duration::from_secs(10),
            Some(admitted),
        )
        .await
    }

    async fn replace_inner(
        &self,
        snapshot: Vec<TransportAddr>,
        deadline: tokio::time::Instant,
        admitted: Option<oneshot::Sender<()>>,
    ) -> Result<(), RuntimeError> {
        let result = self.send_replacement(snapshot, deadline, admitted).await;
        if matches!(
            result,
            Err(RuntimeError::Clock | RuntimeError::Publish(PublishError::ClockFault))
        ) {
            self.clock_fault.store(true, Ordering::Release);
        }
        result
    }

    async fn send_replacement(
        &self,
        snapshot: Vec<TransportAddr>,
        deadline: tokio::time::Instant,
        admitted: Option<oneshot::Sender<()>>,
    ) -> Result<(), RuntimeError> {
        if self.clock_fault.load(Ordering::Acquire) {
            return Err(RuntimeError::Publish(PublishError::ClockFault));
        }
        let (reply, response) = oneshot::channel();
        tokio::time::timeout_at(
            deadline,
            self.commands.send(Command::Replace(
                bounded_replace(snapshot),
                deadline,
                reply,
                admitted,
            )),
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
            self.clock_fault.store(true, Ordering::Release);
        }
        result
    }

    pub(crate) async fn query_publication_status(&self) -> Option<PublicationStatus> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::PublicationStatus(reply))
            .await
            .ok()?;
        response.await.ok()
    }
}

pub(crate) struct RuntimeOwner {
    commands: mpsc::Sender<Command>,
    stop: Option<oneshot::Sender<()>>,
    publisher: Option<JoinHandle<()>>,
    dht: Option<OwnedDht>,
    close_error: Option<RuntimeError>,
    clock: Clock,
    clock_fault: Arc<AtomicBool>,
    resolver: ResolverState,
    publication: watch::Receiver<PublicationStatus>,
}

impl RuntimeOwner {
    pub(crate) fn start(
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
        let owner_clock = clock.clone();
        let (publication_tx, publication) =
            watch::channel(PublicationStatus::Pending { generation: 0 });
        let publisher = tokio::spawn(loop_state::publisher_loop(
            identity,
            key,
            handle,
            receiver,
            stop_receiver,
            clock,
            publication_tx,
        ));
        Ok(Self {
            commands,
            stop: Some(stop),
            publisher: Some(publisher),
            dht: Some(dht),
            close_error: None,
            clock: owner_clock.clone(),
            clock_fault: Arc::new(AtomicBool::new(false)),
            resolver: ResolverState::new(owner_clock),
            publication,
        })
    }

    pub(crate) async fn replace_until(
        &self,
        snapshot: Vec<TransportAddr>,
        deadline: tokio::time::Instant,
    ) -> Result<(), RuntimeError> {
        if let Some(error) = self.clock_fault_error() {
            return Err(error);
        }
        let result = self.replace_inner(snapshot, deadline).await;
        self.note_clock_fault(&result);
        result
    }

    async fn replace_inner(
        &self,
        snapshot: Vec<TransportAddr>,
        deadline: tokio::time::Instant,
    ) -> Result<(), RuntimeError> {
        let result = self.send_replacement(snapshot, deadline, None).await;
        if matches!(
            result,
            Err(RuntimeError::Clock | RuntimeError::Publish(PublishError::ClockFault))
        ) {
            self.clock_fault.store(true, Ordering::Release);
        }
        result
    }

    async fn send_replacement(
        &self,
        snapshot: Vec<TransportAddr>,
        deadline: tokio::time::Instant,
        admitted: Option<oneshot::Sender<()>>,
    ) -> Result<(), RuntimeError> {
        if tokio::time::Instant::now() >= deadline {
            return Err(RuntimeError::DeadlineExceeded);
        }
        let (reply, response) = oneshot::channel();
        tokio::time::timeout_at(
            deadline,
            self.commands.send(Command::Replace(
                bounded_replace(snapshot),
                deadline,
                reply,
                admitted,
            )),
        )
        .await
        .map_err(|_| RuntimeError::DeadlineExceeded)?
        .map_err(|_| RuntimeError::Closed)?;
        tokio::time::timeout_at(deadline, response)
            .await
            .map_err(|_| RuntimeError::DeadlineExceeded)?
            .map_err(|_| RuntimeError::Closed)?
    }

    pub(crate) async fn replace(&self, snapshot: Vec<TransportAddr>) -> Result<(), RuntimeError> {
        self.replace_until(
            snapshot,
            tokio::time::Instant::now() + Duration::from_secs(10),
        )
        .await
    }

    pub(crate) async fn resolve_until(
        &mut self,
        key: EndpointId,
        deadline: tokio::time::Instant,
    ) -> Result<ResolvedAddresses, RuntimeError> {
        self.resolve_with_freshness(key, deadline, false).await
    }

    /// Bypasses address delivery from cache without discarding anti-replay state.
    /// cancel-safe: NO — a completion may be consumed; the retained owner still owns cleanup.
    pub(crate) async fn resolve_fresh_until(
        &mut self,
        key: EndpointId,
        deadline: tokio::time::Instant,
    ) -> Result<ResolvedAddresses, RuntimeError> {
        self.resolve_with_freshness(key, deadline, true).await
    }

    async fn resolve_with_freshness(
        &mut self,
        key: EndpointId,
        deadline: tokio::time::Instant,
        fresh: bool,
    ) -> Result<ResolvedAddresses, RuntimeError> {
        if let Some(error) = self.clock_fault_error() {
            return Err(error);
        }
        let deadline = deadline.min(tokio::time::Instant::now() + Duration::from_secs(10));
        let sample = self.sample_until(deadline).await?;
        let begun = if fresh {
            self.resolver.begin_fresh(key, sample)
        } else {
            self.resolver.begin(key, sample)
        };
        if let Some(cached) = begun.map_err(RuntimeError::Resolve)? {
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
        let sample = match self.clock.sample() {
            Ok(sample) => sample,
            Err(error) => {
                self.resolver.note_terminal_clock_fault();
                self.clock_fault.store(true, Ordering::Release);
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
            self.resolver.note_terminal_clock_fault();
            self.clock_fault.store(true, Ordering::Release);
            let _ = tokio::time::timeout_at(deadline, self.withdraw())
                .await
                .map_err(|_| RuntimeError::DeadlineExceeded)?;
        }
        result
    }

    fn clock_fault_error(&self) -> Option<RuntimeError> {
        self.clock_fault
            .load(Ordering::Acquire)
            .then_some(RuntimeError::Publish(PublishError::ClockFault))
    }

    fn note_clock_fault<T>(&self, result: &Result<T, RuntimeError>) {
        if matches!(
            result,
            Err(RuntimeError::Clock | RuntimeError::Publish(PublishError::ClockFault))
        ) {
            self.clock_fault.store(true, Ordering::Release);
        }
    }

    #[cfg(test)]
    pub(crate) fn dht_handle(&self) -> Option<OwnedDhtHandle> {
        self.dht.as_ref().map(OwnedDht::handle)
    }

    pub(crate) fn publication_handle(&self) -> PublicationHandle {
        PublicationHandle {
            commands: self.commands.clone(),
            clock_fault: Arc::clone(&self.clock_fault),
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.publisher.is_none() && self.dht.is_none()
    }
    pub(crate) fn has_pending_cleanup(&self) -> bool {
        !self.is_closed()
    }

    pub(crate) fn publication_status(&self) -> PublicationStatus {
        self.publication
            .borrow()
            .current(tokio::time::Instant::now())
    }

    #[cfg(test)]
    pub(crate) fn abort_publisher_for_tests(&mut self) {
        if let Some(publisher) = self.publisher.as_ref() {
            publisher.abort();
        }
    }

    #[cfg(test)]
    pub(crate) fn publication_watch(&self) -> watch::Receiver<PublicationStatus> {
        self.publication.clone()
    }

    pub(crate) async fn withdraw(&self) -> Result<(), RuntimeError> {
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

    pub(crate) async fn close(&mut self) -> Result<(), RuntimeError> {
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
        Ok(snapshot.into_boxed_slice().into_vec())
    }
}

#[cfg(test)]
#[path = "resolver_regressions.rs"]
mod resolver_regressions;
#[cfg(test)]
#[path = "seam_tests/mod.rs"]
mod seam_tests;
#[cfg(test)]
#[path = "../tests.rs"]
mod tests;
#[cfg(test)]
#[path = "wiring_tests/mod.rs"]
mod wiring_tests;
#[cfg(test)]
pub(crate) use tests::fixture::LoopbackPeer;

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
