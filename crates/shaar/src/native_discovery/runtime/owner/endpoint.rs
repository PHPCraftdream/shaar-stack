// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

//! Opt-in composition of one SDK endpoint and one native discovery owner.
//! D1 `Endpoint::bind` stays lookup-free; discovery exists only through this explicit
//! constructor, and only the caller's snapshot is ever published.

use std::net::SocketAddr;
use std::time::Duration;

use iroh_base::{PublicKey, TransportAddr};
use tokio::task::JoinHandle;

use super::options::NativeDiscoveryOptions;
use super::{RuntimeError, RuntimeOwner, endpoint_key};
use crate::network::{Allowlist, Endpoint, Limits, NetworkError, Session};

const ENDPOINT_CLOSE_BOUND: Duration = Duration::from_secs(5);
const ATTEMPT_BOUND: Duration = Duration::from_secs(10);
// Matches the four-address cap of a native record.
const MAX_ATTEMPTS: usize = 4;

#[derive(Debug)]
pub(in crate::native_discovery) enum NativeEndpointError {
    Network(NetworkError),
    Runtime(RuntimeError),
    Start(std::io::Error),
    Closed,
    Deadline,
    NoAddress,
    CloseTimeout,
    CloseJoin,
}

pub(in crate::native_discovery) struct NativeDiscoveredEndpoint {
    id: PublicKey,
    address: SocketAddr,
    endpoint: Option<Endpoint>,
    // The SDK endpoint closes by value; its close task stays owned here so a
    // cancelled or timed-out close can be retried and Drop aborts rather than detaches.
    endpoint_close: Option<JoinHandle<()>>,
    runtime: RuntimeOwner,
    closing: bool,
}

impl NativeDiscoveredEndpoint {
    /// Validates the identity conversion, binds the native endpoint, then the DHT owner; a
    /// failed second bind closes the first. Nothing is published at construction.
    /// cancel-safe: NO — cancelled startup aborts owners but cannot join their destruction.
    pub(in crate::native_discovery) async fn bind_with_discovery(
        native: SocketAddr,
        allowlist: Allowlist,
        limits: Limits,
        options: NativeDiscoveryOptions,
    ) -> Result<Self, NativeEndpointError> {
        endpoint_key(options.identity()).map_err(NativeEndpointError::Start)?;
        let endpoint = Endpoint::bind(options.identity(), native, allowlist, limits)
            .await
            .map_err(NativeEndpointError::Network)?;
        let runtime = match RuntimeOwner::start(
            options.identity().clone(),
            options.bind(),
            options.bootstrap(),
        ) {
            Ok(runtime) => runtime,
            Err(error) => {
                endpoint.close().await;
                return Err(NativeEndpointError::Start(error));
            }
        };
        Ok(Self {
            id: endpoint.id(),
            address: endpoint.local_addr(),
            endpoint: Some(endpoint),
            endpoint_close: None,
            runtime,
            closing: false,
        })
    }

    #[cfg(test)]
    pub(super) async fn bind_with_discovery_controlled(
        native: SocketAddr,
        allowlist: Allowlist,
        limits: Limits,
        options: NativeDiscoveryOptions,
        clock: super::super::clock::TestClock,
    ) -> Result<Self, NativeEndpointError> {
        endpoint_key(options.identity()).map_err(NativeEndpointError::Start)?;
        let endpoint = Endpoint::bind(options.identity(), native, allowlist, limits)
            .await
            .map_err(NativeEndpointError::Network)?;
        let runtime = match RuntimeOwner::start_controlled(
            options.identity().clone(),
            options.bind(),
            options.bootstrap(),
            clock,
        ) {
            Ok(runtime) => runtime,
            Err(error) => {
                endpoint.close().await;
                return Err(NativeEndpointError::Start(error));
            }
        };
        Ok(Self {
            id: endpoint.id(),
            address: endpoint.local_addr(),
            endpoint: Some(endpoint),
            endpoint_close: None,
            runtime,
            closing: false,
        })
    }

    pub(in crate::native_discovery) fn id(&self) -> PublicKey {
        self.id
    }

    pub(in crate::native_discovery) fn local_addr(&self) -> SocketAddr {
        self.address
    }

    /// cancel-safe: NO — revocation is not rolled back; pre-ack cancellation cleans work.
    pub(in crate::native_discovery) async fn replace_until(
        &self,
        snapshot: Vec<TransportAddr>,
        deadline: tokio::time::Instant,
    ) -> Result<(), NativeEndpointError> {
        if self.closing {
            return Err(NativeEndpointError::Closed);
        }
        self.runtime
            .replace_until(snapshot, deadline)
            .await
            .map_err(NativeEndpointError::Runtime)
    }

    /// cancel-safe: NO — an admitted withdrawal remains effective.
    pub(in crate::native_discovery) async fn withdraw(&self) -> Result<(), NativeEndpointError> {
        if self.closing {
            return Err(NativeEndpointError::Closed);
        }
        self.runtime
            .withdraw()
            .await
            .map_err(NativeEndpointError::Runtime)
    }

    /// Resolves `expected` once, then dials its addresses one at a time through the existing
    /// exact-key `Endpoint::connect`, all under one caller deadline. The result lease is held
    /// until the attempts finish; a session completed after the deadline is closed, not returned.
    /// cancel-safe: NO — a cancelled handshake is abandoned, not replayed.
    pub(in crate::native_discovery) async fn connect_until(
        &mut self,
        expected: PublicKey,
        deadline: tokio::time::Instant,
    ) -> Result<Session, NativeEndpointError> {
        if self.closing {
            return Err(NativeEndpointError::Closed);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(NativeEndpointError::Deadline);
        }
        let endpoint = self.endpoint.as_ref().ok_or(NativeEndpointError::Closed)?;
        let resolved = self
            .runtime
            .resolve_until(expected, deadline)
            .await
            .map_err(NativeEndpointError::Runtime)?;
        if resolved.addresses().is_empty() {
            return Err(NativeEndpointError::NoAddress);
        }
        let mut last = NetworkError::Deadline;
        for address in resolved.addresses().iter().take(MAX_ATTEMPTS) {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(NativeEndpointError::Deadline);
            }
            let attempt = deadline.min(now + ATTEMPT_BOUND);
            match tokio::time::timeout_at(attempt, endpoint.connect(expected, *address)).await {
                Ok(Ok(session)) => {
                    if tokio::time::Instant::now() >= deadline {
                        session.close();
                        return Err(NativeEndpointError::Deadline);
                    }
                    return Ok(session);
                }
                Ok(Err(error @ (NetworkError::Closed | NetworkError::Capacity))) => {
                    return Err(NativeEndpointError::Network(error));
                }
                Ok(Err(error)) => last = error,
                Err(_) => last = NetworkError::Deadline,
            }
        }
        Err(NativeEndpointError::Network(last))
    }

    /// Both backends are driven to completion without one failure hiding the other;
    /// unfinished joins stay owned, so a failed or timed-out close can be retried.
    /// cancel-safe: yes — the endpoint close task and the owner join handles remain retained.
    pub(in crate::native_discovery) async fn close(&mut self) -> Result<(), NativeEndpointError> {
        self.closing = true;
        if let Some(endpoint) = self.endpoint.take() {
            self.endpoint_close = Some(tokio::spawn(endpoint.close()));
        }
        let task = &mut self.endpoint_close;
        let runtime = &mut self.runtime;
        let (endpoint_result, runtime_result) = tokio::join!(
            async {
                let Some(handle) = task.as_mut() else {
                    return Ok(());
                };
                match tokio::time::timeout(ENDPOINT_CLOSE_BOUND, handle).await {
                    Ok(Ok(())) => {
                        *task = None;
                        Ok(())
                    }
                    Ok(Err(_)) => {
                        *task = None;
                        Err(NativeEndpointError::CloseJoin)
                    }
                    Err(_) => Err(NativeEndpointError::CloseTimeout),
                }
            },
            async { runtime.close().await.map_err(NativeEndpointError::Runtime) },
        );
        endpoint_result.and(runtime_result)
    }
}

impl Drop for NativeDiscoveredEndpoint {
    fn drop(&mut self) {
        if let Some(task) = self.endpoint_close.take() {
            task.abort();
        }
    }
}
