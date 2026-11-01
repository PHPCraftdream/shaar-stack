// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Retained ownership for a numeric-address Mainline DHT actor.
//!
//! The owner keeps the spawned task join handle so shutdown is observable.
#![forbid(unsafe_code)]

use std::io;
use std::net::SocketAddrV4;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::actor;
use crate::dht::{ACTOR_INBOX_CAPACITY, Dht};

/// A DHT handle paired with ownership of its actor task and shutdown signal.
pub struct OwnedDht {
    dht: Dht,
    stop: Option<oneshot::Sender<()>>,
    join: Option<JoinHandle<()>>,
    terminal: Option<(io::ErrorKind, String)>,
}

impl OwnedDht {
    /// Bind a numeric IPv4 address and start an actor using numeric bootstrap addresses.
    ///
    /// All bootstrap addresses are validated before the actor is constructed. Must be
    /// called inside a Tokio runtime because the UDP socket is registered with it.
    pub fn new(bind: SocketAddrV4, bootstrap: &[SocketAddrV4]) -> io::Result<Self> {
        if bootstrap.is_empty()
            || bootstrap.len() > 4
            || bootstrap.iter().any(|addr| addr.port() == 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid numeric bootstrap",
            ));
        }
        let bootstrap = bootstrap.to_vec().into_boxed_slice();
        let actor = actor::Actor::new_numeric(bind, bootstrap)?;
        Ok(Self::from_actor(actor))
    }

    pub(crate) fn from_actor(actor: actor::Actor) -> Self {
        let (sender, receiver) = mpsc::channel(ACTOR_INBOX_CAPACITY);
        let (stop, stop_receiver) = oneshot::channel();
        let join = tokio::spawn(actor::run_owned(actor, receiver, stop_receiver));
        Self {
            dht: Dht(sender),
            stop: Some(stop),
            join: Some(join),
            terminal: None,
        }
    }

    /// Borrow the ordinary DHT handle for requests and queries.
    pub fn dht(&self) -> &Dht {
        &self.dht
    }

    /// Request actor shutdown without waiting. Repeated calls are harmless.
    pub fn request_stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }

    /// Request shutdown and wait up to five seconds for the retained actor task.
    ///
    /// This method is cancellation-safe: if its future is cancelled, the join handle
    /// remains stored in this owner and a later call can continue waiting. A timeout
    /// also retains the handle, allowing another call to observe eventual completion.
    pub async fn close(&mut self) -> io::Result<()> {
        self.request_stop();
        if let Some((kind, message)) = &self.terminal {
            return Err(io::Error::new(*kind, message.clone()));
        }
        let Some(join) = self.join.as_mut() else {
            return Ok(());
        };
        match tokio::time::timeout(Duration::from_secs(5), join).await {
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "DHT actor shutdown timed out",
            )),
            Ok(result) => {
                self.join.take();
                match result {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        let message = error.to_string();
                        let kind = if error.is_cancelled() {
                            io::ErrorKind::Interrupted
                        } else {
                            io::ErrorKind::Other
                        };
                        self.terminal = Some((kind, message.clone()));
                        Err(io::Error::new(kind, message))
                    }
                }
            }
        }
    }
}

impl Drop for OwnedDht {
    fn drop(&mut self) {
        self.request_stop();
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}
