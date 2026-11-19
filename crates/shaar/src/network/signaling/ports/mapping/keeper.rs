//! Keeping one mapping alive for the life of a socket (leaf PORT-1, step 3): the keeper asks the
//! gateway for the mapping, renews it at half its granted lifetime with the same nonce, tries
//! again when the gateway failed or was silent, and deletes the mapping when it is stopped.

use std::time::Duration;

use tokio::{
    sync::{oneshot, watch},
    task::JoinHandle,
    time::sleep,
};

use super::{Gateway, MapError, Mapping, map_udp, release, renew};

/// How the keeper paces itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    /// The lifetime asked for at every request.
    pub lifetime: Duration,
    /// The bound of one request.
    pub request_budget: Duration,
    /// The shortest wait before a renewal, however short the granted lifetime.
    pub min_renew: Duration,
    /// The wait before trying again after a refusal or a socket error.
    pub retry: Duration,
    /// The wait before trying again when the gateway did not answer at all.
    pub silent_retry: Duration,
}

/// The pace of the products: two hours asked and renewed at their half, three seconds per
/// request, and a new try after half a minute, or after ten minutes from a gateway that is silent.
pub const DEFAULT_TIMING: Timing = Timing {
    lifetime: Duration::from_secs(7200),
    request_budget: Duration::from_secs(3),
    min_renew: Duration::from_secs(30),
    retry: Duration::from_secs(30),
    silent_retry: Duration::from_secs(600),
};

/// What the keeper holds now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// The first request is not answered yet.
    Pending,
    /// The gateway granted this mapping (its external port may differ from the one asked for).
    Mapped(Mapping),
    /// The last request failed; the keeper tries again.
    Unavailable(MapError),
}

/// The task that keeps the mapping of one UDP port.
pub struct Keeper {
    state: watch::Receiver<State>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl Keeper {
    /// Starts keeping a mapping of `port` to the same external port at `gateway`.
    #[must_use]
    pub fn start(gateway: Gateway, port: u16, timing: Timing) -> Self {
        let (sender, state) = watch::channel(State::Pending);
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(keep(gateway, port, timing, sender, stopped));
        Self {
            state,
            stop: Some(stop),
            task: Some(task),
        }
    }

    /// What the keeper holds now.
    #[must_use]
    pub fn state(&self) -> State {
        *self.state.borrow()
    }

    /// A receiver that wakes at every change of the state.
    #[must_use]
    pub fn watch(&self) -> watch::Receiver<State> {
        self.state.clone()
    }

    /// Stops the task and deletes the mapping at the gateway, within a short bound.
    /// cancel-safe: yes — a cancelled stop leaves the task stopped and the mapping to expire.
    pub async fn stop(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for Keeper {
    /// A keeper that is dropped without `stop` ends its task; the gateway expires the mapping.
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn keep(
    gateway: Gateway,
    port: u16,
    timing: Timing,
    state: watch::Sender<State>,
    mut stopped: oneshot::Receiver<()>,
) {
    let mut held: Option<Mapping> = None;
    loop {
        let attempt = async {
            match &held {
                None => {
                    map_udp(
                        gateway.address,
                        gateway.local,
                        port,
                        port,
                        timing.lifetime,
                        timing.request_budget,
                    )
                    .await
                }
                Some(mapping) => {
                    renew(
                        gateway.address,
                        gateway.local,
                        mapping,
                        timing.lifetime,
                        timing.request_budget,
                    )
                    .await
                }
            }
        };
        let result = tokio::select! {
            biased;
            _ = &mut stopped => break,
            result = attempt => result,
        };
        let wait = match result {
            Ok(mapping) => {
                held = Some(mapping);
                state.send_replace(State::Mapped(mapping));
                (mapping.lifetime / 2).max(timing.min_renew)
            }
            Err(error) => {
                held = None;
                state.send_replace(State::Unavailable(error));
                if error == MapError::Silent {
                    timing.silent_retry
                } else {
                    timing.retry
                }
            }
        };
        tokio::select! {
            biased;
            _ = &mut stopped => break,
            () = sleep(wait) => {}
        }
    }
    if let Some(mapping) = held {
        let _ = release(gateway.address, gateway.local, &mapping).await;
    }
}
