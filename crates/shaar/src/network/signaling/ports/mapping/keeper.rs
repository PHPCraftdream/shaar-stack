//! Keeping one mapping alive for the life of a socket (leaf PORT-1, step 3): the keeper asks the
//! gateway for the mapping, renews it at half its granted lifetime with the same nonce, tries
//! again when the gateway failed or was silent, and deletes the mapping when it is stopped. A
//! change of the outcome class is reported on stderr in one line without any address or port.

use std::{net::SocketAddr, time::Duration};

use tokio::{
    sync::{oneshot, watch},
    task::JoinHandle,
    time::sleep,
};

use super::{Gateway, MapError, Mapping, Protocol, home_gateway, map_any, release, renew};

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// The first request is not answered yet.
    Pending,
    /// The gateway granted this mapping (its external port may differ from the one asked for).
    Mapped(Mapping),
    /// The last request failed; the keeper tries again.
    Unavailable(MapError),
}

/// The class of a request result: a line is printed only when it changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Granted(Protocol),
    Failed(MapError),
}

impl Outcome {
    pub(super) fn of(result: &Result<Mapping, MapError>) -> Self {
        match result {
            Ok(mapping) => Self::Granted(mapping.protocol),
            Err(error) => Self::Failed(*error),
        }
    }
}

/// The line for `result` when its class differs from `previous`, else nothing. A grant names the
/// protocol and the granted lifetime, a failure its reason; never an address or a port.
pub(super) fn outcome_line(
    previous: Option<Outcome>,
    result: &Result<Mapping, MapError>,
) -> Option<String> {
    if previous == Some(Outcome::of(result)) {
        return None;
    }
    Some(match result {
        Ok(mapping) => format!(
            "shaar: router mapping outcome=granted protocol={} lifetime_s={}",
            mapping.protocol.token(),
            mapping.lifetime.as_secs()
        ),
        Err(error) => format!("shaar: router mapping outcome=unavailable reason={error}"),
    })
}

fn announce(reported: &mut Option<Outcome>, result: &Result<Mapping, MapError>) {
    if let Some(line) = outcome_line(*reported, result) {
        eprintln!("{line}");
    }
    *reported = Some(Outcome::of(result));
}

/// Which gateway the keeper asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    /// This one.
    Fixed(Gateway),
    /// The home router the system names, looked up by the task and again after a failure.
    Home,
}

/// Whether a role asks its router for a mapping of the port its endpoint is bound to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RouterMapping {
    /// No mapping is asked for.
    #[default]
    Off,
    /// The home router the system names is asked; the products use this.
    HomeRouter,
    /// This gateway is asked, at this pace: for tests and measurements.
    Gateway(Gateway, Timing),
}

impl RouterMapping {
    /// Starts keeping a mapping of the port of `bound` when this setting asks for one. An
    /// endpoint bound to loopback or to port zero has nothing to map. The gateway is looked up
    /// by the keeper's task, so this does not wait.
    #[must_use]
    pub fn start(self, bound: SocketAddr) -> Option<Keeper> {
        if bound.port() == 0 {
            return None;
        }
        match self {
            Self::Off => None,
            Self::HomeRouter if bound.ip().is_loopback() => None,
            Self::HomeRouter => Some(Keeper::spawn(Source::Home, bound.port(), DEFAULT_TIMING)),
            Self::Gateway(gateway, timing) => {
                Some(Keeper::spawn(Source::Fixed(gateway), bound.port(), timing))
            }
        }
    }
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
        Self::spawn(Source::Fixed(gateway), port, timing)
    }

    fn spawn(source: Source, port: u16, timing: Timing) -> Self {
        let (sender, state) = watch::channel(State::Pending);
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(keep(source, port, timing, sender, stopped));
        Self {
            state,
            stop: Some(stop),
            task: Some(task),
        }
    }

    /// What the keeper holds now.
    #[must_use]
    pub fn state(&self) -> State {
        self.state.borrow().clone()
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
    source: Source,
    port: u16,
    timing: Timing,
    state: watch::Sender<State>,
    mut stopped: oneshot::Receiver<()>,
) {
    let mut held: Option<Mapping> = None;
    let mut known: Option<Gateway> = None;
    let mut reported: Option<Outcome> = None;
    loop {
        // A home router is looked up until one is named; the mapping starts after that.
        let gateway = if let Some(found) = known {
            found
        } else {
            let found = match source {
                Source::Fixed(fixed) => Some(fixed),
                Source::Home => tokio::select! {
                    biased;
                    _ = &mut stopped => break,
                    found = home_gateway() => found,
                },
            };
            let Some(found) = found else {
                announce(&mut reported, &Err(MapError::NoGateway));
                state.send_replace(State::Unavailable(MapError::NoGateway));
                tokio::select! {
                    biased;
                    _ = &mut stopped => break,
                    () = sleep(timing.silent_retry) => {}
                }
                continue;
            };
            known = Some(found);
            found
        };
        let attempt = async {
            match &held {
                None => map_any(gateway, port, timing.lifetime, timing.request_budget).await,
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
        announce(&mut reported, &result);
        let wait = match result {
            Ok(mapping) => {
                let wait = (mapping.lifetime / 2).max(timing.min_renew);
                state.send_replace(State::Mapped(mapping.clone()));
                held = Some(mapping);
                wait
            }
            Err(error) => {
                held = None;
                state.send_replace(State::Unavailable(error));
                if matches!(
                    error,
                    MapError::Silent | MapError::Unsupported | MapError::NoGateway
                ) {
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
    if let (Some(mapping), Some(gateway)) = (held, known) {
        let _ = release(gateway.address, gateway.local, &mapping).await;
    }
}
