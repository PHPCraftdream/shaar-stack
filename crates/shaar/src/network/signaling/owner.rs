use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use iroh_base::PublicKey;
use shaar_p2p::{Carrier, CarrierHandle, SignalingPump, SignalingTransport};
use tokio::{sync::oneshot, task::JoinHandle};

use super::bind_signaling;
use crate::{identity::Identity, network::NetworkError};

pub(super) struct Owned {
    pub(super) handle: CarrierHandle,
    pub(super) factory: Arc<SignalingTransport>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl Owned {
    pub(super) fn start(
        identity: &Identity,
        address: SocketAddr,
        peers: &[PublicKey],
    ) -> Result<Self, NetworkError> {
        let (carrier, handle, incoming) = bind_signaling(identity, address, peers)?;
        let (factory, pump) = SignalingTransport::attach(handle.clone(), incoming)
            .map_err(NetworkError::Signaling)?;
        let (stop, stopped) = oneshot::channel();
        // One retained coordinator owns both child futures and observes both results.
        let task = tokio::spawn(run(carrier, pump, stopped));
        Ok(Self {
            handle,
            factory,
            stop: Some(stop),
            task: Some(task),
        })
    }

    /// cancel-safe: NO — the owning startup operation must close or drop this owner.
    pub(super) async fn ready(&self) -> Result<SocketAddr, NetworkError> {
        tokio::time::timeout(Duration::from_secs(10), self.handle.local_addr())
            .await
            .map_err(|_| {
                NetworkError::Signaling(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "signaling startup deadline",
                ))
            })?
            .map_err(NetworkError::Signaling)
    }

    /// cancel-safe: NO — only successful completion proves joined destruction.
    pub(super) async fn close(mut self) -> Result<(), NetworkError> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let result = self
            .task
            .as_mut()
            .expect("sole signaling owner retains its task")
            .await
            .map_err(|error| NetworkError::SignalingOperation(io::Error::other(error)));
        drop(self.task.take());
        result?.map_err(NetworkError::SignalingOperation)
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            // Abort-only cancellation fallback, not joined completion; async close retains the result.
            task.abort();
        }
    }
}

/// cancel-safe: NO — aborting the coordinator aborts child futures, not async joins.
async fn run(carrier: Carrier, pump: SignalingPump, stop: oneshot::Receiver<()>) -> io::Result<()> {
    let (carrier_stop, carrier_stopped) = oneshot::channel();
    let (pump_stop, pump_stopped) = oneshot::channel();
    let carrier = carrier.run(async {
        let _ = carrier_stopped.await;
    });
    let pump = pump.run(async {
        let _ = pump_stopped.await;
    });
    coordinate(carrier, pump, stop, carrier_stop, pump_stop).await
}

/// cancel-safe: NO — only completion proves both child futures reached their join boundaries.
async fn coordinate(
    carrier: impl std::future::Future<Output = io::Result<()>>,
    pump: impl std::future::Future<Output = io::Result<()>>,
    mut stop: oneshot::Receiver<()>,
    carrier_stop: oneshot::Sender<()>,
    pump_stop: oneshot::Sender<()>,
) -> io::Result<()> {
    tokio::pin!(carrier, pump);
    let (mut carrier_result, mut pump_result) = (None, None);
    tokio::select! {
        _ = &mut stop => {},
        result = &mut carrier => carrier_result = Some(result),
        result = &mut pump => pump_result = Some(result),
    }
    let _ = pump_stop.send(());
    let _ = carrier_stop.send(());
    let carrier_result = match carrier_result {
        Some(result) => result,
        None => carrier.await,
    };
    let pump_result = match pump_result {
        Some(result) => result,
        None => pump.await,
    };
    carrier_result.and(pump_result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test(flavor = "current_thread")]
    async fn either_child_completion_stops_and_observes_the_other_result() {
        tokio::time::timeout(Duration::from_secs(5), async {
            for carrier_first in [false, true] {
                for first_fails in [false, true] {
                    let count = Arc::new(AtomicUsize::new(0));
                    let first_count = count.clone();
                    let second_count = count.clone();
                    let (_stop, stopped) = oneshot::channel();
                    let (carrier_stop, carrier_stopped) = oneshot::channel();
                    let (pump_stop, pump_stopped) = oneshot::channel();
                    let first = async move {
                        first_count.fetch_add(1, Ordering::SeqCst);
                        if first_fails {
                            Err(io::ErrorKind::PermissionDenied.into())
                        } else {
                            Ok(())
                        }
                    };
                    let second = async move {
                        if carrier_first {
                            pump_stopped.await.unwrap();
                        } else {
                            carrier_stopped.await.unwrap();
                        }
                        second_count.fetch_add(1, Ordering::SeqCst);
                        if first_fails {
                            Ok(())
                        } else {
                            Err(io::ErrorKind::NotConnected.into())
                        }
                    };
                    let result = if carrier_first {
                        coordinate(first, second, stopped, carrier_stop, pump_stop).await
                    } else {
                        coordinate(second, first, stopped, carrier_stop, pump_stop).await
                    };
                    assert_eq!(count.load(Ordering::SeqCst), 2);
                    assert_eq!(
                        result.unwrap_err().kind(),
                        if first_fails {
                            io::ErrorKind::PermissionDenied
                        } else {
                            io::ErrorKind::NotConnected
                        }
                    );
                }
            }
        })
        .await
        .expect("coordinator child result ordering deadline");
    }

    struct Destroyed(Option<oneshot::Sender<()>>);
    impl Drop for Destroyed {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelling_close_keeps_the_pending_join_handle_owned_until_abort() {
        tokio::time::timeout(Duration::from_secs(5), async {
        let identity = Identity::generate();
        let (carrier, handle, incoming) = bind_signaling(&identity, "127.0.0.1:0".parse().unwrap(), &[]).unwrap();
        let (factory, pump) = SignalingTransport::attach(handle.clone(), incoming).unwrap();
        let (stop, stopped) = oneshot::channel();
        let (seen, observed) = oneshot::channel();
        let (destroyed, mut destruction) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _destroyed = Destroyed(Some(destroyed));
            stopped.await.unwrap();
            seen.send(()).unwrap();
            std::future::pending::<io::Result<()>>().await
        });
        let cleanup = task.abort_handle();
        let owned = Owned { handle, factory, stop: Some(stop), task: Some(task) };
        {
            let closing = owned.close();
            tokio::pin!(closing);
            tokio::select! {
                seen = observed => seen.unwrap(),
                _ = &mut closing => panic!("close finished before the held coordinator was released"),
            }
        }
        let result = tokio::time::timeout(Duration::from_secs(2), &mut destruction).await;
        if result.is_err() { cleanup.abort(); let _ = destruction.await; }
        drop(pump);
        carrier.run(async {}).await.unwrap();
        assert!(matches!(result, Ok(Ok(()))), "cancelled close detached the retained pending coordinator");
        }).await.expect("cancelled close coordinator ownership deadline");
    }
}
