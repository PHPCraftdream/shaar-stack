use std::{future::Future, io, sync::Arc};

use futures::future::try_join_all;
use tokio::sync::mpsc;

use crate::{CarrierHandle, Link, Received};

use super::{Inbound, state::Shared};

const WORKERS: usize = 8;

/// Caller-driven bridge pump; its fixed worker futures are not detached Tokio tasks.
/// Dropping the pump synchronously closes adapter admission, not the carrier's native I/O.
pub struct SignalingPump {
    pub(super) shared: Arc<Shared>,
    pub(super) handle: CarrierHandle,
    pub(super) incoming: mpsc::Receiver<Received>,
    pub(super) deliver: mpsc::Sender<Inbound>,
}

impl Drop for SignalingPump {
    fn drop(&mut self) {
        self.shared.close();
    }
}

impl SignalingPump {
    /// Drive alongside the carrier, and stop both before awaiting the carrier's joined shutdown.
    /// cancel-safe: NO — admitted RPCs may finish after pump cancellation; nothing is replayed.
    pub async fn run(mut self, stop: impl Future<Output = ()>) -> io::Result<()> {
        let shared = self.shared.clone();
        let mut closed = shared.closed.subscribe();
        if *closed.borrow() {
            return Ok(());
        }
        let workers =
            try_join_all((0..WORKERS).map(|_| send_worker(shared.clone(), self.handle.clone())));
        let receive = receive_loop(
            shared.clone(),
            self.handle.clone(),
            &mut self.incoming,
            &self.deliver,
        );
        tokio::pin!(workers, receive, stop);
        let result = tokio::select! {
            _ = &mut stop => Ok(()),
            _ = closed.changed() => Ok(()),
            result = &mut workers => result.map(|_| ()),
            result = &mut receive => result,
        };
        shared.close();
        result
    }
}

/// cancel-safe: NO — dropping an admitted RPC waiter cannot undo remote admission.
async fn send_worker(shared: Arc<Shared>, handle: CarrierHandle) -> io::Result<()> {
    while let Some(frame) = shared.next().await? {
        // Queue admission is UDP-like, not remote delivery. QUIC owns control retransmission.
        // A stale/error result never replays this packet against a successor connection.
        let _ = handle.send_on(frame.link, frame.packet).await;
    }
    Ok(())
}

/// cancel-safe: yes — capacity precedes input; no await follows consuming a record.
async fn receive<'a>(
    incoming: &mut mpsc::Receiver<Received>,
    deliver: &'a mpsc::Sender<Inbound>,
) -> Option<(Received, mpsc::Permit<'a, Inbound>)> {
    let permit = deliver.reserve().await.ok()?;
    let received = incoming.recv().await?;
    Some((received, permit))
}

/// cancel-safe: NO — already queued packets are not replayed after pump shutdown.
async fn receive_loop(
    shared: Arc<Shared>,
    handle: CarrierHandle,
    incoming: &mut mpsc::Receiver<Received>,
    deliver: &mpsc::Sender<Inbound>,
) -> io::Result<()> {
    let mut links = handle.links();
    {
        let current = links.borrow_and_update();
        shared.refresh(&current)?;
    }
    loop {
        tokio::select! {
            changed = links.changed() => {
                if changed.is_err() { return Ok(()); }
                let current = links.borrow_and_update();
                shared.refresh(&current)?;
            }
            received = receive(incoming, deliver) => {
                let Some((received, permit)) = received else { return Ok(()); };
                if !handle.is_current(&received) { continue; }
                let link = Link { peer: received.peer, connection: received.connection, route: received.route };
                let mut source = shared.peer_address(received.peer);
                if !source.as_ref().is_ok_and(|source| shared.matches(source, link)) {
                    let current = links.borrow_and_update();
                    shared.refresh(&current)?;
                    source = shared.peer_address(received.peer);
                }
                let Ok(source) = source else { continue; };
                if !shared.matches(&source, link) { continue; }
                permit.send(Inbound { received, source });
            }
        }
    }
}
