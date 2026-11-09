//! Retained, identity-safe Yggdrasil start for composed startup.
//!
//! The operation dials out only: no listen URIs, no allowlist and no
//! group-password knob exist here, because service cores initiate peering.
//! The seed never leaves the identity publicly: it is staged through a
//! zeroizing buffer, and the temporary `YggConfig` copy is erased by its
//! own drop impl. Erasure is best-effort in-memory only: no OS/swap or
//! compiler-proof guarantee is claimed, and copies inside external
//! cryptographic dependencies (for example the ed25519-dalek signing key
//! internals) are out of scope.
//!
//! Ownership: the admitted transport never crosses a cancellable await. The
//! owner task keeps it in a shared slot; every terminal status is recorded
//! through a permanent receiver, so cancelled waiters and later subscribers
//! always observe the completed outcome. `wait` resolves a transport-free
//! status. The guard's `take_transport` is the synchronous explicit transfer
//! into the existing production path (for example `YggBridge::new`); after
//! the transfer the CALLER owns the close obligation through that consumer,
//! while `shutdown` remains the explicit caller-owned join route over the
//! owner task, cancel-safe, retryable, caching its terminal result. A
//! completed shutdown is terminal: every later `wait` reports Closed, even
//! when the start itself failed. Drops send a best-effort close signal and
//! never claim to join.

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use shaar_ygg::{YggConfig, YggError, YggTransport};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::identity::Identity;

use super::StartupError;

/// Lifecycle status. Carries NO transport: dropping a status value is
/// always safe.
#[derive(Clone, Debug)]
enum Status {
    Pending,
    Admitted,
    Failed(StartupError),
    Closed,
}

/// Shared between the owner task and the handles. The slot lock is held
/// only for synchronous take/peek; the async close runs after the transport
/// has been taken out, never while the lock is alive. The permanent
/// receiver keeps the sender alive, so terminal `send_replace` values are
/// recorded even when no waiter is subscribed.
struct StartupShared {
    slot: Mutex<Option<YggTransport>>,
    status_rx: watch::Receiver<Status>,
    status_tx: watch::Sender<Status>,
    /// Test-only fault flag read at the real close-result boundary.
    #[cfg(test)]
    close_fault_for_tests: std::sync::atomic::AtomicBool,
}

impl StartupShared {
    fn set_status(&self, status: Status) {
        self.status_tx.send_replace(status);
    }
}

fn slot_lock(
    slot: &Mutex<Option<YggTransport>>,
) -> std::sync::MutexGuard<'_, Option<YggTransport>> {
    slot.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Read/write guard over an admitted, owner-retained transport. It exposes
/// identity inspection and the synchronous explicit transfer into the
/// existing production consumer; cleanup obligations after a transfer stay
/// with the transferred consumer, while [`RetainedYggStart::shutdown`]
/// remains the joined owner-task cleanup.
pub(crate) struct SameIdentityYgg {
    shared: Arc<StartupShared>,
}

impl fmt::Debug for SameIdentityYgg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: no seed, no URIs, no peer state.
        f.write_str("SameIdentityYgg(..)")
    }
}

impl SameIdentityYgg {
    /// Public key of the admitted core, while it is still retained here.
    #[cfg(test)]
    pub(crate) fn public_key(&self) -> Option<[u8; 32]> {
        slot_lock(&self.shared.slot)
            .as_ref()
            .map(YggTransport::public_key)
    }

    /// Synchronous explicit transfer of the admitted transport to the
    /// caller (for example `YggBridge::new`). Because the transfer is
    /// synchronous there is no cancellation window; afterwards the CALLER
    /// owns the close obligation through the consumer (the bridge's close
    /// releases the key claim and sockets), and [`RetainedYggStart::shutdown`]
    /// still joins the owner task. `None` when already transferred or the
    /// start has since been closed.
    pub(crate) fn take_transport(self) -> Option<YggTransport> {
        slot_lock(&self.shared.slot).take()
    }
}

/// A retained start in progress. Owns the shutdown signal, the owner-task
/// join route and the cached terminal shutdown result; `Option` fields
/// because the type implements `Drop` and consumes them field-wise.
pub(crate) struct RetainedYggStart {
    shared: Arc<StartupShared>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<(), StartupError>>>,
    outcome: Option<Result<(), StartupError>>,
}

impl fmt::Debug for RetainedYggStart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: no seed, no URIs, no peer state.
        f.write_str("RetainedYggStart(..)")
    }
}

impl Drop for RetainedYggStart {
    fn drop(&mut self) {
        // Best-effort close signal only. The owner task closes the admitted
        // transport on its own; this drop never joins (use `shutdown`).
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
    }
}

impl RetainedYggStart {
    /// Resolves admission. Cancel-safe: YES — no transport crosses this
    /// await and terminal statuses are recorded even for later subscribers,
    /// so cancelling and retrying can neither strand a running core nor
    /// lose the completed outcome. A failed start keeps its original error
    /// observable until [`Self::shutdown`] completes; afterwards the
    /// lifecycle reports Closed. After `Ok`, closing is done via
    /// [`Self::shutdown`] or by synchronously transferring with
    /// [`SameIdentityYgg::take_transport`].
    pub(crate) async fn wait(&mut self) -> Result<SameIdentityYgg, StartupError> {
        let mut status_rx = self.shared.status_rx.clone();
        loop {
            match &*status_rx.borrow() {
                Status::Admitted => {
                    return Ok(SameIdentityYgg {
                        shared: Arc::clone(&self.shared),
                    });
                }
                Status::Failed(error) => return Err(error.clone()),
                Status::Closed => return Err(StartupError::Ygg(YggError::Closed)),
                Status::Pending => {}
            }
            status_rx
                .changed()
                .await
                .map_err(|_| StartupError::Ygg(YggError::Closed))?;
        }
    }

    /// Explicit owned cleanup and the caller-owned join route. Cancel-safe
    /// and retryable: the signal is sent once, awaiting the task borrows it
    /// mutably, and the completed result is consumed exactly once, then
    /// cached so repeated shutdowns return it without repolling a consumed
    /// handle; a cancelled poll retains the handle. The transport close
    /// result is propagated. The lifecycle is terminally Closed afterwards:
    /// every later `wait` reports Closed, even after a failed start, whose
    /// original error stays observable only before this completes.
    pub(crate) async fn shutdown(&mut self) -> Result<(), StartupError> {
        if let Some(cached) = &self.outcome {
            return cached.clone();
        }
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
        let Some(task) = self.task.as_mut() else {
            // The owner was already joined elsewhere (for example by the
            // test-only completion seam); the lifecycle is terminally closed.
            self.shared.set_status(Status::Closed);
            return Ok(());
        };
        let result = match task.await {
            Ok(result) => result,
            Err(_) => Err(StartupError::Ygg(YggError::Io(
                "startup task terminated unexpectedly".to_string(),
            ))),
        };
        // The output was consumed exactly once; drop the handle and cache
        // the result so a repeated shutdown cannot repoll it.
        self.task = None;
        self.outcome = Some(result.clone());
        // Terminal state: after a completed shutdown `wait` reports Closed,
        // even when the start itself failed earlier.
        self.shared.set_status(Status::Closed);
        result
    }

    /// Test-only deterministic barrier: awaits the real owner task to
    /// completion WITHOUT subscribing any watch waiter, consuming the join
    /// route exactly once. This observes the concrete "owner finished
    /// before any subscriber existed" interleaving that scheduling order
    /// cannot prove. Only meaningful while the owner completes on its own
    /// (a failed start); production callers use [`Self::shutdown`].
    #[cfg(test)]
    pub(crate) async fn await_owner_without_waiter_for_tests(
        &mut self,
    ) -> Result<(), StartupError> {
        let Some(task) = self.task.as_mut() else {
            return Ok(());
        };
        let result = match task.await {
            Ok(result) => result,
            Err(_) => Err(StartupError::Ygg(YggError::Io(
                "startup task terminated unexpectedly".to_string(),
            ))),
        };
        self.task = None;
        result
    }

    /// Test-only fault seam: wraps an already-spawned owner task so the
    /// cached-error and join-failure contracts of [`Self::shutdown`] can be
    /// forced deterministically. Production entry stays
    /// [`start_ygg_same_identity`]; this is not a production facade.
    #[cfg(test)]
    pub(crate) fn assemble_for_tests(task: JoinHandle<Result<(), StartupError>>) -> Self {
        let (status_tx, status_rx) = watch::channel(Status::Pending);
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        Self {
            shared: Arc::new(StartupShared {
                slot: Mutex::new(None),
                status_rx,
                status_tx,
                close_fault_for_tests: std::sync::atomic::AtomicBool::new(false),
            }),
            shutdown_tx: Some(shutdown_tx),
            task: Some(task),
            outcome: None,
        }
    }

    /// Test-only observation seam: splits the real owner task's join route
    /// off the retained handle, so a test can drop the handle (sending the
    /// production close signal) and then deterministically await THE OWNER
    /// ITSELF — proving its owned close ran before any later key observation
    /// even when cancellation precedes the owner's first poll. Production
    /// callers use [`Self::shutdown`].
    #[cfg(test)]
    pub(crate) fn detach_owner_join_for_tests(
        &mut self,
    ) -> Option<JoinHandle<Result<(), StartupError>>> {
        self.task.take()
    }

    /// Test-only fault arm for the real close-result boundary: the real
    /// `transport.close()` still runs and releases its resources; only the
    /// reported result is replaced once this flag is set.
    #[cfg(test)]
    pub(crate) fn arm_close_fault_for_tests(&mut self) {
        self.shared
            .close_fault_for_tests
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Test-only fault at the REAL close-result boundary: the real
/// `transport.close()` has already run when this is consulted, so its claim
/// and socket release are unaffected; only the result the owner maps and
/// propagates is replaced, deterministically, under test.
#[cfg(test)]
fn apply_close_fault_for_tests(
    shared: &StartupShared,
    result: Result<(), YggError>,
) -> Result<(), YggError> {
    if shared
        .close_fault_for_tests
        .load(std::sync::atomic::Ordering::SeqCst)
    {
        Err(YggError::Io("synthetic close failure".to_string()))
    } else {
        result
    }
}

/// Starts the pinned Yggdrasil backend with the SAME Ed25519 seed as
/// `identity`. `peer_uris` are the 1..=4 validated infrastructure peer
/// URIs from the shared network settings; the adapter re-validates them
/// before creating a core.
///
/// The owner task is spawned on the caller's runtime; the pinned core is
/// `Arc`-based and its futures are already spawned across tasks inside the
/// accepted adapter, but Send of the `start` future itself is verified by
/// CI compilation, not claimed here.
pub(crate) fn start_ygg_same_identity(
    identity: &Identity,
    peer_uris: &[String],
) -> RetainedYggStart {
    // The seed leaves the identity only through an iroh SecretKey clone
    // (zeroize-on-drop) into this staging buffer.
    let seed = Zeroizing::new(identity.transport_key().to_bytes());
    let peer_uris = peer_uris.to_vec();
    let (status_tx, status_rx) = watch::channel(Status::Pending);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let shared = Arc::new(StartupShared {
        slot: Mutex::new(None),
        status_rx,
        status_tx,
        #[cfg(test)]
        close_fault_for_tests: std::sync::atomic::AtomicBool::new(false),
    });
    let task_shared = Arc::clone(&shared);
    let task = tokio::spawn(async move {
        let config = YggConfig {
            seed: *seed,
            listen: Vec::new(),
            peers: peer_uris,
            allowed_public_keys: Vec::new(),
            group_password: None,
        };
        drop(seed);
        let transport = match YggTransport::start(config).await {
            Ok(transport) => transport,
            Err(error) => {
                // A failed start releases its key claim (adapter contract);
                // nothing is retained. The original error stays observable
                // via `wait` only until a joined shutdown records Closed.
                task_shared.set_status(Status::Failed(StartupError::Ygg(error)));
                return Ok(());
            }
        };
        *slot_lock(&task_shared.slot) = Some(transport);
        task_shared.set_status(Status::Admitted);
        // Retain until an explicit shutdown signal arrives; a dropped sender
        // (every handle dropped without shutdown) closes the transport too.
        let _ = shutdown_rx.await;
        // Take the transport out BEFORE the async close so the synchronous
        // lock is never held across an await, and record the closed status
        // so `wait` can no longer report a false admission.
        let admitted = slot_lock(&task_shared.slot).take();
        task_shared.set_status(Status::Closed);
        match admitted {
            Some(transport) => {
                // The REAL close always runs first: claim and sockets are
                // released even when the seam below replaces the reported
                // result under test.
                let result = transport.close().await;
                #[cfg(test)]
                let result = apply_close_fault_for_tests(&task_shared, result);
                result.map_err(StartupError::Ygg)
            }
            None => Ok(()),
        }
    });
    RetainedYggStart {
        shared,
        shutdown_tx: Some(shutdown_tx),
        task: Some(task),
        outcome: None,
    }
}
