//! Dedicated runtime thread for the retained roles.
//!
//! The roles are intentionally not `Send`, so they cannot be spawned onto the
//! caller's executor. `spawn` runs one role future on its own thread with a
//! small multi-thread runtime (the role future is driven by `block_on` on that
//! thread, the `Send` workers it spawns run on the runtime's workers) and gives
//! back a `Send` handle.

use std::future::Future;
use std::pin::Pin;
use std::thread::JoinHandle;

use tokio::sync::oneshot;

use super::SdkError;

/// Worker threads of the role runtime: the role future is driven on its own
/// thread; these run the spawned stream workers and timers.
const WORKER_THREADS: usize = 2;

/// Handle to a role running on its own thread.
pub(super) struct Running<R> {
    stop: Option<oneshot::Sender<()>>,
    done: Option<oneshot::Receiver<Result<(), SdkError>>>,
    thread: Option<JoinHandle<()>>,
    pub(super) ready: R,
}

impl<R> Running<R> {
    /// Signals the role to stop and waits for its joined shutdown.
    /// cancel-safe: YES — the signal is sent once; a later call only waits.
    pub(super) async fn shutdown(&mut self) -> Result<(), SdkError> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.wait().await
    }

    /// Resolves when the role has ended, with its outcome.
    /// cancel-safe: YES — the outcome is kept until it is received.
    pub(super) async fn wait(&mut self) -> Result<(), SdkError> {
        let Some(done) = self.done.as_mut() else {
            return Err(SdkError::Closed);
        };
        let outcome = done.await.unwrap_or(Err(SdkError::Closed));
        self.done = None;
        if let Some(thread) = self.thread.take() {
            // The role has already reported; joining is a formality that
            // must not block an executor thread for long.
            let _ = tokio::task::spawn_blocking(move || thread.join()).await;
        }
        outcome
    }
}

impl<R> std::fmt::Debug for Running<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Running").finish_non_exhaustive()
    }
}

impl<R> Drop for Running<R> {
    fn drop(&mut self) {
        // Best effort: ask the role to stop; the thread ends on its own.
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

/// What a role announces once it has started.
type Boot<R> = Result<R, SdkError>;

/// Runs `build` on a new thread. `build` receives the stop signal and a
/// `ready` callback and returns the role future, which must call `ready` once
/// the role is up; it ends when the role is shut down.
/// cancel-safe: YES — until the role has announced itself nothing outlives the future.
pub(super) async fn spawn<R, B, F>(name: &str, build: B) -> Result<Running<R>, SdkError>
where
    R: Send + 'static,
    B: FnOnce(Stop, Ready<R>) -> F + Send + 'static,
    F: Future<Output = Result<(), SdkError>>,
{
    let (stop_tx, stop_rx) = oneshot::channel();
    let (boot_tx, boot_rx) = oneshot::channel::<Boot<R>>();
    let (done_tx, done_rx) = oneshot::channel();
    let thread = std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(WORKER_THREADS)
                .enable_all()
                .build();
            let outcome = match runtime {
                Ok(runtime) => {
                    let ready = Ready {
                        boot: Some(boot_tx),
                    };
                    runtime.block_on(build(Stop(stop_rx), ready))
                }
                Err(_) => {
                    let _ = boot_tx.send(Err(SdkError::Setup("could not start the runtime")));
                    Err(SdkError::Setup("could not start the runtime"))
                }
            };
            let _ = done_tx.send(outcome);
        })
        .map_err(|_| SdkError::Setup("could not start the role thread"))?;
    match boot_rx.await {
        Ok(Ok(ready)) => Ok(Running {
            stop: Some(stop_tx),
            done: Some(done_rx),
            thread: Some(thread),
            ready,
        }),
        Ok(Err(error)) => {
            let _ = tokio::task::spawn_blocking(move || thread.join()).await;
            Err(error)
        }
        Err(_) => {
            let _ = tokio::task::spawn_blocking(move || thread.join()).await;
            Err(SdkError::Closed)
        }
    }
}

/// The stop signal of a role thread; completes when `shutdown` is requested or
/// the handle is dropped.
pub(super) struct Stop(oneshot::Receiver<()>);

impl Stop {
    pub(super) fn wait(self) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            let _ = self.0.await;
        })
    }
}

/// Announces the started role (or its start failure) to `spawn`.
pub(super) struct Ready<R> {
    boot: Option<oneshot::Sender<Boot<R>>>,
}

impl<R> Ready<R> {
    /// Whether the outcome of the start has already been announced.
    pub(super) fn announced(&self) -> bool {
        self.boot.is_none()
    }

    pub(super) fn announce(&mut self, value: Boot<R>) {
        if let Some(boot) = self.boot.take() {
            let _ = boot.send(value);
        }
    }
}
