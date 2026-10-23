use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
};

use futures::task::AtomicWaker;
use libp2p_swarm::Executor;
use tokio::task::JoinSet;

const TASK_LIMIT: usize = 64;

struct State {
    tasks: JoinSet<()>,
    closed: bool,
    overflowed: bool,
    panicked: bool,
    runtime_unavailable: bool,
}

struct Shared {
    state: Mutex<State>,
    changed: AtomicWaker,
}

/// Cloneable submission capability, not ownership of the task group or its shutdown.
#[derive(Clone)]
pub struct ExecutorHandle(Arc<Shared>);

/// Sole owner of bounded Swarm background tasks and their terminal results.
///
/// Swarm's synchronous `Executor::exec(&self, ...)` requires interior mutability.
/// The mutex covers only bounded admission/spawn/poll, never an await or I/O.
/// One owner observes completions; shutdown takes the JoinSet outside the lock.
pub struct OwnedExecutor {
    shared: Arc<Shared>,
}

impl Default for OwnedExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl OwnedExecutor {
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    tasks: JoinSet::new(),
                    closed: false,
                    overflowed: false,
                    panicked: false,
                    runtime_unavailable: false,
                }),
                changed: AtomicWaker::new(),
            }),
        }
    }

    pub fn handle(&self) -> ExecutorHandle {
        ExecutorHandle(self.shared.clone())
    }

    pub fn active_tasks(&self) -> io::Result<usize> {
        Ok(self
            .shared
            .state
            .lock()
            .map_err(|_| io::Error::other("executor state poisoned"))?
            .tasks
            .len())
    }

    /// cancel-safe: yes — a pending observation consumes no completion or task.
    pub async fn next_result(&mut self) -> io::Result<()> {
        futures::future::poll_fn(|cx| {
            self.shared.changed.register(cx.waker());
            let mut state = match self.shared.state.lock() {
                Ok(state) => state,
                Err(_) => {
                    return std::task::Poll::Ready(Err(io::Error::other(
                        "executor state poisoned",
                    )));
                }
            };
            if state.runtime_unavailable {
                return std::task::Poll::Ready(Err(io::Error::other(
                    "executor requires a Tokio runtime",
                )));
            }
            if state.overflowed {
                return std::task::Poll::Ready(Err(io::Error::other(
                    "executor admission limit reached",
                )));
            }
            match state.tasks.poll_join_next(cx) {
                std::task::Poll::Ready(Some(Ok(()))) => std::task::Poll::Ready(Ok(())),
                std::task::Poll::Ready(Some(Err(error))) => {
                    state.panicked |= error.is_panic();
                    std::task::Poll::Ready(Err(io::Error::other(error)))
                }
                _ => std::task::Poll::Pending,
            }
        })
        .await
    }

    /// Stops admission, aborts all outstanding tasks and joins every terminal result.
    /// cancel-safe: NO — dropping shutdown aborts its JoinSet but cannot await it.
    pub async fn shutdown(self) -> io::Result<()> {
        let (mut tasks, mut failed) = {
            let (mut state, poisoned) = match self.shared.state.lock() {
                Ok(state) => (state, false),
                Err(error) => (error.into_inner(), true),
            };
            state.closed = true;
            let failed =
                poisoned || state.panicked || state.overflowed || state.runtime_unavailable;
            (std::mem::take(&mut state.tasks), failed)
        };
        tasks.abort_all();
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                failed |= error.is_panic();
            }
        }
        if failed {
            Err(io::Error::other("managed executor task failure"))
        } else {
            Ok(())
        }
    }
}

impl Executor for ExecutorHandle {
    fn exec(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        let mut state = match self.0.state.lock() {
            Ok(state) => state,
            Err(error) => {
                drop(error);
                drop(future);
                self.0.changed.wake();
                return;
            }
        };
        if state.closed || state.runtime_unavailable || state.overflowed || state.panicked {
            drop(state);
            drop(future);
            self.0.changed.wake();
            return;
        }
        if state.tasks.len() >= TASK_LIMIT {
            state.overflowed = true;
            drop(state);
            drop(future);
            self.0.changed.wake();
            return;
        }
        let runtime = match tokio::runtime::Handle::try_current() {
            Ok(runtime) => runtime,
            Err(_) => {
                state.runtime_unavailable = true;
                drop(state);
                drop(future);
                self.0.changed.wake();
                return;
            }
        };
        state.tasks.spawn_on(future, &runtime);
        drop(state);
        self.0.changed.wake();
    }
}

impl Drop for OwnedExecutor {
    fn drop(&mut self) {
        {
            let mut state = self
                .shared
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.closed = true;
            state.tasks.abort_all();
        }
        self.shared.changed.wake();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::{net::UdpSocket, sync::oneshot};

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_joins_resource_drop_even_with_submission_handles_alive() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let owner = OwnedExecutor::new();
            let handle = owner.handle();
            let socket = UdpSocket::bind("127.0.0.1:20021").await.unwrap();
            let (ready, observed) = oneshot::channel();
            handle.exec(Box::pin(async move {
                let _socket = socket;
                ready.send(()).unwrap();
                std::future::pending::<()>().await;
            }));
            observed.await.unwrap();
            owner.shutdown().await.unwrap();
            let _rebound = UdpSocket::bind("127.0.0.1:20021").await.unwrap();
            let socket = UdpSocket::bind("127.0.0.1:20022").await.unwrap();
            handle.exec(Box::pin(async move {
                let _socket = socket;
                std::future::pending::<()>().await;
            }));
            let _rejected_rebound = UdpSocket::bind("127.0.0.1:20022").await.unwrap();
        })
        .await
        .expect("executor resource join deadline");
    }

    #[tokio::test]
    async fn capacity_is_enforced_before_spawning_and_reported_to_owner() {
        let mut owner = OwnedExecutor::new();
        let handle = owner.handle();
        for _ in 0..TASK_LIMIT {
            handle.exec(Box::pin(std::future::pending()));
        }
        assert_eq!(owner.active_tasks().unwrap(), TASK_LIMIT);
        handle.exec(Box::pin(std::future::pending()));
        assert_eq!(owner.active_tasks().unwrap(), TASK_LIMIT);
        assert!(owner.next_result().await.is_err());
        assert!(owner.shutdown().await.is_err());
    }

    #[test]
    fn submission_without_a_runtime_is_rejected_without_spawn_panic() {
        let mut owner = OwnedExecutor::new();
        owner.handle().exec(Box::pin(std::future::pending()));
        assert_eq!(owner.active_tasks().unwrap(), 0);
        assert!(futures::executor::block_on(owner.next_result()).is_err());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            owner.handle().exec(Box::pin(async {}));
            assert_eq!(owner.active_tasks().unwrap(), 0);
        });
        assert!(futures::executor::block_on(owner.shutdown()).is_err());
    }

    #[tokio::test]
    async fn cancelled_empty_observation_does_not_lose_the_next_completion() {
        let mut owner = OwnedExecutor::new();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), owner.next_result())
                .await
                .is_err()
        );
        owner.handle().exec(Box::pin(async {}));
        tokio::time::timeout(Duration::from_secs(5), owner.next_result())
            .await
            .unwrap()
            .unwrap();
        owner.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn poisoned_registry_still_joins_and_releases_owned_io() {
        let mut owner = OwnedExecutor::new();
        let socket = UdpSocket::bind("127.0.0.1:20023").await.unwrap();
        let (ready, observed) = oneshot::channel();
        owner.handle().exec(Box::pin(async move {
            let _socket = socket;
            ready.send(()).unwrap();
            std::future::pending::<()>().await;
        }));
        observed.await.unwrap();
        let shared = owner.shared.clone();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = shared.state.lock().unwrap();
            panic!("executor poison fixture");
        }));
        assert!(panic.is_err());
        assert!(owner.next_result().await.is_err());
        assert!(owner.shutdown().await.is_err());
        let _rebound = UdpSocket::bind("127.0.0.1:20023").await.unwrap();
    }

    #[tokio::test]
    async fn completion_and_panic_results_are_observed_not_detached() {
        let mut owner = OwnedExecutor::new();
        owner.handle().exec(Box::pin(async {}));
        owner.next_result().await.unwrap();
        assert_eq!(owner.active_tasks().unwrap(), 0);
        owner.handle().exec(Box::pin(async {
            panic!("managed executor panic fixture");
        }));
        assert!(owner.next_result().await.is_err());
        assert!(owner.shutdown().await.is_err());
    }
}
