use std::{
    future::Future,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use tokio::sync::watch;

struct Shared {
    closed: AtomicBool,
    canceled: watch::Sender<bool>,
}

#[derive(Clone)]
pub(super) struct Gate(Arc<Shared>);

/// Sole lifetime owner. Drop closes admission and wakes work, but never joins it.
pub(crate) struct Lifetime {
    gate: Gate,
}

impl Lifetime {
    pub(super) fn new() -> Self {
        let (canceled, _) = watch::channel(false);
        Self {
            gate: Gate(Arc::new(Shared {
                closed: AtomicBool::new(false),
                canceled,
            })),
        }
    }

    pub(super) fn gate(&self) -> Gate {
        self.gate.clone()
    }

    #[cfg(test)]
    pub(crate) fn observer(&self) -> impl Fn() -> bool + Send + 'static + use<> {
        let gate = self.gate.clone();
        move || gate.check().is_err()
    }

    pub(crate) fn close(&self) {
        if !self.gate.0.closed.swap(true, Ordering::SeqCst) {
            self.gate.0.canceled.send_replace(true);
        }
    }
}

impl Drop for Lifetime {
    fn drop(&mut self) {
        self.close();
    }
}

impl Gate {
    /// The successful sequentially consistent load is each operation's admission point.
    /// Close linearizes at the swap. An already admitted poll may finish outside the gate;
    /// closing is not a destruction barrier. No I/O, future poll or Drop runs under a guard.
    pub(super) fn check(&self) -> io::Result<()> {
        if self.0.closed.load(Ordering::SeqCst) {
            Err(closed())
        } else {
            Ok(())
        }
    }

    /// cancel-safe: NO — destroys the inner future, but cannot roll back admitted I/O.
    /// Every socket poll is enclosed by this waiter (lookup, connect/bind or managed task).
    pub(super) async fn during<F: Future>(&self, future: F) -> io::Result<F::Output> {
        let mut canceled = self.0.canceled.subscribe();
        let changed = canceled.wait_for(|closed| *closed);
        tokio::pin!(changed, future);
        std::future::poll_fn(|cx| {
            // Register before admission so close cannot lose the wakeup.
            if changed.as_mut().poll(cx).is_ready() {
                return std::task::Poll::Ready(Err(closed()));
            }
            if let Err(error) = self.check() {
                return std::task::Poll::Ready(Err(error));
            }
            future.as_mut().poll(cx).map(Ok)
        })
        .await
    }
}

pub(super) fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "carrier DNS lifetime closed")
}
