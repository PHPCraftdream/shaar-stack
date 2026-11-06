use std::{io, sync::Arc, time::Duration};

use tokio::task::JoinHandle;

use super::carrier_state::Shared;

/// Caller-driven owner of the bounded carrier writer task.
pub struct YggPump {
    shared: Arc<Shared>,
    task: Option<JoinHandle<io::Result<()>>>,
    finished: bool,
    outcome: Option<io::ErrorKind>,
}

impl std::fmt::Debug for YggPump {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("YggPump(..)")
    }
}

impl YggPump {
    pub(super) fn new(shared: Arc<Shared>) -> Self {
        Self {
            shared,
            task: None,
            finished: false,
            outcome: None,
        }
    }

    /// cancel-safe: yes — the retained writer handle survives cancellation.
    pub async fn run(&mut self) -> io::Result<()> {
        if self.finished {
            return self
                .outcome
                .map_or(Ok(()), |kind| Err(io::Error::from(kind)));
        }
        if self.task.is_none() && !self.shared.is_closed() {
            let shared = Arc::clone(&self.shared);
            self.task = Some(tokio::spawn(async move {
                let result = writer(Arc::clone(&shared)).await;
                shared.close();
                result
            }));
        }
        let Some(task) = &mut self.task else {
            self.finished = true;
            return Ok(());
        };
        let result = match task.await {
            Ok(result) => result,
            Err(_) => Err(io::ErrorKind::Other.into()),
        };
        self.task = None;
        self.finished = true;
        self.outcome = result.as_ref().err().map(io::Error::kind);
        self.shared.close();
        result
    }

    /// cancel-safe: yes — shutdown and join ownership remain in this pump.
    pub async fn close(&mut self) -> io::Result<()> {
        self.shared.close();
        self.run().await
    }
}

impl Drop for YggPump {
    fn drop(&mut self) {
        self.shared.close();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::DatagramError;
    use crate::test_support::{BUDGET, start_listener};
    use std::{
        future::{Future, poll_fn},
        task::{Poll, Wake},
    };

    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_close_retains_writer_join_until_repeat_call() {
        let (transport, _) = start_listener(0xDA).await;
        let bridge = crate::YggBridge::new(transport, []);
        let cap = bridge.open_datagrams([0x5A; 32], BUDGET).await.unwrap();
        let shared = Arc::new(Shared::new(vec![([0x5A; 32], cap.sender())]).unwrap());
        let mut pump = YggPump::new(Arc::clone(&shared));
        let mut run = Box::pin(pump.run());
        poll_fn(|cx| {
            assert!(run.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(run);
        let mut closing = Box::pin(pump.close());
        poll_fn(|cx| {
            assert!(closing.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(closing);
        tokio::time::timeout(BUDGET, pump.close())
            .await
            .expect("retained writer join deadline")
            .unwrap();
        assert!(shared.is_closed());
        assert!(pump.task.is_none());
        bridge.close().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn writer_send_failure_closes_all_capabilities_and_is_cached() {
        let (transport, _) = start_listener(0xD9).await;
        let bridge = crate::YggBridge::new(transport, []);
        let capability = bridge.open_datagrams([0x59; 32], BUDGET).await.unwrap();
        let sender = capability.sender();
        let shared = Arc::new(Shared::new(vec![([0x59; 32], sender.clone())]).unwrap());
        let address = shared.peer_address(&[0x59; 32]).unwrap();
        let mut pump = YggPump::new(Arc::clone(&shared));
        let waker = std::task::Waker::from(Arc::new(Noop));
        let mut cx = std::task::Context::from_waker(&waker);
        assert!(matches!(
            shared.poll_send(&mut cx, &address, b"will fail after revoke"),
            std::task::Poll::Ready(Ok(()))
        ));
        sender.revoke();
        tokio::time::timeout(BUDGET, pump.run())
            .await
            .expect("writer failure deadline")
            .expect_err("revoked queued sender fails");
        assert!(shared.is_closed());
        assert_eq!(
            sender.send(b"late", BUDGET).await,
            Err(DatagramError::Revoked)
        );
        assert_eq!(
            pump.close().await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        bridge.close().await.unwrap();
    }
}

async fn writer(shared: Arc<Shared>) -> io::Result<()> {
    while let Some(outgoing) = shared.next().await? {
        if let Err(failure) = outgoing
            .sender
            .send(&outgoing.bytes, Duration::from_secs(1))
            .await
        {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, failure));
        }
    }
    Ok(())
}
