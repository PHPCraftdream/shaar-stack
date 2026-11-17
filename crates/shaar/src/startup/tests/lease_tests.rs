//! Lease-observation tests for the erased client-owner seam, split verbatim
//! from dialers.rs for the 700-line rule — no behavior change.

use super::*;
use crate::network::{ForwardError, ForwardStats};
use crate::path::{Mode, PathKind, PolicyConfig, StandbyOwner};
use futures::FutureExt;
use futures::task::ArcWake;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::TcpStream;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, watch};

struct ChargedLink {
    _permit: OwnedSemaphorePermit,
}

impl RouteLink for ChargedLink {
    fn forward(
        &self,
        _: TcpStream,
    ) -> Pin<Box<dyn Future<Output = Result<ForwardStats, ForwardError>> + Send + '_>> {
        Box::pin(std::future::ready(Err(ForwardError::PathUnavailable)))
    }
}

struct ChargedDialer {
    slots: Arc<Semaphore>,
    loss: watch::Receiver<bool>,
}

impl Dialer for ChargedDialer {
    type Link = ChargedLink;

    async fn dial(&mut self, _: Instant) -> Result<Self::Link, DialError> {
        Ok(ChargedLink {
            _permit: Arc::clone(&self.slots)
                .try_acquire_owned()
                .map_err(|_| DialError)?,
        })
    }

    async fn lost(&mut self, _: &Self::Link) {
        loop {
            if *self.loss.borrow_and_update() {
                return;
            }
            self.loss.changed().await.expect("retained loss sender");
        }
    }

    async fn close(&mut self) -> Result<(), DialError> {
        Ok(())
    }
}

#[derive(Default)]
struct WakeProbe {
    notified: Notify,
}

impl ArcWake for WakeProbe {
    fn wake_by_ref(probe: &Arc<Self>) {
        probe.notified.notify_one();
    }
}

#[tokio::test(start_paused = true)]
async fn pending_loss_releases_role_lease_retains_worker_and_keeps_timer_waker() {
    for worker_holds_old_link in [false, true] {
        let slots = Arc::new(Semaphore::new(1));
        let (loss, observed_loss) = watch::channel(false);
        let config = PolicyConfig::default();
        let mut owner = StandbyOwner::new(
            ChargedDialer {
                slots: Arc::clone(&slots),
                loss: observed_loss,
            },
            MissingYggDialer,
            Mode::Signal,
            config,
        )
        .expect("bounded real policy owner");
        let mut lease = None;
        let kind = ErasedClientOwner::follow(&mut owner, &mut lease)
            .await
            .expect("initial route");
        lease = ErasedClientOwner::route(&owner).map(|link| (kind, link));
        let worker =
            worker_holds_old_link.then(|| Arc::clone(&lease.as_ref().expect("role lease").1));
        loss.send(true).expect("actual policy loss");
        let mut advanced = ErasedClientOwner::follow(&mut owner, &mut lease);
        let probe = Arc::new(WakeProbe::default());
        let waker = futures::task::waker_ref(&probe);
        let mut context = Context::from_waker(&waker);
        assert!(matches!(
            advanced.as_mut().poll(&mut context),
            Poll::Pending
        ));
        assert_eq!(
            slots.available_permits(),
            usize::from(!worker_holds_old_link)
        );
        drop(worker);
        assert_eq!(slots.available_permits(), 1);
        loss.send(false).expect("the replacement path is not lost");
        // Discard any earlier notification; the next one must come from retained work.
        let _ = probe.notified.notified().now_or_never();
        tokio::time::advance(Duration::from_millis(config.loss_grace)).await;
        tokio::time::timeout(
            Duration::from_millis(config.attempt_timeout),
            probe.notified.notified(),
        )
        .await
        .expect("the original grace timer must retain its registered waker");
        let kind = tokio::time::timeout(Duration::from_millis(config.attempt_timeout), advanced)
            .await
            .expect("bounded policy progress")
            .expect("replacement admission");
        assert_eq!(kind, PathKind::Native);
        assert!(
            lease.is_none(),
            "withdrawn role lease was released during Pending"
        );
        lease = ErasedClientOwner::route(&owner).map(|link| (kind, link));
        assert_eq!(slots.available_permits(), 0);
        drop(lease);
        ErasedClientOwner::close(&mut owner)
            .await
            .expect("joined policy close");
        assert_eq!(slots.available_permits(), 1);
    }
}
