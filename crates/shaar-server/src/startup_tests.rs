#![forbid(unsafe_code)]

use std::{
    cell::Cell,
    future::{Future, pending, poll_fn, ready},
    task::Poll,
    time::Duration,
};
use tokio::sync::oneshot;

struct WaiterDrop<'a>(&'a Cell<usize>);
impl Drop for WaiterDrop<'_> {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

#[tokio::test]
async fn ready_shutdown_is_polled_before_startup() {
    let polled = Cell::new(false);
    let startup = poll_fn(|_| {
        polled.set(true);
        Poll::Ready(7_u8)
    });
    assert_eq!(super::start_until_shutdown(startup, ready(())).await, None);
    assert!(!polled.get());
}

#[tokio::test]
async fn shutdown_drops_a_pending_startup_waiter_without_waiting_for_it() {
    let entered = Cell::new(false);
    let dropped = Cell::new(0);
    let startup = async {
        let _waiter = WaiterDrop(&dropped);
        entered.set(true);
        pending::<()>().await;
        7_u8
    };
    let (stop, stopped) = oneshot::channel();
    let shutdown = async { stopped.await.expect("stop sender retained") };
    let racing = super::start_until_shutdown(startup, shutdown);
    tokio::pin!(racing);
    assert!(poll_fn(|cx| Poll::Ready(racing.as_mut().poll(cx).is_pending())).await);
    assert!(entered.get());
    assert_eq!(dropped.get(), 0);
    stop.send(()).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), &mut racing)
        .await
        .expect("shutdown must not wait for pending startup");
    assert_eq!(result, None);
    assert_eq!(dropped.get(), 1);
}

#[tokio::test]
async fn successful_startup_retains_the_registered_shutdown_waiter() {
    let registrations = Cell::new(0);
    let (stop, stopped) = oneshot::channel();
    let shutdown = async {
        registrations.set(registrations.get() + 1);
        stopped.await.expect("stop sender retained");
    };
    tokio::pin!(shutdown);
    assert_eq!(
        super::start_until_shutdown(ready(Ok::<(), &str>(())), &mut shutdown).await,
        Some(Ok(()))
    );
    assert_eq!(registrations.get(), 1);
    stop.send(()).unwrap();
    shutdown.await;
    assert_eq!(registrations.get(), 1);
}

#[tokio::test]
async fn startup_error_is_returned_without_replacing_its_cause() {
    assert_eq!(
        super::start_until_shutdown(ready(Err::<(), _>("bind failure")), pending::<()>()).await,
        Some(Err("bind failure"))
    );
}
