use super::{support::*, *};
use futures::{StreamExt, stream::FuturesUnordered};
use hickory_resolver::net::runtime::Spawn;
use libp2p::{dns::Resolver as _, swarm::Executor};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Destroyed(Arc<AtomicUsize>);
impl Drop for Destroyed {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn pending(count: Arc<AtomicUsize>) -> impl Future<Output = ()> + Send + 'static {
    let guard = Destroyed(count);
    async move {
        let _guard = guard;
        std::future::pending::<()>().await;
    }
}

#[tokio::test]
async fn owned_dns_and_swarm_share_exactly_64_tasks_across_submission_clones() {
    bounded(
        async {
            let server = Server::new().await;
            let (mut executor, lifetime, _resolver, provider) = setup(server.address);
            let count = Arc::new(AtomicUsize::new(0));
            for index in 0..64 {
                if index % 2 == 0 {
                    executor.handle().exec(Box::pin(pending(count.clone())));
                } else {
                    provider
                        .clone()
                        .create_handle()
                        .spawn_bg(pending(count.clone()));
                }
            }
            assert_eq!(executor.active_tasks().unwrap(), 64);
            provider.create_handle().spawn_bg(pending(count.clone()));
            assert_eq!(
                count.load(Ordering::SeqCst),
                1,
                "DNS_OVERFLOW_FUTURE_NOT_DESTROYED"
            );
            assert_eq!(executor.active_tasks().unwrap(), 64, "SECOND_DNS_TASK_POOL");
            assert_eq!(
                executor.next_result().await.unwrap_err().to_string(),
                "executor admission limit reached"
            );
            lifetime.close();
            assert!(executor.shutdown().await.is_err());
            assert_eq!(count.load(Ordering::SeqCst), 65, "DNS_TASKS_NOT_JOINED");
            provider.create_handle().spawn_bg(pending(count.clone()));
            assert_eq!(count.load(Ordering::SeqCst), 66);
            server.quiet();
        },
        "OWNED_DNS_TASK_LIMIT_DEADLINE",
    )
    .await;
}

#[tokio::test]
async fn owned_dns_four_unpolled_calls_remain_charged_until_destroyed_or_terminated() {
    let server = Server::new().await;
    let (executor, lifetime, resolver, _) = setup(server.address);
    let clones = [
        resolver.clone(),
        resolver.clone(),
        resolver.clone(),
        resolver.clone(),
    ];
    let mut calls: Vec<_> = clones
        .iter()
        .map(|clone| Box::pin(clone.ipv4_lookup("owned.example.".into())))
        .collect();
    assert!(
        matches!(
            resolver.ipv4_lookup("overflow.example.".into()).await,
            Err(NetError::Busy)
        ),
        "LOOKUP_CLONE_BYPASSED_CAP"
    );
    assert_eq!(resolver.calls.available_permits(), 0);
    drop(calls.pop());
    assert_eq!(resolver.calls.available_permits(), 1);
    let replacement = resolver.ipv4_lookup("replacement.example.".into());
    lifetime.close();
    assert_eq!(
        resolver.calls.available_permits(),
        0,
        "CLOSE_RELEASED_UNDESTROYED_LOOKUP_CHARGES"
    );
    for call in calls {
        assert!(call.await.is_err());
    }
    assert!(replacement.await.is_err());
    assert_eq!(resolver.calls.available_permits(), 4);
    assert_eq!(executor.active_tasks().unwrap(), 0);
    server.quiet();
    executor.shutdown().await.unwrap();
}

#[tokio::test]
async fn owned_dns_pending_udp_call_owners_drop_before_join_and_release_all_native_sockets() {
    bounded(
        async {
            let server = Server::new().await;
            let (executor, lifetime, resolver, provider) = setup(server.address);
            let retained = resolver.clone();
            let handle = provider.create_handle();
            let mut calls = FuturesUnordered::new();
            for index in 0..4 {
                calls.push(resolver.ipv4_lookup(format!("pending{index}.example.")));
            }
            let mut addresses = Vec::with_capacity(4);
            for _ in 0..4 {
                tokio::select! {
                    result = calls.next() => panic!("PENDING_DNS_LOOKUP_TERMINATED: {result:?}"),
                    (_, source) = server.question() => addresses.push(source),
                }
            }
            assert!(matches!(
                retained.ipv4_lookup("overload.example.".into()).await,
                Err(NetError::Busy)
            ));
            for address in &addresses {
                assert!(
                    tokio::net::UdpSocket::bind(address).await.is_err(),
                    "UDP_RESOURCE_WITNESS_MISSING"
                );
            }
            lifetime.close();
            assert_eq!(resolver.calls.available_permits(), 0);
            drop(calls); // Carrier-owned dial/lookup destruction precedes executor shutdown.
            assert_eq!(resolver.calls.available_permits(), 4);
            executor.shutdown().await.unwrap();
            for address in addresses {
                let _rebound = tokio::net::UdpSocket::bind(address).await.unwrap();
            }
            assert!(retained.ipv4_lookup("late.example.".into()).await.is_err());
            assert!(provider.bind_udp(loopback(), server.address).await.is_err());
            drop(handle);
        },
        "OWNED_DNS_PENDING_UDP_JOIN_DEADLINE",
    )
    .await;
}

#[test]
fn owned_dns_spawn_without_runtime_reports_executor_failure_without_polling() {
    let (mut executor, lifetime, _resolver, provider) = setup("127.0.0.1:5300".parse().unwrap());
    let count = Arc::new(AtomicUsize::new(0));
    provider.create_handle().spawn_bg(pending(count.clone()));
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(executor.active_tasks().unwrap(), 0);
    assert_eq!(
        futures::executor::block_on(executor.next_result())
            .unwrap_err()
            .to_string(),
        "executor requires a Tokio runtime"
    );
    lifetime.close();
    assert!(futures::executor::block_on(executor.shutdown()).is_err());
}

#[tokio::test]
async fn owned_dns_child_panic_is_observed_and_joined() {
    bounded(
        async {
            let server = Server::new().await;
            let (mut executor, lifetime, _resolver, provider) = setup(server.address);
            provider
                .create_handle()
                .spawn_bg(async { panic!("owned DNS child panic fixture") });
            assert!(executor.next_result().await.is_err());
            lifetime.close();
            assert!(executor.shutdown().await.is_err());
        },
        "OWNED_DNS_PANIC_JOIN_DEADLINE",
    )
    .await;
}
