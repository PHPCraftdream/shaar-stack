use std::time::Duration;

use shaar::{
    identity::Identity,
    network::{Allowlist, Endpoint, ForwardError, Limits, ServeReport},
};
use tokio::{sync::watch, task::JoinSet, time::timeout};

#[tokio::test]
async fn shutdown_drain_reports_join_panic_without_detaching_other_jobs() {
    timeout(Duration::from_secs(5), async {
        let mut workers: JoinSet<Result<ServeReport, ForwardError>> = JoinSet::new();
        let (panic_signal_tx, panic_signal_rx) = tokio::sync::oneshot::channel::<()>();
        let (signalled_tx, signalled_rx) = tokio::sync::oneshot::channel::<()>();
        let panic_dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let panic_notify = std::sync::Arc::new(tokio::sync::Notify::new());
        let panic_dropped_job = panic_dropped.clone();
        let panic_notify_job = panic_notify.clone();
        workers.spawn(async move {
            let _output_guard = DropFlag(panic_dropped_job, Some(panic_notify_job));
            let _ = panic_signal_rx.await;
            let _ = signalled_tx.send(());
            panic!();
            #[allow(unreachable_code)]
            Ok(ServeReport::default())
        });
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let other_dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let other_dropped_job = other_dropped.clone();
        workers.spawn(async move {
            let _output_guard = DropFlag(other_dropped_job, None);
            let _ = release_rx.await;
            Ok(ServeReport::default())
        });

        let result = {
            let drain = super::super::drain_sessions(&mut workers);
            tokio::pin!(drain);
            tokio::select! {
                biased;
                result = &mut drain => panic!("drain unexpectedly completed: {result:?}"),
                _ = tokio::task::yield_now() => {},
            }
            panic_signal_tx.send(()).unwrap();
            signalled_rx.await.unwrap();
            while !panic_dropped.load(std::sync::atomic::Ordering::SeqCst) {
                panic_notify.notified().await;
            }
            tokio::select! {
                biased;
                result = &mut drain => panic!("drain unexpectedly completed: {result:?}"),
                _ = tokio::task::yield_now() => {},
            }
            release_tx.send(()).unwrap();
            drain.await
        };
        assert!(result.is_some());
        assert!(panic_dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert!(other_dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert!(workers.is_empty());
    })
    .await
    .expect("shutdown drain deadline");
}

struct DropFlag(
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    Option<std::sync::Arc<tokio::sync::Notify>>,
);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(notify) = &self.1 {
            notify.notify_one();
        }
    }
}

#[tokio::test]
async fn cooperative_shutdown_joins_all_bounded_session_workers() {
    timeout(Duration::from_secs(20), async {
        let identities: Vec<_> = (102..105)
            .map(|seed| Identity::from_seed([seed; 32]))
            .collect();
        let allowed: Vec<_> = identities
            .iter()
            .map(|identity| iroh_base::PublicKey::from_bytes(&identity.public_key_bytes()).unwrap())
            .collect();
        let mut server = Endpoint::bind(
            &Identity::from_seed([101; 32]),
            "127.0.0.1:0".parse().unwrap(),
            Allowlist::new(&allowed).unwrap(),
            Limits::new(3).unwrap(),
        )
        .await
        .unwrap();
        let mut clients = Vec::new();
        for identity in &identities {
            clients.push(
                Endpoint::bind(
                    identity,
                    "127.0.0.1:0".parse().unwrap(),
                    Allowlist::new(&[]).unwrap(),
                    Limits::new(1).unwrap(),
                )
                .await
                .unwrap(),
            );
        }
        let server_id = server.id();
        let server_address = server.local_addr();
        let (stop_tx, stop_rx) = watch::channel(false);
        let mut workers = JoinSet::new();
        let mut client_sessions = Vec::new();
        let accepts = async {
            for _ in 0..clients.len() {
                let mut session = server.accept().await.unwrap();
                let receiver = stop_rx.clone();
                workers.spawn(async move {
                    session
                        .serve("127.0.0.1:9".parse().unwrap(), async move {
                            let mut receiver = receiver;
                            if !*receiver.borrow() {
                                let _ = receiver.changed().await;
                            }
                        })
                        .await
                });
            }
        };
        let connects = async {
            for client in &clients {
                client_sessions.push(client.connect(server_id, server_address).await.unwrap());
            }
        };
        tokio::join!(accepts, connects);
        let _ = stop_tx.send(true);
        while let Some(result) = workers.join_next().await {
            result.unwrap().unwrap();
        }
        drop(client_sessions);
        assert!(workers.is_empty());
        server.close().await;
        for client in clients {
            client.close().await;
        }
    })
    .await
    .expect("server shutdown deadline");
}
