use std::time::Duration;

use shaar::{
    identity::Identity,
    network::{Allowlist, Endpoint, ForwardError, Limits, ServeReport},
};
use tokio::{sync::watch, task::JoinSet, time::timeout};

#[tokio::test]
async fn server_loop_joins_a_served_session_before_returning() {
    timeout(Duration::from_secs(30), async {
        use std::{future::Future, task::Poll};
        use tokio::net::{TcpListener, TcpStream, UdpSocket};

        let client_identity = Identity::from_seed([98; 32]);
        let client = Endpoint::bind(
            &client_identity,
            "127.0.0.1:0".parse().unwrap(),
            Allowlist::default(),
            Limits::new(1).unwrap(),
        )
        .await
        .unwrap();
        let mut server = Endpoint::bind(
            &Identity::from_seed([99; 32]),
            "127.0.0.1:0".parse().unwrap(),
            Allowlist::new(&[client.id()]).unwrap(),
            Limits::new(1).unwrap(),
        )
        .await
        .unwrap();
        let server_address = server.local_addr();
        let (client_session, mut server_session) = tokio::try_join!(
            client.connect(server.id(), server_address),
            server.accept(),
        )
        .unwrap();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (application, bridge) = tokio::join!(
            TcpStream::connect(local.local_addr().unwrap()),
            local.accept(),
        );
        let application = application.unwrap();
        let bridge = bridge.unwrap().0;
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let mut workers = JoinSet::new();
        workers.spawn(async move {
            let result = server_session.serve(target_address, async {
                let _ = stop_rx.await;
            }).await;
            let _ = finished_tx.send(());
            let _ = release_rx.await;
            result
        });
        let forwarding = client_session.forward(bridge);
        tokio::pin!(forwarding);
        let (target_stream, _) = tokio::select! {
            result = target.accept() => result.unwrap(),
            result = &mut forwarding => panic!("forwarding ended before target connection: {result:?}"),
        };
        let _ = stop_tx.send(());
        let mut shutdown = Box::pin(std::future::ready(Ok(())));
        let loop_result = {
            let loop_future = super::super::server_loop_with_sessions(
                &mut server, target_address, 1, &mut shutdown, workers,
            );
            tokio::pin!(loop_future);
            tokio::select! {
                result = &mut loop_future => panic!("server returned before worker barrier: {result:?}"),
                result = finished_rx => result.unwrap(),
            }
            let pending = std::future::poll_fn(|cx| Poll::Ready(loop_future.as_mut().poll(cx).is_pending())).await;
            let _ = release_tx.send(());
            let result = loop_future.await;
            (pending, result)
        };
        drop(target_stream);
        drop(application);
        let _ = forwarding.await;
        server.close().await;
        client.close().await;
        UdpSocket::bind(server_address).await.unwrap();
        assert!(loop_result.0, "server returned before the served session worker finished");
        assert!(loop_result.1.is_ok());
    })
    .await
    .expect("served session shutdown deadline");
}

#[tokio::test]
async fn server_loop_waits_for_worker_and_reports_failure_on_shutdown() {
    timeout(Duration::from_secs(15), async {
        use std::{future::Future, task::Poll};

        let mut endpoint = Endpoint::bind(
            &Identity::from_seed([100; 32]),
            "127.0.0.1:0".parse().unwrap(),
            Allowlist::default(),
            Limits::new(1).unwrap(),
        )
        .await
        .unwrap();
        let address = endpoint.local_addr();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let mut workers = JoinSet::new();
        workers.spawn(async move {
            let _ = release_rx.await;
            Err(ForwardError::TaskFailure)
        });
        let mut shutdown = Box::pin(std::future::ready(Ok(())));
        let pending = {
            let server = super::super::server_loop_with_sessions(
                &mut endpoint,
                "127.0.0.1:9".parse().unwrap(),
                1,
                &mut shutdown,
                workers,
            );
            tokio::pin!(server);
            let pending =
                std::future::poll_fn(|cx| Poll::Ready(server.as_mut().poll(cx).is_pending())).await;
            let _ = release_tx.send(());
            let result = server.await;
            (pending, result)
        };
        endpoint.close().await;
        tokio::net::UdpSocket::bind(address).await.unwrap();
        assert!(pending.0, "shutdown returned before the worker completed");
        assert!(pending.1.is_err(), "worker failure must be returned");
    })
    .await
    .expect("server loop shutdown deadline");
}

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
