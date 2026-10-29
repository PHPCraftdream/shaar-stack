use std::{
    collections::VecDeque,
    future::Future,
    panic::AssertUnwindSafe,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Poll,
    time::Duration,
};

use shaar::{
    identity::Identity,
    network::{Allowlist, Endpoint, Limits, NetworkError, Session},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinSet,
    time::timeout,
};

struct ReadySessions {
    queued: VecDeque<Session>,
    admitted: Arc<AtomicUsize>,
}

impl super::super::SessionSource for ReadySessions {
    async fn next_session(&mut self) -> Result<Session, NetworkError> {
        if let Some(session) = self.queued.pop_front() {
            self.admitted.fetch_add(1, Ordering::SeqCst);
            Ok(session)
        } else {
            std::future::pending().await
        }
    }
}

async fn tcp_pair() -> Result<(TcpStream, TcpStream), String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let address = listener.local_addr().map_err(|e| e.to_string())?;
    let (app, accepted) = tokio::try_join!(TcpStream::connect(address), listener.accept())
        .map_err(|e| e.to_string())?;
    Ok((app, accepted.0))
}

#[tokio::test]
async fn ready_session_waits_for_server_worker_capacity() {
    let mut first = None;
    let mut second = None;
    let mut server = None;
    let mut workers = JoinSet::new();
    let outcome = {
        let scenario = async {
            for (slot, seed) in [(&mut first, 201), (&mut second, 202)] {
                *slot = Some(
                    Endpoint::bind(
                        &Identity::from_seed([seed; 32]),
                        "127.0.0.1:0".parse().unwrap(),
                        Allowlist::default(),
                        Limits::new(1).unwrap(),
                    )
                    .await
                    .map_err(|e| e.to_string())?,
                );
            }
            let first_endpoint = first.as_ref().unwrap();
            let second_endpoint = second.as_ref().unwrap();
            server = Some(
                Endpoint::bind(
                    &Identity::from_seed([203; 32]),
                    "127.0.0.1:0".parse().unwrap(),
                    Allowlist::new(&[first_endpoint.id(), second_endpoint.id()]).unwrap(),
                    Limits::new(2).unwrap(),
                )
                .await
                .map_err(|e| e.to_string())?,
            );
            let endpoint = server.as_mut().unwrap();
            let id = endpoint.id();
            let address = endpoint.local_addr();
            let (accepted, connected) =
                tokio::join!(endpoint.accept(), first_endpoint.connect(id, address));
            let first_session = connected.map_err(|e| e.to_string())?;
            let first_accepted = accepted.map_err(|e| e.to_string())?;
            let (accepted, connected) =
                tokio::join!(endpoint.accept(), second_endpoint.connect(id, address));
            let second_session = connected.map_err(|e| e.to_string())?;
            let second_accepted = accepted.map_err(|e| e.to_string())?;
            let admitted = Arc::new(AtomicUsize::new(0));
            let mut source = ReadySessions {
                queued: VecDeque::from([first_accepted, second_accepted]),
                admitted: admitted.clone(),
            };
            let target = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|e| e.to_string())?;
            let target_address = target.local_addr().map_err(|e| e.to_string())?;
            let (stop_tx, stop_rx) = oneshot::channel::<()>();
            let mut shutdown =
                Box::pin(async move { stop_rx.await.map_err(std::io::Error::other) });
            let runtime = super::super::server_loop_with_gate(
                &mut source,
                target_address,
                1,
                &mut shutdown,
                &mut workers,
                || std::future::ready(()),
            );
            tokio::pin!(runtime);
            {
                let (mut app, bridge) = tcp_pair().await?;
                app.write_all(b"one").await.map_err(|e| e.to_string())?;
                let forward = async move { first_session.forward(bridge).await };
                tokio::pin!(forward);
                let (mut stream, _) = tokio::select! {
                    accepted = target.accept() => accepted.map_err(|e| e.to_string())?,
                    result = &mut runtime => return Err(format!("runtime ended early: {result:?}")),
                    result = &mut forward => return Err(format!("first stream ended early: {result:?}")),
                };
                let mut bytes = [0; 3];
                tokio::select! {
                    result = stream.read_exact(&mut bytes) => { result.map_err(|e| e.to_string())?; },
                    result = &mut runtime => return Err(format!("runtime ended early: {result:?}")),
                    result = &mut forward => return Err(format!("first stream ended early: {result:?}")),
                }
                if &bytes != b"one" {
                    return Err("incorrect first payload".into());
                }
                let pending =
                    std::future::poll_fn(|cx| Poll::Ready(runtime.as_mut().poll(cx).is_pending()))
                        .await;
                if !pending || admitted.load(Ordering::SeqCst) != 1 {
                    return Err("ready second session bypassed held worker capacity".into());
                }
            }
            let (mut app, bridge) = tcp_pair().await?;
            app.write_all(b"two").await.map_err(|e| e.to_string())?;
            let forward = async move { second_session.forward(bridge).await };
            tokio::pin!(forward);
            let (mut stream, _) = tokio::select! {
                accepted = target.accept() => accepted.map_err(|e| e.to_string())?,
                result = &mut runtime => return Err(format!("runtime ended before recovery: {result:?}")),
                result = &mut forward => return Err(format!("second stream ended early: {result:?}")),
            };
            let mut bytes = [0; 3];
            tokio::select! {
                result = stream.read_exact(&mut bytes) => { result.map_err(|e| e.to_string())?; },
                result = &mut runtime => return Err(format!("runtime ended before payload: {result:?}")),
                result = &mut forward => return Err(format!("second stream ended early: {result:?}")),
            }
            if &bytes != b"two" || admitted.load(Ordering::SeqCst) != 2 {
                return Err("second ready session did not recover exactly once".into());
            }
            stop_tx.send(()).map_err(|_| "shutdown receiver closed")?;
            runtime.await?;
            Ok::<(), String>(())
        };
        tokio::pin!(scenario);
        timeout(
            Duration::from_secs(40),
            std::future::poll_fn(|cx| {
                match std::panic::catch_unwind(AssertUnwindSafe(|| scenario.as_mut().poll(cx))) {
                    Ok(result) => result,
                    Err(_) => Poll::Ready(Err("capacity scenario panicked".into())),
                }
            }),
        )
        .await
    };
    workers.abort_all();
    let drained = timeout(Duration::from_secs(15), async {
        while let Some(result) = workers.join_next().await {
            if let Err(error) = result {
                if !error.is_cancelled() {
                    return Err(error.to_string());
                }
            }
        }
        Ok::<(), String>(())
    })
    .await;
    let mut closed = true;
    for endpoint in [server, first, second].into_iter().flatten() {
        closed &= timeout(Duration::from_secs(15), endpoint.close())
            .await
            .is_ok();
    }
    assert!(
        matches!(drained, Ok(Ok(()))),
        "worker cleanup failed: {drained:?}"
    );
    assert!(closed, "endpoint cleanup deadline");
    assert!(
        matches!(outcome, Ok(Ok(()))),
        "capacity scenario failed: {outcome:?}"
    );
}
