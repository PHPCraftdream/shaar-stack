use std::{future::Future, io, panic::AssertUnwindSafe, task::Poll, time::Duration};

use shaar::{
    identity::Identity,
    network::{Allowlist, Endpoint, ForwardError, Limits, ServeReport},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, oneshot, watch},
    task::JoinSet,
    time::timeout,
};

#[tokio::test]
async fn shutdown_joins_the_production_accepted_session_worker() {
    let client_identity = Identity::from_seed([0x61; 32]);
    let client = timeout(
        Duration::from_secs(15),
        Endpoint::bind(
            &client_identity,
            "127.0.0.1:0".parse().unwrap(),
            Allowlist::default(),
            Limits::new(1).unwrap(),
        ),
    )
    .await
    .expect("client bind deadline")
    .unwrap();
    let server_identity = Identity::from_seed([0x62; 32]);
    let server_result = timeout(
        Duration::from_secs(15),
        Endpoint::bind(
            &server_identity,
            "127.0.0.1:0".parse().unwrap(),
            Allowlist::new(&[client.id()]).unwrap(),
            Limits::new(1).unwrap(),
        ),
    )
    .await;
    let mut server = match server_result {
        Ok(Ok(server)) => server,
        Ok(Err(error)) => {
            let closed = timeout(Duration::from_secs(15), client.close()).await;
            panic!("server bind failed: {error}; client close: {closed:?}");
        }
        Err(_) => {
            let closed = timeout(Duration::from_secs(15), client.close()).await;
            panic!("server bind deadline; client close: {closed:?}");
        }
    };
    let server_id = server.id();
    let server_address = server.local_addr();
    let (release_tx, release_rx) = watch::channel(false);
    let (entered_tx, mut entered_rx) = mpsc::channel::<()>(1);
    let mut sessions: JoinSet<Result<ServeReport, ForwardError>> = JoinSet::new();

    let outcome = {
        let gate = move || {
            let entered = entered_tx.clone();
            let mut release = release_rx.clone();
            async move {
                if entered.send(()).await.is_err() {
                    return;
                }
                loop {
                    if *release.borrow_and_update() {
                        break;
                    }
                    if release.changed().await.is_err() {
                        break;
                    }
                }
            }
        };
        let release_for_test = release_tx.clone();
        let core = async {
            let target = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|e| e.to_string())?;
            let target_address = target.local_addr().map_err(|e| e.to_string())?;
            let local = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|e| e.to_string())?;
            let (app, accepted) = tokio::try_join!(
                TcpStream::connect(local.local_addr().map_err(|e| e.to_string())?),
                local.accept(),
            )
            .map_err(|e| e.to_string())?;
            let mut app = app;
            let bridge = accepted.0;
            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            let mut shutdown = Box::pin(async move {
                shutdown_rx
                    .await
                    .map_err(|_| io::Error::other("shutdown sender dropped"))
            });
            let server_loop = super::super::server_loop_with_gate(
                &mut server,
                target_address,
                1,
                &mut shutdown,
                &mut sessions,
                gate,
            );
            tokio::pin!(server_loop);
            let session = tokio::select! {
                connected = client.connect(server_id, server_address) => connected.map_err(|e| e.to_string())?,
                result = &mut server_loop => return Err(format!("server ended before admission: {result:?}")),
            };
            app.write_all(b"join-proof")
                .await
                .map_err(|e| e.to_string())?;
            let forwarding = session.forward(bridge);
            tokio::pin!(forwarding);
            let (mut target_stream, _) = tokio::select! {
                accepted = target.accept() => accepted.map_err(|e| e.to_string())?,
                result = &mut server_loop => return Err(format!("server ended before target: {result:?}")),
                result = &mut forwarding => return Err(format!("forwarding ended before target: {result:?}")),
            };
            let mut payload = [0; 10];
            tokio::select! {
                result = target_stream.read_exact(&mut payload) => { result.map_err(|e| e.to_string())?; },
                result = &mut server_loop => return Err(format!("server ended before payload: {result:?}")),
                result = &mut forwarding => return Err(format!("forwarding ended before payload: {result:?}")),
            }
            if &payload != b"join-proof" {
                return Err("target received incorrect bytes".into());
            }
            shutdown_tx
                .send(())
                .map_err(|_| "shutdown receiver closed")?;
            let mut forward_done = false;
            loop {
                tokio::select! {
                    biased;
                    result = &mut server_loop => return Err(format!("server returned before worker gate: {result:?}")),
                    entered = entered_rx.recv() => {
                        entered.ok_or("worker gate sender closed")?;
                        break;
                    }
                    result = &mut forwarding, if !forward_done => {
                        if matches!(result, Err(ForwardError::TaskFailure)) {
                            return Err("client forwarding task failed".into());
                        }
                        forward_done = true;
                    }
                }
            }
            let pending =
                std::future::poll_fn(|cx| Poll::Ready(server_loop.as_mut().poll(cx).is_pending()))
                    .await;
            if !pending {
                return Err("server returned while accepted worker was held".into());
            }
            release_for_test
                .send(true)
                .map_err(|_| "worker release receiver closed")?;
            server_loop.await?;
            Ok::<(), String>(())
        };
        tokio::pin!(core);
        timeout(
            Duration::from_secs(30),
            std::future::poll_fn(|cx| {
                match std::panic::catch_unwind(AssertUnwindSafe(|| core.as_mut().poll(cx))) {
                    Ok(Poll::Ready(result)) => Poll::Ready(Ok(result)),
                    Ok(Poll::Pending) => Poll::Pending,
                    Err(_) => Poll::Ready(Err("scenario panicked".to_owned())),
                }
            }),
        )
        .await
    };

    let _ = release_tx.send(true);
    sessions.abort_all();
    let drained = timeout(Duration::from_secs(15), async {
        let mut failures = Vec::new();
        while let Some(result) = sessions.join_next().await {
            match result {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => failures.push(format!("session cleanup: {error}")),
                Err(error) if error.is_cancelled() => {}
                Err(error) => failures.push(format!("session task: {error}")),
            }
        }
        failures
    })
    .await;
    let server_closed = timeout(Duration::from_secs(15), server.close()).await;
    let client_closed = timeout(Duration::from_secs(15), client.close()).await;
    assert!(
        matches!(&drained, Ok(failures) if failures.is_empty()),
        "session cleanup failed: {drained:?}"
    );
    assert!(server_closed.is_ok(), "server close deadline");
    assert!(client_closed.is_ok(), "client close deadline");
    UdpSocket::bind(server_address).await.unwrap();
    assert!(
        matches!(outcome, Ok(Ok(Ok(())))),
        "production join scenario failed: {outcome:?}"
    );
}
