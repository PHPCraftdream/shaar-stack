#![forbid(unsafe_code)]

use std::{
    env, error::Error, fmt::Write as _, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration,
};

use shaar::{
    config::{ClientConfig, ClientEndpointOverrides, ClientOverrides, Fallback, MAX_CONFIG_BYTES},
    identity::Identity,
    network::{Allowlist, Endpoint, ForwardError, Limits, NetworkError, Session},
};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::sleep,
};

const MAX_CLIENTS: usize = 16;
const MAX_ATTEMPTS: u32 = 3;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(12);
const BACKOFF: Duration = Duration::from_millis(250);

#[derive(Debug, PartialEq, Eq)]
struct Cli {
    config: PathBuf,
}

fn parse_cli(args: impl IntoIterator<Item = String>) -> Result<Cli, &'static str> {
    let mut args = args.into_iter();
    let _ = args.next();
    match (args.next(), args.next(), args.next()) {
        (None, None, None) => Ok(Cli {
            config: "client.ktav".into(),
        }),
        (Some(flag), Some(path), None) if flag == "--config" && !path.is_empty() => Ok(Cli {
            config: path.into(),
        }),
        _ => Err("usage: shaar-client [--config PATH]"),
    }
}

async fn read_config(path: &std::path::Path) -> Result<ClientConfig, Box<dyn Error>> {
    use tokio::io::AsyncReadExt;
    let file = tokio::fs::File::open(path).await?;
    let mut bytes = Vec::with_capacity(4096);
    file.take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err("configuration exceeds size limit".into());
    }
    Ok(ClientConfig::from_text_with_endpoint_overrides(
        std::str::from_utf8(&bytes)?,
        &ClientOverrides::default(),
        &ClientEndpointOverrides::default(),
    )?)
}

fn peer_from_config(config: &ClientConfig) -> Result<String, std::fmt::Error> {
    let mut hex = String::with_capacity(64);
    for byte in config.server_key_bytes() {
        write!(&mut hex, "{byte:02x}")?;
    }
    Ok(hex)
}

async fn dial(
    endpoint: &Endpoint,
    key_hex: &str,
    address: SocketAddr,
) -> Result<Session, NetworkError> {
    let mut retry = 0u32;
    loop {
        let attempt = async {
            let peer = key_hex.parse().map_err(|_| NetworkError::InvalidAddress)?;
            endpoint.connect(peer, address).await
        };
        match tokio::time::timeout(CONNECT_TIMEOUT, attempt).await {
            Ok(Ok(session)) => return Ok(session),
            Ok(Err(error @ NetworkError::AccessDenied))
            | Ok(Err(error @ NetworkError::PeerMismatch)) => return Err(error),
            Ok(Err(error)) if retry + 1 >= MAX_ATTEMPTS => return Err(error),
            Err(_) if retry + 1 >= MAX_ATTEMPTS => return Err(NetworkError::Deadline),
            _ => {
                retry += 1;
                sleep(BACKOFF * retry).await;
            }
        }
    }
}

async fn admission_live(session: &Session) -> bool {
    tokio::select! {
        biased;
        _ = session.closed() => false,
        _ = std::future::ready(()) => true,
    }
}

async fn handle_stream(session: Arc<Session>, stream: TcpStream) -> Result<(), ForwardError> {
    session.forward(stream).await.map(|_| ())
}

fn worker_failure(
    result: Result<Result<(), ForwardError>, tokio::task::JoinError>,
    cancelling: bool,
) -> Option<Box<dyn Error + Send + Sync>> {
    match result {
        Ok(Err(ForwardError::TaskFailure)) => Some(Box::new(ForwardError::TaskFailure)),
        Err(error) if !cancelling || !error.is_cancelled() => Some(Box::new(error)),
        Ok(Err(error)) => {
            eprintln!("shaar-client: stream ended: {error}");
            None
        }
        _ => None,
    }
}

async fn abort_workers(
    workers: &mut JoinSet<Result<(), ForwardError>>,
) -> Option<Box<dyn Error + Send + Sync>> {
    workers.abort_all();
    let mut failure = None;
    while let Some(result) = workers.join_next().await {
        if let Some(error) = worker_failure(result, true) {
            failure.get_or_insert(error);
        }
    }
    failure
}

async fn run(config_path: PathBuf) -> Result<(), Box<dyn Error>> {
    let config = read_config(&config_path).await?;
    let address = config
        .server_address()
        .ok_or("server_address is required for direct client")?;
    match config.fallback() {
        Fallback::Standby => {
            eprintln!("shaar-client: Standby/Ygg fallback is unavailable; using direct only")
        }
        Fallback::Signal => eprintln!("shaar-client: Signal carries no data; using direct only"),
    }
    let key_hex = peer_from_config(&config)?;
    let identity = Identity::load(config.key_file().to_path_buf()).await?;
    let listener = TcpListener::bind(config.listen()).await?;
    let bind = if address.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let endpoint = Endpoint::bind(&identity, bind, Allowlist::default(), Limits::new(1)?).await?;
    coordinate(listener, endpoint, key_hex, address).await
}

async fn coordinate(
    listener: TcpListener,
    endpoint: Endpoint,
    key_hex: String,
    address: SocketAddr,
) -> Result<(), Box<dyn Error>> {
    coordinate_until(
        listener,
        endpoint,
        key_hex,
        address,
        tokio::signal::ctrl_c(),
    )
    .await
    .map_err(|error| error as Box<dyn Error>)
}

async fn coordinate_until<F: std::future::Future<Output = Result<(), std::io::Error>>>(
    listener: TcpListener,
    endpoint: Endpoint,
    key_hex: String,
    address: SocketAddr,
    shutdown: F,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut session: Option<Arc<Session>> = None;
    let mut workers = JoinSet::new();
    let mut stopping = Box::pin(shutdown);
    let mut failure: Option<Box<dyn Error + Send + Sync>> = None;
    'coordinator: loop {
        let monitored = session.clone();
        tokio::select! {
            biased;
            signal = &mut stopping => { if let Err(error) = signal { failure = Some(Box::new(error)); } break; }
            _ = async { if let Some(active) = monitored { active.closed().await; } }, if session.is_some() => {
                session = None;
                if let Some(error) = abort_workers(&mut workers).await { failure = Some(error); break; }
            }
            result = workers.join_next(), if !workers.is_empty() => {
                if let Some(error) = result.and_then(|result| worker_failure(result, false)) { failure = Some(error); break; }
            }
            incoming = listener.accept(), if workers.len() < MAX_CLIENTS => {
                let (stream, _) = match incoming { Ok(value) => value, Err(error) => { failure = Some(Box::new(error)); break; } };
                // Admission liveness is checked before forwarding begins. If closure
                // raced with accept, retire this generation and dial for this socket.
                if let Some(active) = session.clone()
                    && !admission_live(&active).await
                {
                    session = None;
                    if let Some(error) = abort_workers(&mut workers).await {
                        failure = Some(error);
                        break 'coordinator;
                    }
                }
                if session.is_none() {
                    let connected = tokio::select! {
                        signal = &mut stopping => {
                            if let Err(error) = signal { failure = Some(Box::new(error)); }
                            break 'coordinator;
                        }
                        result = dial(&endpoint, &key_hex, address) => match result {
                            Ok(value) => Some(value),
                            Err(error) => { eprintln!("shaar-client: dial failed: {error}"); None }
                        }
                    };
                    let Some(connected) = connected else { continue; };
                    session = Some(Arc::new(connected));
                }
                workers.spawn(handle_stream(session.as_ref().expect("session established").clone(), stream));
            }
        }
    }
    if let Some(error) = abort_workers(&mut workers).await {
        failure.get_or_insert(error);
    }
    if let Some(session) = session.take() {
        drop(session);
    }
    drop(listener);
    endpoint.close().await;
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let result = match parse_cli(env::args()) {
        Ok(cli) => run(cli.config).await,
        Err(error) => Err(error.into()),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("shaar-client: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod task156_tests;

#[cfg(test)]
mod behavior_tests;

#[cfg(test)]
mod admission_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::oneshot,
    };

    #[test]
    fn cli_path_selection_and_rejection() {
        assert_eq!(
            parse_cli(["client".into()]).unwrap().config,
            PathBuf::from("client.ktav")
        );
        assert_eq!(
            parse_cli(["client".into(), "--config".into(), "x.ktav".into()])
                .unwrap()
                .config,
            PathBuf::from("x.ktav")
        );
        assert!(parse_cli(["client".into(), "--config".into()]).is_err());
        assert!(parse_cli(["client".into(), "x".into()]).is_err());
    }

    #[tokio::test]
    async fn coordinator_forwards_and_reconnects_after_session_loss() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let client_identity = Identity::from_seed([91; 32]);
            let server_identity = Identity::from_seed([92; 32]);
            let client = Endpoint::bind(
                &client_identity,
                "127.0.0.1:0".parse().unwrap(),
                Allowlist::default(),
                Limits::new(1).unwrap(),
            )
            .await
            .unwrap();
            let mut server = Endpoint::bind(
                &server_identity,
                "127.0.0.1:0".parse().unwrap(),
                Allowlist::new(&[client.id()]).unwrap(),
                Limits::new(1).unwrap(),
            )
            .await
            .unwrap();
            let server_address = server.local_addr();
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target_address = target.local_addr().unwrap();
            let (close_first, close_first_rx) = oneshot::channel::<()>();
            let (first_done, first_done_rx) = oneshot::channel::<()>();
            let (first_finished, first_finished_rx) = oneshot::channel::<()>();
            let target_task = tokio::spawn(async move {
                let mut tasks = JoinSet::new();
                let mut first_done = Some(first_done);
                for index in 0..2 {
                    let (mut stream, _) = target.accept().await.unwrap();
                    let done = if index == 0 { first_done.take() } else { None };
                    tasks.spawn(async move {
                        let mut bytes = Vec::new();
                        stream.read_to_end(&mut bytes).await.unwrap();
                        stream.write_all(&bytes).await.unwrap();
                        stream.shutdown().await.unwrap();
                        if let Some(done) = done {
                            let _ = done.send(());
                        }
                    });
                }
                while let Some(result) = tasks.join_next().await {
                    result.unwrap();
                }
            });
            let server_task = tokio::spawn(async move {
                let mut first = server.accept().await.unwrap();
                first
                    .serve(target_address, async {
                        let _ = close_first_rx.await;
                    })
                    .await
                    .unwrap();
                drop(first);
                let _ = first_finished.send(());
                let mut second = server.accept().await.unwrap();
                let result = second.serve(target_address, std::future::pending()).await;
                assert!(matches!(
                    result,
                    Err(shaar::network::ForwardError::PathUnavailable)
                ));
                drop(second);
                server
            });
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let local = listener.local_addr().unwrap();
            let (shutdown, shutdown_rx) = oneshot::channel::<()>();
            let coordinator = tokio::spawn(coordinate_until(
                listener,
                client,
                server_key(&server_identity),
                server_address,
                async move {
                    let _ = shutdown_rx.await;
                    Ok(())
                },
            ));
            let mut first_app = tcp_connect(local).await;
            first_app.write_all(b"first stream").await.unwrap();
            first_app.shutdown().await.unwrap();
            let mut first_response = Vec::new();
            first_app.read_to_end(&mut first_response).await.unwrap();
            assert_eq!(first_response, b"first stream");
            let _ = first_done_rx.await;
            let _ = close_first.send(());
            let _ = first_finished_rx.await;
            let mut next_app = tcp_connect(local).await;
            next_app
                .write_all(b"new stream after session loss")
                .await
                .unwrap();
            next_app.shutdown().await.unwrap();
            let mut next_response = Vec::new();
            next_app.read_to_end(&mut next_response).await.unwrap();
            assert_eq!(next_response, b"new stream after session loss");
            drop(first_app);
            drop(next_app);
            let _ = shutdown.send(());
            coordinator.await.unwrap().unwrap();
            target_task.await.unwrap();
            server_task.await.unwrap().close().await;
        })
        .await
        .expect("coordinator integration deadline");
    }

    #[tokio::test]
    async fn admission_gate_prefers_observed_session_closure_when_ready_together() {
        let client_identity = Identity::from_seed([101; 32]);
        let server_identity = Identity::from_seed([102; 32]);
        let client = Endpoint::bind(
            &client_identity,
            "127.0.0.1:0".parse().unwrap(),
            Allowlist::default(),
            Limits::new(1).unwrap(),
        )
        .await
        .unwrap();
        let mut server = Endpoint::bind(
            &server_identity,
            "127.0.0.1:0".parse().unwrap(),
            Allowlist::new(&[client.id()]).unwrap(),
            Limits::new(1).unwrap(),
        )
        .await
        .unwrap();
        let (connected, accepted) = tokio::try_join!(
            client.connect(server.id(), server.local_addr()),
            server.accept(),
        )
        .unwrap();

        accepted.close();
        // This await synchronizes on the SDK closure event; the subsequent gate
        // polls closed() and its ready admission branch together, without timing.
        assert!(matches!(connected.closed().await, NetworkError::Closed));
        assert!(!admission_live(&connected).await);

        connected.close();
        client.close().await;
        server.close().await;
    }

    fn server_key(identity: &Identity) -> String {
        let mut result = String::new();
        for byte in identity.public_key_bytes() {
            write!(&mut result, "{byte:02x}").unwrap();
        }
        result
    }
    async fn tcp_connect(address: SocketAddr) -> TcpStream {
        TcpStream::connect(address).await.unwrap()
    }
}
