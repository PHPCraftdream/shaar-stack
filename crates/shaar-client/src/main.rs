#![forbid(unsafe_code)]

use std::{
    env, error::Error, fmt::Write as _, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration,
};

use shaar::{
    config::{
        ClientConfig, ClientEndpointOverrides, ClientOverrides, ConfigError, Fallback,
        MAX_CONFIG_BYTES, ValidationKind,
    },
    identity::{
        Identity,
        provision::{Role, default_data_dir, first_run_summary_lines, provision},
    },
    network::{
        Allowlist, Endpoint, ForwardError, ForwardStats, Limits, NetworkError, Session, observe,
    },
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

/// Startup selection: explicit config file, zero-config auto mode, or the
/// guided first run with positional server key/address.
#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    Config(PathBuf),
    Auto,
    FirstRun {
        server: Option<String>,
        server_address: Option<String>,
    },
}

fn parse_invocation(args: impl IntoIterator<Item = String>) -> Result<Invocation, &'static str> {
    let mut args = args.into_iter();
    let _ = args.next();
    let positionals: Vec<String> = args.collect();
    match positionals.as_slice() {
        [] => Ok(Invocation::Auto),
        [flag, path] if flag == "--config" && !path.is_empty() => {
            Ok(Invocation::Config(path.into()))
        }
        [server] if !server.starts_with('-') => Ok(Invocation::FirstRun {
            server: Some(server.clone()),
            server_address: None,
        }),
        [server, address] if !server.starts_with('-') && !address.starts_with('-') => {
            Ok(Invocation::FirstRun {
                server: Some(server.clone()),
                server_address: Some(address.clone()),
            })
        }
        _ => Err("usage: shaar-client [--config PATH] | [server-key [server-address]]"),
    }
}

async fn read_config(
    path: &std::path::Path,
    over: &ClientOverrides,
    endpoint_over: &ClientEndpointOverrides,
) -> Result<ClientConfig, Box<dyn Error>> {
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
        over,
        endpoint_over,
    )?)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut hex, "{byte:02x}").expect("hex formatting cannot fail");
    }
    hex
}

fn peer_from_config(config: &ClientConfig) -> Result<String, std::fmt::Error> {
    Ok(hex_bytes(config.server_key_bytes()))
}

/// Operator banner: the client's own key as `public_key`, the pinned server
/// key separately as `server`.
fn composed_banner(identity: &Identity, server_hex: &str, fallback: &str, hint: &str) -> String {
    let own = hex_bytes(&identity.public_key_bytes());
    format!(
        "composed startup: public_key={own} server={server_hex} fallback={fallback} server_address={hint}"
    )
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

async fn handle_stream(
    session: Arc<Session>,
    stream: TcpStream,
) -> Result<ForwardStats, ForwardError> {
    session.forward(stream).await
}

fn worker_failure(
    result: Result<Result<ForwardStats, ForwardError>, tokio::task::JoinError>,
    cancelling: bool,
) -> Option<Box<dyn Error + Send + Sync>> {
    match result {
        Ok(outcome) => {
            observe::emit(observe::session_line(
                observe::Product::Client,
                observe::RoutePath::Native,
                observe::SessionOutcome::of_worker(&outcome),
            ));
            match outcome {
                Err(ForwardError::TaskFailure) => Some(Box::new(ForwardError::TaskFailure)),
                _ => None,
            }
        }
        Err(error) if !cancelling || !error.is_cancelled() => Some(Box::new(error)),
        Err(_) => None,
    }
}

async fn abort_workers(
    workers: &mut JoinSet<Result<ForwardStats, ForwardError>>,
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

/// cancel-safe: NO — dropping the binary future can abandon joined cleanup.
async fn run_from_config(config_path: PathBuf) -> Result<(), Box<dyn Error>> {
    let config = read_config(
        &config_path,
        &ClientOverrides::default(),
        &ClientEndpointOverrides::default(),
    )
    .await?;
    let identity = Identity::load(config.key_file().to_path_buf()).await?;
    run_configured(config, identity, None).await
}

/// Shared startup tail: composed or legacy direct-only. `announce` lines are
/// printed right after each readiness line; `None` keeps today's output.
async fn run_configured(
    config: ClientConfig,
    identity: Identity,
    announce: Option<&[String]>,
) -> Result<(), Box<dyn Error>> {
    let key_hex = peer_from_config(&config)?;
    // Composed startup: the shared role layer owns dialing and fallback; the
    // configured fallback is genuinely honored here, and server_address is
    // only an optional explicit direct-address hint.
    if config.network().is_some() {
        let fallback = match config.fallback() {
            Fallback::Standby => "standby",
            Fallback::Signal => "signal",
        };
        let hint = match config.server_address() {
            Some(address) => address.to_string(),
            None => "none".to_owned(),
        };
        eprintln!(
            "shaar-client: {}",
            composed_banner(&identity, &key_hex, fallback, &hint)
        );
        let limits = Limits::new(1).map_err(|_| "client session limit out of range")?;
        // Truthful signal errors: a failed console handler is reported, not
        // swallowed, after the role future returns.
        let signal_failure = std::sync::Arc::new(std::sync::Mutex::new(None::<std::io::Error>));
        let slot = std::sync::Arc::clone(&signal_failure);
        let mut role = shaar::startup::ClientRole::new(
            config.clone(),
            &identity,
            limits,
            shaar::startup::RoleOptions::default(),
        )
        .map_err(|error| -> Box<dyn Error> { format!("composed startup: {error}").into() })?;
        let mut shutdown = std::pin::pin!(async {
            if let Err(error) = shutdown_signal().await {
                *slot
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error);
            }
        });
        // Primary/secondary truthful contract: the start or run outcome is
        // primary, the joined close secondary. A start failure retains
        // pending rollback in `Starting`, so the production error caller
        // still drives `role.shutdown()` instead of dropping the role into
        // the runtime-exit drop path.
        let started = start_until_shutdown(role.start(), &mut shutdown).await;
        let mut primary: Option<shaar::startup::StartupError> = match started {
            Some(Ok(())) => {
                // Announce the bound listener while the run loop serves.
                let mut listening = std::pin::pin!(role.listening());
                let mut announced = false;
                let mut run = std::pin::pin!(role.run(&mut shutdown));
                loop {
                    tokio::select! {
                        result = &mut run => break result.err(),
                        address = &mut listening, if !announced => {
                            announced = true;
                            if let Some(address) = address {
                                println!("listening={address}");
                                print_announce(announce);
                            }
                        }
                    }
                }
            }
            Some(Err(error)) => Some(error),
            None => None,
        };
        let secondary = role.shutdown().await.err();
        let role_result: Result<(), String> = match (primary.take(), secondary) {
            (Some(error), Some(close)) => Err(format!("{error}; joined close failed: {close}")),
            (Some(error), None) | (None, Some(error)) => Err(error.to_string()),
            (None, None) => Ok(()),
        };
        let signal_error = signal_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        match (role_result, signal_error) {
            (Err(role_error), Some(signal_error)) => {
                return Err(format!(
                    "composed startup: {role_error}; console signal handler failed: {signal_error}"
                )
                .into());
            }
            (Err(role_error), None) => {
                return Err(format!("composed startup: {role_error}").into());
            }
            (Ok(()), Some(signal_error)) => {
                return Err(format!("console signal handler failed: {signal_error}").into());
            }
            (Ok(()), None) => return Ok(()),
        }
    }
    // Legacy direct-only path: no network settings configured.
    let address = config
        .server_address()
        .ok_or("server_address is required for direct-only operation without network settings")?;
    match config.fallback() {
        Fallback::Standby => eprintln!(
            "shaar-client: no composed network settings; running direct-only; configured fallback standby is not active"
        ),
        Fallback::Signal => eprintln!(
            "shaar-client: no composed network settings; running direct-only; configured fallback signal is not active"
        ),
    }
    let listener = TcpListener::bind(config.listen()).await?;
    let bind = if address.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let endpoint = Endpoint::bind(&identity, bind, Allowlist::default(), Limits::new(1)?).await?;
    println!("listening={}", listener.local_addr()?);
    print_announce(announce);
    coordinate(listener, endpoint, key_hex, address).await
}

/// Print the first-run guidance block, one line per stdout line, in order.
fn print_announce(announce: Option<&[String]>) {
    for line in announce.into_iter().flatten() {
        println!("{line}");
    }
}

/// Preserves today's `./client.ktav` behavior; a stat error is reported,
/// not silently treated as absent.
async fn legacy_config_present(path: &std::path::Path) -> Result<bool, std::io::Error> {
    tokio::fs::try_exists(path).await
}

async fn run_auto() -> Result<(), Box<dyn Error>> {
    match legacy_config_present(std::path::Path::new("client.ktav")).await {
        Ok(true) => run_from_config(PathBuf::from("client.ktav")).await,
        Ok(false) => run_first_run(None, None).await,
        Err(error) => Err(error.into()),
    }
}

/// First-run decision: ready to start, or a guided next step the operator
/// must take (a client cannot guess the server key or address).
enum FirstRunState {
    Ready {
        config: Box<ClientConfig>,
        identity: Box<Identity>,
        block: Vec<String>,
    },
    MissingKey {
        block: Vec<String>,
        error: String,
    },
    MissingAddress {
        block: Vec<String>,
        error: String,
    },
}

async fn first_run_state(
    base: &std::path::Path,
    server: Option<String>,
    server_address: Option<String>,
) -> Result<FirstRunState, String> {
    let provisioned = provision(
        Role::Client,
        base,
        server.as_deref(),
        server_address.as_deref(),
    )
    .await
    .map_err(|error| format!("first run: {error}"))?;
    let summary = first_run_summary_lines(Role::Client, &provisioned.report, &provisioned.identity);
    let config = read_config(
        &provisioned.report.paths.config,
        &ClientOverrides {
            server: server.clone(),
            ..Default::default()
        },
        &ClientEndpointOverrides {
            server_address: server_address.clone(),
        },
    )
    .await;
    let config = match config {
        Ok(config) => config,
        Err(error) => {
            if let Some(ConfigError::Validation {
                field: "server",
                kind: ValidationKind::MissingRequired,
            }) = error.downcast_ref::<ConfigError>()
            {
                let mut block = summary;
                block.push("no server key configured".to_owned());
                block.push(
                    "next step: run shaar-client <server-public-key> <server-address>".to_owned(),
                );
                return Ok(FirstRunState::MissingKey {
                    block,
                    error: error.to_string(),
                });
            }
            return Err(format!("configuration: {error}"));
        }
    };
    if config.network().is_none() && config.server_address().is_none() {
        let mut block = summary;
        block.push("no server address configured".to_owned());
        block.push(format!(
            "next step: run shaar-client {} <server-address>",
            hex_bytes(config.server_key_bytes())
        ));
        return Ok(FirstRunState::MissingAddress {
            block,
            error: "server_address is required for direct-only operation without network settings"
                .to_owned(),
        });
    }
    let mut block = summary;
    block.push(format!(
        "your public key for the server allowlist: public_key={}",
        hex_bytes(&provisioned.identity.public_key_bytes())
    ));
    block.push(format!(
        "pinned server: public_key={} address={}",
        hex_bytes(config.server_key_bytes()),
        config
            .server_address()
            .map(|address| address.to_string())
            .unwrap_or_else(|| "none".to_owned())
    ));
    block.push(
        "add your key as one line to the server allowlist file, then restart the server".to_owned(),
    );
    Ok(FirstRunState::Ready {
        config: Box::new(config),
        identity: Box::new(provisioned.identity),
        block,
    })
}

async fn run_first_run(
    server: Option<String>,
    server_address: Option<String>,
) -> Result<(), Box<dyn Error>> {
    let base = default_data_dir().map_err(|error| format!("first run: {error}"))?;
    match first_run_state(&base, server, server_address).await {
        Err(error) => Err(error.into()),
        Ok(FirstRunState::MissingKey { block, error })
        | Ok(FirstRunState::MissingAddress { block, error }) => {
            for line in block {
                println!("{line}");
            }
            Err(error.into())
        }
        Ok(FirstRunState::Ready {
            config,
            identity,
            block,
        }) => run_configured(*config, *identity, Some(block.as_slice())).await,
    }
}

async fn coordinate(
    listener: TcpListener,
    endpoint: Endpoint,
    key_hex: String,
    address: SocketAddr,
) -> Result<(), Box<dyn Error>> {
    coordinate_until(listener, endpoint, key_hex, address, shutdown_signal())
        .await
        .map_err(|error| error as Box<dyn Error>)
}

/// cancel-safe: NO — dropping a listener can discard a notification.
async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(windows)]
    {
        let mut ctrl_break = tokio::signal::windows::ctrl_break()?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            event = ctrl_break.recv() => event.ok_or_else(|| std::io::Error::other("ctrl-break listener closed")),
        }
    }
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        // Service managers stop daemons with SIGTERM.
        let mut terminate = signal(SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            event = terminate.recv() => event.ok_or_else(|| std::io::Error::other("SIGTERM listener closed")),
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        tokio::signal::ctrl_c().await
    }
}

async fn coordinate_until<F: std::future::Future<Output = Result<(), std::io::Error>>>(
    listener: TcpListener,
    endpoint: Endpoint,
    key_hex: String,
    address: SocketAddr,
    shutdown: F,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    coordinate_with_workers(
        listener,
        endpoint,
        key_hex,
        address,
        shutdown,
        JoinSet::new(),
    )
    .await
}

async fn coordinate_with_workers<F: std::future::Future<Output = Result<(), std::io::Error>>>(
    listener: TcpListener,
    endpoint: Endpoint,
    key_hex: String,
    address: SocketAddr,
    shutdown: F,
    mut workers: JoinSet<Result<ForwardStats, ForwardError>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut session: Option<Arc<Session>> = None;
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
                    let route_started = std::time::Instant::now();
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
                    observe::emit(observe::client_route(
                        observe::RoutePath::Native,
                        observe::ResolveObservation::cached(0, 1),
                        observe::elapsed_ms(route_started),
                    ));
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

/// cancel-safe: NO — a losing startup waiter is dropped; its owner must join cleanup.
async fn start_until_shutdown<T>(
    startup: impl std::future::Future<Output = T>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Option<T> {
    tokio::select! {
        biased;
        () = shutdown => None,
        result = startup => Some(result),
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let result = match parse_invocation(env::args()) {
        Ok(Invocation::Config(path)) => run_from_config(path).await,
        Ok(Invocation::Auto) => run_auto().await,
        Ok(Invocation::FirstRun {
            server,
            server_address,
        }) => run_first_run(server, server_address).await,
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
mod startup_tests;

#[cfg(test)]
mod task156_tests;

#[cfg(test)]
mod behavior_tests;

#[cfg(test)]
mod admission_tests;

#[cfg(test)]
mod operator_tests;

#[cfg(test)]
mod first_run_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_path_selection_and_rejection() {
        assert_eq!(parse_invocation(["client".into()]), Ok(Invocation::Auto));
        assert_eq!(
            parse_invocation(["client".into(), "--config".into(), "x.ktav".into()]),
            Ok(Invocation::Config(PathBuf::from("x.ktav")))
        );
        assert_eq!(
            parse_invocation(["client".into(), "abc".into()]),
            Ok(Invocation::FirstRun {
                server: Some("abc".to_owned()),
                server_address: None
            })
        );
        assert!(parse_invocation(["client".into(), "--config".into()]).is_err());
        assert!(parse_invocation(["client".into(), "-x".into()]).is_err());
        assert!(parse_invocation(["client".into(), "a".into(), "b".into(), "c".into()]).is_err());
        assert!(
            parse_invocation([
                "client".into(),
                "--config".into(),
                "x.ktav".into(),
                "extra".into()
            ])
            .is_err()
        );
    }
}
