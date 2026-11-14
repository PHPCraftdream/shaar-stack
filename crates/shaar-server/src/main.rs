#![forbid(unsafe_code)]

use std::{env, fmt::Write as _, path::PathBuf, process::ExitCode};

use shaar::{
    config::{Fallback, ServerOverrides, load_server},
    identity::Identity,
    network::{Allowlist, Endpoint, ForwardError, Limits, ServeReport},
};
use tokio::{sync::watch, task::JoinSet};

#[cfg(test)]
mod startup_tests;
mod test_support;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

const MAX_SESSIONS: usize = 32;

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
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("shaar-server: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let path = config_path()?;
    let config = load_server(path, &ServerOverrides::default())
        .await
        .map_err(|error| format!("configuration: {error}"))?;
    let identity = Identity::load(config.key_file())
        .await
        .map_err(|_| "could not load configured identity key".to_owned())?;
    let keys = test_support::read_allowlist(config.allowlist_path()).await?;
    let allowlist =
        Allowlist::new(&keys).map_err(|_| "allowlist exceeds 256 entries".to_owned())?;
    // Composed startup: the shared role layer owns listeners, fallback and
    // relay negotiation; the configured fallback is genuinely honored here.
    if config.network().is_some() {
        test_support::check_composed_limit(&keys, shaar::startup::MAX_STARTUP_APP_PEERS)?;
        let fallback = match config.fallback() {
            Fallback::Standby => "standby",
            Fallback::Signal => "signal",
        };
        let mut key_hex = String::with_capacity(64);
        for byte in identity.public_key_bytes() {
            write!(&mut key_hex, "{byte:02x}").expect("hex formatting cannot fail");
        }
        eprintln!("shaar-server: composed startup: public_key={key_hex} fallback={fallback}");
        let limits =
            Limits::new(MAX_SESSIONS).map_err(|_| "session limit out of range".to_owned())?;
        // Truthful signal errors: a failed console handler is reported, not
        // swallowed, after the role future returns.
        let signal_failure = std::sync::Arc::new(std::sync::Mutex::new(None::<std::io::Error>));
        let slot = std::sync::Arc::clone(&signal_failure);
        let mut role = shaar::startup::ServerRole::new(
            config.clone(),
            &identity,
            allowlist,
            limits,
            shaar::startup::RoleOptions::default(),
        )
        .map_err(|error| format!("composed startup: {error}"))?;
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
                if let Some(address) = role.native_addr() {
                    println!("bound={address} public_key={key_hex}");
                }
                role.run(&mut shutdown).await.err()
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
                ));
            }
            (Err(role_error), None) => return Err(format!("composed startup: {role_error}")),
            (Ok(()), Some(signal_error)) => {
                return Err(format!("console signal handler failed: {signal_error}"));
            }
            (Ok(()), None) => return Ok(()),
        }
    }
    // Legacy direct-only path: no network settings configured.
    eprintln!(
        "shaar-server: warning: {}",
        direct_only_notice(config.fallback())
    );
    let bind = config.bind();
    if bind.ip().is_unspecified() {
        eprintln!(
            "shaar-server: warning: signal negotiation is unsupported; direct connections only"
        );
        eprintln!(
            "shaar-server: listening on wildcard bind {bind}; this is not a dialable destination"
        );
        eprintln!(
            "shaar-server: provide clients a reachable host address and port for this listener"
        );
    } else {
        eprintln!(
            "shaar-server: warning: signal negotiation is unsupported; direct connections only"
        );
    }
    let mut endpoint = Endpoint::bind(
        &identity,
        bind,
        allowlist,
        Limits::new(MAX_SESSIONS).unwrap(),
    )
    .await
    .map_err(|error| format!("endpoint bind failed: {error}"))?;
    println!(
        "bound={} public_key={}",
        endpoint.local_addr(),
        endpoint.id()
    );

    let target = config.target();
    let mut shutdown = Box::pin(shutdown_signal());
    let outcome = server_loop(&mut endpoint, target, MAX_SESSIONS, &mut shutdown).await;
    endpoint.close().await;
    outcome
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

async fn server_loop(
    endpoint: &mut Endpoint,
    target: std::net::SocketAddr,
    session_limit: usize,
    shutdown: &mut std::pin::Pin<Box<impl std::future::Future<Output = std::io::Result<()>>>>,
) -> Result<(), String> {
    server_loop_with_sessions(endpoint, target, session_limit, shutdown, JoinSet::new()).await
}

async fn server_loop_with_sessions(
    endpoint: &mut Endpoint,
    target: std::net::SocketAddr,
    session_limit: usize,
    shutdown: &mut std::pin::Pin<Box<impl std::future::Future<Output = std::io::Result<()>>>>,
    mut sessions: JoinSet<Result<ServeReport, ForwardError>>,
) -> Result<(), String> {
    server_loop_with_gate(
        endpoint,
        target,
        session_limit,
        shutdown,
        &mut sessions,
        || std::future::ready(()),
    )
    .await
}

trait SessionSource: Send {
    /// cancel-safe: NO — dropping an accept may reject the incoming attempt.
    fn next_session(
        &mut self,
    ) -> impl std::future::Future<
        Output = Result<shaar::network::Session, shaar::network::NetworkError>,
    > + Send;
}

impl SessionSource for Endpoint {
    fn next_session(
        &mut self,
    ) -> impl std::future::Future<
        Output = Result<shaar::network::Session, shaar::network::NetworkError>,
    > + Send {
        self.accept()
    }
}

/// cancel-safe: NO — the caller must abort and join retained session tasks.
async fn server_loop_with_gate<F, G>(
    endpoint: &mut impl SessionSource,
    target: std::net::SocketAddr,
    session_limit: usize,
    shutdown: &mut std::pin::Pin<Box<impl std::future::Future<Output = std::io::Result<()>>>>,
    sessions: &mut JoinSet<Result<ServeReport, ForwardError>>,
    after_serve: F,
) -> Result<(), String>
where
    F: Fn() -> G + Clone + Send + 'static,
    G: std::future::Future<Output = ()> + Send + 'static,
{
    let (stop_sender, stop_receiver) = watch::channel(false);
    let outcome = 'run: loop {
        while let Some(result) = sessions.try_join_next() {
            match result {
                Ok(Ok(_)) => {}
                Ok(Err(ForwardError::PathUnavailable)) => {}
                Ok(Err(ForwardError::TaskFailure)) => {
                    break 'run Err("session forwarding task failed".into());
                }
                Ok(Err(error)) => eprintln!("shaar-server: session ended: {error}"),
                Err(error) => break 'run Err(format!("session task failed: {error}")),
            }
        }
        tokio::select! {
            biased;
            signal = shutdown.as_mut() => match signal {
                Ok(()) => break 'run Ok(()),
                Err(error) => break 'run Err(format!("console signal handler failed: {error}")),
            },
            result = sessions.join_next(), if sessions.len() >= session_limit => {
                match result {
                    Some(Ok(Ok(_))) => {},
                    Some(Ok(Err(ForwardError::PathUnavailable))) => {},
                    Some(Ok(Err(ForwardError::TaskFailure))) => break 'run Err("session forwarding task failed".into()),
                    Some(Ok(Err(error))) => eprintln!("shaar-server: session ended: {error}"),
                    Some(Err(error)) => break 'run Err(format!("session task failed: {error}")),
                    None => {},
                }
            }
            accepted = endpoint.next_session(), if sessions.len() < session_limit => {
                match accepted {
                    Ok(mut session) => {
                        let mut stop = stop_receiver.clone();
                        let after_serve = after_serve.clone();
                        sessions.spawn(async move {
                            let result = session.serve(target, async move {
                                if *stop.borrow() { return; }
                                let _ = stop.changed().await;
                            }).await;
                            after_serve().await;
                            result
                        });
                    }
                    Err(shaar::network::NetworkError::Closed) => break 'run Err("SDK endpoint closed unexpectedly".into()),
                    Err(error) => eprintln!("shaar-server: rejected/failed session: {error}"),
                }
            }
        }
    };
    let _ = stop_sender.send(true);
    let drain_error = drain_sessions(sessions).await;
    match (outcome, drain_error) {
        (Err(error), _) => Err(error),
        (Ok(()), Some(error)) => Err(error),
        (outcome, None) => outcome,
    }
}

async fn drain_sessions(
    sessions: &mut JoinSet<Result<ServeReport, ForwardError>>,
) -> Option<String> {
    let mut drain_error = None;
    while let Some(result) = sessions.join_next().await {
        match result {
            Err(error) => {
                drain_error.get_or_insert_with(|| format!("session task failed: {error}"));
            }
            Ok(Err(ForwardError::TaskFailure)) => {
                drain_error.get_or_insert_with(|| "session forwarding task failed".to_owned());
            }
            Ok(Err(ForwardError::PathUnavailable)) | Ok(Ok(_)) => {}
            Ok(Err(error)) => eprintln!("shaar-server: session ended: {error}"),
        }
    }
    drain_error
}

/// Explicit direct-only notice: names the configured fallback as inactive
/// instead of rejecting it — no silent direct-only fallback.
fn direct_only_notice(fallback: Fallback) -> String {
    let fallback = match fallback {
        Fallback::Standby => "standby",
        Fallback::Signal => "signal",
    };
    format!(
        "no composed network settings; running direct-only; configured fallback {fallback} is not active"
    )
}

fn config_path() -> Result<PathBuf, String> {
    let mut args = env::args_os();
    let _program = args.next();
    match (args.next(), args.next()) {
        (Some(flag), Some(path)) if flag == "--config" && args.next().is_none() => Ok(path.into()),
        _ => Err("usage: shaar-server --config <path.ktav>".into()),
    }
}
