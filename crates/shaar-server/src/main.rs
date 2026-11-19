#![forbid(unsafe_code)]

use std::{
    env,
    fmt::Write as _,
    path::{Path, PathBuf},
    process::ExitCode,
};

use iroh_base::PublicKey;
use shaar::{
    config::{ConfigError, Fallback, ServerOverrides, ValidationKind, load_server},
    identity::{
        Identity,
        provision::{Role, first_run_summary_lines, provision},
    },
    network::{Allowlist, Endpoint, ForwardError, Limits, ServeReport, observe},
};
use tokio::{sync::watch, task::JoinSet};

mod cli;

#[cfg(test)]
mod first_run_tests;

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

#[derive(Debug)]
enum Invocation {
    Config(PathBuf),
    FirstRun { target: Option<String> },
}

fn parse_invocation(
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<Invocation, String> {
    const USAGE: &str = "usage: shaar-server [--config <path.ktav> | <target>]";
    let mut args = args.into_iter();
    let _program = args.next();
    match (args.next(), args.next()) {
        (Some(flag), Some(path)) if flag == "--config" && args.next().is_none() => {
            Ok(Invocation::Config(path.into()))
        }
        (None, None) => Ok(Invocation::FirstRun { target: None }),
        (Some(arg), None) if !arg.to_string_lossy().starts_with('-') => {
            let text = arg.to_str().ok_or_else(|| USAGE.to_owned())?;
            Ok(Invocation::FirstRun {
                target: Some(text.to_owned()),
            })
        }
        _ => Err(USAGE.to_owned()),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<std::ffi::OsString> = env::args_os().collect();
    if cli::is_cli_invocation(&args) {
        return cli::main(args).await;
    }
    let invocation = match parse_invocation(args) {
        Ok(invocation) => invocation,
        Err(error) => {
            eprintln!("shaar-server: {error}");
            return ExitCode::FAILURE;
        }
    };
    let result = match invocation {
        Invocation::Config(path) => run_from_config(path, None).await,
        Invocation::FirstRun { target } => run_first_run(target).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("shaar-server: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run_from_config(config_path: PathBuf, target: Option<String>) -> Result<(), String> {
    let overrides = ServerOverrides {
        target,
        ..ServerOverrides::default()
    };
    let config = load_server(config_path, &overrides)
        .await
        .map_err(|error| format!("configuration: {error}"))?;
    let identity = shaar::identity::load_unlocked_default(config.key_file(), "Key password: ")
        .await
        .map_err(|error| shaar::identity::key_load_message(&error))?;
    let keys = test_support::read_allowlist(config.allowlist_path()).await?;
    run_configured(config, identity, keys, None).await
}

enum FirstRunState {
    Ready {
        config: Box<shaar::config::ServerConfig>,
        identity: Box<Identity>,
        keys: Vec<PublicKey>,
        block: Vec<String>,
    },
    MissingTarget {
        block: Vec<String>,
        error: String,
    },
}

async fn first_run_state(base: &Path, target: Option<String>) -> Result<FirstRunState, String> {
    let provisioned = provision(Role::Server, base, None, None)
        .await
        .map_err(|error| format!("first run: {error}"))?;
    let report = &provisioned.report;
    let identity = provisioned.identity;
    let overrides = ServerOverrides {
        target: target.clone(),
        ..ServerOverrides::default()
    };
    let config = match load_server(&report.paths.config, &overrides).await {
        Err(ConfigError::Validation {
            field: "target",
            kind: ValidationKind::MissingRequired,
        }) => {
            let mut block = first_run_summary_lines(Role::Server, report, &identity);
            block.push("no forward target configured".to_owned());
            block.push(format!(
                "next step: run shaar-server <target:port> or set target: in {}",
                report.paths.config.display()
            ));
            return Ok(FirstRunState::MissingTarget {
                block,
                error: ConfigError::Validation {
                    field: "target",
                    kind: ValidationKind::MissingRequired,
                }
                .to_string(),
            });
        }
        Err(other) => return Err(format!("configuration: {other}")),
        Ok(config) => config,
    };
    let keys = test_support::read_allowlist(config.allowlist_path()).await?;
    let mut block = first_run_summary_lines(Role::Server, report, &identity);
    block.push(
        "clients connect direct: give each client this public key and this machine's address with the bound port"
            .to_owned(),
    );
    block.push(if keys.is_empty() {
        format!(
            "allowlist {}: empty - append each client's public key as one line, then restart the server to admit it",
            config.allowlist_path().display()
        )
    } else {
        format!(
            "allowlist {}: {} client key(s) loaded; edits apply after a restart",
            config.allowlist_path().display(),
            keys.len()
        )
    });
    block.push(format!("forward target: {}", config.target()));
    Ok(FirstRunState::Ready {
        config: Box::new(config),
        identity: Box::new(identity),
        keys,
        block,
    })
}

async fn run_first_run(target: Option<String>) -> Result<(), String> {
    let base =
        shaar::identity::default_data_dir().map_err(|error| format!("first run: {error}"))?;
    run_first_run_in(base, target).await
}

/// The `run` subcommand: the same three starts as the legacy forms, in the chosen place.
async fn run_command(place: cli::Place, target: Option<String>) -> ExitCode {
    let result = match (place.config, place.dir) {
        (Some(path), _) => run_from_config(path, target).await,
        (None, Some(dir)) => run_first_run_in(dir, target).await,
        (None, None) => run_first_run(target).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("shaar-server: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run_first_run_in(base: PathBuf, target: Option<String>) -> Result<(), String> {
    match first_run_state(&base, target).await? {
        FirstRunState::MissingTarget { block, error } => {
            for line in &block {
                println!("{line}");
            }
            Err(error)
        }
        FirstRunState::Ready {
            config,
            identity,
            keys,
            block,
        } => run_configured(*config, *identity, keys, Some(&block)).await,
    }
}

async fn run_configured(
    config: shaar::config::ServerConfig,
    identity: Identity,
    keys: Vec<PublicKey>,
    announce: Option<&[String]>,
) -> Result<(), String> {
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
                    if let Some(announce) = announce {
                        for line in announce {
                            println!("{line}");
                        }
                    }
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
    if let Some(announce) = announce {
        for line in announce {
            println!("{line}");
        }
    }

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
                Ok(Ok(report)) => {
                    observe::emit(observe::session_line(
                        observe::Product::Server,
                        observe::RoutePath::Native,
                        observe::SessionOutcome::of_report(&report),
                    ));
                }
                Ok(Err(error)) => {
                    observe::emit(observe::session_line(
                        observe::Product::Server,
                        observe::RoutePath::Native,
                        observe::SessionOutcome::of_error(&error),
                    ));
                    if matches!(error, ForwardError::TaskFailure) {
                        break 'run Err("session forwarding task failed".into());
                    }
                }
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
                    Some(Ok(Ok(report))) => {
                        observe::emit(observe::session_line(
                            observe::Product::Server,
                            observe::RoutePath::Native,
                            observe::SessionOutcome::of_report(&report),
                        ));
                    }
                    Some(Ok(Err(error))) => {
                        observe::emit(observe::session_line(
                            observe::Product::Server,
                            observe::RoutePath::Native,
                            observe::SessionOutcome::of_error(&error),
                        ));
                        if matches!(error, ForwardError::TaskFailure) {
                            break 'run Err("session forwarding task failed".into());
                        }
                    }
                    Some(Err(error)) => break 'run Err(format!("session task failed: {error}")),
                    None => {},
                }
            }
            accepted = endpoint.next_session(), if sessions.len() < session_limit => {
                match accepted {
                    Ok(mut session) => {
                        observe::emit(observe::server_route(observe::RoutePath::Native));
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
            Ok(Ok(report)) => {
                observe::emit(observe::session_line(
                    observe::Product::Server,
                    observe::RoutePath::Native,
                    observe::SessionOutcome::of_report(&report),
                ));
            }
            Ok(Err(error)) => {
                observe::emit(observe::session_line(
                    observe::Product::Server,
                    observe::RoutePath::Native,
                    observe::SessionOutcome::of_error(&error),
                ));
            }
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
