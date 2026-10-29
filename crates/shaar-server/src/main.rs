#![forbid(unsafe_code)]

use std::{env, path::PathBuf, process::ExitCode};

use shaar::{
    config::{Fallback, ServerOverrides, load_server},
    identity::Identity,
    network::{Allowlist, Endpoint, ForwardError, Limits, ServeReport},
};
use tokio::{sync::watch, task::JoinSet};

mod test_support;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;

const MAX_SESSIONS: usize = 32;

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
    validate_fallback(config.fallback())?;
    let identity = Identity::load(config.key_file())
        .await
        .map_err(|_| "could not load configured identity key".to_owned())?;
    let keys = test_support::read_allowlist(config.allowlist_path()).await?;
    let allowlist =
        Allowlist::new(&keys).map_err(|_| "allowlist exceeds 256 entries".to_owned())?;
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
    #[cfg(not(windows))]
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

/// cancel-safe: NO — the caller must abort and join retained session tasks.
async fn server_loop_with_gate<F, G>(
    endpoint: &mut Endpoint,
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
            accepted = endpoint.accept(), if sessions.len() < session_limit => {
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

fn validate_fallback(fallback: Fallback) -> Result<(), String> {
    match fallback {
        Fallback::Standby => Err(
            "fallback `standby` is unavailable: this server supports direct transport only".into(),
        ),
        Fallback::Signal => Ok(()),
    }
}

fn config_path() -> Result<PathBuf, String> {
    let mut args = env::args_os();
    let _program = args.next();
    match (args.next(), args.next()) {
        (Some(flag), Some(path)) if flag == "--config" && args.next().is_none() => Ok(path.into()),
        _ => Err("usage: shaar-server --config <path.ktav>".into()),
    }
}
