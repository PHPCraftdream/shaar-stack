//! Composed allowlist enforcement across real key-only Client/Server processes.

#![forbid(unsafe_code)]

use super::*;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, watch};

/// cancel-safe: NO — parent finalize retains, terminates and joins all children and actors.
pub(super) async fn scenario(
    temp: &Temp,
    processes: &mut Processes,
    tasks: &mut JoinSet<Result<(), String>>,
    relay: &shaar_p2p::RelayAddr,
    transit: &str,
) -> Result<(), String> {
    for fallback in ["signal", "standby"] {
        mode(temp, processes, tasks, relay, transit, fallback).await?;
    }
    Ok(())
}

/// cancel-safe: NO — terminal case cancellation runs the parent's owned cleanup.
async fn mode(
    temp: &Temp,
    processes: &mut Processes,
    tasks: &mut JoinSet<Result<(), String>>,
    relay: &shaar_p2p::RelayAddr,
    transit: &str,
    fallback: &str,
) -> Result<(), String> {
    let server_key = Identity::from_seed([0xb1; 32]).public_key_bytes();
    let allowed_key = Identity::from_seed([0xb2; 32]).public_key_bytes();
    let denied_key = Identity::from_seed([0xb3; 32]).public_key_bytes();
    assert_ne!(allowed_key, denied_key);
    if fallback == "signal" {
        for (name, seed) in [
            ("deny-server", 0xb1),
            ("deny-allowed", 0xb2),
            ("deny-rejected", 0xb3),
        ] {
            key_file(&temp.0.join(format!("{name}.key")), [seed; 32]).map_err(|e| e.to_string())?;
        }
    }
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let server_peer = mainline_fixture::LoopbackPeer::bind().await;
    let server_bootstrap = server_peer.address;
    let (record, records) = watch::channel::<Option<Arc<mainline_fixture::CapturedPut>>>(None);
    let (publications, mut observed) = mpsc::channel(8);
    // Three owned actors per mode, at most six for this whole case.
    assert!(tasks.len() <= 3);
    let server_records = records.clone();
    let server_publications = publications.clone();
    tasks.spawn(async move {
        server_peer
            .serve_composed(server_records, server_publications, None)
            .await;
        Ok(())
    });
    tokio::fs::write(
        temp.0.join("deny-allowed.txt"),
        format!("{}\n", hex(&allowed_key)),
    )
    .await
    .map_err(|e| e.to_string())?;
    let server_config = temp.0.join("deny-server.ktav");
    let text = format!(
        "target: {}\nallowlist_path:: deny-allowed.txt\nkey_file:: deny-server.key\nfallback: {fallback}\n{}",
        target.local_addr().map_err(|e| e.to_string())?,
        payload::network(server_bootstrap, relay, transit).await?,
    );
    tokio::fs::write(&server_config, text)
        .await
        .map_err(|e| e.to_string())?;
    let server_exe = std::env::var("SHAAR_SERVER_EXE").map_err(|e| e.to_string())?;
    let server = processes.spawn(&server_exe, &server_config, &temp.0)?;
    let item = payload::publication(&mut observed, server_key).await?;
    record.send(Some(item)).map_err(|e| e.to_string())?;

    // Positive control uses the SAME live Server, allowlist and fixed target.
    let (allowed, front) = start_client(
        "deny-allowed",
        server_key,
        fallback,
        temp,
        processes,
        tasks,
        relay,
        transit,
        records.clone(),
        publications.clone(),
    )
    .await?;
    payload::exchange(&target, front)
        .await
        .map_err(|e| format!("authorized control: {e}"))?;
    super::super::shutdown::signal_owned(processes, allowed).await?;
    payload::require_exit(processes, allowed).await?;
    eprintln!("composed denial mode={fallback} authorized_target_connections=1");

    // From before rejected Client startup until BOTH children exit, ANY new target accept fails.
    let reject = async {
        let (denied, front) = start_client(
            "deny-rejected",
            server_key,
            fallback,
            temp,
            processes,
            tasks,
            relay,
            transit,
            records,
            publications,
        )
        .await?;
        let mut stream = TcpStream::connect(front).await.map_err(|e| e.to_string())?;
        eprintln!("composed denial mode={fallback} rejected_local_tcp_connected=true");
        match stream.write_all(b"disallowed composed request").await {
            Ok(()) => {}
            Err(error) if terminal_io(&error) => {}
            Err(error) => return Err(format!("rejected stream write: {error}")),
        }
        let mut byte = [0; 1];
        match stream.read(&mut byte).await {
            Ok(0) => {}
            Err(error) if terminal_io(&error) => {}
            Ok(_) => return Err("disallowed Client received application data".to_owned()),
            Err(error) => return Err(format!("rejected stream read: {error}")),
        }
        let status = processes.0[denied]
            .child
            .wait()
            .await
            .map_err(|e| e.to_string())?;
        if status.code() != Some(1) {
            return Err(format!("expected Client CLI failure exit 1, got {status}"));
        }
        if processes.0[server]
            .child
            .try_wait()
            .map_err(|e| e.to_string())?
            .is_some()
        {
            return Err("Server exited before rejected Client terminal outcome".to_owned());
        }
        eprintln!("composed denial mode={fallback} rejected_client_terminal={status}");
        super::super::shutdown::signal_owned(processes, server).await?;
        payload::require_exit(processes, server).await?;
        Ok::<(), String>(())
    };
    timeout(Duration::from_secs(90), async {
        tokio::select! {
            biased;
            accepted = target.accept() => {
                match accepted {
                    Ok(_) => Err("disallowed composed Client reached fixed target".to_owned()),
                    Err(error) => Err(error.to_string()),
                }
            }
            result = reject => result,
        }
    })
    .await
    .map_err(|_| "rejection must reach a terminal result, not a timeout".to_owned())??;
    // Reap is complete; drain the kernel backlog so a simultaneous late accept cannot be hidden.
    let target = target.into_std().map_err(|e| e.to_string())?;
    match target.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(_) => {
            return Err("disallowed target accept queued after child exit".to_owned());
        }
        Err(error) => return Err(error.to_string()),
    }
    eprintln!("composed denial mode={fallback} rejected_target_connections=0 children_reaped=true");
    Ok(())
}

fn terminal_io(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
    )
}

/// cancel-safe: NO — child ownership transfers to Processes before waiting; parent cleanup is mandatory.
#[allow(clippy::too_many_arguments)] // Private fixture wiring, not an extensible production API.
async fn start_client(
    name: &str,
    server_key: [u8; 32],
    fallback: &str,
    temp: &Temp,
    processes: &mut Processes,
    tasks: &mut JoinSet<Result<(), String>>,
    relay: &shaar_p2p::RelayAddr,
    transit: &str,
    records: watch::Receiver<Option<Arc<mainline_fixture::CapturedPut>>>,
    publications: mpsc::Sender<Arc<mainline_fixture::CapturedPut>>,
) -> Result<(usize, SocketAddr), String> {
    let peer = mainline_fixture::LoopbackPeer::bind().await;
    let bootstrap = peer.address;
    let (seen, received) = oneshot::channel();
    assert!(tasks.len() < 6);
    tasks.spawn(async move {
        peer.serve_composed(records, publications, Some(seen)).await;
        Ok(())
    });
    let reserved = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let front = reserved.local_addr().map_err(|e| e.to_string())?;
    drop(reserved);
    let config = temp.0.join(format!("{name}.ktav"));
    let text = format!(
        "server: {}\nlisten: {front}\nkey_file:: {name}.key\nfallback: {fallback}\n{}",
        hex(&server_key),
        payload::network(bootstrap, relay, transit).await?,
    );
    tokio::fs::write(&config, text)
        .await
        .map_err(|e| e.to_string())?;
    let exe = std::env::var("SHAAR_CLIENT_EXE").map_err(|e| e.to_string())?;
    let index = processes.spawn(&exe, &config, &temp.0)?;
    timeout(IO_TIMEOUT, received)
        .await
        .map_err(|_| "no actual service-key GET from Client")?
        .map_err(|_| "Client service-key GET observer ended")?;
    require_occupied(TcpListener::bind(front).await)?;
    Ok((index, front))
}
