//! Actual composed APP bytes before and after a Server-only process restart.

#![forbid(unsafe_code)]

use super::*;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, watch};

#[allow(dead_code)] // Shared unit-fixture controls are not all used by this integration case.
#[path = "../../../../src/native_discovery/runtime/tests/fixture/wire.rs"]
mod mainline_fixture;

/// cancel-safe: NO — the parent retains children and bounded actor tasks for finalize.
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

async fn mode(
    temp: &Temp,
    processes: &mut Processes,
    tasks: &mut JoinSet<Result<(), String>>,
    relay: &shaar_p2p::RelayAddr,
    transit: &str,
    fallback: &str,
) -> Result<(), String> {
    let server_key = Identity::from_seed([0xa1; 32]).public_key_bytes();
    let client_key = Identity::from_seed([0xa2; 32]).public_key_bytes();
    let server_path = temp.0.join("recovery-server.key");
    let client_path = temp.0.join("recovery-client.key");
    if fallback == "signal" {
        key_file(&server_path, [0xa1; 32]).map_err(|e| e.to_string())?;
        key_file(&client_path, [0xa2; 32]).map_err(|e| e.to_string())?;
    }
    let original_server = tokio::fs::read(&server_path)
        .await
        .map_err(|e| e.to_string())?;
    let original_client = tokio::fs::read(&client_path)
        .await
        .map_err(|e| e.to_string())?;
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let front = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let front_address = front.local_addr().map_err(|e| e.to_string())?;
    drop(front);
    let server_peer = mainline_fixture::LoopbackPeer::bind().await;
    let client_peer = mainline_fixture::LoopbackPeer::bind().await;
    let server_bootstrap = server_peer.address;
    let client_bootstrap = client_peer.address;
    let (record, records) = watch::channel::<Option<Arc<mainline_fixture::CapturedPut>>>(None);
    let (publications, mut observed) = mpsc::channel(8);
    let (get_seen, get_received) = oneshot::channel();
    // Two actors per mode, two modes total: at most four retained tasks.
    assert!(tasks.len() <= 2);
    let server_records = records.clone();
    let server_publications = publications.clone();
    tasks.spawn(async move {
        server_peer
            .serve_composed(server_records, server_publications, None)
            .await;
        Ok(())
    });
    tasks.spawn(async move {
        client_peer
            .serve_composed(records, publications, Some(get_seen))
            .await;
        Ok(())
    });
    tokio::fs::write(
        temp.0.join("recovery-allowed.txt"),
        format!("{}\n", hex(&client_key)),
    )
    .await
    .map_err(|e| e.to_string())?;
    let server_config = temp.0.join("recovery-server.ktav");
    let client_config = temp.0.join("recovery-client.ktav");
    let server_text = format!(
        "target: {}\nallowlist_path:: recovery-allowed.txt\nkey_file:: recovery-server.key\nfallback: {fallback}\n{}",
        target.local_addr().map_err(|e| e.to_string())?,
        network(server_bootstrap, relay, transit).await?,
    );
    let client_text = format!(
        "server: {}\nlisten: {front_address}\nkey_file:: recovery-client.key\nfallback: {fallback}\n{}",
        hex(&server_key),
        network(client_bootstrap, relay, transit).await?,
    );
    tokio::fs::write(&server_config, server_text)
        .await
        .map_err(|e| e.to_string())?;
    tokio::fs::write(&client_config, client_text)
        .await
        .map_err(|e| e.to_string())?;
    let server_exe = std::env::var("SHAAR_SERVER_EXE").map_err(|e| e.to_string())?;
    let client_exe = std::env::var("SHAAR_CLIENT_EXE").map_err(|e| e.to_string())?;
    let server = processes.spawn(&server_exe, &server_config, &temp.0)?;
    let first = publication(&mut observed, server_key).await?;
    let first_sequence = first.sequence;
    record.send(Some(first)).map_err(|e| e.to_string())?;
    let client = processes.spawn(&client_exe, &client_config, &temp.0)?;
    let client_pid = processes.0[client]
        .child
        .id()
        .ok_or("missing retained Client PID")?;
    timeout(IO_TIMEOUT, get_received)
        .await
        .map_err(|_| "no actual service-key GET")?
        .map_err(|_| "service-key GET actor ended")?;
    // NativeDialer resolves this service key only after run_parts binds its listener.
    require_occupied(TcpListener::bind(front_address).await)?;
    exchange(&target, front_address).await?;
    super::super::shutdown::signal_owned(processes, server).await?;
    require_exit(processes, server).await?;
    let restarted = processes.spawn(&server_exe, &server_config, &temp.0)?;
    let second = publication(&mut observed, server_key).await?;
    if second.sequence <= first_sequence {
        return Err("restarted Server did not publish a newer signed record".to_owned());
    }
    record.send(Some(second)).map_err(|e| e.to_string())?;
    if processes.0[client].child.id() != Some(client_pid)
        || processes.0[client]
            .child
            .try_wait()
            .map_err(|e| e.to_string())?
            .is_some()
    {
        return Err("Client was not retained across Server-only restart".to_owned());
    }
    exchange(&target, front_address).await?;
    for index in [client, restarted] {
        super::super::shutdown::signal_owned(processes, index).await?;
        require_exit(processes, index).await?;
    }
    TcpListener::bind(front_address)
        .await
        .map_err(|e| e.to_string())?;
    if tokio::fs::read(&server_path)
        .await
        .map_err(|e| e.to_string())?
        != original_server
        || tokio::fs::read(&client_path)
            .await
            .map_err(|e| e.to_string())?
            != original_client
    {
        return Err("composed APP/restart changed identity key bytes".to_owned());
    }
    eprintln!(
        "composed APP/restart completed: fallback={fallback} retained_client=true exact_exchanges=2"
    );
    Ok(())
}

async fn network(
    bootstrap: SocketAddr,
    relay: &shaar_p2p::RelayAddr,
    transit: &str,
) -> Result<String, String> {
    let signaling = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let address = signaling.local_addr().map_err(|e| e.to_string())?;
    Ok(format!(
        "network: {{\nmainline: {{\nbind: 127.0.0.1:0\nbootstrap: [\n{bootstrap}\n]\n}}\nsignaling: {{\nbind: {address}\nrelay: {}\nrelay_address: {}\n}}\nygg: {{\npeers: [\n{transit}\n]\n}}\n}}\n",
        relay.peer_id(),
        relay.socket_addr(),
    ))
}

/// cancel-safe: NO — a publication may be consumed before validation; timeout is terminal.
async fn publication(
    observed: &mut mpsc::Receiver<Arc<mainline_fixture::CapturedPut>>,
    expected: [u8; 32],
) -> Result<Arc<mainline_fixture::CapturedPut>, String> {
    timeout(IO_TIMEOUT, async {
        while let Some(item) = observed.recv().await {
            if item.key == expected {
                let packet = item.signed_packet();
                let info = iroh_dns::endpoint_info::EndpointInfo::from_pkarr_signed_packet(&packet)
                    .map_err(|e| e.to_string())?;
                if info.ip_addrs().next().is_none() {
                    return Err(
                        "actual signed Server publication has no native addresses".to_owned()
                    );
                }
                return Ok(item);
            }
        }
        Err("publication actor ended".to_owned())
    })
    .await
    .map_err(|_| "actual Server publication deadline".to_owned())?
}

async fn require_exit(processes: &mut Processes, index: usize) -> Result<(), String> {
    let status = timeout(IO_TIMEOUT, processes.0[index].child.wait())
        .await
        .map_err(|_| "composed APP process shutdown deadline")?
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("composed APP process did not exit successfully".to_owned());
    }
    Ok(())
}

/// cancel-safe: NO — partial stream I/O is terminal; owned streams close on cancellation.
async fn exchange(target: &TcpListener, front: SocketAddr) -> Result<(), String> {
    const REQUEST: &[u8] = b"composed request across restart";
    const REPLY: &[u8] = b"fixed-target composed reply";
    timeout(Duration::from_secs(40), async {
        let app = async {
            let mut stream = TcpStream::connect(front).await?;
            stream.write_all(REQUEST).await?;
            stream.shutdown().await?;
            let mut bytes = vec![0; REPLY.len()];
            stream.read_exact(&mut bytes).await?;
            if bytes != REPLY {
                return Err(std::io::Error::other("APP reply differs"));
            }
            let mut extra = [0; 1];
            if stream.read(&mut extra).await? != 0 {
                return Err(std::io::Error::other("extra APP reply bytes"));
            }
            Ok::<(), std::io::Error>(())
        };
        let service = async {
            let (mut stream, _) = target.accept().await?;
            let mut bytes = vec![0; REQUEST.len()];
            stream.read_exact(&mut bytes).await?;
            if bytes != REQUEST {
                return Err(std::io::Error::other("fixed target request differs"));
            }
            let mut extra = [0; 1];
            if stream.read(&mut extra).await? != 0 {
                return Err(std::io::Error::other("missing request half-close"));
            }
            stream.write_all(REPLY).await?;
            stream.shutdown().await?;
            Ok::<(), std::io::Error>(())
        };
        tokio::try_join!(app, service)
            .map(|_| ())
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "composed APP exchange deadline".to_owned())?
}
