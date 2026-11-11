//! Normal standby processes retain APP service without DHT replies or a Client relay.

#![forbid(unsafe_code)]

use super::*;

/// cancel-safe: NO — parent finalize retains, terminates and joins every child.
pub(super) async fn scenario(
    temp: &Temp,
    processes: &mut Processes,
    relay: &shaar_p2p::RelayAddr,
    transit: &str,
) -> Result<(), String> {
    let server_seed = [0xc1; 32];
    let client_seed = [0xc2; 32];
    let server_key = Identity::from_seed(server_seed).public_key_bytes();
    let client_key = Identity::from_seed(client_seed).public_key_bytes();
    let server_path = temp.0.join("outage-server.key");
    let client_path = temp.0.join("outage-client.key");
    key_file(&server_path, server_seed).map_err(|e| e.to_string())?;
    key_file(&client_path, client_seed).map_err(|e| e.to_string())?;
    let original_server = tokio::fs::read(&server_path)
        .await
        .map_err(|e| e.to_string())?;
    let original_client = tokio::fs::read(&client_path)
        .await
        .map_err(|e| e.to_string())?;
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    // These owned sockets NEVER send responses; there is no public bootstrap fallback.
    let server_bootstrap = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let client_bootstrap = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    // Hold the port without accepting or speaking libp2p, excluding accidental port reuse.
    let silent_relay = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let silent_relay_address = silent_relay.local_addr().map_err(|e| e.to_string())?;
    assert_ne!(silent_relay_address, relay.socket_addr());
    let client_relay = shaar_p2p::RelayAddr::new(relay.peer_id(), silent_relay_address)
        .map_err(|e| e.to_string())?;
    let reserved = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let front = reserved.local_addr().map_err(|e| e.to_string())?;
    drop(reserved);
    tokio::fs::write(
        temp.0.join("outage-allowed.txt"),
        format!("{}\n", hex(&client_key)),
    )
    .await
    .map_err(|e| e.to_string())?;
    let server_config = temp.0.join("outage-server.ktav");
    let client_config = temp.0.join("outage-client.ktav");
    let server_text = format!(
        "target: {}\nallowlist_path:: outage-allowed.txt\nkey_file:: outage-server.key\nfallback: standby\n{}",
        target.local_addr().map_err(|e| e.to_string())?,
        payload::network(
            server_bootstrap.local_addr().map_err(|e| e.to_string())?,
            relay,
            transit
        )
        .await?,
    );
    let client_text = format!(
        "server: {}\nlisten: {front}\nkey_file:: outage-client.key\nfallback: standby\n{}",
        hex(&server_key),
        payload::network(
            client_bootstrap.local_addr().map_err(|e| e.to_string())?,
            &client_relay,
            transit
        )
        .await?,
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
    observe_query(&server_bootstrap).await?;
    let client = processes.spawn(&client_exe, &client_config, &temp.0)?;
    observe_query(&client_bootstrap).await?;
    // No DHT reply means a service GET is not a valid readiness prerequisite.
    // Reuse bounded fresh APP transactions, not sleeps or readiness-flag polling.
    payload::recover(&target, front, processes, client).await?;
    require_occupied(TcpListener::bind(front).await)?;
    require_occupied(TcpListener::bind(silent_relay_address).await)?;
    for index in [client, server] {
        super::super::shutdown::signal_owned(processes, index).await?;
        payload::require_exit(processes, index).await?;
    }
    let released = TcpListener::bind(front).await.map_err(|e| e.to_string())?;
    drop(released);
    if tokio::fs::read(&server_path)
        .await
        .map_err(|e| e.to_string())?
        != original_server
        || tokio::fs::read(&client_path)
            .await
            .map_err(|e| e.to_string())?
            != original_client
    {
        return Err("standby outage changed provisioned identity bytes".to_owned());
    }
    eprintln!(
        "composed standby outage: exact APP and child shutdown passed; UDP blockade not claimed"
    );
    Ok(())
}

/// cancel-safe: NO — a consumed query is not replayed; cancellation is terminal.
async fn observe_query(socket: &UdpSocket) -> Result<(), String> {
    let mut packet = [0; 2048];
    let (length, source) = timeout(IO_TIMEOUT, socket.recv_from(&mut packet))
        .await
        .map_err(|_| "no actual child query reached the silent DHT bootstrap")?
        .map_err(|e| e.to_string())?;
    if !source.ip().is_loopback() || source.port() == 0 {
        return Err("silent bootstrap received a non-owned query".to_owned());
    }
    validate_query(&packet[..length])
}
