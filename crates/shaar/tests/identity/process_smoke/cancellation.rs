use super::*;

/// cancel-safe: NO — the caller must reap tracked processes after cancellation.
pub(super) async fn cancel_pending_dial(
    temp: &Temp,
    processes: &mut Processes,
) -> Result<(), String> {
    let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|error| error.to_string())?;
    let server_address = blackhole.local_addr().map_err(|error| error.to_string())?;
    let server_key = hex(&Identity::from_seed([0x31; 32]).public_key_bytes());
    key_file(&temp.0.join("client.key"), [0x72; 32]).map_err(|error| error.to_string())?;
    let config = temp.0.join("client.ktav");
    fs::write(&config, format!("server: {server_key}\nserver_address: {server_address}\nlisten: 127.0.0.1:0\nkey_file:: client.key\nfallback: signal\n"))
        .map_err(|error| error.to_string())?;
    let client_exe = std::env::var("SHAAR_CLIENT_EXE").map_err(|error| error.to_string())?;
    let client_index = processes.spawn(&client_exe, &config, &temp.0)?;
    let line = ready_line(&mut processes.0[client_index].stdout).await?;
    let client_addr: SocketAddr = line
        .trim()
        .strip_prefix("listening=")
        .ok_or("invalid client readiness output")?
        .parse()
        .map_err(|error: std::net::AddrParseError| error.to_string())?;
    if !client_addr.ip().is_loopback() || client_addr.port() == 0 {
        return Err("unexpected client bind address".into());
    }
    let mut stream = timeout(IO_TIMEOUT, TcpStream::connect(client_addr))
        .await
        .map_err(|_| "client connect deadline")?
        .map_err(|error| error.to_string())?;
    stream
        .write_all(REQUEST)
        .await
        .map_err(|error| error.to_string())?;
    let mut packet = [0; 2048];
    let (size, source) = timeout(IO_TIMEOUT, blackhole.recv_from(&mut packet))
        .await
        .map_err(|_| "native dial observation deadline")?
        .map_err(|error| error.to_string())?;
    if size == 0 || !source.ip().is_loopback() {
        return Err("invalid native dial observation".into());
    }
    shutdown::signal_owned(processes, client_index).await?;
    let status = timeout(
        Duration::from_secs(20),
        processes.0[client_index].child.wait(),
    )
    .await
    .map_err(|_| "client shutdown deadline")?
    .map_err(|error| error.to_string())?;
    if !status.success() {
        return Err(format!("client shutdown failed: {status}"));
    }
    let mut extra = [0; 1];
    match timeout(IO_TIMEOUT, stream.read(&mut extra))
        .await
        .map_err(|_| "application closure deadline")?
    {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        Ok(_) => return Err("unexpected application data after cancellation".into()),
        Err(error) => return Err(format!("application closure failed: {error}")),
    }
    drop(stream);
    let rebound = TcpListener::bind(client_addr)
        .await
        .map_err(|error| error.to_string())?;
    if rebound.local_addr().map_err(|error| error.to_string())? != client_addr {
        return Err("client TCP rebind address differs".into());
    }
    Ok(())
}
