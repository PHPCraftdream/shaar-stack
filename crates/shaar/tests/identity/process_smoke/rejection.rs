use super::*;

pub(super) async fn rejection_scenario(
    temp: &Temp,
    processes: &mut Processes,
    wrong_pin: bool,
) -> Result<(), String> {
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| error.to_string())?;
    let target_addr = target.local_addr().map_err(|error| error.to_string())?;
    let server = Identity::from_seed([0x31; 32]);
    let client = Identity::from_seed([0x72; 32]);
    let server_key = hex(&server.public_key_bytes());
    let client_key = hex(&client.public_key_bytes());
    let pinned_key = if wrong_pin {
        hex(&Identity::from_seed([0x44; 32]).public_key_bytes())
    } else {
        server_key.clone()
    };
    key_file(&temp.0.join("server.key"), [0x31; 32]).map_err(|error| error.to_string())?;
    key_file(&temp.0.join("client.key"), [0x72; 32]).map_err(|error| error.to_string())?;
    let allowlist = if wrong_pin {
        format!("{client_key}\n")
    } else {
        String::new()
    };
    fs::write(temp.0.join("allowed.txt"), allowlist).map_err(|error| error.to_string())?;
    let server_config = temp.0.join("server.ktav");
    let client_config = temp.0.join("client.ktav");
    fs::write(&server_config, format!("target: {target_addr}\nbind: 127.0.0.1:0\nkey_file:: server.key\nallowlist_path:: allowed.txt\nfallback: signal\n")).map_err(|error| error.to_string())?;
    let server_exe = std::env::var("SHAAR_SERVER_EXE").map_err(|error| error.to_string())?;
    let client_exe = std::env::var("SHAAR_CLIENT_EXE").map_err(|error| error.to_string())?;
    let server_index = processes.spawn(&server_exe, &server_config, &temp.0)?;
    let line = ready_line(&mut processes.0[server_index].stdout).await?;
    let fields: Vec<_> = line.split_whitespace().collect();
    if fields.len() != 2
        || !fields[0].starts_with("bound=")
        || fields[1] != format!("public_key={server_key}")
    {
        return Err("invalid server readiness output".into());
    }
    let bound: SocketAddr = fields[0]
        .trim_start_matches("bound=")
        .parse()
        .map_err(|error: std::net::AddrParseError| error.to_string())?;
    if !bound.ip().is_loopback() || bound.port() == 0 {
        return Err("unexpected server bind address".into());
    }
    let direct_address = SocketAddr::from(([127, 0, 0, 1], bound.port()));
    fs::write(&client_config, format!("server: {pinned_key}\nserver_address: {direct_address}\nlisten: 127.0.0.1:0\nkey_file:: client.key\nfallback: signal\n")).map_err(|error| error.to_string())?;
    let client_index = processes.spawn(&client_exe, &client_config, &temp.0)?;
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
    let mut byte = [0; 1];
    tokio::select! {
        biased;
        accepted = target.accept() => match accepted {
            Ok(_) => return Err("rejected peer reached target".into()),
            Err(error) => return Err(error.to_string()),
        },
        terminal = stream.read(&mut byte) => match terminal {
            Ok(0) => {},
            Ok(_) => return Err("rejected peer received application bytes".into()),
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {},
            Err(error) => return Err(format!("client terminal read failed: {error}")),
        },
    }
    for index in [server_index, client_index] {
        if processes.0[index]
            .child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Err("process exited before rejection was observed".into());
        }
    }
    processes.0[server_index]
        .child
        .start_kill()
        .map_err(|error| error.to_string())?;
    timeout(CLEANUP_TIMEOUT, processes.0[server_index].child.wait())
        .await
        .map_err(|_| "server reap deadline")?
        .map_err(|error| error.to_string())?;
    let target = target.into_std().map_err(|error| error.to_string())?;
    match target.accept() {
        Ok(_) => Err("rejected peer reached target before server exit".into()),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}
