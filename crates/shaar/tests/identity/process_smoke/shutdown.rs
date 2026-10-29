use super::*;

/// cancel-safe: NO — the caller must reap processes and join tasks after cancellation.
pub(super) async fn shutdown_scenario(
    temp: &Temp,
    processes: &mut Processes,
    tasks: &mut JoinSet<Result<(), String>>,
) -> Result<(), String> {
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| error.to_string())?;
    let target_addr = target.local_addr().map_err(|error| error.to_string())?;
    let (observed_tx, observed_rx) = tokio::sync::oneshot::channel();
    let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
    tasks.spawn(async move {
        let (mut stream, _) = target.accept().await.map_err(|error| error.to_string())?;
        let mut request = [0; REQUEST.len()];
        stream
            .read_exact(&mut request)
            .await
            .map_err(|error| error.to_string())?;
        if request != REQUEST {
            return Err("target received incorrect bytes".into());
        }
        observed_tx.send(()).map_err(|_| "target observer closed")?;
        let mut byte = [0; 1];
        match stream.read(&mut byte).await {
            Ok(0) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            Ok(_) => return Err("unexpected bytes during shutdown".into()),
            Err(error) => return Err(error.to_string()),
        }
        closed_tx
            .send(())
            .map_err(|_| "target closure observer closed")?;
        let (mut restarted, _) = target.accept().await.map_err(|error| error.to_string())?;
        let mut request = [0; REQUEST.len()];
        restarted
            .read_exact(&mut request)
            .await
            .map_err(|error| error.to_string())?;
        if request != REQUEST {
            return Err("target received incorrect post-restart bytes".into());
        }
        restarted
            .write_all(REPLY)
            .await
            .map_err(|error| error.to_string())?;
        restarted
            .shutdown()
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    });
    let server_key = hex(&Identity::from_seed([0x31; 32]).public_key_bytes());
    let client_key = hex(&Identity::from_seed([0x72; 32]).public_key_bytes());
    key_file(&temp.0.join("server.key"), [0x31; 32]).map_err(|error| error.to_string())?;
    key_file(&temp.0.join("client.key"), [0x72; 32]).map_err(|error| error.to_string())?;
    fs::write(temp.0.join("allowed.txt"), format!("{client_key}\n"))
        .map_err(|error| error.to_string())?;
    let server_config = temp.0.join("server.ktav");
    let client_config = temp.0.join("client.ktav");
    fs::write(&server_config, format!("target: {target_addr}\nbind: 127.0.0.1:0\nkey_file:: server.key\nallowlist_path:: allowed.txt\nfallback: signal\n"))
        .map_err(|error| error.to_string())?;
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
    fs::write(&client_config, format!("server: {server_key}\nserver_address: {bound}\nlisten: 127.0.0.1:0\nkey_file:: client.key\nfallback: signal\n"))
        .map_err(|error| error.to_string())?;
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
    timeout(IO_TIMEOUT, observed_rx)
        .await
        .map_err(|_| "target observation deadline")?
        .map_err(|_| "target observation sender closed")?;
    signal_owned(processes, server_index).await?;
    let server_status = timeout(
        Duration::from_secs(20),
        processes.0[server_index].child.wait(),
    )
    .await
    .map_err(|_| "server shutdown deadline")?
    .map_err(|error| error.to_string())?;
    if !server_status.success() {
        return Err(format!("server shutdown failed: {server_status}"));
    }
    timeout(IO_TIMEOUT, closed_rx)
        .await
        .map_err(|_| "target closure deadline")?
        .map_err(|_| "target closure sender closed")?;
    let mut byte = [0; 1];
    match timeout(IO_TIMEOUT, stream.read(&mut byte))
        .await
        .map_err(|_| "old stream closure deadline")?
    {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        Ok(_) => return Err("old stream returned unexpected bytes".into()),
        Err(error) => return Err(format!("old stream closure failed: {error}")),
    }
    drop(stream);
    let rebound = tokio::net::UdpSocket::bind(bound)
        .await
        .map_err(|error| error.to_string())?;
    if rebound.local_addr().map_err(|error| error.to_string())? != bound {
        return Err("server UDP rebind address differs".into());
    }
    drop(rebound);
    fs::write(&server_config, format!("target: {target_addr}\nbind: {bound}\nkey_file:: server.key\nallowlist_path:: allowed.txt\nfallback: signal\n"))
        .map_err(|error| error.to_string())?;
    let restarted = processes.spawn(&server_exe, &server_config, &temp.0)?;
    let line = ready_line(&mut processes.0[restarted].stdout).await?;
    let expected = format!("bound={bound} public_key={server_key}");
    if line.trim() != expected {
        return Err("restarted server readiness differs".into());
    }
    let mut recovered = false;
    for attempt in 0..3 {
        let result = timeout(IO_TIMEOUT, async {
            let mut fresh = TcpStream::connect(client_addr).await?;
            fresh.write_all(REQUEST).await?;
            let mut reply = [0; REPLY.len()];
            fresh.read_exact(&mut reply).await?;
            if reply != REPLY {
                return Err(std::io::Error::other("post-restart reply differs"));
            }
            let mut extra = [0; 1];
            if fresh.read(&mut extra).await? != 0 {
                return Err(std::io::Error::other("unexpected post-restart reply bytes"));
            }
            Ok(())
        })
        .await;
        match result {
            Ok(Ok(())) => {
                recovered = true;
                break;
            }
            Ok(Err(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                ) => {}
            Ok(Err(error)) => return Err(format!("new stream failed: {error}")),
            Err(_) => return Err("new stream deadline".into()),
        }
        if attempt < 2 {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
    if !recovered {
        return Err("new streams did not recover after server restart".into());
    }
    match tasks.join_next().await {
        Some(Ok(Ok(()))) => {}
        Some(Ok(Err(error))) => return Err(error),
        Some(Err(error)) => return Err(format!("target task: {error}")),
        None => return Err("target task missing".into()),
    }
    signal_owned(processes, client_index).await?;
    let client_status = timeout(
        Duration::from_secs(20),
        processes.0[client_index].child.wait(),
    )
    .await
    .map_err(|_| "client shutdown deadline")?
    .map_err(|error| error.to_string())?;
    if !client_status.success() {
        return Err(format!("client shutdown failed: {client_status}"));
    }
    let rebound_client = TcpListener::bind(client_addr)
        .await
        .map_err(|error| error.to_string())?;
    if rebound_client
        .local_addr()
        .map_err(|error| error.to_string())?
        != client_addr
    {
        return Err("client TCP rebind address differs".into());
    }
    Ok(())
}

/// cancel-safe: NO — the caller must reap the tracked signal helper.
pub(super) async fn signal_owned(processes: &mut Processes, index: usize) -> Result<(), String> {
    if processes.0[index]
        .child
        .try_wait()
        .map_err(|error| error.to_string())?
        .is_some()
    {
        return Err("process exited before signal".into());
    }
    let pid = processes.0[index]
        .child
        .id()
        .ok_or("process PID unavailable")?;
    #[cfg(unix)]
    let mut signal_command = {
        let mut command = Command::new("/bin/kill");
        command.arg("-INT").arg(pid.to_string());
        command
    };
    #[cfg(windows)]
    let mut signal_command = {
        let mut command = Command::new("python");
        command.args([
            "-I",
            "-c",
            "import os, signal, sys; os.kill(int(sys.argv[1]), signal.CTRL_BREAK_EVENT)",
        ]);
        command.arg(pid.to_string());
        command
    };
    let mut signal = signal_command
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| error.to_string())?;
    let stdout = signal
        .stdout
        .take()
        .ok_or("piped signal stdout unavailable")?;
    let signal_index = processes.0.len();
    processes.0.push(Process {
        child: signal,
        stdout: BufReader::new(stdout),
    });
    let status = timeout(IO_TIMEOUT, processes.0[signal_index].child.wait())
        .await
        .map_err(|_| "signal command deadline")?
        .map_err(|error| error.to_string())?;
    if !status.success() {
        return Err("could not signal owned process".into());
    }
    Ok(())
}
