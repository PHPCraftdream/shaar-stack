use super::*;

pub(super) async fn unavailable_scenario(
    temp: &Temp,
    processes: &mut Processes,
    tasks: &mut JoinSet<Result<(), String>>,
) -> Result<(), String> {
    let reservation = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| error.to_string())?;
    let target_addr = reservation
        .local_addr()
        .map_err(|error| error.to_string())?;
    let server = Identity::from_seed([0x31; 32]);
    let client = Identity::from_seed([0x72; 32]);
    let server_key = hex(&server.public_key_bytes());
    let client_key = hex(&client.public_key_bytes());
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
    let direct_address = SocketAddr::from(([127, 0, 0, 1], bound.port()));
    fs::write(&client_config, format!("server: {server_key}\nserver_address: {direct_address}\nlisten: 127.0.0.1:0\nkey_file:: client.key\nfallback: signal\n"))
        .map_err(|error| error.to_string())?;
    let mut client = Command::new(&client_exe)
        .arg("--config")
        .arg(&client_config)
        .current_dir(&temp.0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| error.to_string())?;
    let stdout = client.stdout.take().ok_or("piped stdout unavailable")?;
    let stderr = client.stderr.take().ok_or("piped stderr unavailable")?;
    let mut stderr = BufReader::new(stderr);
    let client_index = processes.0.len();
    processes.0.push(Process {
        child: client,
        stdout: BufReader::new(stdout),
    });
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
    drop(reservation);
    let mut failed = timeout(IO_TIMEOUT, TcpStream::connect(client_addr))
        .await
        .map_err(|_| "client connect deadline")?
        .map_err(|error| error.to_string())?;
    failed
        .write_all(REQUEST)
        .await
        .map_err(|error| error.to_string())?;
    let mut byte = [0; 1];
    match timeout(IO_TIMEOUT, failed.read(&mut byte))
        .await
        .map_err(|_| "unavailable target deadline")?
    {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        Ok(_) => return Err("unavailable target returned application bytes".into()),
        Err(error) => return Err(format!("unavailable target read failed: {error}")),
    }
    timeout(IO_TIMEOUT, async {
        for _ in 0..8 {
            if ready_line(&mut stderr).await?.trim()
                == "shaar-client: stream ended: target TCP connection failed"
            {
                return Ok::<(), String>(());
            }
        }
        Err("target failure diagnostic missing".into())
    })
    .await
    .map_err(|_| "target failure diagnostic deadline")??;
    for index in [server_index, client_index] {
        if processes.0[index]
            .child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Err("process exited after unavailable target".into());
        }
    }
    let target = TcpListener::bind(target_addr)
        .await
        .map_err(|error| error.to_string())?;
    tasks.spawn(async move {
        let (mut stream, _) = target.accept().await.map_err(|error| error.to_string())?;
        let mut request = [0; REQUEST.len()];
        stream
            .read_exact(&mut request)
            .await
            .map_err(|error| error.to_string())?;
        if request != REQUEST {
            return Err("recovered target received incorrect bytes".into());
        }
        stream
            .write_all(REPLY)
            .await
            .map_err(|error| error.to_string())?;
        stream.shutdown().await.map_err(|error| error.to_string())?;
        Ok(())
    });
    timeout(IO_TIMEOUT, async {
        let mut stream = TcpStream::connect(client_addr).await?;
        stream.write_all(REQUEST).await?;
        let mut reply = [0; REPLY.len()];
        stream.read_exact(&mut reply).await?;
        if reply != REPLY {
            return Err(std::io::Error::other("recovered reply bytes differ"));
        }
        let mut extra = [0; 1];
        if stream.read(&mut extra).await? != 0 {
            return Err(std::io::Error::other("unexpected recovered reply bytes"));
        }
        Ok(())
    })
    .await
    .map_err(|_| "recovered forwarding deadline")?
    .map_err(|error: std::io::Error| error.to_string())?;
    match tasks.join_next().await {
        Some(Ok(Ok(()))) => Ok(()),
        Some(Ok(Err(error))) => Err(error),
        Some(Err(error)) => Err(format!("target task: {error}")),
        None => Err("target task missing".into()),
    }
}
