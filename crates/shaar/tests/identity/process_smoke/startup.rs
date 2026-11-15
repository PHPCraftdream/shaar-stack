use std::process::ExitStatus;

use super::*;

pub(super) async fn startup_scenario(temp: &Temp, processes: &mut Processes) -> Result<(), String> {
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|error| error.to_string())?;
    let udp_address = udp.local_addr().map_err(|error| error.to_string())?;
    let tcp = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| error.to_string())?;
    let tcp_address = tcp.local_addr().map_err(|error| error.to_string())?;
    let server_exe = std::env::var("SHAAR_SERVER_EXE").map_err(|error| error.to_string())?;
    let client_exe = std::env::var("SHAAR_CLIENT_EXE").map_err(|error| error.to_string())?;
    let server_config = temp.0.join("invalid-server.ktav");
    fs::write(&server_config, format!("target: 127.0.0.1:0\nbind: {udp_address}\nkey_file:: missing.key\nallowlist_path:: missing.txt\nfallback: signal\n"))
        .map_err(|error| error.to_string())?;
    let server_error = failed_start(processes, &server_exe, &server_config, &temp.0).await?;
    if !server_error.contains("field `target`") {
        return Err("server did not report invalid target before bind".into());
    }

    let client_config = temp.0.join("invalid-client.ktav");
    fs::write(&client_config, format!("server: not-a-public-key\nserver_address: 127.0.0.1:1\nlisten: {tcp_address}\nkey_file:: missing.key\nfallback: signal\n"))
        .map_err(|error| error.to_string())?;
    let client_error = failed_start(processes, &client_exe, &client_config, &temp.0).await?;
    if !client_error.contains("field `server`") {
        return Err("client did not report invalid server key before bind".into());
    }

    key_file(&temp.0.join("client.key"), [0x72; 32]).map_err(|error| error.to_string())?;
    let server_key = hex(&Identity::from_seed([0x31; 32]).public_key_bytes());
    let busy_config = temp.0.join("busy-client.ktav");
    fs::write(&busy_config, format!("server: {server_key}\nserver_address: 127.0.0.1:1\nlisten: {tcp_address}\nkey_file:: client.key\nfallback: signal\n"))
        .map_err(|error| error.to_string())?;
    let busy_error = failed_start(processes, &client_exe, &busy_config, &temp.0).await?;
    if !["(os error 98)", "(os error 10048)", "(os error 10013)"]
        .iter()
        .any(|marker| busy_error.contains(marker))
    {
        return Err("busy client listener did not report an expected bind failure".into());
    }
    drop((tcp, udp));
    Ok(())
}

async fn failed_start(
    processes: &mut Processes,
    exe: &str,
    config: &Path,
    working_dir: &Path,
) -> Result<String, String> {
    let mut child = Command::new(exe)
        .arg("--config")
        .arg(config)
        .current_dir(working_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| error.to_string())?;
    let stdout = child.stdout.take().ok_or("piped stdout unavailable")?;
    let stderr = child.stderr.take().ok_or("piped stderr unavailable")?;
    let index = processes.0.len();
    processes.0.push(Process {
        child,
        stdout: BufReader::new(stdout),
    });
    timeout(IO_TIMEOUT, async {
        let mut stderr = BufReader::new(stderr).take(4097);
        let mut diagnostic = Vec::new();
        stderr
            .read_to_end(&mut diagnostic)
            .await
            .map_err(|error| error.to_string())?;
        if diagnostic.len() > 4096 {
            return Err("startup diagnostic exceeds limit".into());
        }
        let status = processes.0[index]
            .child
            .wait()
            .await
            .map_err(|error| error.to_string())?;
        let mut byte = [0; 1];
        let stdout_size = processes.0[index]
            .stdout
            .read(&mut byte)
            .await
            .map_err(|error| error.to_string())?;
        if status.success() || stdout_size != 0 {
            return Err("invalid startup succeeded or emitted readiness".into());
        }
        String::from_utf8(diagnostic).map_err(|error| error.to_string())
    })
    .await
    .map_err(|_| "startup failure deadline".to_owned())?
}

#[tokio::test]
#[ignore = "requires CI-built shaar-server and shaar-client executables"]
async fn real_first_run_bootstrap_without_arguments() {
    run_first_run().await.unwrap();
}

async fn run_first_run() -> Result<(), String> {
    let temp = Temp::new().map_err(|error| error.to_string())?;
    let mut processes = Processes::default();
    let mut tasks = JoinSet::new();
    let result = std::panic::AssertUnwindSafe(timeout(
        DEADLINE,
        first_run_scenario(&temp, &mut processes, &mut tasks),
    ))
    .catch_unwind()
    .await;
    finalize(&mut processes, &mut tasks, result).await
}

/// Spawns an executable with explicit arguments (possibly none) and pins the
/// per-user data root by setting APPDATA, HOME and XDG_DATA_HOME on the child.
async fn spawn_first_run(
    exe: &str,
    args: &[String],
    data_root: &Path,
    working_dir: &Path,
) -> Result<Child, String> {
    let mut command = Command::new(exe);
    command
        .args(args)
        .current_dir(working_dir)
        .env("APPDATA", data_root)
        .env("HOME", data_root)
        .env("XDG_DATA_HOME", data_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        command.creation_flags(CREATE_NEW_PROCESS_GROUP);
    }
    command.spawn().map_err(|error| error.to_string())
}

/// Runs a child that exits by itself: reads piped stdout to end, waits, and
/// returns the exit status with the collected stdout. The child is NOT tracked
/// by Processes; kill_on_drop plus wait keep it reaped here.
async fn run_to_exit(child: &mut Child) -> Result<(ExitStatus, String), String> {
    let stdout = child.stdout.take().ok_or("piped stdout unavailable")?;
    let mut bytes = Vec::new();
    stdout
        .take(65_537)
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| error.to_string())?;
    if bytes.len() > 65_536 {
        return Err("first-run stdout exceeds limit".into());
    }
    let status = child.wait().await.map_err(|error| error.to_string())?;
    let text = String::from_utf8(bytes).map_err(|error| error.to_string())?;
    Ok((status, text))
}

/// Reads one line with the same bounds as ready_line but tolerates a final
/// line without a trailing newline.
async fn next_line(reader: &mut (impl tokio::io::AsyncBufRead + Unpin)) -> Result<String, String> {
    let mut line = Vec::new();
    let size = timeout(IO_TIMEOUT, reader.take(1025).read_until(b'\n', &mut line))
        .await
        .map_err(|_| "operator block deadline")?
        .map_err(|error| error.to_string())?;
    if size == 0 || size > 1024 {
        return Err("operator block ended early".into());
    }
    String::from_utf8(line).map_err(|error| error.to_string())
}

/// Reads the operator block after the readiness line, up to `limit` lines or
/// until a line starting with `final_prefix` is seen.
async fn operator_block(
    reader: &mut (impl tokio::io::AsyncBufRead + Unpin),
    limit: usize,
    final_prefix: &str,
) -> Result<String, String> {
    let mut block = String::new();
    for _ in 0..limit {
        let line = next_line(reader).await?;
        let done = line.starts_with(final_prefix);
        block.push_str(&line);
        if done {
            return Ok(block);
        }
    }
    Err("operator block final line missing".into())
}

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn ensure_file(path: &Path) -> Result<(), String> {
    require(path.is_file(), &format!("missing file: {}", path.display()))
}

async fn first_run_scenario(
    temp: &Temp,
    processes: &mut Processes,
    tasks: &mut JoinSet<Result<(), String>>,
) -> Result<(), String> {
    let server_exe = std::env::var("SHAAR_SERVER_EXE").map_err(|error| error.to_string())?;
    let client_exe = std::env::var("SHAAR_CLIENT_EXE").map_err(|error| error.to_string())?;
    let data = temp.0.join("shaar");
    let server_dir = data.join("server");
    let client_dir = data.join("client");
    let server_ktav = server_dir.join("server.ktav");
    let server_key_file = server_dir.join("shaar.key");
    let allowed = server_dir.join("allowed.txt");
    let client_ktav = client_dir.join("client.ktav");
    let client_key_file = client_dir.join("shaar.key");

    // Step 1: bare shaar-server provisions the data dir, prints the summary,
    // refuses to guess the forward target, and exits with failure.
    let mut child = spawn_first_run(&server_exe, &[], &temp.0, &temp.0).await?;
    let (status, stdout) = timeout(IO_TIMEOUT, run_to_exit(&mut child))
        .await
        .map_err(|_| "bare server deadline")??;
    require(!status.success(), "bare shaar-server exited successfully")?;
    require(
        stdout.lines().any(|line| {
            line.starts_with("first run data directory:") && line.ends_with("(created)")
        }),
        "bare server output missing created data directory line",
    )?;
    require(
        stdout.lines().any(|line| line.starts_with("public_key=")),
        "bare server output missing public_key line",
    )?;
    require(
        stdout.contains("no forward target configured"),
        "bare server output missing no-target line",
    )?;
    require(
        stdout.contains("next step: run shaar-server <target:port> or set target: in "),
        "bare server output missing next-step line",
    )?;
    ensure_file(&server_ktav)?;
    ensure_file(&server_key_file)?;
    ensure_file(&allowed)?;

    // Step 2: bare shaar-client provisions client files but no allowlist.
    let mut child = spawn_first_run(&client_exe, &[], &temp.0, &temp.0).await?;
    let (status, stdout) = timeout(IO_TIMEOUT, run_to_exit(&mut child))
        .await
        .map_err(|_| "bare client deadline")??;
    require(!status.success(), "bare shaar-client exited successfully")?;
    require(
        stdout.contains("no server key configured"),
        "bare client output missing no-server-key line",
    )?;
    require(
        stdout.contains("next step: run shaar-client <server-public-key> <server-address>"),
        "bare client output missing next-step line",
    )?;
    require(
        stdout.lines().any(|line| line.starts_with("public_key=")),
        "bare client output missing public_key line",
    )?;
    ensure_file(&client_ktav)?;
    ensure_file(&client_key_file)?;
    require(
        !client_dir.join("allowed.txt").exists(),
        "bare client must not create an allowlist",
    )?;

    // Step 3: a second bare run reuses the provisioned files byte for byte.
    let ktav_before = fs::read(&server_ktav).map_err(|error| error.to_string())?;
    let mut child = spawn_first_run(&server_exe, &[], &temp.0, &temp.0).await?;
    let (status, stdout) = timeout(IO_TIMEOUT, run_to_exit(&mut child))
        .await
        .map_err(|_| "reuse server deadline")??;
    require(!status.success(), "reused shaar-server exited successfully")?;
    require(
        stdout.contains("next step: run shaar-server <target:port> or set target: in "),
        "reused server output missing next-step line",
    )?;
    require(
        stdout.contains("(reused)"),
        "reused server output missing (reused)",
    )?;
    require(
        stdout.contains("kept: "),
        "reused server output missing kept line",
    )?;
    let ktav_after = fs::read(&server_ktav).map_err(|error| error.to_string())?;
    require(
        ktav_before == ktav_after,
        "server.ktav rewritten by reuse run",
    )?;

    // Step 4: echo forward target and the provisioned client identity.
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| error.to_string())?;
    let target_port = target
        .local_addr()
        .map_err(|error| error.to_string())?
        .port();
    // One-shot echo target: read the exact request, answer the exact reply, close.
    tasks.spawn(async move {
        let (mut stream, _) = target.accept().await.map_err(|error| error.to_string())?;
        let mut payload = [0; REQUEST.len()];
        stream
            .read_exact(&mut payload)
            .await
            .map_err(|error| error.to_string())?;
        if payload != REQUEST {
            return Err("target received incorrect bytes".into());
        }
        stream
            .write_all(REPLY)
            .await
            .map_err(|error| error.to_string())?;
        stream.shutdown().await.map_err(|error| error.to_string())?;
        Ok(())
    });
    let client_identity = Identity::load(&client_key_file)
        .await
        .map_err(|error| error.to_string())?;
    let client_key = hex(&client_identity.public_key_bytes());
    let forward_target = format!("127.0.0.1:{target_port}");

    // Step 5: positional target run keeps serving; parse readiness, then the
    // operator block with the empty allowlist line.
    let mut child = spawn_first_run(
        &server_exe,
        std::slice::from_ref(&forward_target),
        &temp.0,
        &temp.0,
    )
    .await?;
    let stdout = child.stdout.take().ok_or("piped stdout unavailable")?;
    processes.0.push(Process {
        child,
        stdout: BufReader::new(stdout),
    });
    let mut server_index = processes.0.len() - 1;
    let line = ready_line(&mut processes.0[server_index].stdout).await?;
    let fields: Vec<_> = line.split_whitespace().collect();
    require(
        fields.len() == 2
            && fields[0].starts_with("bound=")
            && fields[1].starts_with("public_key="),
        "invalid server readiness output",
    )?;
    let bound: SocketAddr = fields[0]
        .trim_start_matches("bound=")
        .parse()
        .map_err(|error: std::net::AddrParseError| error.to_string())?;
    require(
        (bound.ip().is_loopback() || bound.ip().is_unspecified()) && bound.port() != 0,
        "unexpected server bind address",
    )?;
    let server_hex = fields[1].trim_start_matches("public_key=").to_owned();
    require(
        server_hex.len() == 64 && server_hex.chars().all(|c| c.is_ascii_hexdigit()),
        "server public key is not 64 hex characters",
    )?;
    let block =
        operator_block(&mut processes.0[server_index].stdout, 8, "forward target: ").await?;
    require(
        block.contains("(created)") || block.contains("(reused)"),
        "operator block missing data directory state",
    )?;
    require(
        block
            .contains("clients connect direct: give each client this public key and this machine's address with the bound port"),
        "operator block missing clients-connect-direct line",
    )?;
    require(
        block.contains(&format!(
            "allowlist {}: empty - append each client's public key as one line, then restart the server to admit it",
            allowed.display()
        )),
        "operator block missing empty allowlist line",
    )?;
    require(
        block.contains(&format!("forward target: {forward_target}")),
        "operator block missing forward target line",
    )?;

    // Step 6: append the client key, restart the server, and confirm the
    // allowlist is picked up only by the restart with the same identity.
    {
        use std::io::Write as _;
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&allowed)
            .map_err(|error| error.to_string())?;
        file.write_all(format!("{client_key}\n").as_bytes())
            .map_err(|error| error.to_string())?;
    }
    {
        let process = &mut processes.0[server_index];
        process
            .child
            .start_kill()
            .map_err(|error| error.to_string())?;
        timeout(CLEANUP_TIMEOUT, process.child.wait())
            .await
            .map_err(|_| "server restart kill deadline")?
            .map_err(|error| error.to_string())?;
    }
    let mut child = spawn_first_run(
        &server_exe,
        std::slice::from_ref(&forward_target),
        &temp.0,
        &temp.0,
    )
    .await?;
    let stdout = child.stdout.take().ok_or("piped stdout unavailable")?;
    processes.0.push(Process {
        child,
        stdout: BufReader::new(stdout),
    });
    server_index = processes.0.len() - 1;
    let line = ready_line(&mut processes.0[server_index].stdout).await?;
    let fields: Vec<_> = line.split_whitespace().collect();
    require(
        fields.len() == 2
            && fields[0].starts_with("bound=")
            && fields[1] == format!("public_key={server_hex}"),
        "restarted server did not reuse its identity",
    )?;
    let restarted_bound: SocketAddr = fields[0]
        .trim_start_matches("bound=")
        .parse()
        .map_err(|error: std::net::AddrParseError| error.to_string())?;
    require(
        (restarted_bound.ip().is_loopback() || restarted_bound.ip().is_unspecified())
            && restarted_bound.port() != 0,
        "unexpected restarted server bind address",
    )?;
    let block =
        operator_block(&mut processes.0[server_index].stdout, 8, "forward target: ").await?;
    require(
        block.contains(&format!(
            "allowlist {}: 1 client key(s) loaded; edits apply after a restart",
            allowed.display()
        )),
        "restarted server did not load the appended allowlist entry",
    )?;
    let server_address = format!("127.0.0.1:{}", restarted_bound.port());

    // Step 7: pair the client positionally, confirm its operator block, and
    // verify one exact echo exchange through the pair.
    let ktav_before = fs::read(&client_ktav).map_err(|error| error.to_string())?;
    let mut child = spawn_first_run(
        &client_exe,
        &[server_hex.clone(), server_address.clone()],
        &temp.0,
        &temp.0,
    )
    .await?;
    let stdout = child.stdout.take().ok_or("piped stdout unavailable")?;
    processes.0.push(Process {
        child,
        stdout: BufReader::new(stdout),
    });
    let client_index = processes.0.len() - 1;
    let line = ready_line(&mut processes.0[client_index].stdout).await?;
    let client_addr: SocketAddr = line
        .trim()
        .strip_prefix("listening=")
        .ok_or("invalid client readiness output")?
        .parse()
        .map_err(|error: std::net::AddrParseError| error.to_string())?;
    require(
        client_addr.ip().is_loopback() && client_addr.port() != 0,
        "unexpected client listen address",
    )?;
    let block = operator_block(
        &mut processes.0[client_index].stdout,
        8,
        "add your key as one line to the server allowlist file, then restart the server",
    )
    .await?;
    require(
        block.contains(&format!(
            "your public key for the server allowlist: public_key={client_key}"
        )),
        "client block missing own public key line",
    )?;
    require(
        block.contains(&format!(
            "pinned server: public_key={server_hex} address={server_address}"
        )),
        "client block missing pinned server line",
    )?;
    require(
        block.contains(
            "add your key as one line to the server allowlist file, then restart the server",
        ),
        "client block missing allowlist instruction line",
    )?;
    let ktav_after = fs::read(&client_ktav).map_err(|error| error.to_string())?;
    require(
        ktav_before == ktav_after,
        "client.ktav rewritten by positional run",
    )?;
    let mut stream = timeout(IO_TIMEOUT, TcpStream::connect(client_addr))
        .await
        .map_err(|_| "client connect deadline")?
        .map_err(|error| error.to_string())?;
    timeout(IO_TIMEOUT, async {
        stream.write_all(REQUEST).await?;
        let mut reply = [0; REPLY.len()];
        stream.read_exact(&mut reply).await?;
        if reply != REPLY {
            return Err(std::io::Error::other("reply bytes differ"));
        }
        let mut extra = [0; 1];
        if stream.read(&mut extra).await? != 0 {
            return Err(std::io::Error::other("unexpected bytes after exact reply"));
        }
        Ok::<(), std::io::Error>(())
    })
    .await
    .map_err(|_| "echo exchange deadline")?
    .map_err(|error| error.to_string())?;
    drop(stream);
    Ok(())
}
