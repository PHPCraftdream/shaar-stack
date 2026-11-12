//! Composed operator contract: output, `bind` and allowlist validation, service stop signal.

#![forbid(unsafe_code)]

use super::*;

/// cancel-safe: NO — parent finalize retains and terminates every child.
pub(super) async fn scenario(
    temp: &Temp,
    processes: &mut Processes,
    relay: &shaar_p2p::RelayAddr,
    transit: &str,
) -> Result<(), String> {
    let server_exe = std::env::var("SHAAR_SERVER_EXE").map_err(|e| e.to_string())?;
    let client_exe = std::env::var("SHAAR_CLIENT_EXE").map_err(|e| e.to_string())?;
    let server_key = hex(&Identity::from_seed([0x9d; 32]).public_key_bytes());
    let client_key = hex(&Identity::from_seed([0x9e; 32]).public_key_bytes());
    key_file(&temp.0.join("op-server.key"), [0x9d; 32]).map_err(|e| e.to_string())?;
    key_file(&temp.0.join("op-client.key"), [0x9e; 32]).map_err(|e| e.to_string())?;
    let bootstrap = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let network = payload::network(
        bootstrap.local_addr().map_err(|e| e.to_string())?,
        relay,
        transit,
    )
    .await?;
    let server_head = format!(
        "target: {}\nallowlist_path:: op-allowed.txt\nkey_file:: op-server.key\nfallback: standby\n",
        target.local_addr().map_err(|e| e.to_string())?
    );
    let write = |name: &str, text: String| {
        std::fs::write(temp.0.join(name), text).map_err(|e| e.to_string())
    };
    write("op-allowed.txt", format!("{client_key}\n"))?;

    // Finding 2: an explicit top-level `bind` is rejected in the composed shape.
    write(
        "op-bind.ktav",
        format!("bind: 127.0.0.1:0\n{server_head}{network}"),
    )?;
    let log = temp.0.join("op-bind.log");
    let index = spawn_logged(processes, &server_exe, "op-bind.ktav", temp, &log)?;
    require_failure(processes, index, &log, &["`bind`", "NotApplicable"]).await?;

    // Finding 3: more than 16 distinct allowlisted keys fail before any network I/O.
    let many: String = (1..=17u8)
        .map(|seed| hex(&Identity::from_seed([seed; 32]).public_key_bytes()) + "\n")
        .collect();
    write("op-many.txt", many)?;
    write(
        "op-many.ktav",
        format!("{}{network}", server_head.replace("op-allowed", "op-many")),
    )?;
    let log = temp.0.join("op-many.log");
    let index = spawn_logged(processes, &server_exe, "op-many.ktav", temp, &log)?;
    require_failure(processes, index, &log, &["`allowlist_path`", "16"]).await?;

    // Findings 4 and 5 for the server: bound address line, then service stop.
    write("op-server.ktav", format!("{server_head}{network}"))?;
    let log = temp.0.join("op-server.log");
    let index = spawn_logged(processes, &server_exe, "op-server.ktav", temp, &log)?;
    let line = ready_line(&mut processes.0[index].stdout).await?;
    let fields: Vec<_> = line.split_whitespace().collect();
    let address: SocketAddr = match fields.as_slice() {
        [bound, key] if *key == format!("public_key={server_key}") => bound
            .strip_prefix("bound=")
            .and_then(|value| value.parse().ok())
            .ok_or("invalid composed server bound address")?,
        _ => return Err(format!("invalid composed server readiness line: {line:?}")),
    };
    if address.port() == 0 {
        return Err("composed server reported port 0".to_owned());
    }
    stop_and_require_success(
        processes,
        index,
        &log,
        &[&format!("public_key={server_key}")],
    )
    .await?;

    // Findings 1, 4 and 5 for the client.
    write(
        "op-client.ktav",
        format!(
            "server: {server_key}\nlisten: 127.0.0.1:0\nkey_file:: op-client.key\nfallback: standby\n{network}"
        ),
    )?;
    let log = temp.0.join("op-client.log");
    let index = spawn_logged(processes, &client_exe, "op-client.ktav", temp, &log)?;
    let line = ready_line(&mut processes.0[index].stdout).await?;
    let listening: SocketAddr = line
        .trim()
        .strip_prefix("listening=")
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| format!("invalid composed client readiness line: {line:?}"))?;
    if !listening.ip().is_loopback() || listening.port() == 0 {
        return Err("composed client reported an unusable listener".to_owned());
    }
    require_occupied(TcpListener::bind(listening).await)?;
    stop_and_require_success(
        processes,
        index,
        &log,
        &[&format!("public_key={client_key} server={server_key}")],
    )
    .await?;
    let stderr = std::fs::read_to_string(&log).map_err(|e| e.to_string())?;
    if stderr.contains(&format!("public_key={server_key}")) {
        return Err("client labels the pinned server key as its own".to_owned());
    }
    Ok(())
}

/// Spawns a child with stderr captured to `log`; the config is relative to `temp`.
fn spawn_logged(
    processes: &mut Processes,
    exe: &str,
    config: &str,
    temp: &Temp,
    log: &Path,
) -> Result<usize, String> {
    let stderr = std::fs::File::create(log).map_err(|e| e.to_string())?;
    let mut command = Command::new(exe);
    command
        .arg("--config")
        .arg(temp.0.join(config))
        .current_dir(&temp.0)
        .stdout(Stdio::piped())
        .stderr(Stdio::from(stderr))
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        command.creation_flags(CREATE_NEW_PROCESS_GROUP);
    }
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    let stdout = child.stdout.take().ok_or("piped stdout unavailable")?;
    processes.0.push(Process {
        child,
        stdout: BufReader::new(stdout),
    });
    Ok(processes.0.len() - 1)
}

fn require_text(log: &Path, needles: &[&str]) -> Result<(), String> {
    let text = std::fs::read_to_string(log).map_err(|e| e.to_string())?;
    match needles.iter().find(|needle| !text.contains(**needle)) {
        Some(missing) => Err(format!("child stderr lacks {missing:?}: {text}")),
        None => Ok(()),
    }
}

/// cancel-safe: NO — the caller finalizes the child.
async fn require_failure(
    processes: &mut Processes,
    index: usize,
    log: &Path,
    needles: &[&str],
) -> Result<(), String> {
    let status = timeout(IO_TIMEOUT, processes.0[index].child.wait())
        .await
        .map_err(|_| "startup rejection deadline")?
        .map_err(|e| e.to_string())?;
    if status.success() {
        return Err("invalid composed configuration was accepted".to_owned());
    }
    require_text(log, needles)
}

/// cancel-safe: NO — the caller finalizes the child.
async fn stop_and_require_success(
    processes: &mut Processes,
    index: usize,
    log: &Path,
    needles: &[&str],
) -> Result<(), String> {
    super::super::shutdown::terminate_owned(processes, index).await?;
    payload::require_exit(processes, index).await?;
    require_text(log, needles)
}
