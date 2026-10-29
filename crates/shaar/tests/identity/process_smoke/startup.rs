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
