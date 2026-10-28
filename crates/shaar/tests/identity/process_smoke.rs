#![forbid(unsafe_code)]

use std::{
    fs,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures::FutureExt;
use shaar::identity::Identity;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    process::{Child, ChildStdout, Command},
    task::JoinSet,
    time::timeout,
};

const DEADLINE: Duration = Duration::from_secs(45);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST: &[u8] = b"D1-unique-\0\xff\x17";
const REPLY: &[u8] = b"D1-reply-\xfe\0";

struct Temp(PathBuf);
impl Temp {
    fn new() -> std::io::Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!("shaar-d1-{}-{nonce}", std::process::id()));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Process {
    child: Child,
    stdout: BufReader<ChildStdout>,
}

#[derive(Default)]
struct Processes(Vec<Process>);
impl Processes {
    fn spawn(&mut self, exe: &str, config: &Path, working_dir: &Path) -> Result<usize, String> {
        let mut child = Command::new(exe)
            .arg("--config")
            .arg(config)
            .current_dir(working_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| error.to_string())?;
        let stdout = child.stdout.take().ok_or("piped stdout unavailable")?;
        self.0.push(Process {
            child,
            stdout: BufReader::new(stdout),
        });
        Ok(self.0.len() - 1)
    }

    async fn cleanup(&mut self) -> Result<(), String> {
        let mut errors = Vec::new();
        for process in &mut self.0 {
            match process.child.try_wait() {
                Ok(Some(_)) => continue,
                Ok(None) => {
                    if let Err(error) = process.child.start_kill() {
                        errors.push(format!("failed to terminate child: {error}"));
                    }
                }
                Err(error) => {
                    errors.push(format!("failed to inspect child: {error}"));
                    if let Err(error) = process.child.start_kill() {
                        errors.push(format!("failed to terminate child: {error}"));
                    }
                }
            }
            match timeout(CLEANUP_TIMEOUT, process.child.wait()).await {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => errors.push(format!("failed to reap child: {error}")),
                Err(_) => errors.push("child reap deadline".into()),
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

fn key_file(path: &Path, seed: [u8; 32]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(&seed)?;
        file.sync_all()?;
        assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
    }
    #[cfg(windows)]
    {
        use shaar_platform::winfile::{create_private_new, validate_owner_only};
        let mut file = create_private_new(path)?;
        file.write_all(&seed)?;
        file.sync_all()?;
        validate_owner_only(&file)?;
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn ready_line(reader: &mut (impl tokio::io::AsyncBufRead + Unpin)) -> Result<String, String> {
    let mut line = Vec::new();
    let size = timeout(DEADLINE, reader.take(1025).read_until(b'\n', &mut line))
        .await
        .map_err(|_| "process readiness deadline")?
        .map_err(|error| error.to_string())?;
    if size == 0 || size > 1024 || !line.ends_with(b"\n") {
        return Err("invalid readiness line".into());
    }
    String::from_utf8(line).map_err(|error| error.to_string())
}

#[tokio::test]
async fn readiness_line_requires_bounded_utf8_and_termination() {
    let mut valid = BufReader::new(&b"listening=127.0.0.1:7\nextra"[..]);
    assert_eq!(
        ready_line(&mut valid).await.unwrap(),
        "listening=127.0.0.1:7\n"
    );
    let mut remaining = Vec::new();
    valid.read_to_end(&mut remaining).await.unwrap();
    assert_eq!(remaining, b"extra");
    let mut over_limit = vec![b'x'; 1024];
    over_limit.push(b'\n');
    for bytes in [
        vec![],
        b"unterminated".to_vec(),
        over_limit,
        vec![0xff, b'\n'],
    ] {
        assert!(
            ready_line(&mut BufReader::new(bytes.as_slice()))
                .await
                .is_err()
        );
    }
    let mut maximum = vec![b'x'; 1023];
    maximum.push(b'\n');
    assert_eq!(
        ready_line(&mut BufReader::new(maximum.as_slice()))
            .await
            .unwrap()
            .len(),
        1024
    );
}

#[test]
#[ignore = "child fixture launched by cleanup regression"]
fn child_cleanup_fixture() {
    println!("CHILD_CLEANUP_READY");
    loop {
        std::thread::park();
    }
}

#[tokio::test]
async fn cleanup_reaps_a_running_child() {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "process_smoke::child_cleanup_fixture",
            "--nocapture",
        ])
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let stdout = BufReader::new(child.stdout.take().unwrap());
    let mut processes = Processes(vec![Process { child, stdout }]);
    let observed = timeout(IO_TIMEOUT, async {
        for _ in 0..8 {
            let line = ready_line(&mut processes.0[0].stdout).await?;
            if line.contains("CHILD_CLEANUP_READY") {
                return Ok::<(), String>(());
            }
        }
        Err("child readiness marker missing".into())
    })
    .await;
    let cleanup = processes.cleanup().await;
    assert!(
        observed.is_ok_and(|result| result.is_ok()),
        "child did not become ready"
    );
    cleanup.unwrap();
    assert!(processes.0[0].child.try_wait().unwrap().is_some());
}

#[tokio::test]
#[ignore = "requires CI-built shaar-server and shaar-client executables"]
async fn real_server_client_forward_exact_loopback_bytes() {
    run().await.unwrap();
}

async fn run() -> Result<(), String> {
    let temp = Temp::new().map_err(|error| error.to_string())?;
    let mut processes = Processes::default();
    let mut tasks = JoinSet::new();
    let result = std::panic::AssertUnwindSafe(timeout(
        DEADLINE,
        scenario(&temp, &mut processes, &mut tasks),
    ))
    .catch_unwind()
    .await;
    let mut errors = Vec::new();
    match result {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => errors.push(format!("smoke: {error}")),
        Ok(Err(_)) => errors.push("smoke deadline".into()),
        Err(_) => errors.push("smoke panicked".into()),
    }
    if let Err(error) = processes.cleanup().await {
        errors.push(format!("cleanup: {error}"));
    }
    tasks.abort_all();
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => errors.push(format!("target: {error}")),
            Err(error) if error.is_cancelled() => {}
            Err(error) => errors.push(format!("target task: {error}")),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

async fn scenario(
    temp: &Temp,
    processes: &mut Processes,
    tasks: &mut JoinSet<Result<(), String>>,
) -> Result<(), String> {
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| error.to_string())?;
    let target_addr = target.local_addr().map_err(|error| error.to_string())?;
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
    let server = Identity::from_seed([0x31; 32]);
    let client = Identity::from_seed([0x72; 32]);
    let server_key = hex(&server.public_key_bytes());
    let client_key = hex(&client.public_key_bytes());
    let server_config = temp.0.join("server.ktav");
    let client_config = temp.0.join("client.ktav");
    key_file(&temp.0.join("server.key"), [0x31; 32]).map_err(|error| error.to_string())?;
    key_file(&temp.0.join("client.key"), [0x72; 32]).map_err(|error| error.to_string())?;
    fs::write(temp.0.join("allowed.txt"), format!("{client_key}\n"))
        .map_err(|error| error.to_string())?;
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
    fs::write(&client_config, format!("server: {server_key}\nserver_address: {direct_address}\nlisten: 127.0.0.1:0\nkey_file:: client.key\nfallback: signal\n")).map_err(|error| error.to_string())?;
    let client_index = processes.spawn(&client_exe, &client_config, &temp.0)?;
    let client_line = ready_line(&mut processes.0[client_index].stdout).await?;
    let client_addr: SocketAddr = client_line
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
        Ok(())
    })
    .await
    .map_err(|_| "forwarding deadline")?
    .map_err(|error: std::io::Error| error.to_string())?;
    match tasks.join_next().await {
        Some(Ok(Ok(()))) => Ok(()),
        Some(Ok(Err(error))) => Err(error),
        Some(Err(error)) => Err(format!("target task: {error}")),
        None => Err("target task missing".into()),
    }
}
