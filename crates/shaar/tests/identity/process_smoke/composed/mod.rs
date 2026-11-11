//! Normal composed binaries: console stop and same-key restart under a silent DHT.

#![forbid(unsafe_code)]

use super::*;
use serde_bencode::value::Value;
use shaar_ygg::{YggConfig, YggError, YggTransport};
use tokio::net::UdpSocket;

mod denial;
#[allow(dead_code)] // Unit-fixture controls are not all used by the real-process cases.
#[path = "../../../../src/native_discovery/runtime/tests/fixture/wire.rs"]
mod mainline_fixture;
mod payload;
#[path = "../../../../src/network/signaling/relay_fixture.rs"]
mod relay_fixture;

#[derive(Clone, Copy)]
enum Role {
    Client,
    Server,
}

#[derive(Clone, Copy)]
enum Case {
    Lifecycle(Role),
    Payload,
    Denial,
}

#[tokio::test]
#[ignore = "requires CI-built shaar-server and shaar-client executables"]
async fn real_composed_client_console_stop_and_restart_in_signal_and_standby() {
    run(Case::Lifecycle(Role::Client)).await.unwrap();
}

#[tokio::test]
#[ignore = "requires CI-built shaar-server and shaar-client executables"]
async fn real_composed_server_console_stop_and_restart_in_signal_and_standby() {
    run(Case::Lifecycle(Role::Server)).await.unwrap();
}

#[tokio::test]
#[ignore = "requires CI-built shaar-server and shaar-client executables"]
async fn real_composed_key_only_payload_and_server_restart_in_signal_and_standby() {
    run(Case::Payload).await.unwrap();
}

#[tokio::test]
#[ignore = "requires CI-built shaar-server and shaar-client executables"]
async fn real_composed_denied_key_never_reaches_target_in_signal_and_standby() {
    run(Case::Denial).await.unwrap();
}

async fn run(case: Case) -> Result<(), String> {
    let temp = Temp::new().map_err(|error| error.to_string())?;
    let relay = timeout(IO_TIMEOUT, relay_fixture::RelayFixture::start())
        .await
        .map_err(|_| "owned relay startup deadline".to_owned())?;
    let (transit, uri) = match timeout(Duration::from_secs(30), start_transit()).await {
        Ok(Ok(value)) => value,
        result => {
            relay.close().await;
            return Err(format!(
                "owned transit startup failed: {}",
                match result {
                    Ok(Err(error)) => error,
                    _ => "deadline".to_owned(),
                }
            ));
        }
    };
    let mut processes = Processes::default();
    let mut tasks = JoinSet::new();
    let result = std::panic::AssertUnwindSafe(timeout(
        Duration::from_secs(if matches!(case, Case::Lifecycle(_)) {
            120
        } else {
            240
        }),
        async {
            match case {
                Case::Lifecycle(role) => {
                    scenario(role, &temp, &mut processes, &relay.address, &uri).await
                }
                Case::Denial => {
                    denial::scenario(&temp, &mut processes, &mut tasks, &relay.address, &uri).await
                }
                Case::Payload => {
                    payload::scenario(&temp, &mut processes, &mut tasks, &relay.address, &uri).await
                }
            }
        },
    ))
    .catch_unwind()
    .await;
    let process_result = finalize(&mut processes, &mut tasks, result).await;
    let transit_result = timeout(Duration::from_secs(30), transit.close()).await;
    // Control-byte diagnostics are not an application-route or zero-APP oracle.
    eprintln!(
        "composed fixture relay control bytes={}",
        relay.relayed_bytes()
    );
    timeout(Duration::from_secs(30), relay.close())
        .await
        .map_err(|_| "owned relay close deadline".to_owned())?;
    process_result?;
    transit_result
        .map_err(|_| "owned transit close deadline".to_owned())?
        .map_err(|error| error.to_string())?;
    Ok(())
}

/// cancel-safe: NO — a timed-out whole fixture cannot claim joined transport startup.
async fn start_transit() -> Result<(YggTransport, String), String> {
    for _ in 0..4 {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|error| error.to_string())?;
        let port = listener
            .local_addr()
            .map_err(|error| error.to_string())?
            .port();
        drop(listener);
        let uri = format!("tcp://127.0.0.1:{port}");
        let config = YggConfig {
            seed: [0x94; 32],
            listen: vec![uri.clone()],
            peers: Vec::new(),
            allowed_public_keys: Vec::new(),
            group_password: None,
        };
        match YggTransport::start(config).await {
            Ok(transport) => return Ok((transport, uri)),
            Err(YggError::Start { .. }) => tokio::time::sleep(Duration::from_millis(20)).await,
            Err(error) => return Err(error.to_string()),
        }
    }
    Err("owned transit could not bind a reserved loopback port".to_owned())
}

/// cancel-safe: NO — caller retains all Child handles and runs finalize on every exit.
async fn scenario(
    role: Role,
    temp: &Temp,
    processes: &mut Processes,
    relay: &shaar_p2p::RelayAddr,
    transit: &str,
) -> Result<(), String> {
    let seed = match role {
        Role::Client => [0x91; 32],
        Role::Server => [0x92; 32],
    };
    let key = temp.0.join("composed.key");
    key_file(&key, seed).map_err(|error| error.to_string())?;
    let original = tokio::fs::read(&key)
        .await
        .map_err(|error| error.to_string())?;
    let peer_key = hex(&Identity::from_seed([0x93; 32]).public_key_bytes());
    let allowlist = temp.0.join("allowlist.txt");
    tokio::fs::write(&allowlist, format!("{peer_key}\n"))
        .await
        .map_err(|error| error.to_string())?;
    let exe = std::env::var(match role {
        Role::Client => "SHAAR_CLIENT_EXE",
        Role::Server => "SHAAR_SERVER_EXE",
    })
    .map_err(|error| error.to_string())?;
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| error.to_string())?;
    for fallback in ["signal", "standby"] {
        let bootstrap = UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(|error| error.to_string())?;
        let signaling = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|error| error.to_string())?;
        let signaling_address = signaling.local_addr().map_err(|error| error.to_string())?;
        drop(signaling);
        let prefix = match role {
            Role::Client => format!("server: {peer_key}\nlisten: 127.0.0.1:0\n"),
            Role::Server => format!(
                "target: {}\nallowlist_path:: allowlist.txt\n",
                target.local_addr().unwrap()
            ),
        };
        let text = format!(
            "{prefix}key_file:: composed.key\nfallback: {fallback}\nnetwork: {{\n\
             mainline: {{\n    bind: 127.0.0.1:0\n    bootstrap: [\n        {}\n    ]\n}}\n\
             signaling: {{\n    bind: {signaling_address}\n    relay: {}\n    relay_address: {}\n}}\n\
             ygg: {{\n    peers: [\n        {transit}\n    ]\n}}\n}}\n",
            bootstrap.local_addr().unwrap(),
            relay.peer_id(),
            relay.socket_addr(),
        );
        let config = temp.0.join("composed.ktav");
        tokio::fs::write(&config, &text)
            .await
            .map_err(|error| error.to_string())?;
        for _ in 0..2 {
            drain_queries(&bootstrap)?;
            let index = processes.spawn(&exe, &config, &temp.0)?;
            let mut packet = [0_u8; 2048];
            let (length, source) = timeout(IO_TIMEOUT, bootstrap.recv_from(&mut packet))
                .await
                .map_err(|_| "no real child Mainline query before deadline".to_owned())?
                .map_err(|error| error.to_string())?;
            validate_query(&packet[..length])?;
            if !source.ip().is_loopback() || source.port() == 0 {
                return Err("child query source is not an owned loopback endpoint".to_owned());
            }
            if processes.0[index]
                .child
                .try_wait()
                .map_err(|error| error.to_string())?
                .is_some()
            {
                return Err("composed child exited before console stop".to_owned());
            }
            require_occupied(UdpSocket::bind(source).await)?;
            require_occupied(TcpListener::bind(signaling_address).await)?;
            super::shutdown::signal_owned(processes, index).await?;
            let status = timeout(IO_TIMEOUT, processes.0[index].child.wait())
                .await
                .map_err(|_| "composed console shutdown deadline".to_owned())?
                .map_err(|error| error.to_string())?;
            if !status.success() {
                return Err("composed console stop was not a normal successful exit".to_owned());
            }
            UdpSocket::bind(source)
                .await
                .map_err(|error| error.to_string())?;
            TcpListener::bind(signaling_address)
                .await
                .map_err(|error| error.to_string())?;
            if tokio::fs::read(&key)
                .await
                .map_err(|error| error.to_string())?
                != original
            {
                return Err("composed stop/restart changed the device key bytes".to_owned());
            }
        }
    }
    Ok(())
}

fn require_occupied<T>(result: std::io::Result<T>) -> Result<(), String> {
    match result {
        Err(error)
            if error.kind() == std::io::ErrorKind::AddrInUse
                || (cfg!(windows) && error.kind() == std::io::ErrorKind::PermissionDenied) =>
        {
            Ok(())
        }
        Err(error) => Err(format!("unexpected live-binding probe error: {error}")),
        Ok(_) => Err("composed child did not retain its observed live binding".to_owned()),
    }
}

fn drain_queries(socket: &UdpSocket) -> Result<(), String> {
    let mut packet = [0_u8; 2048];
    for _ in 0..64 {
        match socket.try_recv_from(&mut packet) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error.to_string()),
        }
    }
    Err("owned bootstrap queue exceeded the fixture drain bound".to_owned())
}

fn validate_query(packet: &[u8]) -> Result<(), String> {
    let value: Value = serde_bencode::from_bytes(packet).map_err(|error| error.to_string())?;
    let Value::Dict(fields) = value else {
        return Err("child query is not KRPC".to_owned());
    };
    let bytes = |name: &[u8]| match fields.get(name) {
        Some(Value::Bytes(value)) => Some(value.as_slice()),
        _ => None,
    };
    if bytes(b"y") != Some(b"q".as_slice())
        || !matches!(bytes(b"q"), Some(b"ping" | b"find_node" | b"get" | b"put"))
        || !matches!(bytes(b"t"), Some(value) if !value.is_empty() && value.len() <= 64)
    {
        return Err("child did not emit a valid bounded KRPC query".to_owned());
    }
    let Some(Value::Dict(arguments)) = fields.get(b"a".as_slice()) else {
        return Err("child KRPC query lacks arguments".to_owned());
    };
    if !matches!(arguments.get(b"id".as_slice()), Some(Value::Bytes(id)) if id.len() == 20) {
        return Err("child KRPC query lacks a valid node ID".to_owned());
    }
    Ok(())
}
