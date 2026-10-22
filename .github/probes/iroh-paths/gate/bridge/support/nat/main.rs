#![forbid(unsafe_code)]
//! Disposable CI helper, not a production Server or Client executable.

mod peer;
mod protocol;
mod relay;
mod transport;
#[path = "../wire_oracle.rs"]
mod wire_oracle;

use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

const FILE_MAX: usize = 8 * 1024 * 1024;

fn read_json(path: &Path, limit: usize) -> io::Result<Value> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture JSON size limit",
        ));
    }
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

fn text<'a>(config: &'a Value, field: &str) -> io::Result<&'a str> {
    config[field].as_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing string field: {field}"),
        )
    })
}

fn address(config: &Value, field: &str) -> io::Result<SocketAddr> {
    let address: SocketAddr = text(config, field)?.parse().map_err(io::Error::other)?;
    if !address.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field} must be IPv4 in this fixture"),
        ));
    }
    Ok(address)
}

// Called outside the async runtime; files belong to an exclusively created CI case directory.
fn atomic_json(case: &Path, name: &str, value: &Value) -> io::Result<()> {
    let destination = case.join(name);
    if destination.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "fixture evidence already exists",
        ));
    }
    let temporary = case.join(format!("{name}.tmp"));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec(value).map_err(io::Error::other)?)?;
    drop(file);
    fs::rename(temporary, destination)
}

/// cancel-safe: yes — filesystem metadata reads and timer waits have no fixture commit side effects.
async fn wait_marker(path: &Path) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if tokio::fs::try_exists(path).await? {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fixture barrier deadline"))?
}

fn validate_frames(
    expected: bool,
    custom: wire_oracle::Counts,
    native: wire_oracle::Counts,
    unobserved: wire_oracle::Counts,
) -> io::Result<()> {
    if custom.streams != 0
        || custom.datagrams != 0
        || unobserved.streams != 0
        || unobserved.datagrams != 0
    {
        return Err(io::Error::other("custom or unobserved application payload"));
    }
    if expected {
        if native.streams == 0 || native.datagrams == 0 {
            return Err(io::Error::other("missing native positive calibration"));
        }
    } else if native.streams != 0 || native.datagrams != 0 {
        return Err(io::Error::other("unexpected native application payload"));
    }
    Ok(())
}

fn verify(case: &Path) -> io::Result<Value> {
    let raw = read_json(&case.join("relay-captures.json"), FILE_MAX)?;
    let captures: relay::Captures = serde_json::from_value(raw).map_err(io::Error::other)?;
    if captures.iter().any(|side| {
        side.is_empty()
            || side.len() > 256
            || side
                .iter()
                .any(|packet| packet.is_empty() || packet.len() > protocol::PAYLOAD_MAX)
    }) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid bounded relay capture",
        ));
    }
    let native_path = case.join("native-captures.json");
    let expectation_path = case.join("native-expectation.json");
    if native_path.exists() != expectation_path.exists() {
        return Err(io::Error::other("incomplete native capture evidence"));
    }
    let (native, expected): (relay::Captures, bool) = if native_path.exists() {
        let expected = read_json(&expectation_path, 1024)?["expected"]
            .as_bool()
            .ok_or_else(|| io::Error::other("invalid native expectation"))?;
        let packets =
            serde_json::from_value(read_json(&native_path, FILE_MAX)?).map_err(io::Error::other)?;
        (packets, expected)
    } else {
        (Default::default(), false)
    };
    if native.iter().any(|side| {
        side.len() > 256
            || side
                .iter()
                .any(|packet| packet.is_empty() || packet.len() > 65535)
    }) {
        return Err(io::Error::other("invalid bounded native capture"));
    }
    let mut evidence = Vec::new();
    for (side, captured) in captures.iter().enumerate() {
        let qlog = case.join(format!("qlog-{side}"));
        let mut paths = Vec::new();
        for entry in fs::read_dir(qlog)? {
            let path = entry?.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "qlog")
            {
                paths.push(path);
            }
        }
        if paths.len() != 1 {
            return Err(io::Error::other(
                "expected one original peer connection trace",
            ));
        }
        let index = wire_oracle::Index::parse_file(&paths[0]).map_err(io::Error::other)?;
        let mut seen = index.seen();
        let mut counts = wire_oracle::Counts::default();
        for packet in captured {
            counts.add(index.observe(packet, &mut seen).map_err(io::Error::other)?);
        }
        let mut native_counts = wire_oracle::Counts::default();
        for packet in &native[side] {
            native_counts.add(index.observe(packet, &mut seen).map_err(io::Error::other)?);
        }
        let unobserved = index.unobserved(&seen);
        validate_frames(expected, counts, native_counts, unobserved)?;
        evidence.push(json!({"side":side,"captured_packets":counts.packets,"stream_frames":counts.streams,"datagram_frames":counts.datagrams,
            "native_packets":native_counts.packets,"native_streams":native_counts.streams,"native_datagrams":native_counts.datagrams,
            "constructed_not_observed":unobserved.packets}));
    }
    Ok(json!({"status":"pass","directions":evidence}))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let path = PathBuf::from(args.next().ok_or("usage: nat-peer CONFIG.json")?);
    if args.next().is_some() {
        return Err("usage: nat-peer CONFIG.json".into());
    }
    let config = read_json(&path, 8192)?;
    let role = text(&config, "role")?;
    let case = PathBuf::from(text(&config, "case_dir")?).canonicalize()?;
    if !case.is_dir() {
        return Err("case_dir must already exist".into());
    }
    let nonce = protocol::nonce(text(&config, "nonce")?)?;
    if role == "peer" && config.get("native_bind").is_some() {
        // This target skips packet contents; record only route selection and send errors.
        tracing_subscriber::fmt()
            .with_env_filter("warn,iroh::socket::transports=trace")
            .with_ansi(false)
            .with_writer(std::io::stderr)
            .try_init()
            .map_err(io::Error::other)?;
    }
    if role == "verify" {
        let evidence = verify(&case)?;
        atomic_json(&case, "verified.json", &evidence)?;
        println!("{evidence}");
        return Ok(());
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    match role {
        "relay" => {
            let relay = runtime.block_on(relay::Relay::bind(address(&config, "bind")?, nonce))?;
            atomic_json(
                &case,
                "relay-ready.json",
                &json!({"address":relay.addr()?.to_string()}),
            )?;
            let (captures, peers) = runtime.block_on(relay.run())?;
            atomic_json(&case, "relay-captures.json", &json!(captures))?;
            atomic_json(
                &case,
                "relay-report.json",
                &json!({"status":"pass","peers":peers.map(|peer| peer.map(|address| address.to_string()))}),
            )?;
        }
        "stop" => {
            runtime.block_on(relay::stop(address(&config, "relay")?, nonce))?;
        }
        "peer" => {
            let side = config["side"]
                .as_u64()
                .filter(|side| *side < 2)
                .ok_or("invalid side")?;
            let qlog = case.join(format!("qlog-{side}"));
            fs::create_dir(&qlog)?;
            let peer = peer::Config {
                side: u8::try_from(side)?,
                relay: address(&config, "relay")?,
                control_bind: address(&config, "bind")?,
                native_bind: if config.get("native_bind").is_some() {
                    Some(address(&config, "native_bind")?)
                } else {
                    None
                },
                external_addr: if config.get("external_addr").is_some() {
                    Some(address(&config, "external_addr")?)
                } else {
                    None
                },
                expect_native: match config.get("expect_native") {
                    None => false,
                    Some(value) => value.as_bool().ok_or("invalid expect_native")?,
                },
                nonce,
                qlog,
            };
            let session = runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(30), peer::start(&peer)).await
            })??;
            atomic_json(
                &case,
                &format!("peer-{side}-ready.json"),
                &json!({"side":session.side,"tls_complete":true,"queued_bytes":8,"premature_payload":false}),
            )?;
            runtime.block_on(wait_marker(&case.join("GO")))?;
            runtime.block_on(session.observe(&peer))?;
            atomic_json(
                &case,
                &format!("peer-{side}-observed.json"),
                &json!({"side":side,"native_delivered":peer.expect_native}),
            )?;
            runtime.block_on(wait_marker(&case.join("STOP")))?;
            let (sent, received) = runtime.block_on(session.close());
            atomic_json(
                &case,
                &format!("peer-{side}-report.json"),
                &json!({"status":"pass","side":side,"custom_sent":sent,"custom_received":received,"native_delivered":peer.expect_native}),
            )?;
        }
        _ => return Err("unknown fixture role".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wire_oracle::Counts;

    #[test]
    fn native_expectation_never_weakens_custom_or_unobserved_exclusion() {
        let zero = Counts::default();
        let both = Counts {
            packets: 1,
            streams: 1,
            datagrams: 1,
        };
        assert!(validate_frames(false, zero, zero, zero).is_ok());
        assert!(validate_frames(true, zero, both, zero).is_ok());
        assert!(validate_frames(true, zero, zero, zero).is_err());
        assert!(validate_frames(false, zero, both, zero).is_err());
        for expected in [false, true] {
            assert!(validate_frames(expected, both, both, zero).is_err());
            assert!(validate_frames(expected, zero, both, both).is_err());
        }
        for partial in [
            Counts { streams: 1, ..zero },
            Counts {
                datagrams: 1,
                ..zero
            },
        ] {
            assert!(validate_frames(true, zero, partial, zero).is_err());
        }
    }
}
