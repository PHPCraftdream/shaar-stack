use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

const SERVER: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

fn args(parts: &[&str]) -> Vec<String> {
    std::iter::once("shaar-client")
        .chain(parts.iter().copied())
        .map(str::to_owned)
        .collect()
}

fn parsed(parts: &[&str]) -> Invocation {
    match parse(args(parts)) {
        Ok(invocation) => invocation,
        Err(error) => panic!("{parts:?} must parse, got {error:?}"),
    }
}

fn refused(parts: &[&str]) -> ParseError {
    parse(args(parts)).expect_err("must be refused")
}

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::current_dir()
            .unwrap()
            .join("target/client-cli-fixtures")
            .join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn dir(&self) -> &str {
        self.0.to_str().unwrap()
    }

    fn client_dir(&self) -> PathBuf {
        self.0.join("client")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn run(parts: &[&str]) -> Result<Vec<String>, String> {
    execute(parsed(parts)).await
}

#[test]
fn only_subcommands_help_and_version_select_the_cli_layer() {
    for first in [
        "init",
        "address",
        "connect",
        "config",
        "help",
        "--help",
        "-h",
        "--version",
        "-V",
    ] {
        assert!(is_cli_invocation(&args(&[first])), "{first}");
    }
    for legacy in [
        &[][..],
        &["--config", "client.ktav"],
        SERVER_ONLY,
        &["-x"],
        &["a", "b"],
    ] {
        assert!(!is_cli_invocation(&args(legacy)), "{legacy:?}");
    }
}

const SERVER_ONLY: &[&str] = &["d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"];

#[test]
fn subcommands_parse_into_typed_invocations() {
    let server: PeerKey = SERVER.parse().unwrap();
    assert_eq!(
        parsed(&["init", SERVER]),
        Invocation::Init {
            server,
            address: None,
            dir: None,
            private: false
        }
    );
    assert_eq!(
        parsed(&[
            "init",
            SERVER,
            "--address",
            "198.51.100.8:49152",
            "--dir",
            "d",
            "--private"
        ]),
        Invocation::Init {
            server,
            address: Some("198.51.100.8:49152".parse().unwrap()),
            dir: Some("d".into()),
            private: true
        }
    );
    assert_eq!(
        parsed(&["address", "--dir", "d"]),
        Invocation::Address(Place {
            config: None,
            dir: Some("d".into())
        })
    );
    assert_eq!(
        parsed(&["connect", "--config", "c.ktav"]),
        Invocation::Connect(Place {
            config: Some("c.ktav".into()),
            dir: None
        })
    );
    assert_eq!(parsed(&["connect"]), Invocation::Connect(Place::default()));
    assert_eq!(
        parsed(&["config", "--dir", "d", "set", "listen", "127.0.0.1:3000"]),
        Invocation::Config {
            place: Place {
                config: None,
                dir: Some("d".into())
            },
            action: ConfigAction::Set {
                key: "listen".to_owned(),
                value: "127.0.0.1:3000".to_owned()
            },
        }
    );
    assert_eq!(
        parsed(&["config", "network", "private"]),
        Invocation::Config {
            place: Place::default(),
            action: ConfigAction::Network(NetworkChoice::Private),
        }
    );
}

#[test]
fn refused_arguments_name_the_problem() {
    for bad in [
        &["init"][..],
        &["init", SERVER, "--config", "c"],
        &["connect", "--config", "c", "--dir", "d"],
        &["config"],
        &["config", "network", "maybe"],
        &["config", "unset"],
    ] {
        assert!(matches!(refused(bad), ParseError::Clap(_)), "{bad:?}");
    }
    for (bad, message) in [
        (
            &["init", "not-a-key"][..],
            "the server key is not a public key",
        ),
        (
            &["init", SERVER, "--address", "nowhere"],
            "--address is not an ip:port",
        ),
        (
            &["init", SERVER, "--private"],
            "a direct-only client needs --address <ip:port>",
        ),
    ] {
        match refused(bad) {
            ParseError::Value(text) => assert_eq!(text, message, "{bad:?}"),
            other => panic!("{bad:?}: {other:?}"),
        }
    }
    for (flag, kind) in [
        ("--help", clap::error::ErrorKind::DisplayHelp),
        ("--version", clap::error::ErrorKind::DisplayVersion),
    ] {
        match refused(&[flag]) {
            ParseError::Clap(error) => assert_eq!(error.kind(), kind, "{flag}"),
            other => panic!("{other:?}"),
        }
    }
}

#[tokio::test]
async fn init_pins_the_server_and_prints_the_key_to_give_it() {
    let fixture = Fixture::new();
    let lines = run(&["init", SERVER, "--dir", fixture.dir()])
        .await
        .unwrap();
    let own = lines
        .iter()
        .find_map(|line| line.strip_prefix("public_key="))
        .expect("the summary carries the client key");
    assert_eq!(own.len(), 64);
    assert!(lines.contains(&format!(
        "your public key for the server allowlist: public_key={own}"
    )));
    assert!(lines.contains(&format!("pinned server: public_key={SERVER} address=none")));
    assert!(lines.contains(&format!("on the Server run: shaar-server allow add {own}")));
    assert!(lines.contains(&"then run: shaar-client connect".to_owned()));
    let config = std::fs::read_to_string(fixture.client_dir().join("client.ktav")).unwrap();
    assert!(config.contains(SERVER));
    assert!(config.contains("network: {") && config.contains("tcp://ygg-pa.incognet.io:8883"));

    // The same key is reported by `address`, and a second init keeps the files.
    let address = run(&["address", "--dir", fixture.dir()]).await.unwrap();
    assert_eq!(address[0], format!("public_key={own}"));
    let again = run(&["init", SERVER, "--dir", fixture.dir()])
        .await
        .unwrap();
    assert!(again.iter().any(|line| line.starts_with("kept: ")));
    assert!(
        again
            .iter()
            .any(|line| line.contains("existing configuration was kept"))
    );
    assert_eq!(
        std::fs::read_to_string(fixture.client_dir().join("client.ktav")).unwrap(),
        config
    );
}

#[tokio::test]
async fn a_private_init_needs_the_address_and_writes_a_direct_only_file() {
    let fixture = Fixture::new();
    let lines = run(&[
        "init",
        SERVER,
        "--address",
        "198.51.100.8:49152",
        "--private",
        "--dir",
        fixture.dir(),
    ])
    .await
    .unwrap();
    assert!(lines.contains(&format!(
        "pinned server: public_key={SERVER} address=198.51.100.8:49152"
    )));
    assert!(lines.contains(&"network: direct-only".to_owned()));
    let config = std::fs::read_to_string(fixture.client_dir().join("client.ktav")).unwrap();
    assert!(config.contains("server_address:: 198.51.100.8:49152"));
    assert!(!config.contains("network:"));
}

#[tokio::test]
async fn config_edits_the_file_of_the_chosen_place() {
    let fixture = Fixture::new();
    run(&["init", SERVER, "--dir", fixture.dir()])
        .await
        .unwrap();
    let checked = run(&["config", "check", "--dir", fixture.dir()])
        .await
        .unwrap();
    assert!(checked[0].starts_with("ok: "));
    let set = run(&[
        "config",
        "set",
        "listen",
        "127.0.0.1:3000",
        "--dir",
        fixture.dir(),
    ])
    .await
    .unwrap();
    assert!(set[0].starts_with("updated: "));
    let refused = run(&[
        "config",
        "set",
        "listen",
        "192.0.2.1:3000",
        "--dir",
        fixture.dir(),
    ])
    .await
    .unwrap_err();
    assert!(refused.contains("NotLoopback"), "{refused}");
    let private = run(&["config", "network", "private", "--dir", fixture.dir()])
        .await
        .unwrap();
    // A key-only client without network settings is a valid file but cannot connect;
    // the edit is refused only when the schema is broken, so the strict check is the gate.
    assert!(private[0].starts_with("updated: "), "{private:?}");
    let shown = run(&["config", "show", "--dir", fixture.dir()])
        .await
        .unwrap();
    assert!(
        shown
            .iter()
            .any(|line| line.contains("listen:: 127.0.0.1:3000"))
    );
    assert!(!shown.iter().any(|line| line.contains("network:")));
}

#[tokio::test]
async fn a_missing_file_is_reported_and_connect_is_not_an_administration_command() {
    let fixture = Fixture::new();
    let missing = run(&["address", "--config", "no-such.ktav"])
        .await
        .unwrap_err();
    assert!(missing.starts_with("configuration: "), "{missing}");
    let none = run(&["config", "show", "--dir", fixture.dir()])
        .await
        .unwrap_err();
    assert_eq!(none, "could not read the configuration");
    let error = execute(Invocation::Connect(Place::default()))
        .await
        .unwrap_err();
    assert_eq!(error, "connect is not an administration command");
}
