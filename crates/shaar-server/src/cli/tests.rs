use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

const KEY_A: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

fn args(parts: &[&str]) -> Vec<OsString> {
    std::iter::once("shaar-server")
        .chain(parts.iter().copied())
        .map(OsString::from)
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
            .join("target/server-cli-fixtures")
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

    fn server_dir(&self) -> PathBuf {
        self.0.join("server")
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
        "address-key",
        "allow",
        "config",
        "diag",
        "run",
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
        &["--config", "server.ktav"],
        &["127.0.0.1:8080"],
        &["-x"],
        &["a", "b"],
    ] {
        assert!(!is_cli_invocation(&args(legacy)), "{legacy:?}");
    }
}

#[test]
fn subcommands_parse_into_typed_invocations() {
    assert_eq!(
        parsed(&["init", "--dir", "d", "--private"]),
        Invocation::Init {
            dir: Some("d".into()),
            private: true
        }
    );
    assert_eq!(
        parsed(&["init"]),
        Invocation::Init {
            dir: None,
            private: false
        }
    );
    assert_eq!(
        parsed(&["address", "--config", "c.ktav"]),
        Invocation::Address(Place {
            config: Some("c.ktav".into()),
            dir: None
        })
    );
    assert_eq!(
        parsed(&["address-key", "new", "address.key"]),
        Invocation::AddressKey {
            path: "address.key".into()
        }
    );
    assert_eq!(
        parsed(&["run", "--dir", "d", "127.0.0.1:8080"]),
        Invocation::Run {
            place: Place {
                config: None,
                dir: Some("d".into())
            },
            target: Some("127.0.0.1:8080".to_owned()),
        }
    );
    assert_eq!(
        parsed(&["run"]),
        Invocation::Run {
            place: Place::default(),
            target: None
        }
    );
}

#[test]
fn place_arguments_may_come_before_or_after_the_action() {
    let key: PeerKey = KEY_A.parse().unwrap();
    let expected = Invocation::Allow {
        place: Place {
            config: None,
            dir: Some("d".into()),
        },
        action: AllowAction::Add(vec![key]),
    };
    assert_eq!(parsed(&["allow", "add", KEY_A, "--dir", "d"]), expected);
    assert_eq!(parsed(&["allow", "--dir", "d", "add", KEY_A]), expected);
    assert_eq!(
        parsed(&["allow", "list"]),
        Invocation::Allow {
            place: Place::default(),
            action: AllowAction::List
        }
    );
    assert_eq!(
        parsed(&["config", "set", "target", "127.0.0.1:8080", "--config", "c"]),
        Invocation::Config {
            place: Place {
                config: Some("c".into()),
                dir: None
            },
            action: ConfigAction::Set {
                key: "target".to_owned(),
                value: "127.0.0.1:8080".to_owned(),
            },
        }
    );
    for (word, choice) in [
        ("public", NetworkChoice::Public),
        ("private", NetworkChoice::Private),
    ] {
        assert_eq!(
            parsed(&["config", "network", word]),
            Invocation::Config {
                place: Place::default(),
                action: ConfigAction::Network(choice),
            }
        );
    }
    assert_eq!(
        parsed(&["config", "unset", "bind"]),
        Invocation::Config {
            place: Place::default(),
            action: ConfigAction::Unset {
                key: "bind".to_owned()
            },
        }
    );
}

#[test]
fn refused_arguments_name_the_problem() {
    for bad in [
        &["init", "--config", "c"][..],
        &["address", "--config", "c", "--dir", "d"],
        &["allow", "add"],
        &["allow"],
        &["config", "network", "maybe"],
        &["config", "set", "target"],
        &["address-key", "new"],
    ] {
        assert!(matches!(refused(bad), ParseError::Clap(_)), "{bad:?}");
    }
    match refused(&["allow", "add", KEY_A, "not-a-key"]) {
        ParseError::Value(message) => assert_eq!(message, "argument 2 is not a public key"),
        other => panic!("{other:?}"),
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
async fn init_creates_the_files_and_prints_the_address_forms() {
    let fixture = Fixture::new();
    let lines = run(&["init", "--dir", fixture.dir()]).await.unwrap();
    let public_key = lines
        .iter()
        .find_map(|line| line.strip_prefix("public_key="))
        .expect("the summary carries the public key");
    assert_eq!(public_key.len(), 64);
    assert!(lines.iter().any(|line| line.starts_with("peer_id=")));
    assert!(lines.iter().any(|line| line.starts_with("ygg_ip=")));
    assert!(lines.contains(&format!("clients connect with this address: {public_key}")));
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("next step: shaar-server config set target"))
    );
    let config = std::fs::read_to_string(fixture.server_dir().join("server.ktav")).unwrap();
    assert!(config.contains("network: {") && config.contains("dht.libtorrent.org"));
    assert!(fixture.server_dir().join("shaar.key").exists());
    assert!(fixture.server_dir().join("allowed.txt").exists());

    // A second init keeps everything, including the address.
    let again = run(&["init", "--dir", fixture.dir(), "--private"])
        .await
        .unwrap();
    assert!(again.iter().any(|line| line.starts_with("kept: ")));
    assert!(
        again
            .iter()
            .any(|line| line.contains("existing configuration was kept"))
    );
    assert_eq!(
        std::fs::read_to_string(fixture.server_dir().join("server.ktav")).unwrap(),
        config
    );
    let address = run(&["address", "--dir", fixture.dir()]).await.unwrap();
    assert_eq!(address[0], format!("public_key={public_key}"));
}

#[tokio::test]
async fn a_private_init_writes_a_direct_only_file() {
    let fixture = Fixture::new();
    let lines = run(&["init", "--dir", fixture.dir(), "--private"])
        .await
        .unwrap();
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("network: direct-only"))
    );
    let config = std::fs::read_to_string(fixture.server_dir().join("server.ktav")).unwrap();
    assert!(!config.contains("network:"));
}

#[tokio::test]
async fn allow_and_config_edit_the_files_of_the_chosen_place() {
    let fixture = Fixture::new();
    run(&["init", "--dir", fixture.dir(), "--private"])
        .await
        .unwrap();
    let listed = run(&["allow", "list", "--dir", fixture.dir()])
        .await
        .unwrap();
    assert_eq!(listed, ["clients=0"]);
    let added = run(&["allow", "add", KEY_A, "--dir", fixture.dir()])
        .await
        .unwrap();
    assert_eq!(added[0], format!("added: {KEY_A}"));
    let listed = run(&["allow", "list", "--dir", fixture.dir()])
        .await
        .unwrap();
    assert_eq!(listed, [KEY_A.to_owned(), "clients=1".to_owned()]);
    let removed = run(&["allow", "remove", KEY_A, "--dir", fixture.dir()])
        .await
        .unwrap();
    assert_eq!(removed[0], format!("removed: {KEY_A}"));

    let before = run(&["config", "check", "--dir", fixture.dir()])
        .await
        .unwrap_err();
    assert!(before.contains("target"), "{before}");
    let set = run(&[
        "config",
        "set",
        "target",
        "127.0.0.1:8080",
        "--dir",
        fixture.dir(),
    ])
    .await
    .unwrap();
    assert!(set[0].starts_with("updated: "));
    let checked = run(&["config", "check", "--dir", fixture.dir()])
        .await
        .unwrap();
    assert!(checked[0].starts_with("ok: "));
    let network = run(&["config", "network", "public", "--dir", fixture.dir()])
        .await
        .unwrap();
    assert!(network[0].starts_with("updated: "));
    let shown = run(&["config", "show", "--dir", fixture.dir()])
        .await
        .unwrap();
    // A later edit normalises the file, so the value may print as `target: ...` or `target:: ...`.
    assert!(
        shown
            .iter()
            .any(|line| line.starts_with("target") && line.contains("127.0.0.1:8080"))
    );
    assert!(shown.iter().any(|line| line.contains("dht.libtorrent.org")));
}

#[tokio::test]
async fn explicit_config_paths_find_the_key_and_the_allowlist_they_name() {
    let fixture = Fixture::new();
    run(&["init", "--dir", fixture.dir(), "--private"])
        .await
        .unwrap();
    let config = fixture.server_dir().join("server.ktav");
    let config = config.to_str().unwrap();
    let address = run(&["address", "--config", config]).await.unwrap();
    assert!(address[0].starts_with("public_key="));
    let added = run(&["allow", "add", KEY_A, "--config", config])
        .await
        .unwrap();
    assert_eq!(added[0], format!("added: {KEY_A}"));
    let missing = run(&["address", "--config", "no-such-file.ktav"])
        .await
        .unwrap_err();
    assert!(missing.starts_with("configuration: "), "{missing}");
}

#[tokio::test]
async fn address_key_new_creates_a_key_and_never_overwrites() {
    let fixture = Fixture::new();
    let path = fixture.0.join("address.key");
    let path = path.to_str().unwrap().to_owned();
    let lines = run(&["address-key", "new", &path]).await.unwrap();
    assert_eq!(lines[0], format!("created: {path}"));
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 32);
    let again = run(&["address-key", "new", &path]).await.unwrap_err();
    assert!(again.starts_with("address key: "), "{again}");
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 32);
}

#[test]
fn diag_nat_ports_takes_a_default_and_a_bounded_socket_count() {
    let place = |dir: Option<&str>| Place {
        config: None,
        dir: dir.map(PathBuf::from),
    };
    assert_eq!(
        parsed(&["diag", "nat-ports"]),
        Invocation::DiagNatPorts {
            place: place(None),
            sockets: shaar::network::observe::DEFAULT_SOCKETS,
            show_address: false,
        }
    );
    assert_eq!(
        parsed(&["diag", "nat-ports", "--sockets", "3", "--dir", "d"]),
        Invocation::DiagNatPorts {
            place: place(Some("d")),
            sockets: 3,
            show_address: false,
        }
    );
    assert_eq!(
        parsed(&["diag", "--dir", "d", "nat-ports", "--sockets", "16"]),
        Invocation::DiagNatPorts {
            place: place(Some("d")),
            sockets: MAX_SOCKETS,
            show_address: false,
        }
    );
    for bad in [
        &["diag"][..],
        &["diag", "other"],
        &["diag", "nat-ports", "--sockets", "0"],
        &["diag", "nat-ports", "--sockets", "17"],
        &["diag", "nat-ports", "--sockets", "many"],
    ] {
        assert!(matches!(refused(bad), ParseError::Clap(_)), "{bad:?}");
    }
}

#[tokio::test]
async fn diag_nat_ports_needs_the_bootstrap_hosts_of_a_public_configuration() {
    let fixture = Fixture::new();
    run(&["init", "--dir", fixture.dir(), "--private"])
        .await
        .unwrap();
    let direct_only = run(&["diag", "nat-ports", "--dir", fixture.dir()])
        .await
        .unwrap_err();
    assert!(
        direct_only.contains("no DHT bootstrap hosts"),
        "{direct_only}"
    );
    let missing = run(&["diag", "nat-ports", "--config", "no-such-file.ktav"])
        .await
        .unwrap_err();
    assert!(missing.starts_with("configuration: "), "{missing}");
}

#[test]
fn diag_nat_ports_shows_the_address_only_when_asked() {
    let shown = parsed(&["diag", "nat-ports", "--show-address"]);
    assert!(matches!(
        shown,
        Invocation::DiagNatPorts {
            show_address: true,
            ..
        }
    ));
}

#[test]
fn diag_nat_filter_listen_takes_defaults_a_bounded_window_and_an_optional_knock() {
    use shaar::network::observe::{
        DEFAULT_KNOCK_AFTER_SECONDS, DEFAULT_LISTEN_SECONDS, MAX_LISTEN_SECONDS,
    };
    assert_eq!(
        parsed(&["diag", "nat-filter", "listen"]),
        Invocation::DiagNatFilterListen {
            place: Place::default(),
            seconds: DEFAULT_LISTEN_SECONDS,
            knock: None,
            show_address: false,
        }
    );
    assert_eq!(
        parsed(&[
            "diag",
            "nat-filter",
            "listen",
            "--seconds",
            "60",
            "--knock-ip",
            "203.0.113.7",
            "--knock-after",
            "10",
            "--show-address",
            "--dir",
            "d",
        ]),
        Invocation::DiagNatFilterListen {
            place: Place {
                config: None,
                dir: Some(PathBuf::from("d")),
            },
            seconds: 60,
            knock: Some((Ipv4Addr::new(203, 0, 113, 7), 10)),
            show_address: true,
        }
    );
    // The default first knock applies when only the address is given.
    assert_eq!(
        parsed(&["diag", "nat-filter", "listen", "--knock-ip", "203.0.113.7"]),
        Invocation::DiagNatFilterListen {
            place: Place::default(),
            seconds: DEFAULT_LISTEN_SECONDS,
            knock: Some((Ipv4Addr::new(203, 0, 113, 7), DEFAULT_KNOCK_AFTER_SECONDS)),
            show_address: false,
        }
    );
    let longest = MAX_LISTEN_SECONDS.to_string();
    assert!(matches!(
        parsed(&["diag", "nat-filter", "listen", "--seconds", &longest]),
        Invocation::DiagNatFilterListen { seconds, .. } if seconds == MAX_LISTEN_SECONDS
    ));
    for bad in [
        &["diag", "nat-filter"][..],
        &["diag", "nat-filter", "other"],
        &["diag", "nat-filter", "listen", "--seconds", "0"],
        &["diag", "nat-filter", "listen", "--seconds", "111"],
        &["diag", "nat-filter", "listen", "--seconds", "soon"],
        &["diag", "nat-filter", "listen", "--knock-ip", "not-an-ip"],
        &[
            "diag",
            "nat-filter",
            "listen",
            "--knock-ip",
            "1.2.3.4",
            "--knock-after",
            "110",
        ],
    ] {
        assert!(matches!(refused(bad), ParseError::Clap(_)), "{bad:?}");
    }
    let orphan = refused(&["diag", "nat-filter", "listen", "--knock-after", "5"]);
    assert!(
        matches!(&orphan, ParseError::Value(message) if message.contains("--knock-ip")),
        "{orphan:?}"
    );
    // A first knock that would come after the window ends is refused with a message.
    let late = refused(&[
        "diag",
        "nat-filter",
        "listen",
        "--seconds",
        "20",
        "--knock-ip",
        "1.2.3.4",
    ]);
    assert!(
        matches!(&late, ParseError::Value(message) if message.contains("--knock-after")),
        "{late:?}"
    );
}

#[test]
fn diag_nat_filter_probe_needs_a_target_and_takes_a_bounded_pause() {
    use shaar::network::observe::{DEFAULT_PROBE_WAIT_SECONDS, MAX_PROBE_WAIT_SECONDS};
    assert_eq!(
        parsed(&[
            "diag",
            "nat-filter",
            "probe",
            "--target",
            "203.0.113.7:4000"
        ]),
        Invocation::DiagNatFilterProbe {
            target: "203.0.113.7:4000".parse().unwrap(),
            wait: DEFAULT_PROBE_WAIT_SECONDS,
        }
    );
    let longest = MAX_PROBE_WAIT_SECONDS.to_string();
    assert!(matches!(
        parsed(&[
            "diag",
            "nat-filter",
            "probe",
            "--target",
            "203.0.113.7:4000",
            "--wait",
            &longest,
        ]),
        Invocation::DiagNatFilterProbe { wait, .. } if wait == MAX_PROBE_WAIT_SECONDS
    ));
    for bad in [
        &["diag", "nat-filter", "probe"][..],
        &["diag", "nat-filter", "probe", "--target", "203.0.113.7"],
        &["diag", "nat-filter", "probe", "--target", "[::1]:4000"],
        &[
            "diag",
            "nat-filter",
            "probe",
            "--target",
            "1.2.3.4:4000",
            "--wait",
            "0",
        ],
        &[
            "diag",
            "nat-filter",
            "probe",
            "--target",
            "1.2.3.4:4000",
            "--wait",
            "101",
        ],
    ] {
        assert!(matches!(refused(bad), ParseError::Clap(_)), "{bad:?}");
    }
}

#[tokio::test]
async fn diag_nat_filter_probe_reports_both_phases_and_refuses_a_target_with_port_zero() {
    let sink = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = sink.local_addr().unwrap().to_string();
    let lines = run(&[
        "diag",
        "nat-filter",
        "probe",
        "--target",
        &target,
        "--wait",
        "1",
    ])
    .await
    .unwrap();
    assert_eq!(
        lines,
        [
            "nat-filter probe phase=A sent=3",
            "nat-filter probe phase=B sent=3"
        ]
    );
    let refused = run(&["diag", "nat-filter", "probe", "--target", "127.0.0.1:0"])
        .await
        .unwrap_err();
    assert!(refused.contains("unicast IPv4 address"), "{refused}");
}

#[tokio::test]
async fn diag_nat_filter_listen_needs_the_bootstrap_hosts_of_a_public_configuration() {
    let fixture = Fixture::new();
    run(&["init", "--dir", fixture.dir(), "--private"])
        .await
        .unwrap();
    let direct_only = run(&["diag", "nat-filter", "listen", "--dir", fixture.dir()])
        .await
        .unwrap_err();
    assert!(
        direct_only.contains("no DHT bootstrap hosts"),
        "{direct_only}"
    );
}

#[tokio::test]
async fn run_is_not_an_administration_command() {
    let error = execute(Invocation::Run {
        place: Place::default(),
        target: None,
    })
    .await
    .unwrap_err();
    assert_eq!(error, "run is not an administration command");
}
