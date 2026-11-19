//! Subcommands of `shaar-server`: init, address, address-key, key, allow, config, diag and run.
//!
//! The legacy invocations (`shaar-server`, `shaar-server <target>`, `shaar-server --config
//! <path>`) are parsed by `main.rs` and stay unchanged; this module only answers when the
//! first argument names a subcommand (or asks for help or the version).

use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use shaar::config::{MainlineNetwork, ServerOverrides, load_server};
use shaar::identity::{
    ConfigAction, Identity, NetworkChoice, PasswordSources, Role, config_command, default_data_dir,
    first_run_summary_lines, install_password_sources, load_unlocked_default, provision_with,
    role_dir,
};
use shaar::{AllowAction, PeerKey, allowlist_command};

mod diag;
mod key;

use diag::SweepArgs;
use key::KeyCommand;

/// First arguments that select this module instead of the legacy parser.
const SUBCOMMANDS: [&str; 8] = [
    "init",
    "address",
    "address-key",
    "key",
    "allow",
    "config",
    "diag",
    "run",
];

/// Loopback target that lets the path of a file be read before `target` is set.
const PLACEHOLDER_TARGET: &str = "127.0.0.1:1";

/// Whether the arguments belong to the subcommand layer.
pub(crate) fn is_cli_invocation(args: &[OsString]) -> bool {
    args.get(1)
        .and_then(|first| first.to_str())
        .is_some_and(|first| {
            SUBCOMMANDS.contains(&first)
                || matches!(first, "help" | "--help" | "-h" | "--version" | "-V")
        })
}

/// Where the Server's files are: an explicit configuration file, or the data directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Place {
    pub(crate) config: Option<PathBuf>,
    pub(crate) dir: Option<PathBuf>,
}

/// A parsed subcommand.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Invocation {
    Init {
        dir: Option<PathBuf>,
        private: bool,
    },
    Address(Place),
    AddressKey {
        path: PathBuf,
    },
    /// `key export` or `key import`; `key public` is `address`.
    Key {
        place: Place,
        command: KeyCommand,
    },
    Allow {
        place: Place,
        action: AllowAction,
    },
    Config {
        place: Place,
        action: ConfigAction,
    },
    /// `diag nat-ports`: the external UDP ports `sockets` fresh sockets get.
    DiagNatPorts {
        place: Place,
        sockets: u8,
        show_address: bool,
    },
    /// `diag port-map`: asks the home router to map `port` to the same external port.
    DiagPortMap {
        port: u16,
        show_address: bool,
    },
    /// `diag nat-filter listen`: listens `seconds` and, with a knock address, knocks on it after
    /// `knock.1` seconds; with a sweep it sends one datagram to every port of an address.
    DiagNatFilterListen {
        place: Place,
        seconds: u16,
        knock: Option<(Ipv4Addr, u16)>,
        sweep: Option<SweepArgs>,
        show_address: bool,
    },
    /// `diag nat-filter probe`: probes `target` before and after `wait` seconds.
    DiagNatFilterProbe {
        target: SocketAddrV4,
        wait: u16,
    },
    /// `diag nat-filter catch`: talks to `target` from one socket for `seconds` and reports the
    /// sweep datagram that reaches it.
    DiagNatFilterCatch {
        target: SocketAddrV4,
        seconds: u16,
    },
    Run {
        place: Place,
        target: Option<String>,
    },
}

fn dir_arg(global: bool) -> Arg {
    Arg::new("dir")
        .long("dir")
        .value_name("DIR")
        .value_parser(value_parser!(PathBuf))
        .global(global)
        .help("Data directory (default: the per-user data directory)")
}

fn place_args(command: Command, global: bool) -> Command {
    command
        .arg(
            Arg::new("config")
                .long("config")
                .value_name("PATH")
                .value_parser(value_parser!(PathBuf))
                .conflicts_with("dir")
                .global(global)
                .help("Configuration file to use"),
        )
        .arg(dir_arg(global))
}

pub(crate) fn command() -> Command {
    let keys = |name: &'static str, about: &'static str| {
        Command::new(name).about(about).arg(
            Arg::new("keys")
                .value_name("KEY")
                .num_args(1..)
                .required(true)
                .help("Client public key: 64 hexadecimal characters"),
        )
    };
    Command::new("shaar-server")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Sha'ar Server: publish an address, admit clients, forward to one TCP service")
        .arg(
            Arg::new("password")
                .long("password")
                .value_name("PASSWORD")
                .global(true)
                .help("Password of an encrypted key file; visible in process lists, so the weakest form (see also SHAAR_KEY_PASSWORD, --password-file, the standard input and the terminal)"),
        )
        .arg(
            Arg::new("password-file")
                .long("password-file")
                .value_name("FILE")
                .value_parser(value_parser!(PathBuf))
                .global(true)
                .help("File with the password of an encrypted key file (owner-only rights)"),
        )
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("init")
                .about("Create the key, configuration and allowlist")
                .arg(dir_arg(false))
                .arg(
                    Arg::new("private")
                        .long("private")
                        .action(ArgAction::SetTrue)
                        .help("Write a direct-only configuration without public networks"),
                ),
        )
        .subcommand(place_args(
            Command::new("address").about("Print the address clients use"),
            false,
        ))
        .subcommand(
            Command::new("address-key")
                .about("Manage the key that seals a published address")
                .subcommand_required(true)
                .subcommand(
                    Command::new("new")
                        .about("Create a new address key file")
                        .arg(
                            Arg::new("path")
                                .value_name("PATH")
                                .value_parser(value_parser!(PathBuf))
                                .required(true),
                        ),
                ),
        )
        .subcommand(place_args(key::command(), true))
        .subcommand(place_args(
            Command::new("allow")
                .about("Manage the admitted client keys")
                .subcommand_required(true)
                .subcommand(keys("add", "Admit clients"))
                .subcommand(keys("remove", "Stop admitting clients"))
                .subcommand(Command::new("list").about("List admitted clients")),
            true,
        ))
        .subcommand(place_args(
            Command::new("config")
                .about("Show, check or edit the configuration file")
                .subcommand_required(true)
                .subcommand(Command::new("show").about("Print the file"))
                .subcommand(Command::new("check").about("Validate the file and the files it names"))
                .subcommand(
                    Command::new("set")
                        .about("Set a top-level key")
                        .arg(Arg::new("key").required(true))
                        .arg(Arg::new("value").required(true)),
                )
                .subcommand(
                    Command::new("unset")
                        .about("Remove a top-level key")
                        .arg(Arg::new("key").required(true)),
                )
                .subcommand(
                    Command::new("network")
                        .about("Switch between public networks and direct-only")
                        .arg(
                            Arg::new("choice")
                                .required(true)
                                .value_parser(["public", "private"]),
                        ),
                ),
            true,
        ))
        .subcommand(place_args(diag::command(), true))
        .subcommand(
            place_args(
                Command::new("run")
                    .about("Serve; the optional TARGET overrides `target` for this run"),
                false,
            )
            .arg(Arg::new("target").value_name("TARGET")),
        )
}

fn place_of(matches: &ArgMatches) -> Place {
    Place {
        config: matches.get_one::<PathBuf>("config").cloned(),
        dir: matches.get_one::<PathBuf>("dir").cloned(),
    }
}

fn parse_keys(matches: &ArgMatches) -> Result<Vec<PeerKey>, String> {
    matches
        .get_many::<String>("keys")
        .into_iter()
        .flatten()
        .enumerate()
        .map(|(index, text)| {
            PeerKey::from_str(text)
                .map_err(|_| format!("argument {} is not a public key", index + 1))
        })
        .collect()
}

/// Parses the arguments of a subcommand invocation.
pub(crate) fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Invocation, ParseError> {
    let matches = command()
        .try_get_matches_from(args)
        .map_err(ParseError::Clap)?;
    let (name, sub) = matches.subcommand().expect("a subcommand is required");
    Ok(match name {
        "init" => Invocation::Init {
            dir: sub.get_one::<PathBuf>("dir").cloned(),
            private: sub.get_flag("private"),
        },
        "address" => Invocation::Address(place_of(sub)),
        "address-key" => {
            let (_, new) = sub.subcommand().expect("a subcommand is required");
            Invocation::AddressKey {
                path: new
                    .get_one::<PathBuf>("path")
                    .cloned()
                    .expect("path is required"),
            }
        }
        "key" => match key::parse(sub) {
            KeyCommand::Public => Invocation::Address(place_of(sub)),
            command => Invocation::Key {
                place: place_of(sub),
                command,
            },
        },
        "allow" => {
            let (action, args) = sub.subcommand().expect("a subcommand is required");
            let action = match action {
                "add" => AllowAction::Add(parse_keys(args).map_err(ParseError::Value)?),
                "remove" => AllowAction::Remove(parse_keys(args).map_err(ParseError::Value)?),
                _ => AllowAction::List,
            };
            Invocation::Allow {
                place: place_of(sub),
                action,
            }
        }
        "config" => {
            let (action, args) = sub.subcommand().expect("a subcommand is required");
            let text = |name: &str| args.get_one::<String>(name).cloned().expect("required");
            let action = match action {
                "show" => ConfigAction::Show,
                "check" => ConfigAction::Check,
                "set" => ConfigAction::Set {
                    key: text("key"),
                    value: text("value"),
                },
                "unset" => ConfigAction::Unset { key: text("key") },
                _ => ConfigAction::Network(if text("choice") == "public" {
                    NetworkChoice::Public
                } else {
                    NetworkChoice::Private
                }),
            };
            Invocation::Config {
                place: place_of(sub),
                action,
            }
        }
        "diag" => diag::parse(sub)?,
        _ => Invocation::Run {
            place: place_of(sub),
            target: sub.get_one::<String>("target").cloned(),
        },
    })
}

/// Why the arguments were refused.
#[derive(Debug)]
pub(crate) enum ParseError {
    /// clap's own message (usage, help, version).
    Clap(clap::Error),
    /// A value that clap accepted as text but the product refuses.
    Value(String),
}

fn base_dir(dir: &Option<PathBuf>) -> Result<PathBuf, String> {
    match dir {
        Some(dir) => Ok(dir.clone()),
        None => default_data_dir().map_err(|error| format!("data directory: {error}")),
    }
}

/// The configuration file a place names.
pub(crate) fn config_path(place: &Place) -> Result<PathBuf, String> {
    match &place.config {
        Some(path) => Ok(path.clone()),
        None => Ok(role_dir(&base_dir(&place.dir)?, Role::Server).join("server.ktav")),
    }
}

/// The identity key file and the allowlist file a place names.
async fn file_paths(place: &Place) -> Result<(PathBuf, PathBuf), String> {
    match &place.config {
        Some(path) => {
            let over = ServerOverrides {
                target: Some(PLACEHOLDER_TARGET.to_owned()),
                ..ServerOverrides::default()
            };
            let config = load_server(path, &over)
                .await
                .map_err(|error| format!("configuration: {error}"))?;
            Ok((
                config.key_file().to_path_buf(),
                config.allowlist_path().to_path_buf(),
            ))
        }
        None => {
            let dir = role_dir(&base_dir(&place.dir)?, Role::Server);
            Ok((dir.join("shaar.key"), dir.join("allowed.txt")))
        }
    }
}

/// Runs every subcommand except `run` and returns the lines to print.
pub(crate) async fn execute(invocation: Invocation) -> Result<Vec<String>, String> {
    match invocation {
        Invocation::Init { dir, private } => init(dir, private).await,
        Invocation::Address(place) => {
            let (key_file, _) = file_paths(&place).await?;
            let identity = load_unlocked_default(key_file, "Key password: ")
                .await
                .map_err(|error| shaar::identity::key_load_message(&error))?;
            Ok(PeerKey::of(&identity).summary_lines().to_vec())
        }
        Invocation::AddressKey { path } => {
            Identity::create_new(&path)
                .await
                .map_err(|error| format!("address key: {error}"))?;
            Ok(vec![
                format!("created: {}", path.display()),
                "set `address_key_file` to this file on the Server and give the same file to every Client that may learn the address"
                    .to_owned(),
            ])
        }
        Invocation::Key { place, command } => key::run(&file_paths(&place).await?.0, command).await,
        Invocation::Allow { place, action } => {
            let (_, allowlist) = file_paths(&place).await?;
            allowlist_command(&allowlist, action).await
        }
        Invocation::Config { place, action } => {
            config_command(Role::Server, &config_path(&place)?, action).await
        }
        Invocation::DiagNatPorts {
            place,
            sockets,
            show_address,
        } => diag::ports(&place, sockets, show_address).await,
        Invocation::DiagPortMap { port, show_address } => {
            Ok(diag::port_map(port, show_address).await)
        }
        measuring @ (Invocation::DiagNatFilterListen { .. }
        | Invocation::DiagNatFilterProbe { .. }
        | Invocation::DiagNatFilterCatch { .. }) => {
            let mut lines = Vec::new();
            diag::run_streaming(measuring, &mut |line| lines.push(line)).await?;
            Ok(lines)
        }
        Invocation::Run { .. } => Err("run is not an administration command".to_owned()),
    }
}

/// Prints the failure of a streamed command, or succeeds.
fn finish(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("shaar-server: {error}");
            ExitCode::FAILURE
        }
    }
}

/// The Mainline settings of the configuration a place names.
async fn mainline_of(place: &Place) -> Result<MainlineNetwork, String> {
    let over = ServerOverrides {
        target: Some(PLACEHOLDER_TARGET.to_owned()),
        ..ServerOverrides::default()
    };
    let config = load_server(config_path(place)?, &over)
        .await
        .map_err(|error| format!("configuration: {error}"))?;
    config
        .network()
        .and_then(|network| network.mainline())
        .cloned()
        .ok_or_else(|| {
            "the configuration names no DHT bootstrap hosts (see `config network public`)"
                .to_owned()
        })
}

async fn init(dir: Option<PathBuf>, private: bool) -> Result<Vec<String>, String> {
    let base = base_dir(&dir)?;
    let choice = if private {
        NetworkChoice::Private
    } else {
        NetworkChoice::Public
    };
    let provisioned = provision_with(Role::Server, &base, None, None, choice)
        .await
        .map_err(|error| format!("init: {error}"))?;
    let key = PeerKey::of(&provisioned.identity);
    let mut lines =
        first_run_summary_lines(Role::Server, &provisioned.report, &provisioned.identity);
    lines.push(format!("peer_id={}", key.peer_id()));
    lines.push(format!("ygg_ip={}", key.ygg_ip()));
    lines.push(
        match (provisioned.report.config, private) {
            (shaar::identity::FileState::Kept, _) => {
                "network: unchanged, the existing configuration was kept (see `shaar-server config network`)"
            }
            (_, true) => "network: direct-only, clients need this machine's address and port",
            (_, false) => {
                "network: public DHT bootstrap hosts and Yggdrasil peers (switch with `shaar-server config network private`)"
            }
        }
        .to_owned(),
    );
    lines.push(
        "next step: shaar-server config set target 127.0.0.1:<port of the service to forward to>"
            .to_owned(),
    );
    lines.push(format!("clients connect with this address: {key}"));
    Ok(lines)
}

/// Entry point of the subcommand layer. `run` is handed back to `main.rs`.
/// The password sources the command line names; none when the arguments do not parse.
fn password_sources(args: &[OsString]) -> PasswordSources {
    command()
        .try_get_matches_from(args)
        .ok()
        .map(|matches| {
            PasswordSources::new(
                matches.get_one::<String>("password").cloned(),
                matches.get_one::<PathBuf>("password-file").cloned(),
            )
        })
        .unwrap_or_default()
}

pub(crate) async fn main(args: Vec<OsString>) -> ExitCode {
    install_password_sources(password_sources(&args));
    let invocation = match parse(args) {
        Ok(invocation) => invocation,
        Err(ParseError::Clap(error)) => error.exit(),
        Err(ParseError::Value(message)) => {
            eprintln!("shaar-server: {message}");
            return ExitCode::FAILURE;
        }
    };
    // The measuring commands print as they go, so a log shows the first line before the end.
    let invocation = match invocation {
        Invocation::Run { place, target } => return crate::run_command(place, target).await,
        measuring if diag::is_streaming(&measuring) => {
            let result = diag::run_streaming(measuring, &mut |line| println!("{line}")).await;
            return finish(result);
        }
        other => other,
    };
    match execute(invocation).await {
        Ok(lines) => {
            for line in lines {
                println!("{line}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("shaar-server: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod diag_tests;
#[cfg(test)]
mod tests;
