//! Subcommands of `shaar-client`: init, address, connect, config and key.
//!
//! The legacy invocations (`shaar-client`, `shaar-client <server-key> [address]`,
//! `shaar-client --config <path>`) are parsed by `main.rs` and stay unchanged; this module
//! only answers when the first argument names a subcommand (or asks for help or the version).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use shaar::PeerKey;
use shaar::config::{ClientOverrides, load_client};
use shaar::identity::{
    ConfigAction, FileState, NetworkChoice, PasswordSources, Role, config_command,
    default_data_dir, first_run_summary_lines, install_password_sources, load_unlocked_default,
    provision_with, role_dir,
};

mod key;

use key::KeyCommand;

/// First arguments that select this module instead of the legacy parser.
const SUBCOMMANDS: [&str; 5] = ["init", "address", "connect", "config", "key"];

/// A valid public key that lets the path of a file be read before `server` is set.
const PLACEHOLDER_SERVER: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

/// Whether the arguments belong to the subcommand layer.
pub(crate) fn is_cli_invocation(args: &[String]) -> bool {
    args.get(1).is_some_and(|first| {
        SUBCOMMANDS.contains(&first.as_str())
            || matches!(
                first.as_str(),
                "help" | "--help" | "-h" | "--version" | "-V"
            )
    })
}

/// Where the Client's files are: an explicit configuration file, or the data directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Place {
    pub(crate) config: Option<PathBuf>,
    pub(crate) dir: Option<PathBuf>,
}

/// A parsed subcommand.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Invocation {
    Init {
        server: PeerKey,
        address: Option<SocketAddr>,
        dir: Option<PathBuf>,
        private: bool,
    },
    Address(Place),
    Connect(Place),
    Config {
        place: Place,
        action: ConfigAction,
    },
    /// `key export` or `key import`; `key public` is `address`.
    Key {
        place: Place,
        command: KeyCommand,
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
    Command::new("shaar-client")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Sha'ar Client: reach a Server by its key and forward a local TCP port to it")
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
                .about("Create the key and the configuration for one Server")
                .arg(
                    Arg::new("server")
                        .value_name("SERVER_KEY")
                        .required(true)
                        .help("The Server's address: its public key, 64 hexadecimal characters"),
                )
                .arg(
                    Arg::new("address")
                        .long("address")
                        .value_name("IP:PORT")
                        .help("The Server's reachable address (required with --private)"),
                )
                .arg(dir_arg(false))
                .arg(
                    Arg::new("private")
                        .long("private")
                        .action(ArgAction::SetTrue)
                        .help("Write a direct-only configuration without public networks"),
                ),
        )
        .subcommand(place_args(
            Command::new("address").about("Print this Client's key for the Server's allowlist"),
            false,
        ))
        .subcommand(place_args(
            Command::new("connect").about("Connect and forward the local port to the Server"),
            false,
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
        .subcommand(place_args(key::command(), true))
}

fn place_of(matches: &ArgMatches) -> Place {
    Place {
        config: matches.get_one::<PathBuf>("config").cloned(),
        dir: matches.get_one::<PathBuf>("dir").cloned(),
    }
}

/// Why the arguments were refused.
#[derive(Debug)]
pub(crate) enum ParseError {
    /// clap's own message (usage, help, version).
    Clap(clap::Error),
    /// A value that clap accepted as text but the product refuses.
    Value(String),
}

/// Parses the arguments of a subcommand invocation.
pub(crate) fn parse(args: impl IntoIterator<Item = String>) -> Result<Invocation, ParseError> {
    let matches = command()
        .try_get_matches_from(args)
        .map_err(ParseError::Clap)?;
    let (name, sub) = matches.subcommand().expect("a subcommand is required");
    Ok(match name {
        "init" => {
            let server = sub.get_one::<String>("server").expect("required");
            let server = PeerKey::from_str(server)
                .map_err(|_| ParseError::Value("the server key is not a public key".to_owned()))?;
            let address = sub
                .get_one::<String>("address")
                .map(|text| SocketAddr::from_str(text))
                .transpose()
                .map_err(|_| ParseError::Value("--address is not an ip:port".to_owned()))?;
            let private = sub.get_flag("private");
            if private && address.is_none() {
                return Err(ParseError::Value(
                    "a direct-only client needs --address <ip:port>".to_owned(),
                ));
            }
            Invocation::Init {
                server,
                address,
                dir: sub.get_one::<PathBuf>("dir").cloned(),
                private,
            }
        }
        "address" => Invocation::Address(place_of(sub)),
        "connect" => Invocation::Connect(place_of(sub)),
        "key" => match key::parse(sub) {
            KeyCommand::Public => Invocation::Address(place_of(sub)),
            command => Invocation::Key {
                place: place_of(sub),
                command,
            },
        },
        _ => {
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
    })
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
        None => Ok(role_dir(&base_dir(&place.dir)?, Role::Client).join("client.ktav")),
    }
}

/// The identity key file a place names.
async fn key_file(place: &Place) -> Result<PathBuf, String> {
    match &place.config {
        Some(path) => {
            let over = ClientOverrides {
                server: Some(PLACEHOLDER_SERVER.to_owned()),
                ..ClientOverrides::default()
            };
            let config = load_client(path, &over)
                .await
                .map_err(|error| format!("configuration: {error}"))?;
            Ok(config.key_file().to_path_buf())
        }
        None => Ok(role_dir(&base_dir(&place.dir)?, Role::Client).join("shaar.key")),
    }
}

/// Runs every subcommand except `connect` and returns the lines to print.
pub(crate) async fn execute(invocation: Invocation) -> Result<Vec<String>, String> {
    match invocation {
        Invocation::Init {
            server,
            address,
            dir,
            private,
        } => init(server, address, dir, private).await,
        Invocation::Address(place) => {
            let identity = load_unlocked_default(key_file(&place).await?, "Key password: ")
                .await
                .map_err(|error| shaar::identity::key_load_message(&error))?;
            Ok(PeerKey::of(&identity).summary_lines().to_vec())
        }
        Invocation::Config { place, action } => {
            config_command(Role::Client, &config_path(&place)?, action).await
        }
        Invocation::Key { place, command } => key::run(&key_file(&place).await?, command).await,
        Invocation::Connect(_) => Err("connect is not an administration command".to_owned()),
    }
}

async fn init(
    server: PeerKey,
    address: Option<SocketAddr>,
    dir: Option<PathBuf>,
    private: bool,
) -> Result<Vec<String>, String> {
    let base = base_dir(&dir)?;
    let choice = if private {
        NetworkChoice::Private
    } else {
        NetworkChoice::Public
    };
    let address_text = address.map(|address| address.to_string());
    let provisioned = provision_with(
        Role::Client,
        &base,
        Some(&server.to_string()),
        address_text.as_deref(),
        choice,
    )
    .await
    .map_err(|error| format!("init: {error}"))?;
    let own = PeerKey::of(&provisioned.identity);
    let mut lines =
        first_run_summary_lines(Role::Client, &provisioned.report, &provisioned.identity);
    lines.push(format!(
        "your public key for the server allowlist: public_key={own}"
    ));
    lines.push(format!(
        "pinned server: public_key={server} address={}",
        address_text.as_deref().unwrap_or("none")
    ));
    lines.push(
        match (provisioned.report.config, private) {
            (FileState::Kept, _) => {
                "network: unchanged, the existing configuration was kept (the server key and address of this call were not applied)"
            }
            (_, true) => "network: direct-only",
            (_, false) => {
                "network: public DHT bootstrap hosts and Yggdrasil peers (switch with `shaar-client config network private`)"
            }
        }
        .to_owned(),
    );
    lines.push(format!("on the Server run: shaar-server allow add {own}"));
    lines.push("then run: shaar-client connect".to_owned());
    Ok(lines)
}

/// Entry point of the subcommand layer. `connect` is handed back to `main.rs`.
/// The password sources the command line names; none when the arguments do not parse.
fn password_sources(args: &[String]) -> PasswordSources {
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

pub(crate) async fn main(args: Vec<String>) -> ExitCode {
    install_password_sources(password_sources(&args));
    let invocation = match parse(args) {
        Ok(invocation) => invocation,
        Err(ParseError::Clap(error)) => error.exit(),
        Err(ParseError::Value(message)) => {
            eprintln!("shaar-client: {message}");
            return ExitCode::FAILURE;
        }
    };
    if let Invocation::Connect(place) = invocation {
        return crate::connect_command(place).await;
    }
    match execute(invocation).await {
        Ok(lines) => {
            for line in lines {
                println!("{line}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("shaar-client: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
