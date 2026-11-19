//! The `key` commands: carry the Server's key to another device as text and keep it encrypted on
//! disk (leaves KEY-1 and KEY-2). The text of a key is the key itself, so it is shown only with
//! `--print-secret`, and an import reads it from a file or the standard input, never from an
//! argument. An encrypted key file asks for its password from `--password`, `SHAAR_KEY_PASSWORD`,
//! `--password-file`, the standard input or the terminal, in that order.

use std::fmt;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use shaar::identity::{
    DEFAULT_KEY_COST, KeyCost, NEW_PASSWORD_ENV, PasswordSources, change_key_password, decrypt_key,
    encrypt_key, export_key, import_key, obtain_new_password, obtain_password, read_key_text,
};

/// The cost options of `key encrypt` and `key password`; `None` keeps the default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CostArgs {
    pub(crate) memory_kib: Option<u32>,
    pub(crate) passes: Option<u32>,
}

impl CostArgs {
    fn cost(self) -> KeyCost {
        KeyCost {
            memory_kib: self.memory_kib.unwrap_or(DEFAULT_KEY_COST.memory_kib),
            passes: self.passes.unwrap_or(DEFAULT_KEY_COST.passes),
            lanes: DEFAULT_KEY_COST.lanes,
        }
    }
}

/// The password of an encrypted key file as the command line gave it.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct PasswordArgs {
    pub(crate) password: Option<String>,
    pub(crate) file: Option<PathBuf>,
}

impl PasswordArgs {
    fn sources(&self) -> PasswordSources {
        PasswordSources::new(self.password.clone(), self.file.clone())
    }
}

// A password given as an argument is a secret: the debug form never shows it.
impl fmt::Debug for PasswordArgs {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("PasswordArgs")
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("file", &self.file)
            .finish()
    }
}

/// What `key` does with the key file.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KeyCommand {
    Export {
        out: Option<PathBuf>,
        print_secret: bool,
        passwords: PasswordArgs,
    },
    Import {
        from: Option<PathBuf>,
    },
    Public,
    Encrypt {
        cost: CostArgs,
        passwords: PasswordArgs,
    },
    Decrypt {
        passwords: PasswordArgs,
    },
    Password {
        cost: CostArgs,
        passwords: PasswordArgs,
        new_password: PasswordArgs,
    },
}

fn cost_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("memory-kib")
                .long("memory-kib")
                .value_name("KIB")
                .value_parser(value_parser!(u32))
                .help("Argon2id memory in KiB (default 65536, at most 262144)"),
        )
        .arg(
            Arg::new("passes")
                .long("passes")
                .value_name("N")
                .value_parser(value_parser!(u32))
                .help("Argon2id passes (default 3, at most 10)"),
        )
}

pub(super) fn command() -> Command {
    Command::new("key")
        .about("Carry the key to another device, keep it encrypted on disk, show its public key")
        .subcommand_required(true)
        .subcommand(
            Command::new("export")
                .about("Write the key as text to a new private file, or print it")
                .arg(
                    Arg::new("out")
                        .long("out")
                        .value_name("FILE")
                        .value_parser(value_parser!(PathBuf))
                        .help("Write the text to this new file (never overwritten)"),
                )
                .arg(
                    Arg::new("print-secret")
                        .long("print-secret")
                        .action(ArgAction::SetTrue)
                        .help("Print the text; it is the key itself"),
                ),
        )
        .subcommand(
            Command::new("import")
                .about("Create the key file from a text made by `key export`")
                .arg(
                    Arg::new("from")
                        .long("from")
                        .value_name("FILE")
                        .value_parser(value_parser!(PathBuf))
                        .help("Read the text from this file (default: the standard input)"),
                ),
        )
        .subcommand(Command::new("public").about("Print the public key of the key"))
        .subcommand(cost_args(Command::new("encrypt").about(
            "Encrypt the key file under a password (asked twice on a terminal)",
        )))
        .subcommand(Command::new("decrypt").about("Make the encrypted key file plain again"))
        .subcommand(cost_args(
            Command::new("password")
                .about("Change the password of the encrypted key file")
                .arg(
                    Arg::new("new-password")
                        .long("new-password")
                        .value_name("PASSWORD")
                        .help("The new password; visible in process lists, so the weakest form"),
                )
                .arg(
                    Arg::new("new-password-file")
                        .long("new-password-file")
                        .value_name("FILE")
                        .value_parser(value_parser!(PathBuf))
                        .help("File with the new password (owner-only); or SHAAR_NEW_KEY_PASSWORD"),
                ),
        ))
}

/// The command a `key` invocation names (`sub` is the matches of `key` itself).
pub(super) fn parse(sub: &ArgMatches) -> KeyCommand {
    let (what, args) = sub.subcommand().expect("a subcommand is required");
    let cost = || CostArgs {
        memory_kib: args.get_one::<u32>("memory-kib").copied(),
        passes: args.get_one::<u32>("passes").copied(),
    };
    let passwords = PasswordArgs {
        password: args.get_one::<String>("password").cloned(),
        file: args.get_one::<PathBuf>("password-file").cloned(),
    };
    match what {
        "export" => KeyCommand::Export {
            out: args.get_one::<PathBuf>("out").cloned(),
            print_secret: args.get_flag("print-secret"),
            passwords,
        },
        "import" => KeyCommand::Import {
            from: args.get_one::<PathBuf>("from").cloned(),
        },
        "encrypt" => KeyCommand::Encrypt {
            cost: cost(),
            passwords,
        },
        "decrypt" => KeyCommand::Decrypt { passwords },
        "password" => KeyCommand::Password {
            cost: cost(),
            passwords,
            new_password: PasswordArgs {
                password: args.get_one::<String>("new-password").cloned(),
                file: args.get_one::<PathBuf>("new-password-file").cloned(),
            },
        },
        _ => KeyCommand::Public,
    }
}

/// Runs a `key` command on the key file; `Public` is answered by the caller, which prints the
/// same lines as `address`.
pub(super) async fn run(key_file: &Path, command: KeyCommand) -> Result<Vec<String>, String> {
    let password_error = |error: shaar::identity::IdentityError| format!("password: {error}");
    match command {
        KeyCommand::Export {
            out,
            print_secret,
            passwords,
        } => export_key(key_file, out.as_deref(), print_secret, passwords.sources()).await,
        KeyCommand::Import { from } => {
            let terminal = from.is_none() && std::io::stdin().is_terminal();
            if terminal {
                eprintln!("paste the key text and press Enter:");
            }
            let text = read_key_text(from, terminal).await?;
            import_key(key_file, &text).await
        }
        KeyCommand::Encrypt { cost, passwords } => {
            let password = obtain_new_password(
                passwords.sources(),
                shaar::identity::PASSWORD_ENV,
                "New key password: ",
            )
            .await
            .map_err(password_error)?;
            encrypt_key(key_file, &password, cost.cost()).await
        }
        KeyCommand::Decrypt { passwords } => {
            let password = obtain_password(passwords.sources(), "Key password: ")
                .await
                .map_err(password_error)?;
            decrypt_key(key_file, &password).await
        }
        KeyCommand::Password {
            cost,
            passwords,
            new_password,
        } => {
            let old = obtain_password(passwords.sources(), "Current key password: ")
                .await
                .map_err(password_error)?;
            let new = obtain_new_password(
                new_password.sources(),
                NEW_PASSWORD_ENV,
                "New key password: ",
            )
            .await
            .map_err(password_error)?;
            change_key_password(key_file, &old, &new, cost.cost()).await
        }
        KeyCommand::Public => Err("`key public` has no file operation".to_owned()),
    }
}
