//! `key export`, `key import` and `key public`: carry the Server's key to another device as text
//! (leaf KEY-1). The text is the key itself, so it is shown only with `--print-secret`, and an
//! import reads it from a file or the standard input, never from an argument.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use shaar::identity::{export_key, import_key, read_key_text};

/// What `key` does with the key file.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KeyCommand {
    Export {
        out: Option<PathBuf>,
        print_secret: bool,
    },
    Import {
        from: Option<PathBuf>,
    },
    Public,
}

pub(super) fn command() -> Command {
    Command::new("key")
        .about("Carry the key to another device: export it as text, import it, show its public key")
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
}

/// The command a `key` invocation names (`sub` is the matches of `key` itself).
pub(super) fn parse(sub: &ArgMatches) -> KeyCommand {
    let (what, args) = sub.subcommand().expect("a subcommand is required");
    match what {
        "export" => KeyCommand::Export {
            out: args.get_one::<PathBuf>("out").cloned(),
            print_secret: args.get_flag("print-secret"),
        },
        "import" => KeyCommand::Import {
            from: args.get_one::<PathBuf>("from").cloned(),
        },
        _ => KeyCommand::Public,
    }
}

/// Runs `export` or `import` on the key file; `Public` is answered by the caller, which prints
/// the same lines as `address`.
pub(super) async fn run(key_file: &Path, command: KeyCommand) -> Result<Vec<String>, String> {
    match command {
        KeyCommand::Export { out, print_secret } => {
            export_key(key_file, out.as_deref(), print_secret).await
        }
        KeyCommand::Import { from } => {
            let terminal = from.is_none() && std::io::stdin().is_terminal();
            if terminal {
                eprintln!("paste the key text and press Enter:");
            }
            let text = read_key_text(from, terminal).await?;
            import_key(key_file, &text).await
        }
        KeyCommand::Public => Err("`key public` has no file operation".to_owned()),
    }
}
