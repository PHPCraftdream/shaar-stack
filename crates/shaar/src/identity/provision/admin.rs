//! Editing of configuration files for the command line: set, unset or switch the
//! network shape of one top-level key while every comment of the file survives.
//!
//! The file is first normalised by `ktav::format_str` (comments and grouping blanks are
//! kept, compounds get their block form), so a top-level entry is one line or a block that
//! ends with `}` or `]` in column 0. The edited text must pass the schema of its role
//! before it is returned.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use super::Role;
use super::network::{NetworkChoice, public_network_text};
use crate::config::{
    ClientConfig, ClientOverrides, ConfigError, ServerConfig, ServerOverrides, ValidationKind,
};

/// Keys `set`/`unset` may touch, per role. Compound settings go through
/// [`set_config_network`].
const SERVER_KEYS: [&str; 7] = [
    "target",
    "bind",
    "key_file",
    "allowlist_path",
    "fallback",
    "publish_address",
    "address_key_file",
];
const CLIENT_KEYS: [&str; 6] = [
    "server",
    "server_address",
    "listen",
    "key_file",
    "fallback",
    "address_key_file",
];

/// RFC 8032 test-vector public key: lets a client file without `server` be edited.
const PLACEHOLDER_SERVER: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
/// Loopback target that lets a server file without `target` be edited.
const PLACEHOLDER_TARGET: &str = "127.0.0.1:1";

/// Why a configuration edit was refused; never carries a value of the file.
#[derive(Debug)]
pub enum ConfigEditError {
    /// The key is not an editable setting of this role.
    UnknownKey,
    /// The value contains a control character and cannot be one line.
    ControlCharacter,
    /// The file is not valid ktav text.
    Syntax,
    /// The edited file would be invalid; nothing was changed.
    Invalid(ConfigError),
}

impl fmt::Display for ConfigEditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKey => f.write_str("not an editable setting of this role"),
            Self::ControlCharacter => f.write_str("a value contains a control character"),
            Self::Syntax => f.write_str("the file is not valid ktav text"),
            Self::Invalid(error) => write!(f, "the result would be invalid: {error}"),
        }
    }
}

impl std::error::Error for ConfigEditError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invalid(error) => Some(error),
            _ => None,
        }
    }
}

/// Validates a configuration text against the schema of `role`. A strict check wants every
/// required value; the lenient one lets a file without `target` (Server) or `server`
/// (Client) pass, so such a file can still be edited step by step.
pub fn check_config_text(role: Role, text: &str, strict: bool) -> Result<(), ConfigError> {
    match (check(role, text, false), strict) {
        (
            Err(ConfigError::Validation {
                kind: ValidationKind::MissingRequired,
                ..
            }),
            false,
        ) => check(role, text, true),
        (result, _) => result,
    }
}

fn check(role: Role, text: &str, placeholder: bool) -> Result<(), ConfigError> {
    match role {
        Role::Server => {
            let over = ServerOverrides {
                target: placeholder.then(|| PLACEHOLDER_TARGET.to_owned()),
                ..ServerOverrides::default()
            };
            ServerConfig::from_text(text, &over).map(|_| ())
        }
        Role::Client => {
            let over = ClientOverrides {
                server: placeholder.then(|| PLACEHOLDER_SERVER.to_owned()),
                ..ClientOverrides::default()
            };
            ClientConfig::from_text(text, &over).map(|_| ())
        }
    }
}

fn editable(role: Role, key: &str) -> bool {
    match role {
        Role::Server => SERVER_KEYS.contains(&key),
        Role::Client => CLIENT_KEYS.contains(&key),
    }
}

/// The settings `set` and `unset` accept for `role`.
pub fn editable_keys(role: Role) -> &'static [&'static str] {
    match role {
        Role::Server => &SERVER_KEYS,
        Role::Client => &CLIENT_KEYS,
    }
}

/// Sets one top-level key to a literal string value, keeping the rest of the file.
pub fn set_config_value(
    role: Role,
    text: &str,
    key: &str,
    value: &str,
) -> Result<String, ConfigEditError> {
    if !editable(role, key) {
        return Err(ConfigEditError::UnknownKey);
    }
    if value.chars().any(char::is_control) {
        return Err(ConfigEditError::ControlCharacter);
    }
    edit(role, text, key, Some(format!("{key}:: {value}\n")))
}

/// Removes one top-level key; a missing key is not an error.
pub fn unset_config_key(role: Role, text: &str, key: &str) -> Result<String, ConfigEditError> {
    if !editable(role, key) {
        return Err(ConfigEditError::UnknownKey);
    }
    edit(role, text, key, None)
}

/// Replaces the `network` object by the public defaults, or removes it.
pub fn set_config_network(
    role: Role,
    text: &str,
    choice: NetworkChoice,
) -> Result<String, ConfigEditError> {
    let replacement = match choice {
        NetworkChoice::Public => Some(public_network_text().to_owned()),
        NetworkChoice::Private => None,
    };
    edit(role, text, "network", replacement)
}

fn edit(
    role: Role,
    text: &str,
    key: &str,
    replacement: Option<String>,
) -> Result<String, ConfigEditError> {
    let normalised = ktav::format_str(text).map_err(|_| ConfigEditError::Syntax)?;
    let lines: Vec<&str> = normalised.split_inclusive('\n').collect();
    let mut out = String::with_capacity(normalised.len() + 64);
    match entry_span(&lines, key) {
        Some((start, end)) => {
            // The comment header `init` writes above the network object belongs to it.
            let start = if key == "network" {
                generated_header_start(&lines, start)
            } else {
                start
            };
            lines[..start].iter().for_each(|line| out.push_str(line));
            if let Some(new) = &replacement {
                out.push_str(new);
            }
            lines[end..].iter().for_each(|line| out.push_str(line));
        }
        None => {
            out.push_str(&normalised);
            if let Some(new) = &replacement {
                if !out.is_empty() && !out.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str(new);
            }
        }
    }
    check_config_text(role, &out, false).map_err(ConfigEditError::Invalid)?;
    Ok(out)
}

/// Moves `start` up over the comment header of the generated public network text, when the
/// lines right above it are exactly that header.
fn generated_header_start(lines: &[&str], start: usize) -> usize {
    let header: Vec<&str> = public_network_text()
        .lines()
        .take_while(|line| line.starts_with("##"))
        .collect();
    let Some(first) = start.checked_sub(header.len()) else {
        return start;
    };
    let same = lines[first..start]
        .iter()
        .zip(&header)
        .all(|(line, expected)| line.trim_end() == *expected);
    if same { first } else { start }
}

/// The lines `[start, end)` of the top-level entry `key`: its own line, or the block up to
/// the closing `}` / `]` in column 0.
fn entry_span(lines: &[&str], key: &str) -> Option<(usize, usize)> {
    let start = lines.iter().position(|line| {
        line.strip_prefix(key)
            .is_some_and(|rest| rest.starts_with(':'))
    })?;
    let first = lines[start].trim_end();
    let closer = if first.ends_with('{') {
        "}"
    } else if first.ends_with('[') {
        "]"
    } else {
        return Some((start, start + 1));
    };
    let end = lines[start + 1..]
        .iter()
        .position(|line| line.trim_end() == closer)
        .map(|offset| start + 1 + offset + 1)?;
    Some((start, end))
}

/// Writes `text` to `path` through a temporary file in the same directory and a rename, so
/// a reader never sees a half-written file; the previous content is kept as `<path>.bak`
/// when `backup` is set.
pub async fn write_replacing(path: &Path, text: String, backup: bool) -> io::Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let sibling = |suffix: &str| -> PathBuf {
            let mut name = path.file_name().unwrap_or_default().to_os_string();
            name.push(suffix);
            path.with_file_name(name)
        };
        if backup && path.exists() {
            std::fs::copy(&path, sibling(".bak"))?;
        }
        let temporary = sibling(".tmp");
        let _ = std::fs::remove_file(&temporary);
        std::fs::write(&temporary, text)?;
        std::fs::rename(&temporary, &path)
    })
    .await
    .map_err(io::Error::other)?
}

/// One `config` subcommand of the binaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigAction {
    /// Print the file.
    Show,
    /// Validate the file and the files it names (identity key, allowlist).
    Check,
    /// Set a top-level key to a literal string.
    Set { key: String, value: String },
    /// Remove a top-level key.
    Unset { key: String },
    /// Switch the network shape.
    Network(NetworkChoice),
}

/// Runs one `config` subcommand on the configuration file at `path` and returns the lines
/// to print; the error text is ready to print and names fields, never values.
/// cancel-safe: NO — a write that already started completes after cancellation.
pub async fn config_command(
    role: Role,
    path: &Path,
    action: ConfigAction,
) -> Result<Vec<String>, String> {
    let text = read_text(path).await?;
    let shown = path.display();
    let (key, edited) = match action {
        ConfigAction::Show => return Ok(text.lines().map(str::to_owned).collect()),
        ConfigAction::Check => return check_command(role, path, &text).await,
        ConfigAction::Set { key, value } => {
            (key.clone(), set_config_value(role, &text, &key, &value))
        }
        ConfigAction::Unset { key } => (key.clone(), unset_config_key(role, &text, &key)),
        ConfigAction::Network(choice) => (
            "network".to_owned(),
            set_config_network(role, &text, choice),
        ),
    };
    let edited = edited.map_err(|error| format!("{key}: {error}"))?;
    if edited == text {
        return Ok(vec![format!("unchanged: {shown}")]);
    }
    write_replacing(path, edited, true)
        .await
        .map_err(|_| "could not write the configuration".to_owned())?;
    Ok(vec![
        format!("updated: {shown}"),
        format!("previous content kept as {shown}.bak"),
    ])
}

async fn check_command(role: Role, path: &Path, text: &str) -> Result<Vec<String>, String> {
    check_config_text(role, text, true).map_err(|error| format!("configuration: {error}"))?;
    let key_file = match role {
        Role::Server => {
            let over = ServerOverrides {
                target: Some(PLACEHOLDER_TARGET.to_owned()),
                ..ServerOverrides::default()
            };
            let config = ServerConfig::from_text(text, &over).map_err(|e| e.to_string())?;
            config.key_file().to_path_buf()
        }
        Role::Client => {
            let over = ClientOverrides {
                server: Some(PLACEHOLDER_SERVER.to_owned()),
                ..ClientOverrides::default()
            };
            let config = ClientConfig::from_text(text, &over).map_err(|e| e.to_string())?;
            config.key_file().to_path_buf()
        }
    };
    let identity = crate::identity::Identity::load(key_file)
        .await
        .map_err(|_| "could not load configured identity key".to_owned())?;
    let mut lines = vec![format!("ok: {}", path.display())];
    if role == Role::Server {
        lines.push(format!(
            "public_key={}",
            crate::startup::facade::PeerKey::of(&identity)
        ));
    }
    Ok(lines)
}

/// Reads a configuration file with the same size bound as loading it.
async fn read_text(path: &Path) -> Result<String, String> {
    use tokio::io::AsyncReadExt;
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| "could not read the configuration".to_owned())?;
    let mut text = String::new();
    file.take((crate::config::MAX_CONFIG_BYTES + 1) as u64)
        .read_to_string(&mut text)
        .await
        .map_err(|_| "could not read the configuration".to_owned())?;
    if text.len() > crate::config::MAX_CONFIG_BYTES {
        return Err("configuration exceeds size limit".to_owned());
    }
    Ok(text)
}
