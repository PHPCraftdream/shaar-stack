//! First-run provisioning: per-role data directory, private identity key,
//! and never-rewritten configuration files for the server and client
//! binaries.
//!
//! # File contract
//!
//! Provisioning never overwrites existing files: an existing directory,
//! key file, config file, or allowlist is left byte-for-byte untouched and
//! reported as [`FileState::Kept`]. Config files are plain ktav 0.8 text so
//! the user can edit them freely; the binaries re-read them at startup.
//!
//! # Environment resolution
//!
//! [`resolve_data_dir`] never reads the process environment itself; the
//! caller injects an env accessor, keeping the resolution unit-testable
//! without process-global state.
//!
//! # Secret handling
//!
//! Key material lives only in [`Identity`]; error messages and reports
//! never contain seed or key bytes.

mod network;
#[cfg(test)]
mod network_tests;
#[cfg(test)]
mod tests;

pub use network::{NetworkChoice, public_network_text};

use std::fmt;
use std::path::{Path, PathBuf};

use tokio::io::AsyncWriteExt;

use crate::identity::Identity;
use crate::identity::IdentityError;

/// Which binary role a data directory is provisioned for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Server,
    Client,
}

/// The concrete file layout produced by [`provision`] for one role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionPaths {
    /// `<base>/server` or `<base>/client`.
    pub dir: PathBuf,
    /// `server.ktav` or `client.ktav` inside [`ProvisionPaths::dir`].
    pub config: PathBuf,
    /// `shaar.key` inside [`ProvisionPaths::dir`].
    pub key: PathBuf,
    /// `allowed.txt` inside [`ProvisionPaths::dir`]; `Some` for
    /// [`Role::Server`], `None` for [`Role::Client`].
    pub allowlist: Option<PathBuf>,
}

/// Whether a provisioned file was newly created or already existed (kept).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileState {
    Created,
    Kept,
}

/// What [`provision`] did: which files were created vs. kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionReport {
    pub paths: ProvisionPaths,
    pub dir: FileState,
    pub config: FileState,
    pub key: FileState,
    pub allowlist: Option<FileState>,
}

/// The identity plus the report from a successful provisioning run.
#[derive(Debug)]
pub struct Provisioned {
    pub identity: Identity,
    pub report: ProvisionReport,
}

/// Errors from first-run provisioning. No variant ever carries key material.
#[derive(Debug)]
pub enum ProvisionError {
    /// A filesystem operation failed; `context` names the operation.
    Io {
        context: &'static str,
        source: std::io::Error,
    },
    /// The data dir or an embedded path is not representable as UTF-8 text.
    PathNotUtf8,
    /// A path contains ASCII control characters, which would break the
    /// single-line ktav config values.
    PathControlChars,
    /// No per-user data directory could be resolved; names the missing env var.
    MissingEnv(&'static str),
    /// The identity key file operation failed.
    Key(IdentityError),
}

impl fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { context, source } => write!(f, "{context}: {source}"),
            Self::PathNotUtf8 => write!(f, "path is not valid UTF-8"),
            Self::PathControlChars => {
                write!(f, "path contains control characters")
            }
            Self::MissingEnv(name) => {
                if cfg!(windows) {
                    write!(f, "no per-user data directory: set {name}")
                } else {
                    write!(f, "no per-user data directory: set HOME or XDG_DATA_HOME")
                }
            }
            Self::Key(e) => write!(f, "identity key error: {e}"),
        }
    }
}

impl std::error::Error for ProvisionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Key(e) => Some(e),
            _ => None,
        }
    }
}

impl From<IdentityError> for ProvisionError {
    fn from(e: IdentityError) -> Self {
        Self::Key(e)
    }
}

/// `<base>/server` or `<base>/client`.
pub fn role_dir(base: &Path, role: Role) -> PathBuf {
    match role {
        Role::Server => base.join("server"),
        Role::Client => base.join("client"),
    }
}

/// Resolves the per-user data directory from the injected env accessor.
///
/// Platform rules (empty values count as unset):
/// - Windows: `%LOCALAPPDATA%\shaar`; missing/empty `LOCALAPPDATA` is an
///   error (`APPDATA` is never read, so the key never lands in the roaming
///   profile).
/// - Unix: `$XDG_DATA_HOME/shaar` when `XDG_DATA_HOME` is non-empty AND
///   absolute (a relative value is ignored per the XDG spec); else
///   `$HOME/.local/share/shaar`; else an error.
pub fn resolve_data_dir(
    env: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<PathBuf, ProvisionError> {
    let non_empty = |name: &str| -> Option<PathBuf> {
        match env(name) {
            Some(v) if !v.is_empty() => Some(PathBuf::from(v)),
            _ => None,
        }
    };
    #[cfg(windows)]
    {
        non_empty("LOCALAPPDATA")
            .map(|p| p.join("shaar"))
            .ok_or(ProvisionError::MissingEnv("LOCALAPPDATA"))
    }
    #[cfg(not(windows))]
    {
        if let Some(xdg) = non_empty("XDG_DATA_HOME")
            && xdg.is_absolute()
        {
            return Ok(xdg.join("shaar"));
        }
        non_empty("HOME")
            .map(|home| home.join(".local/share/shaar"))
            .ok_or(ProvisionError::MissingEnv("HOME"))
    }
}

/// Resolves the per-user data directory from the real process environment.
pub fn default_data_dir() -> Result<PathBuf, ProvisionError> {
    resolve_data_dir(|name| std::env::var_os(name))
}

/// Validates a path for embedding as a single-line ktav config value.
pub fn path_as_config_value(path: &Path) -> Result<&str, ProvisionError> {
    let text = path.to_str().ok_or(ProvisionError::PathNotUtf8)?;
    if text.chars().any(char::is_control) {
        return Err(ProvisionError::PathControlChars);
    }
    Ok(text)
}

/// The exact server configuration template for the given paths.
pub fn server_config_text(paths: &ProvisionPaths) -> String {
    let key = path_as_config_value(&paths.key).expect("provision validated paths before writing");
    let allowlist = path_as_config_value(
        paths
            .allowlist
            .as_deref()
            .expect("server paths have allowlist"),
    )
    .expect("provision validated paths before writing");
    format!(
        "## Sha'ar Server configuration (ktav 0.8), generated by the first run.\n\
         ## The binary never rewrites this file; edit it freely.\n\
         ## Set the local TCP service to forward to by adding one line, for example:\n\
         ## target: 127.0.0.1:8080\n\
         ## Or run: shaar-server 127.0.0.1:8080\n\
         key_file:: {key}\n\
         allowlist_path:: {allowlist}\n"
    )
}

/// The exact client configuration text for the given paths and optional
/// server pin values.
///
/// The `::` form is mandatory on the `server` and `server_address` lines so
/// an all-decimal-digit key string still classifies as a ktav String.
pub fn client_config_text(
    paths: &ProvisionPaths,
    server_key: Option<&str>,
    server_address: Option<&str>,
) -> String {
    let key = path_as_config_value(&paths.key).expect("provision validated paths before writing");
    let mut text = format!(
        "## Sha'ar Client configuration (ktav 0.8), generated by the first run.\n\
         ## The binary never rewrites this file; edit it freely.\n\
         ## client: the server key pins the server; server_address is required today\n\
         ## (direct-only first run); both may also be given on the command line.\n\
         key_file:: {key}\n"
    );
    if let Some(server_key) = server_key {
        text.push_str(&format!("server:: {server_key}\n"));
    }
    if let Some(server_address) = server_address {
        text.push_str(&format!("server_address:: {server_address}\n"));
    }
    text
}

/// The allowlist file template: an empty allowlist denies every client.
pub fn allowlist_template_text() -> &'static str {
    "## Sha'ar allowlist: one client public key per line (64 hex characters).\n\
     ## Empty lines and lines starting with # are ignored.\n\
     ## An empty allowlist denies every client.\n\
     ## Append a client key as one line, then RESTART the server: the file is\n\
     ## read once at startup.\n"
}

/// Writes `text` to `path` only if the file does not exist; returns whether
/// it was created.
async fn write_if_missing(path: PathBuf, text: &str) -> Result<FileState, ProvisionError> {
    if tokio::fs::metadata(&path).await.is_ok() {
        return Ok(FileState::Kept);
    }
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .await
        .map_err(|e| ProvisionError::Io {
            context: "create config file",
            source: e,
        })?;
    file.write_all(text.as_bytes())
        .await
        .map_err(|e| ProvisionError::Io {
            context: "write config file",
            source: e,
        })?;
    file.sync_all().await.map_err(|e| ProvisionError::Io {
        context: "sync config file",
        source: e,
    })?;
    Ok(FileState::Created)
}

/// Creates the role directory if missing. Unix: 0o700 via `DirBuilder` with
/// `recursive(true)`. Windows: `create_dir_all` inherits the per-user
/// profile ACL. An existing directory is kept WITHOUT chmod — permissions of
/// an existing directory are never silently fixed.
async fn create_role_dir(dir: &Path) -> Result<FileState, ProvisionError> {
    if tokio::fs::metadata(dir).await.is_ok() {
        return Ok(FileState::Kept);
    }
    let owned = dir.to_path_buf();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        tokio::task::spawn_blocking(move || {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&owned)
        })
        .await
        .map_err(|e| ProvisionError::Io {
            context: "join directory creation",
            source: std::io::Error::other(e),
        })?
        .map_err(|e| ProvisionError::Io {
            context: "create data directory",
            source: e,
        })?;
    }
    #[cfg(not(unix))]
    {
        // Windows: create_dir_all inherits the per-user profile ACL of the
        // parent; no explicit DACL work is performed here.
        tokio::task::spawn_blocking(move || std::fs::create_dir_all(&owned))
            .await
            .map_err(|e| ProvisionError::Io {
                context: "join directory creation",
                source: std::io::Error::other(e),
            })?
            .map_err(|e| ProvisionError::Io {
                context: "create data directory",
                source: e,
            })?;
    }
    Ok(FileState::Created)
}

/// Provisions one role's first-run layout under `base` with a direct-only
/// configuration: [`provision_with`] and [`NetworkChoice::Private`].
pub async fn provision(
    role: Role,
    base: &Path,
    server_key: Option<&str>,
    server_address: Option<&str>,
) -> Result<Provisioned, ProvisionError> {
    provision_with(
        role,
        base,
        server_key,
        server_address,
        NetworkChoice::Private,
    )
    .await
}

/// Provisions one role's layout under `base`.
///
/// Validates the embedded paths BEFORE any filesystem write, creates the
/// role directory (0o700 on Unix), loads-or-creates the identity key, and
/// writes the config (and, for the server, the allowlist) only when missing.
/// `network` decides whether a new config carries the public `network`
/// object. Existing files are never overwritten.
pub async fn provision_with(
    role: Role,
    base: &Path,
    server_key: Option<&str>,
    server_address: Option<&str>,
    network: NetworkChoice,
) -> Result<Provisioned, ProvisionError> {
    let dir = role_dir(base, role);
    let config = dir.join(match role {
        Role::Server => "server.ktav",
        Role::Client => "client.ktav",
    });
    let key = dir.join("shaar.key");
    let allowlist = match role {
        Role::Server => Some(dir.join("allowed.txt")),
        Role::Client => None,
    };
    let paths = ProvisionPaths {
        dir: dir.clone(),
        config: config.clone(),
        key: key.clone(),
        allowlist: allowlist.clone(),
    };
    // Validate every embedded path before any filesystem side effect.
    for p in [&dir, &config, &key] {
        path_as_config_value(p)?;
    }
    if let Some(a) = &allowlist {
        path_as_config_value(a)?;
    }
    let dir_state = create_role_dir(&dir).await?;
    let key_existed = tokio::fs::metadata(&key).await.is_ok();
    let identity = Identity::load_or_create(&key)
        .await
        .map_err(ProvisionError::Key)?;
    let key_state = if key_existed {
        FileState::Kept
    } else {
        FileState::Created
    };
    let mut config_text = match role {
        Role::Server => server_config_text(&paths),
        Role::Client => client_config_text(&paths, server_key, server_address),
    };
    network::append(&mut config_text, network);
    let config_state = write_if_missing(config, &config_text).await?;
    let allowlist_state = match &allowlist {
        Some(a) => Some(write_if_missing(a.clone(), allowlist_template_text()).await?),
        None => None,
    };
    Ok(Provisioned {
        identity,
        report: ProvisionReport {
            paths,
            dir: dir_state,
            config: config_state,
            key: key_state,
            allowlist: allowlist_state,
        },
    })
}

/// Human-readable first-run summary lines (no trailing newlines).
pub fn first_run_summary_lines(
    role: Role,
    report: &ProvisionReport,
    identity: &Identity,
) -> Vec<String> {
    let word = |state: FileState| match state {
        FileState::Created => "created",
        FileState::Kept => "kept",
    };
    let hex: String = identity
        .public_key_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut lines = vec![format!(
        "first run data directory: {} ({})",
        report.paths.dir.to_string_lossy(),
        match report.dir {
            FileState::Created => "created",
            FileState::Kept => "reused",
        }
    )];
    lines.push(format!(
        "{}: {}",
        word(report.config),
        report.paths.config.to_string_lossy()
    ));
    lines.push(format!(
        "{}: {}",
        word(report.key),
        report.paths.key.to_string_lossy()
    ));
    if role == Role::Server
        && let (Some(state), Some(path)) = (report.allowlist, report.paths.allowlist.as_deref())
    {
        lines.push(format!("{}: {}", word(state), path.to_string_lossy()));
    }
    lines.push(format!("public_key={hex}"));
    lines
}
