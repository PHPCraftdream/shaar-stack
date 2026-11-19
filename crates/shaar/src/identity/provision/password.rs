//! Where the password of an encrypted key file comes from (leaf KEY-2). The sources are tried in
//! a fixed order and the first non-empty answer wins: the `--password` parameter, the environment
//! variable `SHAAR_KEY_PASSWORD`, the `--password-file` file (owner-only, like the key), one line
//! of the standard input when it is not a terminal, and a prompt on the terminal that does not
//! echo. With none of them the answer is `PasswordRequired`; nothing waits in the background.
//! A password in a parameter stays visible in process lists and shell histories: the file, the
//! environment variable and the standard input are the safer forms.

use std::fs::File;
use std::io::{BufRead, IsTerminal, Read};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::identity::{Identity, IdentityError, store};

/// The environment variable that holds the password.
pub const PASSWORD_ENV: &str = "SHAAR_KEY_PASSWORD";
/// The environment variable that holds the NEW password of `key password`.
pub const NEW_PASSWORD_ENV: &str = "SHAAR_NEW_KEY_PASSWORD";
/// The most bytes read for a password from a file or the standard input.
const MAX_PASSWORD: u64 = 1024;

/// The explicit sources: what the command line gave.
#[derive(Clone, Default)]
pub struct PasswordSources {
    /// The `--password` value; visible in process lists, so the weakest form.
    pub parameter: Option<Zeroizing<String>>,
    /// The `--password-file` path.
    pub file: Option<PathBuf>,
}

impl PasswordSources {
    /// Sources from what the command line gave: a password value and a password file.
    #[must_use]
    pub fn new(parameter: Option<String>, file: Option<PathBuf>) -> Self {
        Self {
            parameter: parameter.map(Zeroizing::new),
            file,
        }
    }
}

impl std::fmt::Debug for PasswordSources {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("PasswordSources")
            .field("parameter", &self.parameter.as_ref().map(|_| "<redacted>"))
            .field("file", &self.file)
            .finish()
    }
}

/// The password to open an encrypted key file with, from the first source that has one;
/// `prompt` is the text shown before the terminal asks.
/// cancel-safe: NO - a blocking read continues after the waiter is dropped.
pub async fn obtain_password(
    sources: PasswordSources,
    prompt: &'static str,
) -> Result<Zeroizing<String>, IdentityError> {
    obtain(sources, PASSWORD_ENV, prompt, false).await
}

/// A NEW password to set: from the same kinds of source, in the same order, with `env` as the
/// environment variable; a terminal asks twice and refuses two different answers.
/// cancel-safe: NO - see [`obtain_password`].
pub async fn obtain_new_password(
    sources: PasswordSources,
    env: &'static str,
    prompt: &'static str,
) -> Result<Zeroizing<String>, IdentityError> {
    obtain(sources, env, prompt, true).await
}

async fn obtain(
    sources: PasswordSources,
    env_name: &'static str,
    prompt: &'static str,
    confirm: bool,
) -> Result<Zeroizing<String>, IdentityError> {
    tokio::task::spawn_blocking(move || {
        let mismatch = std::cell::Cell::new(false);
        let answer = resolve(
            &sources,
            env_name,
            &|name| std::env::var(name).ok(),
            &mut stdin_line,
            &mut || {
                let first = terminal_password(prompt)?;
                if confirm {
                    let again = terminal_password("Repeat the password: ")?;
                    if *again != *first {
                        mismatch.set(true);
                        return None;
                    }
                }
                Some(first)
            },
        );
        match answer {
            Err(IdentityError::PasswordRequired) if mismatch.get() => {
                Err(IdentityError::PasswordMismatch)
            }
            other => other,
        }
    })
    .await
    .map_err(|error| IdentityError::Io(std::io::Error::other(error)))?
}

/// The message for a key file that did not load: a password problem is named, anything else stays
/// generic so that no file detail reaches the output.
#[must_use]
pub fn key_load_message(error: &IdentityError) -> String {
    match error {
        IdentityError::PasswordRequired
        | IdentityError::WrongPassword
        | IdentityError::PasswordMismatch => {
            format!("could not load configured identity key: {error}")
        }
        _ => "could not load configured identity key".to_owned(),
    }
}

static INSTALLED: std::sync::OnceLock<PasswordSources> = std::sync::OnceLock::new();

/// Installs the password sources that [`load_unlocked_default`] uses for the rest of the process:
/// the binaries do it once, from their command line. A second call changes nothing.
pub fn install_password_sources(sources: PasswordSources) {
    let _ = INSTALLED.set(sources);
}

/// The installed password sources, or none when none were installed.
#[must_use]
pub fn installed_password_sources() -> PasswordSources {
    INSTALLED.get().cloned().unwrap_or_default()
}

/// [`load_unlocked`] with the installed sources, or with none installed, the environment, the
/// standard input and the terminal.
/// cancel-safe: NO - see [`Identity::load_with_password`].
pub async fn load_unlocked_default(
    path: impl Into<PathBuf>,
    prompt: &'static str,
) -> Result<Identity, IdentityError> {
    load_unlocked(path, installed_password_sources(), prompt).await
}

/// Loads the key file at `path`; when it is encrypted, asks for its password from `sources`.
/// cancel-safe: NO — see [`Identity::load_with_password`].
pub async fn load_unlocked(
    path: impl Into<PathBuf>,
    sources: PasswordSources,
    prompt: &'static str,
) -> Result<Identity, IdentityError> {
    let path = path.into();
    match Identity::load(path.clone()).await {
        Err(IdentityError::PasswordRequired) => {
            let password = obtain_password(sources, prompt).await?;
            Identity::load_with_password(path, &password).await
        }
        other => other,
    }
}

/// The ordering of the sources with every outside input passed in, so that it can be tested.
fn resolve(
    sources: &PasswordSources,
    env_name: &str,
    env: &dyn Fn(&str) -> Option<String>,
    stdin: &mut dyn FnMut() -> Option<Zeroizing<String>>,
    terminal: &mut dyn FnMut() -> Option<Zeroizing<String>>,
) -> Result<Zeroizing<String>, IdentityError> {
    if let Some(parameter) = sources.parameter.as_ref().filter(|text| !text.is_empty()) {
        return Ok(parameter.clone());
    }
    if let Some(text) = env(env_name)
        .map(Zeroizing::new)
        .filter(|text| !text.is_empty())
    {
        return Ok(text);
    }
    if let Some(path) = &sources.file {
        let text = read_password_file(path)?;
        if !text.is_empty() {
            return Ok(text);
        }
    }
    if let Some(text) = stdin().filter(|text| !text.is_empty()) {
        return Ok(text);
    }
    terminal()
        .filter(|text| !text.is_empty())
        .ok_or(IdentityError::PasswordRequired)
}

/// The password in a file with the rights of a key file, without its line end.
fn read_password_file(path: &Path) -> Result<Zeroizing<String>, IdentityError> {
    let file = File::open(path).map_err(IdentityError::from)?;
    store::check_private_file(&file)?;
    let mut text = Zeroizing::new(String::new());
    file.take(MAX_PASSWORD + 1)
        .read_to_string(&mut text)
        .map_err(|_| IdentityError::InvalidFormat)?;
    if text.len() as u64 > MAX_PASSWORD {
        return Err(IdentityError::InvalidFormat);
    }
    Ok(trim_line_end(text))
}

fn trim_line_end(mut text: Zeroizing<String>) -> Zeroizing<String> {
    while text.ends_with(['\n', '\r']) {
        text.pop();
    }
    text
}

/// One line of the standard input, only when it is not a terminal.
fn stdin_line() -> Option<Zeroizing<String>> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return None;
    }
    let mut line = Zeroizing::new(String::new());
    stdin.lock().take(MAX_PASSWORD).read_line(&mut line).ok()?;
    Some(trim_line_end(line))
}

/// The password typed on the terminal, which does not echo it; `None` without a terminal.
fn terminal_password(prompt: &str) -> Option<Zeroizing<String>> {
    if !std::io::stdin().is_terminal() {
        return None;
    }
    rpassword::prompt_password(prompt).ok().map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: &str) -> Zeroizing<String> {
        Zeroizing::new(value.to_owned())
    }

    fn sources(parameter: Option<&str>) -> PasswordSources {
        PasswordSources {
            parameter: parameter.map(text),
            file: None,
        }
    }

    /// Runs `resolve` with the given outside answers and reports which sources were asked.
    fn run(
        sources: &PasswordSources,
        env: Option<&str>,
        stdin: Option<&str>,
        terminal: Option<&str>,
    ) -> (Result<String, IdentityError>, Vec<&'static str>) {
        let asked = std::cell::RefCell::new(Vec::new());
        let result = resolve(
            sources,
            PASSWORD_ENV,
            &|name| {
                assert_eq!(name, PASSWORD_ENV);
                asked.borrow_mut().push("env");
                env.map(str::to_owned)
            },
            &mut || {
                asked.borrow_mut().push("stdin");
                stdin.map(text)
            },
            &mut || {
                asked.borrow_mut().push("terminal");
                terminal.map(text)
            },
        );
        (
            result.map(|password| password.to_string()),
            asked.into_inner(),
        )
    }

    #[test]
    fn the_parameter_wins_and_nothing_else_is_asked() {
        let (password, asked) = run(
            &sources(Some("param")),
            Some("env"),
            Some("in"),
            Some("tty"),
        );
        assert_eq!(password.unwrap(), "param");
        assert!(asked.is_empty(), "{asked:?}");
    }

    #[test]
    fn the_sources_are_tried_in_the_fixed_order() {
        let (password, asked) = run(&sources(None), Some("env"), Some("in"), Some("tty"));
        assert_eq!((password.unwrap().as_str(), asked), ("env", vec!["env"]));
        let (password, asked) = run(&sources(None), None, Some("in"), Some("tty"));
        assert_eq!(
            (password.unwrap().as_str(), asked),
            ("in", vec!["env", "stdin"])
        );
        let (password, asked) = run(&sources(None), None, None, Some("tty"));
        assert_eq!(
            (password.unwrap().as_str(), asked),
            ("tty", vec!["env", "stdin", "terminal"])
        );
    }

    #[test]
    fn an_empty_answer_is_no_answer_and_with_none_the_password_is_required() {
        let (password, asked) = run(&sources(Some("")), Some(""), Some(""), Some(""));
        assert!(matches!(password, Err(IdentityError::PasswordRequired)));
        assert_eq!(asked, ["env", "stdin", "terminal"]);
        let (password, _) = run(&sources(None), None, None, None);
        assert!(matches!(password, Err(IdentityError::PasswordRequired)));
    }

    #[test]
    fn a_password_file_comes_between_the_environment_and_the_standard_input() {
        let dir = std::env::current_dir()
            .unwrap()
            .join("target/identity-password-fixtures")
            .join(std::process::id().to_string());
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("password");
        crate::identity::store::create_private_new_blocking(&path, b"from file\r\n").unwrap();
        let with_file = PasswordSources {
            parameter: None,
            file: Some(path.clone()),
        };
        let (password, asked) = run(&with_file, None, Some("in"), Some("tty"));
        assert_eq!(
            (password.unwrap().as_str(), asked),
            ("from file", vec!["env"])
        );
        let (password, asked) = run(&with_file, Some("env"), Some("in"), None);
        assert_eq!((password.unwrap().as_str(), asked), ("env", vec!["env"]));
        let missing = PasswordSources {
            parameter: None,
            file: Some(dir.join("absent")),
        };
        let (password, _) = run(&missing, None, Some("in"), None);
        assert!(
            matches!(password, Err(IdentityError::Io(_))),
            "a named file that is missing is an error"
        );
        std::fs::write(&path, vec![b'a'; 2000]).unwrap();
        let (password, _) = run(&with_file, None, None, None);
        assert!(matches!(password, Err(IdentityError::InvalidFormat)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_debug_form_does_not_show_the_parameter() {
        let shown = format!("{:?}", sources(Some("hunter2")));
        assert!(!shown.contains("hunter2"), "{shown}");
    }

    #[test]
    fn line_ends_are_trimmed_from_the_end_only() {
        assert_eq!(*trim_line_end(text("pw\r\n")), "pw");
        assert_eq!(*trim_line_end(text("p\nw\n")), "p\nw");
        assert_eq!(*trim_line_end(text(" pw ")), " pw ");
    }
}
