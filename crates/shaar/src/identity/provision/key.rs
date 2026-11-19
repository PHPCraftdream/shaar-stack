//! The key commands that both binaries share (leaf KEY-1): the text form of a key written to a
//! new owner-only file or shown on request, and a key file made from such a text. The seed is
//! printed only when the caller asks for it by name, and a text is never taken from an argument
//! (an argument stays in process lists and shell histories).

use std::fs::File;
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::PeerKey;
use crate::identity::{Identity, IdentityError, store};

/// The most bytes read for a key text: it takes at most 64 characters.
const MAX_INPUT: u64 = 256;

fn describe(error: &IdentityError, what: &str) -> String {
    match error {
        IdentityError::AlreadyExists => {
            format!("{what} already exists and was not overwritten")
        }
        other => other.to_string(),
    }
}

/// Exports the key in `key_file` as text: to a new owner-only file `out`, and/or as the returned
/// line when `print_secret`. With neither the command refuses, because the text is the key itself.
/// cancel-safe: NO — a running file write may finish after the waiter is dropped.
pub async fn export_key(
    key_file: &Path,
    out: Option<&Path>,
    print_secret: bool,
) -> Result<Vec<String>, String> {
    if out.is_none() && !print_secret {
        return Err(
            "the text is the key itself: choose --out FILE to write it to a new private file, or --print-secret to show it"
                .to_owned(),
        );
    }
    let identity = Identity::load(key_file)
        .await
        .map_err(|error| format!("key file: {}", describe(&error, "the key file")))?;
    let text = identity
        .export_text()
        .map_err(|error| format!("key text: {error}"))?;
    let mut lines = Vec::with_capacity(2);
    if let Some(out) = out {
        let path = out.to_path_buf();
        let bytes = text.clone();
        tokio::task::spawn_blocking(move || {
            store::create_private_new_blocking(&path, bytes.as_bytes())
        })
        .await
        .map_err(|error| format!("output file: {error}"))?
        .map_err(|error| format!("output file: {}", describe(&error, "the output file")))?;
        lines.push(format!("written: {}", out.display()));
    }
    if print_secret {
        lines.push(text.to_string());
    }
    Ok(lines)
}

/// Creates the key file `key_file` (and its directory, when missing) from the key `text`; an
/// existing file is never overwritten and a text that is not a key creates nothing. Returns the lines that name the imported key's public
/// identity, to compare with the other device.
/// cancel-safe: NO — a running file write may finish after the waiter is dropped.
pub async fn import_key(key_file: &Path, text: &str) -> Result<Vec<String>, String> {
    // A text that is not a key must not even create the directory.
    store::text::decode(text).map_err(|error| format!("import: {error}"))?;
    if let Some(parent) = key_file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        super::create_role_dir(parent)
            .await
            .map_err(|error| format!("import: {error}"))?;
    }
    let identity = Identity::import_text(key_file, text)
        .await
        .map_err(|error| format!("import: {}", describe(&error, "the key file")))?;
    let mut lines = vec![format!("imported: {}", key_file.display())];
    lines.extend(PeerKey::of(&identity).summary_lines().to_vec());
    Ok(lines)
}

/// Reads a key text from `from`, or from the standard input; with `line_only` (a terminal) one
/// line only, otherwise to the end. At most [`MAX_INPUT`] bytes are read.
/// cancel-safe: NO — a blocking read continues after the waiter is dropped.
pub async fn read_key_text(
    from: Option<PathBuf>,
    line_only: bool,
) -> Result<Zeroizing<String>, String> {
    tokio::task::spawn_blocking(move || read_blocking(from.as_deref(), line_only))
        .await
        .map_err(|error| format!("input: {error}"))?
}

fn read_blocking(from: Option<&Path>, line_only: bool) -> Result<Zeroizing<String>, String> {
    let mut text = Zeroizing::new(String::new());
    let read = match from {
        Some(path) => {
            File::open(path).and_then(|file| file.take(MAX_INPUT + 1).read_to_string(&mut text))
        }
        None => {
            let stdin = std::io::stdin().lock().take(MAX_INPUT + 1);
            read_from(stdin, line_only, &mut text)
        }
    };
    read.map_err(|error| format!("input: {error}"))?;
    if text.len() as u64 > MAX_INPUT {
        return Err("input: too long to be a key".to_owned());
    }
    Ok(text)
}

fn read_from(
    mut input: impl BufRead,
    line_only: bool,
    text: &mut String,
) -> std::io::Result<usize> {
    if line_only {
        input.read_line(text)
    } else {
        input.read_to_string(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::current_dir()
                .expect("current directory")
                .join("target/identity-key-fixtures")
                .join(format!(
                    "{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            std::fs::create_dir_all(&path).expect("fixture directory");
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn key_in(dir: &Fixture) -> (PathBuf, Identity) {
        let path = dir.join("key");
        let identity = Identity::create_new(&path).await.expect("create key");
        (path, identity)
    }

    #[tokio::test]
    async fn the_text_is_shown_only_when_asked_for_by_name() {
        let dir = Fixture::new();
        let (key, identity) = key_in(&dir).await;
        let refused = export_key(&key, None, false).await.unwrap_err();
        assert!(
            refused.contains("--print-secret") && refused.contains("--out"),
            "{refused}"
        );
        let shown = export_key(&key, None, true).await.unwrap();
        assert_eq!(shown, [identity.export_text().unwrap().to_string()]);
    }

    #[tokio::test]
    async fn the_text_is_written_to_a_new_private_file_that_imports_back() {
        let dir = Fixture::new();
        let (key, identity) = key_in(&dir).await;
        let out = dir.join("exported.txt");
        let lines = export_key(&key, Some(&out), false).await.unwrap();
        assert_eq!(lines.len(), 1, "no secret in the output: {lines:?}");
        assert!(lines[0].starts_with("written: "));
        let text = std::fs::read_to_string(&out).unwrap();
        assert_eq!(text, *identity.export_text().unwrap());
        let other = dir.join("other-key");
        let imported = import_key(&other, &text).await.unwrap();
        assert!(imported[0].starts_with("imported: "));
        assert!(
            imported.len() > 1,
            "the public identity is shown: {imported:?}"
        );
        let loaded = Identity::load(&other).await.unwrap();
        assert_eq!(loaded.public_key_bytes(), identity.public_key_bytes());
        let text = imported.join("\n");
        assert!(
            !text.contains(identity.export_text().unwrap().as_str()),
            "no secret"
        );
    }

    #[tokio::test]
    async fn an_existing_output_file_or_key_file_is_never_overwritten() {
        let dir = Fixture::new();
        let (key, identity) = key_in(&dir).await;
        let out = dir.join("taken.txt");
        std::fs::write(&out, "keep").unwrap();
        let error = export_key(&key, Some(&out), false).await.unwrap_err();
        assert!(error.contains("not overwritten"), "{error}");
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "keep");
        let text = identity.export_text().unwrap();
        let error = import_key(&key, &text).await.unwrap_err();
        assert!(error.contains("not overwritten"), "{error}");
        let still = Identity::load(&key).await.unwrap();
        assert_eq!(still.public_key_bytes(), identity.public_key_bytes());
    }

    #[tokio::test]
    async fn a_text_that_is_not_a_key_creates_no_file_and_the_error_has_no_text() {
        let dir = Fixture::new();
        let target = dir.join("never");
        let error = import_key(&target, "definitely-not-a-key")
            .await
            .unwrap_err();
        assert!(!target.exists());
        assert!(!error.contains("definitely"), "{error}");
        let missing = export_key(&dir.join("absent"), None, true)
            .await
            .unwrap_err();
        assert!(missing.starts_with("key file: "), "{missing}");
    }

    #[tokio::test]
    async fn an_import_creates_a_missing_directory_but_a_bad_text_creates_nothing() {
        let dir = Fixture::new();
        let text = Identity::generate().export_text().unwrap();
        let nested = dir.join("new/sub/key");
        import_key(&nested, &text).await.unwrap();
        assert!(Identity::load(&nested).await.is_ok());
        let never = dir.join("never");
        import_key(&never.join("key"), "garbage").await.unwrap_err();
        assert!(!never.exists(), "no directory for a text that is not a key");
    }

    #[tokio::test]
    async fn a_key_text_is_read_from_a_file_within_the_size_bound() {
        let dir = Fixture::new();
        let file = dir.join("text.txt");
        std::fs::write(&file, "abc\n").unwrap();
        assert_eq!(
            *read_key_text(Some(file.clone()), false).await.unwrap(),
            "abc\n"
        );
        std::fs::write(&file, "a".repeat(300)).unwrap();
        let error = read_key_text(Some(file), false).await.unwrap_err();
        assert!(error.contains("too long"), "{error}");
        let absent = read_key_text(Some(dir.join("absent")), false)
            .await
            .unwrap_err();
        assert!(absent.starts_with("input: "), "{absent}");
    }

    #[test]
    fn a_terminal_reads_one_line_and_a_pipe_reads_to_the_end() {
        let mut line = String::new();
        read_from(&b"first\nsecond\n"[..], true, &mut line).unwrap();
        assert_eq!(line, "first\n");
        let mut all = String::new();
        read_from(&b"first\nsecond\n"[..], false, &mut all).unwrap();
        assert_eq!(all, "first\nsecond\n");
    }
}
