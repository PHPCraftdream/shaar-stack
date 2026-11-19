//! The key commands that both binaries share (leaf KEY-1): the text form of a key written to a
//! new owner-only file or shown on request, and a key file made from such a text. The seed is
//! printed only when the caller asks for it by name, and a text is never taken from an argument
//! (an argument stays in process lists and shell histories).

use std::fs::File;
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::password::{PasswordSources, load_unlocked};
use crate::PeerKey;
use crate::identity::store::{self, Stored, seal};
use crate::identity::{Identity, IdentityError, KeyCost};

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
    sources: PasswordSources,
) -> Result<Vec<String>, String> {
    if out.is_none() && !print_secret {
        return Err(
            "the text is the key itself: choose --out FILE to write it to a new private file, or --print-secret to show it"
                .to_owned(),
        );
    }
    let identity = load_unlocked(key_file, sources, "Key password: ")
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

fn key_error(error: &IdentityError) -> String {
    format!("key file: {}", describe(error, "the key file"))
}

/// A failed replacement: a leftover new file is named, anything else is the key file's own error.
fn replace_error(error: &IdentityError) -> String {
    match error {
        IdentityError::AlreadyExists => {
            "a file named like the key file with `.new` added is in the way; remove it and try again"
                .to_owned()
        }
        other => key_error(other),
    }
}

fn check_cost(cost: KeyCost) -> Result<(), String> {
    if cost.within_bounds() {
        Ok(())
    } else {
        Err("the cost is outside the bounds: 8 KiB per lane to 256 MiB of memory, 1 to 10 passes, 1 to 4 lanes"
            .to_owned())
    }
}

/// Encrypts the plain key file `key_file` in place under `password`. The encrypted file is written
/// next to it, read back and opened with the password, and only then moved over the plain one; on
/// any failure the plain file stays as it was.
/// cancel-safe: NO - a running worker may finish the replacement after the waiter is dropped.
pub async fn encrypt_key(
    key_file: &Path,
    password: &str,
    cost: KeyCost,
) -> Result<Vec<String>, String> {
    if password.is_empty() {
        return Err("the password must not be empty".to_owned());
    }
    check_cost(cost)?;
    let path = key_file.to_path_buf();
    let password = Zeroizing::new(password.to_owned());
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let seed = match store::load_stored_blocking(&path).map_err(|e| key_error(&e))? {
            Stored::Plain(seed) => seed,
            Stored::Sealed(_) => return Err("the key file is already encrypted".to_owned()),
        };
        let bytes = seal::seal(&seed, &password, cost).map_err(|e| key_error(&e))?;
        store::replace_blocking(&path, &bytes, |read| {
            seal::open(read, &password).is_ok_and(|opened| *opened == *seed)
        })
        .map_err(|e| replace_error(&e))
    })
    .await
    .map_err(|error| format!("key file: {error}"))??;
    Ok(vec![
        format!("encrypted: {}", key_file.display()),
        "the key file now asks for its password at every start: --password, SHAAR_KEY_PASSWORD, --password-file, the standard input or the terminal"
            .to_owned(),
    ])
}

/// Makes the encrypted key file `key_file` plain again, opened with `password`; the same
/// write, read-back and replace as [`encrypt_key`].
/// cancel-safe: NO - see [`encrypt_key`].
pub async fn decrypt_key(key_file: &Path, password: &str) -> Result<Vec<String>, String> {
    let path = key_file.to_path_buf();
    let password = Zeroizing::new(password.to_owned());
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let bytes = match store::load_stored_blocking(&path).map_err(|e| key_error(&e))? {
            Stored::Sealed(bytes) => bytes,
            Stored::Plain(_) => return Err("the key file is not encrypted".to_owned()),
        };
        let seed = seal::open(&bytes, &password).map_err(|e| key_error(&e))?;
        store::replace_blocking(&path, &seed[..], |read| read == &seed[..])
            .map_err(|e| replace_error(&e))
    })
    .await
    .map_err(|error| format!("key file: {error}"))??;
    Ok(vec![
        format!("decrypted: {}", key_file.display()),
        "the key file is plain again: whoever can read it has the key".to_owned(),
    ])
}

/// Changes the password of the encrypted key file `key_file`, and its cost to `cost`.
/// cancel-safe: NO - see [`encrypt_key`].
pub async fn change_key_password(
    key_file: &Path,
    old: &str,
    new: &str,
    cost: KeyCost,
) -> Result<Vec<String>, String> {
    if new.is_empty() {
        return Err("the new password must not be empty".to_owned());
    }
    check_cost(cost)?;
    let path = key_file.to_path_buf();
    let (old, new) = (
        Zeroizing::new(old.to_owned()),
        Zeroizing::new(new.to_owned()),
    );
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let bytes = match store::load_stored_blocking(&path).map_err(|e| key_error(&e))? {
            Stored::Sealed(bytes) => bytes,
            Stored::Plain(_) => return Err("the key file is not encrypted".to_owned()),
        };
        let seed = seal::open(&bytes, &old).map_err(|e| key_error(&e))?;
        let sealed = seal::seal(&seed, &new, cost).map_err(|e| key_error(&e))?;
        store::replace_blocking(&path, &sealed, |read| {
            seal::open(read, &new).is_ok_and(|opened| *opened == *seed)
        })
        .map_err(|e| replace_error(&e))
    })
    .await
    .map_err(|error| format!("key file: {error}"))??;
    Ok(vec![format!("password changed: {}", key_file.display())])
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
        let refused = export_key(&key, None, false, PasswordSources::default())
            .await
            .unwrap_err();
        assert!(
            refused.contains("--print-secret") && refused.contains("--out"),
            "{refused}"
        );
        let shown = export_key(&key, None, true, PasswordSources::default())
            .await
            .unwrap();
        assert_eq!(shown, [identity.export_text().unwrap().to_string()]);
    }

    #[tokio::test]
    async fn the_text_is_written_to_a_new_private_file_that_imports_back() {
        let dir = Fixture::new();
        let (key, identity) = key_in(&dir).await;
        let out = dir.join("exported.txt");
        let lines = export_key(&key, Some(&out), false, PasswordSources::default())
            .await
            .unwrap();
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
        let error = export_key(&key, Some(&out), false, PasswordSources::default())
            .await
            .unwrap_err();
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
        let missing = export_key(&dir.join("absent"), None, true, PasswordSources::default())
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
    /// Cheap enough to derive keys many times in a debug build.
    const FAST: KeyCost = KeyCost {
        memory_kib: 8,
        passes: 1,
        lanes: 1,
    };

    fn sources(password: &str) -> PasswordSources {
        PasswordSources {
            parameter: Some(Zeroizing::new(password.to_owned())),
            file: None,
        }
    }

    #[tokio::test]
    async fn an_encrypted_key_file_needs_its_password_and_keeps_the_identity() {
        let dir = Fixture::new();
        let (key, identity) = key_in(&dir).await;
        let lines = encrypt_key(&key, "correct horse", FAST).await.unwrap();
        assert!(lines[0].starts_with("encrypted: "), "{lines:?}");
        assert_eq!(std::fs::metadata(&key).unwrap().len(), 94);
        assert!(!dir.join("key.new").exists(), "no staging file is left");
        assert!(Identity::is_encrypted(&key).await.unwrap());
        assert!(matches!(
            Identity::load(&key).await,
            Err(IdentityError::PasswordRequired)
        ));
        let opened = Identity::load_with_password(&key, "correct horse")
            .await
            .unwrap();
        assert_eq!(opened.public_key_bytes(), identity.public_key_bytes());
        assert!(matches!(
            Identity::load_with_password(&key, "wrong").await,
            Err(IdentityError::WrongPassword)
        ));
        // A key file that is not generated anew behind a missing password.
        assert!(matches!(
            Identity::load_or_create(&key).await,
            Err(IdentityError::PasswordRequired)
        ));
    }

    #[tokio::test]
    async fn encryption_refuses_an_empty_password_a_bad_cost_and_a_second_run() {
        let dir = Fixture::new();
        let (key, identity) = key_in(&dir).await;
        let plain = std::fs::read(&key).unwrap();
        assert!(
            encrypt_key(&key, "", FAST)
                .await
                .unwrap_err()
                .contains("empty")
        );
        let heavy = KeyCost {
            memory_kib: u32::MAX,
            ..FAST
        };
        assert!(
            encrypt_key(&key, "pw", heavy)
                .await
                .unwrap_err()
                .contains("bounds")
        );
        assert_eq!(
            std::fs::read(&key).unwrap(),
            plain,
            "the plain file is untouched"
        );
        encrypt_key(&key, "pw", FAST).await.unwrap();
        let again = encrypt_key(&key, "pw", FAST).await.unwrap_err();
        assert!(again.contains("already encrypted"), "{again}");
        let loaded = Identity::load_with_password(&key, "pw").await.unwrap();
        assert_eq!(loaded.public_key_bytes(), identity.public_key_bytes());
    }

    #[tokio::test]
    async fn a_leftover_staging_file_blocks_the_change_and_leaves_the_key_alone() {
        let dir = Fixture::new();
        let (key, _) = key_in(&dir).await;
        let plain = std::fs::read(&key).unwrap();
        std::fs::write(dir.join("key.new"), "stale").unwrap();
        let error = encrypt_key(&key, "pw", FAST).await.unwrap_err();
        assert!(error.contains(".new"), "{error}");
        assert_eq!(std::fs::read(&key).unwrap(), plain);
        assert_eq!(
            std::fs::read_to_string(dir.join("key.new")).unwrap(),
            "stale"
        );
    }

    #[tokio::test]
    async fn decryption_needs_the_password_and_a_wrong_one_changes_nothing() {
        let dir = Fixture::new();
        let (key, identity) = key_in(&dir).await;
        let not_yet = decrypt_key(&key, "pw").await.unwrap_err();
        assert!(not_yet.contains("not encrypted"), "{not_yet}");
        encrypt_key(&key, "pw", FAST).await.unwrap();
        let sealed = std::fs::read(&key).unwrap();
        let wrong = decrypt_key(&key, "nope").await.unwrap_err();
        assert!(wrong.contains("wrong password"), "{wrong}");
        assert_eq!(std::fs::read(&key).unwrap(), sealed);
        decrypt_key(&key, "pw").await.unwrap();
        assert_eq!(std::fs::metadata(&key).unwrap().len(), 32);
        let loaded = Identity::load(&key).await.unwrap();
        assert_eq!(loaded.public_key_bytes(), identity.public_key_bytes());
    }

    #[tokio::test]
    async fn changing_the_password_retires_the_old_one() {
        let dir = Fixture::new();
        let (key, identity) = key_in(&dir).await;
        let plain = change_key_password(&key, "a", "b", FAST).await.unwrap_err();
        assert!(plain.contains("not encrypted"), "{plain}");
        encrypt_key(&key, "old", FAST).await.unwrap();
        assert!(
            change_key_password(&key, "wrong", "new", FAST)
                .await
                .is_err()
        );
        assert!(
            change_key_password(&key, "old", "", FAST)
                .await
                .unwrap_err()
                .contains("empty")
        );
        change_key_password(&key, "old", "new", FAST).await.unwrap();
        assert!(matches!(
            Identity::load_with_password(&key, "old").await,
            Err(IdentityError::WrongPassword)
        ));
        let loaded = Identity::load_with_password(&key, "new").await.unwrap();
        assert_eq!(loaded.public_key_bytes(), identity.public_key_bytes());
    }

    #[tokio::test]
    async fn export_and_unlock_use_the_password_sources_for_an_encrypted_key() {
        let dir = Fixture::new();
        let (key, identity) = key_in(&dir).await;
        encrypt_key(&key, "pw", FAST).await.unwrap();
        let shown = export_key(&key, None, true, sources("pw")).await.unwrap();
        assert_eq!(shown, [identity.export_text().unwrap().to_string()]);
        let wrong = export_key(&key, None, true, sources("nope"))
            .await
            .unwrap_err();
        assert!(wrong.contains("wrong password"), "{wrong}");
        let unlocked = load_unlocked(&key, sources("pw"), "Key password: ")
            .await
            .unwrap();
        assert_eq!(unlocked.public_key_bytes(), identity.public_key_bytes());
    }
}
