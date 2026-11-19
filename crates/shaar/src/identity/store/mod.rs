//! Blocking key-file storage: creation, loading, format, permissions.
//!
//! # File format
//!
//! Exactly 32 raw bytes (the Ed25519 seed), no headers, no magic; or, when the key is kept
//! encrypted (leaf KEY-2), the 94-byte file of [`seal`], told apart by its length and its magic.
//!
//! # Reading (invariant I4)
//!
//! The file is opened first; every check runs against the ALREADY-OPENED
//! handle (Unix: `File::metadata()` = fstat, never stat-path-then-reopen;
//! Windows: `shaar_platform::winfile::validate_owner_only` on the handle)
//! BEFORE any byte of content is read. Non-regular files are rejected
//! (`NotARegularFile`); broad group/other permissions are rejected
//! (`InsecurePermissions`) and are never silently chmod-fixed. Content is
//! read into a fixed `[u8; 33]` buffer: `read_exact` for 32 bytes, then a
//! 1-byte read must return `Ok(0)`; any leftover byte is `InvalidFormat`.
//! No allocation is proportional to the (possibly hostile) on-disk size.
//!
//! # Creation (invariants I3 + I4)
//!
//! Unix: `OpenOptions::read(true).write(true).create_new(true).mode(0o600)`
//! — O_EXCL|O_CREAT with mode 0600 in a single syscall, so there is NO
//! create→chmod window; the DACL/mode is in place before the first seed
//! byte. Windows: `shaar_platform::winfile::create_private_new` (DACL
//! `D:P(A;;FA;;;OW)` installed before the first byte). Exactly one of N
//! concurrent creators wins; losers get `AlreadyExists`; nothing is ever
//! overwritten. On write/sync failure the file is removed ONLY if this
//! call created it (create_new succeeded, so no pre-existing key bytes
//! were ever involved).
//!
//! # Trusted-parent assumption
//!
//! We protect the FILE, not the directory. Whoever can modify the parent
//! directory can swap/rename/delete the path entry between operations;
//! callers needing more must secure the parent themselves. Creation is
//! also not crash-atomic: a crash mid-write can leave a short file that
//! fails to LOAD — the safe direction (a broken file never resurrects a
//! fake identity and is never silently overwritten). `load_or_create`
//! under a race: exactly one process wins; losers get an error, never a
//! second identity.
//!
//! All functions here are blocking and are invoked only from
//! `tokio::task::spawn_blocking` with owned inputs. Aborting the async
//! future does NOT stop a running blocking task; cleanup-on-failure
//! therefore always runs to completion inside the task.
//!
//! Write/sync fault injection is private: tests exercise the same exclusive
//! creation and cleanup branch without filling a disk or using special files.
//! Cancellation of a waiter does not stop native I/O or roll back a completed
//! key creation; the blocking worker must finish before cleanup is observable.

use std::fs::File;
#[cfg(not(windows))]
use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;

use super::error::IdentityError;

pub(super) mod seal;
pub(super) mod text;

/// Loads an existing key file, applying all open-handle checks.
///
/// Returns the seed wrapped in [`zeroize::Zeroizing`]: if the caller is
/// cancelled or errors after this returns, the in-memory seed copy is
/// erased on drop rather than left as plain stack/heap bytes.
pub fn load_blocking(path: &Path) -> Result<zeroize::Zeroizing<[u8; 32]>, IdentityError> {
    load_opened(File::open(path).map_err(IdentityError::from)?)
}

pub(super) fn load_if_present_blocking(
    path: &Path,
) -> Result<Option<zeroize::Zeroizing<[u8; 32]>>, IdentityError> {
    load_if_present_with(path, load_opened)
}

fn load_if_present_with<R>(
    path: &Path,
    read: R,
) -> Result<Option<zeroize::Zeroizing<[u8; 32]>>, IdentityError>
where
    R: FnOnce(File) -> Result<zeroize::Zeroizing<[u8; 32]>, IdentityError>,
{
    match File::open(path) {
        Ok(file) => read(file).map(Some),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(IdentityError::from(err)),
    }
}

/// What a key file holds: the plain seed, or the bytes of an encrypted file.
pub(super) enum Stored {
    Plain(zeroize::Zeroizing<[u8; 32]>),
    Sealed(Vec<u8>),
}

fn load_opened(file: File) -> Result<zeroize::Zeroizing<[u8; 32]>, IdentityError> {
    match load_stored_opened(file)? {
        Stored::Plain(seed) => Ok(seed),
        Stored::Sealed(_) => Err(IdentityError::PasswordRequired),
    }
}

/// Loads a key file of either form; an encrypted one is returned still sealed.
pub(super) fn load_stored_blocking(path: &Path) -> Result<Stored, IdentityError> {
    load_stored_opened(File::open(path).map_err(IdentityError::from)?)
}

/// The seed of a plain file, or of an encrypted one opened with `password`.
pub fn load_with_password_blocking(
    path: &Path,
    password: &str,
) -> Result<zeroize::Zeroizing<[u8; 32]>, IdentityError> {
    match load_stored_blocking(path)? {
        Stored::Plain(seed) => Ok(seed),
        Stored::Sealed(bytes) => seal::open(&bytes, password),
    }
}

/// The checks on an already-opened key file, before any byte of it is read.
pub(super) fn check_private_file(file: &File) -> Result<(), IdentityError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = file.metadata().map_err(IdentityError::from)?; // fstat
        if !meta.file_type().is_file() {
            return Err(IdentityError::NotARegularFile);
        }
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(IdentityError::InsecurePermissions);
        }
    }
    #[cfg(windows)]
    {
        let meta = file.metadata().map_err(IdentityError::from)?;
        if !meta.is_file() {
            return Err(IdentityError::NotARegularFile);
        }
        shaar_platform::winfile::validate_owner_only(file)
            .map_err(|_| IdentityError::InsecurePermissions)?;
    }
    #[cfg(not(any(unix, windows)))]
    {
        let meta = file.metadata().map_err(IdentityError::from)?;
        if !meta.is_file() {
            return Err(IdentityError::NotARegularFile);
        }
    }
    Ok(())
}

fn load_stored_opened(mut file: File) -> Result<Stored, IdentityError> {
    check_private_file(&file)?;
    // Fixed-size read: at most one byte more than an encrypted file takes, then the length
    // decides. The buffer never scales with the hostile file size and is zeroized on drop.
    let mut buf = zeroize::Zeroizing::new([0u8; seal::SEALED_LEN + 1]);
    let mut length = 0;
    while length < buf.len() {
        match file.read(&mut buf[length..]) {
            Ok(0) => break,
            Ok(read) => length += read,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(IdentityError::from(err)),
        }
    }
    match length {
        32 => {
            // Single copy out of the zeroizing staging buffer.
            let mut seed = zeroize::Zeroizing::new([0u8; 32]);
            seed.copy_from_slice(&buf[..32]);
            Ok(Stored::Plain(seed))
        }
        seal::SEALED_LEN if seal::is_sealed(&buf[..]) => Ok(Stored::Sealed(buf[..length].to_vec())),
        _ => Err(IdentityError::InvalidFormat),
    }
}

/// Creates a NEW key file (never overwrites) and writes the seed.
pub fn create_new_blocking(path: &Path, seed: &[u8; 32]) -> Result<(), IdentityError> {
    create_private_new_blocking(path, seed)
}

/// Creates a NEW file with the key file's owner-only rights (never overwrites) and writes `data`;
/// the portable text form of a key is kept in such a file.
pub fn create_private_new_blocking(path: &Path, data: &[u8]) -> Result<(), IdentityError> {
    use std::io::Write;
    create_new_with_io(
        path,
        data,
        |file, bytes| file.write_all(bytes),
        File::sync_all,
    )
}

/// Replaces the key file `path` by `bytes` (a plain seed or an encrypted file). The new content
/// goes to a new owner-only file next to the old one, is read back and checked by `verify`, and
/// only then moved over the old file; on any failure the new file is removed and the old one is
/// left as it was. A stale `.new` file from an earlier failure is never overwritten either.
pub(super) fn replace_blocking(
    path: &Path,
    bytes: &[u8],
    verify: impl FnOnce(&[u8]) -> bool,
) -> Result<(), IdentityError> {
    let mut name = path
        .file_name()
        .ok_or(IdentityError::InvalidFormat)?
        .to_owned();
    name.push(".new");
    let staged = path.with_file_name(name);
    create_private_new_blocking(&staged, bytes)?;
    let remove = |error: IdentityError| {
        let _ = std::fs::remove_file(&staged);
        error
    };
    let read = zeroize::Zeroizing::new(std::fs::read(&staged).map_err(|e| remove(e.into()))?);
    if read.as_slice() != bytes || !verify(&read) {
        return Err(remove(IdentityError::InvalidFormat));
    }
    std::fs::rename(&staged, path).map_err(|e| remove(e.into()))
}

fn create_new_with_io<W, S>(
    path: &Path,
    data: &[u8],
    write: W,
    sync: S,
) -> Result<(), IdentityError>
where
    W: FnOnce(&mut File, &[u8]) -> std::io::Result<()>,
    S: FnOnce(&File) -> std::io::Result<()>,
{
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    };
    #[cfg(windows)]
    let file = shaar_platform::winfile::create_private_new(path);
    #[cfg(not(any(unix, windows)))]
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path);

    let mut file = match file {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(IdentityError::AlreadyExists);
        }
        Err(e) => return Err(IdentityError::from(e)),
    };

    // We own this file exclusively (O_EXCL / CREATE_NEW succeeded): on any
    // write failure remove it — no pre-existing key bytes were involved.
    let write_result = write(&mut file, data).and_then(|()| sync(&file));
    if let Err(e) = write_result {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(IdentityError::from(e));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
