//! Blocking key-file storage: creation, loading, format, permissions.
//!
//! # File format
//!
//! Exactly 32 raw bytes (the Ed25519 seed). No headers, no magic.
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

fn load_opened(mut file: File) -> Result<zeroize::Zeroizing<[u8; 32]>, IdentityError> {
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
        shaar_platform::winfile::validate_owner_only(&file)
            .map_err(|_| IdentityError::InsecurePermissions)?;
    }
    #[cfg(not(any(unix, windows)))]
    {
        let meta = file.metadata().map_err(IdentityError::from)?;
        if !meta.is_file() {
            return Err(IdentityError::NotARegularFile);
        }
    }

    // Fixed-size read: exactly 32 bytes, then verify EOF. The buffer never
    // scales with the hostile file size. The 33-byte staging buffer is
    // zeroize-on-drop, so the raw key bytes read from disk (one extra
    // zeroized temporary) do not linger in memory.
    let mut buf = zeroize::Zeroizing::new([0u8; 33]);
    file.read_exact(&mut buf[..32]).map_err(|err| {
        if err.kind() == std::io::ErrorKind::UnexpectedEof {
            IdentityError::InvalidFormat
        } else {
            IdentityError::from(err)
        }
    })?;
    let n = file.read(&mut buf[32..]).map_err(IdentityError::from)?;
    if n != 0 {
        return Err(IdentityError::InvalidFormat);
    }
    // Single copy out of the zeroizing staging buffer; no second plain
    // `copy_from_slice` staging copy exists.
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&buf[..32]);
    Ok(seed)
}

/// Creates a NEW key file (never overwrites) and writes the seed.
pub fn create_new_blocking(path: &Path, seed: &[u8; 32]) -> Result<(), IdentityError> {
    use std::io::Write;
    create_new_with_io(
        path,
        seed,
        |file, bytes| file.write_all(bytes),
        File::sync_all,
    )
}

fn create_new_with_io<W, S>(
    path: &Path,
    seed: &[u8; 32],
    write: W,
    sync: S,
) -> Result<(), IdentityError>
where
    W: FnOnce(&mut File, &[u8; 32]) -> std::io::Result<()>,
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
    let write_result = write(&mut file, seed).and_then(|()| sync(&file));
    if let Err(e) = write_result {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(IdentityError::from(e));
    }
    Ok(())
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
