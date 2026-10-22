#![forbid(unsafe_code)]
//! P04 identity integration tests: derivation vectors, redaction, and
//! platform-specific permission behavior.

use crate::common::{self, TempDir};

use shaar::identity::{Identity, IdentityError};

/// 4. Redaction: Debug of `Identity` and of every error produced in the
/// storage suites must not contain the seed hex.
#[tokio::test]
async fn debug_output_never_contains_seed_hex() {
    let seed_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    let id = Identity::from_seed(common::TEST1_SEED);
    let dbg = format!("{id:?}");
    assert_eq!(dbg, "Identity(..)");
    assert!(!dbg.to_ascii_lowercase().contains(seed_hex));

    // Errors from create_new / load on hostile paths, formatted both ways.
    let td = TempDir::new("redact-errors");
    let mut errs = Vec::new();
    errs.push(
        Identity::create_new(td.path().join("missing-dir").join("k.key"))
            .await
            .expect_err("missing parent"),
    );
    errs.push(
        Identity::load(td.path().join("absent.key"))
            .await
            .expect_err("not found"),
    );
    let big = td.path().join("big.key");
    std::fs::write(&big, [0u8; 40]).expect("write");
    errs.push(Identity::load(&big).await.expect_err("too long"));
    for e in &errs {
        let d = format!("{e:?}");
        let s = format!("{e}");
        assert!(!d.to_ascii_lowercase().contains(seed_hex), "{d}");
        assert!(!s.to_ascii_lowercase().contains(seed_hex), "{s}");
    }
}

/// 12 (cfg(windows)). A key file created through plain std OpenOptions
/// (no owner-only DACL) is rejected by load with InsecurePermissions and
/// is not modified or deleted.
#[cfg(windows)]
#[tokio::test]
async fn windows_unprotected_file_is_rejected() {
    let td = TempDir::new("win-dacl");
    let path = td.key_path();
    std::fs::write(&path, [0x11u8; 32]).expect("write unprotected file");

    let err = Identity::load(&path).await.expect_err("unprotected file");
    assert!(
        matches!(err, IdentityError::InsecurePermissions),
        "got {err:?}"
    );
    assert_eq!(
        std::fs::read(&path).expect("reread"),
        [0x11u8; 32],
        "rejected file must not be modified"
    );
}

/// 12 (cfg(windows)). A file created via create_private_new passes the
/// owner-only validation on load.
#[cfg(windows)]
#[tokio::test]
async fn windows_private_file_loads() {
    let td = TempDir::new("win-private");
    let path = td.key_path();
    let id = Identity::create_new(&path).await.expect("create_new");
    let loaded = Identity::load(&path).await.expect("load");
    assert_eq!(loaded.public_key_bytes(), id.public_key_bytes());
}

/// 7 (cfg(unix)). Creation mode: after create_new, no group/other bits
/// are set.
#[cfg(unix)]
#[tokio::test]
async fn unix_created_file_mode_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let td = TempDir::new("unix-mode");
    let path = td.key_path();
    Identity::create_new(&path).await.expect("create_new");
    let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
    assert_eq!(mode & 0o077, 0, "group/other bits must be clear: {mode:o}");
}

/// 7 (cfg(unix)). A pre-existing 0644 file is rejected with
/// InsecurePermissions and left untouched (not chmod-fixed, not deleted).
#[cfg(unix)]
#[tokio::test]
async fn unix_0644_file_rejected_and_untouched() {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let td = TempDir::new("unix-0644");
    let path = td.key_path();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&path)
        .expect("create 0644")
        .sync_all()
        .expect("sync");
    std::fs::write(&path, [0x22u8; 32]).expect("write junk");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .expect("set insecure fixture mode");

    let err = Identity::load(&path).await.expect_err("0644 file");
    assert!(
        matches!(err, IdentityError::InsecurePermissions),
        "got {err:?}"
    );
    assert_eq!(
        std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(std::fs::read(&path).expect("reread"), [0x22u8; 32]);
}

/// 7 (cfg(unix)). A pre-existing group/world-writable-and-readable 0666
/// file is rejected as well.
///
/// The fixture is built through the private fixture helper (owner-only
/// at creation, immune to umask) and then EXPLICITLY chmod'd to 0666,
/// so the mode under test is known regardless of the ambient umask.
#[cfg(unix)]
#[tokio::test]
async fn unix_0666_file_rejected() {
    use std::os::unix::fs::PermissionsExt;
    let (_td, path) = crate::common::write_private_fixture("unix-0666", &[0x33u8; 32]).await;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).expect("chmod 0666");

    let err = Identity::load(&path).await.expect_err("0666 file");
    assert!(matches!(err, IdentityError::InsecurePermissions));
    assert_eq!(
        std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777,
        0o666,
        "fixture mode must still be 0666 (not fixed or deleted)"
    );
    assert_eq!(
        std::fs::read(&path).expect("reread"),
        [0x33u8; 32],
        "rejected file must not be modified"
    );
}

/// 7 (cfg(unix), supplementary). A directory at the key path is rejected
/// as NotARegularFile, not as a permission problem.
#[cfg(unix)]
#[tokio::test]
async fn unix_directory_at_key_path_is_not_a_regular_file() {
    let td = TempDir::new("unix-dir");
    let path = td.key_path();
    std::fs::create_dir(&path).expect("make dir");
    let err = Identity::load(&path).await.expect_err("directory");
    assert!(matches!(err, IdentityError::NotARegularFile), "got {err:?}");
    assert!(path.is_dir(), "directory must remain");
}
