#![forbid(unsafe_code)]
//! Shared helpers for the P04 identity integration tests.
//!
//! Each test uses its own uniquely named temp directory (process id +
//! nanoseconds) with best-effort cleanup at the end.

#![allow(dead_code)]

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// RFC 8032 §7.1 test seeds (public test vectors, not secrets).
pub const TEST1_SEED: [u8; 32] =
    hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
pub const TEST1_PUB: [u8; 32] =
    hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
pub const TEST2_SEED: [u8; 32] =
    hex32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
pub const TEST2_PUB: [u8; 32] =
    hex32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
pub const TEST3_SEED: [u8; 32] =
    hex32("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
pub const TEST3_PUB: [u8; 32] =
    hex32("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");

/// Compile-time hex decoding of 64 hex digits into 32 bytes.
const fn hex32(h: &str) -> [u8; 32] {
    let h = h.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (hex_val(h[2 * i]) << 4) | hex_val(h[2 * i + 1]);
        i += 1;
    }
    out
}

const fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("invalid hex digit"),
    }
}

/// A uniquely named temp directory with best-effort cleanup.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "shaar-id-test-{}-{}-{tag}",
            std::process::id(),
            nanos
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    pub fn path(&self) -> &std::path::Path {
        &self.0
    }

    pub fn key_path(&self) -> PathBuf {
        self.0.join("identity.key")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Creates a key fixture file with PRIVATE permissions regardless of
/// umask (Unix) or inherited DACLs (Windows), containing exactly
/// `contents`.
///
/// Why not plain `std::fs::write`: the storage layer's permission check
/// runs BEFORE the content checks, so a fixture written with default
/// permissions can fail with `InsecurePermissions` (Unix umask, Windows
/// inherited ACL) instead of reaching the intended `InvalidFormat` /
/// content path.
///
/// - Unix: the file is created with `OpenOptions::create_new(true)
///   .mode(0o600)`, so owner-only mode is guaranteed at creation time
///   regardless of the process umask.
/// - Windows: `Identity::create_new` first creates the file through
///   shaar-platform's owner-only DACL (`D:P(A;;FA;;;OW)` installed at
///   creation). The SAME file is then reopened with std
///   `OpenOptions::write(true).truncate(true)` and overwritten with the
///   desired contents: opening a file never replaces its security
///   descriptor, and the owner keeps FILE_ALL_ACCESS via the OW ACE, so
///   the std open succeeds and the DACL is preserved — only the content
///   changes.
pub async fn write_private_fixture(
    dir_tag: &str,
    contents: &[u8],
) -> (TempDir, std::path::PathBuf) {
    let td = TempDir::new(dir_tag);
    let path = td.key_path();

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("create private fixture");
        f.write_all(contents).expect("write fixture contents");
        f.sync_all().expect("sync fixture");
    }

    #[cfg(windows)]
    {
        use std::io::Write;
        // Obtain a private file via the production creation path (the
        // resulting identity is discarded; the file is what matters).
        let _ = shaar::identity::Identity::create_new(&path)
            .await
            .expect("create private fixture via create_new");
        // Overwrite content only; the owner-only DACL is untouched.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("reopen private fixture");
        f.write_all(contents).expect("write fixture contents");
        f.sync_all().expect("sync fixture");
    }

    #[cfg(not(any(unix, windows)))]
    {
        std::fs::write(&path, contents).expect("write fixture contents");
    }

    (td, path)
}
