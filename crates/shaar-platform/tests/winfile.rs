#![forbid(unsafe_code)]
//! Windows file-contract tests; other targets have no native cases here.
//!
//! Controlled broad/unprotected DACL and before-first-byte checks are library
//! unit tests. NULL/empty/inherited ACLs and actual cross-principal denial
//! remain unverified. All native execution is restricted to GitHub CI.

#[cfg(windows)]
mod windows_tests {
    use shaar_platform::winfile::{create_private_new, validate_owner_only};
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Unique temp directory per test run. Caller removes it best-effort.
    fn unique_temp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "shaar-platform-{}-{}-{}",
            tag,
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&dir).expect("create unique temp dir");
        dir
    }

    /// Best-effort cleanup: remove all children then the directory itself.
    /// Failures are ignored (best-effort; CI runners clean temp dirs).
    fn cleanup(dir: &Path) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    let _ = fs::remove_dir_all(&p);
                } else {
                    let _ = fs::remove_file(&p);
                }
            }
        }
        let _ = fs::remove_dir(dir);
    }

    /// (a) Roundtrip: create, write+read a 32-byte payload; a second create
    /// on the same path errs `AlreadyExists` and the original content is
    /// unchanged.
    #[test]
    fn create_private_new_roundtrip_and_no_overwrite() {
        let dir = unique_temp_dir("roundtrip");
        let path = dir.join("secret.bin");
        let payload: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));

        {
            let mut f = create_private_new(&path).expect("first create succeeds");
            f.write_all(&payload).expect("write payload");
            f.sync_all().expect("sync payload");
        }

        let second = create_private_new(&path);
        assert_eq!(
            second.expect_err("second create must fail").kind(),
            std::io::ErrorKind::AlreadyExists,
            "CREATE_NEW must reject overwrite"
        );

        let read_back = fs::read(&path).expect("read back");
        assert_eq!(read_back, payload, "original content unchanged");

        cleanup(&dir);
    }

    /// (b) Privacy after creation: the file created by
    /// `create_private_new` passes `validate_owner_only`.
    #[test]
    fn created_file_validates_owner_only() {
        let dir = unique_temp_dir("validate-ok");
        let path = dir.join("private.bin");
        let f = create_private_new(&path).expect("create succeeds");
        validate_owner_only(&f).expect("created file must be owner-only-private");
        drop(f);
        cleanup(&dir);
    }

    /// (c) A file created with default `std::fs::OpenOptions` (no protected
    /// DACL) is rejected by `validate_owner_only`.
    #[test]
    fn default_created_file_fails_validation() {
        let dir = unique_temp_dir("validate-reject");
        let path = dir.join("plain.bin");
        {
            use std::io::Write;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .expect("plain create succeeds");
            f.write_all(b"x").expect("write one byte");
        }
        let f = fs::OpenOptions::new()
            .read(true)
            .open(&path)
            .expect("reopen plain file");
        assert!(
            validate_owner_only(&f).is_err(),
            "file without protected owner-only DACL must fail validation"
        );
        drop(f);
        cleanup(&dir);
    }

    /// (d) Error path: creating in a nonexistent directory errs and creates
    /// nothing.
    #[test]
    fn create_in_nonexistent_directory_fails() {
        let dir = unique_temp_dir("errpath");
        let missing = dir.join("does-not-exist");
        let path = missing.join("never.bin");
        assert!(
            create_private_new(&path).is_err(),
            "create in nonexistent directory must fail"
        );
        assert!(!path.exists(), "no file must be created on failure");
        assert!(!missing.exists(), "target directory must not be created");
        cleanup(&dir);
    }

    /// Supplementary boundary: interior NUL in a path is rejected without
    /// touching the filesystem.
    #[test]
    fn interior_nul_path_rejected() {
        // Build a path containing interior NUL bytes from raw wide chars.
        use std::os::windows::ffi::OsStringExt;
        let wide: Vec<u16> = vec![0x0041, 0x0000, 0x0042]; // 'A', NUL, 'B'
        let path = std::path::PathBuf::from(std::ffi::OsString::from_wide(&wide));
        assert!(create_private_new(&path).is_err());
    }
}
