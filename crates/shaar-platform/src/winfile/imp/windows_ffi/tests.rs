#![forbid(unsafe_code)]
use super::*;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

struct FixtureDir(PathBuf);

impl FixtureDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let base = std::env::current_dir()
            .expect("current directory")
            .join("target/private-file-fixtures");
        std::fs::create_dir_all(&base).expect("fixture parent");
        for _ in 0..64 {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!("{}-{id}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("create fixture directory: {err}"),
            }
        }
        panic!("fixture namespace exhausted");
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn owner_sid_bounds_precede_all_byte_reads() {
    let sid = [1u8, 1, 0, 0, 0, 0, 0, 5, 7, 0, 0, 0];
    let pointer = sid.as_ptr().cast_mut().cast();
    assert_eq!(sid_slice(pointer, &sid).unwrap(), &sid);
    for len in 0..sid.len() {
        assert!(sid_slice(pointer, &sid[..len]).is_err());
    }
    // Rejected by the Rust-only checker; never sent to a Win32 API.
    let before = sid.as_ptr().wrapping_sub(1).cast_mut().cast();
    let after = sid.as_ptr().wrapping_add(sid.len()).cast_mut().cast();
    assert!(sid_slice(before, &sid).is_err());
    assert!(sid_slice(after, &sid).is_err());
}

#[test]
fn malformed_owner_sid_is_rejected() {
    for (revision, count) in [(0u8, 1u8), (1, 0), (1, 255)] {
        let mut sid = [0u8; 12];
        sid[0] = revision;
        sid[1] = count;
        assert!(sid_slice(sid.as_ptr().cast_mut().cast(), &sid).is_err());
    }
}

#[test]
fn invalid_sddl_termination_is_rejected_before_ffi() {
    let invalid: &[&[u16]] = &[&[], &[0], &[68], &[68, 0, 58, 0]];
    for sddl in invalid {
        assert_eq!(
            convert_sddl_to_descriptor(sddl).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}

#[test]
fn private_dacl_is_installed_before_first_byte() {
    use std::io::Write;
    let dir = FixtureDir::new();
    let mut file = create_private_new_raw(&dir.0.join("key")).expect("private creation");
    assert_eq!(file.metadata().unwrap().len(), 0);
    validate_owner_only_raw(&file).expect("private before write");
    file.write_all(&[9; 32]).expect("synthetic key bytes");
    validate_owner_only_raw(&file).expect("private after write");
}

#[test]
fn broad_and_unprotected_dacls_are_rejected_on_real_files() {
    let dir = FixtureDir::new();
    for (name, text) in [
        ("broad", "D:P(A;;FA;;;WD)"),
        ("unprotected", "D:(A;;FA;;;OW)"),
    ] {
        let sddl: Vec<u16> = text.encode_utf16().chain([0]).collect();
        let file = create_new_with_sddl(&dir.0.join(name), &sddl).expect("fixture creation");
        assert_eq!(file.metadata().unwrap().len(), 0);
        assert_eq!(
            validate_owner_only_raw(&file).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
