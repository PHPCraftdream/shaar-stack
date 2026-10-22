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

fn owner_allow_acl() -> [u8; 28] {
    // ACL header, one basic ALLOW ACE, READ_DATA mask, documented S-1-3-4 SID.
    [
        2, 0, 28, 0, 1, 0, 0, 0, 0, 0, 20, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0,
    ]
}

#[test]
fn native_valid_null_dacl_is_a_privacy_error() {
    assert_eq!(
        null_dacl_fixture_result().unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[test]
fn empty_and_deny_only_dacls_are_rejected() {
    validate_dacl(&owner_allow_acl()).expect("positive owner-only fixture");
    let empty = [2u8, 0, 8, 0, 0, 0, 0, 0];
    assert_eq!(
        validate_dacl(&empty).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    let mut deny_only = owner_allow_acl();
    deny_only[8] = 1;
    assert_eq!(
        validate_dacl(&deny_only).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[test]
fn inherited_and_nonowner_allow_aces_are_rejected() {
    validate_dacl(&owner_allow_acl()).expect("positive owner-only fixture");
    let mut inherited = owner_allow_acl();
    inherited[9] = 0x10;
    assert_eq!(
        validate_dacl(&inherited).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    let mut nonowner = owner_allow_acl();
    nonowner[24] = 5;
    assert_eq!(
        validate_dacl(&nonowner).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[test]
fn acl_and_ace_extents_are_checked_before_use() {
    let acl = owner_allow_acl();
    for len in 0..acl.len() {
        assert_eq!(
            validate_dacl(&acl[..len]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    let mut missing_ace = acl;
    missing_ace[4] = 2;
    assert_eq!(
        validate_dacl(&missing_ace).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    let mut oversized_ace = acl;
    oversized_ace[10] = 40;
    assert_eq!(
        validate_dacl(&oversized_ace).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn zero_mask_malformed_sid_and_unknown_ace_fail_closed() {
    let mut zero_mask = owner_allow_acl();
    zero_mask[12..16].fill(0);
    assert_eq!(
        validate_dacl(&zero_mask).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    let mut bad_sid = owner_allow_acl();
    bad_sid[17] = 2;
    assert_eq!(
        validate_dacl(&bad_sid).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    let mut unknown = owner_allow_acl();
    unknown[8] = 0xff;
    assert_eq!(
        validate_dacl(&unknown).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[test]
fn world_sid_read_denial_has_a_native_positive_control() {
    let dir = FixtureDir::new();
    let private = create_private_new_raw(&dir.0.join("private")).expect("private creation");
    assert_eq!(private.metadata().unwrap().len(), 0);
    assert!(!authz::world_can_read(&private).expect("native private ACL decision"));
    let broad: Vec<u16> = "D:P(A;;FA;;;WD)".encode_utf16().chain([0]).collect();
    let control = create_new_with_sddl(&dir.0.join("control"), &broad).expect("control creation");
    assert_eq!(control.metadata().unwrap().len(), 0);
    assert!(authz::world_can_read(&control).expect("native positive ACL decision"));
    // Both files have the same exclusive sharing mode; Authz evaluates the
    // actual descriptors, not handle sharing or parent traversal restrictions.
    // This is not a second-account logon/File::open test.
}
