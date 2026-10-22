//! Windows-specific, owner-only-private file helpers.
//!
//! Public API: [`create_private_new`] and [`validate_owner_only`]. All FFI is
//! confined to the `windows_ffi` module; the rest of this module is safe code.
//!
//! # Trusted-parent / race model
//!
//! The DACL installed here protects the **file object only**. The ACL of the
//! parent directory (and the filesystem) determines who can replace, rename,
//! or delete a path entry between operations. An attacker who can write the
//! parent directory can swap the path after creation; callers needing
//! stronger guarantees must secure the directory themselves.
//!
//! `CREATE_NEW` atomicity is per-path on the same volume: of two concurrent
//! creators exactly one wins; the loser gets
//! [`std::io::ErrorKind::AlreadyExists`] (`ERROR_FILE_EXISTS`).
//!
//! Long paths: without the `\\?\` extended-length prefix, Windows rejects
//! paths longer than the default MAX_PATH limit (260 UTF-16 units). This
//! crate passes the path as-is and does NOT add `\\?\`; overly long paths
//! fail with the OS error. Callers needing long paths must supply the prefix
//! themselves.

pub use imp::{create_private_new, validate_owner_only};

mod imp {
    use std::fs::File;
    use std::io;
    use std::path::Path;

    /// Isolated FFI boundary. This is the ONLY place `unsafe` is permitted in
    /// this crate, per repository policy (CLAUDE.md rule 1).
    #[allow(unsafe_code)]
    mod windows_ffi;

    /// Creates a new file at `path` atomically (no overwrite) with a
    /// PROTECTED DACL granting `FILE_ALL_ACCESS` only to the Owner Rights
    /// SID (`OW`, S-1-3-4). The DACL is in place before any byte is written.
    ///
    /// * `dwDesiredAccess = GENERIC_READ | GENERIC_WRITE`, `dwShareMode = 0`,
    ///   `dwCreationDisposition = CREATE_NEW`,
    ///   `dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL`.
    /// * Two concurrent creators on the same path: exactly one wins, the
    ///   loser gets [`std::io::ErrorKind::AlreadyExists`].
    /// * Paths longer than the default MAX_PATH limit without a `\\?\`
    ///   prefix are rejected by the OS with a clear error; this crate does
    ///   not add the prefix itself (documented limitation).
    /// * Trusted-parent assumption: the parent directory's ACL governs who
    ///   can replace or delete the path entry; this crate protects the file
    ///   object, not the directory.
    ///
    /// See: <https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew>,
    /// <https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ns-wtypesbase-security_attributes>,
    /// <https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format>,
    /// <https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-rights-side-using-a-dacl>
    pub fn create_private_new(path: &Path) -> io::Result<File> {
        windows_ffi::create_private_new_raw(path)
    }

    /// Validates that the CURRENT security descriptor of an already-opened
    /// file is owner-only-private:
    ///
    /// * an owner is present;
    /// * a DACL is present and flagged `SE_DACL_PROTECTED`;
    /// * every ACE is a recognized ALLOW or DENY ACE whose full extent lies
    ///   within the ACL buffer, with a well-formed SID (revision 1,
    ///   non-zero subauthority count, full SID length in bounds) placed at
    ///   its true offset (byte 8 of the ACE, after the 4-byte header and the
    ///   4-byte access mask);
    /// * no ACE carries the `INHERITED_ACE` flag — a PROTECTED DACL must
    ///   contain only explicit ACEs;
    /// * every ALLOW ACE must have a non-zero mask and grant access only via
    ///   the Owner Rights SID (`S-1-3-4`); any non-zero mask is accepted
    ///   (including full access — Owner Rights scopes it to the owner);
    ///   an ALLOW ACE for any other principal fails the check;
    /// * at least one ALLOW-OW ACE must be present (fail closed otherwise);
    /// * DENY ACEs for other principals may coexist (well-formed SID
    ///   required); unrecognized ACE types or malformed structures fail
    ///   closed.
    ///
    /// Validation reflects the CURRENT handle's descriptor; a directory-level
    /// race (path swap via the parent directory) cannot be detected here.
    ///
    /// See: <https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getkernelobjectsecurity>,
    /// <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_ace>,
    /// <https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-rights-side-using-a-dacl>
    pub fn validate_owner_only(file: &File) -> io::Result<()> {
        windows_ffi::validate_owner_only_raw(file)
    }
}
