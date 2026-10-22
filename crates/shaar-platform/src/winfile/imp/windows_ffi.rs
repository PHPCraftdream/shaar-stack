use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;

pub(super) const SDDL_REVISION_1: u32 = 1;
// windows-sys 0.61.2 exports no SDDL_* string constants (verified);
// the literal is the wide encoding of L"D:P(A;;FA;;;OW)":
// PROTECTED DACL, one ALLOW ACE granting FILE_ALL_ACCESS to the
// Owner Rights SID (OW = S-1-3-4).
pub(super) const SDDL_OWNER_RIGHTS_PROTECTED: &[u16] = &[
    b'D' as u16,
    b':' as u16,
    b'P' as u16,
    b'(' as u16,
    b'A' as u16,
    b';' as u16,
    b';' as u16,
    b'F' as u16,
    b'A' as u16,
    b';' as u16,
    b';' as u16,
    b';' as u16,
    b'O' as u16,
    b'W' as u16,
    b')' as u16,
    0,
];
/// `INVALID_HANDLE_VALUE` sentinel for kernel object handles.
pub(super) const INVALID_HANDLE_VALUE: windows_sys::Win32::Foundation::HANDLE =
    -1isize as windows_sys::Win32::Foundation::HANDLE;

// Owner Rights SID "S-1-3-4": revision 1, identifier authority 3, one
// subauthority 4. Serialized SID layout: revision(1), subauth count(1),
// authority(6, big-endian), subauthorities(4 each, little-endian).
const OWNER_RIGHTS_SID: [u8; 12] = [
    1, // SID_REVISION
    1, // SubAuthorityCount
    0, 0, 0, 0, 0, 3, // IdentifierAuthority = 3
    4, 0, 0, 0, // SubAuthority[0] = 4
];

/// ACE types this validator recognizes. Anything else fails closed.
const ACE_TYPE_ACCESS_ALLOWED: u8 = 0x00;
const ACE_TYPE_ACCESS_DENIED: u8 = 0x01;

/// Minimal well-formed SID: 8-byte header + at least one u32
/// subauthority.
const MIN_FULL_SID: usize = 12;

/// Converts the SDDL string into a self-relative security descriptor.
///
/// Returns the LocalAlloc-owned descriptor pointer; the caller must
/// release it with [`local_free`] exactly once.
///
/// SDDL_REVISION_1 literal, see:
/// <https://learn.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertstringsecuritydescriptortosecuritydescriptorw>
fn convert_sddl_to_descriptor(sddl: &[u16]) -> io::Result<*mut core::ffi::c_void> {
    let text = sddl
        .strip_suffix(&[0])
        .filter(|text| !text.is_empty() && !text.contains(&0));
    if text.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid SDDL terminator",
        ));
    }
    let mut descriptor: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut length: u32 = 0;
    // SAFETY: the checked NUL-terminated slice remains alive during the call.
    // Output locals are writable. Only a successful nonnull LocalAlloc result
    // transfers ownership, released exactly once by the creator.
    let ok = unsafe {
        windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            &mut length,
        )
    };
    if ok == 0 || descriptor.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(descriptor)
    }
}

/// Frees a LocalAlloc-owned security descriptor. Best-effort: the
/// return value reports whether the allocator considered the handle
/// valid; non-null after free is treated as best-effort, not fatal.
///
/// # Safety
/// `descriptor` must be a pointer returned by
/// `ConvertStringSecurityDescriptorToSecurityDescriptorW` (LocalAlloc
/// memory) that has not been freed before, and must not be
/// dereferenced after this call.
pub(super) unsafe fn local_free(descriptor: *mut core::ffi::c_void) -> bool {
    // SAFETY: see function-level safety contract; single, final
    // release of OS-allocated memory; the return value is only used
    // for best-effort diagnostics and never dereferenced.
    unsafe { windows_sys::Win32::Foundation::LocalFree(descriptor).is_null() }
}

/// Owned NUL-terminated UTF-16 encoding of `path`. Rejects interior
/// NUL bytes; the path is passed as-is (no `\\?\` prefix is added —
/// see the module-level long-path note).
pub(super) fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains an interior NUL byte",
        ));
    }
    wide.push(0);
    Ok(wide)
}

/// Atomically creates a new file with an owner-only PROTECTED DACL.
/// On success the returned HANDLE is an owned OS handle transferred
/// exactly once to the caller; on failure `Err` carries
/// `Error::last_os_error()` captured immediately after the call.
pub(super) fn create_private_new_raw(path: &Path) -> io::Result<File> {
    create_new_with_sddl(path, SDDL_OWNER_RIGHTS_PROTECTED)
}

fn create_new_with_sddl(path: &Path, sddl: &[u16]) -> io::Result<File> {
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_MODE,
    };

    let wide = wide_path(path)?;
    let descriptor = convert_sddl_to_descriptor(sddl)?;
    // From here on, every failure path must local_free(descriptor)
    // exactly once before returning.
    let attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // SAFETY: `wide` is a valid, owned, NUL-terminated UTF-16 buffer
    // that outlives the call. `attrs` points to a fully initialized
    // SECURITY_ATTRIBUTES whose `lpSecurityDescriptor` remains valid
    // for the duration of the call (freed by us afterwards, never by
    // the OS). dwShareMode = 0 requests exclusive access. On success
    // the OS transfers ownership of the returned handle to us; the
    // handle is then wrapped exactly once into a File below and never
    // used raw again. On failure we capture last_os_error() before
    // any cleanup/allocation.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0u32 as FILE_SHARE_MODE,
            &attrs,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        let err = io::Error::last_os_error();
        // SAFETY: descriptor came from convert_sddl_to_descriptor
        // and has not been freed yet; freed exactly once here.
        let freed_cleanly = unsafe { local_free(descriptor) };
        let _ = freed_cleanly; // best-effort; non-null after free is tolerated
        return Err(map_create_error(err));
    }
    // SAFETY: CreateFileW returned an owned, valid handle (checked
    // against INVALID_HANDLE_VALUE and NULL above) with generic
    // read/write access. std::fs::File takes ownership and closes it
    // via CloseHandle on drop — the handle is transferred exactly
    // once and no raw use occurs afterwards. The descriptor is freed
    // exactly once; the File owns only the handle.
    let file: File = unsafe { FromRawHandle::from_raw_handle(handle) };
    // SAFETY: as above: single release of LocalAlloc-owned memory,
    // before any further failure can occur.
    let freed_cleanly = unsafe { local_free(descriptor) };
    let _ = freed_cleanly;
    Ok(file)
}

/// Maps ERROR_FILE_EXISTS to `ErrorKind::AlreadyExists` while
/// preserving the OS error code.
fn map_create_error(err: io::Error) -> io::Error {
    if err.raw_os_error() == Some(windows_sys::Win32::Foundation::ERROR_FILE_EXISTS as i32) {
        io::Error::from(io::ErrorKind::AlreadyExists)
    } else {
        err
    }
}

/// Reads the owner + DACL of an already-opened kernel handle into a
/// freshly allocated buffer, growing on ERROR_INSUFFICIENT_BUFFER
/// with a hard 64 KiB cap. The buffer is sized only by the OS reply,
/// never from untrusted input.
pub(super) fn query_security(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> io::Result<(Vec<usize>, usize)> {
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetKernelObjectSecurity, OWNER_SECURITY_INFORMATION,
    };
    const CAP: usize = 64 * 1024;
    let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut requested = 512usize;
    loop {
        if requested > CAP {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "security descriptor exceeds 64 KiB cap",
            ));
        }
        let mut words = vec![0usize; requested.div_ceil(std::mem::size_of::<usize>())];
        let offered = words.len() * std::mem::size_of::<usize>();
        let mut needed = 0u32;
        // SAFETY: the File keeps handle open. Initialized usize storage
        // supplies pointer-aligned writable bytes, bounded by CAP. Windows
        // writes no more than offered bytes and returns self-relative data.
        let ok = unsafe {
            GetKernelObjectSecurity(
                handle,
                info,
                words.as_mut_ptr().cast(),
                offered as u32,
                &mut needed,
            )
        };
        if ok != 0 {
            let used = needed as usize;
            if used == 0 || used > offered {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid security descriptor length",
                ));
            }
            return Ok((words, used));
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error()
            != Some(windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER as i32)
        {
            return Err(err);
        }
        requested = (needed as usize).max(offered.saturating_mul(2));
    }
}

/// SAFETY (returned triple): all pointers are derived from the
/// self-relative descriptor `buf` returned by GetKernelObjectSecurity
/// and are valid while `buf` is alive and unmodified.
pub(super) type DescriptorParts<'a> = (
    &'a [u8],                                                  // owner SID bytes
    Option<&'a [u8]>,                                          // DACL bytes
    windows_sys::Win32::Security::SECURITY_DESCRIPTOR_CONTROL, // control flags
);

/// Extracts owner, DACL, and control flags, rejecting missing private-file
/// components and spans outside the descriptor.
///
/// # Safety
/// `buf` must hold a valid, pointer-aligned self-relative descriptor with all
/// referenced components contained in it, alive and unmodified while borrowed.
/// Production callers use `GetKernelObjectSecurity`; arbitrary malformed bytes
/// must never be sent to the Win32 descriptor getters.
pub(super) unsafe fn parse_descriptor(buf: &[u8]) -> io::Result<DescriptorParts<'_>> {
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
        PSECURITY_DESCRIPTOR,
    };
    if buf.len() < std::mem::size_of::<windows_sys::Win32::Security::SECURITY_DESCRIPTOR_RELATIVE>()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "security descriptor too small",
        ));
    }
    let sd = buf.as_ptr() as PSECURITY_DESCRIPTOR;
    // SAFETY: `sd` points to a buffer of at least
    // sizeof(SECURITY_DESCRIPTOR_RELATIVE) bytes, per the size check above;
    // the OS only reads it. Output pointers remain valid inside
    // `buf` (self-relative form) for its lifetime.
    let mut owner: windows_sys::Win32::Security::PSID = std::ptr::null_mut();
    let mut owner_default: windows_sys::core::BOOL = 0;
    let mut dacl: *mut windows_sys::Win32::Security::ACL = std::ptr::null_mut();
    let mut dacl_present: windows_sys::core::BOOL = 0;
    let mut _dacl_default: windows_sys::core::BOOL = 0;
    let mut control: windows_sys::Win32::Security::SECURITY_DESCRIPTOR_CONTROL = 0;
    let mut _revision: u32 = 0;
    // SAFETY: sd is valid and pointer-aligned under the caller contract.
    // These getters only read it and write the initialized local outputs;
    // returned pointers borrow the same self-relative descriptor storage.
    let (ok_owner, ok_dacl, ok_control) = unsafe {
        (
            GetSecurityDescriptorOwner(sd, &mut owner, &mut owner_default),
            GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl, &mut _dacl_default),
            GetSecurityDescriptorControl(sd, &mut control, &mut _revision),
        )
    };
    if ok_owner == 0 || ok_dacl == 0 || ok_control == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "GetSecurityDescriptor* failed on returned descriptor",
        ));
    }
    if owner.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "security descriptor has no owner",
        ));
    }
    if dacl_present == 0 || dacl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "security descriptor has no DACL",
        ));
    }
    // Owner SID must be well-formed and lie fully within the buffer.
    let owner_slice = sid_slice(owner, buf)?;
    let tail = descriptor_tail(dacl.cast(), buf)?;
    let header = tail.get(..8).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "DACL header is out of bounds")
    })?;
    let len = u16::from_le_bytes([header[2], header[3]]) as usize;
    let dacl_bytes = tail
        .get(..len)
        .filter(|bytes| bytes.len() >= 8)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "DACL extends outside the descriptor buffer",
            )
        })?;
    Ok((owner_slice, Some(dacl_bytes), control))
}

/// Converts a pointer-into-`buf` SID into a byte slice, verifying it
/// is well-formed and fully contained in `buf`. The returned slice
/// borrows `buf`.
fn descriptor_tail(pointer: *const u8, buf: &[u8]) -> io::Result<&[u8]> {
    let offset = (pointer as usize)
        .checked_sub(buf.as_ptr() as usize)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "descriptor pointer precedes its buffer",
            )
        })?;
    buf.get(offset..).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "descriptor pointer exceeds its buffer",
        )
    })
}

fn sid_slice(sid: windows_sys::Win32::Security::PSID, buf: &[u8]) -> io::Result<&[u8]> {
    let tail = descriptor_tail(sid.cast(), buf)?;
    let header = tail.get(..8).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "owner SID header is out of bounds",
        )
    })?;
    let count = usize::from(header[1]);
    let len = 8 + count * 4;
    if header[0] != 1 || count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "owner SID is malformed",
        ));
    }
    tail.get(..len).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "owner SID extends outside its buffer",
        )
    })
}

/// FFI boundary implementation of [`super::validate_owner_only`]:
/// inspects the CURRENT security descriptor of an already-opened
/// file. See the outer safe wrapper for the documented contract.
pub(super) fn validate_owner_only_raw(file: &File) -> io::Result<()> {
    use windows_sys::Win32::Security::SE_DACL_PROTECTED;

    // The handle is borrowed from the File and never closed here.
    let handle: windows_sys::Win32::Foundation::HANDLE = file.as_raw_handle();
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "file has an invalid handle",
        ));
    }
    let (words, used) = query_security(handle)?;
    // SAFETY: query_security checks used <= initialized storage size.
    // All usize bit patterns are valid after Windows' byte writes. words
    // stays alive and immutable; byte views need no additional alignment.
    let buf = unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), used) };
    // SAFETY: the pointer-aligned buffer is an OS-produced self-relative
    // descriptor, alive and unmodified throughout inspection.
    let (_owner, dacl, control) = unsafe { parse_descriptor(buf)? };
    let descriptor_bytes = dacl.expect("parse_descriptor guarantees a DACL");
    if control & SE_DACL_PROTECTED == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DACL is not protected",
        ));
    }

    validate_dacl(descriptor_bytes)
}

fn validate_dacl(descriptor_bytes: &[u8]) -> io::Result<()> {
    use windows_sys::Win32::Security::INHERITED_ACE;
    let header = descriptor_bytes
        .get(..8)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "DACL header is truncated"))?;
    if usize::from(u16::from_le_bytes([header[2], header[3]])) != descriptor_bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DACL size mismatch",
        ));
    }
    // ACE layout (verified against windows-sys 0.61.2 and
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_ace):
    // `#[repr(C)] ACE_HEADER { AceType: u8, AceFlags: u8, AceSize: u16 }`
    // (4 bytes, no padding), then `Mask: u32` at byte offset 4, then
    // `SidStart` at byte offset 8 — the SID begins at offset 8
    // within the ACE. ACCESS_DENIED_ACE has the identical layout.
    // Offsets here are read as raw little-endian bytes, so no typed
    // pointer (and hence no alignment assumption) is required.
    let ace_count = u16::from_le_bytes([descriptor_bytes[4], descriptor_bytes[5]]) as usize;
    let mut offset = 8usize; // sizeof(ACL) fixed header
    let mut allow_owner_rights_aces = 0usize;
    for _ in 0..ace_count {
        if offset + 4 > descriptor_bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ACE header extends outside the ACL",
            ));
        }
        let ace_type = descriptor_bytes[offset];
        let ace_flags = descriptor_bytes[offset + 1];
        let ace_size =
            u16::from_le_bytes([descriptor_bytes[offset + 2], descriptor_bytes[offset + 3]])
                as usize;
        // Full-ACE bounds: header (4) + mask (4) + minimal SID room.
        if ace_size < 8 + MIN_FULL_SID || offset + ace_size > descriptor_bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ACE extends outside the ACL or is too small",
            ));
        }
        if ace_flags & (INHERITED_ACE as u8) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "ACE is inherited; a PROTECTED DACL must contain none",
            ));
        }
        let mask = u32::from_le_bytes(
            descriptor_bytes[offset + 4..offset + 8]
                .try_into()
                .expect("slice is exactly 4 bytes"),
        );
        // SID extent within the ACE: [offset+8, offset+ace_size).
        let sid_bytes = &descriptor_bytes[offset + 8..offset + ace_size];
        if is_access_allowed(ace_type) {
            if mask == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ALLOW ACE has a zero mask",
                ));
            }
            // Any non-zero mask is accepted for the Owner Rights SID,
            // including FILE_ALL_ACCESS: OW limits evaluation to the
            // owner, so granting owner-all-access is the intended
            // policy here.
            validate_sid_bytes(sid_bytes)?;
            if sid_bytes[..12] != OWNER_RIGHTS_SID {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "ALLOW ACE grants access to a principal other than Owner Rights (S-1-3-4)",
                ));
            }
            allow_owner_rights_aces += 1;
        } else if is_access_denied(ace_type) {
            // DENY ACEs for any principal may coexist; the SID must
            // still be well-formed and fully in bounds.
            validate_sid_bytes(sid_bytes)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unrecognized ACE type; failing closed",
            ));
        }
        offset += ace_size;
    }
    if allow_owner_rights_aces == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DACL contains no ALLOW ACE for Owner Rights; nobody could read the key",
        ));
    }
    Ok(())
}

fn is_access_allowed(ace_type: u8) -> bool {
    ace_type == ACE_TYPE_ACCESS_ALLOWED
}

fn is_access_denied(ace_type: u8) -> bool {
    ace_type == ACE_TYPE_ACCESS_DENIED
}

/// Checks that an ACE's embedded SID is well-formed: revision 1,
/// non-zero subauthority count, and its full extent
/// (`8 + 4 * count` bytes) lies within the provided byte slice.
fn validate_sid_bytes(sid_bytes: &[u8]) -> io::Result<()> {
    if sid_bytes.len() < MIN_FULL_SID {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ACE SID is truncated",
        ));
    }
    let revision = sid_bytes[0];
    let count = sid_bytes[1] as usize;
    let expected_len = 8 + count * 4;
    if revision != 1 || count == 0 || sid_bytes.len() < expected_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ACE SID is malformed",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn null_dacl_fixture_result() -> io::Result<()> {
    use windows_sys::Win32::Security::{
        IsValidSecurityDescriptor, SE_DACL_PRESENT, SE_DACL_PROTECTED, SE_SELF_RELATIVE,
        SECURITY_DESCRIPTOR_RELATIVE,
    };
    #[repr(C, align(8))]
    struct Descriptor {
        header: SECURITY_DESCRIPTOR_RELATIVE,
        owner: [u8; 12],
    }
    let mut descriptor = Descriptor {
        header: SECURITY_DESCRIPTOR_RELATIVE {
            Revision: 1,
            Sbz1: 0,
            Control: SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_PROTECTED,
            Owner: std::mem::offset_of!(Descriptor, owner) as u32,
            Group: 0,
            Sacl: 0,
            Dacl: 0,
        },
        owner: [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0], // Local System SID
    };
    let length = std::mem::size_of::<Descriptor>();
    if length != std::mem::size_of::<SECURITY_DESCRIPTOR_RELATIVE>() + 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected fixture padding",
        ));
    }
    let pointer = std::ptr::from_mut(&mut descriptor).cast();
    // SAFETY: pointer-aligned initialized C layout, owner offset contained in
    // the allocation, null optional components. NULL DACL is valid Windows data.
    let valid = unsafe { IsValidSecurityDescriptor(pointer) };
    if valid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native fixture is invalid",
        ));
    }
    // SAFETY: the size check excludes padding, all fields are initialized, and
    // descriptor remains alive and immutable for the byte view and getters.
    let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), length) };
    // SAFETY: the fixed self-relative fixture has bounded offsets and passed
    // native validation; no dangling or deliberately malformed pointer is used.
    unsafe { parse_descriptor(bytes).map(|_| ()) }
}

#[cfg(test)]
mod anonymous;
#[cfg(test)]
mod authz;
#[cfg(test)]
mod tests;
