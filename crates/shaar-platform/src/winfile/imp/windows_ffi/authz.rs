//! Test-only native authorization oracle, not a logon or impersonation helper.
//!
//! API contracts: Microsoft Learn authz/AuthzInitializeResourceManager,
//! AuthzInitializeContextFromSid, AuthzAccessCheck, AuthzFreeContext, and
//! AuthzFreeResourceManager; signatures verified in windows-sys 0.61.2.

use std::{fs::File, io, marker::PhantomData, os::windows::io::AsRawHandle};
use windows_sys::Win32::{
    Foundation::{ERROR_ACCESS_DENIED, LUID},
    Security::Authorization::{
        AUTHZ_ACCESS_REPLY, AUTHZ_ACCESS_REQUEST, AUTHZ_CLIENT_CONTEXT_HANDLE,
        AUTHZ_RESOURCE_MANAGER_HANDLE, AUTHZ_RM_FLAG_NO_AUDIT, AUTHZ_SKIP_TOKEN_GROUPS,
        AuthzAccessCheck, AuthzFreeContext, AuthzFreeResourceManager,
        AuthzInitializeContextFromSid, AuthzInitializeResourceManager,
    },
    Storage::FileSystem::FILE_GENERIC_READ,
};

#[repr(C, align(8))]
struct WorldSid([u8; 12]);

struct Manager(AUTHZ_RESOURCE_MANAGER_HANDLE);

impl Manager {
    fn new() -> io::Result<Self> {
        let mut handle = std::ptr::null_mut();
        // SAFETY: initialized writable output; optional callbacks/name are null.
        // NO_AUDIT avoids privilege changes. A successful handle is owned here.
        let ok = unsafe {
            AuthzInitializeResourceManager(
                AUTHZ_RM_FLAG_NO_AUDIT,
                None,
                None,
                None,
                std::ptr::null(),
                &mut handle,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if handle.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "null Authz manager",
            ));
        }
        Ok(Self(handle))
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        // SAFETY: exactly one release of an owned manager; Context's lifetime
        // and declaration order ensure no client context outlives this owner.
        unsafe {
            let _ = AuthzFreeResourceManager(self.0);
        }
    }
}

struct Context<'a> {
    handle: AUTHZ_CLIENT_CONTEXT_HANDLE,
    _owners: PhantomData<(&'a Manager, &'a WorldSid)>,
}

impl<'a> Context<'a> {
    fn new(manager: &'a Manager, sid: &'a WorldSid) -> io::Result<Self> {
        let mut handle = std::ptr::null_mut();
        // SAFETY: sid is an aligned, complete S-1-1-0 SID. Both borrowed owners
        // remain alive through Context drop. SKIP_TOKEN_GROUPS permits arbitrary
        // SIDs and prevents account/group lookup; there are no callbacks.
        let ok = unsafe {
            AuthzInitializeContextFromSid(
                AUTHZ_SKIP_TOKEN_GROUPS,
                sid.0.as_ptr().cast_mut().cast(),
                manager.0,
                std::ptr::null(),
                LUID {
                    LowPart: 0,
                    HighPart: 0,
                },
                std::ptr::null(),
                &mut handle,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if handle.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "null Authz context",
            ));
        }
        Ok(Self {
            handle,
            _owners: PhantomData,
        })
    }
}

impl Drop for Context<'_> {
    fn drop(&mut self) {
        // SAFETY: the context is owned, freed exactly once, and its manager/SID
        // are still alive. All native operations stay on this synchronous thread.
        unsafe {
            let _ = AuthzFreeContext(self.handle);
        }
    }
}

/// A SID-only Authz decision, not an actual File::open under another OS account.
/// Native API failures are errors, never interpreted as a denial.
pub(super) fn world_can_read(file: &File) -> io::Result<bool> {
    let (words, used) = super::query_security(file.as_raw_handle())?;
    // SAFETY: query_security returns initialized pointer-aligned storage with
    // checked used length; words remains alive and immutable during inspection.
    let bytes = unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), used) };
    // SAFETY: the buffer is a valid OS-produced self-relative descriptor.
    let (owner, _, _) = unsafe { super::parse_descriptor(bytes)? };
    let sid = WorldSid([1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]);
    if owner == sid.0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oracle SID is the file owner",
        ));
    }
    let manager = Manager::new()?;
    let context = Context::new(&manager, &sid)?;
    let request = AUTHZ_ACCESS_REQUEST {
        DesiredAccess: FILE_GENERIC_READ,
        PrincipalSelfSid: std::ptr::null_mut(),
        ObjectTypeList: std::ptr::null_mut(),
        ObjectTypeListLength: 0,
        OptionalArguments: std::ptr::null_mut(),
    };
    let mut granted = 0u32;
    let mut audit = 0;
    let mut error = 0u32;
    let mut reply = AUTHZ_ACCESS_REPLY {
        ResultListLength: 1,
        GrantedAccessMask: &mut granted,
        SaclEvaluationResults: &mut audit,
        Error: &mut error,
    };
    // SAFETY: valid live context and OS descriptor; request uses an explicit
    // file-specific mask (no generic mapping). All three one-entry result
    // buffers are initialized/writable. No callbacks, optional descriptors,
    // audit event, or cached result retain pointers beyond this call.
    let ok = unsafe {
        AuthzAccessCheck(
            0,
            context.handle,
            &request,
            std::ptr::null_mut(),
            words.as_ptr().cast_mut().cast(),
            std::ptr::null(),
            0,
            &mut reply,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    match error {
        0 if granted & FILE_GENERIC_READ == FILE_GENERIC_READ => Ok(true),
        code if code == ERROR_ACCESS_DENIED => Ok(false),
        code => Err(io::Error::other(format!(
            "unexpected Authz decision {code}, mask {granted}"
        ))),
    }
}
