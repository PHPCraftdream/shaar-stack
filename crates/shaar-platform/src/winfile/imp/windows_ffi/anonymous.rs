//! Test-only file reads under the built-in anonymous principal.
//!
//! Impersonation is limited to one newly created OS thread. No account,
//! registry, process token, or parent-directory ACL is changed.

use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    Security::{ImpersonateAnonymousToken, RevertToSelf},
    System::Threading::{GetCurrentThreadId, OpenThread, THREAD_IMPERSONATE},
};

struct ThreadHandle(HANDLE);

impl Drop for ThreadHandle {
    fn drop(&mut self) {
        // SAFETY: owned real OpenThread handle, not a pseudo-handle; final close.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

struct Anonymous {
    _thread: ThreadHandle,
}

impl Anonymous {
    fn enter() -> io::Result<Self> {
        // SAFETY: queries this synchronous test worker's own OS thread id.
        let id = unsafe { GetCurrentThreadId() };
        // SAFETY: requests only documented THREAD_IMPERSONATE access to that
        // live current thread; the returned nonnull handle is owned locally.
        let handle = unsafe { OpenThread(THREAD_IMPERSONATE, 0, id) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let thread = ThreadHandle(handle);
        // SAFETY: this real handle has THREAD_IMPERSONATE rights and identifies
        // only the current worker. There is no await or cross-thread transfer.
        let ok = unsafe { ImpersonateAnonymousToken(thread.0) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { _thread: thread })
    }
}

impl Drop for Anonymous {
    fn drop(&mut self) {
        // SAFETY: restores this same worker after successful impersonation,
        // including unwind/error paths; the guard is not Send/Sync or exposed.
        let restored = unsafe { RevertToSelf() };
        if restored == 0 {
            // Microsoft requires fail-closed process shutdown on restore failure.
            // This can abort only the CI test process; native code never runs locally.
            std::process::abort();
        }
    }
}

/// Outer errors are setup/join failures; inner errors come from the real read.
/// This separation prevents impersonation failure from masquerading as denial.
pub(super) fn read(path: &Path) -> io::Result<io::Result<Vec<u8>>> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| -> io::Result<io::Result<Vec<u8>>> {
                let _identity = Anonymous::enter()?;
                Ok((|| {
                    let file = File::open(path)?;
                    let mut bytes = Vec::with_capacity(33);
                    file.take(33).read_to_end(&mut bytes)?;
                    Ok(bytes)
                })())
            })
            .join()
            .map_err(|_| io::Error::other("anonymous reader thread panicked"))?
    })
}
