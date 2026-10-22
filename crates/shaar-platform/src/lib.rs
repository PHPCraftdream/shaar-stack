#![deny(unsafe_code)]
//! Minimal Windows-native helpers for owner-only-private file creation.
//!
//! This crate exists because `std::fs` cannot attach a security descriptor
//! (DACL) at file-creation time, and the SDK root crate must keep
//! `#![forbid(unsafe_code)]`. The Windows FFI surface is isolated in the
//! `winfile` module, which exposes only safe functions operating on
//! [`std::fs::File`] and [`std::path::Path`] — raw handles and pointers are
//! never part of the public API.
//!
//! On non-Windows targets this crate compiles as an (almost) empty library;
//! callers are expected to cfg-gate on `windows`. No stubs are provided.

#[cfg(windows)]
pub mod winfile;
