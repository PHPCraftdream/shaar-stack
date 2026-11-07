#![forbid(unsafe_code)]
//! Key-addressed Yggdrasil datagrams without TUN over the pinned Yggdrasil-ng core.
//!
//! The prepared core (`c9a54f1587bb133a06072596484c972a336db0d2`, with the reviewed
//! lifecycle patch) lives under `target/ygg/`; the source gate is
//! `docs/verification/rust-ygg.md`. [`YggTransport`] sends and receives datagrams
//! addressed by the 32-byte peer key; the adapter adds no queue of its own.

mod address;
mod registry;
mod transport;
mod validate;

pub use address::address_for_key;
pub use transport::{YggConfig, YggError, YggTransport};
pub use validate::uri_supported;

#[cfg(test)]
mod smoke {
    use std::any::type_name;

    /// The prepared core library must link and expose the documented core type.
    #[test]
    fn prepared_core_links_and_names_core_type() {
        assert!(type_name::<yggdrasil::core::Core>().ends_with("::Core"));
    }

    /// The library root itself must keep forbidding unsafe code.
    #[test]
    fn crate_root_forbids_unsafe_code() {
        assert_eq!(
            include_str!("lib.rs").lines().next(),
            Some("#![forbid(unsafe_code)]")
        );
    }
}
