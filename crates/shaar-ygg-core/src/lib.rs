#![forbid(unsafe_code)]
//! Key-addressed Yggdrasil datagrams without TUN over the pinned Yggdrasil-ng core.
//!
//! Leaf 53.1 only links the prepared core (`c9a54f1587bb133a06072596484c972a336db0d2`,
//! byte-exact under `target/ygg/`). No transport, shutdown or lifecycle API exists
//! yet; the source gate is `docs/verification/rust-ygg.md`.

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
        assert!(include_str!("lib.rs").starts_with("#![forbid(unsafe_code)]\n"));
    }
}
