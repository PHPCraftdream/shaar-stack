#![forbid(unsafe_code)]

#[path = "tests/admission.rs"]
mod admission;
#[path = "tests/allowlist.rs"]
mod allowlist;
#[path = "tests/capacity.rs"]
mod capacity;
#[path = "tests/production_join.rs"]
mod production_join;
#[path = "tests/runtime.rs"]
mod runtime;
#[path = "tests/shutdown.rs"]
mod shutdown;
