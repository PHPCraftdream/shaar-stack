#![forbid(unsafe_code)]
//! Custom-only baseline for the iroh v1.3.0 transport feasibility gate.
//!
//! The fixture provides bounded datagram queues, an authenticated echo
//! connection, and per-file/direction qlog calibration. The sole transport
//! is established by topology, not by multipath packet attribution.
//!
//! Strict signaling-only enforcement, path migration, and real NAT traversal
//! remain unproven and block dependent implementation. This package cannot
//! grant P03 acceptance. Compilation and execution run only in GitHub CI.

pub mod harness;
pub mod mem_transport;
pub mod qlog_oracle;

pub use mem_transport::{MemNetwork, MemTransport, TEST_TRANSPORT_ID};
