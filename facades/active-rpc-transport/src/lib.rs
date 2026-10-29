//! Transport facade for `active-rpc`.
//!
//! Re-exports the in-process, TCP, shared-memory and optional QUIC transports.
//! The `quic` feature is enabled by default.

pub use active_rpc::transport::*;
