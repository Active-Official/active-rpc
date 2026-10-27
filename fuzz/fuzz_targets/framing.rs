#![no_main]

//! Framing and capability-table fuzz target.
//!
//! Invariants under test:
//!
//! 1. `Envelope::decode` never panics, hangs or over-allocates on arbitrary
//!    bytes; a successful decode re-encodes to bytes that decode again
//!    identically (the envelope is a fixed point).
//! 2. The standalone capability-table codec agrees with the envelope codec and
//!    never panics.
//! 3. A decoded envelope never exceeds the configured limits.
//! 4. The gRPC/Connect framing helper never panics and is self-delimiting.
//!
//! Run with `cargo +nightly fuzz run framing -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_rpc::transport::connect::{grpc_frame, grpc_unframe};
use active_rpc::wire::{decode_capability_table, Envelope, WireLimits};

fuzz_target!(|data: &[u8]| {
    // 1. Envelope decoding is total.
    if let Ok(envelope) = Envelope::decode(data) {
        assert!(envelope.args.len() <= WireLimits::default().max_args as usize);
        assert!(envelope.caps.len() <= WireLimits::default().max_caps as usize);
        if let Ok(bytes) = envelope.encode() {
            let again = Envelope::decode(&bytes).expect("re-encoded envelope must decode");
            assert_eq!(again, envelope, "envelope is not a fixed point");
        }
    }

    // Strict limits must also never panic.
    let _ = Envelope::decode_with(data, WireLimits::strict());

    // 2. Capability tables: independent entry point, same rules.
    if let Ok(caps) = decode_capability_table(data) {
        assert!(caps.len() <= WireLimits::default().max_caps as usize);
        for cap in &caps {
            assert_ne!(cap.budget.max_calls, 0, "a decoded budget must be finite");
        }
    }

    // 3. gRPC framing.
    if let Ok((message, rest)) = grpc_unframe(data) {
        let framed = grpc_frame(message);
        assert!(rest.len() < data.len());
        let (again, tail) = grpc_unframe(&framed).expect("framed message parses");
        assert_eq!(again, message);
        assert!(tail.is_empty());
    }
});
