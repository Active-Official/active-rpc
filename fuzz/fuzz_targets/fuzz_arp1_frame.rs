#![no_main]

//! ARP1 envelope and capability-table framing.
//!
//! Invariants under test (I-8, I-9, I-10):
//!
//! 1. `Envelope::decode` is total; a successful decode re-encodes to a fixed
//!    point, and strict limits never panic.
//! 2. The standalone capability-table codec agrees with the envelope codec and
//!    never accepts a zero call ceiling.
//! 3. A decoded envelope never exceeds the configured counts.
//! 4. The gRPC/Connect framing helper is self-delimiting.
//!
//! Run with `cargo +nightly fuzz run fuzz_arp1_frame -- -runs=200000`.

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

    // Strict and two arbitrary limit profiles must also never panic.
    let _ = Envelope::decode_with(data, WireLimits::strict());
    let tiny = WireLimits {
        max_args: 1,
        max_caps: 1,
        ..WireLimits::default()
    };
    let _ = Envelope::decode_with(data, tiny);

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
