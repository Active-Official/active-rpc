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
    // Positive controls: a codec that refuses every input must fail the target
    // instead of making every assertion below dead (R-20 round 3, H1).
    let probe = Envelope::request(1, "ping", Vec::new());
    let probe_bytes = probe.encode().expect("the probe encodes");
    let probe = Envelope::decode(&probe_bytes).expect("the probe decodes");
    assert_eq!(probe.encode().expect("re-encode"), probe_bytes);
    let descriptor = active_rpc::wire::CapDescriptor::from_attrs(
        active_rpc::cap::CapId([0x11; 16]),
        &active_rpc::cap::CapAttrs::new(&["ping"]),
    );
    let table = active_rpc::wire::encode_capability_table(std::slice::from_ref(&descriptor))
        .expect("the probe table encodes");
    assert_eq!(
        decode_capability_table(&table).expect("the probe table decodes"),
        vec![descriptor]
    );

    // 1. Envelope decoding is total.
    if let Ok(envelope) = Envelope::decode(data) {
        assert!(envelope.args.len() <= WireLimits::default().max_args as usize);
        assert!(envelope.caps.len() <= WireLimits::default().max_caps as usize);
        if let Ok(bytes) = envelope.encode() {
            let again = Envelope::decode(&bytes).expect("re-encoded envelope must decode");
            // Byte equality is the fixed-point oracle, not `Envelope` equality: a
            // decoded `Float(NaN)` is not equal to itself, so `assert_eq!` on the
            // values fails for a perfectly stable encoding (nightly run
            // 41437025560, crash-86b29c5d).
            assert_eq!(
                again.encode().expect("re-encoded envelope must encode"),
                bytes,
                "envelope is not a fixed point"
            );
        }
    }

    // Strict and two arbitrary limit profiles must also never panic, and a
    // profile must bind: an envelope the default accepts with more arguments
    // than the strict limit allows must be refused under strict limits.
    if let Ok(envelope) = Envelope::decode(data) {
        let strict = WireLimits::strict();
        if envelope.args.len() > strict.max_args as usize
            || envelope.caps.len() > strict.max_caps as usize
        {
            assert!(
                Envelope::decode_with(data, strict).is_err(),
                "a strict profile must refuse the envelope it bounds"
            );
        }
    }
    let tiny = WireLimits {
        max_args: 1,
        max_caps: 1,
        ..WireLimits::default()
    };
    if let Ok(envelope) = Envelope::decode(data) {
        if envelope.args.len() > 1 || envelope.caps.len() > 1 {
            assert!(
                Envelope::decode_with(data, tiny).is_err(),
                "a one-argument profile must refuse a wider envelope"
            );
        }
    }

    // 2. Capability tables: independent entry point, same rules.
    if let Ok(caps) = decode_capability_table(data) {
        // The standalone decoder's own profile is MAX_CAP_TABLE, not the
        // envelope's WireLimits: a valid 300-cap table is legal input and must
        // not panic the harness (R-20 round 3, M2).
        assert!(caps.len() <= active_rpc::wire::MAX_CAP_TABLE);
        for cap in &caps {
            assert_ne!(cap.budget.max_calls, 0, "a decoded budget must be finite");
        }
    }

    // 3. gRPC framing.
    if let Ok((message, rest)) = grpc_unframe(data) {
        let Ok(framed) = grpc_frame(message) else { return };
        assert!(rest.len() < data.len());
        let (again, tail) = grpc_unframe(&framed).expect("framed message parses");
        assert_eq!(again, message);
        assert!(tail.is_empty());
    }
});
