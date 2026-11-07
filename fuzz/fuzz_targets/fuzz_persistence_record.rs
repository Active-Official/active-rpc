#![no_main]

//! The durable-capability record parser: arbitrary JSON from a store.
//!
//! Invariants under test (I-8, durable state):
//!
//! 1. `CapabilityRecord::from_json` is total over arbitrary text: a record or a
//!    `rpc/persistence` refusal, never a panic, and never a record that
//!    re-encodes to different bytes (canonical round trip).
//! 2. A record that parses never carries a valid seal for a key it was not
//!    sealed with: the seal is a keyed hash, so a tampered field or a foreign
//!    key must fail `seal_is_valid`.
//! 3. A record the parser accepts survives a `to_json`/`from_json` round trip
//!    unchanged, so a seal computed over one form verifies over the other.
//!
//! The restore path (`Agent::restore_capability`) reads exactly these bytes, and
//! the parser is the boundary that used to have no coverage.
//!
//! Run with `cargo +nightly fuzz run fuzz_persistence_record -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_rpc::persistence::CapabilityRecord;
use active_rpc::Budget;

const KEY: [u8; 32] = [0x77; 32];
const FOREIGN: [u8; 32] = [0x78; 32];

/// A record the parser must accept. Without this the target passed when
/// `from_json` refused every input (R-20 round 3, H1 and M3).
fn probe() -> CapabilityRecord {
    CapabilityRecord {
        provider: "echo".to_string(),
        object: 0,
        methods: ["echo".to_string()].into_iter().collect(),
        budget: Budget::default(),
        read_only: false,
        redact: false,
        path_scope: None,
        topics: None,
        publish: false,
        tool_policy: None,
        bound_to: Some([0x22; 32]),
        expires_at: Some(60_000),
        wall_clock: false,
        lease_ms: Some(60_000),
        record_id: [0x33; 32],
        seal: None,
    }
}

fuzz_target!(|data: &[u8]| {
    // Fixed positive control before the fuzzed input.
    let fixed = probe();
    let fixed_text = fixed.to_json();
    let parsed = CapabilityRecord::from_json(&fixed_text)
        .expect("the fixed record parses");
    let mut sealed = parsed.clone();
    sealed.seal_with(&KEY);
    assert!(sealed.seal_is_valid(&KEY), "a sealed record verifies");
    assert!(
        !sealed.seal_is_valid(&FOREIGN),
        "a sealed record does not verify under another key"
    );

    if data.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    match CapabilityRecord::from_json(text) {
        Ok(record) => {
            // The parser is not a verifier, but `FOREIGN` is a public key and a
            // record sealed under it is legitimate: asserting that *every*
            // parsed record fails under `FOREIGN` panicked on such a seed
            // (R-20 round 6, finding 4). The fixed probe above proves the key
            // separation; here a record verifies only under the key that
            // sealed it.
            // Seal the parsed record ourselves, then edit a field that always
            // changes: the earlier edit inserted a method name, which is a
            // no-op when the record already grants it (R-20 round 4, #2).
            let mut sealed_here = record.clone();
            sealed_here.seal_with(&KEY);
            assert!(sealed_here.seal_is_valid(&KEY));
            let mut edited = sealed_here.clone();
            edited.object ^= 1;
            assert_ne!(edited, sealed_here, "the edit must change the record");
            assert!(
                !edited.seal_is_valid(&KEY),
                "an edited record must not verify"
            );

            // 3. Canonical round trip: a record that parses re-parses to itself
            //    and re-encodes to the same bytes.
            let encoded = record.to_json();
            let again = CapabilityRecord::from_json(&encoded)
                .expect("a record the parser produced must parse");
            assert_eq!(again, record, "a round trip changed the record");
            assert_eq!(
                again.to_json(),
                encoded,
                "encoding the same record twice differs"
            );

            // A record we seal ourselves verifies under our key and only ours.
            assert!(
                !sealed_here.seal_is_valid(&FOREIGN),
                "a sealed record must not verify under another key"
            );
        }
        Err(error) => assert_eq!(
            error.code(),
            "rpc/persistence",
            "a refused record must be a persistence error, got {error}"
        ),
    }
});
