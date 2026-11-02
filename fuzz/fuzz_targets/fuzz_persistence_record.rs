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

const KEY: [u8; 32] = [0x77; 32];
const FOREIGN: [u8; 32] = [0x78; 32];

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    match CapabilityRecord::from_json(text) {
        Ok(record) => {
            // 2. The parser is not a verifier: a record with a seal must not
            //    verify under a key it was not sealed with, and one without a
            //    seal never verifies at all.
            assert!(
                !record.seal_is_valid(&FOREIGN),
                "a record verified under a key it was not sealed with"
            );
            if record.seal.is_some() {
                assert!(
                    !record.seal_is_valid(&KEY),
                    "an arbitrary seal must not verify under the deployment key"
                );
            }

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
            let mut sealed = record.clone();
            sealed.seal_with(&KEY);
            assert!(sealed.seal_is_valid(&KEY), "a sealed record must verify");
            assert!(
                !sealed.seal_is_valid(&FOREIGN),
                "a sealed record must not verify under another key"
            );
            // Editing any field breaks the seal.
            let mut edited = sealed.clone();
            edited.methods.insert("appended".to_string());
            assert!(
                !edited.seal_is_valid(&KEY),
                "an edited record must not verify"
            );
        }
        Err(error) => assert_eq!(
            error.code(),
            "rpc/persistence",
            "a refused record must be a persistence error, got {error}"
        ),
    }
});
