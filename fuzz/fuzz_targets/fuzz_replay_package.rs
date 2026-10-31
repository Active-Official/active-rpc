#![no_main]

//! Replay packages (`ARRP`): decode, re-encode, record/replay agreement.
//!
//! Invariants under test:
//!
//! 1. `decode` is total over arbitrary bytes: it returns a package or a
//!    `rpc/replay` error, never a panic.
//! 2. A decoded package re-encodes to bytes that decode to the same value
//!    (the checksum is recomputed, so the round trip is stable).
//! 3. A package produced by driving the real `Recorder` replays with an
//!    identical trace. The recorder is the shipped path, so a divergence here
//!    is a real defect in recording or replay, not a property of hostile input.
//! 4. Any change to the recorded trace is detected: `replay()` refuses with
//!    `rpc/replay` instead of accepting a doctored decision log.
//!
//! Run with `cargo +nightly fuzz run fuzz_replay_package -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_rpc::replay::{Recorder, ReplayPackage};

/// Replaying is linear in the operation count; keep each fuzz execution cheap
/// while still covering multi-operation packages.
const REPLAY_OP_CEILING: usize = 512;

/// Drive the recorder from the input and check the whole round trip.
fn structured(data: &[u8]) {
    let latency = u64::from(data[0]) % 25;
    let mut recorder = match Recorder::new(latency) {
        Ok(recorder) => recorder,
        Err(error) => {
            assert_eq!(error.code(), "rpc/replay");
            return;
        }
    };

    // Each operation drives real kernel work; a short script keeps the
    // per-execution cost low enough for a long campaign.
    for chunk in data[1..].chunks(2).take(24) {
        let action = chunk[0];
        let argument = u64::from(*chunk.get(1).unwrap_or(&action));
        match action % 6 {
            0 => {
                let _ = recorder.mint(&["echo"], None);
            }
            1 => {
                let _ = recorder.mint(&["echo", "sum"], (argument % 2 == 1).then_some(argument));
            }
            2 => {
                let parent = u32::from((action / 6) % 8);
                let methods: &[&str] = match argument % 3 {
                    0 => &["echo"],
                    1 => &["echo", "sum"],
                    _ => &["echo", "sum", "slow"],
                };
                let _ = recorder.attenuate(parent, methods, None);
            }
            3 => {
                let cap = u32::from((action / 6) % 8);
                let _ = recorder.call(cap, "echo", (argument % 64) as usize);
            }
            4 => {
                let cap = u32::from((action / 6) % 8);
                let _ = recorder.revoke(cap);
            }
            _ => recorder.set_latency(argument % 50),
        }
    }

    let package = recorder.package();
    let encoded = package.encode();
    let decoded =
        ReplayPackage::decode(&encoded).expect("a package the recorder produced must decode");
    assert_eq!(decoded, package, "re-encode did not preserve the package");

    decoded
        .replay()
        .expect("a package recorded through the shipped path must replay exactly");

    // A single altered decision is caught.
    if !package.trace.is_empty() {
        let mut tampered = decoded.clone();
        tampered.trace[0].event.push('!');
        assert_ne!(tampered.trace, decoded.trace);
        let error = tampered
            .replay()
            .expect_err("a doctored trace must be refused");
        assert_eq!(error.code(), "rpc/replay");
    }
}

fuzz_target!(|data: &[u8]| {
    // Arbitrary bytes: the decoder is total and its own fixed point.
    match ReplayPackage::decode(data) {
        Ok(package) => {
            if package.ops.len() > REPLAY_OP_CEILING {
                return;
            }
            let encoded = package.encode();
            let again =
                ReplayPackage::decode(&encoded).expect("a freshly encoded package must decode");
            assert_eq!(again, package, "re-encode changed the package");
            assert_eq!(
                again.encode(),
                encoded,
                "encoding the same package twice differs"
            );
            // A replay either reproduces the recorded trace or refuses; it never
            // panics and never reports success on a different trace.
            match package.replay() {
                Ok(()) => {}
                Err(error) => assert_eq!(error.code(), "rpc/replay"),
            }
        }
        Err(error) => assert_eq!(
            error.code(),
            "rpc/replay",
            "decode refused with an unexpected code: {error}"
        ),
    }

    if !data.is_empty() {
        structured(data);
    }
});
