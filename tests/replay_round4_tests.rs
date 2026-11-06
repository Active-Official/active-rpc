//! R-12 replay round 4: the recorder charges captured events against the
//! package ceiling, so a package it hands out always encodes.

use active_rpc::replay::{Recorder, MAX_PACKAGE_BYTES};

/// Every event the recorder captures is part of the encoded body: a session
/// heavy in refused calls either fits and encodes, or is refused while it is
/// recorded (round 4, M-1).
#[test]
fn a_package_that_exists_always_encodes() {
    let mut recorder = Recorder::new(1).expect("recorder");
    let cap = recorder.mint(&["echo"], None).expect("mint");
    // A long escaped method label makes each refusal's events several hundred
    // bytes, which is what the estimate used to miss.
    let label = format!("m{}", "\u{200b}".repeat(32));
    for _ in 0..2_000 {
        let _ = recorder.call(cap, &label, 8);
    }
    match recorder.package() {
        Ok(package) => {
            let bytes = package.encode().expect("a package encodes");
            assert!(!bytes.is_empty());
            assert!(
                bytes.len() <= MAX_PACKAGE_BYTES,
                "the body exceeded the ceiling: {}",
                bytes.len()
            );
        }
        Err(error) => {
            // A refused session is a refusal, never a package `encode` rejects.
            assert_eq!(error.code(), "rpc/replay", "{error}");
        }
    }
}

/// The body estimate never exceeds the decoder's ceiling for a session that
/// stays under the operation and trace ceilings (round 4, M-1).
#[test]
fn a_large_trace_still_packages() {
    let mut recorder = Recorder::new(0).expect("recorder");
    let cap = recorder.mint(&["echo"], None).expect("mint");
    for index in 0..20_000 {
        // A mix of successes and refusals: both emit events.
        let method = if index % 2 == 0 { "echo" } else { "missing" };
        let _ = recorder.call(cap, method, 4);
    }
    let package = recorder.package().expect("the session fits");
    let bytes = package.encode().expect("and encodes");
    assert!(bytes.len() <= MAX_PACKAGE_BYTES);
    // The encoded artifact is what a replay accepts.
    let decoded = active_rpc::replay::ReplayPackage::decode(&bytes).expect("decode");
    assert_eq!(decoded.ops.len(), package.ops.len());
}
