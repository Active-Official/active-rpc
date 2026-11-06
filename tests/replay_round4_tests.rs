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

/// A package edited in its cap ordinals alone is reported with the ordinal, not
/// as two identical events (round 4, L-4).
#[test]
fn a_mismatch_names_the_ordinal() {
    let mut recorder = Recorder::new(0).expect("recorder");
    let cap = recorder.mint(&["echo"], None).expect("mint");
    recorder.call(cap, "echo", 4).expect("call");
    let mut package = recorder.package().expect("package");
    let first = package
        .trace
        .iter()
        .position(|entry| entry.cap.is_some())
        .expect("a cap entry");
    package.trace[first].cap = Some(9);
    let error = package.replay().expect_err("the ordinal was edited");
    let text = error.to_string();
    assert!(text.contains("cap Some(9)"), "{text}");
    assert!(text.contains("cap Some(0)"), "{text}");
}

/// The encoded layout is pinned byte for byte: a tag or field-order change must
/// update this golden deliberately, because a round-trip alone is
/// self-consistent (R-12 round 4, L-8).
#[test]
fn the_package_layout_is_pinned() {
    use active_rpc::replay::{Op, ReplayPackage, Trace};
    let package = ReplayPackage {
        latency_ms: 7,
        ops: vec![
            Op::SetLatency(7),
            Op::Mint {
                methods: vec!["echo".to_string()],
                ttl_ms: None,
            },
        ],
        trace: vec![
            Trace {
                event: "lane.created".to_string(),
                cap: None,
            },
            Trace {
                event: "cap.minted".to_string(),
                cap: Some(0),
            },
        ],
    };
    let bytes = package.encode().expect("encode");
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(bytes.len(), 110, "the encoded length moved");
    assert_eq!(
        hex,
        "4152525001000007000000000000000200000001070000000000000002010004006563686f0002000000000c0000006c616e652e63726561746564010a0000006361702e6d696e74656400000000cfb09c66e5ce814d4282f92539fe64741f0fb9717c01d8615d4a61a05a87ffd5",
        "the ARRP layout moved; update this golden only for a deliberate format change"
    );
    // And the pinned bytes decode to the same package.
    let decoded = ReplayPackage::decode(&bytes).expect("decode");
    assert_eq!(decoded.latency_ms, 7);
    assert_eq!(decoded.ops.len(), 2);
    assert_eq!(decoded.trace.len(), 2);
}
