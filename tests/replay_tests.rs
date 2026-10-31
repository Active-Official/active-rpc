//! Deterministic replay packages: a recorded session replays to the same
//! decision trace, and tampered, truncated or inconsistent packages are
//! refused.

use active_rpc::replay::{Op, Recorder, ReplayPackage, Trace};

fn session(latency_ms: u64) -> Recorder {
    Recorder::new(latency_ms).expect("recorder")
}

fn demo_session() -> ReplayPackage {
    let mut recorder = session(10);
    let echo = recorder.mint(&["echo"], None).expect("mint");
    recorder.call(echo, "echo", 5).expect("call");
    recorder.call(echo, "refuse", 0).expect("refusal");
    let child = recorder.attenuate(echo, &["echo"], None).expect("child");
    recorder.call(child, "echo", 0).expect("child call");
    recorder.revoke(echo).expect("revoke");
    recorder.call(echo, "echo", 0).expect("revoked call");
    recorder.package()
}

#[test]
fn a_recorded_session_replays_with_the_same_trace() {
    let package = demo_session();
    assert!(package.ops.len() >= 6);
    assert!(package
        .trace
        .iter()
        .any(|entry| entry.event == "cap.minted"));
    assert!(package
        .trace
        .iter()
        .any(|entry| entry.event.starts_with("call.refused:")));
    let encoded = package.encode();
    let decoded = ReplayPackage::decode(&encoded).expect("decode");
    assert_eq!(decoded, package);
    decoded.replay().expect("replay");

    // The encoded form is deterministic.
    assert_eq!(decoded.encode(), encoded);
}

#[test]
fn a_tampered_byte_is_refused() {
    let encoded = demo_session().encode();
    for index in [8usize, 19, encoded.len() / 2, encoded.len() - 1] {
        let mut tampered = encoded.clone();
        tampered[index] ^= 0x01;
        let error = ReplayPackage::decode(&tampered).expect_err("tamper must be refused");
        assert_eq!(error.code(), "rpc/replay", "byte {index}: {error}");
    }
}

#[test]
fn a_truncated_package_is_refused() {
    let encoded = demo_session().encode();
    for length in [0usize, 10, encoded.len() - 1] {
        let error = ReplayPackage::decode(&encoded[..length]).expect_err("truncation");
        assert_eq!(error.code(), "rpc/replay");
    }
}

#[test]
fn an_unknown_operation_tag_is_refused() {
    let mut encoded = demo_session().encode();
    // Header: magic(4) + version(1) + flags(2) + latency(8) + op_count(4).
    let first_op_tag = 4 + 1 + 2 + 8 + 4;
    encoded[first_op_tag] = 9;
    let body_len = encoded.len() - 32;
    let checksum = blake3::hash(&encoded[..body_len]);
    encoded[body_len..].copy_from_slice(checksum.as_bytes());
    let error = ReplayPackage::decode(&encoded).expect_err("unknown tag");
    assert_eq!(error.code(), "rpc/replay");
    assert!(
        error.to_string().contains("unknown operation tag"),
        "{error}"
    );
}

#[test]
fn a_package_that_references_a_missing_capability_is_refused() {
    let mut package = demo_session();
    let call = package
        .ops
        .iter_mut()
        .find_map(|op| match op {
            Op::Call { cap, .. } => Some(cap),
            _ => None,
        })
        .expect("a call op");
    *call = 99;
    let encoded = package.encode();
    let decoded = ReplayPackage::decode(&encoded).expect("decode");
    let error = decoded.replay().expect_err("missing ordinal");
    assert_eq!(error.code(), "rpc/replay");
    assert!(error.to_string().contains("ordinal 99"), "{error}");
}

#[test]
fn a_package_with_an_altered_trace_is_refused() {
    let mut package = demo_session();
    package.trace[0] = Trace {
        event: "cap.minted".to_string(),
        cap: Some(7),
    };
    // The checksum is recomputed, so only the decision comparison can catch it.
    let encoded = package.encode();
    let decoded = ReplayPackage::decode(&encoded).expect("decode");
    let error = decoded.replay().expect_err("mismatch");
    assert_eq!(error.code(), "rpc/replay");
    assert!(error.to_string().contains("trace"), "{error}");
}

#[test]
fn replay_reproduces_an_expired_capability_refusal() {
    let mut recorder = session(100);
    let cap = recorder.mint(&["echo"], Some(100)).expect("ttl cap");
    recorder.call(cap, "echo", 0).expect("at t=0");
    recorder.call(cap, "echo", 0).expect("at t=100, expired");
    let package = recorder.package();
    assert!(
        package
            .trace
            .iter()
            .any(|entry| entry.event == "cap.expired"),
        "{:?}",
        package.trace
    );
    assert!(
        package
            .trace
            .iter()
            .any(|entry| entry.event == "call.refused:rpc/revoked"),
        "{:?}",
        package.trace
    );
    let decoded = ReplayPackage::decode(&package.encode()).expect("decode");
    decoded
        .replay()
        .expect("expired decisions replay identically");
}

#[test]
fn an_empty_session_round_trips() {
    let package = session(0).package();
    let decoded = ReplayPackage::decode(&package.encode()).expect("decode");
    decoded.replay().expect("replay");
    assert_eq!(decoded.latency_ms, 0);
    assert_eq!(decoded.trace.len(), 1, "{:?}", decoded.trace);
}

#[test]
fn arguments_never_enter_the_package() {
    // The recorder API takes a size, not a value; this guards the contract if a
    // future refactor tries to record the text.
    let mut recorder = session(1);
    let cap = recorder.mint(&["echo"], None).expect("mint");
    recorder.call(cap, "echo", 12).expect("call");
    let package = recorder.package();
    let call = package
        .ops
        .iter()
        .find_map(|op| match op {
            Op::Call { arg_bytes, .. } => Some(*arg_bytes),
            _ => None,
        })
        .expect("call op");
    assert_eq!(call, 12);
    let encoded = String::from_utf8_lossy(&package.encode()).into_owned();
    assert!(!encoded.contains("secret"));
    assert!(!encoded.contains("canary"));
}
