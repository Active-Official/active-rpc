//! R-12 replay, confirmation round 2: the input is pinned in the trace, the
//! recorder cannot emit an artifact its own decoder refuses, and an operation
//! whose kernel action succeeded reports that action.
//!
//! Every test drives the shipped `active_rpc::replay` API: a real recorder, the
//! real encoder and a real kernel on replay.

use active_rpc::replay::{
    Op, Recorder, ReplayPackage, MAX_ARG_BYTES, MAX_METHODS, MAX_PACKAGE_BYTES,
};

fn recorded_session() -> ReplayPackage {
    let mut recorder = Recorder::new(0).expect("recorder");
    let cap = recorder.mint(&["echo", "sum"], None).expect("mint");
    recorder.call(cap, "echo", 4).expect("call");
    recorder.call(cap, "sum", 8).expect("call");
    recorder.revoke(cap).expect("revoke");
    recorder.package().expect("package")
}

fn mismatch(package: &ReplayPackage) -> String {
    let error = package.replay().expect_err("an edited package is refused");
    assert_eq!(error.code(), "rpc/replay");
    error.to_string()
}

/// The kernel's events name a capability, never the grant a mint carried, so
/// without an input entry an edited grant replays clean.
#[test]
fn editing_a_grant_is_refused() {
    let mut package = recorded_session();
    let grant = package
        .ops
        .iter_mut()
        .find_map(|op| match op {
            Op::Mint { methods, .. } => Some(methods),
            _ => None,
        })
        .expect("the session mints");
    grant.push("admin".to_string());
    let message = mismatch(&package);
    assert!(message.contains("mismatch"), "{message}");
}

#[test]
fn editing_a_ttl_is_refused() {
    let mut recorder = Recorder::new(0).expect("recorder");
    recorder.mint(&["echo"], Some(1_000)).expect("mint");
    let mut package = recorder.package().expect("package");
    let ttl = package
        .ops
        .iter_mut()
        .find_map(|op| match op {
            Op::Mint { ttl_ms, .. } => Some(ttl_ms),
            _ => None,
        })
        .expect("the session mints");
    *ttl = Some(9_999);
    let message = mismatch(&package);
    assert!(message.contains("mismatch"), "{message}");
}

/// The header latency was checked against op 0, but an edit to the operation
/// that carries it moved both, so the entry itself has to be pinned.
#[test]
fn editing_the_latency_is_refused() {
    let mut package = recorded_session();
    package.ops[0] = Op::SetLatency(5);
    package.latency_ms = 5;
    let message = mismatch(&package);
    assert!(message.contains("mismatch"), "{message}");
}

/// A refused call carries its code but not the method that was refused: the
/// same gap, on the path a reviewer proved replayable clean before this round.
#[test]
fn editing_a_refused_calls_method_is_refused() {
    let mut recorder = Recorder::new(0).expect("recorder");
    let cap = recorder.mint(&["echo"], None).expect("mint");
    // A refusal is recorded in the trace, not returned: the recorder's job is
    // the transcript.
    recorder
        .call(cap, "sum", 64)
        .expect("the refusal is recorded");
    let mut package = recorder.package().expect("package");
    assert!(
        package
            .trace
            .iter()
            .any(|entry| entry.event.starts_with("call.refused:")),
        "{:?}",
        package.trace
    );
    let method = package
        .ops
        .iter_mut()
        .find_map(|op| match op {
            Op::Call { method, .. } => Some(method),
            _ => None,
        })
        .expect("the refused call is recorded");
    *method = "other".to_string();
    let message = mismatch(&package);
    assert!(message.contains("mismatch"), "{message}");
}

#[test]
fn editing_a_revoked_target_is_refused() {
    let mut recorder = Recorder::new(0).expect("recorder");
    let first = recorder.mint(&["echo"], None).expect("mint");
    recorder.mint(&["echo"], None).expect("mint");
    recorder.revoke(first).expect("revoke");
    let mut package = recorder.package().expect("package");
    let target = package
        .ops
        .iter_mut()
        .find_map(|op| match op {
            Op::Revoke { cap } => Some(cap),
            _ => None,
        })
        .expect("the session revokes");
    *target = 1;
    let message = mismatch(&package);
    assert!(message.contains("mismatch"), "{message}");
}

/// The trace is the decision stream plus one input entry per operation, so a
/// recorded session round-trips and a package edited as text does not.
#[test]
fn a_recorded_session_carries_an_input_entry_per_operation() {
    let package = recorded_session();
    let inputs = package
        .trace
        .iter()
        .filter(|entry| entry.event.starts_with("op."))
        .count();
    assert_eq!(
        inputs,
        package.ops.len(),
        "one input entry per operation: {:?}",
        package.trace
    );
    ReplayPackage::decode(&package.encode().expect("encode"))
        .expect("decode")
        .replay()
        .expect("replay");
}

/// The diagnostic path is public, so it has to apply the same header rule the
/// verifying path does.
#[test]
fn the_diagnostic_path_refuses_a_package_without_its_header_latency() {
    let mut package = recorded_session();
    package.ops[0] = Op::Mint {
        methods: vec!["echo".to_string()],
        ttl_ms: None,
    };
    let error = package
        .replay_trace()
        .expect_err("the header latency is missing");
    assert_eq!(error.code(), "rpc/replay");
    assert!(error.to_string().contains("header latency"), "{error}");
}

/// A record-time ceiling that the decoder also enforces: a package that cannot
/// be read back is not a package, and the recorder must not allocate the
/// argument that proves it.
#[test]
fn a_call_over_the_arg_ceiling_is_refused_at_record_time() {
    let mut recorder = Recorder::new(0).expect("recorder");
    let cap = recorder.mint(&["echo"], None).expect("mint");
    for size in [MAX_ARG_BYTES as usize + 1, usize::MAX] {
        let error = recorder
            .call(cap, "echo", size)
            .expect_err("a size over the ceiling is refused");
        assert_eq!(error.code(), "rpc/replay");
        assert!(error.to_string().contains("argument size"), "{error}");
    }
    // The refused attempts never entered the session, so it still replays.
    recorder
        .package()
        .expect("package")
        .replay()
        .expect("the refused attempts are not part of the session");
}

/// The decoder's ceiling is 16 MiB of declared argument bytes: sixteen 1 MiB
/// calls fit, the seventeenth cannot.
const MAX_TOTAL_CALLS: usize = 16;

#[test]
fn a_declared_argument_total_over_the_ceiling_is_refused_at_record_time() {
    let mut recorder = Recorder::new(0).expect("recorder");
    let cap = recorder.mint(&["echo"], None).expect("mint");
    for _ in 0..MAX_TOTAL_CALLS {
        recorder
            .call(cap, "echo", MAX_ARG_BYTES as usize)
            .expect("call");
    }
    let error = recorder
        .call(cap, "echo", 1)
        .expect_err("the total is over the ceiling");
    assert_eq!(error.code(), "rpc/replay");
    assert!(error.to_string().contains("argument sizes"), "{error}");
}

#[test]
fn a_mint_with_too_many_methods_is_refused_at_record_time() {
    let methods: Vec<String> = (0..=MAX_METHODS).map(|index| format!("m{index}")).collect();
    let refs: Vec<&str> = methods.iter().map(String::as_str).collect();

    let mut recorder = Recorder::new(0).expect("recorder");
    let error = recorder
        .mint(&refs, None)
        .expect_err("a grant over the method ceiling is refused");
    assert_eq!(error.code(), "rpc/replay");
    assert!(error.to_string().contains("too many methods"), "{error}");
    recorder
        .package()
        .expect("package")
        .replay()
        .expect("the refused mint is not part of the session");

    // The encoder refuses the same package a hand-built one would carry.
    let package = ReplayPackage {
        latency_ms: 0,
        ops: vec![
            Op::SetLatency(0),
            Op::Mint {
                methods,
                ttl_ms: None,
            },
        ],
        trace: Vec::new(),
    };
    let error = package.encode().expect_err("the encoder refuses the grant");
    assert!(error.to_string().contains("too many methods"), "{error}");
}

/// A recorder session at the legal edge must produce an artifact that decodes
/// and replays: the format's "written == readable" invariant.
#[test]
fn a_recorder_package_at_the_edges_always_decodes() {
    let methods: Vec<String> = (0..MAX_METHODS).map(|index| format!("m{index}")).collect();
    let refs: Vec<&str> = methods.iter().map(String::as_str).collect();

    let mut recorder = Recorder::new(0).expect("recorder");
    let cap = recorder.mint(&refs, Some(u64::MAX)).expect("mint");
    recorder
        .call(
            cap,
            &format!("m{}", MAX_METHODS - 1),
            MAX_ARG_BYTES as usize,
        )
        .expect("call");
    recorder
        .call(cap, "unknown", 0)
        .expect("a refusal is recorded");
    recorder.revoke(cap).expect("revoke");
    let package = recorder.package().expect("package");

    let encoded = package.encode().expect("encode");
    assert!(
        encoded.len() <= MAX_PACKAGE_BYTES,
        "the artifact is {} bytes",
        encoded.len()
    );
    let decoded = ReplayPackage::decode(&encoded).expect("a recorded package must decode");
    assert_eq!(decoded, package);
    decoded.replay().expect("a recorded package must replay");
}

/// The whole-package ceiling is checked while the body grows, not after a
/// hostile session has already built it.
#[test]
fn the_encoder_refuses_a_body_over_the_package_ceiling() {
    // 18 mints of 64 methods of 60 KiB each is 70 MiB of legal fields.
    let method = "m".repeat(60 << 10);
    let methods: Vec<String> = (0..MAX_METHODS).map(|_| method.clone()).collect();
    let mut ops = vec![Op::SetLatency(0)];
    ops.extend((0..18).map(|_| Op::Mint {
        methods: methods.clone(),
        ttl_ms: None,
    }));
    let package = ReplayPackage {
        latency_ms: 0,
        ops,
        trace: Vec::new(),
    };
    let error = match package.encode() {
        Ok(encoded) => panic!(
            "the body is over the ceiling, but encode produced {} bytes",
            encoded.len()
        ),
        Err(error) => error,
    };
    assert_eq!(error.code(), "rpc/replay");
    assert!(error.to_string().contains("size ceiling"), "{error}");
}

/// A transient handle's release is a decision of the operation that borrowed
/// it. Capturing before the drop left the trace ending on an unmatched retain.
#[test]
fn a_trailing_handle_release_is_in_the_trace() {
    let mut recorder = Recorder::new(0).expect("recorder");
    let cap = recorder.mint(&["echo"], None).expect("mint");
    recorder.call(cap, "echo", 0).expect("call");
    let package = recorder.package().expect("package");

    let retained = package
        .trace
        .iter()
        .filter(|entry| entry.event == "cap.retained")
        .count();
    let released = package
        .trace
        .iter()
        .filter(|entry| entry.event == "cap.released")
        .count();
    assert_eq!(retained, released, "trace: {:?}", package.trace);
    assert_eq!(
        retained, 1,
        "one borrowed handle for one call: {:?}",
        package.trace
    );
    // The call's own events follow the borrow, so the invariant is the last
    // capability event, not the last event.
    let last_capability = package
        .trace
        .iter()
        .rev()
        .find(|entry| entry.cap.is_some())
        .map(|entry| entry.event.as_str());
    assert_eq!(
        last_capability,
        Some("cap.released"),
        "the borrowed handle is still retained: {:?}",
        package.trace
    );
}

/// A successful authority change must not be reported as `rpc/replay` because
/// the capture that follows it lost events: the caller would read a completed
/// revocation as a failed one. The loss is refused by `package()`.
#[test]
fn a_recorder_that_lost_events_still_reports_the_kernel_outcome() {
    let mut recorder = Recorder::new(0).expect("recorder");
    let root = recorder.mint(&["echo"], None).expect("mint");
    // Each attenuation emits `cap.minted` plus the borrowed retain/release, and
    // each is captured, so the tape keeps up until one operation emits more
    // than the tape can hold: revoking the whole subtree does exactly that.
    for _ in 0..17_000 {
        recorder
            .attenuate(root, &["echo"], None)
            .expect("attenuate");
    }
    recorder
        .revoke(root)
        .expect("the kernel revoked the subtree, so the recorder reports success");
    let error = recorder
        .package()
        .expect_err("a session that lost events cannot be packaged");
    assert_eq!(error.code(), "rpc/replay");
    assert!(
        error.to_string().contains("lost events") || error.to_string().contains("tape wrapped"),
        "{error}"
    );
}
