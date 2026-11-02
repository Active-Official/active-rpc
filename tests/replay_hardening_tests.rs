//! R-12 replay hardening: what a package can be edited into, what the trace
//! fails to cover, and the cost of replaying a hostile one.
//!
//! Every test drives the shipped `active_rpc::replay` API: a real recorder, the
//! real encoder and a real kernel on replay.

use active_rpc::replay::{Op, Recorder, ReplayPackage, MAX_OPS};

/// A small, honest session: mint, two calls, revoke.
fn recorded_session() -> ReplayPackage {
    let mut recorder = Recorder::new(0).expect("recorder");
    let cap = recorder.mint(&["echo", "sum"], None).expect("mint");
    recorder.call(cap, "echo", 4).expect("call");
    recorder.call(cap, "sum", 8).expect("call");
    recorder.revoke(cap).expect("revoke");
    recorder.package().expect("package")
}

/// A call's method is pinned by the `op.call` input entry, so an edit is caught
/// by the trace comparison rather than by the replayed op list (which is built
/// from the package and therefore proves nothing).
#[test]
fn changing_a_recorded_call_method_is_refused() {
    let mut package = recorded_session();
    let call = package
        .ops
        .iter_mut()
        .find_map(|op| match op {
            Op::Call { method, .. } => Some(method),
            _ => None,
        })
        .expect("the session calls");
    assert_eq!(*call, "echo");
    *call = "sum".to_string();
    let error = package.replay().expect_err("an edited method is refused");
    assert_eq!(error.code(), "rpc/replay");
    assert!(format!("{error}").contains("mismatch"), "{error}");
}

#[test]
fn changing_a_recorded_arg_size_is_refused() {
    let mut package = recorded_session();
    let size = package
        .ops
        .iter_mut()
        .find_map(|op| match op {
            Op::Call { arg_bytes, .. } => Some(arg_bytes),
            _ => None,
        })
        .expect("the session calls");
    assert_eq!(*size, 4);
    *size = 0;
    let error = package.replay().expect_err("an edited size is refused");
    assert_eq!(error.code(), "rpc/replay");
    assert!(format!("{error}").contains("mismatch"), "{error}");
}

/// A refused attenuation emits `cap.retained`/`cap.released`; when it is the
/// last operation, both decisions must be in the trace, release included.
#[test]
fn a_trailing_refused_attenuation_keeps_its_events() {
    let mut recorder = Recorder::new(0).expect("recorder");
    let cap = recorder.mint(&["echo"], None).expect("mint");
    recorder.call(cap, "echo", 0).expect("call");
    let error = recorder
        .attenuate(cap, &["echo", "sum"], None)
        .expect_err("widening is refused");
    assert_eq!(error.code(), "rpc/attenuation-escalation");

    let package = recorder.package().expect("package");
    let last = package.trace.last().expect("a trace");
    assert_eq!(
        last.event, "cap.released",
        "the refused attenuation's borrowed handle is still retained: {last:?}"
    );
    package.replay().expect("the recording replays");
}

/// The package stores a method length as `u16`; a longer name would truncate the
/// field and re-frame the rest of the op stream, so it is refused at record
/// time.
#[test]
fn a_method_name_over_64k_is_refused_at_record_time() {
    let mut recorder = Recorder::new(0).expect("recorder");
    let long = "m".repeat(u16::MAX as usize + 1);
    let error = recorder
        .mint(&[long.as_str()], None)
        .expect_err("a method the wire cannot length-prefix is refused");
    assert_eq!(error.code(), "rpc/replay");
    // The refused attempt never reached the kernel, so the recorder is still
    // usable and the session still replays.
    recorder
        .package()
        .expect("package")
        .replay()
        .expect("the refused attempt is not part of the session");
}

/// A session longer than the package format can carry must fail while it is
/// being recorded, not when the artifact is read back.
#[test]
fn a_session_past_the_op_ceiling_is_refused_at_record_time() {
    let mut recorder = Recorder::new(0).expect("recorder");
    for index in 0..MAX_OPS - 1 {
        recorder.set_latency(index as u64).expect("latency");
    }
    let error = recorder
        .set_latency(1)
        .expect_err("the op ceiling is enforced while recording");
    assert_eq!(error.code(), "rpc/replay");
    assert!(recorder.package().is_err());
}

/// The header latency is the *initial* rate; a package that does not begin with
/// it would replay at the wrong speed and move every expiry boundary.
#[test]
fn a_package_that_does_not_begin_with_its_latency_is_refused() {
    let mut package = recorded_session();
    package.ops[0] = Op::Mint {
        methods: vec!["echo".to_string()],
        ttl_ms: None,
    };
    let encoded = package.encode().expect("encode");
    let decoded = ReplayPackage::decode(&encoded).expect("decode");
    let error = decoded.replay().expect_err("no header latency");
    assert_eq!(error.code(), "rpc/replay");
    assert!(format!("{error}").contains("header latency"), "{error}");
}

/// A mismatch names the differing entries, and the text comes from the package:
/// it must be escaped and bounded.
#[test]
fn a_mismatch_message_is_bounded_and_escaped() {
    let mut package = recorded_session();
    let hostile = format!("\u{1b}[2J\u{1b}[31m{}\nforged", "x".repeat(4096));
    package.trace[0].event = hostile;
    let error = package.replay().expect_err("a mismatch");
    let message = format!("{error}");
    assert!(
        !message.contains('\u{1b}'),
        "an escape survived into the message"
    );
    assert!(!message.contains("forged\n"), "a raw newline survived");
    assert!(
        message.len() < 1_000,
        "the message is {} bytes",
        message.len()
    );
}

/// The encoder refuses a package the decoder would reject instead of truncating
/// a count.
#[test]
fn the_encoder_refuses_a_package_over_a_ceiling() {
    let mut package = recorded_session();
    package.ops = vec![Op::SetLatency(0); MAX_OPS + 1];
    let error = package.encode().expect_err("too many operations");
    assert_eq!(error.code(), "rpc/replay");
}

/// Replay work is linear in the operations, not ops x tape: a recording of
/// thousands of calls must not clone the whole bounded tape per operation.
#[test]
fn replaying_thousands_of_calls_is_linear() {
    let mut recorder = Recorder::new(0).expect("recorder");
    let cap = recorder.mint(&["echo"], None).expect("mint");
    for _ in 0..10_000 {
        recorder.call(cap, "echo", 0).expect("call");
    }
    let package = recorder.package().expect("package");
    let seconds = std::time::Instant::now();
    package.replay().expect("the recording replays");
    let elapsed = seconds.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(20),
        "10 000 calls replayed in {elapsed:?}"
    );
}

/// The header is the *initial* latency. A session that changes its rate used to
/// write the final rate into the header, and replay then started at the wrong
/// clock.
#[test]
fn a_session_that_changes_its_latency_replays() {
    let mut recorder = Recorder::new(3).expect("recorder");
    recorder.set_latency(7).expect("latency");
    let cap = recorder.mint(&["echo"], None).expect("mint");
    recorder.call(cap, "echo", 0).expect("call");
    let package = recorder.package().expect("package");
    assert_eq!(package.latency_ms, 3, "the header is the initial rate");
    package.replay().expect("a latency change replays");
}
