//! RPC-56: receipts and replay record no caller identity.
//!
//! Before the fix, a bound-peer call left a receipt that named the capability
//! and method but never who called: `Event::CallQueued` had no identity field,
//! `Receipt` had none, the replay trace kept only the `cap.introduced`
//! fingerprint prefix, and `replay()` re-executed every call as anonymous.
//! After the fix, the queued event, the sealed receipt, the exported log line
//! and the trace all carry the first 128 bits of the caller's fingerprint,
//! and replay refuses a package whose recorded trace names an introduced peer
//! instead of replaying it approximately.

use active_rpc::cap::CapId;
use active_rpc::kernel::Event;
use active_rpc::replay::{Recorder, Trace};

#[cfg(feature = "test-utils")]
use active_rpc::cap::CapAttrs;
#[cfg(feature = "test-utils")]
use active_rpc::identity::{AdmittedIdentity, IdentityPolicy, PeerIdentity};
#[cfg(feature = "test-utils")]
use active_rpc::receipts::ReceiptLog;
#[cfg(feature = "test-utils")]
use active_rpc::value::{Arg, Call, Response, Value};
#[cfg(feature = "test-utils")]
use active_rpc::{Agent, Budget, Provider};

#[cfg(feature = "test-utils")]
struct Echo;

#[cfg(feature = "test-utils")]
impl Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn methods(&self) -> Vec<String> {
        vec!["echo".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
        let value = call
            .args
            .iter()
            .find_map(|arg| match arg {
                Arg::Value(value) => Some(value.clone()),
                _ => None,
            })
            .unwrap_or(Value::Null);
        Ok(Response::Value(value))
    }
}

/// A verified test identity (the `test-utils` seam, RPC-55).
#[cfg(feature = "test-utils")]
fn identity(seed: &[u8]) -> PeerIdentity {
    PeerIdentity::from_certificate_for_test(seed)
}

/// Admit a certificate identity through the production policy.
#[cfg(feature = "test-utils")]
fn admitted(peer: &PeerIdentity) -> AdmittedIdentity {
    IdentityPolicy::default()
        .admit(Some(peer), true)
        .expect("identity admitted")
}

/// The audit's structural probe, inverted: after the fix the variant has a
/// caller field, and the Debug of a peer call names it.
#[test]
fn r11_receipt_events_carry_the_caller_identity() {
    let event = Event::CallQueued {
        job: 0,
        lane: active_rpc::LaneId(0),
        cap: CapId([0u8; 16]),
        method: "echo".to_string(),
        args_bytes: 0,
        caller: Some([0xabu8; 16]),
    };
    let debug = format!("{event:?}");
    assert!(debug.contains("caller"), "{debug}");
    // An anonymous call still records no caller: absence is absence.
    let anonymous = Event::CallQueued {
        job: 1,
        lane: active_rpc::LaneId(0),
        cap: CapId([0u8; 16]),
        method: "echo".to_string(),
        args_bytes: 0,
        caller: None,
    };
    assert!(
        format!("{anonymous:?}").contains("caller: None"),
        "{anonymous:?}"
    );
}

/// The audit's end-to-end probe: a bound-peer call's receipt names the
/// caller, a second peer's call names a different caller, and a local call
/// names none.
#[cfg(feature = "test-utils")]
#[test]
fn r11_bound_peer_call_receipt_names_the_caller() {
    let peer_a = identity(b"rpc56-peer-a");
    let peer_b = identity(b"rpc56-peer-b");
    let admitted_a = admitted(&peer_a);
    let admitted_b = admitted(&peer_b);
    let agent = Agent::with_secret([0x56; 32]);
    agent.enable_receipts(true);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let cap_a = agent
        .mint_bound(&admitted_a, provider, 0, CapAttrs::new(&["echo"]))
        .expect("bound cap A");
    let cap_b = agent
        .mint_bound(&admitted_b, provider, 0, CapAttrs::new(&["echo"]))
        .expect("bound cap B");
    let cap_open = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("open cap");
    let lane = agent.create_lane("rpc56", Budget::default()).expect("lane");

    let promise = agent
        .call_as(
            Some(admitted_a.identity()),
            lane,
            &cap_a,
            "echo",
            vec![Arg::value(Value::text("a"))],
        )
        .expect("peer A may call");
    agent.run();
    assert_eq!(promise.value().expect("value"), Value::text("a"));

    let promise = agent
        .call_as(
            Some(admitted_b.identity()),
            lane,
            &cap_b,
            "echo",
            vec![Arg::value(Value::text("b"))],
        )
        .expect("peer B may call");
    agent.run();
    assert_eq!(promise.value().expect("value"), Value::text("b"));

    let promise = agent
        .call(
            lane,
            &cap_open,
            "echo",
            vec![Arg::value(Value::text("local"))],
        )
        .expect("local call");
    agent.run();
    assert_eq!(promise.value().expect("value"), Value::text("local"));

    let receipts = agent.receipts();
    assert_eq!(receipts.len(), 3, "{receipts:?}");
    let prefix_a = active_rpc::identity::fingerprint_prefix(peer_a.fingerprint());
    let prefix_b = active_rpc::identity::fingerprint_prefix(peer_b.fingerprint());
    assert_ne!(
        prefix_a, prefix_b,
        "two peers must not share a caller label"
    );
    assert_eq!(
        receipts[0].caller,
        Some(prefix_a),
        "the first receipt names peer A: {receipts:?}"
    );
    assert_eq!(
        receipts[1].caller,
        Some(prefix_b),
        "the second receipt names peer B: {receipts:?}"
    );
    assert_eq!(
        receipts[2].caller, None,
        "a local call records no caller: {receipts:?}"
    );
    // The caller seals with the receipt: every receipt still verifies.
    let key = agent.receipt_key();
    for receipt in &receipts {
        assert!(receipt.verify(&key), "{receipt:?}");
    }
}

/// The queued event in the operator trace names the caller for a peer call
/// and omits the field for a local call.
#[cfg(feature = "test-utils")]
#[test]
fn r11_queued_event_trace_names_the_caller() {
    let peer_a = identity(b"rpc56-peer-a");
    let admitted_a = admitted(&peer_a);
    let agent = Agent::with_secret([0x56; 32]);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let cap_a = agent
        .mint_bound(&admitted_a, provider, 0, CapAttrs::new(&["echo"]))
        .expect("bound cap A");
    let cap_open = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("open cap");
    let lane = agent.create_lane("rpc56", Budget::default()).expect("lane");

    let promise = agent
        .call_as(
            Some(admitted_a.identity()),
            lane,
            &cap_a,
            "echo",
            vec![Arg::value(Value::text("a"))],
        )
        .expect("peer A may call");
    agent.run();
    assert_eq!(promise.value().expect("value"), Value::text("a"));
    let promise = agent
        .call(
            lane,
            &cap_open,
            "echo",
            vec![Arg::value(Value::text("local"))],
        )
        .expect("local call");
    agent.run();
    assert_eq!(promise.value().expect("value"), Value::text("local"));

    let json: serde_json::Value = serde_json::from_str(&agent.trace_json()).expect("json array");
    let events = json.as_array().expect("array");
    let queued: Vec<&serde_json::Value> = events
        .iter()
        .filter(|event| event["event"] == "call.queued")
        .collect();
    assert_eq!(queued.len(), 2, "two queued calls: {}", agent.trace_json());
    let prefix_a = active_rpc::identity::fingerprint_prefix(peer_a.fingerprint());
    let expected = active_rpc::identity::fingerprint_prefix_hex(&prefix_a);
    let named: Vec<&&serde_json::Value> = queued
        .iter()
        .filter(|event| event.get("identity").is_some())
        .collect();
    assert_eq!(
        named.len(),
        1,
        "exactly one queued call names a caller: {}",
        agent.trace_json()
    );
    assert_eq!(named[0]["identity"], expected, "the caller is peer A");
    assert!(
        queued.iter().any(|event| event.get("identity").is_none()),
        "the local call names no caller: {}",
        agent.trace_json()
    );
}

/// A caller survives the durable log round trip, its MAC still verifies, a
/// legacy-shaped record (no caller field) still decodes with `None`, and a
/// flipped caller byte is refused.
#[cfg(feature = "test-utils")]
#[test]
fn r11_receipt_log_round_trip_preserves_the_caller() {
    let peer = identity(b"rpc56-log-peer");
    let admitted = admitted(&peer);
    let agent = Agent::with_secret([0x56; 32]);
    agent.enable_receipts(true);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let cap = agent
        .mint_bound(&admitted, provider, 0, CapAttrs::new(&["echo"]))
        .expect("bound cap");
    let cap_open = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("open cap");
    let lane = agent.create_lane("rpc56", Budget::default()).expect("lane");
    let promise = agent
        .call_as(
            Some(admitted.identity()),
            lane,
            &cap,
            "echo",
            vec![Arg::value(Value::text("peer"))],
        )
        .expect("peer may call");
    agent.run();
    assert_eq!(promise.value().expect("value"), Value::text("peer"));
    let promise = agent
        .call(
            lane,
            &cap_open,
            "echo",
            vec![Arg::value(Value::text("local"))],
        )
        .expect("local call");
    agent.run();
    assert_eq!(promise.value().expect("value"), Value::text("local"));

    let receipts = agent.receipts();
    assert_eq!(receipts.len(), 2, "{receipts:?}");
    let prefix = active_rpc::identity::fingerprint_prefix(peer.fingerprint());
    assert_eq!(receipts[0].caller, Some(prefix));
    assert_eq!(receipts[1].caller, None);

    let dir = std::env::temp_dir().join(format!("active-rpc-rpc56-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("sandbox");
    let path = dir.join("receipts.arrl");
    let log = ReceiptLog::create(&path).expect("create");
    log.append_all(&receipts).expect("append");
    drop(log);
    let log = ReceiptLog::open(&path).expect("open");
    let read = log.records().expect("records");
    assert_eq!(read.len(), 2, "{read:?}");
    assert_eq!(read[0].caller, Some(prefix), "the caller survives the log");
    // The anonymous receipt's record is exactly the pre-fix encoding: no
    // caller field was written, and it decodes with `None`.
    assert_eq!(
        read[1].caller, None,
        "a legacy-shaped record decodes with None"
    );
    log.verify_macs(&agent.receipt_key())
        .expect("macs verify with the caller sealed");

    // Tampering with the caller bytes breaks the chain.
    let bytes = std::fs::read(&path).expect("read log");
    let at = bytes
        .windows(prefix.len())
        .position(|window| window == prefix)
        .expect("caller bytes in the log");
    let mut tampered = bytes.clone();
    tampered[at] ^= 0x01;
    assert!(
        ReceiptLog::verify_bytes(&tampered).is_err(),
        "a flipped caller byte is refused"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Replay is identity-blind by design: a package whose recorded trace names
/// an introduced peer is refused outright, and a caller suffix the replay
/// cannot reproduce is a mismatch, not a pass.
#[test]
fn r11_replay_refuses_a_package_with_an_introduced_peer() {
    let mut recorder = Recorder::new(0).expect("recorder");
    let cap = recorder.mint(&["echo"], None).expect("mint");
    recorder.call(cap, "echo", 0).expect("call");
    let package = recorder.package().expect("package");
    // The recorded package replays cleanly: the refusal below is about the
    // introduced peer, not the package shape.
    package.replay().expect("the recorded package replays");

    let mut edited = package.clone();
    edited.trace.push(Trace {
        event: format!("cap.introduced:{}", "ab".repeat(16)),
        cap: Some(0),
    });
    let error = edited.replay().expect_err("an introduced peer is refused");
    assert_eq!(error.code(), "rpc/replay", "{error}");
    assert!(
        error.to_string().contains("identity-blind"),
        "the refusal names the reason: {error}"
    );
    // The diagnostic half refuses the same package.
    assert!(
        edited.replay_trace().is_err(),
        "replay_trace refuses it too"
    );

    // A caller suffix the replay cannot reproduce is a mismatch, not a pass:
    // the replay runs anonymous, so its queued entry carries no caller.
    let mut suffixed = package.clone();
    for entry in suffixed.trace.iter_mut() {
        if entry.event.starts_with("call.queued:") {
            entry.event = format!("{}:caller={}", entry.event, "cd".repeat(16));
        }
    }
    assert!(
        suffixed
            .trace
            .iter()
            .any(|entry| entry.event.contains(":caller=")),
        "the edited package names a caller"
    );
    let error = suffixed
        .replay()
        .expect_err("a caller the replay cannot reproduce is a mismatch");
    assert_eq!(error.code(), "rpc/replay", "{error}");
    assert!(
        error.to_string().contains("trace mismatch"),
        "the refusal names the mismatch: {error}"
    );
}
