//! The observability schema: stable names, correlation ids, no authority.

use active_rpc::cap::CapAttrs;
use active_rpc::observability::{
    label, project, EVENT_NAMES, MAX_LABEL_BYTES, METRICS_SCHEMA, SCHEMA,
};
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{
    Agent, Budget, CapId, ChannelId, Event, IdentityPolicy, LaneId, PeerIdentity, PromiseId,
    Provider, ProviderId,
};

struct Echo;

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

fn every_event(cap: CapId) -> Vec<Event> {
    let lane = LaneId(3);
    let channel = ChannelId(2);
    vec![
        Event::CapMinted {
            cap,
            provider: ProviderId(1),
        },
        Event::CapRetained(cap),
        Event::CapReleased(cap),
        Event::CapDropped(cap),
        Event::CapRevoked(cap),
        Event::CapExpired(cap),
        Event::CapExported(cap),
        Event::CapRestored(cap),
        Event::CapRecordOrphaned(cap),
        Event::CapRebound {
            cap,
            from: [0x22; 32],
            to: [0x33; 32],
        },
        Event::CapIntroduced {
            cap,
            fingerprint: [0x11; 32],
        },
        Event::CapTransferred { cap, channel },
        Event::LaneCreated(lane),
        Event::LaneDestroyed { lane, jobs: 3 },
        Event::CallQueued {
            job: 9,
            lane,
            cap,
            method: "echo".to_string(),
            args_bytes: 4,
        },
        Event::CallRefused {
            lane,
            cap: Some(cap),
            code: "rpc/method-not-granted".to_string(),
        },
        Event::BatchDispatched {
            provider: ProviderId(1),
            jobs: 2,
            lane_count: 1,
        },
        Event::JobCompleted { job: 9, lane },
        Event::PromiseResolved(PromiseId(5)),
        Event::PromiseRejected {
            promise: PromiseId(6),
            code: "rpc/budget-exceeded".to_string(),
        },
        Event::ChannelSend {
            channel,
            sequence: 1,
        },
        Event::ChannelRecv {
            channel,
            sequence: 1,
        },
        Event::ChannelCreated(channel),
        Event::ChannelSubscribed { lane, channel },
        Event::ChannelUnsubscribed { lane, channel },
        Event::ChannelClosed(channel),
        Event::ChannelDestroyed {
            channel,
            dropped: 2,
        },
        Event::BudgetExhausted {
            cap: Some(cap),
            dimension: "call".to_string(),
        },
        Event::ReceiptsDropped { count: 1 },
        Event::ProviderPanicked {
            provider: ProviderId(1),
            phase: "invoke".to_string(),
        },
        Event::ToolRefused {
            cap,
            reason: "tool not allowed".to_string(),
        },
    ]
}

/// `project` in the library is the compile-time guard: it matches every
/// `Event` variant with no wildcard, so a new variant does not build until it
/// has a name and a projection. This test is the runtime half: the fixture and
/// the closed set must have the same size, which is how `provider.panicked`
/// went missing (it was projected but never listed).
#[test]
fn every_event_name_is_documented_and_projected() {
    let cap = CapId([0xab; 16]);
    let events = every_event(cap);
    assert_eq!(
        events.len(),
        EVENT_NAMES.len(),
        "add the new variant to every_event and to EVENT_NAMES"
    );

    let mut seen = Vec::new();
    for (index, event) in events.iter().enumerate() {
        let trace = project(event, index as u64);
        assert_eq!(trace.sequence(), index as u64);
        seen.push(trace.event());
        let json: serde_json::Value = serde_json::from_str(&trace.to_json()).expect("valid json");
        assert_eq!(json["schema"], SCHEMA);
        assert_eq!(json["event"], trace.event());
    }
    let mut sorted_seen = seen.clone();
    sorted_seen.sort_unstable();
    let mut expected = EVENT_NAMES.to_vec();
    expected.sort_unstable();
    assert_eq!(sorted_seen, expected, "the projection covers the schema");

    let doc = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/spec/observability.md"),
    )
    .expect("observability doc");
    assert!(doc.contains(SCHEMA));
    assert!(doc.contains(METRICS_SCHEMA));
    for name in EVENT_NAMES {
        assert!(doc.contains(name), "docs must name {name}");
    }
}

#[test]
fn the_projection_carries_correlation_ids_and_never_raw_authority() {
    let cap = CapId([0xcd; 16]);
    let raw = cap.hex();
    for event in every_event(cap) {
        let trace = project(&event, 1);
        let json = trace.to_json();
        assert!(!json.contains(&raw), "raw capability id leaked: {json}");
        if let Some(correlation) = trace.cap_correlation() {
            assert_eq!(correlation.len(), 16);
            assert!(json.contains(correlation));
        }
    }
}

#[test]
fn a_kernel_trace_has_monotonic_sequences_and_no_raw_ids() {
    let agent = Agent::with_secret([0x61; 32]);
    let provider = agent.register(Box::new(Echo));
    let alice = IdentityPolicy::default()
        .admit(
            Some(&PeerIdentity::from_certificate(b"observability-peer")),
            true,
        )
        .expect("admitted");
    let first = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap one");
    let second = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap two");
    agent.introduce_to(&first, &alice).expect("introduce");
    let lane = agent.create_lane("main", Budget::default()).expect("lane");

    let promise = agent
        .call_as(
            Some(alice.identity()),
            lane,
            &first,
            "echo",
            vec![Arg::value(Value::text("not-in-telemetry"))],
        )
        .expect("call");
    agent.run();
    assert_eq!(
        promise.value().expect("value"),
        Value::text("not-in-telemetry")
    );

    // A refusal is an event too.
    let _ = agent.call(lane, &second, "missing-method", Vec::new());
    agent.revoke(&second).expect("revoke");

    let trace = agent.trace();
    assert!(!trace.is_empty());
    for pair in trace.windows(2) {
        assert_eq!(pair[1].sequence(), pair[0].sequence() + 1, "contiguous");
    }
    let total = agent.total_events();
    let last = trace.last().expect("events").sequence();
    assert_eq!(last + 1, total);

    let json = agent.trace_json();
    for cap in [first.id(), second.id()] {
        assert!(!json.contains(&cap.hex()), "raw capability id in trace");
    }
    assert!(!json.contains("not-in-telemetry"), "arguments stay out");
    assert!(json.contains("\"event\":\"call.refused\""));
    assert!(json.contains("\"event\":\"cap.introduced\""));
    assert!(json.contains(&first.id().correlation_id()));

    let parsed: serde_json::Value = serde_json::from_str(&json).expect("json array");
    assert!(parsed.as_array().expect("array").len() == trace.len());
}

#[test]
fn metrics_json_matches_the_kernel_counters() {
    let agent = Agent::with_secret([0x62; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let lane = agent.create_lane("main", Budget::default()).expect("lane");
    agent
        .call(lane, &cap, "echo", vec![Arg::value(Value::Int(1))])
        .expect("call");
    agent.run();
    let _ = agent.call(lane, &cap, "not-granted", Vec::new());

    let json: serde_json::Value =
        serde_json::from_str(&agent.metrics_json()).expect("metrics json");
    assert_eq!(json["schema"], METRICS_SCHEMA);
    let metrics = agent.metrics();
    let counters = &json["counters"];
    assert_eq!(counters["calls_queued"], metrics.calls_queued);
    assert_eq!(counters["calls_refused"], metrics.calls_refused);
    assert_eq!(counters["round_trips"], metrics.round_trips);
    assert_eq!(json["gauges"]["lanes"], agent.lane_count());
    assert_eq!(json["gauges"]["promises"], agent.promise_count());
    assert_eq!(json["gauges"]["jobs"], agent.job_count());
}

#[test]
fn identity_refusals_are_counted_and_visible() {
    let agent = Agent::with_secret([0x63; 32]);
    let provider = agent.register(Box::new(Echo));
    let alice = IdentityPolicy::default()
        .admit(
            Some(&PeerIdentity::from_certificate(b"alice-observability")),
            true,
        )
        .expect("admitted");
    let cap = agent
        .mint_bound(&alice, provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let lane = agent.create_lane("main", Budget::default()).expect("lane");
    let _ = agent.call(lane, &cap, "echo", Vec::new());

    let json: serde_json::Value =
        serde_json::from_str(&agent.metrics_json()).expect("metrics json");
    assert_eq!(json["counters"]["identity_refusals"], 1);
    assert!(agent
        .trace()
        .iter()
        .any(|event| { event.event() == "call.refused" && event.code() == Some("rpc/identity") }));
}

#[test]
fn sequences_stay_monotonic_across_a_tape_wrap() {
    let agent = Agent::with_secret([0x64; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let cap_id = cap.id();

    // Retain/release pairs are cheap, deterministic events.
    for _ in 0..(active_rpc::kernel::MAX_EVENTS / 2 + 32) {
        let clone = cap.clone();
        drop(clone);
    }
    let total = agent.total_events();
    assert!(total > active_rpc::kernel::MAX_EVENTS as u64);
    let trace = agent.trace();
    assert_eq!(trace.len(), active_rpc::kernel::MAX_EVENTS);
    assert_eq!(trace[0].sequence(), total - trace.len() as u64);
    assert_eq!(
        trace.last().expect("last").sequence() + 1,
        total,
        "paging continues where the tape begins"
    );
    assert_eq!(
        trace[0].cap_correlation(),
        Some(cap_id.correlation_id().as_str())
    );
}

#[test]
fn loopback_policy_and_identity_kind_stay_out_of_trace_records() {
    // Identity admission is a transport decision; it does not manufacture kernel
    // events on its own. The kernel records only the binding (`cap.introduced`).
    let admitted = IdentityPolicy::default()
        .admit(None, true)
        .expect("loopback admitted");
    assert_eq!(
        admitted.identity().kind(),
        active_rpc::IdentityKind::Loopback
    );
    let agent = Agent::with_secret([0x65; 32]);
    assert!(agent.trace().is_empty());
}

/// Counters must agree with the tape they summarize.
///
/// The old test compared `metrics_json` with `agent.metrics()` — the same source
/// twice — so a counter that was never exported, or an event that was never
/// counted, passed. This one reconstructs each counter from the events.
#[test]
fn counters_agree_with_the_tape() {
    let agent = Agent::with_secret([0x5c; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent
        .create_lane("counters", Budget::default())
        .expect("lane");
    for _ in 0..3 {
        let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("call");
        agent.run();
        promise.value().expect("value");
    }
    // A refusal the kernel records: a method the capability never granted.
    let _ = agent.call(lane, &cap, "mutate", Vec::new());
    agent.revoke(&cap).expect("revoke");

    let metrics = agent.metrics();
    let events: Vec<String> = agent
        .events()
        .iter()
        .map(|event| project(event, 0).event().to_string())
        .collect();
    let count = |name: &str| events.iter().filter(|seen| *seen == name).count() as u64;

    assert_eq!(metrics.calls_queued, count("call.queued"), "queued");
    assert_eq!(metrics.calls_refused, count("call.refused"), "refused");
    assert_eq!(metrics.revocations, count("cap.revoked"), "revoked");
    assert_eq!(
        metrics.promises_resolved,
        count("promise.resolved"),
        "resolved"
    );
    assert_eq!(metrics.round_trips, count("batch.dispatched"), "batches");
    assert_eq!(
        metrics.events_total,
        events.len() as u64 + metrics.events_evicted,
        "every event is either retained or evicted"
    );
    assert_eq!(
        metrics.events_retained,
        events.len() as u64,
        "the gauge is the tape length"
    );
}

/// `MAX_LABEL_BYTES` is the bound a collector sizes its buffer against, so the
/// ellipsis has to fit inside it: a 200-character label used to escape with 128
/// bytes of text plus a three-byte ellipsis.
#[test]
fn a_label_never_exceeds_its_declared_ceiling() {
    for text in [
        "a".repeat(200),
        "b".repeat(MAX_LABEL_BYTES - 1),
        "c".repeat(MAX_LABEL_BYTES),
        "d".repeat(MAX_LABEL_BYTES + 1),
        "e\n".repeat(200),
        format!("{}\u{0}", "f".repeat(200)),
        "é".repeat(200),
        "🎉".repeat(100),
    ] {
        let label = label(&text);
        assert!(
            label.len() <= MAX_LABEL_BYTES,
            "label of {} bytes produced {} bytes: {label:?}",
            text.len(),
            label.len()
        );
        assert!(
            !label.chars().any(char::is_control),
            "a label carries a control character: {label:?}"
        );
    }
    // A short label is unchanged, and a truncated one says so.
    assert_eq!(label("rpc/budget-exceeded"), "rpc/budget-exceeded");
    assert!(label(&"x".repeat(1_000)).ends_with('…'));
}

/// The label rule covers invisible and reordering characters, not only
/// control characters (round 38, F8).
#[test]
fn a_label_escapes_invisible_and_reordering_characters() {
    let label = active_rpc::observability::label("a\u{2028}b\u{202e}c");
    for hostile in ['\u{2028}', '\u{202e}'] {
        assert!(!label.contains(hostile), "raw {hostile:?} in {label:?}");
    }
}
