//! Unit tests for the kernel: capabilities, attenuation, drops, promises,
//! lanes, channels and the wire codec.

use std::collections::BTreeMap;

use active_rpc::cap::{CapAttrs, CapId, ToolPolicy};
use active_rpc::channel::Direction;
use active_rpc::domain::ModuleProvider;
use active_rpc::error::Error;
use active_rpc::kernel::{Event, Provider};
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::wire::{CapDescriptor, Envelope, Kind, WireLimits};
use active_rpc::{Agent, Budget, PromiseState};

const SOURCE: &str = r#"
# @intent: "unit fixture"
[app]
name = "unit"
port = 8080

[limits]
timeout = 1500ms
token = secret("unit-canary")
"#;

struct Echo;

impl Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn methods(&self) -> Vec<String> {
        vec!["echo".to_string(), "mutate".to_string()]
    }

    fn mutating(&self, method: &str) -> bool {
        method == "mutate"
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

fn agent_with_module() -> (Agent, active_rpc::ProviderId, active_rpc::CapHandle) {
    let mut provider = ModuleProvider::new();
    let object = provider
        .install(active_rpc::domain::module_from_source(SOURCE, "unit.active").expect("module"));
    let agent = Agent::with_secret([7u8; 32]);
    let provider_id = agent.register(Box::new(provider));
    let cap = agent
        .mint(
            provider_id,
            object,
            CapAttrs::new(active_rpc::MODULE_METHODS),
        )
        .expect("mint");
    (agent, provider_id, cap)
}

#[test]
fn global_registry_ceilings_are_finite() {
    use active_rpc::kernel::{MAX_CHANNELS, MAX_LANES};

    let agent = Agent::with_secret([21u8; 32]);
    for _ in 0..MAX_LANES {
        agent
            .create_lane("lane", Budget::default())
            .expect("lane below the ceiling");
    }
    let error = agent
        .create_lane("overflow", Budget::default())
        .expect_err("the lane ceiling must bind");
    assert_eq!(error.code(), "rpc/budget-exceeded");

    for _ in 0..MAX_CHANNELS {
        agent
            .create_channel("channel", active_rpc::Direction::Both)
            .expect("channel below the ceiling");
    }
    let error = agent
        .create_channel("overflow", active_rpc::Direction::Both)
        .expect_err("the channel ceiling must bind");
    assert_eq!(error.code(), "rpc/budget-exceeded");
}

#[test]
fn capability_ids_are_unforgeable() {
    let (agent, provider_id, _cap) = agent_with_module();
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    // A guessed id is not in the registry.
    let forged = agent.import(CapId([0xAB; 16]));
    let error = agent
        .call(lane, &forged, "stats", vec![])
        .expect_err("forged capability must be refused");
    assert_eq!(error.code(), "rpc/unknown-capability");

    // A capability minted by a different agent is unknown here too. The two
    // agents use different secrets, so their ids cannot collide.
    let mut provider = ModuleProvider::new();
    let object =
        provider.install(active_rpc::domain::module_from_source(SOURCE, "other.active").unwrap());
    let other_agent = Agent::new();
    let other_provider = other_agent.register(Box::new(provider));
    let other_cap = other_agent
        .mint(
            other_provider,
            object,
            CapAttrs::new(active_rpc::MODULE_METHODS),
        )
        .unwrap();
    let imported = agent.import(other_cap.id());
    let error = agent
        .call(lane, &imported, "stats", vec![])
        .expect_err("foreign capability must be refused");
    assert_eq!(error.code(), "rpc/unknown-capability");
    assert!(other_agent
        .call(
            other_agent.create_lane("main", Budget::default()).unwrap(),
            &other_cap,
            "stats",
            vec![]
        )
        .is_ok());
    let _ = provider_id;
}

#[test]
fn capability_debug_does_not_print_raw_bits() {
    // Possession of a capability id is authority. Default telemetry (Debug,
    // events) must carry a correlation id, never the raw 128 bits.
    let (agent, provider_id, _cap) = agent_with_module();
    let cap = agent
        .mint(provider_id, 0, CapAttrs::new(&["stats"]))
        .expect("mint");
    let raw = cap.id().hex();
    let debug = format!("{:?}", cap.id());
    assert!(debug.starts_with("CapId("));
    assert!(
        !debug.contains(&raw),
        "CapId Debug printed the raw authority: {debug}"
    );
    let handle = format!("{cap:?}");
    assert!(
        !handle.contains(&raw),
        "CapHandle Debug printed the raw authority: {handle}"
    );
    let events = format!("{:?}", agent.events());
    assert!(
        !events.contains(&raw),
        "events printed the raw authority: {events}"
    );
}

#[test]
fn unknown_method_is_refused() {
    let (agent, _provider, cap) = agent_with_module();
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    let error = agent
        .call(lane, &cap, "not_a_method", vec![])
        .expect_err("unknown method");
    assert_eq!(error.code(), "rpc/method-not-granted");
}

#[test]
fn attenuation_narrows_and_never_widens() {
    let (agent, _provider, cap) = agent_with_module();

    // Narrowing works.
    let narrow = agent
        .attenuate(
            &cap,
            CapAttrs::new(&["stats"]).with_budget(Budget::calls(2)),
        )
        .expect("narrowing attenuation");
    let attrs = agent.cap_attrs(&narrow).unwrap();
    assert_eq!(attrs.methods.len(), 1);
    assert_eq!(attrs.budget.max_calls, 2);

    // Adding a method the parent does not have is escalation.
    let error = agent
        .attenuate(&cap, CapAttrs::new(&["patch", "not_granted"]))
        .expect_err("method escalation");
    assert_eq!(error.code(), "rpc/attenuation-escalation");

    // Growing the budget is escalation.
    let error = agent
        .attenuate(
            &narrow,
            CapAttrs::new(&["stats"]).with_budget(Budget::calls(10)),
        )
        .expect_err("budget escalation");
    assert_eq!(error.code(), "rpc/attenuation-escalation");

    // Lifting read-only or redaction is escalation.
    let read_only = agent
        .attenuate(&cap, CapAttrs::new(&["stats"]).read_only())
        .unwrap();
    let error = agent
        .attenuate(&read_only, CapAttrs::new(&["stats"]))
        .expect_err("read-only cannot be lifted");
    assert_eq!(error.code(), "rpc/attenuation-escalation");
    let redacted = agent
        .attenuate(&cap, CapAttrs::new(&["stats"]).redacted())
        .unwrap();
    let error = agent
        .attenuate(&redacted, CapAttrs::new(&["stats"]))
        .expect_err("redaction cannot be lifted");
    assert_eq!(error.code(), "rpc/attenuation-escalation");

    // Path scope cannot be widened or removed.
    let scoped = agent
        .attenuate(&cap, CapAttrs::new(&["stats"]).with_path("app"))
        .unwrap();
    let error = agent
        .attenuate(&scoped, CapAttrs::new(&["stats"]).with_path("limits"))
        .expect_err("path escalation");
    assert_eq!(error.code(), "rpc/attenuation-escalation");
    assert!(agent
        .attenuate(&scoped, CapAttrs::new(&["stats"]).with_path("app.nested"))
        .is_ok());

    // Tool policies cannot gain tools.
    let tool = agent
        .attenuate(
            &cap,
            CapAttrs::new(&["stats"]).with_tool_policy(ToolPolicy::allow(&["read"])),
        )
        .unwrap();
    let error = agent
        .attenuate(
            &tool,
            CapAttrs::new(&["stats"]).with_tool_policy(ToolPolicy::allow(&["write"])),
        )
        .expect_err("tool escalation");
    assert_eq!(error.code(), "rpc/attenuation-escalation");
}

#[test]
fn attenuated_budget_is_enforced_on_the_real_call_path() {
    let (agent, _provider, cap) = agent_with_module();
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    let narrow = agent
        .attenuate(
            &cap,
            CapAttrs::new(&["stats"]).with_budget(Budget::calls(2)),
        )
        .unwrap();
    for _ in 0..2 {
        let promise = agent.call(lane, &narrow, "stats", vec![]).unwrap();
        assert!(promise.value().is_ok());
    }
    let error = agent
        .call(lane, &narrow, "stats", vec![])
        .expect_err("budget exhausted");
    assert_eq!(error.code(), "rpc/budget-exceeded");
    // The parent capability still has its own budget.
    assert!(agent.call(lane, &cap, "stats", vec![]).is_ok());
}

#[test]
fn lane_budget_is_independent_and_enforced() {
    let (agent, _provider, cap) = agent_with_module();
    let lane = agent.create_lane("tight", Budget::calls(1)).unwrap();
    let first = agent.call(lane, &cap, "stats", vec![]).unwrap();
    assert!(first.value().is_ok(), "the first call completes");
    let error = agent
        .call(lane, &cap, "stats", vec![])
        .expect_err("lane budget");
    assert_eq!(error.code(), "rpc/budget-exceeded");
    // A second lane is unaffected.
    let other = agent.create_lane("roomy", Budget::default()).unwrap();
    assert!(agent.call(other, &cap, "stats", vec![]).is_ok());
}

#[test]
fn read_only_capability_refuses_mutation() {
    let (agent, _provider, cap) = agent_with_module();
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    let read_only = agent
        .attenuate(&cap, CapAttrs::new(&["stats", "patch"]).read_only())
        .unwrap();
    let error = agent
        .call(
            lane,
            &read_only,
            "patch",
            vec![
                Arg::Value(Value::Path("app.port".into())),
                Arg::value(Value::Int(9)),
            ],
        )
        .expect_err("read-only patch");
    assert_eq!(error.code(), "rpc/read-only");
    assert!(agent.call(lane, &read_only, "stats", vec![]).is_ok());
}

#[test]
fn path_scope_is_enforced_before_the_provider() {
    let (agent, _provider, cap) = agent_with_module();
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    let scoped = agent
        .attenuate(&cap, CapAttrs::new(&["impact"]).with_path("app"))
        .unwrap();
    assert!(agent
        .call(
            lane,
            &scoped,
            "impact",
            vec![Arg::Value(Value::Path("app.port".into()))]
        )
        .is_ok());
    let error = agent
        .call(
            lane,
            &scoped,
            "impact",
            vec![Arg::Value(Value::Path("limits.timeout".into()))],
        )
        .expect_err("path outside the scope");
    assert_eq!(error.code(), "rpc/path-not-granted");
}

#[test]
fn dropping_the_last_handle_notifies_the_provider() {
    let (agent, provider_id, cap) = agent_with_module();
    let clone = cap.clone();
    drop(cap);
    assert!(agent.take_drops(provider_id).is_empty(), "a handle remains");
    drop(clone);
    let drops = agent.take_drops(provider_id);
    assert_eq!(drops.len(), 1, "provider notified on last drop");
    let events = agent.events();
    assert!(events
        .iter()
        .any(|event| matches!(event, Event::CapDropped(_))));
}

#[test]
fn revocation_kills_the_capability_and_its_children() {
    let (agent, _provider, cap) = agent_with_module();
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    let child = agent.attenuate(&cap, CapAttrs::new(&["stats"])).unwrap();
    agent.revoke(&cap);
    let error = agent
        .call(lane, &child, "stats", vec![])
        .expect_err("revoked child");
    assert_eq!(error.code(), "rpc/revoked");
}

#[test]
fn pipelining_costs_one_round_trip_and_sequential_costs_two() {
    let agent = Agent::with_secret([3u8; 32]);
    let provider_id = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider_id, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent.create_lane("main", Budget::default()).unwrap();

    // Sequential: wait for the first result before issuing the second call.
    let before = agent.round_trips();
    let first = agent
        .call(lane, &cap, "echo", vec![Arg::text("a")])
        .unwrap();
    assert_eq!(first.value().unwrap(), Value::text("a"));
    let second = agent
        .call(lane, &cap, "echo", vec![Arg::text("b")])
        .unwrap();
    assert_eq!(second.value().unwrap(), Value::text("b"));
    let sequential = agent.round_trips() - before;

    // Pipelined: pass the first promise as the argument of the second call.
    let before = agent.round_trips();
    let first = agent
        .call(lane, &cap, "echo", vec![Arg::text("a")])
        .unwrap();
    let second = agent
        .call(lane, &cap, "echo", vec![Arg::Promise(first.id())])
        .unwrap();
    assert_eq!(second.value().unwrap(), Value::text("a"));
    let pipelined = agent.round_trips() - before;
    println!("round trips: sequential={sequential} pipelined={pipelined}");
    assert_eq!(sequential, 2);
    assert_eq!(pipelined, 1);
    assert!(pipelined < sequential);
}

#[test]
fn promise_argument_values_are_resolved_before_the_provider_runs() {
    let agent = Agent::with_secret([4u8; 32]);
    let provider_id = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider_id, 0, CapAttrs::new(&["echo"]))
        .unwrap();
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    let first = agent
        .call(lane, &cap, "echo", vec![Arg::text("nested")])
        .unwrap();
    let second = agent
        .call(lane, &cap, "echo", vec![Arg::Promise(first.id())])
        .unwrap();
    assert_eq!(second.value().unwrap(), Value::text("nested"));
}

#[test]
fn promise_can_be_cancelled_or_resolved_once() {
    let agent = Agent::with_secret([5u8; 32]);
    let provider_id = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider_id, 0, CapAttrs::new(&["echo"]))
        .unwrap();
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    let promise = agent
        .call(lane, &cap, "echo", vec![Arg::text("x")])
        .unwrap();
    agent.cancel(&promise).unwrap();
    assert_eq!(promise.peek().unwrap_err().code(), "rpc/promise-cancelled");
    assert!(matches!(
        active_rpc::kernel::promise_state(&agent, promise.id()),
        Some(PromiseState::Cancelled)
    ));

    let promise = agent
        .call(lane, &cap, "echo", vec![Arg::text("y")])
        .unwrap();
    agent.resolve(&promise, Value::text("manual")).unwrap();
    assert_eq!(
        agent
            .resolve(&promise, Value::text("again"))
            .unwrap_err()
            .code(),
        "rpc/promise-resolved"
    );
    assert_eq!(promise.peek().unwrap(), Value::text("manual"));
}

#[test]
fn channels_carry_messages_and_transfer_capabilities() {
    let (agent, provider_id, cap) = agent_with_module();
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    let channel = agent.create_channel("control", Direction::Both).unwrap();
    agent.subscribe(lane, channel).unwrap();

    let sequence = agent
        .send(
            lane,
            channel,
            Value::text("hello"),
            std::slice::from_ref(&cap),
        )
        .unwrap();
    assert_eq!(sequence, 0);
    let message = agent.recv(channel).unwrap().expect("message");
    assert_eq!(message.payload, Value::text("hello"));
    assert_eq!(message.caps, vec![cap.id()]);
    assert!(agent.recv(channel).unwrap().is_none());

    // Channel capability sharing is a borrow within one agent: the sender keeps
    // its handle and the ids travel with the message.
    assert!(agent.call(lane, &cap, "stats", vec![]).is_ok());
    assert_eq!(
        message.caps,
        vec![cap.id()],
        "the message names the shared capability"
    );
    assert!(agent
        .events()
        .iter()
        .any(|event| matches!(event, Event::CapTransferred { .. })));
    let _ = provider_id;
}

#[test]
fn send_only_and_receive_only_channels_enforce_direction() {
    let agent = Agent::with_secret([6u8; 32]);
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    let send_only = agent.create_channel("out", Direction::Send).unwrap();
    let receive_only = agent.create_channel("in", Direction::Receive).unwrap();
    assert!(agent.send(lane, send_only, Value::Null, &[]).is_ok());
    let error = agent.recv(send_only).unwrap_err();
    assert_eq!(error.code(), "rpc/invalid-argument");
    let error = agent
        .send(lane, receive_only, Value::Null, &[])
        .unwrap_err();
    assert_eq!(error.code(), "rpc/invalid-argument");
}

#[test]
fn destroyed_lane_refuses_further_calls() {
    let (agent, _provider, cap) = agent_with_module();
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    assert!(agent.call(lane, &cap, "stats", vec![]).is_ok());
    agent.destroy_lane(lane).unwrap();
    let error = agent
        .call(lane, &cap, "stats", vec![])
        .expect_err("destroyed lane");
    assert_eq!(error.code(), "rpc/unknown-lane");
}

#[test]
fn wire_envelope_round_trips_with_capability_table() {
    let envelope = Envelope::request(
        42,
        "evaluate",
        vec![
            Arg::Value(Value::Path("app.port".into())),
            Arg::Value(Value::Int(7)),
            Arg::Value(Value::Module(vec![1, 2, 3])),
        ],
    )
    .with_payload(vec![0x41, 0x49, 0x4e, 0x46])
    .with_caps(vec![CapDescriptor {
        id: CapId([9u8; 16]),
        methods: ["evaluate".to_string(), "why".to_string()]
            .into_iter()
            .collect(),
        budget: Budget::calls(5),
        read_only: true,
        redact: true,
        path_scope: Some("app".to_string()),
    }]);
    let bytes = envelope.encode().unwrap();
    let decoded = Envelope::decode(&bytes).unwrap();
    assert_eq!(decoded, envelope);
    assert_eq!(decoded.kind, Kind::Request);
    assert_eq!(decoded.request_id, 42);
}

#[test]
fn wire_rejects_malformed_envelopes() {
    let bytes = Envelope::request(1, "stats", vec![]).encode().unwrap();

    let mut bad_magic = bytes.clone();
    bad_magic[0] = b'X';
    assert_eq!(Envelope::decode(&bad_magic).unwrap_err().code(), "rpc/wire");

    let mut bad_version = bytes.clone();
    bad_version[4] = 9;
    assert_eq!(
        Envelope::decode(&bad_version).unwrap_err().code(),
        "rpc/wire"
    );

    assert_eq!(
        Envelope::decode(&bytes[..10]).unwrap_err().code(),
        "rpc/wire"
    );

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(Envelope::decode(&trailing).unwrap_err().code(), "rpc/wire");

    // A capability table that disables a budget ceiling is refused.
    let mut cap = CapDescriptor {
        id: CapId([1u8; 16]),
        methods: ["stats".to_string()].into_iter().collect(),
        budget: Budget::calls(1),
        read_only: false,
        redact: false,
        path_scope: None,
    };
    cap.budget.max_calls = 0;
    let envelope = Envelope::request(1, "stats", vec![]).with_caps(vec![cap]);
    let bytes = envelope.encode().unwrap();
    assert_eq!(
        Envelope::decode(&bytes).unwrap_err().code(),
        "rpc/capability-table"
    );

    // Strict limits refuse an oversized envelope.
    let big = Envelope::request(1, "stats", vec![]).with_payload(vec![0u8; 2 << 20]);
    let bytes = big.encode().unwrap();
    assert_eq!(
        Envelope::decode_with(&bytes, WireLimits::strict())
            .unwrap_err()
            .code(),
        "rpc/wire"
    );
}

#[test]
fn response_and_error_envelopes_carry_no_payload() {
    let response = Envelope::response(7, Value::Secret);
    let bytes = response.encode().unwrap();
    let decoded = Envelope::decode(&bytes).unwrap();
    assert_eq!(decoded.first_value(), Some(&Value::Secret));
    let error = Envelope::error(8, &Error::ReadOnly);
    let decoded = Envelope::decode(&error.encode().unwrap()).unwrap();
    assert_eq!(decoded.kind, Kind::Error);
    assert_eq!(decoded.method, "rpc/read-only");
}

#[test]
fn tool_policy_is_enforced_on_tool_calls() {
    let agent = Agent::with_secret([11u8; 32]);
    let provider_id = agent.register(Box::new(Echo));
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    let mut policy = ToolPolicy::allow(&["echo"]);
    // Wire size of Arg::text("ok") is 7 bytes (tag + length + text).
    policy.max_arg_bytes = 8;
    let cap = agent
        .mint(
            provider_id,
            0,
            CapAttrs::new(&["echo", "mutate"]).with_tool_policy(policy),
        )
        .unwrap();
    assert!(agent
        .call(lane, &cap, "echo", vec![Arg::text("ok")])
        .is_ok());
    let error = agent
        .call(lane, &cap, "echo", vec![Arg::text("too long")])
        .expect_err("argument over the policy ceiling");
    assert_eq!(error.code(), "rpc/tool-policy");
}

#[test]
fn events_record_the_dispatch_batches() {
    let (agent, _provider, cap) = agent_with_module();
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    let promise = agent.call(lane, &cap, "stats", vec![]).unwrap();
    promise.value().unwrap();
    let events = agent.events();
    let batches: Vec<&Event> = events
        .iter()
        .filter(|event| matches!(event, Event::BatchDispatched { .. }))
        .collect();
    assert_eq!(batches.len(), 1);
    assert!(matches!(batches[0], Event::BatchDispatched { jobs: 1, .. }));
    let _ = BTreeMap::<u8, u8>::new();
}

/// Closing a channel stops sends but not the drain: messages already queued stay
/// receivable, which is what the documented behavior promises.
#[test]
fn shared_memory_compaction_survives_a_wrapped_ring() {
    use active_rpc::transport::shm::SharedSegment;

    let segment = SharedSegment::new(1024);
    let frame = vec![0x5a; 500];
    segment.write(&frame).expect("first frame");
    segment.write(&frame).expect("second frame");
    // Consume the first frame: tail moves to 504 while head stays at 1008.
    assert_eq!(segment.read().expect("read").expect("frame"), frame);
    // The third write must compact the unread bytes from the *tail*. The old
    // code copied from the head offset and panicked at 1008..1512.
    segment.write(&frame).expect("compacting write");
    assert_eq!(segment.read().expect("read").expect("frame"), frame);
    assert_eq!(segment.read().expect("read").expect("frame"), frame);
    assert!(segment.read().expect("read").is_none());
}

#[test]
fn shared_memory_write_is_total_after_a_desynchronised_advance() {
    use active_rpc::transport::shm::SharedSegment;

    let segment = SharedSegment::new(1024);
    let frame = vec![7u8; 100];
    segment.write(&frame).expect("frame");
    // A consumer that advances without a frame is misuse, but a safe public
    // API must return an error rather than panic or corrupt the ring.
    segment.advance(0);
    let _ = segment.write(&frame);
    let _ = segment.read();
    let _ = segment.with_frame(|bytes| bytes.len());
    let _ = segment.pop_frame(|bytes| bytes.len());
}

#[test]
fn close_stops_sends_but_queued_messages_remain_receivable() {
    use active_rpc::{Channel, ChannelId, Direction, LaneId, Value};
    let mut channel = Channel::new(ChannelId(1), "demo", Direction::Both);
    channel
        .send(LaneId(7), Value::Int(1), Vec::new())
        .expect("open channel accepts a send");
    channel.close();
    assert!(channel.is_closed());
    assert!(
        channel.send(LaneId(7), Value::Int(2), Vec::new()).is_err(),
        "a closed channel refuses new sends"
    );
    let message = channel
        .recv()
        .expect("draining is allowed")
        .expect("the queued message is still there");
    assert_eq!(message.payload, Value::Int(1));
    assert!(channel.recv().expect("drained").is_none());
}

/// The MCP handshake is not a tool invocation, and discovery still works on a
/// transport that answers both handshake methods.
#[test]
fn mcp_handshake_is_not_counted_as_a_tool_call() {
    use active_rpc::tool::{McpSession, MemoryTransport};
    use std::collections::BTreeMap;

    let mut responses = BTreeMap::new();
    responses.insert(
        "initialize".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"stub"}}}"#
            .to_string(),
    );
    responses.insert(
        "tools/list".to_string(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echo back"}]}}"#
            .to_string(),
    );
    let session = McpSession::handshake(MemoryTransport::new(responses)).expect("handshake");
    assert_eq!(session.tools().len(), 1);
    assert_eq!(
        session.calls, 0,
        "only tool invocations count, not the handshake"
    );
    assert!(session.policy().allowed.contains("echo"));
}

#[test]
fn refusals_are_observable_without_payloads() {
    let (agent, provider_id, _cap) = agent_with_module();
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    let mut attrs = CapAttrs::new(&["stats"]);
    attrs.budget.max_calls = 1;
    let cap = agent.mint(provider_id, 0, attrs).expect("cap");
    let first = agent.call(lane, &cap, "stats", vec![]).expect("first call");
    first.value().expect("first value");
    let second = agent
        .call(lane, &cap, "stats", vec![])
        .expect_err("second call must exhaust the call budget");
    assert_eq!(second.code(), "rpc/budget-exceeded");

    let metrics = agent.metrics();
    assert_eq!(metrics.calls_queued, 1);
    assert_eq!(metrics.calls_refused, 1);
    assert_eq!(metrics.budget_exhaustions, 1);
    assert!(agent.events().iter().any(|event| matches!(
        event,
        Event::BudgetExhausted { dimension, .. } if dimension == "call"
    )));
}

#[test]
fn tool_refusals_are_observable_and_carry_no_arguments() {
    let (agent, provider_id, _cap) = agent_with_module();
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    let attrs = CapAttrs::new(&["stats"]).with_tool_policy(ToolPolicy::allow(&["echo"]));
    let cap = agent.mint(provider_id, 0, attrs).expect("cap");
    let canary = "tool-refusal-canary-9f31";
    let error = agent
        .call(lane, &cap, "stats", vec![Arg::Value(Value::text(canary))])
        .expect_err("tool policy must refuse");
    assert_eq!(error.code(), "rpc/tool-policy");
    let metrics = agent.metrics();
    assert_eq!(metrics.calls_refused, 1);
    assert_eq!(metrics.tool_refusals, 1);
    let log = format!("{:?}", agent.events());
    assert!(log.contains("ToolRefused"));
    assert!(!log.contains(canary), "event log leaked an argument value");
}

#[test]
fn event_log_is_bounded_but_metrics_stay_exact() {
    use active_rpc::kernel::MAX_EVENTS;

    let (agent, provider_id, _cap) = agent_with_module();
    let budget = Budget {
        max_calls: 40_000,
        ..Budget::default()
    };
    let lane = agent.create_lane("storm", budget).unwrap();
    let mut attrs = CapAttrs::new(&["stats"]);
    attrs.budget = budget;
    let cap = agent.mint(provider_id, 0, attrs).expect("cap");
    for _ in 0..20_000 {
        agent.call(lane, &cap, "stats", vec![]).expect("call");
    }
    assert!(agent.events().len() <= MAX_EVENTS);
    assert_eq!(agent.metrics().calls_queued, 20_000);
}

/// A provider that answers one method and counts drop notifications.
struct DropSpy {
    drops: std::rc::Rc<std::cell::Cell<usize>>,
}

impl Provider for DropSpy {
    fn name(&self) -> &'static str {
        "drop-spy"
    }
    fn methods(&self) -> Vec<String> {
        vec!["ping".to_string()]
    }
    fn mutating(&self, _method: &str) -> bool {
        false
    }
    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::text("pong")))
    }
    fn on_drop(&mut self, _object: u64, _cap: CapId) {
        self.drops.set(self.drops.get() + 1);
    }
}

/// Exhaustive small-state model of the capability lifecycle.
///
/// Five operations over four steps is 625 sequences. For each, the test drives
/// the real kernel and compares the observable result (call accepted/refused,
/// provider notification count) with a hand-written model. This is the bounded
/// model check required by H6.8; the fuzz target explores longer sequences.
#[test]
fn capability_lifecycle_matches_the_bounded_model() {
    use std::collections::BTreeSet;

    const OPS: u32 = 5;
    const DEPTH: u32 = 4;
    for code in 0..OPS.pow(DEPTH) {
        let mut digits = Vec::new();
        let mut rest = code;
        for _ in 0..DEPTH {
            digits.push(rest % OPS);
            rest /= OPS;
        }
        let drops = std::rc::Rc::new(std::cell::Cell::new(0usize));
        let agent = Agent::with_secret([3u8; 32]);
        let provider = agent.register(Box::new(DropSpy {
            drops: std::rc::Rc::clone(&drops),
        }));
        let lane = agent.create_lane("life", Budget::default()).expect("lane");
        let root = agent
            .mint(provider, 0, CapAttrs::new(&["ping"]))
            .expect("mint");
        let mut known: BTreeSet<CapId> = BTreeSet::new();
        known.insert(root.id());
        let mut handles = vec![root];
        let mut revoked = false;
        for op in digits {
            match op {
                0 => {
                    let result = agent.attenuate(&handles[0], CapAttrs::new(&["ping"]));
                    if revoked {
                        assert!(result.is_err(), "attenuation of a revoked cap succeeded");
                    } else {
                        let child = result.expect("attenuation of a live cap");
                        known.insert(child.id());
                        handles.push(child);
                    }
                }
                1 => {
                    handles.push(handles[0].clone());
                }
                2 => {
                    agent.revoke(&handles[0]);
                    revoked = true;
                }
                3 => {
                    handles.pop();
                    if handles.is_empty() {
                        break;
                    }
                }
                _ => {
                    let result = agent.call(lane, &handles[0], "ping", vec![]);
                    if revoked {
                        let error = result.expect_err("call on a revoked cap");
                        assert_eq!(error.code(), "rpc/revoked");
                    } else {
                        result.expect("call on a live cap");
                    }
                }
            }
        }
        let _ = agent.run();
        drop(handles);
        assert_eq!(
            drops.get(),
            known.len(),
            "sequence {code}: every capability id must notify exactly once"
        );
    }
}

#[cfg(windows)]
#[test]
fn local_process_timeout_kills_a_hung_child() {
    use active_rpc::tool::LocalProcess;

    let mut tool = LocalProcess::new("cmd.exe", &["/C", "*"]).with_timeout(150);
    let mut call = Call::new(
        "run",
        vec![
            Arg::text("/C"),
            Arg::text("C:\\Windows\\System32\\ping.exe -n 20 127.0.0.1"),
        ],
    );
    call.tool_allows_process = true;
    let start = std::time::Instant::now();
    let error = tool
        .invoke(0, &call)
        .expect_err("a hung child must time out");
    assert_eq!(error.code(), "rpc/timeout");
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "timeout took {:?}",
        start.elapsed()
    );
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn local_process_timeout_kills_a_hung_child() {
    use active_rpc::tool::LocalProcess;

    let mut tool = LocalProcess::new("sh", &["-c", "*"]).with_timeout(150);
    let mut call = Call::new("run", vec![Arg::text("-c"), Arg::text("sleep 5")]);
    call.tool_allows_process = true;
    let start = std::time::Instant::now();
    let error = tool
        .invoke(0, &call)
        .expect_err("a hung child must time out");
    assert_eq!(error.code(), "rpc/timeout");
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "timeout took {:?}",
        start.elapsed()
    );
}

#[test]
fn channel_queue_ceiling_bounds_one_sender() {
    use active_rpc::channel::{Channel, ChannelId, MAX_QUEUED_PER_CHANNEL};

    let mut channel = Channel::new(ChannelId(1), "bounded", Direction::Both);
    for _ in 0..MAX_QUEUED_PER_CHANNEL {
        channel
            .send(active_rpc::LaneId(1), Value::Null, vec![])
            .expect("below the channel ceiling");
    }
    let error = channel
        .send(active_rpc::LaneId(1), Value::Null, vec![])
        .expect_err("channel queue must be bounded");
    assert_eq!(error.code(), "rpc/budget-exceeded");
}

#[test]
fn destroyed_lanes_and_channels_reclaim_registry_slots() {
    use active_rpc::kernel::{MAX_CHANNELS, MAX_LANES};

    let agent = Agent::with_secret([15u8; 32]);
    let mut lanes = Vec::new();
    for _ in 0..MAX_LANES {
        lanes.push(agent.create_lane("slot", Budget::default()).expect("lane"));
    }
    for lane in lanes {
        agent.destroy_lane(lane).expect("destroy lane");
    }
    for _ in 0..MAX_LANES {
        let lane = agent
            .create_lane("reused", Budget::default())
            .expect("reused lane");
        agent.destroy_lane(lane).expect("destroy reused lane");
    }

    let mut channels = Vec::new();
    for _ in 0..MAX_CHANNELS {
        channels.push(
            agent
                .create_channel("slot", active_rpc::Direction::Both)
                .expect("channel"),
        );
    }
    for channel in channels {
        agent.destroy_channel(channel).expect("destroy channel");
    }
    for _ in 0..MAX_CHANNELS {
        let channel = agent
            .create_channel("reused", active_rpc::Direction::Both)
            .expect("reused channel");
        agent
            .destroy_channel(channel)
            .expect("destroy reused channel");
    }
}

#[test]
fn promise_ceiling_is_finite_and_refuses_before_charging() {
    use active_rpc::kernel::MAX_PROMISES;

    let (agent, provider_id, _cap) = agent_with_module();
    let wide = Budget {
        max_calls: 200_000,
        ..Budget::default()
    };
    let lane = agent.create_lane("storm", wide).expect("lane");
    let mut attrs = CapAttrs::new(&["stats"]);
    attrs.budget = wide;
    let cap = agent.mint(provider_id, 0, attrs).expect("cap");
    for _ in 0..MAX_PROMISES {
        agent
            .call(lane, &cap, "stats", vec![])
            .expect("below ceiling");
    }
    let refused = agent
        .call(lane, &cap, "stats", vec![])
        .expect_err("promise ceiling must bind");
    assert_eq!(refused.code(), "rpc/budget-exceeded");
    assert_eq!(agent.metrics().calls_queued as usize, MAX_PROMISES);
    assert_eq!(agent.metrics().calls_refused, 1);
}

#[test]
fn capability_display_and_errors_do_not_print_raw_bits() {
    let (agent, _provider_id, cap) = agent_with_module();
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    let raw_hex = cap.id().hex();
    let raw_decimal = u128::from_be_bytes(cap.id().0).to_string();
    assert_eq!(format!("{}", cap.id()), cap.id().correlation_id());
    assert_ne!(format!("{}", cap.id()), raw_hex);

    let forged = agent.import(CapId([0x5a; 16]));
    let error = agent
        .call(lane, &forged, "stats", vec![])
        .expect_err("forged cap");
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains("5a5a5a5a"));
    assert!(!rendered.contains(&raw_hex));
    assert!(!rendered.contains(&raw_decimal));
}

#[test]
fn double_settlement_is_counted_not_hidden() {
    let (agent, provider_id, _cap) = agent_with_module();
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    let cap = agent
        .mint(provider_id, 0, CapAttrs::new(&["stats"]))
        .expect("cap");
    let promise = agent.call(lane, &cap, "stats", vec![]).expect("call");
    agent
        .resolve(&promise, Value::Int(1))
        .expect("first settlement");
    assert!(agent.resolve(&promise, Value::Int(2)).is_err());
    assert_eq!(agent.metrics().promises_double_settled, 1);
}

#[cfg(windows)]
#[test]
fn capability_wall_budget_caps_a_slow_tool() {
    use active_rpc::tool::LocalProcess;

    let mut tool = LocalProcess::new("cmd.exe", &["/C", "*"]).with_timeout(10_000);
    let mut call = Call::new(
        "run",
        vec![
            Arg::text("/C"),
            Arg::text("C:\\Windows\\System32\\ping.exe -n 20 127.0.0.1"),
        ],
    );
    call.tool_allows_process = true;
    call.budget.max_wall_ms = 120;
    let start = std::time::Instant::now();
    let error = tool.invoke(0, &call).expect_err("wall budget must bind");
    assert_eq!(error.code(), "rpc/timeout");
    assert!(start.elapsed() < std::time::Duration::from_secs(2));
}

#[test]
fn dropped_capability_fails_queued_work_with_unknown_capability() {
    let (agent, provider_id, _cap) = agent_with_module();
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    let cap = agent
        .mint(provider_id, 0, CapAttrs::new(&["stats"]))
        .expect("cap");
    let promise = agent.call(lane, &cap, "stats", vec![]).expect("queued");
    drop(cap);
    agent.run();
    let error = promise.value().expect_err("the capability vanished");
    assert_eq!(error.code(), "rpc/unknown-capability");
}

#[test]
fn destroyed_lane_keeps_a_settled_promise_readable() {
    let (agent, provider_id, _cap) = agent_with_module();
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    let cap = agent
        .mint(provider_id, 0, CapAttrs::new(&["stats"]))
        .expect("cap");
    let promise = agent.call(lane, &cap, "stats", vec![]).expect("call");
    promise.value().expect("settled before destroy");
    agent.destroy_lane(lane).expect("destroy");
    assert!(
        promise.value().is_ok(),
        "a settled result must survive lane destruction"
    );
}

#[test]
fn settled_promise_and_job_records_are_reclaimed() {
    use active_rpc::kernel::MAX_SETTLED_PROMISES;

    let (agent, provider_id, _cap) = agent_with_module();
    let wide = Budget {
        max_calls: 200_000,
        ..Budget::default()
    };
    let lane = agent.create_lane("reclaim", wide).expect("lane");
    let mut attrs = CapAttrs::new(&["stats"]);
    attrs.budget = wide;
    let cap = agent.mint(provider_id, 0, attrs).expect("cap");

    let mut last = None;
    for _ in 0..110_000 {
        let promise = agent.call(lane, &cap, "stats", vec![]).expect("call");
        promise.value().expect("value");
        last = Some(promise);
    }
    assert_eq!(agent.job_count(), 0, "completed jobs must be removed");
    assert!(
        agent.promise_count() <= MAX_SETTLED_PROMISES,
        "settled promises were not trimmed: {}",
        agent.promise_count()
    );
    // Capacity returned: a call after the retention window still succeeds.
    let after = agent
        .call(lane, &cap, "stats", vec![])
        .expect("post-trim call");
    after.value().expect("post-trim value");
    last.expect("last handle")
        .value()
        .expect("last value readable");
}

struct BigValue;

impl Provider for BigValue {
    fn name(&self) -> &'static str {
        "big"
    }
    fn methods(&self) -> Vec<String> {
        vec!["big".to_string()]
    }
    fn mutating(&self, _method: &str) -> bool {
        false
    }
    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::text("x".repeat(1 << 20))))
    }
}

#[test]
fn settled_value_bytes_are_bounded_after_a_drain() {
    use active_rpc::kernel::MAX_SETTLED_BYTES;

    let agent = Agent::with_secret([19u8; 32]);
    let provider = agent.register(Box::new(BigValue));
    let wide = Budget {
        max_calls: 10_000,
        max_bytes: 64 << 20,
        max_value_size: 8 << 20,
        ..Budget::default()
    };
    let lane = agent.create_lane("big", wide).expect("lane");
    let mut attrs = CapAttrs::new(&["big"]);
    attrs.budget = wide;
    let cap = agent.mint(provider, 0, attrs).expect("cap");

    for _ in 0..100 {
        let promise = agent.call(lane, &cap, "big", vec![]).expect("call");
        let value = promise.value().expect("value");
        assert!(value.wire_size() >= 1 << 20);
    }
    assert_eq!(agent.job_count(), 0);
    // 100 MiB of settled values cannot stay pinned under the 64 MiB budget.
    let retained = agent.promise_count();
    assert!(
        retained <= 64,
        "retained {retained} one-MiB promises, byte budget did not bind"
    );
    assert!(
        (retained as u64) * (1 << 20) <= MAX_SETTLED_BYTES as u64 + (1 << 20),
        "retained bytes exceed the budget plus the newest value"
    );
}
