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
    policy.max_arg_bytes = 3;
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
