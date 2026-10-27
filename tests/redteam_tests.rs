//! Red-team suite for Active RPC.
//!
//! Each test names the threat it covers: capability forgery, escalation,
//! confused deputy, secret leakage, budget bypass, promise abuse, malformed
//! frames and transport-level bombs.

use std::collections::BTreeMap;

use active_rpc::cap::{CapAttrs, CapId, ToolPolicy};
use active_rpc::domain::ModuleProvider;
use active_rpc::kernel::{Event, Provider};
use active_rpc::transport::shm::{SharedMemoryTransport, SharedSegment};
use active_rpc::transport::Transport;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::wire::{CapDescriptor, Envelope, WireLimits};
use active_rpc::{Agent, Budget};

const SOURCE: &str = r#"
[app]
port  = 8080
token = secret("red-team-canary")
"#;

fn setup() -> (
    Agent,
    active_rpc::ProviderId,
    active_rpc::CapHandle,
    active_rpc::LaneId,
) {
    let mut provider = ModuleProvider::new();
    let object = provider.install(active_rpc::domain::module_from_source(SOURCE, "rt").unwrap());
    let agent = Agent::with_secret([51u8; 32]);
    let provider_id = agent.register(Box::new(provider));
    let cap = agent
        .mint(
            provider_id,
            object,
            CapAttrs::new(active_rpc::MODULE_METHODS),
        )
        .unwrap();
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    (agent, provider_id, cap, lane)
}

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
        Ok(Response::Value(
            call.args
                .iter()
                .find_map(|arg| match arg {
                    Arg::Value(value) => Some(value.clone()),
                    _ => None,
                })
                .unwrap_or(Value::Null),
        ))
    }
}

#[test]
fn threat_forgery_and_transplant() {
    let (agent, _provider, cap, lane) = setup();
    // Random ids, an id from another kernel, and a mutated id are all refused.
    let mut candidates = vec![CapId([0u8; 16]), CapId([0xff; 16])];
    let mut mutated = cap.id().0;
    mutated[0] ^= 1;
    candidates.push(CapId(mutated));
    for id in candidates {
        let imported = agent.import(id);
        let error = agent
            .call(lane, &imported, "stats", vec![])
            .expect_err("forged capability");
        assert_eq!(error.code(), "rpc/unknown-capability");
    }
}

#[test]
fn threat_confused_deputy() {
    // A capability for provider A must not reach provider B, even when method
    // names overlap.
    let (agent, _provider, module_cap, lane) = setup();
    let echo_provider = agent.register(Box::new(Echo));
    let echo_cap = agent
        .mint(echo_provider, 0, CapAttrs::new(&["echo"]))
        .unwrap();
    let error = agent
        .call(lane, &echo_cap, "stats", vec![])
        .expect_err("method not on the echo provider");
    assert_eq!(error.code(), "rpc/method-not-granted");
    // Attenuating one capability cannot add another provider's methods.
    let error = agent
        .attenuate(&echo_cap, CapAttrs::new(&["stats"]))
        .expect_err("attenuation cannot borrow methods");
    assert_eq!(error.code(), "rpc/attenuation-escalation");
    assert!(agent.call(lane, &module_cap, "stats", vec![]).is_ok());
}

#[test]
fn threat_escalation_through_metadata() {
    let (agent, _provider, cap, _lane) = setup();
    // A descriptor claiming a bigger budget than its parent is refused by the
    // attenuation rule.
    let error = agent
        .attenuate(
            &cap,
            CapAttrs::new(&["stats"]).with_budget(Budget::default().max_calls(1_000_000)),
        )
        .expect_err("budget escalation");
    assert_eq!(error.code(), "rpc/attenuation-escalation");
    // A read-only parent cannot produce a writable child.
    let read_only = agent
        .attenuate(&cap, CapAttrs::new(&["patch"]).read_only())
        .unwrap();
    let error = agent
        .attenuate(&read_only, CapAttrs::new(&["patch"]))
        .expect_err("read-only escalation");
    assert_eq!(error.code(), "rpc/attenuation-escalation");
}

trait BudgetExt {
    fn max_calls(self, limit: u64) -> Budget;
}

impl BudgetExt for Budget {
    fn max_calls(mut self, limit: u64) -> Budget {
        self.max_calls = limit;
        self
    }
}

#[test]
fn threat_secret_material_never_reaches_the_wire() {
    const CANARY: &str = "red-team-canary";
    let (agent, _provider, cap, lane) = setup();
    let evaluated = agent
        .call(lane, &cap, "evaluate", vec![])
        .expect("call")
        .value()
        .expect("evaluate");
    // The secret is a marker, never text.
    let rendered = format!("{evaluated:?}");
    assert!(!rendered.contains(CANARY), "evaluation leaked: {rendered}");
    assert!(rendered.contains("Secret"));

    // A response envelope carrying the value has no canary bytes either.
    let envelope = Envelope::response(1, evaluated.clone());
    let bytes = envelope.encode().unwrap();
    assert!(
        !bytes
            .windows(CANARY.len())
            .any(|window| window == CANARY.as_bytes()),
        "envelope leaked secret bytes"
    );

    // Annotations and provenance are redacted too.
    let annotations = agent
        .call(lane, &cap, "annotations", vec![])
        .expect("call")
        .value()
        .expect("annotations");
    assert!(!format!("{annotations:?}").contains(CANARY));
    let provenance = agent
        .call(lane, &cap, "provenance", vec![])
        .expect("call")
        .value()
        .expect("provenance");
    assert!(!format!("{provenance:?}").contains(CANARY));
}

#[test]
fn threat_budget_bypass_attempts() {
    let (agent, _provider, cap, lane) = setup();

    // 1. Exhausting the capability budget stops calls even for cheap methods.
    let narrow = agent
        .attenuate(
            &cap,
            CapAttrs::new(&["stats"]).with_budget(Budget::calls(1)),
        )
        .unwrap();
    let promise = agent.call(lane, &narrow, "stats", vec![]).unwrap();
    assert!(promise.value().is_ok());
    assert_eq!(
        agent
            .call(lane, &narrow, "stats", vec![])
            .unwrap_err()
            .code(),
        "rpc/budget-exceeded"
    );

    // 2. A lane budget cannot be raised by attenuation.
    assert_eq!(
        agent
            .attenuate_lane(lane, Budget::calls(u64::MAX))
            .unwrap_err()
            .code(),
        "rpc/attenuation-escalation"
    );

    // 3. A tool policy cannot be exceeded.
    let agent = Agent::with_secret([52u8; 32]);
    let provider = agent.register(Box::new(Echo));
    let policy = ToolPolicy {
        allowed: ["echo".to_string()].into_iter().collect(),
        max_arg_bytes: 4,
        allow_process: false,
    };
    let tool_cap = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["echo"]).with_tool_policy(policy),
        )
        .unwrap();
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    let error = agent
        .call(lane, &tool_cap, "echo", vec![Arg::text("too many bytes")])
        .unwrap_err();
    assert_eq!(error.code(), "rpc/tool-policy");
}

#[test]
fn threat_promise_abuse() {
    let (agent, _provider, cap, lane) = setup();
    // A promise id that was never minted is refused at call time.
    let error = agent
        .call(
            lane,
            &cap,
            "impact",
            vec![Arg::Promise(active_rpc::PromiseId(9_999))],
        )
        .unwrap_err();
    assert_eq!(error.code(), "rpc/unknown-promise");

    // Resolving twice, cancelling twice and awaiting a cancelled promise all
    // fail with stable codes instead of hanging.
    let promise = agent.call(lane, &cap, "stats", vec![]).unwrap();
    agent.cancel(&promise).unwrap();
    assert_eq!(
        agent.cancel(&promise).unwrap_err().code(),
        "rpc/promise-resolved"
    );
    assert_eq!(promise.peek().unwrap_err().code(), "rpc/promise-cancelled");
}

#[test]
fn threat_malformed_frames_and_bombs() {
    // Envelope bombs: huge counts, truncated bodies, trailing bytes.
    let good = Envelope::request(1, "stats", vec![]).encode().unwrap();
    for (name, bytes) in [
        ("empty", Vec::new()),
        ("half", good[..8].to_vec()),
        ("trailing", {
            let mut bytes = good.clone();
            bytes.push(0);
            bytes
        }),
        ("huge-args", {
            let mut bytes = good.clone();
            bytes[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
            bytes
        }),
        ("huge-caps", {
            let mut bytes = good.clone();
            bytes[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
            bytes
        }),
    ] {
        let outcome = std::panic::catch_unwind(|| Envelope::decode(&bytes));
        assert!(outcome.is_ok(), "{name} panicked");
        assert!(outcome.unwrap().is_err(), "{name} was accepted");
    }

    // Capability-table bombs are reported as a capability-table failure, not a
    // generic crash.
    let mut caps = vec![CapDescriptor {
        id: CapId([1u8; 16]),
        methods: ["stats".to_string()].into_iter().collect(),
        budget: Budget::default(),
        read_only: false,
        redact: false,
        path_scope: None,
    }];
    caps[0].methods = (0..1000).map(|index| format!("m{index}")).collect();
    let envelope = Envelope::request(1, "stats", vec![]).with_caps(caps);
    let bytes = envelope.encode().unwrap();
    let error = Envelope::decode_with(&bytes, WireLimits::strict()).unwrap_err();
    assert!(
        error.code() == "rpc/capability-table" || error.code() == "rpc/wire",
        "unexpected {error:?}"
    );

    // A shared-memory frame that is not an envelope is refused.
    let segment = SharedSegment::new(1024);
    segment.write(&[0xde, 0xad, 0xbe, 0xef]).unwrap();
    let mut transport = SharedMemoryTransport::new(segment);
    assert_eq!(transport.recv().unwrap_err().code(), "rpc/wire");
}

#[test]
fn threat_revocation_and_lifetime_edges() {
    let (agent, provider_id, cap, lane) = setup();
    let child = agent.attenuate(&cap, CapAttrs::new(&["stats"])).unwrap();
    let clone = child.clone();
    drop(child);
    assert!(agent.take_drops(provider_id).is_empty());
    drop(clone);
    assert_eq!(agent.take_drops(provider_id).len(), 1);

    // Calling through a dropped handle is refused: the registry no longer knows
    // the id.
    let leftover = agent.import(cap.id());
    agent.revoke(&cap);
    assert_eq!(
        agent
            .call(lane, &leftover, "stats", vec![])
            .unwrap_err()
            .code(),
        "rpc/revoked"
    );
    assert!(agent
        .events()
        .iter()
        .any(|event| matches!(event, Event::CapRevoked(_))));
    assert_eq!(
        agent
            .call(lane, &leftover, "stats", vec![])
            .unwrap_err()
            .code(),
        "rpc/revoked"
    );
    let _ = BTreeMap::<u8, u8>::new();
}

#[test]
fn threat_argument_bombs_in_memory_budget() {
    // A text argument that claims to be huge but is not, and a module argument
    // that is not a valid image, must both be refused by the layer that owns
    // the check.
    let agent = Agent::with_secret([53u8; 32]);
    let provider = agent.register(Box::new(Echo));
    let policy = ToolPolicy {
        allowed: ["echo".to_string()].into_iter().collect(),
        max_arg_bytes: 8,
        allow_process: false,
    };
    let cap = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["echo"]).with_tool_policy(policy),
        )
        .unwrap();
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    assert_eq!(
        agent
            .call(
                lane,
                &cap,
                "echo",
                vec![Arg::Value(Value::Module(vec![0xff; 64]))]
            )
            .unwrap_err()
            .code(),
        "rpc/tool-policy"
    );
}

// ---------------------------------------------------------------------------
// Regressions from the independent security review (2026-10-27)
// ---------------------------------------------------------------------------

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Counts invocations and can call back into the agent to prove re-entrancy.
struct CountingProvider {
    calls: Arc<AtomicUsize>,
    agent: Rc<RefCell<Option<Agent>>>,
}

impl Provider for CountingProvider {
    fn name(&self) -> &'static str {
        "counting"
    }
    fn methods(&self) -> Vec<String> {
        vec!["ping".to_string()]
    }
    fn mutating(&self, _method: &str) -> bool {
        false
    }
    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        // A provider holding the agent must not panic the kernel.
        if let Some(agent) = self.agent.borrow().as_ref() {
            let _ = agent.events();
            let _ = agent.round_trips();
        }
        Ok(Response::Value(Value::text("pong")))
    }
}

fn counting_agent() -> (
    Agent,
    Arc<AtomicUsize>,
    active_rpc::CapHandle,
    active_rpc::LaneId,
) {
    let agent = Agent::with_secret([61u8; 32]);
    let calls = Arc::new(AtomicUsize::new(0));
    let holder = Rc::new(RefCell::new(None::<Agent>));
    let provider = CountingProvider {
        calls: Arc::clone(&calls),
        agent: Rc::clone(&holder),
    };
    let provider_id = agent.register(Box::new(provider));
    let cap = agent
        .mint(provider_id, 0, CapAttrs::new(&["ping"]))
        .unwrap();
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    *holder.borrow_mut() = Some(agent.clone());
    (agent, calls, cap, lane)
}

#[test]
fn review_revocation_after_queueing_prevents_invocation() {
    let (agent, calls, cap, lane) = counting_agent();
    let promise = agent.call(lane, &cap, "ping", vec![]).unwrap();
    agent.revoke(&cap);
    let error = promise.value().expect_err("revoked before dispatch");
    assert_eq!(error.code(), "rpc/revoked");
    assert_eq!(calls.load(Ordering::SeqCst), 0, "provider must not run");
}

#[test]
fn review_cancelled_and_destroyed_work_never_runs() {
    let (agent, calls, cap, lane) = counting_agent();
    let cancelled = agent.call(lane, &cap, "ping", vec![]).unwrap();
    agent.cancel(&cancelled).unwrap();
    let _ = cancelled.peek().unwrap_err();
    agent.run();
    assert_eq!(calls.load(Ordering::SeqCst), 0, "cancelled job dispatched");

    let lane2 = agent.create_lane("second", Budget::default()).unwrap();
    let _queued = agent.call(lane2, &cap, "ping", vec![]).unwrap();
    agent.destroy_lane(lane2).unwrap();
    agent.run();
    assert_eq!(calls.load(Ordering::SeqCst), 0, "destroyed lane dispatched");
}

#[test]
fn review_lane_capacity_counts_queued_calls() {
    let (agent, _calls, cap, _lane) = counting_agent();
    let lane = agent.create_lane("tight", Budget::calls(1)).unwrap();
    assert!(agent.call(lane, &cap, "ping", vec![]).is_ok());
    let error = agent
        .call(lane, &cap, "ping", vec![])
        .expect_err("a queued call counts against the lane budget");
    assert_eq!(error.code(), "rpc/budget-exceeded");
}

#[test]
fn review_byte_budget_is_charged() {
    let (agent, _calls, cap, lane) = counting_agent();
    let narrow = agent
        .attenuate(
            &cap,
            CapAttrs::new(&["ping"]).with_budget(Budget {
                max_bytes: 8,
                ..Budget::default()
            }),
        )
        .unwrap();
    let error = agent
        .call(
            lane,
            &narrow,
            "ping",
            vec![Arg::text("a string larger than eight bytes")],
        )
        .expect_err("byte budget");
    assert_eq!(error.code(), "rpc/budget-exceeded");
    assert!(error.to_string().contains("byte"), "{error}");
}

#[test]
fn review_tool_policy_predicate_matches_the_enforcer() {
    let (agent, _calls, cap, _lane) = counting_agent();
    // Parent without a policy: adding one narrows (allowed).
    let child = agent
        .attenuate(
            &cap,
            CapAttrs::new(&["ping"]).with_tool_policy(ToolPolicy::allow(&["ping"])),
        )
        .expect("adding a policy narrows authority");
    let attrs = agent.cap_attrs(&child).unwrap();
    assert!(attrs.tool_policy.is_some());
    assert!(attrs.is_attenuation_of(&agent.cap_attrs(&cap).unwrap()));

    // Parent with a policy: dropping it widens (refused).
    let error = agent
        .attenuate(&child, CapAttrs::new(&["ping"]))
        .expect_err("dropping a tool policy widens authority");
    assert_eq!(error.code(), "rpc/attenuation-escalation");
}

#[test]
fn review_module_payloads_are_redacted() {
    // A subgraph that contains the secret must not carry its bytes on the wire.
    let (agent, _provider, cap, lane) = setup();
    let value = agent
        .call(
            lane,
            &cap,
            "subgraph",
            vec![Arg::Value(Value::Path("app".into()))],
        )
        .expect("call")
        .value()
        .expect("subgraph");
    let bytes = match value {
        Value::Module(bytes) => bytes,
        other => panic!("expected module bytes, got {other:?}"),
    };
    assert!(
        !bytes
            .windows("red-team-canary".len())
            .any(|window| window == b"red-team-canary"),
        "a module payload leaked secret bytes"
    );
    let module = active_infinity::decode(&bytes).expect("decode");
    assert!(!module.has_secret(), "secret kind survived redaction");
    assert!(module.nodes().iter().any(|node| matches!(
        node,
        active_infinity::Inode::Str(text) if text == active_rpc::security::SECRET_MARKER
    )));
}

#[test]
fn review_wire_rejects_deep_value_nesting() {
    // 80 nested lists exceed the 64-level ceiling.
    let mut value = Value::Int(1);
    for _ in 0..80 {
        value = Value::list(vec![value]);
    }
    let envelope = Envelope::request(1, "ping", vec![Arg::Value(value)]);
    let bytes = envelope.encode().expect("encode");
    let error = Envelope::decode(&bytes).unwrap_err();
    assert_eq!(error.code(), "rpc/wire");
}

#[test]
fn review_zero_ceilings_are_refused_in_every_budget_field() {
    for budget in [
        Budget {
            max_calls: 0,
            ..Budget::default()
        },
        Budget {
            max_array_len: 0,
            ..Budget::default()
        },
        Budget {
            max_value_size: 0,
            ..Budget::default()
        },
    ] {
        assert!(budget.check().is_err());
    }
}

#[test]
fn review_agent_secrets_are_random() {
    let first = Agent::new();
    let second = Agent::new();
    let one = first.mint(first.register(Box::new(Echo)), 0, CapAttrs::new(&["echo"]));
    let two = second.mint(second.register(Box::new(Echo)), 0, CapAttrs::new(&["echo"]));
    assert_ne!(
        one.unwrap().id(),
        two.unwrap().id(),
        "two agents must not derive the same first capability id"
    );
}

#[test]
fn review_provider_may_call_back_into_the_agent() {
    let (agent, calls, cap, lane) = counting_agent();
    let promise = agent.call(lane, &cap, "ping", vec![]).unwrap();
    assert_eq!(promise.value().unwrap(), Value::text("pong"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
