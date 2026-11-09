//! R-03 capabilities: attenuation monotonicity, durable records, reference
//! accounting and the budget meter.
//!
//! Every test here fails against the tree before its fix.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use active_rpc::budget::{Budget, BudgetMeter};
use active_rpc::cap::{CapAttrs, CapId, ToolPolicy};
use active_rpc::identity::{IdentityPolicy, PeerIdentity};
use active_rpc::kernel::Provider;
use active_rpc::tool::HttpTool;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::wire::{decode_capability_table, CapDescriptor};
use active_rpc::{Agent, CapHandle, CapPersistence, CapabilityRecord};

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
                .unwrap_or(Value::text("ok")),
        ))
    }
}

/// Records every argument list it is asked to run.
struct Recorder {
    calls: Rc<Cell<usize>>,
}

impl Provider for Recorder {
    fn name(&self) -> &'static str {
        "recorder"
    }

    fn methods(&self) -> Vec<String> {
        vec!["run".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
        self.calls.set(self.calls.get() + 1);
        Ok(Response::Value(
            call.args
                .iter()
                .find_map(|arg| match arg {
                    Arg::Value(value) => Some(value.clone()),
                    _ => None,
                })
                .unwrap_or(Value::text("ok")),
        ))
    }
}

fn admitted(certificate: &[u8]) -> active_rpc::AdmittedIdentity {
    let peer = PeerIdentity::from_certificate(certificate);
    IdentityPolicy::default()
        .admit(Some(&peer), true)
        .expect("admit")
}

fn agent() -> (Agent, active_rpc::ProviderId, active_rpc::LaneId) {
    let agent = Agent::with_secret([0x31; 32]);
    let provider = agent.register(Box::new(Echo));
    let lane = agent.create_lane("caps", Budget::default()).expect("lane");
    (agent, provider, lane)
}

fn durable_agent() -> (Agent, active_rpc::ProviderId) {
    let agent = Agent::with_secret([0x32; 32]);
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key([0x82; 32]);
    let provider = agent.register(Box::new(Echo));
    (agent, provider)
}

/// A durable capability bound to the peer that restores it: a record must
/// name its peer, so an unbound one cannot be exported.
fn durable_cap(agent: &Agent, provider: active_rpc::ProviderId) -> CapHandle {
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let owner = admitted(b"owner");
    agent
        .mint_bound(&owner, provider, 0, attrs)
        .expect("durable cap")
}

/// A promise argument was a placeholder when the scope check ran; the value it
/// resolves to is the argument the provider actually receives.
#[test]
fn a_pipelined_argument_cannot_carry_a_path_outside_the_scope() {
    let calls = Rc::new(Cell::new(0));
    let agent = Agent::with_secret([0x33; 32]);
    let provider = agent.register(Box::new(Recorder {
        calls: Rc::clone(&calls),
    }));
    let lane = agent.create_lane("pipe", Budget::default()).expect("lane");
    let producer = agent
        .mint(provider, 0, CapAttrs::new(&["run"]))
        .expect("producer");
    let consumer = agent
        .mint(provider, 0, CapAttrs::new(&["run"]).with_path("public"))
        .expect("consumer");

    // A literal path is refused before the provider runs.
    let error = agent
        .call(
            lane,
            &consumer,
            "run",
            vec![Arg::Value(Value::path("secret.item"))],
        )
        .expect_err("a literal path outside the scope is refused");
    assert_eq!(error.code(), "rpc/path-not-granted", "{error}");

    let produced = agent
        .call(
            lane,
            &producer,
            "run",
            vec![Arg::Value(Value::path("secret.item"))],
        )
        .expect("producer call");
    agent.run();
    produced.value().expect("the producer is unscoped");
    let before = calls.get();

    let pipelined = agent
        .call(lane, &consumer, "run", vec![Arg::Promise(produced.id())])
        .expect("queued");
    agent.run();
    let error = pipelined
        .value()
        .expect_err("the resolved value is checked too");
    assert_eq!(error.code(), "rpc/path-not-granted", "{error}");
    assert_eq!(
        calls.get(),
        before,
        "the provider ran with a path outside the scope"
    );
}

/// The byte budget of the capability and of its ancestors is charged for what
/// a promise resolves into, not only for the placeholder.
#[test]
fn a_pipelined_argument_is_charged_at_dispatch() {
    let agent = Agent::with_secret([0x34; 32]);
    let provider = agent.register(Box::new(Echo));
    let lane = agent.create_lane("bytes", Budget::default()).expect("lane");
    let producer = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("producer");
    let consumer = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["echo"]).with_budget(Budget {
                max_bytes: 64,
                ..Budget::default()
            }),
        )
        .expect("consumer");

    let produced = agent
        .call(
            lane,
            &producer,
            "echo",
            vec![Arg::Value(Value::text("x".repeat(4096)))],
        )
        .expect("producer call");
    agent.run();
    produced.value().expect("unscoped producer");

    let pipelined = agent
        .call(lane, &consumer, "echo", vec![Arg::Promise(produced.id())])
        .expect("queued under the placeholder size");
    agent.run();
    let error = pipelined
        .value()
        .expect_err("4096 bytes do not fit a 64-byte grant");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

/// A tool policy may not add process execution under a parent that has no
/// explicit policy: the parent's effective policy is "its methods, its bytes, no
/// process".
#[test]
fn attenuation_cannot_add_process_execution() {
    let parent = CapAttrs::new(&["run"]);
    let child = CapAttrs::new(&["run"]).with_tool_policy(ToolPolicy {
        allowed: ["run".to_string()].into_iter().collect(),
        max_arg_bytes: parent.budget.max_bytes,
        allow_process: true,
    });
    assert!(
        !child.is_attenuation_of(&parent),
        "the predicate accepted a widened tool policy"
    );
    let error = parent
        .attenuate(child)
        .expect_err("attenuation must refuse a process grant");
    assert_eq!(error.code(), "rpc/attenuation-escalation", "{error}");
}

/// Revocation reaches a durable record: the exported authority cannot be
/// restored after the live capability is revoked.
#[test]
fn a_revoked_durable_capability_cannot_be_restored() {
    let (agent, provider) = durable_agent();
    let cap = durable_cap(&agent, provider);
    let record = agent.export_capability(&cap).expect("export");
    agent.revoke(&cap).expect("revoke");
    // The record belongs to `owner`; the binding is reported before the
    // tombstone, so the restore must present that peer to reach the tombstone.
    let error = agent
        .restore_capability_in_process_only(&record, &admitted(b"owner"))
        .expect_err("a revoked record must not restore");
    assert_eq!(error.code(), "rpc/revoked", "{error}");
}

/// A record is a credential: without a seal from this deployment it is not
/// accepted, and an edit breaks the seal.
#[test]
fn an_edited_or_unsealed_record_is_refused() {
    let (agent, provider) = durable_agent();
    let cap = durable_cap(&agent, provider);
    let record = agent.export_capability(&cap).expect("export");
    let peer = admitted(b"owner");

    let mut widened = record.clone();
    widened.budget = Budget {
        max_calls: u64::MAX,
        max_bytes: u64::MAX,
        max_wall_ms: u64::MAX,
        max_nodes: u64::MAX,
        max_depth: u64::MAX,
        max_array_len: u64::MAX,
        max_value_size: u64::MAX,
    };
    let error = agent
        .restore_capability_in_process_only(&widened, &peer)
        .expect_err("an edited record must not restore");
    assert_eq!(error.code(), "rpc/persistence", "{error}");

    let mut unsealed = record.clone();
    unsealed.seal = None;
    let error = agent
        .restore_capability_in_process_only(&unsealed, &peer)
        .expect_err("an unsealed record must not restore");
    assert_eq!(error.code(), "rpc/persistence", "{error}");

    // A kernel with no key exports nothing at all.
    let keyless = Agent::with_secret([0x35; 32]);
    keyless.set_durable_capabilities(true);
    let provider = keyless.register(Box::new(Echo));
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let cap = keyless.mint(provider, 0, attrs).expect("cap");
    let error = keyless
        .export_capability(&cap)
        .expect_err("no key, no record");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
}

/// The parent's budget bounds its whole subtree.
#[test]
fn a_child_call_consumes_the_parent_budget() {
    let (agent, provider, lane) = agent();
    let parent = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["echo"]).with_budget(Budget::calls(2)),
        )
        .expect("parent");
    let child = agent
        .attenuate(
            &parent,
            CapAttrs::new(&["echo"]).with_budget(Budget::calls(2)),
        )
        .expect("child");
    for _ in 0..2 {
        let promise = agent.call(lane, &parent, "echo", Vec::new()).expect("call");
        agent.run();
        promise.value().expect("within the grant");
    }
    let error = agent
        .call(lane, &child, "echo", Vec::new())
        .expect_err("the parent's grant is spent");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");

    // A sibling that only spends the child's own meter is refused as well: the
    // subtree shares the parent's ceiling.
    let error = agent
        .call(lane, &parent, "echo", Vec::new())
        .expect_err("the parent itself is spent");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

/// A record field is hostile input: 64 bytes of multi-byte characters must be
/// a refusal, never a slice panic.
#[test]
fn a_non_ascii_record_field_is_refused_without_panicking() {
    let binding: String = "\u{20ac}".repeat(21) + "a";
    assert_eq!(binding.len(), 64);
    let json = format!(
        r#"{{"format":"active-rpc/capability-record/1","provider":"echo","object":0,"methods":["echo"],"budget":{{"calls":1,"bytes":1,"wall_ms":1,"nodes":1,"depth":1,"array_len":1,"value_size":1}},"read_only":false,"redact":false,"path_scope":null,"topics":null,"tool_policy":null,"bound_to":"{binding}","expires_at":null,"wall_clock":false,"record_id":"{id}","seal":null}}"#,
        id = "11".repeat(32)
    );
    let error = CapabilityRecord::from_json(&json).expect_err("must be refused");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
}

/// The meter never wraps: a byte count at the ceiling cannot take it back to
/// zero in release, and does not panic in debug.
#[test]
fn a_meter_at_the_ceiling_never_wraps() {
    let mut meter = BudgetMeter::new(Budget {
        max_bytes: u64::MAX,
        ..Budget::default()
    });
    meter.charge(u64::MAX).expect("the exact ceiling fits");
    assert_eq!(meter.bytes(), u64::MAX);
    let error = meter.charge(1).expect_err("one more byte is over");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    assert_eq!(meter.bytes(), u64::MAX);
}

/// A text argument is not a path: the adapter must read `Value::Path`, so the
/// kernel's scope walk is the only route to the path.
#[test]
fn a_text_argument_is_not_an_http_path() {
    let mut tool = HttpTool::new("http://127.0.0.1:1", &[("GET", "/safe")]);
    let mut call = Call::new("get", vec![Arg::text("/admin")]);
    call.budget = Budget::default();
    let error = tool.invoke(0, &call).expect_err("text is not a path");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
}

/// The evaluator's ceilings are derived from the grant and clamped to it.
#[test]
fn evaluator_ceilings_never_exceed_the_grant() {
    let budget = Budget {
        max_bytes: 1_024,
        max_value_size: 10_000_000,
        max_depth: 256,
        max_array_len: 100_000,
        ..Budget::default()
    };
    let evaluator = budget.to_active_budget();
    assert!(evaluator.max_total_value_size <= budget.max_bytes);
    assert!(evaluator.max_keys <= budget.max_array_len);
    assert!(evaluator.max_keys <= budget.max_depth.saturating_mul(64));
}

/// A negotiated table cannot grow past its ceiling one delta at a time.
#[test]
fn a_delta_cannot_grow_the_table_past_its_ceiling() {
    use active_rpc::wire::{CapTableDelta, MAX_CAP_TABLE};
    let mut base = Vec::new();
    // Start at 1: a zero id is not a capability, and the delta validates its
    // descriptors (round 33, M4).
    for index in 1..=MAX_CAP_TABLE {
        let mut id = [0u8; 16];
        id[0] = (index & 0xff) as u8;
        id[1] = (index >> 8) as u8;
        base.push(CapDescriptor::from_attrs(
            CapId(id),
            &CapAttrs::new(&["echo"]),
        ));
    }
    let mut extra = [0u8; 16];
    extra[15] = 0x7f;
    let delta = CapTableDelta::new(
        &base,
        Vec::new(),
        vec![CapDescriptor::from_attrs(
            CapId(extra),
            &CapAttrs::new(&["echo"]),
        )],
    )
    .expect("delta");
    let error = delta.apply_to(&base).expect_err("the table is full");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");
}

/// A provider that drops a handle from its own `on_drop` still has that release
/// applied, and the provider sees exactly one notification per object.
#[test]
fn a_drop_inside_a_provider_notification_is_applied() {
    struct Holder {
        slot: Rc<RefCell<Option<CapHandle>>>,
        notifications: Rc<RefCell<Vec<u64>>>,
    }

    impl Provider for Holder {
        fn name(&self) -> &'static str {
            "holder"
        }

        fn methods(&self) -> Vec<String> {
            vec!["hold".to_string()]
        }

        fn mutating(&self, _method: &str) -> bool {
            false
        }

        fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
            Ok(Response::Value(Value::text("ok")))
        }

        fn on_drop(&mut self, object: u64, _cap: CapId) {
            self.notifications.borrow_mut().push(object);
            // Dropping a handle here runs inside the kernel borrow.
            let held = self.slot.borrow_mut().take();
            drop(held);
        }
    }

    let slot: Rc<RefCell<Option<CapHandle>>> = Rc::new(RefCell::new(None));
    let notifications = Rc::new(RefCell::new(Vec::new()));
    let agent = Agent::with_secret([0x36; 32]);
    let provider = agent.register(Box::new(Holder {
        slot: Rc::clone(&slot),
        notifications: Rc::clone(&notifications),
    }));
    let held = agent
        .mint(provider, 7, CapAttrs::new(&["hold"]))
        .expect("held cap");
    // The slot holds the only reference to object 7.
    *slot.borrow_mut() = Some(held);
    let doomed = agent
        .mint(provider, 9, CapAttrs::new(&["hold"]))
        .expect("doomed cap");
    drop(doomed);
    // The release of the held handle happened inside `on_drop`; it is applied
    // at the next kernel borrow point.
    agent.run();
    let seen = notifications.borrow().clone();
    assert_eq!(seen, vec![9, 7], "notifications were lost: {seen:?}");
}

/// An imported (id-only) handle has no reference of its own and cannot export
/// authority.
#[test]
fn export_from_an_imported_handle_is_refused() {
    let (agent, provider) = durable_agent();
    let cap = durable_cap(&agent, provider);
    let borrowed = agent.import(cap.id());
    let error = agent
        .export_capability(&borrowed)
        .expect_err("an id-only handle must not export");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
}

/// Descriptors that cannot be re-encoded byte-for-byte are refused.
#[test]
fn a_descriptor_is_canonical_or_refused() {
    let descriptor = CapDescriptor::from_attrs(CapId([5u8; 16]), &CapAttrs::new(&["echo"]));
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&descriptor.id.0);
    // Two method names, both "echo".
    bytes.extend_from_slice(&2u32.to_le_bytes());
    for _ in 0..2 {
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(b"echo");
    }
    for value in [
        Budget::default().max_calls,
        Budget::default().max_bytes,
        Budget::default().max_wall_ms,
        Budget::default().max_nodes,
        Budget::default().max_depth,
        Budget::default().max_array_len,
        Budget::default().max_value_size,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.push(0);
    bytes.push(0);
    bytes.push(0);
    let error = decode_capability_table(&bytes).expect_err("duplicate methods are not canonical");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");

    // A descriptor with no methods grants nothing.
    let mut empty = Vec::new();
    empty.extend_from_slice(&1u32.to_le_bytes());
    empty.extend_from_slice(&descriptor.id.0);
    empty.extend_from_slice(&0u32.to_le_bytes());
    for value in [
        Budget::default().max_calls,
        Budget::default().max_bytes,
        Budget::default().max_wall_ms,
        Budget::default().max_nodes,
        Budget::default().max_depth,
        Budget::default().max_array_len,
        Budget::default().max_value_size,
    ] {
        empty.extend_from_slice(&value.to_le_bytes());
    }
    empty.push(0);
    empty.push(0);
    empty.push(0);
    let error = decode_capability_table(&empty).expect_err("an empty grant is not a capability");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");
}

/// The capability registry and the lineage depth are bounded.
#[test]
fn the_registry_and_the_lineage_are_bounded() {
    use active_rpc::kernel::{MAX_CAPS, MAX_LINEAGE_DEPTH};
    let agent = Agent::with_secret([0x37; 32]);
    let provider = agent.register(Box::new(Echo));
    let mut caps = Vec::with_capacity(MAX_CAPS);
    for _ in 0..MAX_CAPS {
        caps.push(
            agent
                .mint(provider, 0, CapAttrs::new(&["echo"]))
                .expect("under the ceiling"),
        );
    }
    let error = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect_err("the registry is full");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    drop(caps);

    let mut chain = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("root");
    for depth in 0..MAX_LINEAGE_DEPTH {
        chain = agent
            .attenuate(&chain, CapAttrs::new(&["echo"]))
            .unwrap_or_else(|error| panic!("depth {depth}: {error}"));
    }
    let error = agent
        .attenuate(&chain, CapAttrs::new(&["echo"]))
        .expect_err("the chain is too deep");
    assert_eq!(error.code(), "rpc/attenuation-escalation", "{error}");
}

/// A restore carries the binding it describes.
///
/// `CapabilityRecord::attrs` used to be public, which published a bridge that
/// turned an unauthenticated record into mintable authority (the seal is checked
/// by `restore_capability_with`, not by the parser). The audited path is the restore
/// itself, so this test drives that and compares the restored capability with
/// the record.
#[test]
fn a_restore_preserves_the_binding() {
    let (agent, provider) = durable_agent();
    let owner = admitted(b"owner");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let cap = agent
        .mint_bound(&owner, provider, 0, attrs)
        .expect("bound cap");
    let record = agent.export_capability(&cap).expect("export");
    // One live capability per credential: releasing the handle frees the grant
    // for the restore (a revocation would tombstone the record instead).
    drop(cap);
    let restored = agent
        .restore_capability_in_process_only(&record, &owner)
        .expect("restore");
    assert_eq!(
        agent.cap_attrs(&restored).expect("attrs").bound_to,
        Some(PeerIdentity::from_certificate(b"owner").fingerprint())
    );
}

/// A capability record keeps its id across a round trip, and the record id is
/// what a revocation tombstones.
#[test]
fn a_record_keeps_its_identity_across_the_round_trip() {
    let (agent, provider) = durable_agent();
    let cap = durable_cap(&agent, provider);
    let record = agent.export_capability(&cap).expect("export");
    let parsed = CapabilityRecord::from_json(&record.to_json()).expect("parse");
    assert_eq!(parsed.record_id, record.record_id);
    assert_ne!(record.record_id, [0u8; 32]);
    // The seal covers the record id: changing it invalidates the seal.
    let mut tampered = parsed;
    tampered.record_id[0] ^= 1;
    let error = agent
        .restore_capability_in_process_only(&tampered, &admitted(b"owner"))
        .expect_err("a re-pointed record is not sealed");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
}
