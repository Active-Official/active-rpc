//! R-02 kernel dispatch: authority, rollback and revocation regressions.
//!
//! Each test corresponds to a finding in `docs/hardening/COPILOT-MARATHON.md`
//! (R-02, 2026-11-01) and fails against the pre-fix tree.

use active_rpc::cap::{CapAttrs, CapPersistence};
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, Budget, CapHandle, ProviderId};

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

    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::text("ok")))
    }
}

fn agent() -> (Agent, ProviderId, active_rpc::LaneId) {
    let agent = Agent::with_secret([0x5a; 32]);
    let provider = agent.register(Box::new(Echo));
    let lane = agent
        .create_lane("kernel", Budget::default())
        .expect("lane");
    (agent, provider, lane)
}

fn settle(agent: &Agent, lane: active_rpc::LaneId, cap: &CapHandle) -> active_rpc::Result<()> {
    let promise = agent.call(lane, cap, "echo", Vec::new())?;
    agent.run();
    promise.value().map(|_| ())
}

/// Revocation is transitive even after an intermediate record is dropped.
#[test]
fn revocation_reaches_a_grandchild_through_a_dropped_intermediate() {
    let (agent, provider, lane) = agent();
    let root = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("root");
    let child = agent
        .attenuate(&root, CapAttrs::new(&["echo"]))
        .expect("child");
    let grandchild = agent
        .attenuate(&child, CapAttrs::new(&["echo"]))
        .expect("grandchild");
    drop(child); // the intermediate record is removed
    agent.revoke(&root);
    let error = settle(&agent, lane, &grandchild).expect_err("the grandchild must be revoked");
    assert_eq!(error.code(), "rpc/revoked", "{error}");
}

/// A call refused for an unknown dependency leaves no charge, promise or
/// receipt behind.
#[test]
fn a_refused_promise_dependency_charges_nothing_and_leaves_no_record() {
    let (agent, provider, lane) = agent();
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.budget = Budget::calls(1);
    let cap = agent.mint(provider, 0, attrs).expect("cap");
    agent.enable_receipts(true);
    let unknown = active_rpc::PromiseId(9_999);
    let error = agent
        .call(lane, &cap, "echo", vec![Arg::Promise(unknown)])
        .expect_err("the dependency does not exist");
    assert_eq!(error.code(), "rpc/unknown-promise", "{error}");
    assert_eq!(agent.promise_count(), 0, "a refused call created a promise");
    assert!(agent.receipts().is_empty(), "a refused call was receipted");
    // The single budgeted call is still available.
    let promise = agent
        .call(lane, &cap, "echo", Vec::new())
        .expect("the budget is intact");
    agent.run();
    promise.value().expect("ok");
}

/// An idempotent replay is a fresh exercise of authority: revoking the
/// capability (or rebinding it) disables the cached promise.
#[test]
fn an_idempotent_replay_is_refused_after_revoke() {
    let (agent, provider, lane) = agent();
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let first = agent
        .call_idempotent(lane, &cap, "echo", Vec::new(), "key-1")
        .expect("first");
    agent.run();
    first.value().expect("ok");
    agent.revoke(&cap);
    let error = agent
        .call_idempotent(lane, &cap, "echo", Vec::new(), "key-1")
        .expect_err("a replay must re-check liveness");
    assert_eq!(error.code(), "rpc/revoked", "{error}");
}

/// A caller-supplied binding that disagrees with the admitted peer is refused
/// instead of silently overwritten.
#[test]
fn mint_bound_refuses_a_conflicting_binding() {
    use active_rpc::identity::{IdentityPolicy, PeerIdentity};
    let (agent, provider, _lane) = agent();
    let peer = PeerIdentity::from_certificate(b"peer-a");
    let admitted = IdentityPolicy::default()
        .admit(Some(&peer), true)
        .expect("admit");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.bound_to = Some([0x11; 32]);
    let error = agent
        .mint_bound(&admitted, provider, 0, attrs)
        .expect_err("a bound mismatch must not be overwritten");
    assert_eq!(error.code(), "rpc/identity", "{error}");
}

/// Durable policy applies to attenuation and export, not only to mint.
#[test]
fn disabling_durable_refuses_attenuation_and_export() {
    let agent = Agent::with_secret([0x5b; 32]);
    agent.set_durable_capabilities(true);
    let provider = agent.register(Box::new(Echo));
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let durable = agent.mint(provider, 0, attrs).expect("durable");
    agent.set_durable_capabilities(false);
    let error = agent
        .attenuate(&durable, CapAttrs::new(&["echo"]).durable())
        .expect_err("durable attenuation is refused by policy");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
    let error = agent
        .export_capability(&durable)
        .expect_err("export is refused by policy");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
}

/// Path scope is checked through lists and maps, not only at the top level.
#[test]
fn a_nested_path_argument_is_outside_the_scope() {
    let (agent, provider, lane) = agent();
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]).with_path("app"))
        .expect("cap");
    let nested = Value::List(vec![Value::Map(
        [("file".to_string(), Value::Path("etc.passwd".into()))]
            .into_iter()
            .collect(),
    )]);
    let error = agent
        .call(lane, &cap, "echo", vec![Arg::Value(nested)])
        .expect_err("the nested path is outside app");
    assert_eq!(error.code(), "rpc/path-not-granted", "{error}");
    // A path inside the scope still passes.
    let inside = Value::List(vec![Value::Path("app.data".into())]);
    agent
        .call(lane, &cap, "echo", vec![Arg::Value(inside)])
        .expect("inside the scope");
}

/// Sending a capability id the kernel does not know is a capability-table
/// fault, not an argument fault.
#[test]
fn send_reports_an_unknown_capability() {
    let (agent, _provider, lane) = agent();
    let channel = agent
        .create_channel("send", active_rpc::channel::Direction::Send)
        .expect("channel");
    let forged = agent.import(active_rpc::CapId([0x7f; 16]));
    let error = agent
        .send(lane, channel, Value::text("x"), &[forged])
        .expect_err("the id is unknown");
    assert_eq!(error.code(), "rpc/unknown-capability", "{error}");
}

/// Subscribing enqueues nothing, so a full channel queue is not a reason to
/// refuse it.
#[test]
fn subscribe_is_not_refused_by_a_full_queue() {
    let (agent, _provider, lane) = agent();
    agent.set_channel_queue_ceiling(1).expect("ceiling");
    let channel = agent
        .create_channel("full", active_rpc::channel::Direction::Both)
        .expect("channel");
    agent
        .send(lane, channel, Value::text("first"), &[])
        .expect("first send");
    agent
        .subscribe(lane, channel)
        .expect("a subscription must not need queue space");
}

/// An idempotency key is bounded.
#[test]
fn an_oversized_idempotency_key_is_refused() {
    let (agent, provider, lane) = agent();
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let key = "k".repeat(active_rpc::kernel::MAX_IDEMPOTENCY_KEY_BYTES + 1);
    let error = agent
        .call_idempotent(lane, &cap, "echo", Vec::new(), &key)
        .expect_err("the key is too long");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
}

/// A delta cannot remove an id and re-add it with wider authority.
#[test]
fn a_delta_cannot_replace_an_id_with_a_wider_descriptor() {
    use active_rpc::wire::{CapDescriptor, CapTableDelta};
    let (agent, provider, _lane) = agent();
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let base = vec![CapDescriptor::from_attrs(
        cap.id(),
        &CapAttrs::new(&["echo"]),
    )];
    let mut wider = CapAttrs::new(&["echo", "admin"]);
    wider.budget = Budget {
        max_calls: u64::MAX,
        max_bytes: u64::MAX,
        ..Budget::default()
    };
    let added = vec![CapDescriptor::from_attrs(cap.id(), &wider)];
    let delta = CapTableDelta {
        base: active_rpc::wire::cap_table_hash(&base).expect("hash"),
        removed: vec![cap.id()],
        added,
    };
    let error = delta
        .apply_to(&base)
        .expect_err("a replacement is not an addition");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");
}
