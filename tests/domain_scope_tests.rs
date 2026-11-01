//! R-07 round 1, D-1: a capability confined to a path sees only that path.
//!
//! The kernel checks `Arg::Value(Value::Path)` arguments; these tests drive the
//! domain provider, which must also refuse a pathless form (it would return the
//! whole module) and a path outside the scope.

use active_rpc::cap::CapAttrs;
use active_rpc::domain::ModuleProvider;
use active_rpc::value::{Arg, Value};
use active_rpc::{Agent, Budget};

const SOURCE: &str = r#"
# @intent: "scope fixture"
[app]
name = "in-scope"

[ops]
host = "out-of-scope-canary"
"#;

fn fixture() -> (Agent, active_rpc::CapHandle, active_rpc::LaneId) {
    let agent = Agent::with_secret([0x71; 32]);
    let mut provider = ModuleProvider::new();
    let module = active_rpc::domain::module_from_source(SOURCE, "scope.active").expect("module");
    let object = provider.install(module).expect("install");
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(&["evaluate", "patch", "stats"]);
    attrs.path_scope = Some("app".to_string());
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent.create_lane("scope", Budget::default()).expect("lane");
    (agent, cap, lane)
}

fn call(
    agent: &Agent,
    lane: active_rpc::LaneId,
    cap: &active_rpc::CapHandle,
    args: Vec<Arg>,
) -> active_rpc::Result<Value> {
    let promise = agent.call(lane, cap, "evaluate", args)?;
    agent.run();
    promise.value()
}

/// A pathless `evaluate` under a scoped capability must not return the module.
#[test]
fn a_pathless_evaluate_is_refused_under_a_scope() {
    let (agent, cap, lane) = fixture();
    let error = call(&agent, lane, &cap, Vec::new()).expect_err("no path is not the module");
    assert_eq!(error.code(), "rpc/path-not-granted", "{error}");
}

/// A path outside the scope is refused by the provider, not only by the kernel.
#[test]
fn an_out_of_scope_path_is_refused_by_the_provider() {
    let (agent, cap, lane) = fixture();
    let error = call(&agent, lane, &cap, vec![Arg::Value(Value::path("ops"))])
        .expect_err("ops is outside app");
    assert_eq!(error.code(), "rpc/path-not-granted", "{error}");
}

/// An in-scope path answers, and the answer holds only in-scope data.
#[test]
fn an_in_scope_path_answers_without_out_of_scope_data() {
    let (agent, cap, lane) = fixture();
    let value = call(&agent, lane, &cap, vec![Arg::Value(Value::path("app"))]).expect("in scope");
    let rendered = format!("{value:?}");
    assert!(!rendered.contains("out-of-scope-canary"), "{rendered}");
}

/// The same rule protects a write: a scoped `patch` cannot reach outside.
#[test]
fn a_scoped_patch_cannot_reach_outside_the_scope() {
    let agent = Agent::with_secret([0x72; 32]);
    let mut provider = ModuleProvider::new();
    let module = active_rpc::domain::module_from_source(SOURCE, "scope.active").expect("module");
    let object = provider.install(module).expect("install");
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(&["patch"]);
    attrs.path_scope = Some("app".to_string());
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent.create_lane("scope", Budget::default()).expect("lane");
    let promise = agent
        .call(lane, &cap, "patch", vec![Arg::Value(Value::path("ops"))])
        .expect_err("ops is outside app");
    assert_eq!(promise.code(), "rpc/path-not-granted");
}
