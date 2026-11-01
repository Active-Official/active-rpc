//! Throwaway R-07 probes, batch 2.

use active_infinity::{InfinityModule, Inode, NodeId, SecretBytes};
use active_rpc::cap::CapAttrs;
use active_rpc::domain::ModuleProvider;
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Value};
use active_rpc::{Agent, Budget};

const SRC: &str = r#"
# @ai_immutable: true
[app]
name = "in-scope"

[ops]
host = "out"
"#;

#[test]
fn q1_panic_site() {
    let mut module = InfinityModule::new();
    let leaf = module.push(Inode::Str("a-value".into()));
    let root = module.push(Inode::Table {
        fields: vec![("a".to_string(), leaf)],
    });
    module.set_root(Some(root));
    module.push(Inode::SecretRef {
        locator: NodeId(99),
    });
    let mut provider = ModuleProvider::new();
    let object = provider.install(module);
    let mut call = Call::new("why", vec![Arg::Value(Value::Path("a".into()))]);
    call.redact = true;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        provider.invoke(object, &call)
    }));
    let payload = outcome.err().expect("panic");
    let message = payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default();
    println!("Q1 panic message = {message}");
    assert!(message.contains("index out of bounds"), "{message}");
}

#[test]
fn q2_patch_ignores_ai_immutable() {
    let module = active_rpc::domain::module_from_source(SRC, "probe.active").expect("module");
    println!(
        "Q2 immutable nodes = {:?}",
        active_infinity::interop::immutable_nodes(&module)
    );
    let target = active_rpc::domain::resolve_path(&module, "app.name").expect("path");
    let mut provider = ModuleProvider::new();
    let object = provider.install(module);
    let call = Call::new(
        "patch",
        vec![
            Arg::Value(Value::Path("app.name".into())),
            Arg::Value(Value::Text("agent-changed-it".into())),
        ],
    );
    let outcome = provider.invoke(object, &call);
    println!("Q2 patch of node {target:?} -> ok={}", outcome.is_ok());
    let stored = provider.module(object).expect("module");
    println!(
        "Q2 stored value now = {:?}",
        stored.get(target).map(|n| format!("{n:?}"))
    );
    assert!(outcome.is_ok(), "BUG: ai_immutable node was patched");
}

#[test]
fn q3_provenance_with_a_literal_secret() {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::new("literal-canary")));
    let root = module.push(Inode::Table {
        fields: vec![("token".to_string(), secret)],
    });
    module.set_root(Some(root));
    module.set_provenance(Some(active_infinity::Provenance {
        producer: None,
        timestamp_ms: 0,
        model: None,
        tool: Some("run --token literal-canary".into()),
        parent: None,
        entries: Vec::new(),
    }));
    println!(
        "Q3 library provenance_lines = {:?}",
        active_infinity::interop::provenance_lines(&module)
    );
    let mut provider = ModuleProvider::new();
    let object = provider.install(module);
    let value = provider
        .invoke(object, &Call::new("provenance", vec![]))
        .expect("provenance");
    println!("Q3 provider provenance = {value:?}");
}

#[test]
fn q4_evaluate_budget_is_enforced() {
    let mut provider = ModuleProvider::new();
    let module = active_rpc::domain::module_from_source(SRC, "probe.active").expect("module");
    let object = provider.install(module);
    let mut call = Call::new("evaluate", vec![]);
    call.budget = Budget {
        max_nodes: 1,
        ..Budget::default()
    };
    let outcome = provider.invoke(object, &call);
    println!("Q4 evaluate with max_nodes=1 -> {outcome:?}");
}

#[test]
fn q5_stats_under_a_redacting_capability() {
    let mut provider = ModuleProvider::new();
    let module = active_rpc::domain::module_from_source(
        r#"
[a]
one = secret("one-canary")
two = secret("two-canary")
three = secret("three-canary")
"#,
        "secrets.active",
    )
    .expect("module");
    let object = provider.install(module);
    let agent = Agent::with_secret([9u8; 32]);
    let provider_id = agent.register(Box::new(provider));
    let cap = agent
        .mint(
            provider_id,
            object,
            CapAttrs::new(&["stats"]).redacted().read_only(),
        )
        .expect("mint");
    let lane = agent.create_lane("main", Budget::default()).expect("lane");
    let value = agent
        .call(lane, &cap, "stats", vec![])
        .expect("queued")
        .value()
        .expect("stats");
    println!("Q5 redacting stats -> {value:?}");
}

#[test]
fn q6_why_of_a_secret_path_under_a_redacting_capability() {
    let mut provider = ModuleProvider::new();
    let module = active_rpc::domain::module_from_source(
        r#"
[a]
one = "x"
[gen]
derived = "${a.one}-suffix"
"#,
        "redact.active",
    )
    .expect("module");
    let object = provider.install(module);
    let mut call = Call::new(
        "why",
        vec![Arg::Value(Value::Path("gen.derived".into()))],
    );
    call.redact = true;
    println!("Q6 why -> {:?}", provider.invoke(object, &call));
}

#[test]
fn q7_patch_of_an_out_of_scope_node_is_impossible_but_whole_module_is_returned() {
    // Patch refuses a target outside the path scope (kernel), yet the answer is
    // the whole module: confirm the small reply still contains every sibling.
    let (agent, _object, cap, lane) = {
        let mut provider = ModuleProvider::new();
        let module = active_rpc::domain::module_from_source(
            r#"
[app]
name = "in-scope"
[ops]
host = "out-of-scope-canary"
"#,
            "probe.active",
        )
        .expect("module");
        let object = provider.install(module);
        let agent = Agent::with_secret([3u8; 32]);
        let provider_id = agent.register(Box::new(provider));
        let cap = agent
            .mint(
                provider_id,
                object,
                CapAttrs::new(&["patch", "dependents"]).with_path("app"),
            )
            .expect("mint");
        let lane = agent.create_lane("main", Budget::default()).expect("lane");
        (agent, object, cap, lane)
    };
    let outside = agent
        .call(
            lane,
            &cap,
            "patch",
            vec![
                Arg::Value(Value::Path("ops.host".into())),
                Arg::Value(Value::Text("x".into())),
            ],
        )
        .expect("queued")
        .value();
    println!("Q7 out-of-scope patch -> {outside:?}");
    assert!(outside.is_err(), "kernel refuses the target path");
}
