//! Throwaway R-07 probes.

use std::time::Instant;

use active_infinity::{InfinityModule, Inode, NodeId, SecretBytes};
use active_rpc::cap::CapAttrs;
use active_rpc::domain::ModuleProvider;
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, Budget};

const SRC: &str = r#"
[app]
name = "in-scope"

[ops]
host = "out-of-scope-canary"
token = secret("probe-secret-canary")
"#;

fn setup(methods: &[&str], attrs: impl FnOnce(CapAttrs) -> CapAttrs) -> (Agent, u64, active_rpc::CapHandle, active_rpc::LaneId) {
    let mut provider = ModuleProvider::new();
    let module = active_rpc::domain::module_from_source(SRC, "probe.active").expect("module");
    let object = provider.install(module);
    let agent = Agent::with_secret([7u8; 32]);
    let provider_id = agent.register(Box::new(provider));
    let cap = agent
        .mint(provider_id, object, attrs(CapAttrs::new(methods)))
        .expect("mint");
    let lane = agent.create_lane("main", Budget::default()).expect("lane");
    (agent, object, cap, lane)
}

#[test]
fn p1_pathless_evaluate_escapes_path_scope() {
    let (agent, _object, cap, lane) = setup(&["evaluate"], |attrs| attrs.with_path("app"));
    let result = agent
        .call(lane, &cap, "evaluate", vec![])
        .expect("call queues")
        .value();
    println!("P1 evaluate(no path) under scope=app -> {result:?}");
    assert!(
        result.is_ok(),
        "BUG: pathless evaluate should be refused under a path scope"
    );
    let map = result.unwrap();
    let text = format!("{map:?}");
    assert!(
        text.contains("out-of-scope-canary"),
        "expected the whole-module escape"
    );
}

#[test]
fn p2_pathless_evaluate_secret_marker_only() {
    // Same escape, but confirm secrets still collapse (no secret bytes leak).
    let (agent, _object, cap, lane) = setup(&["evaluate"], |attrs| attrs.with_path("app"));
    let value = agent
        .call(lane, &cap, "evaluate", vec![])
        .expect("call queues")
        .value()
        .expect("value");
    let text = format!("{value:?}");
    assert!(!text.contains("probe-secret-canary"), "secret bytes leaked");
    assert!(text.contains("Value::Secret"), "secret marker missing");
    println!("P2 secret collapses to marker: {text}");
}

#[test]
fn p3_patch_returns_the_whole_module_under_a_narrow_scope() {
    let (agent, _object, cap, lane) = setup(&["patch"], |attrs| attrs.with_path("app"));
    let value = agent
        .call(
            lane,
            &cap,
            "patch",
            vec![
                Arg::Value(Value::Path("app.name".into())),
                Arg::Value(Value::Text("patched".into())),
            ],
        )
        .expect("call queues")
        .value()
        .expect("patch");
    let bytes = match value {
        Value::Module(bytes) => bytes,
        other => panic!("expected module, got {other:?}"),
    };
    let haystack = String::from_utf8_lossy(&bytes);
    println!("P3 patch reply is {} bytes", bytes.len());
    assert!(
        haystack.contains("out-of-scope-canary"),
        "BUG: patch reply should not carry out-of-scope content"
    );
}

#[test]
fn p4_annotations_ignore_path_scope() {
    let mut module = active_rpc::domain::module_from_source(SRC, "probe.active").expect("module");
    let out_of_scope = active_rpc::domain::resolve_path(&module, "ops.host").expect("path");
    module.annotate(
        out_of_scope,
        active_infinity::AnnotationKind::Intent("outside-scope-intent".into()),
    );
    let mut provider = ModuleProvider::new();
    let object = provider.install(module);
    let agent = Agent::with_secret([8u8; 32]);
    let provider_id = agent.register(Box::new(provider));
    let cap = agent
        .mint(
            provider_id,
            object,
            CapAttrs::new(&["annotations"]).with_path("app"),
        )
        .expect("mint");
    let lane = agent.create_lane("main", Budget::default()).expect("lane");
    let value = agent
        .call(lane, &cap, "annotations", vec![])
        .expect("call queues")
        .value()
        .expect("annotations");
    println!("P4 annotations under scope=app -> {value:?}");
    assert!(
        format!("{value:?}").contains("outside-scope-intent"),
        "BUG: annotations from outside the path scope are served"
    );
}

#[test]
fn p5_stats_report_the_whole_module_under_a_narrow_scope() {
    let (agent, _object, cap, lane) = setup(&["stats"], |attrs| attrs.with_path("app"));
    let value = agent
        .call(lane, &cap, "stats", vec![])
        .expect("call queues")
        .value()
        .expect("stats");
    println!("P5 stats under scope=app -> {value:?}");
    match value {
        Value::Map(map) => {
            let nodes = match map.get("nodes") {
                Some(Value::Int(n)) => *n,
                other => panic!("nodes: {other:?}"),
            };
            assert!(nodes > 6, "BUG: whole-module node count under a 1-leaf scope ({nodes})");
        }
        other => panic!("{other:?}"),
    }
}

fn dangling_secret_module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let leaf = module.push(Inode::Str("a-value".into()));
    let root = module.push(Inode::Table {
        fields: vec![("a".to_string(), leaf)],
    });
    module.set_root(Some(root));
    // A secret locator that points outside the arena: a hand-built arena is
    // accepted by install() without validation.
    module.push(Inode::SecretRef {
        locator: NodeId(99),
    });
    module
}

#[test]
fn p6_panic_loses_the_module_permanently() {
    std::panic::set_hook(Box::new(|_| {}));
    let mut provider = ModuleProvider::new();
    let object = provider.install(dangling_secret_module());
    let mut call = Call::new("why", vec![Arg::Value(Value::Path("a".into()))]);
    call.redact = true;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        provider.invoke(object, &call)
    }));
    println!("P6 why(redact) outcome is_panic={}", outcome.is_err());
    assert!(outcome.is_err(), "expected the tainted_labels panic");
    let after = provider.invoke(object, &Call::new("stats", vec![]));
    println!("P6 stats after the panic -> {after:?}");
    let _ = std::panic::take_hook();
    assert!(
        after.is_err(),
        "BUG: the object survived a panicking call (then no loss)"
    );
}

#[test]
fn p7_why_ignores_the_capability_budget() {
    let n = 3000usize;
    let mut module = InfinityModule::new();
    let mut fields = Vec::new();
    for i in 0..n {
        let leaf = module.push(Inode::Str(format!("v{i}")));
        fields.push((format!("f{i}"), leaf));
    }
    let root = module.push(Inode::Table { fields });
    module.set_root(Some(root));
    module.bind("tree", root);
    let mut provider = ModuleProvider::new();
    let object = provider.install(module);
    let mut call = Call::new("why", vec![Arg::Value(Value::Path("tree".into()))]);
    call.budget = Budget {
        max_nodes: 1,
        max_wall_ms: 1,
        ..Budget::default()
    };
    let start = Instant::now();
    let response = provider.invoke(object, &call).expect("why");
    let elapsed = start.elapsed();
    let count = match response {
        Response::Labels(labels) => labels.len(),
        other => panic!("{other:?}"),
    };
    println!("P7 why on {n} nodes with max_nodes=1: {count} labels in {elapsed:?}");
    assert!(count > 1000);
    assert!(elapsed.as_millis() > 1, "expected to exceed the 1ms wall budget");
}

#[test]
fn p8_redacted_impact_is_superlinear() {
    for n in [1000usize, 2000, 4000] {
        let mut module = InfinityModule::new();
        for _ in 0..n {
            module.push(Inode::Null);
        }
        for i in 0..n - 1 {
            *module
                .node_mut(NodeId(i as u32))
                .expect("node")
                = Inode::Ref(NodeId(i as u32 + 1));
        }
        *module.node_mut(NodeId(n as u32 - 1)).expect("node") =
            Inode::Secret(SecretBytes::new("chain-secret"));
        module.set_root(Some(NodeId(0)));
        module.bind("chain", NodeId(0));

        let bytes = active_infinity::encode(&module).expect("encode");
        let valid = active_infinity::validate_canonical(&bytes, active_infinity::Limits::default());
        println!("P8 n={n} encodes to {} bytes, canonical={}", bytes.len(), valid.is_ok());

        let mut provider = ModuleProvider::new();
        let object = provider.install_canonical_image(&bytes).unwrap_or_else(|_| provider.install(module.clone()));
        let target = format!("chain"); // resolution via binding
        let mut plain = Call::new("impact", vec![Arg::Value(Value::Path(target.clone()))]);
        plain.redact = false;
        let t0 = Instant::now();
        let plain_out = provider.invoke(object, &plain).map(|r| match r {
            Response::Labels(l) => l.len(),
            _ => 0,
        });
        let plain_ms = t0.elapsed();

        let mut redacted = Call::new("impact", vec![Arg::Value(Value::Path(target))]);
        redacted.redact = true;
        let t1 = Instant::now();
        let redacted_out = provider.invoke(object, &redacted).map(|r| match r {
            Response::Labels(l) => l.len(),
            _ => 0,
        });
        let redacted_ms = t1.elapsed();
        println!(
            "P8 n={n} impact plain={plain_out:?} in {plain_ms:?}; redacted={redacted_out:?} in {redacted_ms:?}"
        );
    }
}

#[test]
fn p9_provenance_text_is_not_redacted() {
    let mut module = active_rpc::domain::module_from_source(SRC, "probe.active").expect("module");
    module.set_provenance(Some(active_infinity::Provenance {
        producer: Some("probe".into()),
        timestamp_ms: 0,
        model: None,
        tool: Some("curl -H 'Authorization: probe-secret-canary'".into()),
        parent: None,
        entries: Vec::new(),
    }));
    let lines = active_infinity::interop::provenance_lines(&module);
    println!("P9 library provenance_lines -> {lines:?}");
    let mut provider = ModuleProvider::new();
    let object = provider.install(module);
    let value = provider
        .invoke(object, &Call::new("provenance", vec![]))
        .expect("provenance");
    println!("P9 provider provenance -> {value:?}");
    assert!(
        format!("{value:?}").contains("probe-secret-canary"),
        "BUG: the provider leaks the secret text (expected for this probe)"
    );
    assert!(
        !format!("{lines:?}").contains("probe-secret-canary"),
        "the library redacts it; the provider must match"
    );
}

#[test]
fn p10_float_nan_patch() {
    let mut provider = ModuleProvider::new();
    let module = active_rpc::domain::module_from_source(SRC, "probe.active").expect("module");
    let object = provider.install(module);
    let call = Call::new(
        "patch",
        vec![
            Arg::Value(Value::Path("app.name".into())),
            Arg::Value(Value::Float(f64::NAN)),
        ],
    );
    let outcome = provider.invoke(object, &call);
    println!("P10 patch NaN -> {outcome:?}");
    let hash = provider.invoke(object, &Call::new("content_hash", vec![]));
    println!("P10 content_hash after NaN patch -> {hash:?}");
}
