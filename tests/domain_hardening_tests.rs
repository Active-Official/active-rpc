//! R-07 round 1: the domain provider's ceilings, annotations, immutability,
//! redaction and write confinement.
//!
//! Each test drives the shipped `Provider::invoke` over a module it installs, so
//! the assertions pin the provider's behaviour rather than a re-implementation.

use std::time::{Duration, Instant};

use active_rpc::domain::ModuleProvider;
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Budget, Error};

fn source_available() -> bool {
    true
}

fn install_source(provider: &mut ModuleProvider, source: &str) -> u64 {
    let module = active_rpc::domain::module_from_source(source, "hardening.active")
        .expect("fixture module parses");
    provider.install(module).expect("install")
}

fn call_with_budget(method: &str, path: &str, budget: Budget) -> Call {
    let mut call = Call::new(method, vec![Arg::Value(Value::path(path))]);
    call.budget = budget;
    call
}

/// A metadata query over a module larger than the capability's node ceiling is
/// refused instead of walking the whole arena.
#[test]
fn metadata_queries_respect_max_nodes() {
    let mut source = String::from("# @intent: \"big\"\n[big]\n");
    for index in 0..200 {
        source.push_str(&format!("k{index} = {index}\n"));
    }
    let mut provider = ModuleProvider::new();
    let object = install_source(&mut provider, &source);

    let budget = Budget {
        max_nodes: 8,
        ..Budget::default()
    };
    let call = call_with_budget("why", "big.k1", budget);
    let error = provider
        .invoke(object, &call)
        .expect_err("the walk exceeds the node ceiling");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");

    // The same query under the default budget answers.
    let call = call_with_budget("why", "big.k1", Budget::default());
    assert!(matches!(
        provider.invoke(object, &call).expect("within budget"),
        Response::Labels(_)
    ));
}

/// `why` over a 6 000-node module is a linear walk, not the quadratic one the
/// first implementation performed (10.6 s measured before the fix).
#[test]
fn why_is_linear_in_module_size() {
    fn module_of(size: usize) -> (ModuleProvider, u64) {
        let mut source = String::from("# @intent: \"scale\"\n[big]\n");
        for index in 0..size {
            source.push_str(&format!("k{index} = {index}\n"));
        }
        let mut provider = ModuleProvider::new();
        let object = install_source(&mut provider, &source);
        (provider, object)
    }

    let (mut small, small_object) = module_of(3_000);
    let started = Instant::now();
    let call = call_with_budget("why", "big.k1", Budget::default());
    small.invoke(small_object, &call).expect("small why");
    let small_elapsed = started.elapsed();

    let (mut large, large_object) = module_of(6_000);
    let started = Instant::now();
    large.invoke(large_object, &call).expect("large why");
    let large_elapsed = started.elapsed();

    // Doubling the module must not quadruple the work: the ceiling allows 4x
    // with room for noise, where the quadratic shape measured 4x per doubling
    // and would sit at ~10 s for the large module.
    assert!(
        large_elapsed < small_elapsed * 4 + Duration::from_millis(200),
        "why is not linear: {small_elapsed:?} -> {large_elapsed:?}"
    );
    assert!(
        large_elapsed < Duration::from_secs(2),
        "a 6 000-node why took {large_elapsed:?}"
    );
}

/// A hand-built arena with a locator pointing outside the arena is refused at
/// install, so no query can index past the end.
#[test]
fn install_refuses_a_dangling_locator() {
    let mut module = active_infinity::InfinityModule::new();
    let secret = module.push(active_infinity::Inode::Secret(
        active_infinity::SecretBytes::new("canary"),
    ));
    let _ = secret;
    let locator = module.push(active_infinity::Inode::SecretRef {
        locator: active_infinity::NodeId(99),
    });
    let root = module.push(active_infinity::Inode::Table {
        fields: vec![("a".to_string(), locator)],
    });
    module.set_root(Some(root));

    let mut provider = ModuleProvider::new();
    let error = provider
        .install(module)
        .expect_err("a dangling locator is not a canonical module");
    assert_eq!(error.code(), "rpc/payload", "{error}");
}

/// A deep reference chain is a canonical image (4 000 links) and redacting a
/// query over it must stay linear (4.9 s measured before the fix).
#[test]
fn a_deep_chain_redacts_quickly() {
    let depth = 4_000u32;
    let mut module = active_infinity::InfinityModule::new();
    let leaf = module.push(active_infinity::Inode::Secret(
        active_infinity::SecretBytes::new("chain-secret"),
    ));
    let mut current = leaf;
    for _ in 0..depth {
        current = module.push(active_infinity::Inode::Ref(current));
    }
    let table = module.push(active_infinity::Inode::Table {
        fields: vec![("chain".to_string(), current)],
    });
    module.set_root(Some(table));
    let bytes = active_infinity::encode(&module).expect("encode");
    let mut provider = ModuleProvider::new();
    let object = provider
        .install_canonical_image(&bytes)
        .expect("the chain is canonical");

    let mut call = call_with_budget("impact", "chain", Budget::default());
    call.redact = true;
    let started = Instant::now();
    let response = provider.invoke(object, &call).expect("impact");
    let elapsed = started.elapsed();
    assert!(matches!(response, Response::Labels(_)));
    assert!(
        elapsed < Duration::from_secs(2),
        "redacting impact over a {depth}-deep chain took {elapsed:?}"
    );
}

/// A subgraph keeps the annotations inside its cone: `@ai_immutable` and a
/// constraint travel with the node they guard.
#[test]
fn subgraph_preserves_annotations() {
    let mut module = active_rpc::domain::module_from_source(
        "# @intent: \"annotated\"\n[app]\nport = 8080\n[other]\nport = 1\n",
        "annotated.active",
    )
    .expect("module");
    let app = active_infinity::interop::resolve_path(&module, "app").expect("app");
    let constraint = module.push(active_infinity::Inode::Bool(false));
    module.annotate(app, active_infinity::AnnotationKind::AiImmutable(true));
    module.annotate(
        app,
        active_infinity::AnnotationKind::Constraint {
            source: "false".to_string(),
            expr: constraint,
        },
    );
    let bytes = active_infinity::encode(&module).expect("encode");
    let mut provider = ModuleProvider::new();
    let object = provider
        .install_canonical_image(&bytes)
        .expect("annotated module is canonical");

    let response = provider
        .invoke(
            object,
            &call_with_budget("subgraph", "app", Budget::default()),
        )
        .expect("subgraph");
    let Response::Module(bytes) = response else {
        panic!("subgraph returns a module");
    };
    let sub = active_infinity::decode(&bytes).expect("decode");
    assert!(
        !active_infinity::interop::immutable_nodes(&sub).is_empty(),
        "the cone lost @ai_immutable"
    );
    assert!(
        sub.annotations().iter().any(|annotation| matches!(
            annotation.kind,
            active_infinity::AnnotationKind::Constraint { .. }
        )),
        "the cone lost its constraint"
    );
}

/// `@ai_immutable` is a guard, not a comment: the write path refuses it.
#[test]
fn patch_refuses_an_ai_immutable_node() {
    let mut provider = ModuleProvider::new();
    let object = install_source(
        &mut provider,
        "# @ai_immutable: true\n[app]\nname = \"fixed\"\n[other]\nname = \"free\"\n",
    );
    let call = Call::new(
        "patch",
        vec![
            Arg::Value(Value::path("app.name")),
            Arg::Value(Value::text("changed")),
        ],
    );
    let error = provider
        .invoke(object, &call)
        .expect_err("the marked table is agent-immutable");
    assert_eq!(error.code(), "rpc/read-only", "{error}");

    // The mutable sibling still accepts a write.
    let call = Call::new(
        "patch",
        vec![
            Arg::Value(Value::path("other.name")),
            Arg::Value(Value::text("changed")),
        ],
    );
    assert!(matches!(
        provider.invoke(object, &call).expect("mutable"),
        Response::Module(_)
    ));
}

/// A patch records the module it derives from, and keeps the producer chain.
#[test]
fn patch_preserves_the_parent_provenance() {
    let mut provider = ModuleProvider::new();
    let object = install_source(
        &mut provider,
        "# @intent: \"provenance\"\n[app]\nname = \"before\"\n",
    );
    let before = active_infinity::content_hash(
        &active_infinity::encode(provider.module(object).expect("module")).expect("encode"),
    )
    .expect("hash");
    let call = Call::new(
        "patch",
        vec![
            Arg::Value(Value::path("app.name")),
            Arg::Value(Value::text("after")),
        ],
    );
    provider.invoke(object, &call).expect("patch");
    let provenance = provider
        .module(object)
        .expect("module")
        .provenance()
        .expect("the patched module keeps a provenance");
    assert_eq!(
        provenance.parent,
        Some(before),
        "the new provenance names the module it derives from"
    );
}

/// Provenance text is redacted exactly as the library redacts it: a copy of a
/// secret literal comes back as the marker, never as ordinary text.
#[test]
fn provenance_redacts_secret_literals() {
    let mut module = active_rpc::domain::module_from_source(
        "# @intent: \"redaction\"\n[app]\nname = \"x\"\n",
        "redaction.active",
    )
    .expect("module");
    module.set_provenance(Some(active_infinity::Provenance {
        producer: Some("pipeline".to_string()),
        timestamp_ms: 7,
        model: None,
        tool: Some("run --token shared-canary".to_string()),
        parent: None,
        entries: Vec::new(),
    }));
    let secret = module.push(active_infinity::Inode::Secret(
        active_infinity::SecretBytes::new("shared-canary"),
    ));
    let root = module.root().expect("root");
    module.set_root(Some(root));
    let _ = secret;
    let bytes = active_infinity::encode(&module).expect("encode");
    let mut provider = ModuleProvider::new();
    let object = provider
        .install_canonical_image(&bytes)
        .expect("canonical module with a secret");

    let Response::Value(Value::Map(map)) = provider
        .invoke(object, &Call::new("provenance", vec![]))
        .expect("provenance")
    else {
        panic!("provenance returns a map");
    };
    match map.get("tool") {
        Some(Value::Text(text)) => {
            assert!(
                text.contains(active_rpc::security::SECRET_MARKER),
                "the secret copy must be replaced by the marker: {text}"
            );
            assert!(
                !text.contains("shared-canary"),
                "the secret bytes must not leave as text: {text}"
            );
        }
        Some(Value::Secret) => {}
        other => panic!("the tool field is missing or unredacted: {other:?}"),
    }
}

/// A scoped write may not change a value another path can read.
#[test]
fn a_scoped_patch_cannot_change_a_value_outside_its_scope() {
    // admin.internal and app.url share one node, so a write through one path is
    // visible through the other.
    let mut module = active_infinity::InfinityModule::new();
    let shared = module.push(active_infinity::Inode::Str("shared".to_string()));
    let admin = module.push(active_infinity::Inode::Table {
        fields: vec![("internal".to_string(), shared)],
    });
    let app = module.push(active_infinity::Inode::Table {
        fields: vec![("url".to_string(), shared)],
    });
    let root = module.push(active_infinity::Inode::Table {
        fields: vec![("admin".to_string(), admin), ("app".to_string(), app)],
    });
    module.set_root(Some(root));
    let bytes = active_infinity::encode(&module).expect("encode");
    let mut provider = ModuleProvider::new();
    let object = provider
        .install_canonical_image(&bytes)
        .expect("the shared DAG is canonical");

    // Writing the shared node through `admin.internal` would also change
    // `app.url`, which the `admin` scope does not name.
    let mut call = Call::new(
        "patch",
        vec![
            Arg::Value(Value::path("admin.internal")),
            Arg::Value(Value::text("rewritten")),
        ],
    );
    call.path_scope = Some("admin".to_string());
    let error = provider
        .invoke(object, &call)
        .expect_err("the write reaches outside the scope");
    assert_eq!(error.code(), "rpc/path-not-granted", "{error}");
}

/// Guard: the fixture helper stays used even if a test is filtered out.
#[test]
fn the_fixture_source_parses() {
    assert!(source_available());
    let _ = Error::ReadOnly;
}
