//! R-07 round 2: a scoped capability is confined to its subtree in every
//! direction — dependencies, dependents, metadata, hashes and shared nodes.
//!
//! The module is built directly so the DAG is exactly the hostile shape: a
//! reference into another subtree and one node shared by two names.

use active_infinity::{AnnotationKind, InfinityModule, Inode};
use active_rpc::cap::CapAttrs;
use active_rpc::domain::ModuleProvider;
use active_rpc::value::{Arg, Value};
use active_rpc::{Agent, Budget, CapHandle, LaneId};

const OUTSIDE: &str = "OUTSIDE-CANARY";

/// `app.x` is a reference into `ops`, and `app.y` and `admin.internal` are the
/// same node, so both the read side and the write side have an outside edge.
fn hostile_module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let canary = module.push(Inode::Str(OUTSIDE.to_string()));
    let shared = module.push(Inode::Str("in".to_string()));
    let reference = module.push(Inode::Ref(canary));
    let app = module.push(Inode::Table {
        fields: vec![("x".to_string(), reference), ("y".to_string(), shared)],
    });
    let ops = module.push(Inode::Table {
        fields: vec![("secret".to_string(), canary)],
    });
    let admin = module.push(Inode::Table {
        fields: vec![("internal".to_string(), shared)],
    });
    let root = module.push(Inode::Table {
        fields: vec![
            ("admin".to_string(), admin),
            ("app".to_string(), app),
            ("ops".to_string(), ops),
        ],
    });
    module.set_root(Some(root));
    module
}

struct Fixture {
    agent: Agent,
}

fn fixture(methods: &[&str], scope: Option<&str>) -> (Fixture, CapHandle, LaneId) {
    let agent = Agent::with_secret([0x77; 32]);
    let mut provider = ModuleProvider::new();
    let object = provider.install(hostile_module()).expect("install");
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(methods);
    attrs.path_scope = scope.map(str::to_string);
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent.create_lane("scope", Budget::default()).expect("lane");
    (Fixture { agent }, cap, lane)
}

fn call(
    fixture: &Fixture,
    lane: LaneId,
    cap: &CapHandle,
    method: &str,
    args: Vec<Arg>,
) -> active_rpc::Result<Value> {
    let promise = fixture.agent.call(lane, cap, method, args)?;
    fixture.agent.run();
    promise.value()
}

fn path(value: &str) -> Arg {
    Arg::Value(Value::path(value))
}

/// `evaluate` follows a reference; a scoped capability may not read through it.
#[test]
fn a_scoped_evaluate_cannot_follow_a_reference_outside_the_scope() {
    let (fixture, cap, lane) = fixture(&["evaluate"], Some("app"));
    let error = call(&fixture, lane, &cap, "evaluate", vec![path("app.x")])
        .expect_err("app.x references ops.secret");
    assert_eq!(error.code(), "rpc/path-not-granted", "{error}");

    // The in-scope value without a reference still answers.
    let value = call(&fixture, lane, &cap, "evaluate", vec![path("app.y")]).expect("in scope");
    assert_eq!(value, Value::text("in"));
}

/// `why` labels a node's dependencies; an out-of-scope dependency would leak it.
#[test]
fn a_scoped_why_cannot_name_an_outside_dependency() {
    let (fixture, cap, lane) = fixture(&["why"], Some("app"));
    let error = call(&fixture, lane, &cap, "why", vec![path("app.x")])
        .expect_err("the label set names ops.secret");
    assert_eq!(error.code(), "rpc/path-not-granted", "{error}");
}

/// `impact` walks dependents; a shared leaf has dependents outside the scope.
#[test]
fn a_scoped_impact_cannot_name_an_outside_dependent() {
    let (fixture, cap, lane) = fixture(&["impact"], Some("admin"));
    let error = call(&fixture, lane, &cap, "impact", vec![path("admin.internal")])
        .expect_err("the dependent set names app");
    assert_eq!(error.code(), "rpc/path-not-granted", "{error}");
}

/// The whole-module queries are global answers: a scope refuses them.
#[test]
fn a_scoped_capability_cannot_read_global_metadata() {
    let (fixture, cap, lane) = fixture(
        &[
            "stats",
            "annotations",
            "provenance",
            "content_hash",
            "subgraph",
        ],
        Some("app"),
    );
    for method in ["stats", "annotations", "provenance", "content_hash"] {
        for args in [vec![path("app")], Vec::new()] {
            let result = call(&fixture, lane, &cap, method, args);
            assert_eq!(
                result.as_ref().err().map(active_rpc::Error::code),
                Some("rpc/path-not-granted"),
                "{method}: {result:?}"
            );
        }
    }
    // A subgraph of `app` would carry the referenced `ops.secret`, so it is
    // refused; a leaf with no outside edge answers.
    let subgraph = call(&fixture, lane, &cap, "subgraph", vec![path("app")]);
    assert_eq!(
        subgraph.as_ref().err().map(active_rpc::Error::code),
        Some("rpc/path-not-granted"),
        "{subgraph:?}"
    );
    let leaf = call(&fixture, lane, &cap, "subgraph", vec![path("app.y")]);
    assert!(leaf.is_ok(), "{leaf:?}");
}

/// `subgraph` and `content_hash` are metadata work like `why`: they honour the
/// node ceiling.
#[test]
fn subgraph_and_content_hash_respect_the_node_budget() {
    let agent = Agent::with_secret([0x79; 32]);
    let mut provider = ModuleProvider::new();
    let object = provider.install(hostile_module()).expect("install");
    let id = agent.register(Box::new(provider));
    let mut tight_attrs = CapAttrs::new(&["subgraph", "content_hash"]);
    tight_attrs.budget = Budget {
        max_nodes: 1,
        ..Budget::default()
    };
    let tight = agent.mint(id, object, tight_attrs).expect("tight cap");
    let lane = agent.create_lane("tight", Budget::default()).expect("lane");
    let fixture = Fixture { agent };

    for method in ["subgraph", "content_hash"] {
        let result = call(&fixture, lane, &tight, method, vec![path("app")]);
        assert_eq!(
            result.as_ref().err().map(active_rpc::Error::code),
            Some("rpc/budget-exceeded"),
            "{method}: {result:?}"
        );
    }
}

/// A shared node under an immutable subtree cannot be rewritten through an alias.
#[test]
fn an_alias_cannot_bypass_ai_immutable() {
    let mut module = InfinityModule::new();
    let value = module.push(Inode::Str("original".to_string()));
    let protected = module.push(Inode::Table {
        fields: vec![("value".to_string(), value)],
    });
    let other = module.push(Inode::Table {
        fields: vec![("alias".to_string(), value)],
    });
    let root = module.push(Inode::Table {
        fields: vec![
            ("other".to_string(), other),
            ("protected".to_string(), protected),
        ],
    });
    module.set_root(Some(root));
    module.annotate(protected, AnnotationKind::AiImmutable(true));

    let agent = Agent::with_secret([0x78; 32]);
    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let id = agent.register(Box::new(provider));
    let cap = agent
        .mint(id, object, CapAttrs::new(&["patch", "evaluate"]))
        .expect("cap");
    let lane = agent
        .create_lane("immutable", Budget::default())
        .expect("lane");

    // The refusal is decided at dispatch, so it surfaces on the promise.
    let promise = agent
        .call(
            lane,
            &cap,
            "patch",
            vec![path("other.alias"), Arg::Value(Value::text("hacked"))],
        )
        .expect("queued");
    agent.run();
    let error = promise
        .value()
        .expect_err("the shared node is under an immutable subtree");
    assert_eq!(error.code(), "rpc/read-only", "{error}");

    let promise = agent
        .call(lane, &cap, "evaluate", vec![path("protected.value")])
        .expect("call");
    agent.run();
    assert_eq!(promise.value().expect("value"), Value::text("original"));
}

/// A constraint expression is stored text the cone carries: a scoped answer must
/// not include one from outside the scope.
#[test]
fn a_scoped_answer_cannot_reach_a_constraint_expression_outside_the_scope() {
    let mut module = InfinityModule::new();
    let canary = module.push(Inode::Str(OUTSIDE.to_string()));
    let inside = module.push(Inode::Str("in".to_string()));
    let app = module.push(Inode::Table {
        fields: vec![("y".to_string(), inside)],
    });
    let ops = module.push(Inode::Table {
        fields: vec![("secret".to_string(), canary)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("app".to_string(), app), ("ops".to_string(), ops)],
    });
    module.set_root(Some(root));
    // The app subtree is watched by a rule whose expression lives in ops.
    module.annotate(
        app,
        AnnotationKind::Constraint {
            source: "ops-bound".to_string(),
            expr: canary,
        },
    );

    let agent = Agent::with_secret([0x7a; 32]);
    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(&["evaluate", "subgraph"]);
    attrs.path_scope = Some("app".to_string());
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent.create_lane("expr", Budget::default()).expect("lane");
    let fixture = Fixture { agent };

    for method in ["evaluate", "subgraph"] {
        let result = call(&fixture, lane, &cap, method, vec![path("app")]);
        assert_eq!(
            result.as_ref().err().map(active_rpc::Error::code),
            Some("rpc/path-not-granted"),
            "{method}: {result:?}"
        );
    }
}

/// `Env` resolves against the process environment, which a scope never granted.
#[test]
fn a_scoped_evaluate_refuses_a_host_environment_read() {
    let mut module = InfinityModule::new();
    let env = module.push(Inode::Env {
        name: "PATH".to_string(),
        default: None,
    });
    let app = module.push(Inode::Table {
        fields: vec![("k".to_string(), env)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("app".to_string(), app)],
    });
    module.set_root(Some(root));

    let agent = Agent::with_secret([0x7b; 32]);
    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(&["evaluate"]);
    attrs.path_scope = Some("app".to_string());
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent.create_lane("env", Budget::default()).expect("lane");
    let fixture = Fixture { agent };

    let result = call(&fixture, lane, &cap, "evaluate", vec![path("app.k")]);
    assert_eq!(
        result.as_ref().err().map(active_rpc::Error::code),
        Some("rpc/path-not-granted"),
        "{result:?}"
    );
}

/// Replacing an ancestor deletes its subtree, so a marked descendant protects
/// the ancestor from a patch.
#[test]
fn an_ancestor_patch_cannot_delete_an_immutable_subtree() {
    let mut module = InfinityModule::new();
    let value = module.push(Inode::Str("original".to_string()));
    let protected = module.push(Inode::Table {
        fields: vec![("value".to_string(), value)],
    });
    let outer = module.push(Inode::Table {
        fields: vec![("protected".to_string(), protected)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("outer".to_string(), outer)],
    });
    module.set_root(Some(root));
    module.annotate(protected, AnnotationKind::AiImmutable(true));

    let agent = Agent::with_secret([0x7c; 32]);
    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let id = agent.register(Box::new(provider));
    let cap = agent
        .mint(id, object, CapAttrs::new(&["patch", "evaluate"]))
        .expect("cap");
    let lane = agent
        .create_lane("ancestor", Budget::default())
        .expect("lane");

    let promise = agent
        .call(
            lane,
            &cap,
            "patch",
            vec![path("outer"), Arg::Value(Value::text("pwned"))],
        )
        .expect("queued");
    agent.run();
    let error = promise
        .value()
        .expect_err("the patch would delete the marked subtree");
    assert_eq!(error.code(), "rpc/read-only", "{error}");

    let promise = agent
        .call(lane, &cap, "evaluate", vec![path("outer.protected.value")])
        .expect("call");
    agent.run();
    assert_eq!(promise.value().expect("value"), Value::text("original"));
}

/// A scoped cone reply is the subtree's data: the module's provenance (producer,
/// parent hash) is not part of it.
#[test]
fn a_scoped_subgraph_carries_no_provenance() {
    let mut module = hostile_module();
    module.set_provenance(Some(active_infinity::Provenance {
        producer: Some("OUTSIDE-PRODUCER".to_string()),
        timestamp_ms: 1,
        model: None,
        tool: None,
        parent: None,
        entries: Vec::new(),
    }));

    let agent = Agent::with_secret([0x7d; 32]);
    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(&["subgraph"]);
    attrs.path_scope = Some("app".to_string());
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent.create_lane("cone", Budget::default()).expect("lane");

    let promise = agent
        .call(lane, &cap, "subgraph", vec![path("app.y")])
        .expect("queued");
    agent.run();
    let bytes = match promise.value().expect("subgraph") {
        Value::Module(bytes) => bytes,
        other => panic!("expected module bytes, got {other:?}"),
    };
    let decoded = active_infinity::decode(&bytes).expect("decode");
    assert!(
        decoded.provenance().is_none(),
        "the cone carried provenance"
    );
    let rendered = String::from_utf8_lossy(&bytes).into_owned();
    assert!(!rendered.contains("OUTSIDE-PRODUCER"), "{rendered}");
}

/// `evaluate` is evaluator work like the queries: it honours the node ceiling.
#[test]
fn evaluate_respects_the_node_budget() {
    let agent = Agent::with_secret([0x7e; 32]);
    let mut provider = ModuleProvider::new();
    let object = provider.install(hostile_module()).expect("install");
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(&["evaluate"]);
    attrs.budget = Budget {
        max_nodes: 1,
        ..Budget::default()
    };
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent.create_lane("nodes", Budget::default()).expect("lane");
    let fixture = Fixture { agent };

    let result = call(&fixture, lane, &cap, "evaluate", vec![path("app.y")]);
    assert_eq!(
        result.as_ref().err().map(active_rpc::Error::code),
        Some("rpc/budget-exceeded"),
        "{result:?}"
    );
}

/// A floating value (no path) still travels in the cone: a scope refuses a
/// closure that contains one.
#[test]
fn a_scoped_answer_cannot_reach_a_pathless_expression() {
    let mut module = InfinityModule::new();
    let floating = module.push(Inode::Str(OUTSIDE.to_string()));
    let inside = module.push(Inode::Str("in".to_string()));
    let app = module.push(Inode::Table {
        fields: vec![("y".to_string(), inside)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("app".to_string(), app)],
    });
    module.set_root(Some(root));
    module.annotate(
        app,
        AnnotationKind::Constraint {
            source: "floating".to_string(),
            expr: floating,
        },
    );

    let agent = Agent::with_secret([0x81; 32]);
    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(&["evaluate", "subgraph"]);
    attrs.path_scope = Some("app".to_string());
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent
        .create_lane("floating", Budget::default())
        .expect("lane");
    let fixture = Fixture { agent };

    for method in ["evaluate", "subgraph"] {
        let result = call(&fixture, lane, &cap, method, vec![path("app")]);
        assert_eq!(
            result.as_ref().err().map(active_rpc::Error::code),
            Some("rpc/path-not-granted"),
            "{method}: {result:?}"
        );
    }
}

/// A constraint chain of ten annotations still has to be followed to its end.
#[test]
fn a_deep_constraint_chain_is_followed() {
    let mut module = InfinityModule::new();
    let outside = module.push(Inode::Str(OUTSIDE.to_string()));
    let inside = module.push(Inode::Str("in".to_string()));
    let app = module.push(Inode::Table {
        fields: vec![("y".to_string(), inside)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("app".to_string(), app)],
    });
    module.set_root(Some(root));
    // app -> E1 -> E2 -> ... -> outside, ten links deep.
    let mut chain = Vec::new();
    for _ in 0..10 {
        chain.push(module.push(Inode::Str("link".to_string())));
    }
    module.annotate(
        app,
        AnnotationKind::Constraint {
            source: "e1".to_string(),
            expr: chain[0],
        },
    );
    for index in 0..9 {
        module.annotate(
            chain[index],
            AnnotationKind::Constraint {
                source: "next".to_string(),
                expr: chain[index + 1],
            },
        );
    }
    module.annotate(
        chain[9],
        AnnotationKind::Constraint {
            source: "tail".to_string(),
            expr: outside,
        },
    );

    let agent = Agent::with_secret([0x82; 32]);
    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(&["subgraph"]);
    attrs.path_scope = Some("app".to_string());
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent.create_lane("chain", Budget::default()).expect("lane");
    let fixture = Fixture { agent };

    let result = call(&fixture, lane, &cap, "subgraph", vec![path("app")]);
    assert_eq!(
        result.as_ref().err().map(active_rpc::Error::code),
        Some("rpc/path-not-granted"),
        "{result:?}"
    );
}

/// A scoped cone reply carries values only: annotation text (an intent or a
/// constraint source can name outside paths) is not part of it.
#[test]
fn a_scoped_cone_reply_carries_no_annotation_text() {
    let mut module = hostile_module();
    let app = active_infinity::interop::resolve_path(&module, "app").expect("app");
    module.annotate(
        app,
        AnnotationKind::Constraint {
            source: "OUTSIDE-SOURCE-MARKER".to_string(),
            expr: app,
        },
    );

    let agent = Agent::with_secret([0x83; 32]);
    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(&["subgraph"]);
    attrs.path_scope = Some("app".to_string());
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent.create_lane("text", Budget::default()).expect("lane");

    let promise = agent
        .call(lane, &cap, "subgraph", vec![path("app.y")])
        .expect("queued");
    agent.run();
    let bytes = match promise.value().expect("subgraph") {
        Value::Module(bytes) => bytes,
        other => panic!("expected module bytes, got {other:?}"),
    };
    let rendered = String::from_utf8_lossy(&bytes).into_owned();
    assert!(!rendered.contains("OUTSIDE-SOURCE-MARKER"), "{rendered}");
    let decoded = active_infinity::decode(&bytes).expect("decode");
    assert!(
        decoded.annotations().is_empty(),
        "the cone carried annotations"
    );
}

/// Under a scope, labels never name a node by its index: a `Kind[index]` label
/// is a node-id oracle over the hidden module.
#[test]
fn scoped_labels_never_name_a_node_index() {
    let (fixture, cap, lane) = fixture(&["why", "impact", "dependents"], Some("app"));
    for method in ["why", "impact", "dependents"] {
        let result = call(&fixture, lane, &cap, method, vec![path("app.y")]);
        if let Ok(Value::List(labels)) = result {
            for label in &labels {
                if let Value::Text(text) = label {
                    assert!(!text.contains('['), "{method} leaked a node id: {text}");
                }
            }
        }
    }
}

/// A scoped patch reply is a cone: it carries no provenance (producer or parent
/// content address) of the whole module.
#[test]
fn a_scoped_patch_reply_carries_no_provenance() {
    // No sharing here: `app.y` has no dependent outside the scope, so the write
    // itself is allowed and the reply is what this test inspects.
    let mut module = InfinityModule::new();
    let inside = module.push(Inode::Str("in".to_string()));
    let app = module.push(Inode::Table {
        fields: vec![("y".to_string(), inside)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("app".to_string(), app)],
    });
    module.set_root(Some(root));
    module.set_provenance(Some(active_infinity::Provenance {
        producer: Some("OUTSIDE-PRODUCER".to_string()),
        timestamp_ms: 1,
        model: None,
        tool: None,
        parent: Some([0x11; 32]),
        entries: Vec::new(),
    }));

    let agent = Agent::with_secret([0x84; 32]);
    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(&["patch"]);
    attrs.path_scope = Some("app".to_string());
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent
        .create_lane("patchcone", Budget::default())
        .expect("lane");

    let promise = agent
        .call(
            lane,
            &cap,
            "patch",
            vec![path("app.y"), Arg::Value(Value::text("changed"))],
        )
        .expect("queued");
    agent.run();
    let bytes = match promise.value().expect("patch") {
        Value::Module(bytes) => bytes,
        other => panic!("expected module bytes, got {other:?}"),
    };
    let decoded = active_infinity::decode(&bytes).expect("decode");
    assert!(
        decoded.provenance().is_none(),
        "the scoped patch reply carried provenance"
    );
}
