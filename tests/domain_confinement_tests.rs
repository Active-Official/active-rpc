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

/// A binding is a second name for a node. `value_paths` reports that name, so an
/// outside node bound under an in-scope-looking name would pass the scope check
/// unless the name is required to resolve back to the node.
#[test]
fn a_binding_cannot_launder_an_outside_node_into_the_scope() {
    let mut module = InfinityModule::new();
    let outside = module.push(Inode::Str(OUTSIDE.to_string()));
    let app = module.push(Inode::Table {
        fields: vec![("y".to_string(), outside)],
    });
    let other = module.push(Inode::Str("other".to_string()));
    let ops = module.push(Inode::Table {
        fields: vec![("secret".to_string(), other)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("app".to_string(), app), ("ops".to_string(), ops)],
    });
    module.set_root(Some(root));
    // The value inside `app.y` is also reachable as an in-scope-looking binding.
    module.bind("app.sneaky", outside);

    let agent = Agent::with_secret([0x85; 32]);
    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(&["evaluate", "why", "subgraph"]);
    attrs.path_scope = Some("app".to_string());
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent
        .create_lane("binding", Budget::default())
        .expect("lane");
    let fixture = Fixture { agent };

    // The bound name does not resolve back to its node, so the closure is out of
    // scope and every read is refused.
    for method in ["evaluate", "why", "subgraph"] {
        let result = call(&fixture, lane, &cap, method, vec![path("app.y")]);
        assert_eq!(
            result.as_ref().err().map(active_rpc::Error::code),
            Some("rpc/path-not-granted"),
            "{method}: {result:?}"
        );
    }
}

/// `impact` answers the dependent closure, so a dependent outside the scope must
/// refuse even when every dependency is inside it (a Ref alias is the usual way
/// this arises).
#[test]
fn a_scoped_impact_cannot_answer_through_a_reference_alias() {
    let mut module = InfinityModule::new();
    let inside = module.push(Inode::Str("in".to_string()));
    let app = module.push(Inode::Table {
        fields: vec![("y".to_string(), inside)],
    });
    // `ops.r` references the in-scope value, so its dependent set reaches into
    // the scope while the alias itself is outside.
    let alias = module.push(Inode::Ref(inside));
    let ops = module.push(Inode::Table {
        fields: vec![("r".to_string(), alias)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("app".to_string(), app), ("ops".to_string(), ops)],
    });
    module.set_root(Some(root));

    let agent = Agent::with_secret([0x86; 32]);
    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(&["impact"]);
    attrs.path_scope = Some("app".to_string());
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent.create_lane("alias", Budget::default()).expect("lane");
    let fixture = Fixture { agent };

    let result = call(&fixture, lane, &cap, "impact", vec![path("app.y")]);
    assert_eq!(
        result.as_ref().err().map(active_rpc::Error::code),
        Some("rpc/path-not-granted"),
        "{result:?}"
    );
}

/// A scoped cone keeps `@ai_immutable`: the guard travels with the subtree so the
/// recipient cannot rewrite what the marker protects.
#[test]
fn a_scoped_cone_keeps_the_immutability_guard() {
    let mut module = InfinityModule::new();
    let value = module.push(Inode::Str("original".to_string()));
    let inner = module.push(Inode::Table {
        fields: vec![("value".to_string(), value)],
    });
    let app = module.push(Inode::Table {
        fields: vec![("inner".to_string(), inner)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("app".to_string(), app)],
    });
    module.set_root(Some(root));
    module.annotate(inner, AnnotationKind::AiImmutable(true));

    let agent = Agent::with_secret([0x87; 32]);
    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(&["subgraph"]);
    attrs.path_scope = Some("app".to_string());
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent.create_lane("guard", Budget::default()).expect("lane");

    let promise = agent
        .call(lane, &cap, "subgraph", vec![path("app")])
        .expect("queued");
    agent.run();
    let bytes = match promise.value().expect("subgraph") {
        Value::Module(bytes) => bytes,
        other => panic!("expected module bytes, got {other:?}"),
    };
    let decoded = active_infinity::decode(&bytes).expect("decode");
    assert_eq!(
        decoded.annotations().len(),
        1,
        "the cone dropped the @ai_immutable guard"
    );
    assert!(matches!(
        decoded.annotations()[0].kind,
        AnnotationKind::AiImmutable(true)
    ));
}

/// The constraint tail is a fixpoint, not one pass: with the annotations
/// recorded in reverse order, a single scan missed the links after the first
/// and let a scoped write through that the forward order refused.
#[test]
fn a_reverse_order_constraint_chain_is_followed_to_its_end() {
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
    let mut chain = Vec::new();
    for _ in 0..10 {
        chain.push(module.push(Inode::Str("link".to_string())));
    }
    // Record the chain from the tail backwards: the annotation that connects
    // `app` is seen last, after the links it reaches were already scanned.
    module.annotate(
        chain[9],
        AnnotationKind::Constraint {
            source: "tail".to_string(),
            expr: outside,
        },
    );
    for index in (0..9).rev() {
        module.annotate(
            chain[index],
            AnnotationKind::Constraint {
                source: "next".to_string(),
                expr: chain[index + 1],
            },
        );
    }
    module.annotate(
        app,
        AnnotationKind::Constraint {
            source: "e1".to_string(),
            expr: chain[0],
        },
    );

    let agent = Agent::with_secret([0x83; 32]);
    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(&["subgraph", "patch"]);
    attrs.path_scope = Some("app".to_string());
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent
        .create_lane("reverse", Budget::default())
        .expect("lane");
    let fixture = Fixture { agent };

    // A read of the cone refuses (the chain reaches outside) ...
    let result = call(&fixture, lane, &cap, "subgraph", vec![path("app")]);
    assert_eq!(
        result.as_ref().err().map(active_rpc::Error::code),
        Some("rpc/path-not-granted"),
        "{result:?}"
    );
    // ... and so does a write, whatever order the annotations were recorded in.
    let result = call(
        &fixture,
        lane,
        &cap,
        "patch",
        vec![path("app.y"), Arg::text("changed")],
    );
    assert_eq!(
        result.as_ref().err().map(active_rpc::Error::code),
        Some("rpc/path-not-granted"),
        "{result:?}"
    );
}

/// A redacting caller never receives a content address: the parent hash in the
/// provenance compares equal to the full image's hash, which is an equality
/// oracle over secret material.
#[test]
fn a_redacting_patch_cone_carries_no_provenance() {
    let mut module = hostile_module();
    module.set_provenance(Some(active_infinity::Provenance {
        producer: Some("test".to_string()),
        timestamp_ms: 1,
        model: None,
        tool: None,
        parent: Some([0x44; 32]),
        entries: Vec::new(),
    }));

    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let mut call = active_rpc::value::Call::new("patch", vec![path("app.y"), Arg::text("changed")]);
    call.redact = true;
    let response =
        active_rpc::kernel::Provider::invoke(&mut provider, object, &call).expect("patch reply");
    let active_rpc::value::Response::Module(bytes) = response else {
        panic!("a patch answers a module: {response:?}");
    };
    let decoded = active_infinity::decode(&bytes).expect("decode");
    assert_eq!(
        decoded.provenance().and_then(|prov| prov.parent),
        None,
        "the cone carries the parent hash a redacting caller may not see"
    );
}

/// A node that names one child twice used to stall the Kahn pass, so the taint
/// never reached the node above it and a redacting query returned its intent in
/// clear.
#[test]
fn a_doubly_referenced_secret_taints_everything_above_it() {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(active_infinity::SecretBytes::new(b"canary")));
    let middle = module.push(Inode::Table {
        fields: vec![("a".to_string(), secret), ("b".to_string(), secret)],
    });
    let top = module.push(Inode::Table {
        fields: vec![("m".to_string(), middle)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("top".to_string(), top)],
    });
    module.set_root(Some(root));
    module.annotate(middle, AnnotationKind::Intent("CANARY-MIDDLE".to_string()));
    module.annotate(top, AnnotationKind::Intent("CANARY-TOP".to_string()));

    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let mut call = active_rpc::value::Call::new("annotations", Vec::new());
    call.redact = true;
    let response =
        active_rpc::kernel::Provider::invoke(&mut provider, object, &call).expect("annotations");
    let active_rpc::value::Response::Value(Value::List(entries)) = response else {
        panic!("annotations answers a list: {response:?}");
    };
    for entry in &entries {
        if let Value::Map(fields) = entry {
            if let Some(Value::Text(text)) = fields.get("text") {
                assert!(
                    !text.contains("CANARY"),
                    "a redacting answer carried an intent above a doubly-referenced secret: {text}"
                );
            }
        }
    }
}

/// A patch carries the previous content address in its `Input` entry, so a
/// redacting provenance answer used to serve the same oracle as `parent`.
#[test]
fn a_redacting_provenance_answer_serves_no_hash() {
    let mut module = hostile_module();
    module.set_provenance(Some(active_infinity::Provenance {
        producer: Some("test".to_string()),
        timestamp_ms: 1,
        model: None,
        tool: None,
        parent: Some([0x44; 32]),
        entries: vec![active_infinity::ProvEntry {
            key: "input".to_string(),
            value: active_infinity::ProvValue::Hash([0xAB; 32]),
        }],
    }));

    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let mut call = active_rpc::value::Call::new("provenance", Vec::new());
    call.redact = true;
    let response =
        active_rpc::kernel::Provider::invoke(&mut provider, object, &call).expect("provenance");
    let active_rpc::value::Response::Value(Value::Map(fields)) = response else {
        panic!("provenance answers a map: {response:?}");
    };
    for (key, value) in &fields {
        if let Value::Text(text) = value {
            assert!(
                !text.starts_with("blake3:"),
                "a redacting answer served the content address {key}={text}"
            );
        }
    }
    assert!(!fields.contains_key("parent"));
}

/// The cone bytes and the metadata query must agree: a redacting cone carries
/// neither the intent text nor a binding that names a tainted node.
#[test]
fn a_redacting_cone_carries_no_annotation_text() {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(active_infinity::SecretBytes::new(b"canary")));
    let holder = module.push(Inode::Table {
        fields: vec![("s".to_string(), secret)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("holder".to_string(), holder)],
    });
    module.set_root(Some(root));
    module.annotate(holder, AnnotationKind::Intent("CANARY-LABEL".to_string()));
    module.bind("named", holder);

    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let mut call = active_rpc::value::Call::new("subgraph", vec![path("holder")]);
    call.redact = true;
    let response =
        active_rpc::kernel::Provider::invoke(&mut provider, object, &call).expect("subgraph");
    let active_rpc::value::Response::Module(bytes) = response else {
        panic!("subgraph answers a module: {response:?}");
    };
    let decoded = active_infinity::decode(&bytes).expect("decode");
    assert!(
        decoded.annotations().is_empty(),
        "the cone carries annotation text a redacting caller may not see"
    );
    assert!(
        decoded.bindings().is_empty(),
        "the cone carries a binding that names a tainted node"
    );
}

// ---------------------------------------------------------------------------
// R-07 round 9
// ---------------------------------------------------------------------------

const PROBE_SECRET: &str = "probe-canary-9f3a";

/// A module where the secret is copied as ordinary data and where an outside
/// subtree's rule watches an in-scope value.
fn copying_module() -> InfinityModule {
    use active_infinity::{Constraint, Provenance};
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(PROBE_SECRET.into()));
    let copy = module.push(Inode::Str(PROBE_SECRET.to_string()));
    let in_scope = module.push(Inode::Str("in".to_string()));
    let outside = module.push(Inode::Str("outside".to_string()));
    let app = module.push(Inode::Table {
        fields: vec![("copy".to_string(), copy), ("y".to_string(), in_scope)],
    });
    let ops = module.push(Inode::Table {
        fields: vec![("rule".to_string(), outside)],
    });
    let root = module.push(Inode::Table {
        fields: vec![
            ("app".to_string(), app),
            ("ops".to_string(), ops),
            ("secret".to_string(), secret),
        ],
    });
    module.set_root(Some(root));
    // The rule on `ops` is validated by the in-scope value: rewriting `app.y`
    // changes the rule that watches data the scope does not name.
    module.annotate(
        ops,
        AnnotationKind::Constraint {
            source: "rule".to_string(),
            expr: in_scope,
        },
    );
    module.annotate(ops, AnnotationKind::Intent("OUTSIDE-RULE".to_string()));
    module.annotate(app, AnnotationKind::Intent("APP-RULE".to_string()));
    module.set_provenance(Some(Provenance {
        producer: Some("test".to_string()),
        timestamp_ms: 1,
        model: None,
        tool: None,
        parent: Some([0x51; 32]),
        entries: vec![active_infinity::ProvEntry {
            key: "input".to_string(),
            value: active_infinity::ProvValue::Hash([0x52; 32]),
        }],
    }));
    let _ = Constraint::Odd;
    module
}

fn install_copying(attrs: CapAttrs) -> (Agent, CapHandle, LaneId, u64) {
    let agent = Agent::with_secret([0x62; 32]);
    let mut provider = ModuleProvider::new();
    let object = provider.install(copying_module()).expect("install");
    let id = agent.register(Box::new(provider));
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent
        .create_lane("round9", Budget::default())
        .expect("lane");
    (agent, cap, lane, object)
}

/// F1: the parent content address is an equality oracle over the secret heap,
/// and a redacting cone served it on the `subgraph` path while `patch` cleared
/// it.
#[test]
fn a_redacting_subgraph_carries_no_provenance() {
    let mut attrs = CapAttrs::new(&["subgraph"]);
    attrs.redact = true;
    let (agent, cap, lane, _) = install_copying(attrs);
    let value = call(
        &Fixture { agent },
        lane,
        &cap,
        "subgraph",
        vec![path("app")],
    )
    .expect("subgraph");
    let Value::Module(bytes) = value else {
        panic!("subgraph answers a module: {value:?}");
    };
    let decoded = active_infinity::decode(&bytes).expect("decode");
    assert!(
        decoded.provenance().is_none(),
        "the cone carries the whole module's provenance"
    );
}

/// F2: a plain `Str` that copies a secret literal is neither a secret node nor
/// metadata, so the old redactor left it in the cone verbatim.
#[test]
fn a_redacted_cone_carries_no_secret_literal_copy() {
    let mut attrs = CapAttrs::new(&["subgraph"]);
    attrs.redact = true;
    let (agent, cap, lane, _) = install_copying(attrs);
    let value = call(
        &Fixture { agent },
        lane,
        &cap,
        "subgraph",
        vec![path("app")],
    )
    .expect("subgraph");
    let Value::Module(bytes) = value else {
        panic!("subgraph answers a module: {value:?}");
    };
    let decoded = active_infinity::decode(&bytes).expect("decode");
    for index in 0..decoded.node_count() {
        let id = active_infinity::NodeId(index as u32);
        if let Some(Inode::Str(text)) | Some(Inode::Ident(text)) = decoded.get(id) {
            assert!(
                !text.contains(PROBE_SECRET),
                "the cone carries a copy of the secret: {text}"
            );
        }
    }
}

/// F2 on the evaluator: the engine has no notion of a secret literal, so it
/// returned the copy as text.
#[test]
fn an_evaluated_secret_copy_is_not_text() {
    let mut attrs = CapAttrs::new(&["evaluate"]);
    attrs.redact = true;
    let (agent, cap, lane, _) = install_copying(attrs);
    let value = call(
        &Fixture { agent },
        lane,
        &cap,
        "evaluate",
        vec![path("app.copy")],
    )
    .expect("evaluate");
    match &value {
        Value::Text(text) => assert!(
            !text.contains(PROBE_SECRET),
            "evaluate returned the secret copy: {text}"
        ),
        Value::Secret => {}
        other => panic!("unexpected answer {other:?}"),
    }
}

/// F3: the constraint relation is undirected. A scoped write to a rule's
/// expression changes the rule that guards an outside subtree.
#[test]
fn a_scoped_patch_cannot_change_an_outside_rule_expression() {
    let (fixture, cap, lane) = fixture(&["patch"], Some("app"));
    let error = call(
        &fixture,
        lane,
        &cap,
        "patch",
        vec![path("app.y"), Arg::text("changed")],
    )
    .expect_err("the rule on ops watches app.y");
    assert_eq!(error.code(), "rpc/path-not-granted", "{error}");
}

/// F4: the cone and the `annotations` query must agree. A rule on a node outside
/// the secret cone is data the capability was granted, so it travels.
#[test]
fn a_redacting_cone_keeps_rules_outside_the_secret_cone() {
    let mut attrs = CapAttrs::new(&["subgraph"]);
    attrs.redact = true;
    let (agent, cap, lane, _) = install_copying(attrs);
    let value = call(
        &Fixture { agent },
        lane,
        &cap,
        "subgraph",
        vec![path("app")],
    )
    .expect("subgraph");
    let Value::Module(bytes) = value else {
        panic!("subgraph answers a module: {value:?}");
    };
    let decoded = active_infinity::decode(&bytes).expect("decode");
    let intents: Vec<&str> = decoded
        .annotations()
        .iter()
        .filter_map(|annotation| match &annotation.kind {
            AnnotationKind::Intent(text) => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        intents.contains(&"APP-RULE"),
        "the cone dropped a rule on a granted node: {intents:?}"
    );
}

/// F6: `Kind[index]` names an arena position. Under a redacting capability a
/// pathless node has no name the caller may receive.
#[test]
fn a_redacting_answer_never_names_a_node_index() {
    use active_infinity::BinOp;
    let mut module = InfinityModule::new();
    let left = module.push(Inode::Str("1".to_string()));
    let right = module.push(Inode::Str("2".to_string()));
    let sum = module.push(Inode::Binary {
        op: BinOp::Add,
        lhs: left,
        rhs: right,
    });
    let app = module.push(Inode::Table {
        fields: vec![("x".to_string(), sum)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("app".to_string(), app)],
    });
    module.set_root(Some(root));

    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let mut call = active_rpc::value::Call::new("why", vec![path("app.x")]);
    call.redact = true;
    let response = active_rpc::kernel::Provider::invoke(&mut provider, object, &call).expect("why");
    let active_rpc::value::Response::Labels(labels) = response else {
        panic!("why answers labels: {response:?}");
    };
    for label in &labels {
        assert!(
            !label.contains('['),
            "a redacting answer names an arena position: {label}"
        );
    }
}
