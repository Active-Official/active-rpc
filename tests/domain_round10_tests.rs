//! R-07 round 10: installed metadata, constraint cycles, root aliases, labels.
//!
//! Each test drives the shipped provider through the same path a capability
//! does: install, mint, call.

use active_infinity::{AnnotationKind, InfinityModule, Inode};
use active_rpc::cap::CapAttrs;
use active_rpc::domain::ModuleProvider;
use active_rpc::value::{Arg, Call, Value};
use active_rpc::{Agent, Budget, CapHandle, LaneId};

const CANARY: &str = "round10-canary-7f2b";

fn install(
    module: InfinityModule,
    methods: &[&str],
    scope: Option<&str>,
    redact: bool,
) -> (Agent, CapHandle, LaneId) {
    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let agent = Agent::with_secret([0x71; 32]);
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(methods);
    attrs.path_scope = scope.map(str::to_string);
    attrs.redact = redact;
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent.create_lane("r10", Budget::default()).expect("lane");
    (agent, cap, lane)
}

fn call(agent: &Agent, cap: &CapHandle, lane: LaneId, method: &str, args: Vec<Arg>) -> Value {
    let promise = agent.call(lane, cap, method, args).expect("call");
    agent.run();
    promise.value().expect("value")
}

fn path(value: &str) -> Arg {
    Arg::Value(Value::path(value))
}

/// The encoder canonicalizes annotation prose; the stored module must be that
/// canonical form, or `annotations` serves the copy the encoder replaced.
#[test]
fn an_installed_annotation_copy_is_not_served() {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(CANARY.into()));
    let app = module.push(Inode::Table {
        fields: vec![("y".to_string(), secret)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("app".to_string(), app)],
    });
    module.set_root(Some(root));
    module.annotate(
        app,
        AnnotationKind::Intent(format!("the intent copies {CANARY} here")),
    );

    for redact in [false, true] {
        let (agent, cap, lane) = install(module.clone(), &["annotations"], None, redact);
        let mut call = Call::new("annotations", Vec::new());
        call.redact = redact;
        let promise = agent
            .call(lane, &cap, "annotations", Vec::new())
            .expect("call");
        agent.run();
        let value = promise.value().expect("annotations");
        let Value::List(entries) = value else {
            panic!("a list: {value:?}");
        };
        for entry in entries {
            if let Value::Map(fields) = entry {
                if let Some(Value::Text(text)) = fields.get("text") {
                    assert!(
                        !text.contains(CANARY),
                        "install served the raw copy (redact={redact}): {text}"
                    );
                }
            }
        }
    }
}

/// A constraint whose expression is its own subject used to re-enqueue forever:
/// the walk must terminate.
#[test]
fn a_self_referential_constraint_terminates() {
    use std::time::{Duration, Instant};

    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(CANARY.into()));
    let leaf = module.push(Inode::Table {
        fields: vec![("s".to_string(), secret)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("app".to_string(), leaf)],
    });
    module.set_root(Some(root));
    module.annotate(
        leaf,
        AnnotationKind::Constraint {
            source: "self".to_string(),
            expr: leaf,
        },
    );

    let (agent, cap, lane) = install(module, &["annotations"], None, true);
    let mut call = Call::new("annotations", Vec::new());
    call.redact = true;
    let started = Instant::now();
    let promise = agent
        .call(lane, &cap, "annotations", Vec::new())
        .expect("call");
    agent.run();
    promise.value().expect("annotations");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the taint walk did not terminate: {:?}",
        started.elapsed()
    );
}

/// A binding can name the module root, and the label resolves back to it, so a
/// scoped write could replace the whole module.
#[test]
fn a_scoped_patch_cannot_replace_the_module_root() {
    let mut module = InfinityModule::new();
    let inner = module.push(Inode::Str("OUTSIDE-DATA".to_string()));
    let ops = module.push(Inode::Table {
        fields: vec![("secret".to_string(), inner)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("ops".to_string(), ops)],
    });
    module.set_root(Some(root));
    module.bind("app", root);

    let (agent, cap, lane) = install(module, &["patch", "evaluate"], Some("app"), true);
    let promise = agent
        .call(lane, &cap, "patch", vec![path("app"), Arg::text("pwned")])
        .expect("queued");
    agent.run();
    let error = promise
        .value()
        .expect_err("the root is not a scoped write target");
    assert_eq!(error.code(), "rpc/path-not-granted", "{error}");
}

/// A label that does not resolve back to its node is an arena position (or a
/// stale name), not a name the caller may receive.
#[test]
fn a_redacting_answer_names_no_synthetic_label() {
    let mut module = InfinityModule::new();
    let mut current = module.push(Inode::Int(1));
    // Past the export path depth, where the library switches to `@node[id]`.
    for index in 0..80 {
        current = module.push(Inode::Table {
            fields: vec![(format!("f{index}"), current)],
        });
    }
    let secret = module.push(Inode::Secret(CANARY.into()));
    let root = module.push(Inode::Table {
        fields: vec![
            ("deep".to_string(), current),
            ("secret".to_string(), secret),
        ],
    });
    module.set_root(Some(root));

    let (agent, cap, lane) = install(module, &["why", "impact", "dependents"], None, true);
    for method in ["why", "impact", "dependents"] {
        let value = call(&agent, &cap, lane, method, vec![path("deep")]);
        let Value::List(labels) = value else {
            continue;
        };
        for label in labels {
            if let Value::Text(text) = label {
                assert!(
                    !text.contains('[') && !text.contains('@'),
                    "{method} named an arena position: {text}"
                );
            }
        }
    }
}

/// When a secret is a substring of the marker the redactor writes the empty
/// string; the answer must still be the structural marker.
#[test]
fn a_marker_substring_secret_is_a_value_secret() {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret("*".into()));
    let root = module.push(Inode::Table {
        fields: vec![("value".to_string(), secret)],
    });
    module.set_root(Some(root));

    for redact in [false, true] {
        let (agent, cap, lane) = install(module.clone(), &["evaluate"], None, redact);
        let mut call = Call::new("evaluate", vec![path("value")]);
        call.redact = redact;
        let promise = agent
            .call(lane, &cap, "evaluate", call.args.clone())
            .expect("call");
        agent.run();
        let value = promise.value().expect("evaluate");
        assert!(
            matches!(value, Value::Secret),
            "a secret came back as plain text (redact={redact}): {value:?}"
        );
    }
}

/// A hidden annotation does not reveal how many rules exist or their kinds.
#[test]
fn a_redacting_annotation_answer_collapses_the_hidden_set() {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(CANARY.into()));
    let app = module.push(Inode::Table {
        fields: vec![("s".to_string(), secret)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("app".to_string(), app)],
    });
    module.set_root(Some(root));
    module.annotate(app, AnnotationKind::Intent("one".to_string()));
    module.annotate(app, AnnotationKind::Intent("two".to_string()));
    module.annotate(
        app,
        AnnotationKind::Constraint {
            source: "three".to_string(),
            expr: app,
        },
    );

    let (agent, cap, lane) = install(module, &["annotations"], None, true);
    let mut call = Call::new("annotations", Vec::new());
    call.redact = true;
    let promise = agent
        .call(lane, &cap, "annotations", call.args.clone())
        .expect("call");
    agent.run();
    let value = promise.value().expect("annotations");
    let Value::List(entries) = value else {
        panic!("a list: {value:?}");
    };
    assert_eq!(
        entries.len(),
        1,
        "one marker for the hidden set: {entries:?}"
    );
    let Value::Map(fields) = &entries[0] else {
        panic!("a map: {:?}", entries[0]);
    };
    assert!(fields.contains_key("text"));
    assert!(!fields.contains_key("kind"), "the kind leaks: {fields:?}");
    assert!(!fields.contains_key("node"), "the node leaks: {fields:?}");
}

/// A binding that spells the scope exactly still names an outside node: the
/// scope is a statement about the field tree, so the alias does not move the
/// node inside it.
#[test]
fn an_undotted_binding_alias_does_not_widen_the_scope() {
    let mut module = InfinityModule::new();
    let outside = module.push(Inode::Str("OUTSIDE-DATA".to_string()));
    let ops = module.push(Inode::Table {
        fields: vec![("s".to_string(), outside)],
    });
    // No real `app` field: the alias is the only meaning of the name, so the
    // resolution follows it and the structural check is what refuses.
    let root = module.push(Inode::Table {
        fields: vec![("ops".to_string(), ops)],
    });
    module.set_root(Some(root));
    module.bind("app", outside);

    let (agent, cap, lane) = install(module, &["evaluate", "subgraph", "why"], Some("app"), false);
    for method in ["evaluate", "subgraph", "why"] {
        let promise = agent
            .call(lane, &cap, method, vec![path("app")])
            .expect("queued");
        agent.run();
        let error = promise
            .value()
            .expect_err("the alias points outside the scope");
        assert_eq!(error.code(), "rpc/path-not-granted", "{method}: {error}");
    }
}

/// The last capability drop reclaims the module: a later mint on the same
/// object finds no module.
#[test]
fn the_last_drop_reclaims_the_module() {
    let mut module = InfinityModule::new();
    let value = module.push(Inode::Str("v".to_string()));
    let root = module.push(Inode::Table {
        fields: vec![("v".to_string(), value)],
    });
    module.set_root(Some(root));

    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let agent = Agent::with_secret([0x72; 32]);
    let provider_id = agent.register(Box::new(provider));
    let cap = agent
        .mint(provider_id, object, CapAttrs::new(&["evaluate"]))
        .expect("cap");
    drop(cap);
    let _ = agent.take_drops(provider_id);

    let stale = agent
        .mint(provider_id, object, CapAttrs::new(&["evaluate"]))
        .expect("mint on a stale object is the caller's business");
    let lane = agent
        .create_lane("reclaim", Budget::default())
        .expect("lane");
    let promise = agent
        .call(lane, &stale, "evaluate", vec![path("v")])
        .expect("queued");
    agent.run();
    let error = promise.value().expect_err("the module is gone");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
}

/// The entry node of a dependency query is part of the answer: an alias that
/// names an outside node must not answer, with or without redaction.
#[test]
fn a_scoped_dependency_query_refuses_an_alias_entry() {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(CANARY.into()));
    let ops = module.push(Inode::Table {
        fields: vec![("s".to_string(), secret)],
    });
    // No real `app` field: the only meaning of the name is the alias.
    let root = module.push(Inode::Table {
        fields: vec![("ops".to_string(), ops)],
    });
    module.set_root(Some(root));
    module.bind("app", secret);

    for redact in [false, true] {
        let (agent, cap, lane) = install(
            module.clone(),
            &["dependents", "dependencies"],
            Some("app"),
            redact,
        );
        for method in ["dependents", "dependencies"] {
            let promise = agent
                .call(lane, &cap, method, vec![path("app")])
                .expect("queued");
            agent.run();
            let error = promise
                .value()
                .expect_err("the alias entry is outside the scope");
            assert_eq!(error.code(), "rpc/path-not-granted", "{method}: {error}");
        }
    }
}

/// A secret-bearing module never serves a raw content address through its
/// provenance, with or without a redacting capability.
#[test]
fn a_secret_bearing_module_serves_no_raw_parent_hash() {
    use active_infinity::Provenance;

    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(CANARY.into()));
    let root = module.push(Inode::Table {
        fields: vec![("s".to_string(), secret)],
    });
    module.set_root(Some(root));
    module.set_provenance(Some(Provenance {
        producer: Some("test".to_string()),
        timestamp_ms: 1,
        model: None,
        tool: None,
        parent: Some([0x61; 32]),
        entries: Vec::new(),
    }));

    for redact in [false, true] {
        let (agent, cap, lane) = install(module.clone(), &["provenance", "subgraph"], None, redact);
        let value = {
            let promise = agent
                .call(lane, &cap, "provenance", Vec::new())
                .expect("queued");
            agent.run();
            promise.value().expect("provenance")
        };
        if let Value::Map(fields) = value {
            for (key, value) in &fields {
                if let Value::Text(text) = value {
                    assert!(
                        !text.starts_with("blake3:"),
                        "a raw content address leaked (redact={redact}): {key}={text}"
                    );
                }
            }
            assert!(!fields.contains_key("parent"), "{fields:?}");
        }

        let cone = {
            let promise = agent
                .call(lane, &cap, "subgraph", vec![path("s")])
                .expect("queued");
            agent.run();
            promise.value().expect("subgraph")
        };
        let Value::Module(bytes) = cone else {
            panic!("a module: {cone:?}");
        };
        let decoded = active_infinity::decode(&bytes).expect("decode");
        assert!(
            decoded.provenance().is_none(),
            "the cone carries a raw content address (redact={redact})"
        );
    }
}

/// A semantic wrapper above a table or an array is transparent to the scope
/// walk, and a single-segment path never slices the path (round 14, H2/M1).
#[test]
fn a_semantic_wrapper_is_transparent_to_the_scope() {
    use active_infinity::SemanticTag;

    let mut module = InfinityModule::new();
    let leaf = module.push(Inode::Str("inside".to_string()));
    let inner = module.push(Inode::Table {
        fields: vec![("w".to_string(), leaf)],
    });
    let wrapped = module.push(Inode::Semantic {
        tag: SemanticTag::Policy,
        inner,
    });
    let app = module.push(Inode::Table {
        fields: vec![("w".to_string(), wrapped)],
    });
    let root = module.push(Inode::Semantic {
        tag: SemanticTag::Prompt,
        inner: app,
    });
    module.set_root(Some(root));

    let (agent, cap, lane) = install(module, &["evaluate"], None, false);
    // A single segment over a semantic root used to panic.
    let promise = agent
        .call(lane, &cap, "evaluate", vec![path("w")])
        .expect("queued");
    agent.run();
    let _ = promise.value();
}

/// A patch that removes the last secret still must not serve the pre-patch
/// content address (round 14, H1).
#[test]
fn a_patch_removing_the_last_secret_serves_no_parent() {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(CANARY.into()));
    let root = module.push(Inode::Table {
        fields: vec![("s".to_string(), secret)],
    });
    module.set_root(Some(root));

    let (agent, cap, lane) = install(module, &["patch", "provenance", "subgraph"], None, false);
    let promise = agent
        .call(lane, &cap, "patch", vec![path("s"), Arg::text("public")])
        .expect("queued");
    agent.run();
    let cone = promise.value().expect("patch");
    let Value::Module(bytes) = cone else {
        panic!("a module: {cone:?}");
    };
    let decoded = active_infinity::decode(&bytes).expect("decode");
    assert!(
        decoded.provenance().is_none(),
        "the cone carries the pre-patch address"
    );

    let promise = agent
        .call(lane, &cap, "provenance", Vec::new())
        .expect("queued");
    agent.run();
    if let Value::Map(fields) = promise.value().expect("provenance") {
        assert!(!fields.contains_key("parent"), "{fields:?}");
        for value in fields.values() {
            if let Value::Text(text) = value {
                assert!(!text.contains("blake3:"), "{text}");
            }
        }
    }
}

/// An embedded content address is dropped like a bare one (round 14, L1).
#[test]
fn an_embedded_content_address_is_dropped() {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(CANARY.into()));
    let root = module.push(Inode::Table {
        fields: vec![("s".to_string(), secret)],
    });
    module.set_root(Some(root));
    module.set_provenance(Some(active_infinity::Provenance {
        producer: Some("see blake3:0011 for the lineage".to_string()),
        timestamp_ms: 1,
        model: None,
        tool: None,
        parent: None,
        entries: Vec::new(),
    }));

    let (agent, cap, lane) = install(module, &["provenance"], None, false);
    let promise = agent
        .call(lane, &cap, "provenance", Vec::new())
        .expect("queued");
    agent.run();
    let value = promise.value().expect("provenance");
    let Value::Map(fields) = value else {
        panic!("a map: {value:?}");
    };
    for text in fields.values() {
        if let Value::Text(text) = text {
            assert!(!text.contains("blake3:"), "{text}");
        }
    }
}
