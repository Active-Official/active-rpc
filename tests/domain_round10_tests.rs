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

/// A redacting caller never receives an arena index: `stats` hides the size,
/// and a node number handed it back (round 25, #4).
#[test]
fn a_redacting_annotation_answer_names_no_arena_index() {
    let mut module = InfinityModule::new();
    let leaf = module.push(Inode::Int(5));
    let root = module.push(Inode::Table {
        fields: vec![("a".to_string(), leaf)],
    });
    module.set_root(Some(root));
    module.annotate(leaf, AnnotationKind::Intent("visible".to_string()));

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
                assert_eq!(
                    fields.contains_key("node"),
                    !redact,
                    "an arena index leaked (redact={redact}): {fields:?}"
                );
            }
        }
    }
}

/// One subgraph pass follows a whole constraint chain: `edges()` lists every
/// expression as a dependency of its subject, so the old fixpoint was
/// redundant work, not a correctness requirement (round 25, #1).
#[test]
fn a_constraint_chain_is_inside_one_cone() {
    let mut module = InfinityModule::new();
    let first = module.push(Inode::Int(0));
    let mut previous = first;
    for index in 1..200 {
        let node = module.push(Inode::Int(index));
        module.annotate(
            previous,
            AnnotationKind::Constraint {
                source: format!("rule {index}"),
                expr: node,
            },
        );
        previous = node;
    }
    let app = module.push(Inode::Table {
        fields: vec![("a".to_string(), first)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("app".to_string(), app)],
    });
    module.set_root(Some(root));

    let (agent, cap, lane) = install(module, &["subgraph"], None, false);
    let promise = agent
        .call(lane, &cap, "subgraph", vec![path("app.a")])
        .expect("queued");
    agent.run();
    match promise.value().expect("a cone") {
        Value::Module(bytes) => {
            let cone = active_infinity::decode(&bytes).expect("the cone decodes");
            let tail = cone
                .nodes()
                .iter()
                .any(|node| matches!(node, Inode::Int(value) if *value == 199));
            assert!(
                tail,
                "the last constraint expression is missing from the cone"
            );
        }
        other => panic!("a module: {other:?}"),
    }
}

/// A patch that removes the last secret node must not declassify the literals
/// the module held at install: the redactor is the install-time set, so a
/// redacting capability still sees the marker and a redacted hash, never a
/// plaintext copy or the raw content address (round 27, critical).
#[test]
fn a_patch_cannot_declassify_an_install_time_secret() {
    const SECRET: &str = "round27-canary-4d1a";

    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SECRET.into()));
    let copy = module.push(Inode::Str(SECRET.into()));
    let app = module.push(Inode::Table {
        fields: vec![("s".to_string(), secret), ("c".to_string(), copy)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("app".to_string(), app)],
    });
    module.set_root(Some(root));

    let mut provider = ModuleProvider::new();
    let object = provider.install(module.clone()).expect("install");
    let agent = Agent::with_secret([0x74; 32]);
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(&["patch", "subgraph", "evaluate", "content_hash"]);
    attrs.redact = true;
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent
        .create_lane("r27-declassify", Budget::default())
        .expect("lane");

    // Remove the only secret node through a supported write.
    let promise = agent
        .call(
            lane,
            &cap,
            "patch",
            vec![path("app.s"), Arg::Value(Value::Int(0))],
        )
        .expect("queued");
    agent.run();
    promise.value().expect("patch");

    // A plaintext copy in the module must still read as hidden.
    let promise = agent
        .call(lane, &cap, "subgraph", vec![path("app.c")])
        .expect("queued");
    agent.run();
    match promise.value().expect("subgraph") {
        Value::Module(bytes) => assert!(
            !bytes
                .windows(SECRET.len())
                .any(|window| window == SECRET.as_bytes()),
            "a cone carried the install-time secret"
        ),
        other => panic!("a module: {other:?}"),
    }

    let promise = agent
        .call(lane, &cap, "evaluate", vec![path("app.c")])
        .expect("queued");
    agent.run();
    match promise.value().expect("evaluate") {
        Value::Text(text) => assert!(!text.contains(SECRET), "evaluate returned {text:?}"),
        Value::Secret => {}
        other => panic!("unexpected {other:?}"),
    }

    // The raw content address of the declassified image must not be served.
    // The image is reconstructed exactly: the write, plus the provenance a
    // patch records (no parent and no hash entries, because the slot held a
    // secret). A hand arena without that provenance would differ from the
    // served hash for the wrong reason (round 28, critical).
    let mut patched = module;
    let node = active_infinity::interop::resolve_path(&patched, "app.s")
        .expect("the secret node resolves");
    *patched.node_mut(node).expect("node") = Inode::Int(0);
    patched.set_provenance(Some(active_infinity::Provenance {
        producer: Some("active-rpc/patch".to_string()),
        timestamp_ms: 0,
        model: None,
        tool: Some("patch".to_string()),
        parent: None,
        entries: Vec::new(),
    }));
    let raw = active_infinity::encode(&patched).expect("encode");
    let raw_text = format!(
        "blake3:{}",
        active_infinity::content_hash_hex(&raw).expect("hash")
    );
    let promise = agent
        .call(lane, &cap, "content_hash", Vec::new())
        .expect("queued");
    agent.run();
    let served = match promise.value().expect("content_hash") {
        Value::Text(text) => text,
        other => panic!("unexpected {other:?}"),
    };
    assert_ne!(served, raw_text, "the raw hash of the declassified image");
}

/// A scoped evaluation maps placeholders by the cone's ids, not the module's:
/// the two arenas diverge once a subtree is renumbered, and indexing the cone
/// with module ids turned a secret field into data and a public one into
/// `Secret` (round 28, medium).
#[test]
fn a_scoped_evaluate_keeps_secret_and_public_fields_apart() {
    const SECRET: &str = "round28-placeholder-7c";

    let mut module = InfinityModule::new();
    let _padding = module.push(Inode::Int(0));
    let a = module.push(Inode::Str(SECRET.into()));
    let b = module.push(Inode::Secret(SECRET.into()));
    let c = module.push(Inode::Str(SECRET.into()));
    let d = module.push(Inode::Str("public-d".into()));
    let e = module.push(Inode::Str("public-e".into()));
    let app = module.push(Inode::Table {
        fields: vec![
            ("a".to_string(), a),
            ("b".to_string(), b),
            ("c".to_string(), c),
            ("d".to_string(), d),
            ("e".to_string(), e),
        ],
    });
    let root = module.push(Inode::Table {
        fields: vec![("app".to_string(), app)],
    });
    module.set_root(Some(root));

    let (agent, cap, lane) = install(module, &["evaluate"], None, true);
    let promise = agent
        .call(lane, &cap, "evaluate", vec![path("app")])
        .expect("queued");
    agent.run();
    let value = promise.value().expect("evaluate");
    let Value::Map(fields) = value else {
        panic!("a table: {value:?}");
    };
    for name in ["a", "b", "c"] {
        assert!(
            matches!(fields.get(name), Some(Value::Secret)),
            "{name} = {:?}",
            fields.get(name)
        );
    }
    for (name, text) in [("d", "public-d"), ("e", "public-e")] {
        match fields.get(name) {
            Some(Value::Text(value)) => assert_eq!(value, text, "{name}"),
            other => panic!("{name} = {other:?}"),
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
    // A vanished provider object is provider state (round 34, L-7).
    assert_eq!(error.code(), "rpc/provider", "{error}");
    assert_eq!(error.provider_code(), Some("provider/object"), "{error}");
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
        .call(
            lane,
            &cap,
            "patch",
            vec![path("s"), Arg::Value(Value::Int(1))],
        )
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

/// The scope walk is exercised with a scope: a semantic wrapper above a table is
/// transparent, and a single-segment path never panics (round 15, #1).
#[test]
fn a_scoped_semantic_wrapper_resolves() {
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
    let root = module.push(Inode::Table {
        fields: vec![("app".to_string(), app)],
    });
    module.set_root(Some(root));

    let (agent, cap, lane) = install(module, &["evaluate"], Some("app"), false);
    // `app.w` is a Table behind a Semantic wrapper: a legal in-scope name.
    let promise = agent
        .call(lane, &cap, "evaluate", vec![path("app.w")])
        .expect("queued");
    agent.run();
    let value = promise.value().expect("the wrapper is transparent");
    assert!(matches!(value, Value::Map(_)), "{value:?}");
}

/// A declassifying patch drops the hash-bearing provenance entries too: they
/// name the pre-patch image (round 15, #2).
#[test]
fn a_patch_removing_the_last_secret_drops_hash_entries() {
    use active_infinity::{ProvEntry, ProvValue, Provenance};

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
        parent: None,
        entries: vec![ProvEntry {
            key: "input".to_string(),
            value: ProvValue::Hash([0x63; 32]),
        }],
    }));

    let (agent, cap, lane) = install(module, &["patch", "provenance"], None, false);
    let promise = agent
        .call(
            lane,
            &cap,
            "patch",
            vec![path("s"), Arg::Value(Value::Int(1))],
        )
        .expect("queued");
    agent.run();
    promise.value().expect("patch");

    let promise = agent
        .call(lane, &cap, "provenance", Vec::new())
        .expect("queued");
    agent.run();
    let value = promise.value().expect("provenance");
    if let Value::Map(fields) = value {
        for text in fields.values() {
            if let Value::Text(text) = text {
                assert!(
                    !text.contains("blake3:"),
                    "a pre-patch address survives: {text}"
                );
            }
        }
    }
}

/// Annotations are records every metadata walk scans, and a module may hold
/// more of them than it holds nodes: a flood is refused before the walk
/// against the same ceiling, not measured after it (round 23, #5).
#[test]
fn an_annotation_flood_is_refused_by_the_node_ceiling() {
    let mut module = InfinityModule::new();
    let field = module.push(Inode::Int(1));
    let root = module.push(Inode::Table {
        fields: vec![("a".to_string(), field)],
    });
    module.set_root(Some(root));
    for index in 0..4 {
        module.annotate(field, AnnotationKind::Intent(format!("note {index}")));
    }

    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let agent = Agent::with_secret([0x72; 32]);
    let id = agent.register(Box::new(provider));
    let cap = agent
        .mint(id, object, CapAttrs::new(&["why"]))
        .expect("cap");
    let lane = agent
        .create_lane(
            "r23-annotations",
            Budget {
                max_nodes: 3,
                ..Budget::default()
            },
        )
        .expect("lane");
    let promise = agent
        .call(lane, &cap, "why", vec![path("a")])
        .expect("queued");
    agent.run();
    let error = promise
        .value()
        .expect_err("four annotations over three nodes");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    // One kind for both counts: a distinct label would let a scoped or
    // redacting caller binary-search a size `stats` hides (round 24, F6).
    assert!(format!("{error}").contains("nodes"), "{error}");
}

/// A scope closure over a hostile annotation count is bounded by the wall
/// ceiling inside the round, not after it: the adjacency is built once and the
/// grant is checked every 64 annotations (round 24, F1).
#[test]
fn a_scoped_walk_over_many_constraints_stays_within_the_wall_ceiling() {
    use std::time::Instant;

    let mut module = InfinityModule::new();
    // A wide expression (depth 2) keeps the module inside the format's depth
    // ceiling while making every walk visit four hundred nodes. The annotation
    // subject is a single small node: an annotation's key renders its subject,
    // so a wide subject would hit the key-byte ceiling first.
    let mut fields = Vec::with_capacity(400);
    for index in 0..400 {
        let field = module.push(Inode::Int(index));
        fields.push((format!("f{index}"), field));
    }
    let wide = module.push(Inode::Table { fields });
    let subject = module.push(Inode::Int(7));
    let app = module.push(Inode::Table {
        fields: vec![("a".to_string(), subject)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("app".to_string(), app)],
    });
    module.set_root(Some(root));
    // Every rule watches the wide expression, so one round walks it once per
    // rule. The default install ceiling accepts 4 096 annotations.
    for index in 0..4_000 {
        module.annotate(
            subject,
            AnnotationKind::Constraint {
                source: format!("rule {index}"),
                expr: wide,
            },
        );
    }

    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let agent = Agent::with_secret([0x73; 32]);
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(&["why", "patch"]);
    attrs.path_scope = Some("app.a".to_string());
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent
        .create_lane(
            "r24-wall",
            Budget {
                max_wall_ms: 5,
                ..Budget::default()
            },
        )
        .expect("lane");

    for (method, args) in [
        ("why", vec![path("app.a")]),
        ("patch", vec![path("app.a"), Arg::Value(Value::Int(7))]),
    ] {
        let started = Instant::now();
        let promise = agent.call(lane, &cap, method, args).expect("queued");
        agent.run();
        let error = promise.value().expect_err("the walk exceeds the grant");
        let elapsed = started.elapsed();
        assert_eq!(error.code(), "rpc/budget-exceeded", "{method}: {error}");
        assert!(format!("{error}").contains("wall"), "{method}: {error}");
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "{method} took {elapsed:?} for a 20 ms grant"
        );
    }
}

/// An over-deep evaluation result is refused with the depth code every other
/// depth refusal uses (round 15, #3).
#[test]
fn an_over_deep_evaluation_is_a_budget_refusal() {
    let mut module = InfinityModule::new();
    let mut current = module.push(Inode::Int(1));
    for index in 0..80 {
        current = module.push(Inode::Table {
            fields: vec![(format!("f{index}"), current)],
        });
    }
    module.set_root(Some(current));

    let (agent, cap, lane) = install(module, &["evaluate"], None, false);
    let promise = agent
        .call(lane, &cap, "evaluate", Vec::new())
        .expect("queued");
    agent.run();
    let error = promise.value().expect_err("too deep for the wire");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

/// A marker-substring secret collapses public empty text too: the accepted
/// fail-closed direction (round 15, #6).
#[test]
fn an_empty_placeholder_collapses_public_empty_text() {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret("*".into()));
    let public = module.push(Inode::Str(String::new()));
    let root = module.push(Inode::Table {
        fields: vec![
            ("secret".to_string(), secret),
            ("public".to_string(), public),
        ],
    });
    module.set_root(Some(root));

    let (agent, cap, lane) = install(module, &["evaluate"], None, true);
    for name in ["secret", "public"] {
        let promise = agent
            .call(lane, &cap, "evaluate", vec![path(name)])
            .expect("queued");
        agent.run();
        let value = promise.value().expect("evaluate");
        assert!(
            matches!(value, Value::Secret),
            "{name} answered {value:?}; the empty placeholder collapses as documented"
        );
    }
}

// ---------------------------------------------------------------------------
// Round 17
// ---------------------------------------------------------------------------

/// A duration past `i64::MAX` saturates instead of wrapping negative
/// (round 17, F1).
#[test]
fn a_duration_past_i64_saturates() {
    let mut module = InfinityModule::new();
    let duration = module.push(Inode::DurationMs(u64::MAX));
    let root = module.push(Inode::Table {
        fields: vec![("d".to_string(), duration)],
    });
    module.set_root(Some(root));

    let (agent, cap, lane) = install(module, &["evaluate"], None, false);
    let promise = agent
        .call(lane, &cap, "evaluate", vec![path("d")])
        .expect("queued");
    agent.run();
    let value = promise.value().expect("evaluate");
    let Value::Map(fields) = value else {
        panic!("a duration answers a map: {value:?}");
    };
    assert_eq!(fields.get("ms"), Some(&Value::Int(i64::MAX)), "{fields:?}");
}

/// Caller text with a line separator or a zero-width character does not reach
/// the log verbatim (round 17, F2).
#[test]
fn a_displayed_path_cannot_forge_a_log_line() {
    let error = active_rpc::Error::PathNotGranted("a\u{2028}b\u{200b}c\nd".to_string());
    let text = error.to_string();
    for hostile in ['\u{2028}', '\u{200b}', '\n'] {
        assert!(!text.contains(hostile), "raw {hostile:?} in {text:?}");
    }
}

// ---------------------------------------------------------------------------
// Round 18
// ---------------------------------------------------------------------------

/// The evaluator's ceiling names survive the mapping (round 18, #6).
#[test]
fn evaluator_limit_dimensions_are_preserved() {
    let mut module = InfinityModule::new();
    let mut current = module.push(Inode::Int(1));
    for index in 0..40 {
        current = module.push(Inode::Table {
            fields: vec![(format!("f{index}"), current)],
        });
    }
    module.set_root(Some(current));

    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let mut call = Call::new("evaluate", Vec::new());
    call.budget = Budget {
        max_nodes: 4,
        ..Budget::default()
    };
    let error = active_rpc::kernel::Provider::invoke(&mut provider, object, &call)
        .expect_err("the node budget is tiny");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    assert!(
        error.to_string().contains("nodes"),
        "the dimension is named: {error}"
    );
}

/// The synthetic level of a duration counts against the wire ceiling
/// (round 18, #7).
#[test]
fn the_synthetic_level_counts_against_the_ceiling() {
    let mut module = InfinityModule::new();
    let mut current = module.push(Inode::DurationMs(7));
    for index in 0..63 {
        current = module.push(Inode::Table {
            fields: vec![(format!("f{index}"), current)],
        });
    }
    module.set_root(Some(current));

    let (agent, cap, lane) = install(module, &["evaluate"], None, false);
    let promise = agent
        .call(lane, &cap, "evaluate", Vec::new())
        .expect("queued");
    agent.run();
    let error = promise
        .value()
        .expect_err("the converted value is too deep");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

// ---------------------------------------------------------------------------
// Round 19
// ---------------------------------------------------------------------------

/// The evaluator's own ceilings are budget refusals, not domain faults
/// (round 19, #1).
#[test]
fn an_evaluator_array_ceiling_is_a_budget_refusal() {
    let mut module = InfinityModule::new();
    let value = module.push(Inode::Int(1));
    let elements: Vec<active_infinity::NodeId> = vec![value; 200_000];
    let array = module.push(Inode::Array { elements });
    let root = module.push(Inode::Table {
        fields: vec![("a".to_string(), array)],
    });
    module.set_root(Some(root));

    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let mut call = Call::new("evaluate", vec![path("a")]);
    call.budget = Budget {
        max_nodes: 1_000_000,
        max_array_len: 16,
        ..Budget::default()
    };
    let error = active_rpc::kernel::Provider::invoke(&mut provider, object, &call)
        .expect_err("the array ceiling trips");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    assert!(
        error.to_string().contains("array_len"),
        "the dimension is named: {error}"
    );
}

/// A dotted path into an array resolves for a scoped capability (round 19, #2).
#[test]
fn an_array_element_path_resolves() {
    let mut module = InfinityModule::new();
    let first = module.push(Inode::Str("first".to_string()));
    let second = module.push(Inode::Str("second".to_string()));
    let array = module.push(Inode::Array {
        elements: vec![first, second],
    });
    let app = module.push(Inode::Table {
        fields: vec![("list".to_string(), array)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("app".to_string(), app)],
    });
    module.set_root(Some(root));

    let (agent, cap, lane) = install(module, &["evaluate"], Some("app"), false);
    let promise = agent
        .call(lane, &cap, "evaluate", vec![path("app.list.1")])
        .expect("queued");
    agent.run();
    let value = promise.value().expect("an array element is a name");
    assert_eq!(value, Value::text("second"));
}

/// A redacting stats answer hides the module's size (round 21, #1).
#[test]
fn a_redacting_stats_answer_hides_the_size() {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(CANARY.into()));
    let root = module.push(Inode::Table {
        fields: vec![("s".to_string(), secret)],
    });
    module.set_root(Some(root));

    let (agent, cap, lane) = install(module.clone(), &["stats"], None, true);
    let promise = agent.call(lane, &cap, "stats", Vec::new()).expect("queued");
    agent.run();
    let value = promise.value().expect("stats");
    let Value::Map(fields) = value else {
        panic!("a map: {value:?}");
    };
    assert!(!fields.contains_key("nodes"), "{fields:?}");
    assert!(!fields.contains_key("edges"), "{fields:?}");
    assert!(!fields.contains_key("secrets"), "{fields:?}");
}

/// A patch that orphans a secret leaves a canonical image, and the module
/// stays secret-bearing because the install-time redactor still holds the
/// literal (round 21, #3; round 31, F5 restored the assertions this test lost
/// in round 27).
#[test]
fn a_patch_that_orphans_a_secret_stays_secret_bearing() {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(CANARY.into()));
    let subtree = module.push(Inode::Table {
        fields: vec![("s".to_string(), secret)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("app".to_string(), subtree)],
    });
    module.set_root(Some(root));

    let (agent, cap, lane) = install(
        module,
        &["patch", "provenance", "content_hash", "stats"],
        None,
        false,
    );
    let promise = agent
        .call(
            lane,
            &cap,
            "patch",
            vec![path("app"), Arg::Value(Value::Int(1))],
        )
        .expect("queued");
    agent.run();
    promise.value().expect("patch");

    // Stats still reports one secret: the redactor remembers the literal, so
    // the module is treated as secret-bearing for every other method too.
    let promise = agent.call(lane, &cap, "stats", Vec::new()).expect("queued");
    agent.run();
    let stats = promise.value().expect("stats");
    let Value::Map(stats) = stats else {
        panic!("stats is a map: {stats:?}");
    };
    assert_eq!(stats.get("secrets"), Some(&Value::Int(1)), "{stats:?}");
    assert!(
        !stats.contains_key("has_provenance"),
        "stats no longer answers a signal the provenance method owns: {stats:?}"
    );

    // The hash is still served, in the redacted form.
    let promise = agent
        .call(lane, &cap, "content_hash", Vec::new())
        .expect("queued");
    agent.run();
    let hash = promise.value().expect("hash");
    let Value::Text(hash) = hash else {
        panic!("a hash: {hash:?}");
    };
    assert!(hash.starts_with("blake3:"), "{hash}");

    // Provenance stays visible but never names the canonical image's hash,
    // which would let a caller recompute what was redacted.
    let promise = agent
        .call(lane, &cap, "provenance", Vec::new())
        .expect("queued");
    agent.run();
    let provenance = promise.value().expect("provenance");
    assert!(
        !format!("{provenance:?}").contains("blake3:"),
        "provenance still names a canonical hash: {provenance:?}"
    );
}

/// A scoped evaluate gives one answer whether the name is missing or confined
/// (round 22, #1).
#[test]
fn a_scoped_evaluate_hides_whether_a_name_exists() {
    let mut module = InfinityModule::new();
    let outside = module.push(Inode::Str("OUTSIDE".to_string()));
    let leaf = module.push(Inode::Str("in".to_string()));
    let app = module.push(Inode::Table {
        fields: vec![
            ("y".to_string(), leaf),
            // A reference that leaves the scope.
            ("x".to_string(), outside),
        ],
    });
    let root = module.push(Inode::Table {
        fields: vec![("app".to_string(), app), ("other".to_string(), outside)],
    });
    module.set_root(Some(root));

    let (agent, cap, lane) = install(module, &["evaluate"], Some("app"), false);
    let missing = {
        let promise = agent
            .call(lane, &cap, "evaluate", vec![path("app.missing")])
            .expect("queued");
        agent.run();
        promise.value().expect_err("missing")
    };
    let outside = {
        let promise = agent
            .call(lane, &cap, "evaluate", vec![path("app.x")])
            .expect("queued");
        agent.run();
        promise.value().expect_err("outside")
    };
    assert_eq!(missing.code(), outside.code(), "{missing} vs {outside}");
    assert_eq!(missing.code(), "rpc/path-not-granted", "{missing}");
}

/// A mutating provider that ran before the byte charge is not reported as a
/// retryable budget refusal, and its receipt records the admission: the write
/// stands even though the reply was withheld (round 31, F1).
#[test]
fn a_mutating_patch_refused_on_egress_reports_the_write() {
    use active_rpc::receipts::Decision;

    let mut module = InfinityModule::new();
    let blob = module.push(Inode::Str("x".repeat(64 * 1024)));
    let app = module.push(Inode::Table {
        fields: vec![("data".to_string(), blob)],
    });
    // The large sibling keeps the returned image past the grant even after the
    // patched cone shrinks.
    let big = module.push(Inode::Str("y".repeat(64 * 1024)));
    let root = module.push(Inode::Table {
        fields: vec![("app".to_string(), app), ("big".to_string(), big)],
    });
    module.set_root(Some(root));

    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let agent = Agent::with_secret([0x72; 32]);
    agent.enable_receipts(true);
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(&["patch", "content_hash"]);
    // Enough for the arguments and a hash reply, not enough for the patch
    // reply that carries the new cone.
    attrs.budget.max_bytes = 256;
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent
        .create_lane("r10-egress", Budget::default())
        .expect("lane");

    let before = call(&agent, &cap, lane, "content_hash", Vec::new());
    let promise = agent
        .call(lane, &cap, "patch", vec![path("app"), Arg::text("public")])
        .expect("queued");
    agent.run();
    let error = promise
        .value()
        .expect_err("the reply does not fit the grant");
    assert_eq!(error.code(), "rpc/provider", "{error}");
    assert_eq!(
        error.provider_code(),
        Some("provider/reply-withheld"),
        "{error}"
    );

    let receipts = agent.receipts();
    assert_eq!(receipts.len(), 2, "one receipt per job");
    match &receipts[1].decision {
        Decision::Admitted => {}
        other => panic!("the write was receipted as {other:?}"),
    }

    // The write landed: the module's content hash moved.
    let after = call(&agent, &cap, lane, "content_hash", Vec::new());
    assert_ne!(before, after, "the patch did not change the module");
}

/// A text replacement on a secret-bearing module is refused uniformly: the
/// reply is the caller's own literal through the install-time redactor, so a
/// candidate that contains the secret would echo the marker and one that does
/// not would echo the text. The `redact` flag does not narrow it: the cone is
/// redacted for every capability (round 32, #1; round 33, F1).
#[test]
fn a_patch_reply_does_not_reveal_the_installed_secret() {
    for redact in [true, false] {
        let mut module = InfinityModule::new();
        let secret = module.push(Inode::Secret(CANARY.into()));
        let app = module.push(Inode::Table {
            fields: vec![("c".to_string(), secret)],
        });
        let root = module.push(Inode::Table {
            fields: vec![("app".to_string(), app)],
        });
        module.set_root(Some(root));

        let mut provider = ModuleProvider::new();
        let object = provider.install(module).expect("install");
        let agent = Agent::with_secret([0x74; 32]);
        let id = agent.register(Box::new(provider));
        let mut attrs = CapAttrs::new(&["patch"]);
        attrs.redact = redact;
        let cap = agent.mint(id, object, attrs).expect("cap");
        let lane = agent
            .create_lane("r10-oracle", Budget::default())
            .expect("lane");

        for candidate in [CANARY, "not-the-secret"] {
            let promise = agent
                .call(
                    lane,
                    &cap,
                    "patch",
                    vec![path("app.c"), Arg::text(candidate)],
                )
                .expect("queued");
            agent.run();
            let error = promise
                .value()
                .expect_err("a text replacement on a secret-bearing module is refused");
            assert_eq!(
                error.code(),
                "rpc/invalid-argument",
                "redact={redact} {candidate:?}: {error}"
            );
        }
    }
}

/// Any kernel refusal after a mutating provider succeeded is a withheld reply,
/// whatever its class: the effect landed and the receipt records it
/// (round 32, #2).
#[test]
fn a_mutating_reply_with_a_structural_secret_is_a_withheld_reply() {
    use active_rpc::receipts::Decision;
    use active_rpc::value::Response;

    struct SecretWriter {
        image: Vec<u8>,
    }

    impl active_rpc::kernel::Provider for SecretWriter {
        fn name(&self) -> &'static str {
            "secret-writer"
        }
        fn methods(&self) -> Vec<String> {
            vec!["write".to_string()]
        }
        fn mutating(&self, _method: &str) -> bool {
            true
        }
        fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
            Ok(Response::Module(self.image.clone()))
        }
    }

    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(CANARY.into()));
    module.set_root(Some(secret));
    let image = active_infinity::encode(&module).expect("encode");

    let agent = Agent::with_secret([0x75; 32]);
    agent.enable_receipts(true);
    let id = agent.register(Box::new(SecretWriter { image }));
    let cap = agent.mint(id, 0, CapAttrs::new(&["write"])).expect("cap");
    let lane = agent
        .create_lane("r10-withheld", Budget::default())
        .expect("lane");
    let promise = agent.call(lane, &cap, "write", Vec::new()).expect("queued");
    agent.run();
    let error = promise.value().expect_err("the reply carries a secret");
    assert_eq!(
        error.provider_code(),
        Some("provider/reply-withheld"),
        "{error}"
    );
    let receipts = agent.receipts();
    assert_eq!(receipts.len(), 1, "one receipt per job");
    match &receipts[0].decision {
        Decision::Admitted => {}
        other => panic!("the write was receipted as {other:?}"),
    }
}

/// A withheld reply is not forgotten by the idempotency cache: replaying the
/// key returns the same outcome instead of running the mutating provider again
/// (round 33, F2).
#[test]
fn a_withheld_reply_is_not_re_executed_by_its_key() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct SecretWriter {
        image: Vec<u8>,
        calls: Arc<AtomicUsize>,
    }

    impl active_rpc::kernel::Provider for SecretWriter {
        fn name(&self) -> &'static str {
            "secret-writer"
        }
        fn methods(&self) -> Vec<String> {
            vec!["write".to_string()]
        }
        fn mutating(&self, _method: &str) -> bool {
            true
        }
        fn invoke(
            &mut self,
            _object: u64,
            _call: &Call,
        ) -> active_rpc::Result<active_rpc::value::Response> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(active_rpc::value::Response::Module(self.image.clone()))
        }
    }

    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(CANARY.into()));
    module.set_root(Some(secret));
    let image = active_infinity::encode(&module).expect("encode");

    let calls = Arc::new(AtomicUsize::new(0));
    let agent = Agent::with_secret([0x76; 32]);
    let id = agent.register(Box::new(SecretWriter {
        image,
        calls: Arc::clone(&calls),
    }));
    let cap = agent.mint(id, 0, CapAttrs::new(&["write"])).expect("cap");
    let lane = agent
        .create_lane("r10-withheld-key", Budget::default())
        .expect("lane");

    let mut outcomes = Vec::new();
    for _ in 0..2 {
        let promise = agent
            .call_idempotent(lane, &cap, "write", Vec::new(), "key-1")
            .expect("queued");
        agent.run();
        let error = promise.value().expect_err("the reply is withheld");
        outcomes.push(error.provider_code().map(str::to_string));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the provider ran once");
    assert_eq!(
        outcomes,
        vec![
            Some("provider/reply-withheld".to_string()),
            Some("provider/reply-withheld".to_string())
        ]
    );
}

/// Bindings are charged against the node ceiling: a two-node module with a
/// thousand names would otherwise make every label pass walk the table inside
/// one charged call (round 35, L-3).
#[test]
fn a_binding_heavy_module_is_refused_against_the_node_ceiling() {
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Str("app".to_string()));
    module.set_root(Some(root));
    for index in 0..1000 {
        module.bind(format!("alias{index}"), root);
    }

    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let agent = Agent::with_secret([0x77; 32]);
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(&["stats"]);
    attrs.budget.max_nodes = 32;
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent
        .create_lane("r10-bindings", Budget::default())
        .expect("lane");
    let promise = agent.call(lane, &cap, "stats", Vec::new()).expect("queued");
    agent.run();
    let error = promise
        .value()
        .expect_err("the binding table is over the node ceiling");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    assert!(format!("{error}").contains("nodes"), "{error}");
}

/// The node ceiling bounds the references a metadata walk traverses, not only
/// the node count: a two-node module with 200 000 fields used to pass
/// `max_nodes = 4` and spend hundreds of milliseconds under a 5 ms grant
/// (round 36, M-1).
#[test]
fn a_wide_table_is_refused_against_the_node_ceiling_before_the_walk() {
    let mut module = InfinityModule::new();
    let leaf = module.push(Inode::Int(1));
    let fields: Vec<(String, active_infinity::NodeId)> = (0..200_000)
        .map(|index| (format!("f{index:06}"), leaf))
        .collect();
    let root = module.push(Inode::Table { fields });
    module.set_root(Some(root));

    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let agent = Agent::with_secret([0x78; 32]);
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(&["stats", "why"]);
    attrs.budget.max_nodes = 4;
    attrs.budget.max_wall_ms = 5;
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent
        .create_lane("r10-wide", Budget::default())
        .expect("lane");

    for (method, args) in [("stats", Vec::new()), ("why", vec![path("f000000")])] {
        let started = std::time::Instant::now();
        let promise = agent.call(lane, &cap, method, args).expect("queued");
        agent.run();
        let error = promise
            .value()
            .expect_err("the walk weight is over the ceiling");
        assert_eq!(error.code(), "rpc/budget-exceeded", "{method}: {error}");
        assert!(format!("{error}").contains("nodes"), "{method}: {error}");
        // The refusal is decided from the precomputed weight, so it precedes
        // the walk.
        assert!(
            started.elapsed() < std::time::Duration::from_millis(100),
            "{method} took {:?}",
            started.elapsed()
        );
    }
}

/// Revoking a sibling durable capability must not release the export pin of a
/// restorable record on the same object: the provided object must stay alive
/// for the restore (round 37, A).
#[test]
fn a_sibling_revoke_does_not_release_an_export_pin() {
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Str("app".to_string()));
    module.set_root(Some(root));

    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let agent = Agent::with_secret([0x79; 32]);
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key([0x95; 32]);
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(&["stats"]);
    attrs.persistence = active_rpc::CapPersistence::Durable;
    let owner = active_rpc::IdentityPolicy::default()
        .admit(
            Some(&active_rpc::PeerIdentity::from_certificate(b"pin-owner")),
            true,
        )
        .expect("admitted");
    let exported = agent
        .mint_bound(&owner, id, object, attrs.clone())
        .expect("cap A");
    let sibling = agent.mint_bound(&owner, id, object, attrs).expect("cap B");
    let record = agent.export_capability(&exported).expect("export A");
    // B is durable but was never exported; revoking it must not touch A's pin.
    agent.revoke(&sibling).expect("revoke B");
    drop(sibling);
    drop(exported);
    let drops = agent.take_drops(id);
    assert!(
        drops.is_empty(),
        "the restorable record lost its object: {drops:?}"
    );
    let restored = agent
        .restore_capability(&record, &owner)
        .expect("restore A");
    let lane = agent
        .create_lane("r10-pin", Budget::default())
        .expect("lane");
    let promise = agent
        .call_as(Some(owner.identity()), lane, &restored, "stats", Vec::new())
        .expect("queued");
    agent.run();
    promise.value().expect("the object is still served");
}

/// A redacted cone keeps `@ai_immutable`: the flag is a guard, not content
/// (round 37, B).
#[test]
fn a_redacting_cone_keeps_the_immutability_guard() {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(CANARY.into()));
    let root = module.push(Inode::Table {
        fields: vec![("pw".to_string(), secret)],
    });
    module.set_root(Some(root));
    module.annotate(secret, AnnotationKind::AiImmutable(true));

    let (agent, cap, lane) = install(module, &["subgraph"], None, true);
    let promise = agent
        .call(lane, &cap, "subgraph", vec![path("pw")])
        .expect("queued");
    agent.run();
    let value = promise.value().expect("subgraph");
    let Value::Module(bytes) = value else {
        panic!("subgraph returns a module: {value:?}");
    };
    let cone = active_rpc::domain::decode_module(&bytes).expect("decode");
    assert!(
        cone.annotations()
            .iter()
            .any(|annotation| matches!(annotation.kind, AnnotationKind::AiImmutable(_))),
        "the guard was dropped: {:?}",
        cone.annotations()
    );
}

/// A field name that cannot be logged safely is refused at install: a label is
/// a dotted path and must stay resolvable, so it is refused instead of
/// scrubbed (round 37, C).
#[test]
fn a_field_name_that_cannot_be_logged_is_refused_at_install() {
    let mut module = InfinityModule::new();
    let leaf = module.push(Inode::Int(1));
    let root = module.push(Inode::Table {
        fields: vec![("a\nFAKE rpc/admitted".to_string(), leaf)],
    });
    module.set_root(Some(root));

    let mut provider = ModuleProvider::new();
    let error = provider
        .install(module)
        .expect_err("a control character in a field name is refused");
    assert_eq!(error.code(), "rpc/payload", "{error}");
}
