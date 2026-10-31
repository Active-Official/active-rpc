//! Domain provider hot path: the canonical hash is computed once and cleared
//! when the module changes, and a refused call leaves the object in place.
//!
//! These tests drive the shipped `Provider::invoke`; they do not re-implement
//! it. The assertions pin the two invariants the M-4.1 refactor introduced:
//! **one** encode per module per version, and no lost module on an error path.

use active_rpc::cap::CapAttrs;
use active_rpc::domain::ModuleProvider;
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::Error;

const SOURCE: &str = r#"
# @intent: "domain provider hot-path fixture"
# @ai_immutable: true
[app]
name        = "domain-hotpath"
environment = env.APP_ENV ?: "test"
debug       = true

let base = "https://api.example.com"
let timeout = 1500ms
let retries = 3

[server]
host         = "127.0.0.1"
port         = 8080
read_timeout = timeout * 2
ratio        = 25%

[services]
auth_url  = "${base}/auth"
users_url = "${base}/users"
weights   = [1, 2, 3, 5, 8, 13]

[database]
host     = "localhost"
password = secret("hotpath-canary")
pool     = 16
"#;

fn fixture() -> (ModuleProvider, u64) {
    let mut provider = ModuleProvider::new();
    let module = active_rpc::domain::module_from_source(SOURCE, "hotpath.active")
        .expect("fixture module parses and lowers");
    let object = provider.install(module);
    (provider, object)
}

fn invoke(provider: &mut ModuleProvider, object: u64, call: &Call) -> Response {
    provider.invoke(object, call).expect("call succeeds")
}

fn text(response: Response) -> String {
    match response {
        Response::Value(Value::Text(text)) => text,
        other => panic!("expected text, got {other:?}"),
    }
}

#[test]
fn content_hash_is_computed_once_and_cached() {
    let (mut provider, object) = fixture();
    assert_eq!(
        provider.cached_hash(object),
        None,
        "install() starts with no cached hash"
    );

    let first = text(invoke(
        &mut provider,
        object,
        &Call::new("content_hash", vec![]),
    ));
    let cached = provider
        .cached_hash(object)
        .expect("the first call fills the cache");

    let encoded =
        active_infinity::encode(provider.module(object).expect("module")).expect("encode");
    let expected = active_infinity::content_hash(&encoded).expect("hash");
    assert_eq!(
        cached, expected,
        "the cached hash is the canonical hash of the module"
    );
    assert_eq!(
        first,
        format!("blake3:{}", active_infinity::ir::hash_hex(&cached))
    );

    let second = text(invoke(
        &mut provider,
        object,
        &Call::new("content_hash", vec![]),
    ));
    assert_eq!(first, second, "the cached answer is stable");
    assert_eq!(
        provider.cached_hash(object),
        Some(cached),
        "a call never changes the cached hash"
    );
}

#[test]
fn install_canonical_image_seeds_the_cache_without_encoding() {
    let module = active_rpc::domain::module_from_source(SOURCE, "hotpath.active").expect("module");
    let bytes = active_infinity::encode(&module).expect("encode");
    let mut provider = ModuleProvider::new();
    let object = provider
        .install_canonical_image(&bytes)
        .expect("canonical bytes install");

    let seeded = provider
        .cached_hash(object)
        .expect("the install path seeds the hash");
    assert_eq!(
        seeded,
        active_infinity::content_hash(&bytes).expect("hash"),
        "the seeded hash is the hash of the bytes that were installed"
    );
    let answered = text(invoke(
        &mut provider,
        object,
        &Call::new("content_hash", vec![]),
    ));
    assert_eq!(
        answered,
        format!("blake3:{}", active_infinity::ir::hash_hex(&seeded))
    );
    assert_eq!(
        provider.module(object).expect("module"),
        &module,
        "the installed module is the decoded image"
    );
}

#[test]
fn install_canonical_image_refuses_a_non_canonical_image() {
    let module = active_rpc::domain::module_from_source(SOURCE, "hotpath.active").expect("module");
    let mut bytes = active_infinity::encode(&module).expect("encode");
    bytes.push(0);
    let mut provider = ModuleProvider::new();
    let error = provider
        .install_canonical_image(&bytes)
        .expect_err("trailing bytes are not canonical");
    assert_eq!(error.code(), "rpc/payload");
    assert_eq!(provider.module_count(), 0, "a refused image is not stored");
}

#[test]
fn patch_clears_the_cached_hash_and_advances_the_module() {
    let (mut provider, object) = fixture();
    let before = text(invoke(
        &mut provider,
        object,
        &Call::new("content_hash", vec![]),
    ));
    assert!(provider.cached_hash(object).is_some());

    let patch = Call::new(
        "patch",
        vec![
            Arg::Value(Value::Path("app.name".to_string())),
            Arg::Value(Value::text("renamed")),
        ],
    );
    let response = invoke(&mut provider, object, &patch);
    let Response::Module(bytes) = response else {
        panic!("patch returns a module");
    };
    // The returned image is the redacted projection; the stored module keeps
    // its secret and must show the replacement at the target path.
    let stored = provider.module(object).expect("module");
    let node = active_rpc::domain::resolve_path(stored, "app.name").expect("path resolves");
    assert_eq!(
        stored.get(node).expect("node"),
        &active_infinity::Inode::Str("renamed".to_string())
    );
    let projected = active_infinity::decode(&bytes).expect("patched image decodes");
    // The projection replaces the secret with a marker, so it is canonical and
    // carries no `Secret` node while the stored module still does.
    active_infinity::validate_canonical(&bytes, active_infinity::Limits::default())
        .expect("the projecton is canonical");
    assert!(
        !projected.nodes().iter().any(|node| node.is_secret()),
        "a capability result never carries secret material"
    );
    assert!(
        stored.nodes().iter().any(|node| node.is_secret()),
        "the stored module keeps its secret"
    );
    assert_eq!(
        provider.cached_hash(object),
        None,
        "a patch invalidates the cached hash"
    );

    let after = text(invoke(
        &mut provider,
        object,
        &Call::new("content_hash", vec![]),
    ));
    assert_ne!(before, after, "the hash follows the change");
    let stored_hash = active_infinity::content_hash(
        &active_infinity::encode(provider.module(object).expect("module")).expect("encode"),
    )
    .expect("hash");
    assert_eq!(
        provider.cached_hash(object),
        Some(stored_hash),
        "the recomputed hash is the hash of the patched module"
    );
}

#[test]
fn a_refused_call_leaves_the_module_in_place() {
    let (mut provider, object) = fixture();
    let node_count = provider.module(object).expect("module").node_count();

    // Missing path argument.
    let error = provider
        .invoke(object, &Call::new("why", vec![]))
        .expect_err("why needs a path");
    assert_eq!(error.code(), "rpc/invalid-argument");
    assert_eq!(
        provider.module_count(),
        1,
        "the object survives the refusal"
    );

    // Path that does not resolve.
    let missing = Call::new(
        "subgraph",
        vec![Arg::Value(Value::Path("nope".to_string()))],
    );
    let error = provider
        .invoke(object, &missing)
        .expect_err("unknown path is refused");
    assert_eq!(error.code(), "rpc/invalid-argument");

    // Method the physics does not grant.
    let error = provider
        .invoke(object, &Call::new("format_disk", vec![]))
        .expect_err("unknown method is refused");
    assert!(matches!(error, Error::MethodNotGranted { .. }));

    let stats = invoke(&mut provider, object, &Call::new("stats", vec![]));
    let Response::Value(Value::Map(stats)) = stats else {
        panic!("stats returns a map");
    };
    assert_eq!(
        stats.get("nodes"),
        Some(&Value::Int(node_count as i64)),
        "the module is unchanged after three refusals"
    );
}

#[test]
fn an_unknown_object_is_refused_without_touching_the_map() {
    let (mut provider, object) = fixture();
    let error = provider
        .invoke(object + 100, &Call::new("stats", vec![]))
        .expect_err("unknown object");
    assert_eq!(error.code(), "rpc/invalid-argument");
    assert!(provider.module(object).is_some());
}

#[test]
fn root_evaluate_answers_from_the_stored_module() {
    let (mut provider, object) = fixture();
    let response = invoke(&mut provider, object, &Call::new("evaluate", vec![]));
    let Response::Value(value) = response else {
        panic!("evaluate returns a value");
    };
    assert_ne!(value, Value::Null, "the fixture evaluates to a record");

    // The slot is intact: the hash still describes the stored module.
    let hash = text(invoke(
        &mut provider,
        object,
        &Call::new("content_hash", vec![]),
    ));
    let expected = active_infinity::content_hash(
        &active_infinity::encode(provider.module(object).expect("module")).expect("encode"),
    )
    .expect("hash");
    assert_eq!(
        hash,
        format!("blake3:{}", active_infinity::ir::hash_hex(&expected))
    );
}

#[test]
fn scoped_evaluate_does_not_replace_the_stored_module() {
    let (mut provider, object) = fixture();
    let before = provider.module(object).expect("module").clone();
    let scoped = Call::new(
        "evaluate",
        vec![Arg::Value(Value::Path("services".to_string()))],
    );
    let response = invoke(&mut provider, object, &scoped);
    assert!(matches!(response, Response::Value(_)));
    assert_eq!(
        provider.module(object).expect("module"),
        &before,
        "a scoped evaluation reads a projection and never writes back"
    );
}

#[test]
fn subgraph_of_a_cone_with_interpolation_and_env_defaults_encodes() {
    let (mut provider, object) = fixture();
    let source_nodes = provider.module(object).expect("module").node_count();
    // `services.auth_url` interpolates `base`; `app.environment` carries an env
    // default. Both node kinds used to be copied with their original child ids,
    // which produced a module whose references pointed outside its arena.
    for path in ["services", "app", "services.auth_url"] {
        let subgraph = Call::new("subgraph", vec![Arg::Value(Value::Path(path.to_string()))]);
        let Response::Module(bytes) = invoke(&mut provider, object, &subgraph) else {
            panic!("subgraph returns a module for {path}");
        };
        let meta = active_infinity::validate(&bytes).expect("the projection is a valid image");
        assert!(meta.nodes >= 1);
        let decoded = active_infinity::decode(&bytes).expect("decode");
        for (index, node) in decoded.nodes().iter().enumerate() {
            for child in node.children() {
                assert!(
                    child.index() < decoded.node_count(),
                    "node {index} in the {path} cone references {} outside a {}-node arena",
                    child.0,
                    decoded.node_count()
                );
            }
        }
        if path == "services" {
            assert!(
                decoded
                    .nodes()
                    .iter()
                    .any(|node| matches!(node, active_infinity::Inode::Interpolate { .. })),
                "the cone keeps its interpolation node"
            );
        }
        assert_eq!(
            provider.module(object).expect("module").node_count(),
            source_nodes,
            "a projection never mutates the source module"
        );
    }
}

#[test]
fn why_follows_an_interpolation_dependency() {
    let (mut provider, object) = fixture();
    let why = Call::new(
        "why",
        vec![Arg::Value(Value::Path("services.auth_url".to_string()))],
    );
    let Response::Labels(labels) = invoke(&mut provider, object, &why) else {
        panic!("why returns labels");
    };
    assert!(
        labels.iter().any(|label| label == "base"),
        "the interpolation's binding is a dependency: {labels:?}"
    );
}

#[test]
fn cap_attrs_still_gate_the_refactor() {
    let (mut provider, object) = fixture();
    let mut read_only = Call::new(
        "patch",
        vec![
            Arg::Value(Value::Path("app.name".to_string())),
            Arg::Value(Value::text("x")),
        ],
    );
    read_only.read_only = true;
    let error = provider
        .invoke(object, &read_only)
        .expect_err("a read-only capability cannot patch");
    assert_eq!(error.code(), "rpc/read-only");

    let patch = Call::new(
        "patch",
        vec![
            Arg::Value(Value::Path("app.name".to_string())),
            Arg::Value(Value::text("x")),
        ],
    );
    // The provider reports `patch` as mutating; the dispatcher uses this to
    // decide whether the call needs a write-capable capability.
    assert!(<ModuleProvider as Provider>::mutating(&provider, "patch"));
    assert!(!<ModuleProvider as Provider>::mutating(&provider, "stats"));
    assert!(matches!(
        invoke(&mut provider, object, &patch),
        Response::Module(_)
    ));
    let attrs = CapAttrs::new(&["stats"]);
    assert!(attrs.methods.iter().any(|method| method == "stats"));
}
