//! R-16 round 10: a module whose only secret material is a tainted blob is not
//! secret-free, in every domain projection and in the taint set.

use active_infinity::layout::EncodeOpts;
use active_infinity::{encode, encode_with, InfinityModule, Inode, Provenance};
use active_rpc::cap::CapAttrs;
use active_rpc::domain::ModuleProvider;
use active_rpc::value::{Arg, Value};
use active_rpc::{Agent, Budget, CapHandle, LaneId};

const BLOB_HASH: [u8; 32] = [0x5a; 32];
const PARENT: [u8; 32] = [0x5b; 32];

fn module_with_blob(annotation: bool) -> InfinityModule {
    let mut module = InfinityModule::new();
    let blob = module.push(Inode::Blob {
        hash: BLOB_HASH,
        size: 32,
        tainted: true,
        media_type: "application/octet-stream".to_string(),
        payload: None,
    });
    if annotation {
        module.annotate(
            blob,
            active_infinity::AnnotationKind::Intent(format!(
                "checksum blake3:{}",
                active_infinity::ir::hash_hex(&BLOB_HASH)
            )),
        );
    }
    let root = module.push(Inode::Table {
        fields: vec![("blob".to_string(), blob)],
    });
    module.set_root(Some(root));
    module.set_provenance(Some(Provenance {
        producer: Some("test".to_string()),
        timestamp_ms: 1,
        model: None,
        tool: None,
        parent: Some(PARENT),
        entries: Vec::new(),
    }));
    module
}

fn install(
    mut provider: ModuleProvider,
    module: InfinityModule,
    methods: &[&str],
    redact: bool,
) -> (Agent, CapHandle, LaneId) {
    let object = provider.install(module).expect("install");
    let agent = Agent::with_secret([0x73; 32]);
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(methods);
    attrs.redact = redact;
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent
        .create_lane("r16r10", Budget::default())
        .expect("lane");
    (agent, cap, lane)
}

fn call(agent: &Agent, lane: LaneId, cap: &CapHandle, method: &str, args: Vec<Arg>) -> Value {
    let promise = agent.call(lane, cap, method, args).expect("queued");
    agent.run();
    promise.value().expect(method)
}

fn hash_hex(hash: &[u8; 32]) -> String {
    active_infinity::ir::hash_hex(hash)
}

/// The high: a tainted-blob-only module is secret material, so its raw content
/// address and provenance must not leave a non-redacting capability.
#[test]
fn a_tainted_blob_only_module_is_not_secret_free() {
    let provider = ModuleProvider::new();
    let module = module_with_blob(false);
    let raw = encode(&module).expect("encode");
    let raw_hash = active_infinity::content_hash(&raw).expect("hash");
    let (agent, cap, lane) = install(
        provider,
        module,
        &["content_hash", "provenance", "stats"],
        false,
    );

    let answer = call(&agent, lane, &cap, "content_hash", Vec::new());
    let Value::Text(answer) = answer else {
        panic!("a text digest");
    };
    assert_ne!(
        answer,
        format!("blake3:{}", hash_hex(&raw_hash)),
        "the raw digest covers blake3(secret) in the blob"
    );

    let provenance = call(&agent, lane, &cap, "provenance", Vec::new());
    let printed = format!("{provenance:?}");
    assert!(
        !printed.contains("blake3:"),
        "a raw content address leaked through provenance: {printed}"
    );

    let Value::Map(stats) = call(&agent, lane, &cap, "stats", Vec::new()) else {
        panic!("a stats map");
    };
    assert!(
        stats
            .get("secrets")
            .is_some_and(|value| *value != Value::Int(0)),
        "a tainted blob is secret material: {stats:?}"
    );
}

/// The metadata carrier: an annotation that names the blob must be hidden from a
/// redacting caller, in both `annotations` and a `subgraph` cone.
#[test]
fn an_annotation_on_a_tainted_blob_is_hidden() {
    let provider = ModuleProvider::new();
    let module = module_with_blob(true);
    let (agent, cap, lane) = install(provider, module, &["annotations", "subgraph"], true);

    let annotations = call(&agent, lane, &cap, "annotations", Vec::new());
    let printed = format!("{annotations:?}");
    assert!(
        !printed.contains(&hash_hex(&BLOB_HASH)),
        "the blob address leaked through an annotation: {printed}"
    );

    let cone = call(
        &agent,
        lane,
        &cap,
        "subgraph",
        vec![Arg::Value(Value::path("blob"))],
    );
    let Value::Module(bytes) = cone else {
        panic!("a module: {cone:?}");
    };
    let printed = String::from_utf8_lossy(&bytes);
    assert!(
        !printed.contains(&hash_hex(&BLOB_HASH)),
        "the blob address leaked through a cone"
    );
}

/// A patch that removes the blob cannot declassify the module: the flag is
/// sticky, so the pre-patch address stays out of every answer.
#[test]
fn a_patch_cannot_declassify_a_tainted_blob() {
    let provider = ModuleProvider::new();
    let module = module_with_blob(false);
    let (agent, cap, lane) = install(provider, module, &["patch", "provenance"], false);
    let replacement = Value::text("public");
    call(
        &agent,
        lane,
        &cap,
        "patch",
        vec![Arg::Value(Value::path("blob")), Arg::Value(replacement)],
    );
    let provenance = call(&agent, lane, &cap, "provenance", Vec::new());
    let printed = format!("{provenance:?}");
    assert!(
        !printed.contains("blake3:"),
        "the pre-patch address survived the patch: {printed}"
    );
}

/// A streamed secret-free image keeps its identity under a redacting caller: the
/// digest is the address of the stored bytes, not of a re-encoding.
#[test]
fn a_streamed_secret_free_image_keeps_its_address() {
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Str("plain".to_string()));
    module.set_root(Some(root));
    let streamed = encode_with(
        &module,
        EncodeOpts {
            write_hash: true,
            mark_canonical: true,
            streamed: true,
        },
    )
    .expect("encode");
    let expected = active_infinity::content_hash(&streamed).expect("hash");

    let mut provider = ModuleProvider::new();
    let object = provider
        .install_canonical_image(&streamed)
        .expect("install");
    let agent = Agent::with_secret([0x74; 32]);
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(&["content_hash"]);
    attrs.redact = true;
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent
        .create_lane("streamed", Budget::default())
        .expect("lane");
    let answer = call(&agent, lane, &cap, "content_hash", Vec::new());
    assert_eq!(
        answer,
        Value::Text(format!("blake3:{}", hash_hex(&expected))),
        "a redacting caller gets the address of the installed bytes"
    );
}
