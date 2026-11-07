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

fn contains(bytes: &[u8], needle: &[u8; 32]) -> bool {
    bytes.windows(32).any(|window| window == needle)
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
    // A text replacement is refused on a secret-bearing module (it could copy
    // a literal); a scalar replacement is what a public write looks like.
    let replacement = Value::Int(1);
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

/// A non-redacting capability must not receive a tainted blob's address from
/// `annotations`, even though it may read the module's structure
/// (R-16 round 11, Finding 1).
#[test]
fn a_non_redacting_annotation_cannot_name_a_tainted_blob() {
    let provider = ModuleProvider::new();
    let module = module_with_blob(true);
    let (agent, cap, lane) = install(provider, module, &["annotations"], false);
    let annotations = call(&agent, lane, &cap, "annotations", Vec::new());
    let printed = format!("{annotations:?}");
    assert!(
        !printed.contains(&hash_hex(&BLOB_HASH)),
        "a non-redacting caller received the blob address: {printed}"
    );
}

/// A patch reply's cone carries no tainted blob address, and the blob itself
/// is untainted in the projection (R-16 round 11, Finding 6b).
#[test]
fn a_patch_cone_never_carries_a_tainted_blob_address() {
    let provider = ModuleProvider::new();
    let module = module_with_blob(false);
    let (agent, cap, lane) = install(provider, module, &["patch"], false);
    let cone = call(
        &agent,
        lane,
        &cap,
        "patch",
        vec![Arg::Value(Value::path("blob")), Arg::Value(Value::Int(1))],
    );
    let Value::Module(bytes) = cone else {
        panic!("a cone: {cone:?}");
    };
    let printed = String::from_utf8_lossy(&bytes);
    assert!(
        !printed.contains(&hash_hex(&BLOB_HASH)),
        "the cone leaked the address"
    );
}

/// Two distinct tainted blobs both lose their address, and the projection is
/// still a canonical image (R-16 round 11, Finding 6c).
#[test]
fn two_tainted_blobs_both_lose_their_address() {
    let mut module = InfinityModule::new();
    let first = module.push(Inode::Blob {
        hash: [0x31; 32],
        size: 8,
        tainted: true,
        media_type: "application/octet-stream".to_string(),
        payload: None,
    });
    let second = module.push(Inode::Blob {
        hash: [0x32; 32],
        size: 8,
        tainted: true,
        media_type: "application/octet-stream".to_string(),
        payload: None,
    });
    let root = module.push(Inode::Table {
        fields: vec![("a".to_string(), first), ("b".to_string(), second)],
    });
    module.set_root(Some(root));
    let redacted = active_rpc::security::redact_module(&encode(&module).expect("encode"))
        .expect("a redacted image");
    assert!(!contains(&redacted, &[0x31; 32]));
    assert!(!contains(&redacted, &[0x32; 32]));
    active_infinity::validate_canonical(&redacted, active_infinity::Limits::default())
        .expect("the projection is canonical");
}

/// A tainted blob's `media_type` is an operator-facing label that can be
/// secret-derived, and a text that quotes the address must go even when the
/// annotation names another node (R-16 round 12, F1 and F4). An `AiImmutable`
/// flag carries no text, so it survives (F3).
#[test]
fn a_tainted_blobs_media_type_and_quoted_address_do_not_survive() {
    let mut module = InfinityModule::new();
    let blob = module.push(Inode::Blob {
        hash: BLOB_HASH,
        size: 64,
        tainted: true,
        media_type: "application/x-canary-secret".to_string(),
        payload: None,
    });
    let root = module.push(Inode::Table {
        fields: vec![("blob".to_string(), blob)],
    });
    module.set_root(Some(root));
    module.annotate(
        root,
        active_infinity::AnnotationKind::Intent(format!("see blake3:{}", hash_hex(&BLOB_HASH))),
    );
    module.annotate(blob, active_infinity::AnnotationKind::AiImmutable(true));

    let raw = encode(&module).expect("encode");
    assert!(String::from_utf8_lossy(&raw).contains("canary-secret"));
    let redacted = active_rpc::security::redact_module(&raw).expect("redact");
    let printed = String::from_utf8_lossy(&redacted);
    assert!(
        !printed.contains("canary-secret"),
        "the media type survived the projection"
    );
    assert!(
        !printed.contains(&hash_hex(&BLOB_HASH)),
        "a text that quotes the address survived"
    );

    let decoded = active_infinity::decode(&redacted).expect("decode");
    // Canonical numbering reorders nodes; find the blob by shape.
    let (media_type, tainted) = decoded
        .nodes()
        .iter()
        .find_map(|node| match node {
            active_infinity::Inode::Blob {
                media_type,
                tainted,
                ..
            } => Some((media_type.clone(), *tainted)),
            _ => None,
        })
        .expect("the projection still carries the blob");
    assert_eq!(media_type, active_rpc::security::SECRET_MARKER);
    assert!(!tainted, "the sanitized projection is not tainted");
    assert_eq!(
        decoded.annotations().len(),
        1,
        "only the text annotation was dropped: {:?}",
        decoded.annotations()
    );
    assert!(matches!(
        decoded.annotations()[0].kind,
        active_infinity::AnnotationKind::AiImmutable(true)
    ));
}

/// A text copy of a tainted blob's address is scrubbed in every case: an
/// uppercase string, a field name, and an extra address the caller names
/// (R-16 round 13, F1-F3).
#[test]
fn a_text_copy_of_an_address_is_scrubbed() {
    let mut module = InfinityModule::new();
    let blob = module.push(Inode::Blob {
        hash: BLOB_HASH,
        size: 8,
        tainted: true,
        media_type: "application/octet-stream".to_string(),
        payload: None,
    });
    let shout = module.push(Inode::Str(hash_hex(&BLOB_HASH).to_uppercase()));
    let root = module.push(Inode::Table {
        fields: vec![
            ("blob".to_string(), blob),
            (format!("addr{}", hash_hex(&BLOB_HASH)), shout),
        ],
    });
    module.set_root(Some(root));
    let raw = encode(&module).expect("encode");
    let redacted = active_rpc::security::redact_module(&raw).expect("redact");
    let printed = String::from_utf8_lossy(&redacted).to_lowercase();
    assert!(
        !printed.contains(&hash_hex(&BLOB_HASH)),
        "an address survived as a text or a field name"
    );

    // An address the caller names (a pre-patch lineage or the image's own) is
    // scrubbed by the derived-module helper too.
    let patch_hash = [0x6bu8; 32];
    let mut derived = InfinityModule::new();
    let text = derived.push(Inode::Str(hash_hex(&patch_hash)));
    derived.set_root(Some(text));
    let redactor = active_rpc::security::redactor_for(&derived);
    active_rpc::security::redact_derived_with(&mut derived, &redactor, &[patch_hash])
        .expect("redact");
    let printed = String::from_utf8_lossy(&encode(&derived).expect("encode")).to_lowercase();
    assert!(
        !printed.contains(&hash_hex(&patch_hash)),
        "the extra address survived"
    );
}
