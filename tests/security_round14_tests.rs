//! R-16 round 14: every text carrier, a removed blob's sticky address, the
//! provenance text, binary carriers and separated copies.

use active_infinity::layout::Limits;
use active_infinity::{
    encode, AnnotationKind, Constraint, InfinityModule, Inode, PatchOp, Provenance,
    SchemaFieldSpec, TypeSpec, UnitTag,
};
use active_rpc::cap::CapAttrs;
use active_rpc::domain::ModuleProvider;
use active_rpc::value::{Arg, Value};
use active_rpc::{Agent, Budget, CapHandle, LaneId};

const BLOB_HASH: [u8; 32] = [0x5a; 32];

fn hash_hex(hash: &[u8; 32]) -> String {
    active_infinity::ir::hash_hex(hash)
}

fn contains_raw(bytes: &[u8], needle: &[u8; 32]) -> bool {
    bytes.windows(32).any(|window| window == needle)
}

/// A tainted blob plus a root that keeps it reachable.
fn blob_module() -> (InfinityModule, active_infinity::NodeId) {
    let mut module = InfinityModule::new();
    let blob = module.push(Inode::Blob {
        hash: BLOB_HASH,
        size: 8,
        tainted: true,
        media_type: "application/octet-stream".to_string(),
        payload: None,
    });
    (module, blob)
}

fn install(module: InfinityModule, methods: &[&str], redact: bool) -> (Agent, CapHandle, LaneId) {
    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let agent = Agent::with_secret([0x7a; 32]);
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(methods);
    attrs.redact = redact;
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent
        .create_lane("r16r14", Budget::default())
        .expect("lane");
    (agent, cap, lane)
}

fn call(agent: &Agent, lane: LaneId, cap: &CapHandle, method: &str, args: Vec<Arg>) -> Value {
    let promise = agent.call(lane, cap, method, args).expect("queued");
    agent.run();
    promise.value().expect(method)
}

/// F1: a binding name, a constraint, an enum member, a unit name, a patch path,
/// a schema type list and a media type are all carriers the round-13 pass did
/// not scan.
#[test]
fn an_address_in_every_text_carrier_is_scrubbed() {
    let (mut module, blob) = blob_module();
    let address = hash_hex(&BLOB_HASH);
    module.bind(address.clone(), blob);

    let target = module.push(Inode::Int(1));
    let enumerated = module.push(Inode::Constrained {
        target,
        constraint: Constraint::Enum(vec![address.clone()]),
    });
    let pattern = module.push(Inode::Constrained {
        target,
        constraint: Constraint::Pattern(address.clone()),
    });
    let patch = module.push(Inode::Patch(PatchOp::Set {
        path: address.clone(),
        value: target,
    }));
    let schema = module.push(Inode::SchemaField(SchemaFieldSpec {
        typ: TypeSpec::Enum(vec![address.clone()]),
        min: Some(target),
        max: Some(target),
        min_len: None,
        max_len: None,
        pattern: None,
        default: None,
        deprecated: Some(address.clone()),
    }));
    let quantity = module.push(Inode::Quantity {
        value: target,
        unit: UnitTag::Named(address.clone()),
    });
    let labelled = module.push(Inode::Blob {
        hash: [0x11; 32],
        size: 1,
        tainted: false,
        media_type: address.clone(),
        payload: None,
    });
    let root = module.push(Inode::Table {
        fields: vec![
            (address.clone(), blob),
            ("enum".to_string(), enumerated),
            ("pattern".to_string(), pattern),
            ("patch".to_string(), patch),
            ("schema".to_string(), schema),
            ("quantity".to_string(), quantity),
            ("labelled".to_string(), labelled),
        ],
    });
    module.set_root(Some(root));

    let raw = encode(&module).expect("encode");
    assert!(
        String::from_utf8_lossy(&raw).contains(&address),
        "the fixture must carry the address before redaction"
    );
    let redacted = active_rpc::security::redact_module(&raw).expect("redact");
    let printed = String::from_utf8_lossy(&redacted).to_lowercase();
    assert!(
        !printed.contains(&address),
        "a carrier kept the address: {printed}"
    );
    assert!(
        !contains_raw(&redacted, &BLOB_HASH),
        "a carrier kept the bytes"
    );
    let decoded = active_infinity::decode(&redacted).expect("decode");
    active_infinity::validate_canonical(&redacted, Limits::default()).expect("canonical");
    assert!(
        decoded
            .nodes()
            .iter()
            .any(|node| matches!(node, Inode::SchemaField(spec) if spec.deprecated.as_deref() != Some(address.as_str()))),
        "the schema field was replaced whole instead of rewritten"
    );
}

/// F2: a patch that removes the tainted blob must not declassify the address
/// an annotation still quotes; the set is sticky on the slot.
#[test]
fn a_removed_blobs_address_stays_out_of_every_projection() {
    let (mut module, blob) = blob_module();
    module.annotate(
        blob,
        AnnotationKind::Intent(format!("checksum {}", hash_hex(&BLOB_HASH))),
    );
    let root = module.push(Inode::Table {
        fields: vec![("blob".to_string(), blob)],
    });
    module.set_root(Some(root));
    let (agent, cap, lane) = install(module, &["patch", "annotations", "subgraph"], false);

    // A scalar replacement removes the blob from the arena.
    call(
        &agent,
        lane,
        &cap,
        "patch",
        vec![Arg::Value(Value::path("blob")), Arg::Value(Value::Int(1))],
    );
    for (method, args) in [
        ("annotations", Vec::new()),
        ("subgraph", vec![Arg::Value(Value::path("blob"))]),
    ] {
        let answer = call(&agent, lane, &cap, method, args);
        let printed = format!("{answer:?}").to_lowercase();
        let Value::Module(bytes) = &answer else {
            assert!(
                !printed.contains(&hash_hex(&BLOB_HASH)),
                "{method} kept the removed address: {printed}"
            );
            continue;
        };
        assert!(
            !String::from_utf8_lossy(bytes)
                .to_lowercase()
                .contains(&hash_hex(&BLOB_HASH)),
            "{method} kept the removed address"
        );
    }
}

/// F3: the provenance's own text fields are free text, so a bare-hex address in
/// a producer string or an entry key is returned to a non-redacting caller.
#[test]
fn a_provenance_text_that_names_an_address_is_scrubbed() {
    let (mut module, blob) = blob_module();
    let address = hash_hex(&BLOB_HASH);
    module.set_provenance(Some(Provenance {
        producer: Some(address.clone()),
        timestamp_ms: 1,
        model: Some("m".to_string()),
        tool: Some("t".to_string()),
        parent: None,
        entries: vec![active_infinity::ProvEntry {
            key: address.clone(),
            value: active_infinity::ProvValue::Text("value".to_string()),
        }],
    }));
    let root = module.push(Inode::Table {
        fields: vec![("blob".to_string(), blob)],
    });
    module.set_root(Some(root));
    let (agent, cap, lane) = install(module, &["provenance"], false);
    let answer = call(&agent, lane, &cap, "provenance", Vec::new());
    let printed = format!("{answer:?}").to_lowercase();
    assert!(
        !printed.contains(&address),
        "the provenance returned the address: {printed}"
    );
}

/// F4: a blob whose payload embeds the address is the same oracle, and the
/// payload is dropped because its bytes define the identity.
#[test]
fn a_payload_that_embeds_an_address_is_dropped() {
    let (mut module, blob) = blob_module();
    let mut carrier_bytes = BLOB_HASH.to_vec();
    carrier_bytes.extend_from_slice(b"pad!");
    let carrier = module.push(Inode::Blob {
        hash: *blake3::hash(&carrier_bytes).as_bytes(),
        size: carrier_bytes.len() as u64,
        tainted: false,
        media_type: "application/octet-stream".to_string(),
        payload: Some(carrier_bytes),
    });
    let root = module.push(Inode::Table {
        fields: vec![("blob".to_string(), blob), ("carrier".to_string(), carrier)],
    });
    module.set_root(Some(root));
    let raw = encode(&module).expect("encode");
    assert!(
        contains_raw(&raw, &BLOB_HASH),
        "the fixture carries the bytes"
    );
    let redacted = active_rpc::security::redact_module(&raw).expect("redact");
    assert!(
        !contains_raw(&redacted, &BLOB_HASH),
        "the payload copy survived"
    );
}

/// F4: a second blob with the same identity is refused by the library's own
/// encoder, and `redact_module` passes that refusal through: the shape is never
/// published unredacted.
#[test]
fn a_duplicate_identity_is_refused_rather_than_published() {
    let (mut module, blob) = blob_module();
    let duplicate = module.push(Inode::Blob {
        hash: BLOB_HASH,
        size: 32,
        tainted: false,
        media_type: "application/octet-stream".to_string(),
        payload: None,
    });
    let root = module.push(Inode::Table {
        fields: vec![("blob".to_string(), blob), ("dup".to_string(), duplicate)],
    });
    module.set_root(Some(root));
    match encode(&module) {
        Err(_) => {}
        Ok(raw) => match active_rpc::security::redact_module(&raw) {
            Err(error) => assert_eq!(error.code(), "rpc/payload", "{error}"),
            Ok(bytes) => {
                assert!(
                    !contains_raw(&bytes, &BLOB_HASH)
                        && !String::from_utf8_lossy(&bytes)
                            .to_lowercase()
                            .contains(&hash_hex(&BLOB_HASH)),
                    "a duplicate identity was published"
                );
            }
        },
    }
}

/// F4: an extension payload is opaque, so a copy there is dropped.
#[test]
fn an_extension_that_copies_an_address_is_dropped() {
    let (mut module, blob) = blob_module();
    module.set_extensions(vec![(1, BLOB_HASH.to_vec()), (2, b"public".to_vec())]);
    let root = module.push(Inode::Table {
        fields: vec![("blob".to_string(), blob)],
    });
    module.set_root(Some(root));
    let raw = encode(&module).expect("encode");
    let redacted = active_rpc::security::redact_module(&raw).expect("redact");
    assert!(!contains_raw(&redacted, &BLOB_HASH));
    let decoded = active_infinity::decode(&redacted).expect("decode");
    assert_eq!(
        decoded.extensions().len(),
        1,
        "the public extension stays and the copy goes: {:?}",
        decoded.extensions()
    );
}

/// F5: a hyphenated copy decodes to the same address.
#[test]
fn a_separated_copy_of_an_address_is_scrubbed() {
    let (mut module, blob) = blob_module();
    let address = hash_hex(&BLOB_HASH);
    let separated = address
        .as_bytes()
        .chunks(2)
        .map(|pair| std::str::from_utf8(pair).expect("hex"))
        .collect::<Vec<_>>()
        .join("-");
    let text = module.push(Inode::Str(separated.clone()));
    let root = module.push(Inode::Table {
        fields: vec![("blob".to_string(), blob), ("sep".to_string(), text)],
    });
    module.set_root(Some(root));
    let raw = encode(&module).expect("encode");
    let redacted = active_rpc::security::redact_module(&raw).expect("redact");
    let printed = String::from_utf8_lossy(&redacted).to_lowercase();
    // Both forms: the copy itself, and the address once its separators are
    // removed (a scrub that only rewrote the contiguous form would leave the
    // separated copy readable).
    let normalised: String = printed
        .chars()
        .filter(|character| *character != '-' && *character != ':')
        .collect();
    assert!(
        !printed.contains(&separated) && !normalised.contains(&address),
        "the separated copy survived: {printed}"
    );
}

/// R-16 round 15, F1: `evaluate` has no redactor to consult when the cone
/// drops the only blob, so it took its unredacted fast path and returned a
/// text that quotes the address.
#[test]
fn an_evaluated_text_that_quotes_a_blob_address_is_scrubbed() {
    let (mut module, blob) = blob_module();
    let address = hash_hex(&BLOB_HASH);
    let note = module.push(Inode::Str(address.clone()));
    let root = module.push(Inode::Table {
        fields: vec![("blob".to_string(), blob), ("note".to_string(), note)],
    });
    module.set_root(Some(root));
    for redact in [false, true] {
        let (agent, cap, lane) = install(module.clone(), &["evaluate"], redact);
        let value = call(
            &agent,
            lane,
            &cap,
            "evaluate",
            vec![Arg::Value(Value::path("note"))],
        );
        let printed = format!("{value:?}").to_lowercase();
        assert!(
            !printed.contains(&address),
            "evaluate(note) returned the address (redact {redact}): {printed}"
        );
    }
}

/// R-16 round 15, F3: the hex search used to require a UTF-8 payload, so an
/// address followed by a non-UTF-8 byte survived.
#[test]
fn a_payload_copy_with_a_binary_tail_is_dropped() {
    let (mut module, blob) = blob_module();
    let mut payload = hash_hex(&BLOB_HASH).into_bytes();
    payload.push(0xff);
    let carrier = module.push(Inode::Blob {
        hash: *blake3::hash(&payload).as_bytes(),
        size: payload.len() as u64,
        tainted: false,
        media_type: "application/octet-stream".to_string(),
        payload: Some(payload),
    });
    let root = module.push(Inode::Table {
        fields: vec![("blob".to_string(), blob), ("carrier".to_string(), carrier)],
    });
    module.set_root(Some(root));
    let raw = encode(&module).expect("encode");
    let redacted = active_rpc::security::redact_module(&raw).expect("redact");
    let printed = String::from_utf8_lossy(&redacted).to_lowercase();
    assert!(
        !printed.contains(&hash_hex(&BLOB_HASH)),
        "a binary-tailed payload copy survived"
    );
}

/// R-16 round 15, F2: a field name can hold the address, and a metadata label
/// is that name. Every capability must not learn it.
#[test]
fn a_label_that_names_a_tainted_blobs_address_is_hidden() {
    let (mut module, blob) = blob_module();
    let address = hash_hex(&BLOB_HASH);
    let sibling = module.push(Inode::Str("x".to_string()));
    let root = module.push(Inode::Table {
        fields: vec![
            ("blob".to_string(), blob),
            (format!("addr{address}"), sibling),
        ],
    });
    module.set_root(Some(root));
    let methods = ["dependencies", "dependents", "why", "impact"];
    for redact in [false, true] {
        let (agent, cap, lane) = install(module.clone(), &methods, redact);
        for method in methods {
            // Each query takes the root path.
            let value = call(
                &agent,
                lane,
                &cap,
                method,
                vec![Arg::Value(Value::path(""))],
            );
            let printed = format!("{value:?}").to_lowercase();
            assert!(
                !printed.contains(&address),
                "{method} (redact {redact}) returned the address: {printed}"
            );
        }
    }
}
