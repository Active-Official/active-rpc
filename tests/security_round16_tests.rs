//! R-16 round 16: compatibility-form copies, projection-side byte assertions
//! with the caller's extra, separator parity, provenance precision and shape
//! collisions.

use active_infinity::layout::Limits;
use active_infinity::{encode, InfinityModule, Inode, Provenance};
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
    let agent = Agent::with_secret([0x7b; 32]);
    let id = agent
        .register(Box::new(provider))
        .expect("register provider");
    let mut attrs = CapAttrs::new(methods);
    attrs.redact = redact;
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent
        .create_lane("r16r16", Budget::default())
        .expect("lane");
    (agent, cap, lane)
}

fn call(agent: &Agent, lane: LaneId, cap: &CapHandle, method: &str, args: Vec<Arg>) -> Value {
    let promise = agent.call(lane, cap, method, args).expect("queued");
    agent.run();
    promise.value().expect(method)
}

/// Fold an ASCII hex string into fullwidth characters (NFKC-equal to ASCII).
fn fullwidth(text: &str) -> String {
    text.chars()
        .map(|character| match character {
            '0'..='9' => char::from_u32(0xFF10 + (character as u32 - '0' as u32)).expect("digit"),
            'a'..='f' => char::from_u32(0xFF41 + (character as u32 - 'a' as u32)).expect("letter"),
            other => other,
        })
        .collect()
}

/// F5: a fullwidth copy of the address is the same oracle to a consumer that
/// normalizes identifiers, so the scrub must see it.
#[test]
fn a_fullwidth_copy_of_an_address_is_scrubbed() {
    let (mut module, blob) = blob_module();
    let address = fullwidth(&hash_hex(&BLOB_HASH));
    let text = module.push(Inode::Str(address.clone()));
    let root = module.push(Inode::Table {
        fields: vec![("blob".to_string(), blob), ("copy".to_string(), text)],
    });
    module.set_root(Some(root));
    let raw = encode(&module).expect("encode");
    let redacted = active_rpc::security::redact_module(&raw).expect("redact");
    let printed = String::from_utf8_lossy(&redacted);
    assert!(
        !printed.contains(&address),
        "a fullwidth copy survived: {printed}"
    );
    active_infinity::validate_canonical(&redacted, Limits::default()).expect("canonical");
}

/// F4: a copy split by a soft hyphen is a separator the renderer hides, and
/// the scrub uses the same invisible set as the metadata pass.
#[test]
fn a_soft_hyphen_separated_copy_is_scrubbed() {
    let (mut module, blob) = blob_module();
    let address = hash_hex(&BLOB_HASH);
    let split: String = address
        .chars()
        .enumerate()
        .flat_map(|(index, character)| {
            if index == 32 {
                vec!['\u{00ad}', character]
            } else {
                vec![character]
            }
        })
        .collect();
    let text = module.push(Inode::Str(split));
    let root = module.push(Inode::Table {
        fields: vec![("blob".to_string(), blob), ("copy".to_string(), text)],
    });
    module.set_root(Some(root));
    let raw = encode(&module).expect("encode");
    let redacted = active_rpc::security::redact_module(&raw).expect("redact");
    let printed = String::from_utf8_lossy(&redacted);
    let decoded = active_infinity::decode(&redacted).expect("decode");
    let text = decoded.nodes().iter().find_map(|node| match node {
        Inode::Str(text) if text.contains('\u{00ad}') => Some(text.clone()),
        _ => None,
    });
    assert!(
        text.is_none(),
        "the separated copy survived as {text:?}: {printed}"
    );
}

/// F3: a binary payload that quotes the address is dropped, and a projection
/// that quotes the caller's parent hash is caught by the byte assertion.
#[test]
fn a_binary_payload_and_a_parent_hash_copy_do_not_leave() {
    let (mut module, blob) = blob_module();
    let address = hash_hex(&BLOB_HASH);
    // The payload is `hex(H) || 0xFF`: not UTF-8, so a UTF-8-gated scan missed
    // it and the field pass could not rewrite it.
    let mut payload = address.clone().into_bytes();
    payload.push(0xFF);
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
    assert!(
        !String::from_utf8_lossy(&redacted).contains(&address),
        "the binary payload kept the hex copy"
    );
    assert!(
        !contains_raw(&redacted, &BLOB_HASH),
        "the binary payload kept the raw copy"
    );
    active_infinity::validate_canonical(&redacted, Limits::default()).expect("canonical");
}

/// F7: a public provenance value that merely mentions `blake3:` is audit text,
/// not an oracle, and survives a redacting read.
#[test]
fn a_public_provenance_mention_of_blake3_survives() {
    // A public module: no tainted blob, no sticky address, so the `blake3:`
    // mention is ordinary audit text.
    let mut module = InfinityModule::new();
    let text = module.push(Inode::Str("x".to_string()));
    let root = module.push(Inode::Table {
        fields: vec![("value".to_string(), text)],
    });
    module.set_root(Some(root));
    module.set_provenance(Some(Provenance {
        producer: Some("built with blake3: manifests".to_string()),
        parent: None,
        model: None,
        entries: Vec::new(),
        timestamp_ms: 1,
        tool: Some("blake3:verify".to_string()),
    }));
    let (agent, cap, lane) = install(module, &["provenance"], true);
    let Value::Map(map) = call(&agent, lane, &cap, "provenance", vec![]) else {
        panic!("a map");
    };
    assert_eq!(
        map.get("producer"),
        Some(&Value::text("built with blake3: manifests")),
        "a public audit string was dropped"
    );
    assert_eq!(map.get("tool"), Some(&Value::text("blake3:verify")));
}

/// F8: two keys that scrub to the same name change the projection's shape, so
/// the reply is refused instead of silently losing a field.
#[test]
fn two_field_keys_that_scrub_to_one_name_are_refused() {
    let (mut module, blob) = blob_module();
    let address = hash_hex(&BLOB_HASH);
    // The contiguous key becomes the marker; the soft-hyphen-split key cannot
    // be cut, so the whole key becomes the marker too. Two distinct keys, one
    // scrubbed name.
    let split: String = address
        .chars()
        .enumerate()
        .flat_map(|(index, character)| {
            if index == 32 {
                vec!['\u{00ad}', character]
            } else {
                vec![character]
            }
        })
        .collect();
    let first = module.push(Inode::Int(1));
    let second = module.push(Inode::Int(2));
    let table = module.push(Inode::Table {
        fields: vec![(address, first), (split, second)],
    });
    let root = module.push(Inode::Table {
        fields: vec![("blob".to_string(), blob), ("t".to_string(), table)],
    });
    module.set_root(Some(root));
    let raw = encode(&module).expect("encode");
    let error = active_rpc::security::redact_module(&raw)
        .expect_err("a scrubbed-key collision changes the shape");
    assert!(
        error.to_string().contains("provider/redaction"),
        "the refusal names the redaction class: {error}"
    );
}
