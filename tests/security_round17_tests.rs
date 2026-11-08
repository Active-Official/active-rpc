//! R-16 round 17: provenance and raw-text oracles, compatibility separators,
//! non-UTF-8 compatibility payloads, enum collisions and the zero-hash sentinel.

use active_infinity::layout::Limits;
use active_infinity::{encode, AnnotationKind, Constraint, InfinityModule, Inode, Provenance};
use active_rpc::cap::CapAttrs;
use active_rpc::domain::ModuleProvider;
use active_rpc::value::{Arg, Value};
use active_rpc::{Agent, Budget, CapHandle, LaneId};

const CANARY: &str = "r16r17-canary";

fn hash_hex(hash: &[u8; 32]) -> String {
    active_infinity::ir::hash_hex(hash)
}

fn install(module: InfinityModule, methods: &[&str], redact: bool) -> (Agent, CapHandle, LaneId) {
    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let agent = Agent::with_secret([0x7c; 32]);
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(methods);
    attrs.redact = redact;
    let cap = agent.mint(id, object, attrs).expect("cap");
    let lane = agent
        .create_lane("r16r17", Budget::default())
        .expect("lane");
    (agent, cap, lane)
}

fn call(agent: &Agent, lane: LaneId, cap: &CapHandle, method: &str, args: Vec<Arg>) -> Value {
    let promise = agent.call(lane, cap, method, args).expect("queued");
    agent.run();
    promise.value().expect(method)
}

fn text_contains(value: &Value, needle: &str) -> bool {
    match value {
        Value::Text(text) => text.contains(needle),
        Value::List(items) => items.iter().any(|item| text_contains(item, needle)),
        Value::Map(map) => map.values().any(|item| text_contains(item, needle)),
        _ => false,
    }
}

/// F1: a secret module's provenance parent (and a text copying it) is not an
/// oracle to `provenance`, `annotations`, `evaluate` or `subgraph`.
#[test]
fn a_provenance_parent_does_not_leave_any_projection() {
    let parent = [0x44u8; 32];
    let parent_hex = hash_hex(&parent);
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(CANARY.into()));
    let copy = module.push(Inode::Str(parent_hex.clone()));
    let root = module.push(Inode::Table {
        fields: vec![("s".to_string(), secret), ("copy".to_string(), copy)],
    });
    module.set_root(Some(root));
    module.annotate(root, AnnotationKind::Intent(format!("parent {parent_hex}")));
    module.set_provenance(Some(Provenance {
        producer: Some("test".to_string()),
        parent: Some(parent),
        model: None,
        tool: None,
        entries: Vec::new(),
        timestamp_ms: 1,
    }));
    let (agent, cap, lane) = install(module, &["provenance", "annotations", "evaluate"], true);

    for method in ["provenance", "annotations", "evaluate"] {
        let answer = call(&agent, lane, &cap, method, vec![]);
        assert!(
            !text_contains(&answer, &parent_hex),
            "{method} served the parent address: {answer:?}"
        );
    }
}

/// Every folded compatibility separator splits a copy (R-16 round 18, F5).
#[test]
fn every_folded_separator_splits_a_copy() {
    let separators = [
        '\u{ff1a}', '\u{fe13}', '\u{2236}', '\u{ff0d}', '\u{fe63}', '\u{ff3f}', '\u{fe33}',
        '\u{fe4d}', '\u{fe4e}', '\u{fe4f}',
    ];
    for (index, separator) in separators.into_iter().enumerate() {
        let hash = [(index as u8) + 0x60; 32];
        let address = hash_hex(&hash);
        let split = format!("{}{}{}", &address[..32], separator, &address[32..]);
        let mut module = InfinityModule::new();
        let blob = module.push(Inode::Blob {
            hash,
            size: 8,
            tainted: true,
            media_type: "application/octet-stream".to_string(),
            payload: None,
        });
        let copy = module.push(Inode::Str(split.clone()));
        let root = module.push(Inode::Table {
            fields: vec![("blob".to_string(), blob), ("copy".to_string(), copy)],
        });
        module.set_root(Some(root));
        let raw = encode(&module).expect("encode");
        let redacted = active_rpc::security::redact_module(&raw).expect("redact");
        assert!(
            !String::from_utf8_lossy(&redacted).contains(&split),
            "a copy split by U+{:04X} survived",
            separator as u32
        );
    }
}

/// A raw (non-hex) 32-byte address quoted in a text is hidden on the Value
/// paths (R-16 round 17, F9).
#[test]
fn a_raw_address_copy_in_a_text_is_hidden() {
    let raw = [0x41u8; 32];
    let text = String::from_utf8(raw.to_vec()).expect("ASCII");
    let mut module = InfinityModule::new();
    let blob = module.push(Inode::Blob {
        hash: raw,
        size: 8,
        tainted: true,
        media_type: "application/octet-stream".to_string(),
        payload: None,
    });
    let secret = module.push(Inode::Secret(CANARY.into()));
    let copy = module.push(Inode::Str(text.clone()));
    let root = module.push(Inode::Table {
        fields: vec![
            ("blob".to_string(), blob),
            ("s".to_string(), secret),
            ("copy".to_string(), copy),
        ],
    });
    module.set_root(Some(root));
    module.annotate(root, AnnotationKind::Intent(text.clone()));
    module.set_provenance(Some(Provenance {
        producer: Some(text.clone()),
        parent: None,
        model: None,
        tool: None,
        entries: Vec::new(),
        timestamp_ms: 1,
    }));
    let (agent, cap, lane) = install(module, &["provenance", "annotations"], true);
    for method in ["provenance", "annotations"] {
        let answer = call(&agent, lane, &cap, method, vec![]);
        assert!(
            !text_contains(&answer, &text),
            "{method} served the raw address: {answer:?}"
        );
    }

    // A non-redacting capability still must not receive the annotation text.
    let mut module = InfinityModule::new();
    let blob = module.push(Inode::Blob {
        hash: raw,
        size: 8,
        tainted: true,
        media_type: "application/octet-stream".to_string(),
        payload: None,
    });
    let leaf = module.push(Inode::Str("x".to_string()));
    let root = module.push(Inode::Table {
        fields: vec![("blob".to_string(), blob), ("leaf".to_string(), leaf)],
    });
    module.set_root(Some(root));
    module.annotate(leaf, AnnotationKind::Intent(text.clone()));
    let (agent, cap, lane) = install(module, &["annotations"], false);
    let answer = call(&agent, lane, &cap, "annotations", vec![]);
    assert!(
        !text_contains(&answer, &text),
        "a non-redacting read served the raw annotation: {answer:?}"
    );
}

/// A fullwidth-colon split copy is a separators split to a consumer that
/// normalizes, and the scrub folds it (R-16 round 17, F3).
#[test]
fn a_fullwidth_separator_split_copy_is_scrubbed() {
    let hash = [0x5bu8; 32];
    let address = hash_hex(&hash);
    let split = format!("{}{}{}", &address[..32], '\u{ff1a}', &address[32..]);
    let mut module = InfinityModule::new();
    let blob = module.push(Inode::Blob {
        hash,
        size: 8,
        tainted: true,
        media_type: "application/octet-stream".to_string(),
        payload: None,
    });
    let copy = module.push(Inode::Str(split.clone()));
    let root = module.push(Inode::Table {
        fields: vec![("blob".to_string(), blob), ("copy".to_string(), copy)],
    });
    module.set_root(Some(root));
    let raw = encode(&module).expect("encode");
    let redacted = active_rpc::security::redact_module(&raw).expect("redact");
    let printed = String::from_utf8_lossy(&redacted);
    assert!(
        !printed.contains(&split),
        "the fullwidth-separated copy survived"
    );
    active_infinity::validate_canonical(&redacted, Limits::default()).expect("canonical");
}

/// A copy split by U+2028 (line separator) is scrubbed: the separator set is
/// the invisible predicate minus ASCII whitespace (R-16 round 17, F4).
#[test]
fn a_line_separator_split_copy_is_scrubbed() {
    let hash = [0x5cu8; 32];
    let address = hash_hex(&hash);
    let split = format!("{}{}{}", &address[..32], '\u{2028}', &address[32..]);
    let mut module = InfinityModule::new();
    let blob = module.push(Inode::Blob {
        hash,
        size: 8,
        tainted: true,
        media_type: "application/octet-stream".to_string(),
        payload: None,
    });
    let copy = module.push(Inode::Str(split.clone()));
    let root = module.push(Inode::Table {
        fields: vec![("blob".to_string(), blob), ("copy".to_string(), copy)],
    });
    module.set_root(Some(root));
    let raw = encode(&module).expect("encode");
    let redacted = active_rpc::security::redact_module(&raw).expect("redact");
    assert!(
        !String::from_utf8_lossy(&redacted).contains(&split),
        "the U+2028-separated copy survived"
    );
}

/// A non-UTF-8 payload that carries the fullwidth address is dropped: the
/// compat scan no longer requires the whole payload to be valid UTF-8
/// (R-16 round 17, F5).
#[test]
fn a_non_utf8_fullwidth_payload_is_dropped() {
    let hash = [0x5du8; 32];
    let address = hash_hex(&hash);
    let fullwidth: String = address
        .chars()
        .map(|character| match character {
            '0'..='9' => char::from_u32(0xFF10 + (character as u32 - '0' as u32)).expect("digit"),
            'a'..='f' => char::from_u32(0xFF41 + (character as u32 - 'a' as u32)).expect("letter"),
            other => other,
        })
        .collect();
    let mut payload = fullwidth.into_bytes();
    payload.push(0xFF);
    let mut module = InfinityModule::new();
    let blob = module.push(Inode::Blob {
        hash,
        size: 8,
        tainted: true,
        media_type: "application/octet-stream".to_string(),
        payload: None,
    });
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
    let decoded = active_infinity::decode(&redacted).expect("decode");
    let carrier = decoded
        .nodes()
        .iter()
        .filter_map(|node| match node {
            Inode::Blob { payload, .. } => Some(payload.is_some()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        !carrier.iter().any(|present| *present),
        "the non-UTF-8 fullwidth payload survived"
    );
}

/// Two enum members that scrub to one marker are refused, not deduplicated
/// (R-16 round 17, F11).
#[test]
fn two_enum_members_that_scrub_to_one_are_refused() {
    let hash = [0x5eu8; 32];
    let address = hash_hex(&hash);
    let split = format!("{}{}{}", &address[..32], '\u{00ad}', &address[32..]);
    let mut module = InfinityModule::new();
    let blob = module.push(Inode::Blob {
        hash,
        size: 8,
        tainted: true,
        media_type: "application/octet-stream".to_string(),
        payload: None,
    });
    let target = module.push(Inode::Int(1));
    let constrained = module.push(Inode::Constrained {
        target,
        constraint: Constraint::Enum(vec![address, split]),
    });
    let root = module.push(Inode::Table {
        fields: vec![("blob".to_string(), blob), ("c".to_string(), constrained)],
    });
    module.set_root(Some(root));
    let raw = encode(&module).expect("encode");
    let error = active_rpc::security::redact_module(&raw)
        .expect_err("two enum members that scrub to one marker change the type");
    assert!(
        error.to_string().contains("provider/redaction"),
        "the refusal names the redaction class: {error}"
    );
}

/// A tainted blob whose hash is the all-zero sentinel still redacts: the
/// assertion skips the sentinel instead of treating it as a secret address
/// (R-16 round 17, F10).
#[test]
fn a_zero_hash_tainted_blob_redacts() {
    let mut module = InfinityModule::new();
    let blob = module.push(Inode::Blob {
        hash: [0u8; 32],
        size: 8,
        tainted: true,
        media_type: "application/octet-stream".to_string(),
        payload: None,
    });
    let root = module.push(Inode::Table {
        fields: vec![("blob".to_string(), blob)],
    });
    module.set_root(Some(root));
    let raw = encode(&module).expect("encode");
    let redacted = active_rpc::security::redact_module(&raw).expect("the sentinel is not a secret");
    active_infinity::validate_canonical(&redacted, Limits::default()).expect("canonical");
}
