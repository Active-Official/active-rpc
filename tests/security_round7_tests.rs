//! R-16 round 7: the generic redaction helper drops the provenance of a
//! secret-bearing image, a secret-free image keeps its bytes, the egress proves
//! canonical form, and the depth walk agrees with the conversion.

use active_core::Value as ActiveValue;
use active_infinity::layout::EncodeOpts;
use active_infinity::{
    encode, encode_with, InfinityModule, Inode, ProvEntry, ProvValue, Provenance,
};
use active_rpc::security::{
    active_value_too_deep, assert_no_structural_secrets, check_module_payload, from_active_value,
    redact_value,
};
use active_rpc::value::Value;

const PARENT: [u8; 32] = [0x11; 32];
const HASH_ENTRY: [u8; 32] = [0x22; 32];

fn provenance() -> Provenance {
    Provenance {
        producer: Some("test".to_string()),
        parent: Some(PARENT),
        entries: vec![ProvEntry {
            key: "h".to_string(),
            value: ProvValue::Hash(HASH_ENTRY),
        }],
        ..Provenance::default()
    }
}

fn contains(bytes: &[u8], needle: &[u8; 32]) -> bool {
    bytes.windows(32).any(|window| window == needle)
}

/// The library drops a provenance entry that *is* a secret literal, not the
/// content address of a secret-bearing image. A redacting caller used to
/// receive that address, an offline equality oracle over the secret heap.
#[test]
fn redaction_drops_the_provenance_of_a_secret_bearing_image() {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(active_infinity::SecretBytes::new(b"canary")));
    module.set_root(Some(secret));
    module.set_provenance(Some(provenance()));
    let image = encode(&module).expect("encode");
    assert!(contains(&image, &PARENT), "the fixture carries the oracle");

    let redacted = redact_value(Value::Module(image));
    let Value::Module(bytes) = redacted else {
        panic!("an intact image is redacted, not collapsed");
    };
    assert!(
        !contains(&bytes, &PARENT),
        "the parent content address survived redaction"
    );
    assert!(
        !contains(&bytes, &HASH_ENTRY),
        "a hash provenance entry survived redaction"
    );
    assert!(
        !String::from_utf8_lossy(&bytes).contains("canary"),
        "the secret survived"
    );
    let decoded = active_infinity::decode(&bytes).expect("the redacted image decodes");
    assert!(
        decoded.provenance().is_none(),
        "a redacted secret-bearing image carries no provenance"
    );
}

/// A secret-free image is returned untouched: rewriting it dropped
/// `FLAG_STREAMED` and changed an identity nothing had to change.
#[test]
fn a_secret_free_image_keeps_its_bytes_under_redaction() {
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Str("plain".to_string()));
    module.set_root(Some(root));
    module.set_provenance(Some(provenance()));
    let streamed = encode_with(
        &module,
        EncodeOpts {
            write_hash: true,
            mark_canonical: true,
            streamed: true,
        },
    )
    .expect("encode");
    check_module_payload(&streamed).expect("a streamed canonical image is accepted");
    assert_eq!(
        redact_value(Value::Module(streamed.clone())),
        Value::Module(streamed),
        "nothing needed redaction, so the bytes and the flag stay"
    );
}

/// A decodable but non-canonical image is refused by the egress, because the
/// receiver's install gate refuses it: two byte strings must not name one
/// module.
#[test]
fn a_non_canonical_image_is_refused_by_the_egress() {
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Str("plain".to_string()));
    module.set_root(Some(root));
    let non_canonical = encode_with(
        &module,
        EncodeOpts {
            write_hash: true,
            mark_canonical: false,
            streamed: false,
        },
    )
    .expect("encode");
    assert!(
        active_infinity::validate(&non_canonical).is_ok(),
        "the fixture is structurally valid"
    );
    assert!(
        active_infinity::decode(&non_canonical).is_ok(),
        "the fixture decodes"
    );
    let error = check_module_payload(&non_canonical).expect_err("canonicity is not proven");
    assert_eq!(error.code(), "rpc/payload");
    assert_eq!(
        assert_no_structural_secrets(&Value::Module(non_canonical.clone()))
            .expect_err("the egress applies the receiver's proof")
            .code(),
        "rpc/payload"
    );
    assert_eq!(
        redact_value(Value::Module(non_canonical)),
        Value::Secret,
        "a redacting caller does not receive an image no receiver would install"
    );
}

/// The depth walk roots at 0 and applies the conversion's rule, so a value it
/// accepts converts and encodes; one it refuses would have been truncated.
#[test]
fn the_depth_walk_agrees_with_the_conversion() {
    let limit = active_rpc::wire::MAX_VALUE_DEPTH;
    let mut value = ActiveValue::Null;
    for _ in 0..limit {
        value = ActiveValue::Array(vec![value]);
    }
    assert!(
        !active_value_too_deep(&value, limit),
        "a wire-legal 64-container value must not be refused"
    );
    let converted = from_active_value(&value);
    let envelope = active_rpc::wire::Envelope::request(
        1,
        "value",
        vec![active_rpc::value::Arg::Value(converted)],
    );
    assert!(envelope.encode().is_ok(), "the accepted value encodes");

    // One more container is past the conversion's cap.
    let mut deeper = ActiveValue::Null;
    for _ in 0..=limit {
        deeper = ActiveValue::Array(vec![deeper]);
    }
    assert!(
        active_value_too_deep(&deeper, limit),
        "a container at the cap would be truncated"
    );

    // A duration at the cap becomes a map whose entries would sit past it.
    let mut duration = ActiveValue::DurationMs(5);
    for _ in 0..limit {
        duration = ActiveValue::Array(vec![duration]);
    }
    assert!(
        active_value_too_deep(&duration, limit),
        "a synthetic map at the cap cannot encode its entries"
    );
}
