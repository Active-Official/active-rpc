//! R-16 round 9: a tainted blob's content address is secret-derived and does
//! not survive a projection, and both egress gates classify a module the same
//! way.

use active_infinity::layout::EncodeOpts;
use active_infinity::{encode, encode_with, InfinityModule, Inode};
use active_rpc::security::{
    assert_no_secret_material, assert_no_structural_secrets, redact_module, redact_value,
};
use active_rpc::value::Value;

const BLOB_HASH: [u8; 32] = [0x77; 32];

fn contains(bytes: &[u8], needle: &[u8; 32]) -> bool {
    bytes.windows(32).any(|window| window == needle)
}

/// A module whose only secret is a tainted blob: the blob hash is
/// `blake3(secret)` by definition, and redaction must not carry it.
fn tainted_blob_module(blob_hash: [u8; 32]) -> InfinityModule {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(active_infinity::SecretBytes::new(b"canary")));
    let blob = module.push(Inode::Blob {
        hash: blob_hash,
        size: 64,
        tainted: true,
        media_type: "application/octet-stream".to_string(),
        payload: None,
    });
    let root = module.push(Inode::Table {
        fields: vec![("blob".to_string(), blob), ("s".to_string(), secret)],
    });
    module.set_root(Some(root));
    module
}

#[test]
fn a_tainted_blob_address_does_not_survive_redaction() {
    let raw = encode(&tainted_blob_module(BLOB_HASH)).expect("encode");
    let redacted = redact_module(&raw).expect("redact the module");
    assert!(
        !contains(&redacted, &BLOB_HASH),
        "the blob's content address survived the redaction"
    );
    let Value::Module(redacted_value) = redact_value(Value::Module(raw)) else {
        panic!("an intact image is redacted, not collapsed");
    };
    assert!(
        !contains(&redacted_value, &BLOB_HASH),
        "the redacting caller received the blob's content address"
    );

    // Two modules whose only difference is the secret-derived blob hash must
    // share one redacted projection (the hash was the oracle).
    let first =
        redact_module(&encode(&tainted_blob_module([0x11; 32])).expect("encode")).expect("redact");
    let second =
        redact_module(&encode(&tainted_blob_module([0x22; 32])).expect("encode")).expect("redact");
    assert_eq!(first, second, "the blob hash must not enter the projection");
}

/// Both gates classify a module the same way: opaque passes, a corrupt image and
/// a secret-bearing image are `provider/secret-material`, a canonical secret-free
/// image passes, and a decodable non-canonical image is a payload fault.
#[test]
fn both_egress_gates_classify_a_module_the_same_way() {
    let opaque = Value::Module(b"not an image".to_vec());
    let mut secret = InfinityModule::new();
    let node = secret.push(Inode::Secret(active_infinity::SecretBytes::new(b"canary")));
    secret.set_root(Some(node));
    let secret = Value::Module(encode(&secret).expect("encode"));
    let mut plain = InfinityModule::new();
    let node = plain.push(Inode::Str("plain".to_string()));
    plain.set_root(Some(node));
    let plain = Value::Module(encode(&plain).expect("encode"));
    let non_canonical = Value::Module(
        encode_with(
            &plain_module(),
            EncodeOpts {
                write_hash: true,
                mark_canonical: false,
                streamed: false,
            },
        )
        .expect("encode"),
    );
    let mut corrupt_bytes = encode(&plain_module()).expect("encode");
    let last = corrupt_bytes.len() - 1;
    corrupt_bytes[last] ^= 0xFF;
    let corrupt = Value::Module(corrupt_bytes);

    for gate in [assert_no_structural_secrets, assert_no_secret_material] {
        assert!(gate(&opaque).is_ok(), "opaque bytes pass");
        assert_eq!(
            gate(&secret)
                .expect_err("a secret image never crosses")
                .code(),
            "rpc/provider"
        );
        assert_eq!(
            gate(&corrupt)
                .expect_err("a corrupt image fails closed")
                .code(),
            "rpc/provider"
        );
        assert!(gate(&plain).is_ok(), "a canonical secret-free image passes");
        assert_eq!(
            gate(&non_canonical)
                .expect_err("non-canonical bytes are a payload fault")
                .code(),
            "rpc/payload"
        );
    }
}

fn plain_module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let node = module.push(Inode::Str("plain".to_string()));
    module.set_root(Some(node));
    module
}
