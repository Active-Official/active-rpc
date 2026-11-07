//! R-16 round 5: a corrupted image is not opaque, a deep Active value converts
//! without recursing, and a `Response::Module` prints its shape only.

use active_rpc::security::{from_active_value, module_carries_a_secret};
use active_rpc::value::{Response, Value};

/// A payload that starts with the image magic but cannot be decoded is not
/// opaque: it claims to be an image, so it cannot be proven secret-free
/// (R-16 round 5, #1).
#[test]
fn a_corrupted_image_is_not_treated_as_opaque() {
    use active_infinity::{encode, InfinityModule, Inode};

    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(active_infinity::SecretBytes::new(b"canary")));
    module.set_root(Some(secret));
    let mut image = encode(&module).expect("encode");
    assert!(
        module_carries_a_secret(&image),
        "the intact image carries one"
    );

    // Corrupt the payload while keeping the magic: the decoder now refuses it.
    let last = image.len() - 1;
    image[last] ^= 0xFF;
    assert!(
        active_infinity::decode(&image).is_err(),
        "the fixture must fail to decode"
    );
    assert!(
        module_carries_a_secret(&image),
        "an image that cannot be decoded is not provably secret-free"
    );

    // Opaque bytes (no magic) stay opaque: the accepted residual.
    assert!(!module_carries_a_secret(b"not an image at all"));
}

/// A value deeper than the stack converts without recursing (R-16 round 5, #6).
#[test]
fn a_deep_active_value_converts_without_recursing() {
    let mut value = active_core::Value::Null;
    for _ in 0..100_000 {
        value = active_core::Value::Array(vec![value]);
    }
    let converted = from_active_value(&value);
    // The fixture's own drop would recurse on its 100 000 levels, which is the
    // hazard the conversion's ceiling exists for; the converted value is bounded
    // by the wire cap and drops safely.
    std::mem::forget(value);

    let mut depth = 0usize;
    let mut cursor = &converted;
    while let Value::List(items) = cursor {
        assert_eq!(items.len(), 1);
        cursor = &items[0];
        depth += 1;
        if depth > 10_000 {
            break;
        }
    }
    // The wire refuses a container at the cap's depth, so the conversion stops
    // exactly at `MAX_VALUE_DEPTH` (R-16 round 7, L-1: an off-by-one here emits
    // a value the wire cannot encode).
    assert_eq!(
        depth,
        active_rpc::wire::MAX_VALUE_DEPTH,
        "the conversion stops exactly at the wire cap"
    );
    // And the result encodes: the point of the exact bound.
    let envelope = active_rpc::wire::Envelope::request(
        1,
        "value",
        vec![active_rpc::value::Arg::Value(converted)],
    );
    assert!(
        envelope.encode().is_ok(),
        "the converted value is within what the wire accepts"
    );
}

/// A `Response::Module` prints its length, never its bytes (R-16 round 5, #2).
#[test]
fn a_module_response_prints_no_bytes() {
    let payload = vec![0x41u8; 64];
    let printed = format!("{:?}", Response::Module(payload));
    assert!(printed.contains("len"), "{printed}");
    assert!(!printed.contains("65"), "no byte values: {printed}");
    assert!(!printed.contains("A"), "no rendered bytes: {printed}");
    assert!(
        printed.len() < 64,
        "the payload is not in the line: {printed}"
    );
}

/// A redacting caller never receives a magic-prefixed payload that could not be
/// redacted: the arm that returns opaque bytes is unreachable for anything that
/// claims to be an image (R-16 round 6, #1).
#[test]
fn a_corrupted_image_is_not_returned_by_redaction() {
    use active_infinity::{encode, InfinityModule, Inode};
    use active_rpc::security::redact_value;

    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(active_infinity::SecretBytes::new(b"canary")));
    module.set_root(Some(secret));
    let mut image = encode(&module).expect("encode");
    let last = image.len() - 1;
    image[last] ^= 0xFF;
    assert!(
        active_infinity::decode(&image).is_err(),
        "the fixture is corrupt"
    );

    let redacted = redact_value(Value::Module(image.clone()));
    assert_eq!(
        redacted,
        Value::Secret,
        "an image that cannot be redacted collapses"
    );
    let printed = format!("{redacted:?}");
    assert!(
        !printed.contains("canary"),
        "no secret material survives: {printed}"
    );

    // An intact image is redacted, not collapsed, and its secret is gone.
    let intact = encode(&module).expect("encode");
    let redacted = redact_value(Value::Module(intact));
    match &redacted {
        Value::Module(bytes) => {
            let walked = String::from_utf8_lossy(bytes);
            assert!(
                !walked.contains("canary"),
                "the redaction removed the secret"
            );
        }
        other => panic!("an intact image redacts: {other:?}"),
    }

    // Opaque bytes stay opaque: the accepted residual.
    let opaque = Value::Module(b"not an image".to_vec());
    assert_eq!(redact_value(opaque.clone()), opaque);
}

/// The non-redacting egress validates a decodable image, so a trailing tail that
/// a receiver refuses cannot cross it (R-16 round 6, #2).
#[test]
fn an_image_with_a_trailing_byte_is_refused_by_the_egress() {
    use active_infinity::{encode, InfinityModule, Inode};
    use active_rpc::security::assert_no_structural_secrets;

    let mut module = InfinityModule::new();
    let root = module.push(Inode::Str("value".to_string()));
    module.set_root(Some(root));
    let mut image = encode(&module).expect("encode");
    assert_no_structural_secrets(&Value::Module(image.clone())).expect("the image is valid");

    image.push(0x7F);
    let error = assert_no_structural_secrets(&Value::Module(image))
        .expect_err("a trailing tail is refused");
    // The image is refused as secret-material (it fails to decode, so it
    // cannot be proven secret-free), which is an `rpc/provider` class.
    assert!(
        error.code() == "rpc/provider" || error.code() == "rpc/payload",
        "the refusal is a payload fault: {error}"
    );
}
