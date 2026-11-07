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
    assert!(
        (1..=active_rpc::wire::MAX_VALUE_DEPTH).contains(&depth),
        "the conversion is bounded by the wire cap: {depth}"
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
