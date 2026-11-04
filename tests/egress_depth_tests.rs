//! F-04: the egress secret walks are iterative.
//!
//! A provider builds its answer in process, so the kernel's wire depth ceiling
//! is not the only way a value arrives. These tests build values far deeper
//! than the Rust stack would survive with a recursive walk and drive the
//! shipped helpers.

use active_rpc::security::{assert_no_secret_material, assert_no_structural_secrets, redact_value};
use active_rpc::Value;

/// A chain of nested one-element lists, `depth` deep.
fn deep_list(depth: usize, leaf: Value) -> Value {
    let mut value = leaf;
    for _ in 0..depth {
        value = Value::List(vec![value]);
    }
    value
}

/// A chain of nested one-entry maps, `depth` deep.
fn deep_map(depth: usize, leaf: Value) -> Value {
    let mut value = leaf;
    for _ in 0..depth {
        let mut entry = std::collections::BTreeMap::new();
        entry.insert("k".to_string(), value);
        value = Value::Map(entry);
    }
    value
}

const DEPTH: usize = 10_000;

#[test]
fn a_deep_value_with_a_secret_is_refused_without_overflowing() {
    let value = deep_list(DEPTH, Value::Secret);
    let error = assert_no_secret_material(&value).expect_err("the secret is at the bottom");
    assert_eq!(error.code(), "rpc/provider", "{error}");
    // `Value`'s derived `Drop` recurses (documented in `value.rs`); leaking the
    // fixture keeps this test about the walk and not about the drop.
    std::mem::forget(value);

    let value = deep_map(DEPTH, Value::Secret);
    let error = assert_no_secret_material(&value).expect_err("the secret is at the bottom");
    assert_eq!(error.code(), "rpc/provider", "{error}");
    std::mem::forget(value);
}

#[test]
fn a_deep_value_without_a_secret_is_accepted() {
    let value = deep_list(DEPTH, Value::Int(1));
    assert_no_secret_material(&value).expect("nothing secret");
    assert_no_structural_secrets(&value).expect("nothing structural");
    std::mem::forget(value);
}

/// `redact_value` preserves the shape of a deep value and does not recurse.
#[test]
fn redaction_walks_a_deep_value_iteratively() {
    let value = deep_list(DEPTH, Value::Secret);
    let redacted = redact_value(value);
    let mut depth = 0usize;
    let mut current = &redacted;
    loop {
        match current {
            Value::List(items) if items.len() == 1 => {
                depth += 1;
                current = &items[0];
            }
            Value::Secret => break,
            other => panic!("unexpected node {other:?} at depth {depth}"),
        }
    }
    assert_eq!(depth, DEPTH, "every level survived the walk");
    std::mem::forget(redacted);
}

/// The map rule still holds after the rewrite: a marker key collapses the map.
#[test]
fn a_marker_key_still_collapses_the_map() {
    let mut entry = std::collections::BTreeMap::new();
    entry.insert("***SECRET***".to_string(), Value::Int(1));
    assert_eq!(redact_value(Value::Map(entry)), Value::Secret);

    let mut nested = std::collections::BTreeMap::new();
    nested.insert("k".to_string(), Value::Secret);
    assert_eq!(
        redact_value(Value::List(vec![Value::Map(nested)])),
        Value::List(vec![Value::Map(
            [("k".to_string(), Value::Secret)].into_iter().collect()
        )])
    );
}
