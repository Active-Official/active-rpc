//! R-10 bulk round 13: the wall throttle funds the body's own estimate and
//! counts every grant below it.

use std::collections::BTreeMap;

use active_infinity::{encode, InfinityModule, Inode, SecretBytes};
use active_rpc::bulk::{BulkProvider, BulkTransfer};
use active_rpc::kernel::Provider;
use active_rpc::value::{Call, Response, Value};
use active_rpc::Budget;

fn body(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| seed.wrapping_add((index % 251) as u8))
        .collect()
}

fn call(method: &str, payload: Vec<u8>) -> Call {
    Call::new(method, Vec::new()).with_payload(payload)
}

fn drive(provider: &mut BulkProvider, transfer: &BulkTransfer) {
    provider
        .invoke(0, &call("plan", transfer.plan_frame()))
        .expect("plan");
    for index in 0..transfer.plan().chunk_count() {
        provider
            .invoke(0, &call("put", transfer.chunk_frame(index).expect("chunk")))
            .expect("chunk");
    }
}

fn finish(
    provider: &mut BulkProvider,
    transfer: &BulkTransfer,
    wall_ms: u64,
) -> Result<(), String> {
    let mut request = call("finish", transfer.finish_frame());
    request.budget = Budget {
        max_wall_ms: wall_ms,
        ..Budget::default()
    };
    match provider.invoke(0, &request) {
        Ok(_) => Ok(()),
        Err(error) => Err(error.code().to_string()),
    }
}

/// Raising the grant one millisecond at a time used to clear the failure count
/// every step (`grant > failed_at`), so each 1 ms step bought a full assembly
/// and the freeze never engaged. Three sub-estimate failures must count and
/// freeze the transfer, and the estimate itself must still finish it
/// (R-10 round 13, F1).
#[test]
fn escalating_the_grant_by_a_millisecond_does_not_buy_more_assemblies() {
    // 8 MiB needs ~160 ms at the documented rate, so 1..=4 ms are all below the
    // estimate.
    let transfer = BulkTransfer::new(body(8 << 20, 96), 256 * 1024).expect("transfer");
    let plan = transfer.plan().clone();
    let mut provider = BulkProvider::new();
    drive(&mut provider, &transfer);
    let estimate = plan.assembly_wall_ms();
    for wall in 1..=3u64 {
        assert!(wall < estimate, "the fixture's estimate is {estimate} ms");
        let code = finish(&mut provider, &transfer, wall).expect_err("below the estimate");
        assert_eq!(code, "rpc/budget-exceeded", "wall {wall}");
    }
    // A fourth grant is wider than every failure so far; it must not run.
    let code = finish(&mut provider, &transfer, 4).expect_err("the escalation is frozen");
    assert_eq!(code, "rpc/bulk", "a 1 ms widening bought another assembly");
    // One millisecond below the estimate is still a refusal, not a reset.
    let code = finish(&mut provider, &transfer, estimate - 1).expect_err("still below");
    assert_eq!(code, "rpc/bulk");
    // The estimate is the price the transfer asks for: it clears the freeze.
    finish(&mut provider, &transfer, estimate).expect("the estimate finishes the body");
}

/// A `put` with no transfer is a state refusal whatever the provider's
/// occupancy: the ceiling used to answer first and leak another object's live
/// bytes to a put-only capability (R-10 round 13, F2).
#[test]
fn a_put_without_a_transfer_is_a_state_refusal_even_at_the_live_bound() {
    let transfer = BulkTransfer::new(body(4096, 97), 1024).expect("transfer");
    // A ceiling of one byte is already over the plan vector, so every put is
    // over the bound if the ceiling is consulted first.
    let mut provider = BulkProvider::new().with_max_live_bytes(1);
    let code = provider
        .invoke(0, &call("put", transfer.chunk_frame(0).expect("chunk")))
        .expect_err("no transfer is active")
        .code()
        .to_string();
    assert_eq!(code, "rpc/bulk", "the ceiling answered before the state");
    // With the plan accepted the same frame is a byte refusal, which is the
    // code the ceiling is for. The plan is admitted only because the provider
    // has no bound set for this half of the test.
    let mut open = BulkProvider::new();
    open.invoke(0, &call("plan", transfer.plan_frame()))
        .expect("plan");
    open.invoke(0, &call("put", transfer.chunk_frame(0).expect("chunk")))
        .expect("the first chunk fits");
    let mut bounded = open.with_max_live_bytes(1);
    let code = bounded
        .invoke(0, &call("put", transfer.chunk_frame(1).expect("chunk")))
        .expect_err("over the live bound")
        .code()
        .to_string();
    assert_eq!(
        code, "rpc/budget-exceeded",
        "an open transfer answers the ceiling"
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A module whose root table holds one structural secret.
fn secret_module(secret: &str) -> InfinityModule {
    let mut module = InfinityModule::new();
    let secret_node = module.push(Inode::Secret(SecretBytes::new(secret)));
    let root = module.push(Inode::Table {
        fields: vec![("token".to_string(), secret_node)],
    });
    module.set_root(Some(root));
    module
}

/// A canonical secret-free module: one string under the root table.
fn plain_module() -> InfinityModule {
    let mut module = InfinityModule::new();
    let node = module.push(Inode::Str("plain".to_string()));
    let root = module.push(Inode::Table {
        fields: vec![("v".to_string(), node)],
    });
    module.set_root(Some(root));
    module
}

/// The finish reply for a driven transfer, as a map.
fn finish_map(provider: &mut BulkProvider, transfer: &BulkTransfer) -> BTreeMap<String, Value> {
    match provider.invoke(0, &call("finish", transfer.finish_frame())) {
        Ok(Response::Value(Value::Map(entries))) => entries,
        other => panic!("unexpected finish reply {other:?}"),
    }
}

fn text(map: &BTreeMap<String, Value>, key: &str) -> String {
    match map.get(key) {
        Some(Value::Text(text)) => text.clone(),
        other => panic!("expected text for {key}, got {other:?}"),
    }
}

/// R2-BND-02: the raw Blake3 digest is an offline equality oracle over the
/// un-redacted bytes, so a secret-bearing image's finish omits `body_hash`
/// while keeping the redacted `content` address — on the fresh finish, on a
/// `completed` replay, and on a `last_finished` replay after the body is
/// taken.
#[test]
fn a_secret_image_finish_omits_body_hash_but_keeps_the_redacted_address() {
    let bytes = encode(&secret_module("s3cr3t-value")).expect("encode");
    let redacted = active_rpc::security::redact_module(&bytes).expect("redact");
    let redacted_hash = active_infinity::content_hash(&redacted).expect("redacted hash");
    let transfer = BulkTransfer::new(bytes.clone(), 256).expect("transfer");
    let mut provider = BulkProvider::new();
    drive(&mut provider, &transfer);
    let map = finish_map(&mut provider, &transfer);
    assert_eq!(text(&map, "content"), hex(&redacted_hash));
    assert_eq!(
        map.get("length"),
        Some(&Value::Int(bytes.len() as i64)),
        "the length is still reported"
    );
    assert!(
        !map.contains_key("body_hash"),
        "a secret image's finish must not serve the raw digest: {map:?}"
    );
    // A repeated marker while the body is still resident re-serves the same
    // omission (the `completed` replay path).
    let replayed = finish_map(&mut provider, &transfer);
    assert_eq!(text(&replayed, "content"), hex(&redacted_hash));
    assert!(
        !replayed.contains_key("body_hash"),
        "a completed replay must not re-serve the oracle: {replayed:?}"
    );
    // After the host takes the body, the digest reply outlives the bytes —
    // the `last_finished` replay must omit it too.
    provider.take_body(0).expect("take body");
    let retried = finish_map(&mut provider, &transfer);
    assert_eq!(text(&retried, "content"), hex(&redacted_hash));
    assert!(
        !retried.contains_key("body_hash"),
        "a last_finished replay must not re-serve the oracle: {retried:?}"
    );
}

/// R2-BND-02 control: the omission is keyed on the body's secrecy, not on
/// the image shape. A secret-free image keeps `body_hash` as its
/// transfer-integrity value.
#[test]
fn a_secret_free_image_finish_keeps_body_hash() {
    let bytes = encode(&plain_module()).expect("encode");
    let address = active_infinity::content_hash(&bytes).expect("content hash");
    let transfer = BulkTransfer::new(bytes.clone(), 256).expect("transfer");
    let mut provider = BulkProvider::new();
    drive(&mut provider, &transfer);
    let map = finish_map(&mut provider, &transfer);
    assert_eq!(
        text(&map, "body_hash"),
        hex(blake3::hash(&bytes).as_bytes()),
        "a secret-free image keeps its integrity digest"
    );
    assert_eq!(text(&map, "content"), hex(&address));
}

/// R2-BND-02 control: a body that is not an image has no secret structure,
/// so its finish keeps `body_hash` and reports no content address.
#[test]
fn a_non_image_body_finish_keeps_body_hash() {
    let bytes = b"not an image".to_vec();
    let transfer = BulkTransfer::new(bytes.clone(), 256).expect("transfer");
    let mut provider = BulkProvider::new();
    drive(&mut provider, &transfer);
    let map = finish_map(&mut provider, &transfer);
    assert_eq!(
        text(&map, "body_hash"),
        hex(blake3::hash(&bytes).as_bytes()),
        "a non-image body keeps its integrity digest"
    );
    assert!(
        !map.contains_key("content"),
        "a non-image body has no content address: {map:?}"
    );
    assert!(
        !map.contains_key("content_error"),
        "a non-image body is not a degradation: {map:?}"
    );
}

/// R2-BND-02: a body that claims to be an image but cannot be classified
/// (`"parser"`) cannot be proven secret-free, so its finish omits
/// `body_hash` too.
#[test]
fn a_corrupt_image_finish_omits_body_hash() {
    let mut bytes = encode(&plain_module()).expect("encode");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    let transfer = BulkTransfer::new(bytes.clone(), 256).expect("transfer");
    let mut provider = BulkProvider::new();
    drive(&mut provider, &transfer);
    let map = finish_map(&mut provider, &transfer);
    assert_eq!(text(&map, "content_error"), "parser");
    assert!(
        !map.contains_key("body_hash"),
        "an unclassifiable image must not serve the raw digest: {map:?}"
    );
}

/// R2-BND-02 (extension of the design's condition): the omission is keyed on
/// the BODY's secrecy, so it also holds when classification could not run —
/// here the live bound leaves no room for it (`"memory"`) — and the
/// `last_finished` replay after the take keeps it.
#[test]
fn a_secret_image_finish_under_a_memory_bound_omits_body_hash() {
    let bytes = encode(&secret_module("s3cr3t-value")).expect("encode");
    let transfer = BulkTransfer::new(bytes.clone(), 256).expect("transfer");
    // A 360-byte body needs ~901 live bytes; classification needs ~9541, so
    // this bound admits the transfer and refuses the classification.
    let mut provider = BulkProvider::new().with_max_live_bytes(2000);
    drive(&mut provider, &transfer);
    let map = finish_map(&mut provider, &transfer);
    assert_eq!(text(&map, "content_error"), "memory");
    assert!(
        !map.contains_key("body_hash"),
        "a secret image whose address could not be computed must not serve the raw digest: {map:?}"
    );
    provider.take_body(0).expect("take body");
    let retried = finish_map(&mut provider, &transfer);
    assert!(
        !retried.contains_key("body_hash"),
        "a last_finished replay must not re-serve the oracle: {retried:?}"
    );
}
