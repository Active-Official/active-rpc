//! R-10 bulk round 5: the digest record is O(1) and dropped with the capability,
//! the idle sweep is not per object, the lifetime bound is absolute, the call
//! grant is named, a finish honours its wall grant, the strict frame has
//! headroom for a descriptor, and the refusing constructors do not panic.

use std::collections::BTreeMap;

use active_rpc::bulk::{
    BulkChunk, BulkPlan, BulkProvider, BulkSender, BulkTransfer, MAX_CHUNKS,
    MAX_TRANSFER_LIFETIME_MS, TRANSFER_IDLE_MS,
};
use active_rpc::cap::{CapAttrs, CapId};
use active_rpc::kernel::Provider;
use active_rpc::value::{Call, Value};
use active_rpc::wire::{CapDescriptor, Envelope, WireLimits};
use active_rpc::{Agent, Budget, Error};

fn body(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| seed.wrapping_add((index % 251) as u8))
        .collect()
}

fn call(method: &str, payload: Vec<u8>) -> Call {
    Call::new(method, Vec::new()).with_payload(payload)
}

fn reply_map(response: active_rpc::Response) -> BTreeMap<String, Value> {
    match response {
        active_rpc::Response::Value(Value::Map(entries)) => entries,
        other => panic!("unexpected reply {other:?}"),
    }
}

fn drive(provider: &mut BulkProvider, transfer: &BulkTransfer, object: u64, now_ms: u64) {
    let mut open = call("plan", transfer.plan_frame());
    open.now_ms = now_ms;
    provider.invoke(object, &open).expect("plan");
    for index in 0..transfer.plan().chunk_count() {
        let mut put = call("put", transfer.chunk_frame(index).expect("chunk"));
        put.now_ms = now_ms;
        provider.invoke(object, &put).expect("chunk");
    }
}

/// The digest record is dropped with the capability, so a revoked object leaves
/// nothing behind and a stale marker is refused (round 5, F1).
#[test]
fn a_dropped_capability_drops_the_digest_record() {
    let transfer = BulkTransfer::new(body(4_000, 40), 1_000).expect("transfer");
    let mut provider = BulkProvider::new();
    drive(&mut provider, &transfer, 5, 0);
    let marker = transfer.finish_frame();
    let mut finish = call("finish", marker.clone());
    finish.now_ms = 0;
    let first = reply_map(provider.invoke(5, &finish).expect("finish"));

    // A retried marker is answered while the object is live.
    let mut again = call("finish", marker.clone());
    again.now_ms = 0;
    assert_eq!(first, reply_map(provider.invoke(5, &again).expect("retry")));

    provider.on_drop(5, CapId([4; 16]));
    let mut late = call("finish", marker);
    late.now_ms = 0;
    let error = provider
        .invoke(5, &late)
        .expect_err("a dropped object has no digest reply");
    assert_eq!(error.code(), "rpc/bulk");
}

/// The idle sweep is provider-wide: a new transfer on one object releases the
/// abandoned state of another (round 5, F2).
#[test]
fn a_new_transfer_sweeps_other_objects() {
    let abandoned = BulkTransfer::new(body(3_000, 41), 1_000).expect("transfer");
    let fresh = BulkTransfer::new(body(2_000, 42), 1_000).expect("transfer");
    let mut provider = BulkProvider::new();
    drive(&mut provider, &abandoned, 1, 0);
    assert_eq!(provider.active_root(1), Some(abandoned.plan().root()));

    let mut open = call("plan", fresh.plan_frame());
    open.now_ms = TRANSFER_IDLE_MS + 1;
    provider.invoke(2, &open).expect("plan on another object");
    assert_eq!(
        provider.active_root(1),
        None,
        "the abandoned transfer on object 1 was not swept"
    );
}

/// `expire_idle` is the host's sweep, and it covers both maps (round 5, F2).
#[test]
fn expire_idle_releases_incomplete_and_finished_state() {
    let done = BulkTransfer::new(body(2_000, 43), 1_000).expect("transfer");
    let pending = BulkTransfer::new(body(2_000, 44), 1_000).expect("transfer");
    let mut provider = BulkProvider::new();
    drive(&mut provider, &done, 1, 0);
    let mut finish = call("finish", done.finish_frame());
    finish.now_ms = 0;
    provider.invoke(1, &finish).expect("finish");
    drive(&mut provider, &pending, 2, 0);
    assert!(provider.has_body(1));

    provider.expire_idle(10_000);
    assert!(provider.has_body(1), "inside the completed window");
    provider.expire_idle(active_rpc::bulk::COMPLETED_IDLE_MS + 1);
    assert!(!provider.has_body(1), "the finished body was not released");
    assert_eq!(
        provider.active_root(2),
        None,
        "the incomplete transfer was not released"
    );
}

/// The idle window can be refreshed; the lifetime bound cannot (round 5, F2).
#[test]
fn a_refreshed_transfer_still_hits_the_lifetime_bound() {
    let transfer = BulkTransfer::new(body(3_000, 45), 1_000).expect("transfer");
    let mut provider = BulkProvider::new();
    let mut open = call("plan", transfer.plan_frame());
    open.now_ms = 0;
    provider.invoke(1, &open).expect("plan");

    let mut poll = call("missing", Vec::new());
    poll.now_ms = MAX_TRANSFER_LIFETIME_MS - 1;
    provider
        .invoke(1, &poll)
        .expect("a late poll refreshes the idle window");

    let mut put = call("put", transfer.chunk_frame(0).expect("chunk"));
    put.now_ms = MAX_TRANSFER_LIFETIME_MS + 1;
    let error = provider
        .invoke(1, &put)
        .expect_err("the lifetime bound is anchored at the opening call");
    assert_eq!(error.code(), "rpc/bulk");
}

/// The call grant is part of the contract: one call short cannot carry a
/// transfer, the named grant can, and it counts the resume pages (round 5, F3;
/// round 6, L8).
#[test]
fn the_call_grant_is_named() {
    let transfer = BulkTransfer::new(body(4_000, 46), 1_000).expect("transfer");
    let chunks = transfer.plan().chunk_count() as u64;
    let pages = chunks.div_ceil(active_rpc::bulk::MISSING_PAGE as u64);
    assert_eq!(transfer.plan().required_calls(), chunks + 2 + pages);
    assert!(run_kernel(&transfer, chunks + 1).is_err());
    run_kernel(&transfer, transfer.plan().required_calls())
        .expect("the named call grant carries the transfer");
}

fn run_kernel(transfer: &BulkTransfer, calls: u64) -> Result<(), Error> {
    let agent = Agent::new();
    let id = agent.register(Box::new(BulkProvider::new()));
    let lane = agent.create_lane("bulk", Budget::default()).expect("lane");
    let mut attrs = CapAttrs::new(&["plan", "put", "missing", "finish"]);
    attrs.budget.max_calls = calls;
    attrs.budget.max_bytes = transfer.plan().required_grant();
    let cap = agent.mint(id, 0, attrs).expect("cap");
    let mut request = 1u64;
    let mut send = |method: &str, payload: Vec<u8>| -> Result<Value, Error> {
        let promise = agent.call_from_envelope(
            None,
            lane,
            &cap,
            &Envelope::request(request, method, Vec::new()).with_payload(payload),
        )?;
        request += 1;
        agent.run();
        promise.value()
    };
    send("plan", transfer.plan_frame())?;
    for index in 0..transfer.plan().chunk_count() {
        send("put", transfer.chunk_frame(index)?)?;
    }
    send("finish", transfer.finish_frame())?;
    Ok(())
}

/// A finish whose wall grant is already spent refuses before the work and keeps
/// the transfer (round 5, F4).
#[test]
fn a_finish_without_wall_grant_refuses_and_keeps_the_transfer() {
    let transfer = BulkTransfer::new(body(3_000, 47), 1_000).expect("transfer");
    let mut provider = BulkProvider::new();
    drive(&mut provider, &transfer, 1, 0);
    let mut finish = call("finish", transfer.finish_frame());
    finish.now_ms = 0;
    finish.budget = Budget {
        max_wall_ms: 0,
        ..Budget::default()
    };
    let error = provider
        .invoke(1, &finish)
        .expect_err("a spent wall grant refuses the assembly");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    assert_eq!(
        provider.active_root(1),
        Some(transfer.plan().root()),
        "a refused finish must keep the transfer"
    );

    let mut retry = call("finish", transfer.finish_frame());
    retry.now_ms = 0;
    provider.invoke(1, &retry).expect("a real grant completes");
}

/// The maximal plan still fits a strict frame that carries a capability
/// descriptor and a cap delta (round 5, F5).
#[test]
fn the_maximal_plan_fits_with_a_descriptor_and_a_delta() {
    let payload = vec![0u8; MAX_CHUNKS as usize];
    let plan = BulkPlan::new(&payload, 1).expect("plan");
    let mut attrs = CapAttrs::new(&["plan", "put", "missing", "finish"]);
    attrs.path_scope =
        Some("/a/scope/that/is/long/enough/to/take/headroom/in/a/strict/frame".to_string());
    let descriptor = CapDescriptor::from_attrs(CapId([7; 16]), &attrs);
    let envelope = Envelope::request(1, "plan", Vec::new())
        .with_caps(vec![descriptor])
        .with_payload(plan.encode());
    let bytes = envelope
        .encode_with_limits(WireLimits::strict())
        .expect("the maximal plan with a descriptor fits the strict frame");
    Envelope::decode_with(&bytes, WireLimits::strict()).expect("and decodes");
}

/// The refusing chunk constructor does not panic on an overflowing offset
/// (round 5, F6).
#[test]
fn a_chunk_offset_that_overflows_is_refused() {
    let error = BulkChunk::try_new(u32::MAX, usize::MAX, b"x").expect_err("the offset overflows");
    assert_eq!(error.code(), "rpc/bulk");
}

/// `frames` reports a build failure instead of dropping the frame
/// (round 5, F7).
#[test]
fn frames_reports_every_chunk() {
    let sender = BulkSender::new(body(5_000, 48), 1_000).expect("sender");
    let frames = sender.frames().expect("frames");
    assert_eq!(frames.len(), sender.plan().chunk_count() as usize);
    assert_eq!(frames.len(), 5);
}
