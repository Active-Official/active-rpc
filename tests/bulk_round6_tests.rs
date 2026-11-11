//! R-10 bulk round 6: the absolute lifetime covers `missing`, the records hold
//! roots rather than plans, the call grant counts a resume, the chunk
//! constructor cannot overflow, and every map is swept.

use active_rpc::bulk::{
    BulkChunk, BulkPlan, BulkProvider, BulkTransfer, COMPLETED_IDLE_MS, MAX_CHUNKS,
    MAX_TRANSFER_LIFETIME_MS, MISSING_PAGE, TRANSFER_IDLE_MS,
};
use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::value::{Call, Value};
use active_rpc::wire::{CapDescriptor, CapTableDelta, Envelope, WireLimits};
use active_rpc::{Agent, Budget, CapId, Error};

fn body(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| seed.wrapping_add((index % 251) as u8))
        .collect()
}

fn call(method: &str, payload: Vec<u8>) -> Call {
    Call::new(method, Vec::new()).with_payload(payload)
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

/// Polling cannot hold a transfer past the absolute lifetime, whatever the idle
/// window says (round 6, M1).
#[test]
fn a_poll_does_not_outlive_the_absolute_lifetime() {
    let transfer = BulkTransfer::new(body(3_000, 60), 1_000).expect("transfer");
    let mut provider = BulkProvider::new();
    drive(&mut provider, &transfer, 1, 0);

    let mut early = call("missing", Vec::new());
    early.now_ms = MAX_TRANSFER_LIFETIME_MS - 1;
    provider
        .invoke(1, &early)
        .expect("inside the lifetime the poll is answered");

    let mut late = call("missing", Vec::new());
    late.now_ms = MAX_TRANSFER_LIFETIME_MS + 1;
    let error = provider
        .invoke(1, &late)
        .expect_err("the lifetime bound is absolute");
    assert_eq!(error.code(), "rpc/bulk");
    assert_eq!(provider.active_root(1), None, "the state was not released");
}

/// A resume needs `missing` pages on top of the clean pass, and the accessor
/// says so (round 6, L8).
#[test]
fn the_call_grant_counts_the_resume_pages() {
    let chunks = (MISSING_PAGE * 2) as u32;
    let plan = BulkPlan::new(&body(chunks as usize, 61), 1).expect("plan");
    let pages = chunks.div_ceil(MISSING_PAGE as u32) as u64;
    assert_eq!(plan.required_calls(), chunks as u64 + 2 + pages);
    assert!(plan.required_calls() > chunks as u64 + 2);

    // The clean pass fits inside the accessor's bound at the kernel.
    let transfer = BulkTransfer::new(body(4_000, 62), 1_000).expect("transfer");
    let calls = transfer.plan().required_calls();
    let agent = Agent::new();
    let id = agent
        .register(Box::new(BulkProvider::new()))
        .expect("register provider");
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
    send("plan", transfer.plan_frame()).expect("plan");
    for index in 0..transfer.plan().chunk_count() {
        send("put", transfer.chunk_frame(index).expect("chunk")).expect("chunk");
    }
    send("finish", transfer.finish_frame()).expect("finish");
}

/// The digest reply is released with the completed window, so it cannot
/// accumulate per object (round 6, L7).
#[test]
fn the_digest_reply_is_released_with_the_window() {
    let transfer = BulkTransfer::new(body(2_000, 63), 1_000).expect("transfer");
    let mut provider = BulkProvider::new();
    drive(&mut provider, &transfer, 1, 0);
    let mut finish = call("finish", transfer.finish_frame());
    finish.now_ms = 0;
    provider.invoke(1, &finish).expect("finish");
    assert!(provider.take_body(1).is_some());

    provider.expire_idle(COMPLETED_IDLE_MS * 2 + 1);
    let mut late = call("finish", transfer.finish_frame());
    late.now_ms = COMPLETED_IDLE_MS * 2 + 1;
    let error = provider
        .invoke(1, &late)
        .expect_err("the digest reply expired with the body");
    assert_eq!(error.code(), "rpc/bulk");
}

/// The infallible chunk constructor does not panic on an overflowing offset
/// (round 6, L3).
#[test]
fn the_chunk_constructor_saturates_an_overflow() {
    let chunk = BulkChunk::new(u32::MAX, usize::MAX, b"x");
    assert_eq!(chunk.offset(), u64::MAX);
    // A frame at that offset is refused by every plan.
    let plan = BulkPlan::new(&body(1_000, 64), 100).expect("plan");
    let mut receiver = active_rpc::bulk::BulkReceiver::new(plan).expect("receiver");
    let error = receiver
        .accept(&chunk.encode())
        .expect_err("no plan accepts the saturated offset");
    assert_eq!(error.code(), "rpc/bulk");
}

/// The maximal plan still fits a strict frame that carries a `max_path` scope
/// and a cap delta (round 6, L4).
#[test]
fn the_maximal_plan_fits_with_a_scope_and_a_delta() {
    let payload = vec![0u8; MAX_CHUNKS as usize];
    let plan = BulkPlan::new(&payload, 1).expect("plan");
    assert_eq!(plan.chunk_count(), MAX_CHUNKS);
    let mut attrs = CapAttrs::new(&["plan", "put", "missing", "finish"]);
    let limit = WireLimits::strict().max_path as usize;
    attrs.path_scope = Some(format!("/{}", "s".repeat(limit - 1)));
    let descriptor = CapDescriptor::from_attrs(CapId([8; 16]), &attrs);
    let base: Vec<CapDescriptor> = Vec::new();
    let delta = CapTableDelta::new(&base, Vec::new(), vec![descriptor.clone()])
        .expect("delta against an empty base");
    let envelope = Envelope::request(1, "plan", Vec::new())
        .with_caps(Vec::new())
        .with_cap_delta(delta)
        .with_payload(plan.encode());
    let bytes = envelope
        .encode_with_limits(WireLimits::strict())
        .expect("the maximal plan with a scope and a delta fits the strict frame");
    Envelope::decode_with(&bytes, WireLimits::strict()).expect("and decodes");
}

/// The chunk ceiling is the number the docs must quote, and the decoder refuses
/// one more (round 6, L5).
#[test]
fn the_chunk_ceiling_is_pinned() {
    assert_eq!(MAX_CHUNKS, 32_700);
    let bytes = vec![0u8; MAX_CHUNKS as usize + 1];
    let error = BulkPlan::new(&bytes, 1).expect_err("one chunk too many");
    assert_eq!(error.code(), "rpc/bulk");
}

/// The idle window still releases an abandoned transfer on its own object
/// (round 6 keeps the round-4 behaviour for idleness).
#[test]
fn idleness_still_releases_without_a_poll() {
    let transfer = BulkTransfer::new(body(2_000, 65), 1_000).expect("transfer");
    let mut provider = BulkProvider::new();
    drive(&mut provider, &transfer, 1, 0);
    let mut put = call("put", transfer.chunk_frame(0).expect("chunk"));
    put.now_ms = TRANSFER_IDLE_MS + 1;
    let error = provider
        .invoke(1, &put)
        .expect_err("the idle window released the transfer");
    assert_eq!(error.code(), "rpc/bulk");
}
