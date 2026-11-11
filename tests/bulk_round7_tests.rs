//! R-10 bulk round 7: a retried finish cannot outlive its window, the resumed
//! grant is named, duplicates are charged, the sender reuses the planned hash,
//! and the chunk-size floor matches the ceiling.

use active_rpc::bulk::{
    BulkChunk, BulkPlan, BulkProvider, BulkSender, BulkTransfer, COMPLETED_IDLE_MS, MAX_CHUNKS,
};
use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::value::{Call, Value};
use active_rpc::wire::Envelope;
use active_rpc::{Agent, Budget, Error};

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

/// Retrying the finish marker does not keep an untaken body alive past its
/// window, and it does not wedge the object (round 7, M1).
#[test]
fn a_retried_finish_cannot_pin_the_body() {
    let transfer = BulkTransfer::new(body(2_000, 70), 1_000).expect("transfer");
    let mut provider = BulkProvider::new();
    drive(&mut provider, &transfer, 1, 0);
    let marker = transfer.finish_frame();
    let mut first = call("finish", marker.clone());
    first.now_ms = 0;
    provider.invoke(1, &first).expect("finish");
    assert!(provider.has_body(1));

    // Retry the marker at the last moment inside the window, then past it: the
    // fast path must expire first, not answer forever.
    let mut live = call("finish", marker.clone());
    live.now_ms = COMPLETED_IDLE_MS;
    provider
        .invoke(1, &live)
        .expect("inside the window the marker is answered");

    let mut stale = call("finish", marker);
    stale.now_ms = COMPLETED_IDLE_MS * 2 + 1;
    let error = provider
        .invoke(1, &stale)
        .expect_err("the body expired despite the retries");
    assert_eq!(error.code(), "rpc/bulk");
    assert!(!provider.has_body(1), "the untaken body was pinned");
}

/// The resumed grant is the one a caller that may reconnect needs (round 7,
/// M2).
#[test]
fn the_resumed_grant_covers_two_passes() {
    let transfer = BulkTransfer::new(body(4_000, 71), 1_000).expect("transfer");
    let plan = transfer.plan().clone();
    assert!(plan.required_grant_with_resume() > plan.required_grant());
    assert!(
        plan.required_grant_with_resume()
            >= plan.required_grant() + plan.total() + 53 * plan.chunk_count() as u64
    );

    // A clean pass, then a full resume of every chunk: the plain grant runs out,
    // the resumed one carries it.
    assert!(
        run_kernel(&transfer, plan.required_grant()).is_err(),
        "the plain grant cannot pay for a resume"
    );
    run_kernel(&transfer, plan.required_grant_with_resume())
        .expect("the resumed grant carries the second pass");
}

fn run_kernel(transfer: &BulkTransfer, grant: u64) -> Result<(), Error> {
    let agent = Agent::new();
    let id = agent
        .register(Box::new(BulkProvider::new()))
        .expect("register provider");
    let lane = agent.create_lane("bulk", Budget::default()).expect("lane");
    let mut attrs = CapAttrs::new(&["plan", "put", "missing", "finish"]);
    attrs.budget.max_bytes = grant;
    attrs.budget.max_calls = transfer.plan().required_calls_with_resume();
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
    // The connection "drops" after the first pass: re-plan and send everything
    // again, the resume the module advertises.
    send("plan", transfer.plan_frame())?;
    for index in 0..transfer.plan().chunk_count() {
        send("put", transfer.chunk_frame(index)?)?;
    }
    send("finish", transfer.finish_frame())?;
    Ok(())
}

/// The documented chunk-size floor for a 1 GiB body is 32 837, not 32 836
/// (round 7, L4).
#[test]
fn the_documented_chunk_floor_is_exact() {
    // One gigabyte at the floor: 32 700 chunks, the ceiling.
    let bytes = vec![0u8; 1 << 30];
    let plan = BulkPlan::new(&bytes, 32_837).expect("the floor fits the ceiling");
    assert_eq!(plan.chunk_count(), MAX_CHUNKS);
    let error = BulkPlan::new(&bytes, 32_836).expect_err("one byte smaller is over the ceiling");
    assert_eq!(error.code(), "rpc/bulk");
}

/// A duplicate frame is charged: it still costs a decode, a hash and an
/// allocation (round 7, L6).
#[test]
fn a_duplicate_frame_is_charged() {
    let sender = BulkSender::new(body(3_000, 72), 1_000).expect("sender");
    let frame = sender.frame_at(0).expect("frame");
    let budget = Budget {
        max_bytes: 4_096,
        ..Budget::default()
    };
    let mut receiver = active_rpc::bulk::BulkReceiver::with_budget(sender.plan().clone(), budget)
        .expect("receiver");
    for _ in 0..3 {
        receiver.accept(&frame).expect("accepted");
    }
    assert_eq!(
        receiver.charged_bytes(),
        3 * frame.len() as u64,
        "each replay is charged"
    );
}

/// A frame carries the hash the plan already holds (round 7, L8).
#[test]
fn a_frame_carries_the_planned_hash() {
    let sender = BulkSender::new(body(5_000, 73), 1_000).expect("sender");
    for index in 0..sender.plan().chunk_count() {
        let frame = sender.frame_at(index).expect("frame");
        let chunk = BulkChunk::decode(&frame).expect("frame decodes");
        assert_eq!(
            Some(chunk.hash()),
            sender.plan().chunk_hash_at(index),
            "chunk {index}"
        );
    }
}
