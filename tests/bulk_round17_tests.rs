//! R-10 round 17: the wall-replay classification gate, receiver reuse after a
//! finish, the zero-count resume request, duplicate-heavy frame lists and the
//! classification bound.

use active_rpc::bulk::{
    BulkPlan, BulkProvider, BulkReceiver, BulkRequest, BulkSender, BulkTransfer, CHUNK_OVERHEAD,
};
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

fn with_wall(method: &str, payload: Vec<u8>, wall_ms: u64) -> Call {
    let mut request = call(method, payload);
    request.budget = Budget {
        max_wall_ms: wall_ms,
        ..Budget::default()
    };
    request
}

/// A finished receiver is empty, not complete: a second `finish` says the body
/// is incomplete rather than silently assembling nothing (R-10 round 17, F2).
#[test]
fn a_finished_receiver_is_not_complete() {
    let sender = BulkSender::new(body(2_000, 0x31), 700).expect("sender");
    let mut receiver = BulkReceiver::new(sender.plan().clone()).expect("receiver");
    for index in 0..receiver.plan().chunk_count() {
        receiver
            .accept(&sender.frame_at(index).expect("frame"))
            .expect("accept");
    }
    assert!(receiver.is_complete());
    let assembled = receiver.finish().expect("finish");
    assert_eq!(assembled, body(2_000, 0x31));
    assert!(
        !receiver.is_complete(),
        "a finished receiver holds no chunks"
    );
    assert_eq!(
        receiver.missing().len() as u32,
        receiver.plan().chunk_count(),
        "the receiver is reusable from the start"
    );
}

/// A zero-count resume request means "nothing missing": the provider answers
/// the authoritative window instead of an empty page with `more: true`
/// (R-10 round 17, F6).
#[test]
fn a_zero_count_request_returns_the_window() {
    let transfer = BulkTransfer::new(body(8 * 1024, 0x32), 1_024).expect("transfer");
    assert!(transfer.plan().chunk_count() > 1);
    let mut provider = BulkProvider::new();
    provider
        .invoke(0, &call("plan", transfer.plan_frame()))
        .expect("plan");
    let payload = BulkRequest::new(&[]).encode();
    let reply = provider
        .invoke(0, &call("missing", payload))
        .expect("missing");
    let Response::Value(Value::Map(entries)) = reply else {
        panic!("a map reply");
    };
    let Some(Value::List(items)) = entries.get("missing") else {
        panic!("a missing list");
    };
    assert!(
        !items.is_empty(),
        "the window is the whole missing set, not an empty page"
    );
}

/// A duplicate-heavy resume list is legal: the bound is on distinct indexes
/// (R-10 round 17, F8).
#[test]
fn a_duplicate_heavy_resume_list_is_legal() {
    let sender = BulkSender::new(body(2_000, 0x33), 1_500).expect("sender");
    assert_eq!(sender.plan().chunk_count(), 2);
    let frames = sender.frames_for(&[0, 0, 0]).expect("dedup first");
    assert_eq!(frames.len(), 1);
    let error = sender
        .frames_for(&[0, 9])
        .expect_err("an index outside the plan is still refused");
    assert_eq!(error.code(), "rpc/bulk", "{error}");
}

/// A provider bound at `required_classification_bytes` yields the image
/// address; one byte less degrades to `memory` (R-10 round 17, F4/F16).
#[test]
fn the_classification_bound_is_exact() {
    let module =
        active_rpc::domain::module_from_source("[app]\nname = \"bulk-r17\"\n", "r17.active")
            .expect("module");
    let image = active_infinity::encode(&module).expect("encode");
    for (slack, expect_content) in [(0u64, true), (1u64, false)] {
        let transfer = BulkTransfer::new(image.clone(), 1 << 20).expect("transfer");
        let bound = transfer
            .plan()
            .required_classification_bytes()
            .saturating_sub(slack);
        let mut provider = BulkProvider::new().with_max_live_bytes(bound);
        provider
            .invoke(0, &call("plan", transfer.plan_frame()))
            .expect("plan");
        for index in 0..transfer.plan().chunk_count() {
            provider
                .invoke(0, &call("put", transfer.chunk_frame(index).expect("chunk")))
                .expect("chunk");
        }
        let reply = provider
            .invoke(0, &with_wall("finish", transfer.finish_frame(), 60_000))
            .expect("finish");
        let Response::Value(Value::Map(entries)) = &reply else {
            panic!("a map reply");
        };
        assert_eq!(
            entries.get("canonical"),
            Some(&Value::Bool(expect_content)),
            "bound {bound}: {entries:?}"
        );
        let expected_error = if expect_content {
            None
        } else {
            Some(Value::text("memory"))
        };
        assert_eq!(
            entries.get("content_error"),
            expected_error.as_ref(),
            "bound {bound}: {entries:?}"
        );
    }
}

/// The plan's exact completion bound does not cover the classification
/// (R-10 round 16, M4 kept here as the accessor boundary).
#[test]
fn the_completion_bound_is_below_the_classification_bound() {
    let plan = BulkPlan::new(&body(2_000, 0x34), 700).expect("plan");
    assert!(
        plan.required_classification_bytes() > plan.required_live_bytes(),
        "the classification adds the body itself"
    );
    assert_eq!(
        plan.required_classification_bytes() - plan.required_live_bytes(),
        (active_rpc::bulk::CLASSIFY_BODY_COPIES - 2) * plan.total()
    );
    assert!(plan.required_live_bytes() >= 2 * plan.total() + CHUNK_OVERHEAD);
}
