//! R-10 bulk round 8: the wall and lane bounds are named, `missing` consumes its
//! request frame, and the provider can bound the bytes it holds.

use active_rpc::bulk::{
    BulkProvider, BulkReceiver, BulkRequest, BulkTransfer, FINISH_BYTES_PER_MS,
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

/// A wall grant too small to finish refuses and keeps the transfer, and the
/// named bound completes (round 8, M1).
#[test]
fn the_wall_bound_is_named() {
    let transfer = BulkTransfer::new(body(4_000, 80), 1_000).expect("transfer");
    let plan = transfer.plan().clone();
    assert!(plan.required_wall_ms() >= Budget::default().max_wall_ms);
    assert!(plan.required_wall_ms() > 0);

    let agent = Agent::new();
    let id = agent.register(Box::new(BulkProvider::new()));
    let lane = agent.create_lane("bulk", Budget::default()).expect("lane");
    let mut attrs = CapAttrs::new(&["plan", "put", "missing", "finish"]);
    attrs.budget.max_bytes = plan.required_grant();
    attrs.budget.max_calls = plan.required_calls();
    attrs.budget.max_wall_ms = 1;
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
    for index in 0..plan.chunk_count() {
        send("put", transfer.chunk_frame(index).expect("chunk")).expect("chunk");
    }
    // A deadline that has already passed is a deterministic refusal on the
    // receiver API, and it keeps the chunks.
    let mut receiver = BulkReceiver::new(plan.clone()).expect("receiver");
    for index in 0..plan.chunk_count() {
        receiver
            .accept(&transfer.chunk_frame(index).expect("chunk"))
            .expect("chunk");
    }
    let past = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_millis(1))
        .expect("a past instant");
    let error = receiver
        .finish_within(Some(past))
        .expect_err("a spent deadline refuses the assembly");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    assert!(receiver.is_complete(), "the chunks were kept");
    let _ = &mut send;

    // The same provider still holds the transfer: a cap sized to the named
    // bound finishes it.
    let mut attrs = CapAttrs::new(&["finish"]);
    attrs.budget.max_wall_ms = plan.required_wall_ms();
    attrs.budget.max_bytes = plan.required_grant();
    let second = agent.mint(id, 0, attrs).expect("cap");
    let promise = agent
        .call_from_envelope(
            None,
            lane,
            &second,
            &Envelope::request(99, "finish", Vec::new()).with_payload(transfer.finish_frame()),
        )
        .expect("queued");
    agent.run();
    let reply = promise.value().expect("the named bound finishes");
    match reply {
        Value::Map(entries) => assert_eq!(entries.get("length"), Some(&Value::Int(4_000))),
        other => panic!("unexpected reply {other:?}"),
    }
}

/// The lane is metered beside the capability, and the plan names the number a
/// lane needs (round 8, M2).
#[test]
fn the_lane_bound_is_named() {
    let transfer = BulkTransfer::new(body(4_000, 81), 1_000).expect("transfer");
    let plan = transfer.plan().clone();
    assert_eq!(plan.required_lane_bytes(), plan.required_grant());

    assert!(run_lane(&transfer, 1_000).is_err(), "the lane is narrower");
    run_lane(&transfer, plan.required_lane_bytes()).expect("the named lane bound carries it");
}

fn run_lane(transfer: &BulkTransfer, lane_bytes: u64) -> Result<(), Error> {
    let agent = Agent::new();
    let id = agent.register(Box::new(BulkProvider::new()));
    let lane = agent
        .create_lane(
            "bulk",
            Budget {
                max_bytes: lane_bytes,
                ..Budget::default()
            },
        )
        .expect("lane");
    let mut attrs = CapAttrs::new(&["plan", "put", "missing", "finish"]);
    attrs.budget.max_bytes = transfer.plan().required_grant();
    attrs.budget.max_calls = transfer.plan().required_calls();
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

/// `missing` consumes its request frame and refuses an off-plan index
/// (round 8, L1).
#[test]
fn a_missing_frame_is_validated() {
    let transfer = BulkTransfer::new(body(3_000, 82), 1_000).expect("transfer");
    let plan = transfer.plan().clone();
    let mut provider = BulkProvider::new();
    provider
        .invoke(0, &call("plan", plan.encode()))
        .expect("plan");

    // The documented frame is accepted.
    let request = BulkRequest::new(&[0, 2]).encode();
    provider
        .invoke(0, &call("missing", request))
        .expect("a resume frame is accepted");

    // An index at the count is outside the plan.
    let mut frame = Vec::new();
    frame.extend_from_slice(b"ARBM");
    frame.push(active_rpc::bulk::VERSION);
    frame.extend_from_slice(&1u32.to_le_bytes());
    frame.extend_from_slice(&plan.chunk_count().to_le_bytes());
    let error = provider
        .invoke(0, &call("missing", frame))
        .expect_err("an off-plan index is refused");
    assert_eq!(error.code(), "rpc/bulk");

    // The reply still lists the window.
    let reply = match provider
        .invoke(0, &call("missing", Vec::new()))
        .expect("missing")
    {
        active_rpc::Response::Value(value) => value,
        other => panic!("unexpected reply {other:?}"),
    };
    match reply {
        Value::Map(entries) => assert_eq!(
            entries.get("remaining"),
            Some(&Value::Int(plan.chunk_count() as i64))
        ),
        other => panic!("unexpected reply {other:?}"),
    }
}

/// A provider can bound the bytes it holds across objects (round 8, L5).
#[test]
fn the_provider_can_bound_its_live_bytes() {
    let first = BulkTransfer::new(body(2_000, 83), 1_000).expect("first");
    let second = BulkTransfer::new(body(2_000, 84), 1_000).expect("second");
    let plan = first.plan().clone();
    let reserved = 2 * plan.total() + 53 + 32 * plan.chunk_count() as u64;
    let mut provider = BulkProvider::new().with_max_live_bytes(reserved);
    provider
        .invoke(0, &call("plan", first.plan_frame()))
        .expect("first fits");
    assert_eq!(
        provider.live_bytes(),
        reserved,
        "the plan, its assembly and its hash vector are reserved"
    );
    assert!(
        provider
            .invoke(1, &call("plan", second.plan_frame()))
            .is_err(),
        "the second plan is over the provider bound"
    );
    assert_eq!(
        FINISH_BYTES_PER_MS,
        128 * 1024 * 1024 / 1000,
        "the wall formula's rate"
    );
}

/// The lane's wall axis carries the same bound as the capability's
/// (round 9, M1).
#[test]
fn the_lane_wall_is_named() {
    let plan = active_rpc::bulk::BulkPlan::new(&body(4_000, 85), 1_000).expect("plan");
    assert_eq!(plan.required_lane_wall_ms(), plan.required_wall_ms());
    assert!(plan.required_lane_wall_ms() >= Budget::default().max_wall_ms);
}

/// Retrying the same plan under a live-bytes bound is not a second reservation
/// (round 9, M2).
#[test]
fn a_plan_retry_does_not_double_reserve() {
    let transfer = BulkTransfer::new(body(2_000, 86), 1_000).expect("transfer");
    let plan = transfer.plan().clone();
    // Two body copies plus the retained plan hash vector (round 10, M-1).
    let reserved = 2 * plan.total() + 53 + 32 * plan.chunk_count() as u64;
    let mut provider = BulkProvider::new().with_max_live_bytes(reserved);
    provider
        .invoke(0, &call("plan", plan.encode()))
        .expect("first plan");
    assert_eq!(provider.live_bytes(), reserved, "the reservation is exact");
    provider
        .invoke(0, &call("plan", plan.encode()))
        .expect("the identical plan is a retry, not a second reservation");
    assert_eq!(provider.live_bytes(), reserved);
}

/// A resume request names the indexes the reply contains (round 9, M3).
#[test]
fn a_missing_request_names_its_indexes() {
    let transfer = BulkTransfer::new(body(10_000, 87), 1_000).expect("transfer");
    let plan = transfer.plan().clone();
    let mut provider = BulkProvider::new();
    provider
        .invoke(0, &call("plan", plan.encode()))
        .expect("plan");
    let request = BulkRequest::new(&[5]).encode();
    let reply = match provider
        .invoke(0, &call("missing", request))
        .expect("missing")
    {
        active_rpc::Response::Value(value) => value,
        other => panic!("unexpected reply {other:?}"),
    };
    match reply {
        Value::Map(entries) => match entries.get("missing") {
            Some(Value::List(items)) => assert_eq!(items, &vec![Value::Int(5)]),
            other => panic!("unexpected missing list {other:?}"),
        },
        other => panic!("unexpected reply {other:?}"),
    }
}
