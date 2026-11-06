//! R-10 bulk round 10: the live bound counts the plan, a frame is charged before
//! it is decoded, an exhausted finish is a state refusal, and a missing content
//! address says why.

use active_rpc::bulk::{BulkProvider, BulkReceiver, BulkTransfer};
use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::value::{Call, Value};
use active_rpc::{Agent, Budget, Error};

fn body(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| seed.wrapping_add((index % 251) as u8))
        .collect()
}

fn call(method: &str, payload: Vec<u8>) -> Call {
    Call::new(method, Vec::new()).with_payload(payload)
}

fn reply_map(response: active_rpc::Response) -> std::collections::BTreeMap<String, Value> {
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

/// The live bound counts the retained plan hash vector, so a one-byte-chunk plan
/// cannot slip under a body-only limit (round 10, M-1).
#[test]
fn the_live_bound_counts_the_plan() {
    let transfer = BulkTransfer::new(body(10, 90), 1).expect("transfer");
    let plan = transfer.plan().clone();
    let body_only = 2 * plan.total();
    let reserved = body_only + 53 + 32 * plan.chunk_count() as u64;
    assert!(reserved > body_only);

    let mut tight = BulkProvider::new().with_max_live_bytes(body_only);
    assert!(
        tight.invoke(0, &call("plan", plan.encode())).is_err(),
        "a body-only bound must not admit the plan hashes"
    );

    let mut exact = BulkProvider::new().with_max_live_bytes(reserved);
    exact
        .invoke(0, &call("plan", plan.encode()))
        .expect("the exact reservation fits");
    assert_eq!(exact.live_bytes(), reserved);
}

/// A frame is charged before it is decoded, so a wrong-hash frame is not free
/// (round 10, M-2).
#[test]
fn a_bad_frame_is_charged_before_validation() {
    let sender = active_rpc::bulk::BulkSender::new(body(3_000, 91), 1_000).expect("sender");
    let mut frame = sender.frame_at(0).expect("frame");
    let last = frame.len() - 1;
    frame[last] ^= 0xFF;
    let budget = Budget {
        max_bytes: 4_096,
        ..Budget::default()
    };
    let mut receiver = BulkReceiver::with_budget(sender.plan().clone(), budget).expect("receiver");
    let error = receiver.accept(&frame).expect_err("the hash is wrong");
    assert_eq!(error.code(), "rpc/bulk");
    assert_eq!(
        receiver.charged_bytes(),
        frame.len() as u64,
        "the decode and hash were not charged"
    );
    assert!(!receiver.is_complete());
}

/// An exhausted finish is a state refusal, not a budget one: the transfer will
/// not take another under-resourced attempt, so the caller either grants the
/// body's wall (`assembly_wall_ms`) or aborts it. A re-plan does not clear the
/// counter, and no refusal destroys the paid chunks (round 10, M-3; round 15).
#[test]
fn an_exhausted_finish_is_a_state_refusal() {
    // 64 MiB cannot be assembled inside a 1 ms grant on any host, so the
    // deadline trips between chunks and the provider counts the refusal.
    let transfer = BulkTransfer::new(body(64 << 20, 92), 256 * 1024).expect("transfer");
    let plan = transfer.plan().clone();
    let agent = Agent::new();
    let id = agent.register(Box::new(BulkProvider::new()));
    let lane = agent
        .create_lane(
            "bulk",
            Budget {
                max_bytes: plan.required_grant(),
                ..Budget::default()
            },
        )
        .expect("lane");
    let mut attrs = CapAttrs::new(&["plan", "put", "missing", "finish"]);
    attrs.budget.max_bytes = plan.required_grant();
    attrs.budget.max_calls = plan.required_calls_with_resume();
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
    for attempt in 0..3 {
        let error = send("finish", transfer.finish_frame())
            .expect_err("the 1 ms grant cannot assemble 64 MiB");
        assert_eq!(
            error.code(),
            "rpc/budget-exceeded",
            "attempt {attempt}: {error}"
        );
    }
    // The fourth attempt is refused before any work, as a state fault.
    let error = send("finish", transfer.finish_frame())
        .expect_err("the finish is exhausted, not the grant");
    assert_eq!(error.code(), "rpc/bulk", "{error}");
    assert!(
        error.to_string().contains("frozen"),
        "the state fault says the transfer is frozen: {error}"
    );
    assert!(
        error.to_string().contains("abort"),
        "the state fault names the way out: {error}"
    );
}

/// A reply says whether the body has a canonical address, and why it does not
/// when the address could have been computed (round 10, M-4).
#[test]
fn a_reply_says_whether_the_body_is_canonical() {
    // Not an image: `canonical: false` and no error, because nothing failed.
    let plain = BulkTransfer::new(body(2_000, 93), 1_000).expect("transfer");
    let mut provider = BulkProvider::new();
    drive(&mut provider, &plain, 0, 0);
    let mut finish = call("finish", plain.finish_frame());
    finish.now_ms = 0;
    let map = reply_map(provider.invoke(0, &finish).expect("finish"));
    assert_eq!(map.get("canonical"), Some(&Value::Bool(false)));
    assert_eq!(map.get("content"), None);
    assert_eq!(map.get("content_error"), None, "a non-image has no error");

    // An image: `canonical: true` and the address.
    const SOURCE: &str = "[app]\nname = \"bulk-r10\"\n";
    let module = active_rpc::domain::module_from_source(SOURCE, "bulk-r10.active").expect("module");
    let image = active_infinity::encode(&module).expect("encode");
    let transfer = BulkTransfer::new(image, 4_096).expect("transfer");
    let mut provider = BulkProvider::new();
    drive(&mut provider, &transfer, 0, 0);
    let mut finish = call("finish", transfer.finish_frame());
    finish.now_ms = 0;
    let map = reply_map(provider.invoke(0, &finish).expect("finish"));
    assert_eq!(map.get("canonical"), Some(&Value::Bool(true)));
    assert!(matches!(map.get("content"), Some(Value::Text(_))));
    assert_eq!(map.get("content_error"), None);
}

use active_rpc::wire::Envelope;
