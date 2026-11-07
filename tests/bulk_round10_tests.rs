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

/// The live bound counts the retained plan hash vector but **not** the announced
/// total of a plan nobody has paid for: an unpaid plan holds its vector, and the
/// chunks reserve more as they arrive (round 10, M-1; round 18, #1).
#[test]
fn the_live_bound_counts_the_plan_and_not_an_unpaid_total() {
    let transfer = BulkTransfer::new(body(10, 90), 1).expect("transfer");
    let plan = transfer.plan().clone();
    // `PLAN_OVERHEAD` (53) plus one 32-byte hash per chunk.
    let vector = 53 + 32 * plan.chunk_count() as u64;
    assert!(
        vector > 2 * plan.total(),
        "the fixture must be vector-heavy"
    );

    let mut tight = BulkProvider::new().with_max_live_bytes(vector - 1);
    assert!(
        tight.invoke(0, &call("plan", plan.encode())).is_err(),
        "a bound one byte under the vector must refuse the plan"
    );

    let mut exact = BulkProvider::new().with_max_live_bytes(vector);
    exact
        .invoke(0, &call("plan", plan.encode()))
        .expect("the vector fits");
    assert_eq!(
        exact.live_bytes(),
        vector,
        "an announced plan reserves its hash vector, not twice its total"
    );

    // Storing a chunk reserves twice its bytes on top of the vector, so a bound
    // exactly at the vector has no room for even one chunk.
    let chunk = transfer.chunk_frame(0).expect("chunk");
    let stored = (chunk.len() - 53) as u64;
    let error = exact
        .invoke(0, &call("put", chunk.clone()))
        .expect_err("no room for the first chunk");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");

    let mut roomy = BulkProvider::new().with_max_live_bytes(vector + 2 * stored);
    roomy.invoke(0, &call("plan", plan.encode())).expect("plan");
    roomy
        .invoke(0, &call("put", chunk))
        .expect("the first chunk fits");
    assert_eq!(roomy.live_bytes(), vector + 2 * stored);
}

/// A large announced body is admitted under a small live bound, and a chunk that
/// would push the bound is refused before it is stored (round 18, #1).
#[test]
fn an_unpaid_plan_does_not_hold_the_provider_bound() {
    let big = BulkTransfer::new(body(64 << 20, 0x21), 256 * 1024).expect("transfer");
    let other = BulkTransfer::new(body(64 << 20, 0x22), 256 * 1024).expect("transfer");
    let mut provider = BulkProvider::new().with_max_live_bytes(4 << 20);

    // Two announced 64 MiB bodies fit: neither has stored anything yet.
    provider
        .invoke(0, &call("plan", big.plan_frame()))
        .expect("an unpaid plan reserves its vector");
    provider
        .invoke(1, &call("plan", other.plan_frame()))
        .expect("a second unpaid plan also fits");

    // A chunk is 256 KiB, so twice it is 512 KiB: it fits, and enough chunks to
    // pass the bound are refused at the ceiling.
    provider
        .invoke(0, &call("put", big.chunk_frame(0).expect("chunk")))
        .expect("the first chunk fits");
    let mut refused = false;
    for index in 1..64u32 {
        match provider.invoke(0, &call("put", big.chunk_frame(index).expect("chunk"))) {
            Ok(_) => {}
            Err(error) => {
                assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
                refused = true;
                break;
            }
        }
    }
    assert!(refused, "the bound refuses a chunk before it is stored");
    assert!(
        provider.live_bytes() <= 4 << 20,
        "the reservation never passes the bound"
    );
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
