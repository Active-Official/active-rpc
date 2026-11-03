//! R-10 bulk hardening: plan binding, budget charging, bounded resume and the
//! provider that gives the wire format a consumer.
//!
//! Every test drives the shipped `active_rpc::bulk` API. The end-to-end case
//! goes through a real kernel: the plan, chunks and finish marker travel as the
//! envelope payload, so the registry, the method grant and the byte budget all
//! apply.

use std::collections::BTreeMap;

use active_rpc::bulk::{
    BulkChunk, BulkFinish, BulkPlan, BulkProvider, BulkReceiver, BulkRequest, BulkSender,
    BulkTransfer, MAX_CHUNK, MAX_CHUNKS,
};
use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::wire::Envelope;
use active_rpc::{Agent, Budget, CapToken, Error, Value};

fn body(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| seed.wrapping_add(index as u8))
        .collect()
}

fn plan_frame(plan: &BulkPlan) -> Vec<u8> {
    plan.encode()
}

/// A plan is internally consistent, not authoritative: pinning the root is what
/// refuses a substituted plan.
#[test]
fn a_substituted_plan_is_refused_by_the_pinned_root() {
    let honest = body(200_000, 1);
    let substituted = body(200_000, 2);
    let plan_a = BulkPlan::new(&honest, 64 * 1024).expect("plan a");
    let plan_b = BulkPlan::new(&substituted, 64 * 1024).expect("plan b");
    assert_ne!(plan_a.root(), plan_b.root());

    let error = BulkReceiver::with_expected_root(plan_b.clone(), plan_a.root())
        .expect_err("a plan with another root is refused");
    assert_eq!(error.code(), "rpc/bulk");

    let mut provider = BulkProvider::with_expected_root(plan_a.root());
    let call = active_rpc::Call::new("plan", Vec::new()).with_payload(plan_frame(&plan_b));
    let error = provider
        .invoke(0, &call)
        .expect_err("the provider refuses a substituted plan");
    assert_eq!(error.code(), "rpc/bulk");
    assert!(provider.active_root().is_none());
}

/// The transfer context folds into the root and is never transmitted, so a plan
/// built for one exchange cannot be replayed into another.
#[test]
fn a_plan_is_bound_to_its_transfer_context() {
    let bytes = body(70_000, 3);
    let context = b"request 7 / capability 9f31";
    let plan = BulkPlan::new_with_context(&bytes, 32 * 1024, context).expect("plan");
    let encoded = plan.encode();

    let error = BulkPlan::decode(&encoded).expect_err("no context");
    assert_eq!(error.code(), "rpc/bulk");
    let error = BulkPlan::decode_with_context(&encoded, b"request 8 / capability 9f31")
        .expect_err("another context");
    assert_eq!(error.code(), "rpc/bulk");
    let recovered = BulkPlan::decode_with_context(&encoded, context).expect("same context");
    assert_eq!(recovered.root(), plan.root());
}

/// A receiver with a budget charges the wire size of every accepted frame before
/// it stores the chunk, so a refused chunk costs no memory.
#[test]
fn a_receiver_charges_every_chunk_and_stores_nothing_refused() {
    // The plan fits the grant, but the two chunk frames plus their headers do
    // not: the second charge is what refuses, and nothing is stored.
    let bytes = body(69_950, 4);
    let sender = BulkSender::new(bytes, 35_000).expect("sender");
    let budget = Budget {
        max_bytes: 70_000,
        ..Budget::default()
    };
    let mut receiver = BulkReceiver::with_budget(sender.plan().clone(), budget).expect("receiver");
    let frames = sender.frames();

    let first = receiver.accept(&frames[0]).expect("first chunk");
    assert_eq!(first, 0);
    let charged = receiver.charged_bytes();
    assert_eq!(charged, frames[0].len() as u64, "the wire size is charged");

    let error = receiver.accept(&frames[1]).expect_err("over the grant");
    assert_eq!(error.code(), "rpc/budget-exceeded");
    assert_eq!(
        receiver.bytes_received(),
        frames[0].len() as u64 - 53,
        "nothing was stored"
    );
    assert_eq!(receiver.charged_bytes(), charged, "nothing was charged");
}

/// A resume request comes from the peer: duplicates are collapsed and the list
/// is bounded by the plan instead of the request.
#[test]
fn a_resume_request_is_deduplicated_and_bounded() {
    let sender = BulkSender::new(body(4 * 64 * 1024, 5), 64 * 1024).expect("sender");
    let duplicate = sender.frames_for(&[0, 0, 1]).expect("duplicates collapse");
    assert_eq!(duplicate.len(), 2);

    let over = vec![0u32; sender.plan().chunk_count() as usize + 1];
    let error = sender.frames_for(&over).expect_err("bounded by the plan");
    assert_eq!(error.code(), "rpc/bulk");

    let outside = sender
        .frames_for(&[sender.plan().chunk_count()])
        .expect_err("outside the plan");
    assert_eq!(outside.code(), "rpc/bulk");

    let error = sender
        .frames_from(sender.plan().chunk_count() + 1)
        .expect_err("a resume point past the plan is an error");
    assert_eq!(error.code(), "rpc/bulk");
}

/// A small frame cannot declare a body the receiver would never admit, and the
/// refusal happens before the hash vector exists.
#[test]
fn a_plan_counts_are_bounded_before_allocation() {
    let plan = BulkPlan::new(&body(70_000, 6), 16 * 1024).expect("plan");
    let mut frame = plan_frame(&plan);
    // Rewrite the chunk count to one past the ceiling; the length check comes
    // after the count check, so this is refused without reading hashes.
    frame[17..21].copy_from_slice(&(MAX_CHUNKS + 1).to_le_bytes());
    let error = BulkPlan::decode(&frame).expect_err("too many chunks");
    assert_eq!(error.code(), "rpc/bulk");

    // A body larger than the ceiling is refused even when the count is legal.
    let mut huge = plan_frame(&plan);
    huge[9..17].copy_from_slice(&(1u64 << 40).to_le_bytes());
    let error = BulkPlan::decode_with_ceiling(&huge, 1 << 20).expect_err("above the ceiling");
    assert_eq!(error.code(), "rpc/bulk");
}

#[test]
fn a_finish_marker_names_the_transfer() {
    let plan_a = BulkPlan::new(&body(100_000, 7), 32 * 1024).expect("plan a");
    let plan_b = BulkPlan::new(&body(100_000, 8), 32 * 1024).expect("plan b");
    let marker = BulkFinish::new(&plan_a);
    let error =
        BulkFinish::decode(&marker.encode(), &plan_b).expect_err("a marker from another transfer");
    assert_eq!(error.code(), "rpc/bulk");
    let decoded = BulkFinish::decode(&marker.encode(), &plan_a).expect("its own plan");
    assert_eq!(decoded.root(), plan_a.root());
    assert_eq!(decoded.total(), plan_a.total());
}

#[test]
fn a_request_frame_round_trips_and_refuses_an_off_plan_index() {
    let plan = BulkPlan::new(&body(5 * 32 * 1024, 9), 32 * 1024).expect("plan");
    let request = BulkRequest::new(&[4, 1, 1]);
    assert_eq!(request.missing(), &[1, 4]);
    let decoded = BulkRequest::decode(&request.encode(), &plan).expect("decode");
    assert_eq!(decoded, request);

    let mut outside = request.encode();
    outside[9..13].copy_from_slice(&9u32.to_le_bytes());
    let error = BulkRequest::decode(&outside, &plan).expect_err("off plan");
    assert_eq!(error.code(), "rpc/bulk");
}

/// Debug output must not carry the body: a bulk body may be a secret, and a
/// gigabyte of it is a log bomb.
#[test]
fn debug_does_not_print_the_body() {
    let canary = b"bulk-canary-4f31";
    let chunk = BulkChunk::new(0, 64 * 1024, canary);
    let text = format!("{chunk:?}");
    assert!(!text.contains("bulk-canary"), "{text}");

    let sender = BulkSender::new(canary.to_vec(), 8).expect("sender");
    let text = format!("{sender:?}");
    assert!(!text.contains("bulk-canary"), "{text}");

    let mut receiver = BulkReceiver::new(sender.plan().clone()).expect("receiver");
    for frame in sender.frames() {
        receiver.accept(&frame).expect("chunk");
    }
    let text = format!("{receiver:?}");
    assert!(!text.contains("bulk-canary"), "{text}");
}

/// One chunk larger than the frame format can carry is refused at construction.
#[test]
fn a_chunk_cannot_exceed_the_frame_ceiling() {
    let error =
        BulkChunk::try_new(0, MAX_CHUNK, &vec![0u8; MAX_CHUNK + 1]).expect_err("oversized chunk");
    assert_eq!(error.code(), "rpc/bulk");
    let chunk = BulkChunk::try_new(0, MAX_CHUNK, &vec![0u8; MAX_CHUNK]).expect("at the ceiling");
    let decoded = BulkChunk::decode(&chunk.encode()).expect("round trip");
    assert_eq!(decoded.hash(), chunk.hash());
}

/// The provider refuses chunks for a transfer it never opened.
#[test]
fn the_provider_refuses_a_chunk_without_a_transfer() {
    let mut provider = BulkProvider::new();
    let sender = BulkSender::new(body(70_000, 10), 32 * 1024).expect("sender");
    let frame = sender.frame_at(0).expect("frame");
    let call = active_rpc::Call::new("put", Vec::new()).with_payload(frame);
    let error = provider.invoke(0, &call).expect_err("no transfer");
    assert_eq!(error.code(), "rpc/bulk");
}

/// A whole transfer through a real kernel: plan, chunks, missing list, finish.
///
/// The frames ride as envelope payloads, so the registry, the method grant and
/// the ingress byte charge all apply; the provider re-checks the pinned root.
#[test]
fn a_bulk_transfer_through_the_kernel_assembles_the_body() {
    let payload = body(400_000, 11);
    let transfer = BulkTransfer::new(payload.clone(), 128 * 1024).expect("transfer");
    let root = transfer.plan().root();
    let provider = BulkProvider::with_expected_root(root);

    let agent = Agent::new();
    let id = agent.register(Box::new(provider));
    let lane = agent.create_lane("bulk", Budget::default()).expect("lane");
    let cap = agent
        .mint(id, 0, CapAttrs::new(&["plan", "put", "missing", "finish"]))
        .expect("cap");

    let call = |request_id: u64, method: &str, frame: Vec<u8>| -> Vec<(String, Value)> {
        let envelope = Envelope::request(request_id, method, Vec::new()).with_payload(frame);
        let promise = agent
            .call_from_envelope(None, lane, &cap, &envelope)
            .expect("queued");
        agent.run();
        let reply = promise.value().expect("settled");
        match &reply {
            Value::Map(entries) => entries
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
            other => panic!("unexpected reply {other:?}"),
        }
    };
    let dispatch = call;

    let plan_reply = dispatch(1, "plan", transfer.plan_frame());
    let plan_map: BTreeMap<String, Value> = plan_reply.into_iter().collect();
    assert_eq!(
        plan_map.get("root"),
        Some(&Value::text(transfer.plan().root_hex()))
    );
    assert_eq!(
        plan_map.get("missing"),
        Some(&Value::Int(transfer.plan().chunk_count() as i64))
    );

    for index in 0..transfer.plan().chunk_count() {
        let reply = dispatch(
            2 + index as u64,
            "put",
            transfer.chunk_frame(index).expect("chunk"),
        );
        let map: BTreeMap<String, Value> = reply.into_iter().collect();
        assert_eq!(map.get("index"), Some(&Value::Int(index as i64)));
    }

    let missing = dispatch(90, "missing", Vec::new());
    let missing_map: BTreeMap<String, Value> = missing.into_iter().collect();
    match missing_map.get("missing") {
        Some(Value::List(items)) => assert!(items.is_empty(), "{items:?}"),
        other => panic!("unexpected missing list {other:?}"),
    }

    let finish = dispatch(91, "finish", transfer.finish_frame());
    let finish_map: BTreeMap<String, Value> = finish.into_iter().collect();
    let expected = *blake3::hash(&payload).as_bytes();
    let mut hex = String::new();
    for byte in expected {
        hex.push_str(&format!("{byte:02x}"));
    }
    assert_eq!(finish_map.get("hash"), Some(&Value::text(hex)));
    assert_eq!(
        finish_map.get("length"),
        Some(&Value::Int(payload.len() as i64))
    );
}

/// A capability that does not grant `put` cannot push a chunk, and a budget that
/// covers only part of the body refuses the chunk that would cross it.
#[test]
fn the_kernel_grant_and_byte_budget_bound_a_bulk_transfer() {
    let payload = body(400_000, 12);
    let transfer = BulkTransfer::new(payload.clone(), 128 * 1024).expect("transfer");
    let root = transfer.plan().root();
    let agent = Agent::new();
    let id = agent.register(Box::new(BulkProvider::with_expected_root(root)));
    let lane = agent.create_lane("bulk", Budget::default()).expect("lane");

    let read_only = agent
        .mint(id, 0, CapAttrs::new(&["plan", "missing"]))
        .expect("cap");
    let envelope = Envelope::request(1, "put", Vec::new())
        .with_payload(transfer.chunk_frame(0).expect("chunk"));
    let error = agent
        .call_from_envelope(None, lane, &read_only, &envelope)
        .expect_err("put is not granted");
    assert_eq!(error.code(), "rpc/method-not-granted");

    // A 200 KiB grant: the plan fits, the first chunk fits, the second does not.
    let mut attrs = CapAttrs::new(&["plan", "put", "missing", "finish"]);
    attrs.budget.max_bytes = 200 * 1024;
    let small = agent.mint(id, 0, attrs).expect("cap");
    let plan = agent
        .call_from_envelope(
            None,
            lane,
            &small,
            &Envelope::request(2, "plan", Vec::new()).with_payload(transfer.plan_frame()),
        )
        .expect("plan");
    agent.run();
    plan.value().expect("plan settles");

    let first = agent
        .call_from_envelope(
            None,
            lane,
            &small,
            &Envelope::request(3, "put", Vec::new())
                .with_payload(transfer.chunk_frame(0).expect("chunk")),
        )
        .expect("first chunk");
    agent.run();
    first.value().expect("first chunk settles");

    let error = agent
        .call_from_envelope(
            None,
            lane,
            &small,
            &Envelope::request(4, "put", Vec::new())
                .with_payload(transfer.chunk_frame(1).expect("chunk")),
        )
        .expect_err("the grant is spent");
    assert_eq!(error.code(), "rpc/budget-exceeded");
    let _ = CapToken(0);
}

/// An idempotent call can carry a payload, the payload is charged, and the size
/// is part of the key's fingerprint.
#[test]
fn an_idempotent_call_with_a_payload_is_charged_and_fingerprinted() {
    struct Echo;
    impl Provider for Echo {
        fn name(&self) -> &'static str {
            "echo"
        }
        fn methods(&self) -> Vec<String> {
            vec!["ping".to_string()]
        }
        fn mutating(&self, _method: &str) -> bool {
            false
        }
        fn invoke(
            &mut self,
            _object: u64,
            _call: &active_rpc::Call,
        ) -> active_rpc::Result<active_rpc::Response> {
            Ok(active_rpc::Response::Value(Value::Null))
        }
    }

    let agent = Agent::new();
    let id = agent.register(Box::new(Echo));
    let lane = agent.create_lane("idem", Budget::default()).expect("lane");
    let cap = agent.mint(id, 0, CapAttrs::new(&["ping"])).expect("cap");

    let error = agent
        .call_idempotent_as_with_payload(
            None,
            lane,
            &cap,
            "ping",
            Vec::new(),
            Budget::default().max_bytes + 1,
            "key-1",
        )
        .expect_err("over the grant");
    assert!(matches!(error, Error::BudgetExceeded("byte")), "{error:?}");

    let promise = agent
        .call_idempotent_as_with_payload(None, lane, &cap, "ping", Vec::new(), 1024, "key-2")
        .expect("within the grant");
    agent.run();
    promise.value().expect("settles");

    let error = agent
        .call_idempotent_as_with_payload(None, lane, &cap, "ping", Vec::new(), 2048, "key-2")
        .expect_err("a different payload size is a different call");
    assert_eq!(error.code(), "rpc/invalid-argument");
}

/// Egress payload bytes are charged to the same grant as ingress, so
/// `max_bytes` bounds the round trip rather than one direction of it.
#[test]
fn egress_payload_bytes_are_charged() {
    struct Echo;
    impl Provider for Echo {
        fn name(&self) -> &'static str {
            "echo"
        }
        fn methods(&self) -> Vec<String> {
            vec!["ping".to_string()]
        }
        fn mutating(&self, _method: &str) -> bool {
            false
        }
        fn invoke(
            &mut self,
            _object: u64,
            call: &active_rpc::Call,
        ) -> active_rpc::Result<active_rpc::Response> {
            // A provider that echoes its payload, which is what the CLI does.
            Ok(active_rpc::Response::Value(Value::Int(
                call.payload.len() as i64
            )))
        }
    }

    let agent = Agent::new();
    let id = agent.register(Box::new(Echo));
    let lane = agent
        .create_lane("egress", Budget::default())
        .expect("lane");
    let mut attrs = CapAttrs::new(&["ping"]);
    attrs.budget.max_bytes = 13 * 1024;
    let cap = agent.mint(id, 0, attrs).expect("cap");

    let promise = agent
        .call_with_payload(lane, &cap, "ping", Vec::new(), 6 * 1024)
        .expect("first round trip");
    agent.run();
    promise.value().expect("settles");
    agent
        .charge_egress_bytes(lane, &cap, 6 * 1024)
        .expect("the echoed half fits");

    let error = agent
        .call_with_payload(lane, &cap, "ping", Vec::new(), 6 * 1024)
        .expect_err("the grant is spent after the round trip");
    assert_eq!(error.code(), "rpc/budget-exceeded");
}

/// A retransmitted plan frame is ordinary on a flaky link. It must not reset the
/// chunks the caller already sent and paid for.
#[test]
fn a_retried_plan_keeps_the_received_chunks() {
    let payload = body(200_000, 21);
    let sender = BulkSender::new(payload, 32 * 1024).expect("sender");
    let plan = sender.plan().clone();
    let mut provider = BulkProvider::new();

    let call = active_rpc::Call::new("plan", Vec::new()).with_payload(plan.encode());
    let first = provider.invoke(0, &call).expect("plan");
    let missing_of = |response: &active_rpc::Response| -> i64 {
        match response {
            active_rpc::Response::Value(value) => match &value {
                Value::Map(map) => match map.get("missing") {
                    Some(Value::Int(missing)) => *missing,
                    other => panic!("no missing field: {other:?}"),
                },
                other => panic!("not a map: {other:?}"),
            },
            other => panic!("not a value: {other:?}"),
        }
    };
    let _ = first;

    let frame = sender.frame_at(0).expect("frame");
    let put = active_rpc::Call::new("put", Vec::new()).with_payload(frame);
    provider.invoke(0, &put).expect("chunk");

    let repeat = provider
        .invoke(0, &call)
        .expect("a retried plan is accepted");
    assert_eq!(
        missing_of(&repeat),
        (plan.chunk_count() - 1) as i64,
        "the retried plan kept the first chunk"
    );
    provider
        .invoke(
            0,
            &active_rpc::Call::new("finish", Vec::new())
                .with_payload(BulkFinish::new(&plan).encode()),
        )
        .expect_err("the rest is still missing");
}

/// A finish that cannot settle the transfer (wrong marker, or an incomplete
/// body) must not destroy the chunks already received: the caller would have to
/// pay for the whole body again.
#[test]
fn a_refused_finish_keeps_the_transfer() {
    let payload = body(150_000, 22);
    let sender = BulkSender::new(payload, 32 * 1024).expect("sender");
    let plan = sender.plan().clone();
    let mut provider = BulkProvider::new();

    let plan_call = active_rpc::Call::new("plan", Vec::new()).with_payload(plan.encode());
    provider.invoke(0, &plan_call).expect("plan");

    // Every chunk but the last.
    for index in 0..plan.chunk_count() - 1 {
        let frame = sender.frame_at(index).expect("frame");
        let put = active_rpc::Call::new("put", Vec::new()).with_payload(frame);
        provider.invoke(0, &put).expect("chunk");
    }

    // A finish before the last chunk is refused and keeps the state.
    let early =
        active_rpc::Call::new("finish", Vec::new()).with_payload(BulkFinish::new(&plan).encode());
    let error = provider.invoke(0, &early).expect_err("incomplete");
    assert_eq!(error.code(), "rpc/bulk");
    assert_eq!(provider.active_root(), Some(plan.root()));

    let last = sender.frame_at(plan.chunk_count() - 1).expect("frame");
    provider
        .invoke(
            0,
            &active_rpc::Call::new("put", Vec::new()).with_payload(last),
        )
        .expect("last chunk");

    // A marker for another transfer is refused and keeps the state too.
    let other = BulkPlan::new(&body(150_000, 23), 32 * 1024).expect("other plan");
    let foreign =
        active_rpc::Call::new("finish", Vec::new()).with_payload(BulkFinish::new(&other).encode());
    let error = provider.invoke(0, &foreign).expect_err("another transfer");
    assert_eq!(error.code(), "rpc/bulk");
    assert_eq!(provider.active_root(), Some(plan.root()));

    provider
        .invoke(
            0,
            &active_rpc::Call::new("finish", Vec::new())
                .with_payload(BulkFinish::new(&plan).encode()),
        )
        .expect("the complete body settles");
    let (assembled, _) = provider.take_body().expect("body");
    assert_eq!(assembled.len(), plan.total() as usize);
}
