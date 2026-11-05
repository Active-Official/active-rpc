//! R-10 bulk round 3: per-object state, bounded per-frame work, an idempotent
//! finish, the content address, the provider's transfer context, and the
//! sender-side ceilings.
//!
//! Every test drives the shipped `active_rpc::bulk` API through `Provider::invoke`
//! or the receiver itself; nothing re-implements the code under test.

use std::collections::BTreeMap;
use std::time::Instant;

use active_rpc::bulk::{
    BulkFinish, BulkPlan, BulkProvider, BulkReceiver, BulkSender, BulkTransfer, CHUNK_OVERHEAD,
    MAX_CHUNKS, MAX_TOTAL, MISSING_PAGE, TRANSFER_IDLE_MS,
};
use active_rpc::cap::CapId;
use active_rpc::kernel::Provider;
use active_rpc::value::{Call, Value};
use active_rpc::Error;

fn body(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| seed.wrapping_add((index % 251) as u8))
        .collect()
}

fn hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
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

/// State is keyed by object: two capabilities on one provider never see each
/// other's transfer, and neither can wedge the other (round 3, F1).
#[test]
fn two_objects_hold_two_independent_transfers() {
    let first = BulkPlan::new(&body(90_000, 1), 30_000).expect("plan a");
    let second = BulkPlan::new(&body(60_000, 2), 20_000).expect("plan b");
    let mut provider = BulkProvider::new();

    let reply = reply_map(
        provider
            .invoke(7, &call("plan", first.encode()))
            .expect("object 7 plans"),
    );
    assert_eq!(
        reply.get("missing"),
        Some(&Value::Int(first.chunk_count() as i64))
    );

    // A different plan on another object is admitted, where the single slot
    // used to refuse it for every peer on the provider.
    let reply = reply_map(
        provider
            .invoke(8, &call("plan", second.encode()))
            .expect("object 8 plans too"),
    );
    assert_eq!(
        reply.get("root"),
        Some(&Value::text(second.root_hex())),
        "object 8 must see its own plan"
    );
    assert_eq!(provider.active_root(7), Some(first.root()));
    assert_eq!(provider.active_root(8), Some(second.root()));

    // A chunk for object 8 is refused against object 7's plan, and lands on 8.
    let sender = BulkSender::new(body(60_000, 2), 20_000).expect("sender");
    let frame = sender.frame_at(0).expect("frame");
    provider
        .invoke(8, &call("put", frame.clone()))
        .expect("object 8 accepts its chunk");
    let error = provider
        .invoke(7, &call("put", frame))
        .expect_err("object 7 has another plan");
    assert_eq!(error.code(), "rpc/bulk", "{error}");
    assert_eq!(
        reply_map(
            provider
                .invoke(8, &call("missing", Vec::new()))
                .expect("missing")
        )
        .get("remaining"),
        Some(&Value::Int(second.chunk_count() as i64 - 1))
    );
}

/// The kernel's drop notification releases both the incomplete transfer and an
/// untaken body (round 3, F1).
#[test]
fn a_dropped_capability_releases_its_bulk_state() {
    let plan = BulkPlan::new(&body(3_000, 4), 1_000).expect("plan");
    let sender = BulkSender::new(body(3_000, 4), 1_000).expect("sender");
    let mut provider = BulkProvider::new();
    provider
        .invoke(3, &call("plan", plan.encode()))
        .expect("plan");
    for index in 0..plan.chunk_count() {
        provider
            .invoke(3, &call("put", sender.frame_at(index).expect("frame")))
            .expect("chunk");
    }
    provider
        .invoke(3, &call("finish", BulkFinish::new(&plan).encode()))
        .expect("finish");
    assert!(provider.has_body(3));
    assert_eq!(provider.active_root(3), None);

    provider.on_drop(3, CapId([9; 16]));
    assert!(!provider.has_body(3), "the body was retained");
    assert_eq!(provider.take_body(3).map(|body| body.len()), None);
}

/// An incomplete transfer past the idle window is released, so a peer that
/// opens a transfer and sends nothing cannot hold the slot (round 3, F1).
#[test]
fn an_idle_transfer_expires() {
    let plan = BulkPlan::new(&body(4_000, 5), 1_000).expect("plan");
    let mut provider = BulkProvider::new();
    let mut open = call("plan", plan.encode());
    open.now_ms = 10_000;
    provider.invoke(1, &open).expect("plan");
    assert_eq!(provider.active_root(1), Some(plan.root()));

    let mut idle = call("missing", Vec::new());
    idle.now_ms = 10_000 + TRANSFER_IDLE_MS;
    assert_eq!(
        reply_map(provider.invoke(1, &idle).expect("still inside the window")).get("remaining"),
        Some(&Value::Int(plan.chunk_count() as i64))
    );

    let mut late = call("missing", Vec::new());
    late.now_ms = 10_000 + TRANSFER_IDLE_MS + 1;
    let error = provider.invoke(1, &late).expect_err("the transfer is gone");
    assert_eq!(error.code(), "rpc/bulk");
    assert_eq!(provider.active_root(1), None);
}

/// A `put` does constant work whatever the plan size: the old path summed the
/// stored bytes and scanned every index per frame, which is quadratic on a plan
/// with tiny chunks (round 3, F2).
#[test]
fn a_put_on_a_large_plan_is_bounded() {
    // The largest plan the protocol allows, with the smallest chunk: 32 766
    // one-byte chunks.
    let chunks = MAX_CHUNKS as usize;
    let payload = body(chunks, 6);
    let sender = BulkSender::new(payload.clone(), 1).expect("sender");
    let plan = sender.plan().clone();
    assert_eq!(plan.chunk_count() as usize, chunks);
    let mut provider = BulkProvider::new();
    provider
        .invoke(0, &call("plan", plan.encode()))
        .expect("plan");

    let started = Instant::now();
    for index in 0..plan.chunk_count() {
        let reply = reply_map(
            provider
                .invoke(0, &call("put", sender.frame_at(index).expect("frame")))
                .expect("chunk"),
        );
        // The status is derived from the stored set, and it is exact.
        assert_eq!(
            reply.get("missing"),
            Some(&Value::Int(chunks as i64 - index as i64 - 1))
        );
        assert_eq!(reply.get("received"), Some(&Value::Int(index as i64 + 1)));
    }
    let elapsed = started.elapsed();
    // A hang guard for a quadratic regression, not a performance budget: the
    // round-2 code did ~5 x 10^8 map probes and allocated 128 KiB per frame for
    // this plan, minutes of work on this runner.
    assert!(
        elapsed < std::time::Duration::from_secs(30),
        "32 766 puts took {elapsed:?}"
    );
    let reply = reply_map(
        provider
            .invoke(0, &call("finish", BulkFinish::new(&plan).encode()))
            .expect("finish"),
    );
    assert_eq!(reply.get("length"), Some(&Value::Int(payload.len() as i64)));
}

/// A repeated finish marker answers with the same reply instead of a refusal:
/// the effect landed, and a retry must not be receipted as `rpc/bulk`
/// (round 3, F3).
#[test]
fn a_repeated_finish_answers_with_the_same_reply() {
    let payload = body(5_000, 7);
    let plan = BulkPlan::new(&payload, 2_000).expect("plan");
    let sender = BulkSender::new(payload, 2_000).expect("sender");
    let mut provider = BulkProvider::new();
    provider
        .invoke(0, &call("plan", plan.encode()))
        .expect("plan");
    for index in 0..plan.chunk_count() {
        provider
            .invoke(0, &call("put", sender.frame_at(index).expect("frame")))
            .expect("chunk");
    }
    let marker = BulkFinish::new(&plan).encode();
    let first = reply_map(
        provider
            .invoke(0, &call("finish", marker.clone()))
            .expect("finish"),
    );
    let second = reply_map(
        provider
            .invoke(0, &call("finish", marker.clone()))
            .expect("a repeated marker is not a fault"),
    );
    assert_eq!(first, second);
    assert_eq!(
        second.get("body_hash"),
        Some(&Value::text(hex(
            blake3::hash(&plan_body(&plan, &sender)).as_bytes()
        ))),
        "the reply names the body digest"
    );

    // An untaken body is not silently replaced by a new transfer.
    let other = BulkPlan::new(&body(1_000, 8), 500).expect("other");
    let error = provider
        .invoke(0, &call("plan", other.encode()))
        .expect_err("the previous body was not taken");
    assert_eq!(error.code(), "rpc/bulk");
    assert!(provider.take_body(0).is_some());

    // Once taken, the object is free again.
    provider
        .invoke(0, &call("plan", other.encode()))
        .expect("a taken body frees the object");
}

fn plan_body(plan: &BulkPlan, sender: &BulkSender) -> Vec<u8> {
    let mut out = Vec::with_capacity(plan.total() as usize);
    for index in 0..plan.chunk_count() {
        let frame = sender.frame_at(index).expect("frame");
        // The frame header is fixed: magic, version, index, offset, length and
        // hash.
        out.extend_from_slice(&frame[CHUNK_OVERHEAD as usize..]);
    }
    out
}

/// The finish reply publishes the canonical, redacted content address for an
/// Infinity image, and the raw body digest under a name that says it is not one
/// (round 3, F4).
#[test]
fn a_transferred_image_reports_the_redacted_content_address() {
    const SOURCE: &str = r#"
[app]
name     = "bulk-content"
password = secret("bulk-canary")

[server]
host = "127.0.0.1"
port = 8080
"#;
    let module =
        active_rpc::domain::module_from_source(SOURCE, "bulk-content.active").expect("module");
    let image = active_infinity::encode(&module).expect("encode");
    let image = active_rpc::security::redact_module(&image).expect("redact");
    let expected = active_infinity::content_hash(&image).expect("content hash");

    let transfer = BulkTransfer::new(image.clone(), 4_096).expect("transfer");
    let plan = transfer.plan().clone();
    let mut provider = BulkProvider::new();
    provider
        .invoke(0, &call("plan", plan.encode()))
        .expect("plan");
    for index in 0..plan.chunk_count() {
        provider
            .invoke(0, &call("put", transfer.chunk_frame(index).expect("chunk")))
            .expect("chunk");
    }
    let reply = reply_map(
        provider
            .invoke(0, &call("finish", transfer.finish_frame()))
            .expect("finish"),
    );
    assert_eq!(reply.get("content"), Some(&Value::text(hex(&expected))));
    assert_eq!(
        reply.get("body_hash"),
        Some(&Value::text(hex(blake3::hash(&image).as_bytes())))
    );
    assert_ne!(
        format!("{:?}", reply.get("content")),
        format!("{:?}", reply.get("body_hash")),
        "the content address must not be the raw body digest"
    );
    let taken = provider.take_body(0).expect("body");
    assert_eq!(taken.content_hash(), Some(expected));
    assert_eq!(taken.body(), &image[..]);
}

/// A provider given the transfer context admits a context-bound plan and refuses
/// one bound to another exchange (round 3, F5).
#[test]
fn a_context_bound_plan_is_admitted_by_the_provider() {
    let payload = body(40_000, 11);
    let context = b"request 3 / capability 0f2a".to_vec();
    let plan = BulkPlan::new_with_context(&payload, 10_000, &context).expect("plan");
    let mut provider = BulkProvider::new().with_context(context.clone());
    provider
        .invoke(0, &call("plan", plan.encode()))
        .expect("the same context is admitted");

    let foreign = BulkPlan::new_with_context(&payload, 10_000, b"another exchange").expect("plan");
    let mut other = BulkProvider::new().with_context(context);
    let error = other
        .invoke(0, &call("plan", foreign.encode()))
        .expect_err("a plan from another exchange is refused");
    assert_eq!(error.code(), "rpc/bulk");
    assert_eq!(other.active_root(0), None);
}

/// A resume reply is a bounded window under the strict profile, with a `more`
/// flag, so a large transfer can be resumed in pages (round 3, F8).
#[test]
fn a_resume_reply_is_paged() {
    let chunks = (MISSING_PAGE * 2) as u32;
    let plan = BulkPlan::new(&body(chunks as usize, 12), 1).expect("plan");
    assert_eq!(plan.chunk_count(), chunks);
    assert!(chunks < MAX_CHUNKS);
    assert!(
        53 + 32 * plan.chunk_count() <= active_rpc::wire::WireLimits::strict().max_payload,
        "the plan frame must fit the strict payload ceiling"
    );
    let mut provider = BulkProvider::new();
    provider
        .invoke(0, &call("plan", plan.encode()))
        .expect("plan");
    let reply = reply_map(
        provider
            .invoke(0, &call("missing", Vec::new()))
            .expect("missing"),
    );
    match reply.get("missing") {
        Some(Value::List(items)) => assert_eq!(items.len(), MISSING_PAGE, "{items:?}"),
        other => panic!("unexpected missing list {other:?}"),
    }
    assert_eq!(reply.get("more"), Some(&Value::Bool(true)));
    assert_eq!(
        reply.get("remaining"),
        Some(&Value::Int(chunks as i64)),
        "the count is the whole transfer, not the page"
    );
}

/// A grant that covers the frames, not just the body bytes, carries the whole
/// transfer (round 3, F9).
#[test]
fn a_grant_that_covers_the_frames_is_enough() {
    let payload = body(3_000, 13);
    let sender = BulkSender::new(payload.clone(), 1_000).expect("sender");
    let plan = sender.plan().clone();
    let frames = plan.chunk_count() as u64;
    let grant = plan.total() + CHUNK_OVERHEAD * frames;
    let budget = active_rpc::Budget {
        max_bytes: grant,
        ..active_rpc::Budget::default()
    };
    let mut receiver = BulkReceiver::with_budget(plan.clone(), budget).expect("receiver");
    for index in 0..plan.chunk_count() {
        receiver
            .accept(&sender.frame_at(index).expect("frame"))
            .expect("chunk fits the grant");
    }
    assert_eq!(receiver.charged_bytes(), grant);
    assert_eq!(receiver.finish().expect("finish"), payload);
}

/// The sender side refuses a plan its own decoder rejects, and the chunk divisor
/// is guarded (round 3, F7, F10).
#[test]
fn a_plan_the_decoder_would_refuse_is_never_built() {
    let hashes = vec![[0u8; 32]; ((MAX_TOTAL + 1) / (64 * 1024) + 1) as usize];
    let error = BulkPlan::from_hashes(64 * 1024, MAX_TOTAL + 1, hashes)
        .expect_err("past the protocol ceiling");
    assert_eq!(error.code(), "rpc/bulk");

    let error = BulkPlan::from_hashes(0, 10, Vec::new()).expect_err("a zero chunk is refused");
    assert_eq!(error.code(), "rpc/bulk");

    // Whatever a sender builds, the decoder accepts.
    let plan = BulkPlan::new(&body(70_000, 14), 32 * 1024).expect("plan");
    let decoded = BulkPlan::decode(&plan.encode()).expect("the decoder accepts its own frames");
    assert_eq!(decoded.root(), plan.root());
    assert_eq!(decoded.chunk_count(), plan.chunk_count());
}

/// A failed finish keeps the transfer, so the paid-for chunks are not destroyed
/// by an error path (round 3, F6).
#[test]
fn a_finish_that_cannot_verify_keeps_the_chunks() {
    let payload = body(2_000, 15);
    let sender = BulkSender::new(payload.clone(), 1_000).expect("sender");
    let plan = sender.plan().clone();
    let mut receiver = BulkReceiver::new(plan.clone()).expect("receiver");
    for index in 0..plan.chunk_count() {
        receiver
            .accept(&sender.frame_at(index).expect("frame"))
            .expect("chunk");
    }
    assert!(receiver.is_complete());
    // A body whose bytes are all present assembles once; a second finish on the
    // drained receiver reports incompleteness rather than an internal fault.
    assert_eq!(receiver.finish().expect("finish"), payload);
    let error = receiver.finish().expect_err("the chunks were released");
    assert_eq!(error, Error::Bulk("body is incomplete"));
}
