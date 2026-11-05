//! R-10 bulk round 4: the redacted content address, the grant a whole transfer
//! needs, the true per-object contract, allocation order, resume liveness, the
//! strict plan frame, the finish reply surviving `take_body`, and body expiry.
//!
//! Every test drives the shipped provider through `Provider::invoke` or a real
//! kernel; nothing re-implements the code under test.

use std::collections::BTreeMap;
use std::time::Instant;

use active_rpc::bulk::{
    BulkPlan, BulkProvider, BulkReceiver, BulkSender, BulkTransfer, CHUNK_OVERHEAD,
    COMPLETED_IDLE_MS, MAX_CHUNKS, TRANSFER_IDLE_MS,
};
use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::value::{Call, Value};
use active_rpc::wire::{Envelope, WireLimits};
use active_rpc::{Agent, Budget, Error};

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

fn map_of(value: Value) -> BTreeMap<String, Value> {
    match value {
        Value::Map(entries) => entries,
        other => panic!("unexpected reply {other:?}"),
    }
}

/// Send every frame of a transfer through one capability with `grant` bytes and
/// report the first refusal. The kernel charges ingress and egress to the same
/// meter, which is what the documented grant has to cover (round 4, M-2).
fn run_through_kernel(transfer: &BulkTransfer, grant: u64) -> Result<(), Error> {
    let agent = Agent::new();
    let id = agent.register(Box::new(BulkProvider::new()));
    let lane = agent.create_lane("bulk", Budget::default()).expect("lane");
    let mut attrs = CapAttrs::new(&["plan", "put", "missing", "finish"]);
    attrs.budget.max_bytes = grant;
    let cap = agent.mint(id, 0, attrs).expect("cap");

    let mut request = 1u64;
    let plan = agent.call_from_envelope(
        None,
        lane,
        &cap,
        &Envelope::request(request, "plan", Vec::new()).with_payload(transfer.plan_frame()),
    )?;
    agent.run();
    let _ = plan.value()?;
    for index in 0..transfer.plan().chunk_count() {
        request += 1;
        let frame = transfer.chunk_frame(index)?;
        let promise = agent.call_from_envelope(
            None,
            lane,
            &cap,
            &Envelope::request(request, "put", Vec::new()).with_payload(frame),
        )?;
        agent.run();
        let _ = promise.value()?;
    }
    request += 1;
    let finish = agent.call_from_envelope(
        None,
        lane,
        &cap,
        &Envelope::request(request, "finish", Vec::new()).with_payload(transfer.finish_frame()),
    )?;
    agent.run();
    let _ = finish.value()?;
    Ok(())
}

/// The content address published for a body that still holds a secret is the
/// **redacted** canonical hash, never the raw one (round 4, H-1).
#[test]
fn the_content_address_is_the_redacted_hash() {
    const SOURCE: &str = r#"
[app]
name     = "bulk-round4"
password = secret("bulk-round4-canary")

[server]
host = "127.0.0.1"
port = 8080
"#;
    let module =
        active_rpc::domain::module_from_source(SOURCE, "bulk-round4.active").expect("module");
    let image = active_infinity::encode(&module).expect("encode");
    let raw = active_infinity::content_hash(&image).expect("raw hash");
    let redacted = active_rpc::security::redact_module(&image).expect("redact");
    let expected = active_infinity::content_hash(&redacted).expect("redacted hash");
    assert_ne!(raw, expected, "the fixture must have a secret to redact");

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
    assert_eq!(
        reply.get("content"),
        Some(&Value::text(hex(&expected))),
        "the reply must publish the redacted address"
    );
    assert_ne!(
        reply.get("content"),
        Some(&Value::text(hex(&raw))),
        "the raw canonical hash is an offline equality oracle"
    );
    assert_eq!(
        reply.get("body_hash"),
        Some(&Value::text(hex(blake3::hash(&image).as_bytes())))
    );
    // The host's view carries the same redacted address.
    let taken = provider.take_body(0).expect("body");
    assert_eq!(taken.content_hash(), Some(expected));
}

/// `required_grant` carries a whole transfer through a kernel, while the
/// chunk-frames-only formula does not (round 4, M-2).
#[test]
fn the_required_grant_carries_the_whole_transfer() {
    let transfer = BulkTransfer::new(body(300_000, 20), 32 * 1024).expect("transfer");
    let chunks = transfer.plan().chunk_count() as u64;
    let frames_only = transfer.plan().total() + CHUNK_OVERHEAD * chunks;
    let required = transfer.plan().required_grant();
    assert!(required > frames_only, "{required} <= {frames_only}");

    let error = run_through_kernel(&transfer, frames_only)
        .expect_err("the chunk-frames formula cannot pay for the plan and the replies");
    assert!(
        error.code() == "rpc/budget-exceeded" || error.code() == "rpc/bulk",
        "unexpected refusal: {error}"
    );
    run_through_kernel(&transfer, required).expect("the documented grant completes");
}

/// The provider's state is per object, and an object is expected to have one
/// principal: a capability delegated from the same grant shares the slot
/// (round 4, M-3). This pins the documented contract.
#[test]
fn a_delegated_capability_on_the_same_object_shares_the_transfer() {
    let transfer = BulkTransfer::new(body(40_000, 21), 10_000).expect("transfer");
    let agent = Agent::new();
    let id = agent.register(Box::new(BulkProvider::new()));
    let lane = agent.create_lane("bulk", Budget::default()).expect("lane");
    let parent = agent
        .mint(id, 0, CapAttrs::new(&["plan", "put", "missing"]))
        .expect("parent");
    let observer = agent
        .mint(id, 0, CapAttrs::new(&["missing"]))
        .expect("observer");

    let plan = agent
        .call_from_envelope(
            None,
            lane,
            &parent,
            &Envelope::request(1, "plan", Vec::new()).with_payload(transfer.plan_frame()),
        )
        .expect("plan queued");
    agent.run();
    plan.value().expect("plan settles");

    let reply = agent
        .call_from_envelope(
            None,
            lane,
            &observer,
            &Envelope::request(2, "missing", Vec::new()),
        )
        .expect("missing queued");
    agent.run();
    let map = map_of(reply.value().expect("missing settles"));
    assert_eq!(
        map.get("remaining"),
        Some(&Value::Int(transfer.plan().chunk_count() as i64)),
        "a capability on the same object observes the transfer"
    );
}

/// The chunk-count ceiling is applied before the hash vector exists, so a
/// one-byte chunk cannot ask for a 34 GB allocation (round 4, M-4).
#[test]
fn a_plan_past_the_chunk_ceiling_is_refused_before_hashing() {
    let started = Instant::now();
    let bytes = vec![0u8; MAX_CHUNKS as usize + 1];
    let error = BulkPlan::new(&bytes, 1).expect_err("too many chunks");
    assert_eq!(error.code(), "rpc/bulk");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the refusal took {:?}",
        started.elapsed()
    );
}

/// `missing` refreshes the idle window and never expires the transfer, so a
/// resume poll keeps it alive and a read-only caller cannot destroy it
/// (round 4, L-1).
#[test]
fn a_resume_poll_keeps_the_transfer_alive() {
    let plan = BulkPlan::new(&body(4_000, 22), 1_000).expect("plan");
    let mut provider = BulkProvider::new();
    let mut open = call("plan", plan.encode());
    open.now_ms = 0;
    provider.invoke(1, &open).expect("plan");

    let mut poll = call("missing", Vec::new());
    poll.now_ms = TRANSFER_IDLE_MS;
    provider.invoke(1, &poll).expect("poll");

    // A put one millisecond past the original window still lands, because the
    // poll refreshed it.
    let sender = BulkSender::new(body(4_000, 22), 1_000).expect("sender");
    let mut put = call("put", sender.frame_at(0).expect("frame"));
    put.now_ms = TRANSFER_IDLE_MS + 1;
    provider
        .invoke(1, &put)
        .expect("the poll refreshed the window");
}

/// The maximal plan is a frame the strict profile encodes and decodes
/// (round 4, L-2).
#[test]
fn the_maximal_plan_fits_a_strict_envelope() {
    let payload = vec![0u8; MAX_CHUNKS as usize];
    let plan = BulkPlan::new(&payload, 1).expect("plan");
    assert_eq!(plan.chunk_count(), MAX_CHUNKS);
    let envelope = Envelope::request(1, "plan", Vec::new()).with_payload(plan.encode());
    let bytes = envelope
        .encode_with_limits(WireLimits::strict())
        .expect("the maximal plan fits the strict frame");
    Envelope::decode_with(&bytes, WireLimits::strict()).expect("and decodes");
}

/// One context per provider: a plan from another exchange is refused, and the
/// constraint is the same for every object on that provider (round 4, L-3).
#[test]
fn the_transfer_context_is_one_per_provider() {
    let payload = body(9_000, 23);
    let plan = BulkPlan::new_with_context(&payload, 3_000, b"exchange A").expect("plan");
    let mut provider = BulkProvider::new().with_context(b"exchange A".to_vec());
    provider
        .invoke(0, &call("plan", plan.encode()))
        .expect("object 0 admits the bound plan");
    provider
        .invoke(1, &call("plan", plan.encode()))
        .expect("object 1 shares the provider context");

    let foreign = BulkPlan::new_with_context(&payload, 3_000, b"exchange B").expect("plan");
    let error = provider
        .invoke(2, &call("plan", foreign.encode()))
        .expect_err("another exchange's plan is refused");
    assert_eq!(error.code(), "rpc/bulk");
    assert_eq!(provider.active_root(2), None);
}

/// A repeated finish marker is answered after the host takes the body
/// (round 4, L-4).
#[test]
fn a_repeated_finish_survives_take_body() {
    let payload = body(5_000, 24);
    let transfer = BulkTransfer::new(payload, 2_000).expect("transfer");
    let mut provider = BulkProvider::new();
    provider
        .invoke(0, &call("plan", transfer.plan_frame()))
        .expect("plan");
    for index in 0..transfer.plan().chunk_count() {
        provider
            .invoke(0, &call("put", transfer.chunk_frame(index).expect("chunk")))
            .expect("chunk");
    }
    let first = reply_map(
        provider
            .invoke(0, &call("finish", transfer.finish_frame()))
            .expect("finish"),
    );
    assert!(provider.take_body(0).is_some());
    let again = reply_map(
        provider
            .invoke(0, &call("finish", transfer.finish_frame()))
            .expect("the retried marker is answered, not refused"),
    );
    assert_eq!(first, again);
}

/// A finished, untaken body is released after its window, so a capability that
/// expires by TTL cannot hold the bytes for the process lifetime
/// (round 4, L-5).
#[test]
fn an_untaken_body_is_released_after_its_window() {
    let payload = body(6_000, 25);
    let transfer = BulkTransfer::new(payload, 2_000).expect("transfer");
    let mut provider = BulkProvider::new();
    let mut open = call("plan", transfer.plan_frame());
    open.now_ms = 0;
    provider.invoke(0, &open).expect("plan");
    for index in 0..transfer.plan().chunk_count() {
        let mut put = call("put", transfer.chunk_frame(index).expect("chunk"));
        put.now_ms = 0;
        provider.invoke(0, &put).expect("chunk");
    }
    let mut finish = call("finish", transfer.finish_frame());
    finish.now_ms = 0;
    provider.invoke(0, &finish).expect("finish");
    assert!(provider.has_body(0));

    let next = BulkPlan::new(&body(2_000, 26), 1_000).expect("next plan");
    let mut reopen = call("plan", next.encode());
    reopen.now_ms = COMPLETED_IDLE_MS + 1;
    provider
        .invoke(0, &reopen)
        .expect("the expired body no longer blocks a new transfer");
    assert!(!provider.has_body(0));
    assert_eq!(provider.take_body(0).map(|body| body.len()), None);

    // The digest reply is still answerable after the bytes are gone.
    let mut late = call("finish", transfer.finish_frame());
    late.now_ms = COMPLETED_IDLE_MS + 1;
    let error = provider
        .invoke(0, &late)
        .expect_err("a new transfer is active, so the old marker is refused");
    assert_eq!(error.code(), "rpc/bulk");
}

/// The admitted-call counter is observable (round 4, L-6).
#[test]
fn the_provider_counts_admitted_calls() {
    let plan = BulkPlan::new(&body(1_000, 27), 500).expect("plan");
    let mut provider = BulkProvider::new();
    assert_eq!(provider.calls(), 0);
    provider
        .invoke(0, &call("plan", plan.encode()))
        .expect("plan");
    provider
        .invoke(0, &call("missing", Vec::new()))
        .expect("missing");
    assert_eq!(provider.calls(), 2);
}

/// A receiver built under the documented formula still completes: the receiver
/// sees frames only, and the kernel-level formula is `required_grant`
/// (round 4, M-2). This pins the two claims apart.
#[test]
fn the_receiver_grant_and_the_kernel_grant_are_named() {
    let payload = body(3_000, 28);
    let sender = BulkSender::new(payload.clone(), 1_000).expect("sender");
    let budget = Budget {
        max_bytes: payload.len() as u64 + CHUNK_OVERHEAD * 3,
        ..Budget::default()
    };
    let mut receiver = BulkReceiver::with_budget(sender.plan().clone(), budget).expect("receiver");
    for index in 0..3 {
        receiver
            .accept(&sender.frame_at(index).expect("frame"))
            .expect("frame");
    }
    assert_eq!(receiver.finish().expect("finish"), payload);
}
