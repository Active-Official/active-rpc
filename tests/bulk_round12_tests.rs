//! R-10 bulk rounds 15-16: the verification pass is inside the wall grant, the
//! throttle counts every wall failure and needs a wider grant to clear, a
//! narrow cap can still finish a small body, the transfer can be abandoned, and
//! a taken body's `Debug` does not publish the raw digest.

use active_rpc::bulk::{BulkPlan, BulkProvider, BulkTransfer};
use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::value::{Call, Value};
use active_rpc::wire::Envelope;
use active_rpc::Agent;
use active_rpc::Budget;
use std::time::{Duration, Instant};

fn body(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| seed.wrapping_add((index % 251) as u8))
        .collect()
}

fn call(method: &str, payload: Vec<u8>) -> Call {
    Call::new(method, Vec::new()).with_payload(payload)
}

fn drive(provider: &mut BulkProvider, transfer: &BulkTransfer) {
    provider
        .invoke(0, &call("plan", transfer.plan_frame()))
        .expect("plan");
    for index in 0..transfer.plan().chunk_count() {
        provider
            .invoke(0, &call("put", transfer.chunk_frame(index).expect("chunk")))
            .expect("chunk");
    }
}

fn with_wall(method: &str, payload: Vec<u8>, wall_ms: u64) -> Call {
    let mut request = call(method, payload);
    request.budget = Budget {
        max_wall_ms: wall_ms,
        ..Budget::default()
    };
    request
}

/// The verification pass re-hashes the whole body, so it is charged to the wall
/// grant: a pass that outlives the deadline is refused instead of running
/// unbounded (R-10 round 15, #1).
#[test]
fn a_verification_that_outlives_the_grant_is_refused() {
    // 64 MiB re-hashes in tens of milliseconds on any host; a 1 ms deadline
    // cannot cover it. One chunk so the deadline is the only variable.
    let bytes = body(64 << 20, 0x15);
    let plan = BulkPlan::new(&bytes, 1 << 20).expect("plan");
    let deadline = Instant::now() + Duration::from_millis(1);
    let error = plan
        .verify_within(&bytes, Some(deadline))
        .expect_err("a 1 ms deadline cannot re-hash 64 MiB");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    assert!(error.to_string().contains("wall"), "{error}");
    // The control: the same bytes verify when nothing bounds the pass, so the
    // refusal above is the deadline and not a hash mismatch.
    plan.verify(&bytes).expect("the bytes match the plan");
}

/// The deadline is checked before the first hash: a spent grant answers the
/// wall refusal, not the hash verdict for bytes that were never hashed
/// (R-10 round 15, #1).
#[test]
fn a_spent_grant_is_refused_before_the_first_hash() {
    let plan = BulkPlan::new(&body(64 << 10, 0x11), 8 << 10).expect("plan");
    let wrong = vec![0u8; 64 << 10];
    let error = plan
        .verify_within(&wrong, Some(Instant::now()))
        .expect_err("a spent deadline refuses");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    // The bytes really are wrong, so the unbounded pass says so: the order is
    // the deadline first, the hash second.
    let error = plan.verify(&wrong).expect_err("the bytes do not match");
    assert_eq!(error.code(), "rpc/bulk", "{error}");
}

/// The throttle's bound is the body's own wall — bytes at the documented rate,
/// a per-chunk term and the slack — and `required_wall_ms` is the recommended
/// sizing on top of it (R-10 round 15, #2; round 16, #4).
#[test]
fn the_body_wall_is_the_bodys_own() {
    let small = BulkPlan::new(&body(2_000, 0x12), 1_000).expect("small plan");
    // 2 KB is one chunk at the documented rate, two chunks of per-chunk term and
    // the 100 ms slack.
    assert_eq!(small.chunk_count(), 2);
    assert_eq!(small.assembly_wall_ms(), 102);
    // The recommendation never asks for less than the default grant.
    assert_eq!(small.required_wall_ms(), 5_000);

    // A body large enough that its own cost dominates: 1 GiB is 8 000 ms at the
    // documented rate, 4 096 chunks are 17 ms of per-chunk term, plus the slack.
    let mut hashes = vec![[0u8; 32]; (1usize << 30) / (256 * 1024)];
    hashes[0] = [1u8; 32];
    let large = BulkPlan::from_hashes(256 * 1024, 1 << 30, hashes).expect("1 GiB plan");
    assert_eq!(large.chunk_count(), 4_096);
    assert_eq!(large.assembly_wall_ms(), 8_118);
    assert_eq!(large.required_wall_ms(), 8_118);

    // The per-chunk term is a real term, not a constant: a body with the same
    // bytes in more chunks needs strictly more wall, which is the shape the
    // byte-only estimate under-sized by 1.3-1.7x (round 16, #4).
    let few = BulkPlan::new(&body(256 * 1024, 0x13), 256 * 1024).expect("one chunk");
    let many = BulkPlan::new(&body(256 * 1024, 0x13), 1_000).expect("many chunks");
    assert_eq!(few.total(), many.total());
    assert!(many.chunk_count() > few.chunk_count());
    assert!(
        many.assembly_wall_ms() > few.assembly_wall_ms(),
        "the same bytes in more chunks must need more wall: {} vs {}",
        many.assembly_wall_ms(),
        few.assembly_wall_ms()
    );
}

/// A capability whose wall is between the body's own wall and the recommended
/// sizing still finishes after three refusals: gating the freeze on the default
/// 5 s grant made a narrow-profile deployment lose a fully paid body it could
/// have finished (R-10 round 15, #2).
#[test]
fn a_grant_above_the_bodys_wall_finishes_after_three_refusals() {
    // 4 MiB needs ~132 ms at the documented rate, measured with 5x margin.
    let transfer = BulkTransfer::new(body(4 << 20, 0x13), 256 * 1024).expect("transfer");
    let plan = transfer.plan().clone();
    assert!(
        plan.assembly_wall_ms() < 1_000 && plan.required_wall_ms() == 5_000,
        "the fixture must sit between the body's wall and the default grant"
    );
    let mut provider = BulkProvider::new();
    drive(&mut provider, &transfer);
    for _ in 0..3 {
        let code = provider
            .invoke(0, &with_wall("finish", transfer.finish_frame(), 1))
            .expect_err("a 1 ms grant cannot assemble 4 MiB")
            .code()
            .to_string();
        assert_eq!(code, "rpc/budget-exceeded");
    }
    // 1 s is under the recommended 5 s but over the body's 132 ms, so the
    // attempt can pay for the work and must run rather than answer the freeze.
    provider
        .invoke(0, &with_wall("finish", transfer.finish_frame(), 1_000))
        .expect("the body's own wall is what the freeze gates on");
    assert!(provider.has_body(0), "the finish completed");
}

/// A transfer that cannot finish holds the object's slot and its reserved
/// bytes. `abort` is the caller's way out: the refusal rules forbid destroying
/// a paid body, so the caller has to be able to say so itself
/// (R-10 round 15, #2).
#[test]
fn a_wedged_object_can_be_abandoned() {
    // The method is part of the contract, so a capability can be granted it.
    assert!(BulkProvider::new().has_method("abort"));
    assert!(BulkProvider::new()
        .methods()
        .iter()
        .any(|method| method == "abort"));
    assert!(BulkProvider::new().mutating("abort"), "abort changes state");
    // A 4 MiB body needs ~30 ms; a 1 ms grant freezes it after three attempts.
    let wedged = BulkTransfer::new(body(4 << 20, 0x14), 256 * 1024).expect("wedged transfer");
    let held = BulkTransfer::new(body(2_000, 0x16), 1_000).expect("small transfer");
    let mut provider = BulkProvider::new();
    // The ceiling holds exactly the wedged transfer, so a second object is
    // refused while it is resident.
    drive(&mut provider, &wedged);
    let ceiling = provider.live_bytes();
    assert!(ceiling > 0, "the wedged transfer reserves bytes");
    provider = provider.with_max_live_bytes(ceiling);

    let error = provider
        .invoke(1, &call("plan", held.plan_frame()))
        .expect_err("the wedged transfer holds the ceiling");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");

    for _ in 0..3 {
        let code = provider
            .invoke(0, &with_wall("finish", wedged.finish_frame(), 1))
            .expect_err("no time to work")
            .code()
            .to_string();
        assert_eq!(code, "rpc/budget-exceeded");
    }
    let error = provider
        .invoke(0, &with_wall("finish", wedged.finish_frame(), 1))
        .expect_err("the transfer is frozen");
    assert_eq!(error.code(), "rpc/bulk", "{error}");

    // The caller abandons it, which frees the slot and the reservation.
    provider
        .invoke(0, &call("abort", Vec::new()))
        .expect("abort");
    assert_eq!(provider.active_root(0), None, "the transfer is gone");
    assert_eq!(provider.live_bytes(), 0, "the reservation is released");
    provider
        .invoke(1, &call("plan", held.plan_frame()))
        .expect("the freed ceiling admits the next transfer");
    // Aborting again is idempotent rather than an error, and the reply is the
    // same constant shape either way.
    provider
        .invoke(0, &call("abort", Vec::new()))
        .expect("a second abort is a no-op with the same answer");
}

/// The raw digest of a body is the offline equality oracle a redacting
/// capability withholds, so `Debug` must not print it (R-10 round 15, #4).
#[test]
fn debug_of_a_body_never_shows_the_raw_digest() {
    let transfer = BulkTransfer::new(body(2_000, 0x17), 1_000).expect("transfer");
    let mut provider = BulkProvider::new();
    drive(&mut provider, &transfer);
    provider
        .invoke(0, &with_wall("finish", transfer.finish_frame(), 60_000))
        .expect("finish");
    let taken = provider.take_body(0).expect("the body is there");
    let digest: String = taken
        .body_hash()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let printed = format!("{taken:?}");
    assert!(
        !printed.contains(&digest),
        "Debug printed the raw body digest: {printed}"
    );
    assert!(printed.contains("BulkBody"), "{printed}");
}

/// A grant the transfer has already refused is not a new price: repeating it
/// does not get a free pass, and the count reaches the freeze. A wider grant is
/// a price it has not refused, so it runs (R-10 round 16, #1).
#[test]
fn repeating_a_refused_grant_does_not_get_a_free_pass() {
    // 64 MiB cannot be assembled inside a millisecond on any host.
    let transfer = BulkTransfer::new(body(64 << 20, 0x18), 256 * 1024).expect("transfer");
    let mut provider = BulkProvider::new();
    drive(&mut provider, &transfer);
    for _ in 0..3 {
        let code = provider
            .invoke(0, &with_wall("finish", transfer.finish_frame(), 1))
            .expect_err("a 1 ms grant cannot assemble 64 MiB")
            .code()
            .to_string();
        assert_eq!(code, "rpc/budget-exceeded");
    }
    let error = provider
        .invoke(0, &with_wall("finish", transfer.finish_frame(), 1))
        .expect_err("the fourth attempt at the same grant is frozen");
    assert_eq!(error.code(), "rpc/bulk", "{error}");
    assert!(error.to_string().contains("abort"), "{error}");
    // A strictly wider grant is a price the transfer has not refused.
    provider
        .invoke(0, &with_wall("finish", transfer.finish_frame(), 60_000))
        .expect("the wider grant finishes the paid body");
}

/// `abort` acts on the object, like every other bulk method: the object model
/// is one principal per object, so a sibling capability on the same object can
/// discard its state. This test pins that boundary so the rule is visible, and
/// the spec and the ADR state it (R-10 round 16, #2).
#[test]
fn a_sibling_capability_on_a_shared_object_can_abort() {
    let transfer = BulkTransfer::new(body(4_000, 0x19), 1_000).expect("transfer");
    let agent = Agent::new();
    let id = agent.register(Box::new(BulkProvider::new()));
    let lane = agent
        .create_lane("shared", Budget::default())
        .expect("lane");
    let attrs = CapAttrs::new(&["plan", "put", "missing", "finish", "abort"]);
    // Two capabilities on one object: the host chose to share it.
    let first = agent.mint(id, 0, attrs.clone()).expect("first cap");
    let second = agent.mint(id, 0, attrs).expect("second cap");

    let mut request = 1u64;
    let mut send = |cap: &active_rpc::cap::CapHandle, method: &str, frame: Vec<u8>| {
        let envelope = Envelope::request(request, method, Vec::new()).with_payload(frame);
        request += 1;
        let promise = agent
            .call_from_envelope(None, lane, cap, &envelope)
            .expect("queued");
        agent.run();
        promise.value()
    };
    send(&first, "plan", transfer.plan_frame()).expect("plan");
    send(&first, "put", transfer.chunk_frame(0).expect("chunk")).expect("chunk");

    let reply = send(&second, "abort", Vec::new()).expect("the sibling aborts");
    // The reply is constant: a capability that grants only `abort` learns nothing
    // about whether another principal held state on the object (R-10 round 17).
    assert!(
        matches!(&reply, Value::Map(entries) if entries.get("aborted") == Some(&Value::Bool(true))),
        "abort answers one constant shape: {reply:?}"
    );
    assert!(
        !matches!(&reply, Value::Map(entries) if entries.contains_key("dropped")),
        "the reply no longer reports whether anything was there: {reply:?}"
    );
    let error = send(&first, "finish", transfer.finish_frame())
        .expect_err("the transfer the sibling dropped is gone");
    assert_eq!(error.code(), "rpc/bulk", "{error}");
}

/// A refusal that never started does no work, so it is not evidence about the
/// grant: five zero-grant attempts must leave the three-attempt budget intact
/// (R-10 round 16, #3).
#[test]
fn a_zero_grant_attempt_never_counts_against_the_budget() {
    // 8 MiB needs ~160 ms at the documented rate.
    let transfer = BulkTransfer::new(body(8 << 20, 0x1a), 256 * 1024).expect("transfer");
    let mut provider = BulkProvider::new();
    drive(&mut provider, &transfer);
    for attempt in 0..5 {
        let code = provider
            .invoke(0, &with_wall("finish", transfer.finish_frame(), 0))
            .expect_err("a zero grant cannot start the assembly")
            .code()
            .to_string();
        assert_eq!(code, "rpc/budget-exceeded", "attempt {attempt}");
    }
    // The budget is untouched: three real attempts are still available.
    for attempt in 0..3 {
        let code = provider
            .invoke(0, &with_wall("finish", transfer.finish_frame(), 1))
            .expect_err("1 ms cannot assemble 8 MiB")
            .code()
            .to_string();
        assert_eq!(code, "rpc/budget-exceeded", "attempt {attempt}");
    }
    let error = provider
        .invoke(0, &with_wall("finish", transfer.finish_frame(), 1))
        .expect_err("three attempts at a refused grant are spent");
    assert_eq!(error.code(), "rpc/bulk", "{error}");
    // And the paid escape still works.
    provider
        .invoke(0, &with_wall("finish", transfer.finish_frame(), 60_000))
        .expect("a wider grant finishes");
}
