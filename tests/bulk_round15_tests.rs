//! R-10 bulk round 15: a duplicate chunk is free against the provider-wide
//! live-byte ceiling, a refused frame reports its own defect rather than the
//! provider's occupancy, and the documented minimal bound can complete.

use active_rpc::bulk::{BulkProvider, BulkReceiver, BulkSender, BulkTransfer, CHUNK_OVERHEAD};
use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::value::{Call, Response, Value};
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

fn stored_bytes(frame: &[u8]) -> u64 {
    (frame.len() as u64).saturating_sub(CHUNK_OVERHEAD)
}

fn with_wall(method: &str, payload: Vec<u8>, wall_ms: u64) -> Call {
    let mut request = call(method, payload);
    request.budget = Budget {
        max_wall_ms: wall_ms,
        ..Budget::default()
    };
    request
}

/// The live-byte ceiling charges what a chunk actually stores, once: an
/// identically retransmitted chunk must not be charged again, or at the
/// documented minimal bound every retransmission is refused
/// (R-10 round 15, F2).
#[test]
fn a_duplicate_chunk_does_not_charge_the_live_ceiling_again() {
    let transfer = BulkTransfer::new(body(2_000, 0x21), 1_200).expect("transfer");
    assert_eq!(transfer.plan().chunk_count(), 2, "chunks of 1 200 and 800");
    let chunk0 = transfer.chunk_frame(0).expect("chunk 0");
    let chunk1 = transfer.chunk_frame(1).expect("chunk 1");
    let mut provider = BulkProvider::new();
    provider
        .invoke(0, &call("plan", transfer.plan_frame()))
        .expect("plan");
    // Exactly the provider's current footprint plus both chunks, so the
    // duplicate is the only thing that can overflow it.
    let ceiling = provider.live_bytes() + 2 * stored_bytes(&chunk0) + 2 * stored_bytes(&chunk1);
    provider = provider.with_max_live_bytes(ceiling);

    provider
        .invoke(0, &call("put", chunk0.clone()))
        .expect("the first copy fits");
    provider
        .invoke(0, &call("put", chunk0.clone()))
        .expect("an identical retransmission is free");
    provider
        .invoke(0, &call("put", chunk1))
        .expect("the last chunk fits");
    assert_eq!(
        provider.live_bytes(),
        ceiling,
        "the ceiling is exactly spent"
    );
}

/// A frame that fails validation reports its own defect even when the provider
/// is at its live-byte ceiling: the pre-validation growth check was a one-byte
/// occupancy oracle over every object's bytes (R-10 round 15, F3).
#[test]
fn a_refused_frame_reports_its_defect_at_a_full_ceiling() {
    let transfer = BulkTransfer::new(body(2_000, 0x22), 1_200).expect("transfer");
    let chunk0 = transfer.chunk_frame(0).expect("chunk 0");
    let chunk1 = transfer.chunk_frame(1).expect("chunk 1");
    let mut provider = BulkProvider::new();
    provider
        .invoke(0, &call("plan", transfer.plan_frame()))
        .expect("plan");
    let ceiling = provider.live_bytes() + 2 * stored_bytes(&chunk0) + 2 * stored_bytes(&chunk1);
    provider = provider.with_max_live_bytes(ceiling);
    provider
        .invoke(0, &call("put", chunk0))
        .expect("the first copy fits");
    provider
        .invoke(0, &call("put", chunk1.clone()))
        .expect("the ceiling is exactly spent");

    let mut tampered = chunk1;
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;
    let error = provider
        .invoke(0, &call("put", tampered))
        .expect_err("a corrupted chunk is refused");
    assert_eq!(
        error.code(),
        "rpc/bulk",
        "the frame's own defect, not the provider's occupancy: {error}"
    );
}

/// `required_live_bytes` is the bound a complete body needs, and it is exact:
/// one byte less must refuse the last chunk (R-10 round 15, F5).
#[test]
fn required_live_bytes_is_the_bound_a_complete_body_needs() {
    let transfer = BulkTransfer::new(body(2_000, 0x24), 1_200).expect("transfer");
    let mut provider = BulkProvider::new();
    provider
        .invoke(0, &call("plan", transfer.plan_frame()))
        .expect("plan");
    let base = provider.live_bytes();
    let required = transfer.plan().required_live_bytes();
    assert!(
        required > base && required >= 2 * transfer.plan().total(),
        "a completion holds the chunks, the assembly buffer and the plan vector"
    );
    provider = provider.with_max_live_bytes(required);
    for index in 0..transfer.plan().chunk_count() {
        provider
            .invoke(0, &call("put", transfer.chunk_frame(index).expect("chunk")))
            .expect("the chunk fits the exact bound");
    }
    assert_eq!(
        provider.live_bytes(),
        required,
        "the accessor is the completion footprint"
    );
    provider
        .invoke(0, &with_wall("finish", transfer.finish_frame(), 60_000))
        .expect("finish");

    // One byte less: the last chunk is refused even though every frame is
    // valid, which is the trap the accessor lets a host avoid.
    let mut tight = BulkProvider::new();
    tight
        .invoke(0, &call("plan", transfer.plan_frame()))
        .expect("plan");
    let tight_base = tight.live_bytes();
    assert!(tight_base < required - 1, "the plan itself fits");
    tight = tight.with_max_live_bytes(required - 1);
    let last = transfer.plan().chunk_count() - 1;
    let mut refused = None;
    for index in 0..transfer.plan().chunk_count() {
        let result = tight.invoke(0, &call("put", transfer.chunk_frame(index).expect("chunk")));
        if let Err(error) = result {
            refused = Some((index, error));
            break;
        }
    }
    let (index, error) = refused.expect("the exact bound minus one cannot complete");
    assert_eq!(index, last, "only the last chunk crosses the bound");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    tight
        .invoke(0, &call("abort", Vec::new()))
        .expect("abort releases the slot");
}

/// A resume batch is byte-identical to the streaming frames, so it carries the
/// plan's hashes instead of re-hashing the remaining body
/// (R-10 round 15, F8).
#[test]
fn a_resume_batch_is_the_streaming_frames() {
    let sender = BulkSender::new(body(2_000, 0x25), 700).expect("sender");
    let plan = sender.plan();
    for from in 0..=plan.chunk_count() {
        let batch = sender.frames_from(from).expect("resume batch");
        let expected: Vec<Vec<u8>> = (from..plan.chunk_count())
            .map(|index| sender.frame_at(index).expect("frame"))
            .collect();
        assert_eq!(batch, expected, "the batch differs at resume point {from}");
    }
    let error = sender
        .frames_from(plan.chunk_count() + 1)
        .expect_err("a resume point past the plan is refused");
    assert_eq!(error.code(), "rpc/bulk", "{error}");
}

/// The documented `required_grant`/`required_calls` carry a one-chunk image
/// through the resume order the module advertises (plan, missing, put, finish).
/// The reply allowance used to be six bytes short of the plan-plus-finish
/// replies, so the effect landed while egress was refused
/// (R-10 round 15, M1).
#[test]
fn a_one_chunk_image_with_an_early_missing_page_fits_required_grant() {
    let module =
        active_rpc::domain::module_from_source("[app]\nname = \"bulk-r15\"\n", "bulk-r15.active")
            .expect("module");
    let image = active_infinity::encode(&module).expect("encode");
    let transfer = BulkTransfer::new(image, 1 << 20).expect("one-chunk transfer");
    assert_eq!(transfer.plan().chunk_count(), 1);
    run_kernel_flow(
        &transfer,
        transfer.plan().required_grant(),
        transfer.plan().required_calls(),
    )
    .expect("the documented grant carries plan, missing, put and finish");
}

fn run_kernel_flow(transfer: &BulkTransfer, grant: u64, calls: u64) -> Result<(), Error> {
    let agent = Agent::new();
    let id = agent
        .register(Box::new(BulkProvider::new()))
        .expect("register provider");
    let lane = agent.create_lane("bulk", Budget::default()).expect("lane");
    let mut attrs = CapAttrs::new(&["plan", "put", "missing", "finish"]);
    attrs.budget.max_bytes = grant;
    attrs.budget.max_calls = calls;
    let cap = agent.mint(id, 0, attrs).expect("cap");

    let mut request = 1u64;
    let plan = agent.call_from_envelope(
        None,
        lane,
        &cap,
        &Envelope::request(request, "plan", Vec::new()).with_payload(transfer.plan_frame()),
    )?;
    agent.run();
    plan.value()?;
    request += 1;
    let missing = agent.call_from_envelope(
        None,
        lane,
        &cap,
        &Envelope::request(request, "missing", Vec::new()),
    )?;
    agent.run();
    missing.value()?;
    for index in 0..transfer.plan().chunk_count() {
        request += 1;
        let promise = agent.call_from_envelope(
            None,
            lane,
            &cap,
            &Envelope::request(request, "put", Vec::new())
                .with_payload(transfer.chunk_frame(index)?),
        )?;
        agent.run();
        promise.value()?;
    }
    request += 1;
    let finish = agent.call_from_envelope(
        None,
        lane,
        &cap,
        &Envelope::request(request, "finish", Vec::new()).with_payload(transfer.finish_frame()),
    )?;
    agent.run();
    finish.value()?;
    Ok(())
}

/// `accept_charged` charges the callback only: a receiver built with its own
/// meter used to charge the same frame twice, so a host combining the two
/// documented APIs refused a transfer at half its true grant
/// (R-10 round 15, L1).
#[test]
fn an_externally_charged_receiver_does_not_charge_its_own_meter() {
    let sender = BulkSender::new(body(2_000, 0x26), 700).expect("sender");
    let mut receiver =
        BulkReceiver::with_budget(sender.plan().clone(), Budget::default()).expect("receiver");
    let frame = sender.frame_at(0).expect("chunk");
    let mut external = 0u64;
    receiver
        .accept_charged(&frame, &mut |bytes| {
            external += bytes;
            Ok(())
        })
        .expect("the frame is accepted");
    assert_eq!(external, frame.len() as u64, "the callback sees the frame");
    assert_eq!(
        receiver.charged_bytes(),
        0,
        "the callback is the only meter on this path"
    );
}

/// The advertised resume door works under a narrowed array budget: the page is
/// capped by `max_array_len` instead of always asking for 1 024
/// (R-10 round 15, L2).
#[test]
fn a_narrow_array_budget_can_still_page_the_missing_indexes() {
    let transfer = BulkTransfer::new(body(64 * 1024, 0x27), 1_024).expect("transfer");
    assert!(transfer.plan().chunk_count() > 10);
    let agent = Agent::new();
    let id = agent
        .register(Box::new(BulkProvider::new()))
        .expect("register provider");
    let lane = agent.create_lane("bulk", Budget::default()).expect("lane");
    let mut attrs = CapAttrs::new(&["plan", "missing"]);
    attrs.budget.max_array_len = 10;
    attrs.budget.max_bytes = 1 << 20;
    let cap = agent.mint(id, 0, attrs).expect("cap");
    let plan = agent
        .call_from_envelope(
            None,
            lane,
            &cap,
            &Envelope::request(1, "plan", Vec::new()).with_payload(transfer.plan_frame()),
        )
        .expect("plan queued");
    agent.run();
    plan.value().expect("plan settles");
    let missing = agent
        .call_from_envelope(
            None,
            lane,
            &cap,
            &Envelope::request(2, "missing", Vec::new()),
        )
        .expect("missing queued");
    agent.run();
    let value = missing.value().expect("missing settles");
    let Value::Map(entries) = value else {
        panic!("a map reply");
    };
    let Some(Value::List(items)) = entries.get("missing") else {
        panic!("a missing list: {entries:?}");
    };
    assert!(
        items.len() <= 10,
        "the page is capped by the caller's array budget: {}",
        items.len()
    );
    assert_eq!(
        entries.get("more"),
        Some(&Value::Bool(true)),
        "the capped page reports that more remain"
    );
}

/// A plan's `Debug` does not print the full root: the root is a commitment to
/// the body, so a log line would be an offline equality oracle
/// (R-10 round 15, L7).
#[test]
fn a_plan_debug_never_prints_the_full_root() {
    let sender = BulkSender::new(body(2_000, 0x28), 700).expect("sender");
    let plan = sender.plan();
    let rendered = format!("{plan:?}");
    let full: String = plan
        .root()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert!(
        !rendered.contains(&full),
        "the full root is in the debug form: {rendered}"
    );
    assert!(
        rendered.contains("root_prefix"),
        "the prefix names what it prints: {rendered}"
    );
}

/// The funded-assembly cap is two attempts: the literal value and the frozen
/// state are pinned, so raising the constant to 100 cannot pass the suite
/// silently (R-10 round 15, M2).
#[test]
fn the_funded_assembly_cap_is_two_literal_attempts() {
    assert_eq!(
        active_rpc::bulk::FUNDED_ASSEMBLY_LIMIT,
        2,
        "the shipped cap is part of the throttle contract"
    );
}

/// The throttle's counted and frozen branches, and the paid way out: the same
/// shape the fuzz control now drives (R-10 round 15, F7).
#[test]
fn the_throttle_freezes_and_a_paid_grant_still_finishes() {
    let transfer = BulkTransfer::new(vec![0u8; 8 << 20], 256 * 1024).expect("transfer");
    let mut provider = BulkProvider::new();
    provider
        .invoke(0, &call("plan", transfer.plan_frame()))
        .expect("plan");
    for index in 0..transfer.plan().chunk_count() {
        provider
            .invoke(0, &call("put", transfer.chunk_frame(index).expect("chunk")))
            .expect("chunk");
    }
    for _ in 0..3 {
        let error = provider
            .invoke(0, &with_wall("finish", transfer.finish_frame(), 1))
            .expect_err("1 ms cannot assemble 8 MiB");
        assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    }
    let error = provider
        .invoke(0, &with_wall("finish", transfer.finish_frame(), 1))
        .expect_err("three failures freeze the transfer");
    assert_eq!(error.code(), "rpc/bulk", "{error}");
    provider
        .invoke(0, &with_wall("finish", transfer.finish_frame(), 60_000))
        .expect("a paid grant still finishes after the freeze");
}

/// A sender and a provider can share a transfer context, and the default
/// constructor is refused by a bound provider (R-10 round 16, L10).
#[test]
fn a_context_bound_provider_accepts_a_context_bound_sender() {
    let transfer =
        BulkTransfer::new_with_context(body(2_000, 0x29), 700, b"exchange-1").expect("transfer");
    let mut provider = BulkProvider::new().with_context(b"exchange-1".to_vec());
    provider
        .invoke(0, &call("plan", transfer.plan_frame()))
        .expect("the bound plan is accepted");
    for index in 0..transfer.plan().chunk_count() {
        provider
            .invoke(0, &call("put", transfer.chunk_frame(index).expect("chunk")))
            .expect("chunk");
    }
    provider
        .invoke(0, &with_wall("finish", transfer.finish_frame(), 60_000))
        .expect("finish");
    // The context-free constructor produces a plan the bound provider refuses.
    let plain = BulkTransfer::new(body(10, 1), 1_024).expect("plain");
    let mut bound = BulkProvider::new().with_context(b"exchange-1".to_vec());
    bound
        .invoke(0, &call("plan", plain.plan_frame()))
        .expect_err("a context-free plan is refused");
}

/// A provider bound that covers the assembly but not the classification
/// degrades the reply instead of allocating past its own bound
/// (R-10 round 16, M4).
#[test]
fn a_bound_that_cannot_cover_the_classification_degrades_the_reply() {
    let module =
        active_rpc::domain::module_from_source("[app]\nname = \"bulk-r16m4\"\n", "r16m4.active")
            .expect("module");
    let image = active_infinity::encode(&module).expect("encode");
    let transfer = BulkTransfer::new(image, 1 << 20).expect("transfer");
    let required = transfer.plan().required_live_bytes();
    let mut provider = BulkProvider::new().with_max_live_bytes(required);
    provider
        .invoke(0, &call("plan", transfer.plan_frame()))
        .expect("plan");
    for index in 0..transfer.plan().chunk_count() {
        provider
            .invoke(0, &call("put", transfer.chunk_frame(index).expect("chunk")))
            .expect("chunk fits the exact bound");
    }
    let reply = provider
        .invoke(0, &with_wall("finish", transfer.finish_frame(), 60_000))
        .expect("the finish still answers");
    let Response::Value(Value::Map(entries)) = &reply else {
        panic!("a map reply");
    };
    assert_eq!(
        entries.get("content_error"),
        Some(&Value::text("memory")),
        "the classification is skipped when the bound cannot cover it: {entries:?}"
    );
    assert_eq!(entries.get("canonical"), Some(&Value::Bool(false)));
    assert!(
        entries.contains_key("body_hash"),
        "the record is still usable"
    );
}

/// A transfer opened at the documented minimal bound
/// (`total + CHUNK_OVERHEAD * chunks` of grant) completes, and its
/// retransmissions are free (R-10 round 15, F5).
#[test]
fn the_documented_minimal_bound_completes_and_retransmits() {
    let transfer = BulkTransfer::new(body(2_000, 0x23), 1_200).expect("transfer");
    let mut provider = BulkProvider::new();
    provider
        .invoke(0, &call("plan", transfer.plan_frame()))
        .expect("plan");
    let announced =
        transfer.plan().total() + CHUNK_OVERHEAD * u64::from(transfer.plan().chunk_count());
    let ceiling = provider.live_bytes() + 2 * announced;
    provider = provider.with_max_live_bytes(ceiling);
    for index in 0..transfer.plan().chunk_count() {
        let frame = transfer.chunk_frame(index).expect("chunk");
        provider
            .invoke(0, &call("put", frame.clone()))
            .expect("the first copy fits");
        provider
            .invoke(0, &call("put", frame))
            .expect("a retransmission is free");
    }
    assert!(
        provider.live_bytes() <= ceiling,
        "the announced grant covers the stored bytes"
    );
    provider
        .invoke(0, &with_wall("finish", transfer.finish_frame(), 60_000))
        .expect("finish");
}
