//! R-10 bulk round 15: a duplicate chunk is free against the provider-wide
//! live-byte ceiling, a refused frame reports its own defect rather than the
//! provider's occupancy, and the documented minimal bound can complete.

use active_rpc::bulk::{BulkProvider, BulkSender, BulkTransfer, CHUNK_OVERHEAD};
use active_rpc::kernel::Provider;
use active_rpc::value::Call;
use active_rpc::Budget;

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
