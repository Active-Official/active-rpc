//! R-10 bulk round 13: the wall throttle funds the body's own estimate and
//! counts every grant below it.

use active_rpc::bulk::{BulkProvider, BulkTransfer};
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

fn finish(
    provider: &mut BulkProvider,
    transfer: &BulkTransfer,
    wall_ms: u64,
) -> Result<(), String> {
    let mut request = call("finish", transfer.finish_frame());
    request.budget = Budget {
        max_wall_ms: wall_ms,
        ..Budget::default()
    };
    match provider.invoke(0, &request) {
        Ok(_) => Ok(()),
        Err(error) => Err(error.code().to_string()),
    }
}

/// Raising the grant one millisecond at a time used to clear the failure count
/// every step (`grant > failed_at`), so each 1 ms step bought a full assembly
/// and the freeze never engaged. Three sub-estimate failures must count and
/// freeze the transfer, and the estimate itself must still finish it
/// (R-10 round 13, F1).
#[test]
fn escalating_the_grant_by_a_millisecond_does_not_buy_more_assemblies() {
    // 8 MiB needs ~160 ms at the documented rate, so 1..=4 ms are all below the
    // estimate.
    let transfer = BulkTransfer::new(body(8 << 20, 96), 256 * 1024).expect("transfer");
    let plan = transfer.plan().clone();
    let mut provider = BulkProvider::new();
    drive(&mut provider, &transfer);
    let estimate = plan.assembly_wall_ms();
    for wall in 1..=3u64 {
        assert!(wall < estimate, "the fixture's estimate is {estimate} ms");
        let code = finish(&mut provider, &transfer, wall).expect_err("below the estimate");
        assert_eq!(code, "rpc/budget-exceeded", "wall {wall}");
    }
    // A fourth grant is wider than every failure so far; it must not run.
    let code = finish(&mut provider, &transfer, 4).expect_err("the escalation is frozen");
    assert_eq!(code, "rpc/bulk", "a 1 ms widening bought another assembly");
    // One millisecond below the estimate is still a refusal, not a reset.
    let code = finish(&mut provider, &transfer, estimate - 1).expect_err("still below");
    assert_eq!(code, "rpc/bulk");
    // The estimate is the price the transfer asks for: it clears the freeze.
    finish(&mut provider, &transfer, estimate).expect("the estimate finishes the body");
}

/// A `put` with no transfer is a state refusal whatever the provider's
/// occupancy: the ceiling used to answer first and leak another object's live
/// bytes to a put-only capability (R-10 round 13, F2).
#[test]
fn a_put_without_a_transfer_is_a_state_refusal_even_at_the_live_bound() {
    let transfer = BulkTransfer::new(body(4096, 97), 1024).expect("transfer");
    // A ceiling of one byte is already over the plan vector, so every put is
    // over the bound if the ceiling is consulted first.
    let mut provider = BulkProvider::new().with_max_live_bytes(1);
    let code = provider
        .invoke(0, &call("put", transfer.chunk_frame(0).expect("chunk")))
        .expect_err("no transfer is active")
        .code()
        .to_string();
    assert_eq!(code, "rpc/bulk", "the ceiling answered before the state");
    // With the plan accepted the same frame is a byte refusal, which is the
    // code the ceiling is for. The plan is admitted only because the provider
    // has no bound set for this half of the test.
    let mut open = BulkProvider::new();
    open.invoke(0, &call("plan", transfer.plan_frame()))
        .expect("plan");
    open.invoke(0, &call("put", transfer.chunk_frame(0).expect("chunk")))
        .expect("the first chunk fits");
    let mut bounded = open.with_max_live_bytes(1);
    let code = bounded
        .invoke(0, &call("put", transfer.chunk_frame(1).expect("chunk")))
        .expect_err("over the live bound")
        .code()
        .to_string();
    assert_eq!(
        code, "rpc/budget-exceeded",
        "an open transfer answers the ceiling"
    );
}
