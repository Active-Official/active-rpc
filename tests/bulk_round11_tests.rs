//! R-10 bulk round 11: a re-plan is the documented recovery from an exhausted
//! finish, and a refusal that did no work does not spend the attempt budget.

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

/// After three real wall refusals the finish is a state fault, and the transfer
/// is released so a re-plan starts fresh (round 11, M-1; round 12, M-1).
#[test]
fn an_exhausted_finish_releases_the_transfer() {
    // 8 MiB cannot be assembled inside 1 ms on any host, so each attempt does
    // work and spends the budget.
    let transfer = BulkTransfer::new(body(8 << 20, 95), 256 * 1024).expect("transfer");
    let mut provider = BulkProvider::new();
    drive(&mut provider, &transfer);
    for attempt in 0..3 {
        let code = finish(&mut provider, &transfer, 1).expect_err("the 1 ms grant is too small");
        assert_eq!(code, "rpc/budget-exceeded", "attempt {attempt}");
    }
    let code = finish(&mut provider, &transfer, 1).expect_err("the finish is exhausted");
    assert_eq!(code, "rpc/bulk", "the exhausted state is a state fault");

    // The transfer is gone: a 53-byte re-plan cannot resume the paid chunks.
    assert_eq!(
        provider.active_root(0),
        None,
        "the transfer was not released"
    );
    let reply = match provider
        .invoke(0, &call("plan", transfer.plan_frame()))
        .expect("the re-plan starts a new transfer")
    {
        active_rpc::Response::Value(active_rpc::Value::Map(entries)) => entries,
        other => panic!("unexpected reply {other:?}"),
    };
    assert_eq!(
        reply.get("missing"),
        Some(&active_rpc::Value::Int(transfer.plan().chunk_count() as i64)),
        "the released chunks must not be resumable"
    );

    // Re-sending the body is the documented recovery.
    for index in 0..transfer.plan().chunk_count() {
        provider
            .invoke(0, &call("put", transfer.chunk_frame(index).expect("chunk")))
            .expect("chunk");
    }
    finish(&mut provider, &transfer, 60_000).expect("the re-sent transfer finishes");
}

/// A deadline that had already passed does no work, so it does not spend the
/// attempt budget (round 11, M-2).
#[test]
fn a_zero_work_refusal_does_not_spend_the_budget() {
    let transfer = BulkTransfer::new(body(2_000, 96), 1_000).expect("transfer");
    let mut provider = BulkProvider::new();
    drive(&mut provider, &transfer);
    // A zero-millisecond grant refuses before the assembly every time.
    for _ in 0..5 {
        let code = finish(&mut provider, &transfer, 0).expect_err("no time to work");
        assert_eq!(code, "rpc/budget-exceeded");
    }
    // A workable grant still succeeds: the five cheap refusals did not exhaust
    // the three-attempt budget.
    finish(&mut provider, &transfer, 60_000).expect("a real grant still finishes");
}
