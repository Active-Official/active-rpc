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

/// An under-resourced finish is throttled after three assemblies and the body
/// is never destroyed: a refusal must not lose bytes the caller paid for, and a
/// workable grant still finishes (round 13).
#[test]
fn an_under_resourced_finish_is_throttled_without_losing_the_body() {
    // 8 MiB needs ~160 ms of wall at the documented rate; a 1 ms grant cannot.
    let transfer = BulkTransfer::new(body(8 << 20, 95), 256 * 1024).expect("transfer");
    let plan = transfer.plan().clone();
    let mut provider = BulkProvider::new();
    drive(&mut provider, &transfer);
    for attempt in 0..3 {
        let code = finish(&mut provider, &transfer, 1).expect_err("the 1 ms grant is too small");
        assert_eq!(code, "rpc/budget-exceeded", "attempt {attempt}");
    }
    let code = finish(&mut provider, &transfer, 1).expect_err("the budget is spent");
    assert_eq!(code, "rpc/bulk", "the refusal is a state fault");

    // The paid body survives, and a re-plan cannot reset the budget: the
    // transfer is still the same one (round 12, M-1).
    assert_eq!(provider.active_root(0), Some(plan.root()));
    provider
        .invoke(0, &call("plan", transfer.plan_frame()))
        .expect("the re-plan is a retry of the same transfer");
    let code = finish(&mut provider, &transfer, 1).expect_err("a 53-byte re-plan buys no more");
    assert_eq!(code, "rpc/bulk");

    // A grant that can pay for the work is always allowed.
    finish(&mut provider, &transfer, plan.required_wall_ms()).expect("the workable grant finishes");
}

/// A same-root re-plan cannot buy another batch of assemblies
/// (round 12, M-1).
#[test]
fn a_replan_cannot_buy_unbounded_assemblies() {
    let transfer = BulkTransfer::new(body(4 << 20, 97), 256 * 1024).expect("transfer");
    let plan = transfer.plan().clone();
    let mut provider = BulkProvider::new();
    drive(&mut provider, &transfer);
    let mut assemblies = 0;
    for _ in 0..6 {
        for _ in 0..3 {
            // Only a budget refusal means the provider started the work; the
            // state refusal happens before any assembly.
            if matches!(
                finish(&mut provider, &transfer, 1),
                Err(code) if code == "rpc/budget-exceeded"
            ) {
                assemblies += 1;
            }
        }
        // The cheap re-plan is a retry, not a fresh budget.
        let _ = provider.invoke(0, &call("plan", transfer.plan_frame()));
    }
    assert_eq!(
        assemblies, 3,
        "the transfer bought {assemblies} assemblies, not three"
    );
    assert_eq!(
        provider.active_root(0),
        Some(plan.root()),
        "the body was lost"
    );
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
