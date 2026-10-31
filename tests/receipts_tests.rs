//! Capability receipts: an authenticated audit trail of authorization
//! decisions that never carries arguments or secrets.

use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::receipts::MAX_RECEIPTS;
use active_rpc::value::{Call, Response, Value};
use active_rpc::{Agent, Budget};

struct Echo;

impl Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn methods(&self) -> Vec<String> {
        vec!["echo".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::text("ok")))
    }
}

fn fixture() -> (Agent, active_rpc::CapHandle, active_rpc::LaneId) {
    let agent = Agent::with_secret([0x3d; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent
        .create_lane("receipts", Budget::default())
        .expect("lane");
    (agent, cap, lane)
}

fn call(agent: &Agent, lane: active_rpc::LaneId, cap: &active_rpc::CapHandle, text: &str) {
    let promise = agent
        .call(lane, cap, "echo", vec![active_rpc::Arg::text(text)])
        .expect("call");
    agent.run();
    promise.value().expect("value");
}

#[test]
fn receipts_are_opt_in() {
    let (agent, cap, lane) = fixture();
    call(&agent, lane, &cap, "one");
    assert!(agent.receipts().is_empty());
    agent.enable_receipts(true);
    call(&agent, lane, &cap, "two");
    assert_eq!(agent.receipts().len(), 1);
    agent.enable_receipts(false);
    assert!(agent.receipts().is_empty());
}

#[test]
fn an_admitted_call_records_one_verifiable_receipt() {
    let (agent, cap, lane) = fixture();
    agent.enable_receipts(true);
    agent.set_latency(7);
    call(&agent, lane, &cap, "payload-that-must-not-appear");
    let receipts = agent.receipts();
    assert_eq!(receipts.len(), 1);
    let receipt = &receipts[0];
    assert_eq!(receipt.sequence, 1);
    assert_eq!(receipt.method, "echo");
    assert_eq!(receipt.cap, cap.id().correlation_id());
    assert!(agent.verify_receipt(receipt));
    // The audit record carries no argument material.
    let rendered = format!("{receipt:?}");
    assert!(!rendered.contains("payload-that-must-not-appear"));
    assert!(!receipt.cap.contains(&cap.id().hex()));
}

#[test]
fn a_refused_call_records_no_receipt() {
    let (agent, cap, lane) = fixture();
    agent.enable_receipts(true);
    let error = agent
        .call(lane, &cap, "refuse", Vec::new())
        .expect_err("refused");
    assert!(error.code().starts_with("rpc/"));
    assert!(agent.receipts().is_empty());
}

#[test]
fn a_tampered_receipt_does_not_verify() {
    let (agent, cap, lane) = fixture();
    agent.enable_receipts(true);
    call(&agent, lane, &cap, "one");
    let mut receipt = agent.receipts().remove(0);
    receipt.method = "write".to_string();
    assert!(!agent.verify_receipt(&receipt));
    receipt.method = "echo".to_string();
    receipt.at_ms = receipt.at_ms.saturating_add(1);
    assert!(!agent.verify_receipt(&receipt));
    receipt.at_ms = receipt.at_ms.saturating_sub(1);
    receipt.sequence = receipt.sequence.saturating_add(1);
    assert!(!agent.verify_receipt(&receipt));
    receipt.sequence = 1;
    assert!(
        agent.verify_receipt(&receipt),
        "the original fields verify again"
    );
}

#[test]
fn a_receipt_from_another_kernel_does_not_verify() {
    let (first, first_cap, first_lane) = fixture();
    first.enable_receipts(true);
    call(&first, first_lane, &first_cap, "a");
    let foreign = first.receipts().remove(0);
    // Same receipt fields, different kernel secret: the mac cannot transfer.
    let second = Agent::with_secret([0x4e; 32]);
    assert!(!second.verify_receipt(&foreign));
    // The owning kernel still verifies it.
    assert!(first.verify_receipt(&foreign));
}

#[test]
fn the_ring_keeps_the_newest_receipts() {
    let (agent, cap, lane) = fixture();
    agent.enable_receipts(true);
    for index in 0..(MAX_RECEIPTS + 3) {
        call(&agent, lane, &cap, &format!("call-{index}"));
    }
    let receipts = agent.receipts();
    assert_eq!(receipts.len(), MAX_RECEIPTS);
    assert_eq!(
        receipts.last().expect("newest").sequence as usize,
        MAX_RECEIPTS + 3
    );
    assert!(receipts
        .windows(2)
        .all(|pair| pair[0].sequence < pair[1].sequence));
}
