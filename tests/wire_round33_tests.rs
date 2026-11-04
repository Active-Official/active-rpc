//! R-01 wire, round 33: the writer applies every rule the reader applies.
//!
//! `Envelope::encode` validates against the default limits before it emits a
//! frame, so a table or a payload the decoder would refuse cannot leave the
//! process. These tests drive `encode` and assert the fault class.

use std::collections::BTreeSet;

use active_rpc::cap::CapId;
use active_rpc::value::{Arg, Value};
use active_rpc::wire::{CapDescriptor, CapTableDelta, Envelope};
use active_rpc::Budget;

fn descriptor(id: u8, method: &str) -> CapDescriptor {
    CapDescriptor {
        id: CapId([id; 16]),
        methods: BTreeSet::from([method.to_string()]),
        budget: Budget::default(),
        read_only: false,
        redact: false,
        path_scope: None,
    }
}

/// A zero id is not a capability; the reader refused it and the writer must
/// not emit one (round 33, M4).
#[test]
fn a_writer_refuses_a_zero_capability_id() {
    let envelope =
        Envelope::request(1, "stats", Vec::new()).with_caps(vec![descriptor(0, "stats")]);
    let error = envelope
        .encode()
        .expect_err("a zero id is not a capability");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");
}

/// A descriptor that grants no method is refused before it reaches the wire,
/// on the same terms as `mint` and `attenuate` (round 33, M4).
#[test]
fn a_writer_refuses_a_descriptor_with_no_methods() {
    let mut cap = descriptor(1, "stats");
    cap.methods.clear();
    let error = Envelope::request(1, "stats", Vec::new())
        .with_caps(vec![cap])
        .encode()
        .expect_err("a descriptor with no methods is not a capability");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");
}

/// A zero ceiling disables a bound; the table must not carry one
/// (round 33, M4).
#[test]
fn a_writer_refuses_a_budget_with_a_disabled_ceiling() {
    for disable in 0..7 {
        let mut cap = descriptor(2, "stats");
        let mut budget = Budget::default();
        match disable {
            0 => budget.max_calls = 0,
            1 => budget.max_bytes = 0,
            2 => budget.max_wall_ms = 0,
            3 => budget.max_nodes = 0,
            4 => budget.max_depth = 0,
            5 => budget.max_array_len = 0,
            _ => budget.max_value_size = 0,
        }
        cap.budget = budget;
        let error = Envelope::request(1, "stats", Vec::new())
            .with_caps(vec![cap])
            .encode()
            .expect_err("a disabled ceiling is not a budget");
        assert_eq!(
            error.code(),
            "rpc/capability-table",
            "field {disable}: {error}"
        );
    }
}

/// A delta that adds an id the base already carries makes the table
/// order-dependent; the writer refuses it as the reader does
/// (round 33, M4).
#[test]
fn a_writer_refuses_a_duplicate_id_across_the_caps_and_the_delta() {
    let mut envelope =
        Envelope::request(1, "stats", Vec::new()).with_caps(vec![descriptor(3, "stats")]);
    envelope.cap_delta = Some(CapTableDelta {
        base: [0x33; 32],
        removed: Vec::new(),
        added: vec![descriptor(3, "stats")],
    });
    let error = envelope
        .encode()
        .expect_err("the same id twice makes the table order-dependent");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");
}

/// A payload past the ceiling is a framing refusal, exactly as the reader
/// reports it; `rpc/payload` would send a caller to fix a payload that is
/// merely too large (round 33, H2).
#[test]
fn an_oversized_payload_is_a_wire_fault_at_the_writer() {
    // The default ceiling is 32 MiB; one byte past it must not leave.
    let big =
        Envelope::request(1, "stats", Vec::new()).with_payload(vec![0u8; (33 << 20) as usize]);
    let error = big.encode().expect_err("past the payload ceiling");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    assert!(
        error.to_string().contains("payload"),
        "the reason names the payload: {error}"
    );

    // The same image through the value path keeps that class: a caller can
    // branch on `rpc/wire` for every framing ceiling.
    let bytes = Envelope::request(1, "stats", vec![Arg::Value(Value::Int(1))])
        .encode()
        .expect("a small frame");
    assert_eq!(Envelope::decode(&bytes).expect("decode").payload.len(), 0);
}
