//! R-01 wire, round 34: the encoder's value budget is cumulative across the
//! whole frame, exactly as the decoder's is.

use active_rpc::value::{Arg, Value};
use active_rpc::wire::{Envelope, WireLimits};

/// Two arguments that each fit the value ceiling are still over it together;
/// the decoder counts the whole frame (round 34, #4).
#[test]
fn the_value_ceiling_is_cumulative_across_arguments() {
    let limits = WireLimits::default();
    let half = limits.max_values / 2 + 1;
    let arg = Value::list((0..half).map(|_| Value::Null));
    let envelope = Envelope::request(1, "p", vec![Arg::Value(arg.clone()), Arg::Value(arg)]);
    let error = envelope
        .encode()
        .expect_err("the two arguments together pass the ceiling");
    assert_eq!(error.code(), "rpc/wire", "{error}");

    // One argument of the same shape is under the ceiling and round-trips.
    let single = Value::list((0..half).map(|_| Value::Null));
    let bytes = Envelope::request(1, "p", vec![Arg::Value(single)])
        .encode()
        .expect("one argument fits");
    Envelope::decode(&bytes).expect("the decoder agrees");
}

/// A descriptor's method is bounded by the same `max_method` the envelope uses:
/// the writer refused the frame but the table encoder used to emit it, so a
/// peer was left to refuse it (round 41, F3).
#[test]
fn a_descriptor_method_past_the_ceiling_is_refused_by_the_writer() {
    use std::collections::BTreeSet;

    use active_rpc::cap::CapId;
    use active_rpc::wire::{encode_capability_table, CapDescriptor};
    use active_rpc::Budget;

    let long = "m".repeat(WireLimits::default().max_method as usize + 1);
    let descriptor = CapDescriptor {
        id: CapId([0x5A; 16]),
        methods: BTreeSet::from([long]),
        budget: Budget::default(),
        read_only: false,
        redact: false,
        path_scope: None,
    };
    let error = encode_capability_table(std::slice::from_ref(&descriptor))
        .expect_err("a descriptor method past the ceiling");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");
    let error = Envelope::request(1, "p", Vec::new())
        .with_caps(vec![descriptor])
        .encode()
        .expect_err("the envelope applies the same rule");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");
}
