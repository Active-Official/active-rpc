//! R-01 wire round 2: the decode arena is bounded, the encoder refuses a
//! value it could never transmit, and the table refuses duplicates.

use std::collections::BTreeSet;

use active_rpc::cap::CapId;
use active_rpc::value::{Arg, Value};
use active_rpc::wire::{
    decode_capability_table_with, encode_capability_table, CapDescriptor, Envelope, WireLimits,
};
use active_rpc::Budget;

fn envelope_with(value: Value) -> Vec<u8> {
    Envelope::request(1, "p", vec![Arg::Value(value)])
        .encode()
        .expect("encode")
}

#[test]
fn a_wide_list_is_refused_by_the_decode_arena_ceiling() {
    // A frame is bounded by bytes, but a byte can be a whole value: 200 000
    // nulls fit in 200 KB and decode to 200 000 `Value`s. The decode limits
    // bound the arena, not the frame.
    let wide = Value::list((0..1_100_000).map(|_| Value::Null));
    let bytes = envelope_with(wide);

    let strict = WireLimits::strict();
    let error = Envelope::decode_with(&bytes, strict).expect_err("too many values");
    assert_eq!(error.code(), "rpc/wire", "{}", error.code());

    let error = Envelope::decode(&bytes).expect_err("the default arena ceiling binds");
    assert_eq!(error.code(), "rpc/wire", "{}", error.code());

    // A list wider than `max_array_len` is refused even when the cumulative
    // count would fit.
    let limits = WireLimits {
        max_values: 1 << 20,
        max_array_len: 4,
        ..WireLimits::default()
    };
    let small = envelope_with(Value::list((0..8).map(|_| Value::Null)));
    let error = Envelope::decode_with(&small, limits).expect_err("too wide");
    assert_eq!(error.code(), "rpc/wire", "{error}");
}

#[test]
fn a_duplicate_capability_id_in_a_full_table_is_refused() {
    let descriptor = CapDescriptor {
        id: CapId([0x11; 16]),
        methods: BTreeSet::from(["echo".to_string()]),
        budget: Budget::default(),
        read_only: false,
        redact: false,
        path_scope: None,
    };
    let bytes = encode_capability_table(&[descriptor.clone(), descriptor]).expect("encode");
    let error = decode_capability_table_with(&bytes, &WireLimits::default())
        .expect_err("the same id twice makes the table order-dependent");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");
}

#[test]
fn floats_compare_bit_exactly() {
    // The derived equality answered `NaN != NaN` (identical images compared
    // unequal) and `0.0 == -0.0` (different images compared equal).
    assert_eq!(
        Value::Float(f64::NAN),
        Value::Float(f64::NAN),
        "identical NaN images must compare equal"
    );
    assert_ne!(Value::Float(0.0), Value::Float(-0.0));
    assert_eq!(
        Value::Float(f64::NAN),
        Value::Float(f64::from_bits(f64::NAN.to_bits())),
        "the same bit pattern is the same value"
    );
    // And a round trip is equality, for every float shape.
    for number in [f64::NAN, f64::INFINITY, 0.0, -0.0, 1.5, -2.25] {
        let value = Value::Float(number);
        let bytes = envelope_with(value.clone());
        let decoded = Envelope::decode(&bytes).expect("decode");
        match &decoded.args[0] {
            Arg::Value(round) => assert_eq!(round, &value, "round trip of {number}"),
            other => panic!("unexpected argument {other:?}"),
        }
    }
}

#[test]
fn the_encoder_refuses_a_value_deeper_than_the_wire() {
    let mut value = Value::Int(1);
    for _ in 0..100 {
        value = Value::list(vec![value]);
    }
    let error = Envelope::request(1, "p", vec![Arg::Value(value)])
        .encode()
        .expect_err("the encoder refuses a value the decoder would");
    assert_eq!(error.code(), "rpc/wire", "{error}");
}
