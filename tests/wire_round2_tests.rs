//! R-01 wire round 2: the decode arena is bounded, the encoder refuses a
//! value it could never transmit, and the table refuses duplicates.

use std::collections::BTreeSet;

use active_rpc::cap::CapId;
use active_rpc::value::{Arg, Value};
use active_rpc::wire::{
    decode_capability_table_with, encode_capability_table, CapDescriptor, CapTableDelta, Envelope,
    WireLimits,
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

#[test]
fn a_truncated_delta_is_a_capability_table_fault() {
    // Every fault inside the delta region is a table fault: a peer that branches
    // on the class must not read "framing" and resynchronize on a table attack.
    let mut envelope = Envelope::request(1, "p", Vec::new());
    envelope.cap_delta = Some(CapTableDelta {
        base: [0x22; 32],
        removed: Vec::new(),
        added: Vec::new(),
    });
    let bytes = envelope.encode().expect("encode");
    // Cut two bytes out of `removed_count` (4 bytes) and out of `added_count`.
    for cut in [2usize, 6] {
        let truncated = &bytes[..bytes.len() - cut];
        let error = Envelope::decode(truncated).expect_err("truncated delta");
        assert_eq!(error.code(), "rpc/capability-table", "cut {cut}: {error}");
    }
}

#[test]
fn a_non_canonical_map_is_refused() {
    // Keys must be strictly increasing: `{"b":null,"a":null}` decoded to a
    // sorted map and re-encoded differently, so two byte images named one value.
    let mut value = vec![6, 2, 0, 0, 0];
    value.extend_from_slice(&1u32.to_le_bytes());
    value.push(b'b');
    value.push(0);
    value.extend_from_slice(&1u32.to_le_bytes());
    value.push(b'a');
    value.push(0);

    let shallow = Envelope::request(1, "p", vec![Arg::Value(Value::Null)])
        .encode()
        .expect("encode");
    let offset = 16 + 4 + 1 + 4 + 1;
    let mut spliced = Vec::new();
    spliced.extend_from_slice(&shallow[..offset]);
    spliced.extend_from_slice(&value);
    spliced.extend_from_slice(&shallow[offset + 1..]);
    let error = Envelope::decode(&spliced).expect_err("out of order");
    assert_eq!(error.code(), "rpc/wire", "{error}");

    // The canonical order for the same value is accepted and re-encodes to the
    // same bytes.
    let mut canonical = vec![6, 2, 0, 0, 0];
    canonical.extend_from_slice(&1u32.to_le_bytes());
    canonical.push(b'a');
    canonical.push(0);
    canonical.extend_from_slice(&1u32.to_le_bytes());
    canonical.push(b'b');
    canonical.push(0);
    let mut spliced = Vec::new();
    spliced.extend_from_slice(&shallow[..offset]);
    spliced.extend_from_slice(&canonical);
    spliced.extend_from_slice(&shallow[offset + 1..]);
    let decoded = Envelope::decode(&spliced).expect("canonical");
    assert_eq!(decoded.encode().expect("re-encode"), spliced);
}

#[test]
fn a_strict_profile_bounds_the_path_scope() {
    let descriptor = CapDescriptor {
        id: CapId([0x33; 16]),
        methods: BTreeSet::from(["echo".to_string()]),
        budget: Budget::default(),
        read_only: false,
        redact: false,
        path_scope: Some("p".repeat(512)),
    };
    let bytes = encode_capability_table(&[descriptor]).expect("encode");
    // The default profile allows a 1 KiB scope; strict allows 128 bytes.
    decode_capability_table_with(&bytes, &WireLimits::default()).expect("default");
    let error = decode_capability_table_with(&bytes, &WireLimits::strict())
        .expect_err("strict bounds the scope");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");
}

#[test]
fn a_non_canonical_method_order_is_refused() {
    // Two methods in descending order decode to a sorted set and re-encode
    // differently, so the bytes are not a fixed point.
    let canonical = CapDescriptor {
        id: CapId([0x44; 16]),
        methods: BTreeSet::from(["a".to_string(), "b".to_string()]),
        budget: Budget::default(),
        read_only: false,
        redact: false,
        path_scope: None,
    };
    let bytes = encode_capability_table(&[canonical]).expect("encode");
    // Find the method block: count(4) then "a" (4+1) then "b" (4+1).
    let count_at = 4usize;
    let first_len_at = count_at + 4 + 16;
    let second_len_at = first_len_at + 4 + 1;
    let mut swapped = bytes.clone();
    // Swap the two one-byte names and their lengths.
    swapped[first_len_at] = b'b';
    swapped[second_len_at] = b'a';
    let error = decode_capability_table_with(&swapped, &WireLimits::default())
        .expect_err("descending method order is refused");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");
}

/// A map key is a value for the decode arena. Keys were read with `read_str`
/// and never charged, so a frame of many keys bought one `BTreeMap` insert
/// each without touching `max_values` (round 24, #7).
#[test]
fn map_keys_charge_the_decode_arena() {
    let map = Value::Map(
        (0..8u32)
            .map(|index| (format!("k{index:02}"), Value::Null))
            .collect(),
    );
    let bytes = envelope_with(map);
    // One arg value, the map node, eight keys and eight null values.
    let limits = WireLimits {
        max_values: 12,
        ..WireLimits::default()
    };
    let error = Envelope::decode_with(&bytes, limits).expect_err("keys count as values");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    // The same frame decodes when the ceiling covers keys and values.
    Envelope::decode_with(&bytes, WireLimits::default()).expect("keys and values fit");
}

/// A provider failure keeps its inner code on the wire: `rpc/provider` alone
/// cannot tell a peer whether a mutating call landed (round 33, F3).
#[test]
fn an_error_envelope_carries_the_provider_inner_code() {
    let envelope = Envelope::error(
        3,
        &active_rpc::Error::Provider {
            code: "provider/reply-withheld".to_string(),
        },
    );
    let bytes = envelope.encode().expect("encode");
    let decoded = Envelope::decode(&bytes).expect("decode");
    assert_eq!(decoded.method, "provider/reply-withheld");

    // A kernel-authored refusal keeps its own code.
    let envelope = Envelope::error(4, &active_rpc::Error::ReadOnly);
    let bytes = envelope.encode().expect("encode");
    let decoded = Envelope::decode(&bytes).expect("decode");
    assert_eq!(decoded.method, "rpc/read-only");
}

/// An error envelope carries the provider inner code only when it fits the
/// bounded destination field; an over-long OS-bearing code falls back to the
/// class so the refusal stays decodable under the strict profile
/// (round 34, M-3).
#[test]
fn an_overlong_provider_code_falls_back_to_the_class() {
    let long = format!("process/spawn:{}", "x".repeat(300));
    let envelope = Envelope::error(5, &active_rpc::Error::Provider { code: long.clone() });
    assert_eq!(envelope.method, "rpc/provider");
    let bytes = envelope.encode().expect("encode");
    let strict = WireLimits::strict();
    Envelope::decode_with(&bytes, strict).expect("the refusal stays decodable");

    // A code that fits keeps its detail.
    let short = Envelope::error(
        6,
        &active_rpc::Error::Provider {
            code: "provider/object".to_string(),
        },
    );
    assert_eq!(short.method, "provider/object");
}

/// A provider code carrying a control character falls back to the class: a
/// newline in an OS-derived code would forge a line in the peer's log
/// (round 37, D).
#[test]
fn a_provider_code_cannot_carry_a_control_character() {
    let envelope = Envelope::error(
        7,
        &active_rpc::Error::Provider {
            code: "process/spawn:bad\nFAKE rpc/read-only".to_string(),
        },
    );
    assert_eq!(envelope.method, "rpc/provider");
}
