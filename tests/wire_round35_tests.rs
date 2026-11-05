//! R-01 wire, round 35: the programmatic delta path applies the descriptor
//! rule the wire path applies.

use std::collections::BTreeSet;

use active_rpc::cap::CapId;
use active_rpc::wire::{CapDescriptor, CapTableDelta, WireLimits};
use active_rpc::Budget;

fn descriptor(id: u8, methods: BTreeSet<String>) -> CapDescriptor {
    CapDescriptor {
        id: CapId([id; 16]),
        methods,
        budget: Budget::default(),
        read_only: false,
        redact: false,
        path_scope: None,
    }
}

/// A delta addition is a descriptor: the method-count, method-length and path
/// ceilings apply to it as they do on the wire (round 35, N2).
#[test]
fn a_delta_addition_obeys_the_descriptor_ceilings() {
    let base = vec![descriptor(1, BTreeSet::from(["echo".to_string()]))];
    let too_many: BTreeSet<String> = (0..=64).map(|index| format!("m{index}")).collect();
    let long = "m".repeat(1_025);

    for methods in [too_many, BTreeSet::from([long])] {
        let delta = CapTableDelta::new(&base, Vec::new(), vec![descriptor(2, methods)])
            .expect("the delta itself is well formed");
        let error = delta
            .apply_to(&base)
            .expect_err("the addition is not a legal descriptor");
        assert_eq!(error.code(), "rpc/capability-table", "{error}");
    }

    // And a legal addition still applies.
    let delta = CapTableDelta::new(
        &base,
        Vec::new(),
        vec![descriptor(3, BTreeSet::from(["echo".to_string()]))],
    )
    .expect("delta");
    let table = delta.apply_to(&base).expect("a legal addition");
    assert_eq!(table.len(), 2);
}

/// The table encoder emits only tables its own reader accepts: a repeated id
/// and a table past the descriptor ceiling are refused (round 42, F2).
#[test]
fn a_table_encoder_refuses_duplicate_ids_and_an_over_count() {
    use active_rpc::wire::{encode_capability_table, WireLimits};

    let one = descriptor(1, BTreeSet::from(["echo".to_string()]));
    let error =
        encode_capability_table(&[one.clone(), one]).expect_err("the same id twice is not a table");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");

    // `MAX_CAP_TABLE + 1` non-zero ids: the count is what the writer must
    // refuse, not the zero-id rule (round 43, F3).
    use active_rpc::wire::MAX_CAP_TABLE;
    let mut many = Vec::with_capacity(MAX_CAP_TABLE + 1);
    for index in 1..=(MAX_CAP_TABLE + 1) {
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&(index as u64).to_le_bytes());
        many.push(CapDescriptor {
            id: CapId(id),
            methods: BTreeSet::from(["echo".to_string()]),
            budget: Budget::default(),
            read_only: false,
            redact: false,
            path_scope: None,
        });
    }
    let error = encode_capability_table(&many).expect_err("past the table ceiling");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");

    // The reader honours `max_caps` when the caller supplies it, and the
    // convenience wrapper accepts what the writer produces.
    let mut table = Vec::new();
    for index in 1..=300u64 {
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&index.to_le_bytes());
        table.push(CapDescriptor {
            id: CapId(id),
            methods: BTreeSet::from(["echo".to_string()]),
            budget: Budget::default(),
            read_only: false,
            redact: false,
            path_scope: None,
        });
    }
    let bytes = encode_capability_table(&table).expect("300 descriptors fit the table");
    assert_eq!(
        active_rpc::wire::decode_capability_table(&bytes)
            .expect("the table profile accepts it")
            .len(),
        300
    );
    let error = active_rpc::wire::decode_capability_table_with(
        &bytes,
        &WireLimits {
            max_caps: 16,
            ..WireLimits::default()
        },
    )
    .expect_err("a strict caller's ceiling is honoured");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");
}

/// A programmatic delta is bounded like an envelope delta: 300 additions applied
/// locally would never encode (round 36, #2).
#[test]
fn a_programmatic_delta_past_the_per_delta_ceiling_is_refused() {
    let base = vec![descriptor(1, BTreeSet::from(["echo".to_string()]))];
    let mut added = Vec::new();
    for index in 0u32..=WireLimits::default().max_caps {
        let mut id = [0u8; 16];
        id[..4].copy_from_slice(&(index + 2).to_le_bytes());
        added.push(CapDescriptor {
            id: CapId(id),
            methods: BTreeSet::from(["echo".to_string()]),
            budget: Budget::default(),
            read_only: false,
            redact: false,
            path_scope: None,
        });
    }
    let delta = CapTableDelta::new(&base, Vec::new(), added).expect("delta");
    let error = delta
        .apply_to(&base)
        .expect_err("past the per-delta ceiling");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");
}

/// A standalone table is the table profile (`MAX_CAP_TABLE`); an envelope is
/// the frame profile (`max_caps`). The wrapper accepts a 300-descriptor table
/// that the default envelope profile refuses, and that asymmetry is deliberate
/// and pinned here (round 44, F-7).
#[test]
fn the_table_profile_and_the_frame_profile_are_named() {
    use active_rpc::wire::{decode_capability_table, decode_capability_table_with, MAX_CAP_TABLE};

    let mut table = Vec::new();
    for index in 1u32..=300 {
        let mut id = [0u8; 16];
        id[..4].copy_from_slice(&index.to_le_bytes());
        table.push(CapDescriptor {
            id: CapId(id),
            methods: BTreeSet::from(["echo".to_string()]),
            budget: Budget::default(),
            read_only: false,
            redact: false,
            path_scope: None,
        });
    }
    let bytes = active_rpc::wire::encode_capability_table(&table).expect("encode");
    assert!(MAX_CAP_TABLE >= table.len());
    assert_eq!(
        decode_capability_table(&bytes)
            .expect("table profile")
            .len(),
        300
    );
    let error = decode_capability_table_with(&bytes, &WireLimits::default())
        .expect_err("the frame profile is 256 descriptors");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");
}
