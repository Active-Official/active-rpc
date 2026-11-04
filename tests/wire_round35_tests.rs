//! R-01 wire, round 35: the programmatic delta path applies the descriptor
//! rule the wire path applies.

use std::collections::BTreeSet;

use active_rpc::cap::CapId;
use active_rpc::wire::{CapDescriptor, CapTableDelta};
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

    let limits = WireLimits::default();
    let mut many = Vec::with_capacity(limits.max_caps as usize + 1);
    for index in 0..=limits.max_caps {
        let mut id = [0u8; 16];
        id[..4].copy_from_slice(&index.to_le_bytes());
        many.push(CapDescriptor {
            id: CapId(id),
            methods: BTreeSet::from(["echo".to_string()]),
            budget: Budget::default(),
            read_only: false,
            redact: false,
            path_scope: None,
        });
    }
    let error = encode_capability_table(&many).expect_err("past the descriptor ceiling");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");
}
