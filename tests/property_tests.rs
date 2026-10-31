//! Property tests for the wire codec and attenuation algebra.
//!
//! `proptest` reports the case count; the properties are:
//!
//! 1. every generated envelope survives encode → decode → encode unchanged;
//! 2. a decoded envelope never has more args, caps or bytes than the limits;
//! 3. attenuation is monotone: a child's budget and method set never exceed the
//!    parent's, and any attempt to do so fails;
//! 4. arbitrary byte strings are rejected or decoded without panicking.

use std::collections::BTreeSet;

use active_rpc::budget::Budget;
use active_rpc::cap::{CapAttrs, CapId};
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::wire::{CapDescriptor, Envelope, WireLimits};
use active_rpc::Agent;
use proptest::prelude::*;

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

    fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
        let value = call
            .args
            .iter()
            .find_map(|arg| match arg {
                Arg::Value(value) => Some(value.clone()),
                _ => None,
            })
            .unwrap_or(Value::Null);
        Ok(Response::Value(value))
    }
}

fn value_strategy() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::Int),
        (-1e9..1e9f64).prop_map(Value::Float),
        "[a-zA-Z0-9 _.-]{0,32}".prop_map(Value::Text),
        Just(Value::Secret),
        prop::collection::vec(any::<u8>(), 0..64).prop_map(Value::Module),
        "[a-z][a-z0-9_.]{0,24}".prop_map(Value::Path),
    ];
    leaf.prop_recursive(2, 16, 3, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::List),
            prop::collection::btree_map("[a-z][a-z0-9_]{0,6}", inner, 0..4).prop_map(Value::Map),
        ]
    })
}

fn budget_strategy() -> impl Strategy<Value = Budget> {
    (
        1u64..10_000,
        1u64..1_000_000,
        1u64..10_000,
        1u64..100_000,
        1u64..256,
        1u64..10_000,
        1u64..1_000_000,
    )
        .prop_map(|(calls, bytes, wall, nodes, depth, array, value)| Budget {
            max_calls: calls,
            max_bytes: bytes,
            max_wall_ms: wall,
            max_nodes: nodes,
            max_depth: depth,
            max_array_len: array,
            max_value_size: value,
        })
}

fn cap_strategy() -> impl Strategy<Value = CapDescriptor> {
    (
        any::<[u8; 16]>(),
        prop::collection::btree_set("[a-z]{1,8}", 1..4),
        budget_strategy(),
        any::<bool>(),
        any::<bool>(),
        prop::option::of("[a-z]{1,8}"),
    )
        .prop_map(
            |(id, methods, budget, read_only, redact, path_scope)| CapDescriptor {
                id: CapId(id),
                methods,
                budget,
                read_only,
                redact,
                path_scope,
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn envelope_round_trips(
        request_id in any::<u64>(),
        method in "[a-z][a-z0-9_]{0,16}",
        values in prop::collection::vec(value_strategy(), 0..5),
        payload in prop::collection::vec(any::<u8>(), 0..128),
        caps in prop::collection::vec(cap_strategy(), 0..3),
    ) {
        let args = values.into_iter().map(Arg::Value).collect();
        let envelope = Envelope::request(request_id, method, args)
            .with_payload(payload)
            .with_caps(caps);
        let bytes = envelope.encode().expect("encode");
        let decoded = Envelope::decode(&bytes).expect("decode");
        prop_assert_eq!(&decoded, &envelope);
        prop_assert_eq!(decoded.encode().expect("re-encode"), bytes);
    }

    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let outcome = std::panic::catch_unwind(|| Envelope::decode(&bytes));
        prop_assert!(outcome.is_ok(), "decode panicked");
        match outcome.unwrap() {
            Ok(envelope) => {
                prop_assert!(envelope.args.len() <= WireLimits::default().max_args as usize);
                prop_assert!(envelope.caps.len() <= WireLimits::default().max_caps as usize);
            }
            Err(error) => prop_assert!(!error.code().is_empty()),
        }
    }

    #[test]
    fn attenuation_is_monotone(
        parent_budget in budget_strategy(),
        child_calls in 1u64..20_000,
        methods in prop::collection::btree_set("[a-z]{1,6}", 1..4),
        subset in prop::collection::btree_set("[a-z]{1,6}", 0..3),
    ) {
        let parent = CapAttrs::new(
            &methods.iter().map(String::as_str).collect::<Vec<_>>(),
        )
        .with_budget(parent_budget);
        let mut child_methods: BTreeSet<String> = subset
            .intersection(&methods)
            .cloned()
            .collect();
        if child_methods.is_empty() {
            child_methods = methods.clone();
        }
        let child_budget = Budget {
            max_calls: child_calls.min(parent_budget.max_calls),
            ..parent_budget
        };
        let child = CapAttrs::new(
            &child_methods.iter().map(String::as_str).collect::<Vec<_>>(),
        )
        .with_budget(child_budget);
        let attenuated = parent.attenuate(child).expect("a narrowing attenuation");
        prop_assert!(attenuated.budget.max_calls <= parent_budget.max_calls);
        prop_assert!(attenuated.methods.is_subset(&parent.methods));

        // Asking for more calls than the parent is always refused.
        let greedy = CapAttrs::new(
            &child_methods.iter().map(String::as_str).collect::<Vec<_>>(),
        )
        .with_budget(Budget {
            max_calls: parent_budget.max_calls.saturating_add(1),
            ..parent_budget
        });
        prop_assert!(parent.attenuate(greedy).is_err());
    }

    #[test]
    fn revoke_at_dispatch_is_always_enforced(
        seed in any::<[u8; 32]>(),
        payload in "[a-zA-Z0-9 _.-]{0,48}",
    ) {
        let agent = Agent::with_secret(seed);
        let provider = agent.register(Box::new(Echo));
        let cap = agent
            .mint(provider, 0, CapAttrs::new(&["echo"]))
            .expect("mint");
        let lane = agent
            .create_lane("property", Budget::default())
            .expect("lane");
        let promise = agent
            .call(lane, &cap, "echo", vec![Arg::text(payload)])
            .expect("queued");
        agent.revoke(&cap);
        let error = promise.value().expect_err("revoked call must fail");
        prop_assert_eq!(error.code(), "rpc/revoked");
    }
}
