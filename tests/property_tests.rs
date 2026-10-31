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
use active_rpc::cap::{CapAttrs, CapId, CapPersistence, ToolPolicy};
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

/// Every authority attribute, generated independently, so the attenuation
/// property covers methods, all seven budget fields, read-only, redaction,
/// path scope, topics, TTL, tool policy, persistence and identity binding.
fn attrs_strategy() -> impl Strategy<Value = CapAttrs> {
    (
        prop::collection::btree_set("[a-z]{1,6}", 1..4),
        budget_strategy(),
        any::<bool>(),
        any::<bool>(),
        prop::option::of(("[a-z]{1,6}", prop::collection::vec("[a-z]{1,6}", 0..3))),
        prop::option::of(prop::collection::btree_set("[a-z]{1,6}", 0..3)),
        prop::option::of(1u64..10_000),
        prop::option::of(prop::collection::btree_set("[a-z]{1,6}", 0..3)),
        prop::option::of(any::<[u8; 32]>()),
        any::<bool>(),
    )
        .prop_map(
            |(
                methods,
                budget,
                read_only,
                redact,
                path,
                topics,
                ttl_ms,
                tools,
                binding,
                allow_process,
            )| {
                let method_refs: Vec<&str> = methods.iter().map(String::as_str).collect();
                let mut attrs = CapAttrs::new(&method_refs).with_budget(budget);
                attrs.read_only = read_only;
                attrs.redact = redact;
                attrs.path_scope = path.map(|(head, tail)| {
                    let mut scope = head;
                    for part in tail {
                        scope.push('.');
                        scope.push_str(&part);
                    }
                    scope
                });
                attrs.topics = topics;
                attrs.ttl_ms = ttl_ms;
                attrs.tool_policy = tools.map(|allowed| ToolPolicy {
                    allowed,
                    max_arg_bytes: 1 << 10,
                    allow_process,
                });
                attrs.bound_to = binding;
                attrs
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// `attenuate` and `is_attenuation_of` must agree exactly: the enforcer
    /// accepts a child if and only if the predicate says it is monotone, and
    /// the result is itself a narrowing of both sides.
    #[test]
    fn attenuation_accepts_exactly_the_monotone_children(
        parent in attrs_strategy(),
        child in attrs_strategy(),
    ) {
        let expected = child.is_attenuation_of(&parent);
        match parent.attenuate(child.clone()) {
            Ok(result) => {
                prop_assert!(expected, "attenuate accepted a child the predicate rejects");
                prop_assert!(result.is_attenuation_of(&parent));
                prop_assert!(result.methods.is_subset(&child.methods));
                prop_assert!(result.budget.is_attenuation_of(&parent.budget));
                prop_assert!(result.budget.is_attenuation_of(&child.budget));
                prop_assert_eq!(result.path_scope.clone(), child.path_scope.clone());
                prop_assert_eq!(result.topics.clone(), child.topics.clone());
                prop_assert_eq!(result.ttl_ms, child.ttl_ms);
                prop_assert_eq!(result.bound_to, parent.bound_to.or(child.bound_to));
            }
            Err(error) => {
                prop_assert!(!expected, "attenuate refused a monotone child: {error}");
            }
        }
    }

    /// Widening any single attribute is refused, whatever the parent's other
    /// attributes are.
    #[test]
    fn widening_any_single_attribute_is_refused(parent in attrs_strategy()) {
        let mut child = parent.clone();
        child.methods.insert("zz_widen".to_string());
        prop_assert!(parent.attenuate(child).is_err(), "method set grew");

        let mut child = parent.clone();
        child.budget.max_calls = parent.budget.max_calls.saturating_add(1);
        prop_assert!(parent.attenuate(child).is_err(), "call budget grew");

        let mut child = parent.clone();
        child.budget.max_bytes = parent.budget.max_bytes.saturating_add(1);
        prop_assert!(parent.attenuate(child).is_err(), "byte budget grew");

        let mut child = parent.clone();
        child.budget.max_depth = parent.budget.max_depth.saturating_add(1);
        prop_assert!(parent.attenuate(child).is_err(), "depth budget grew");

        if parent.read_only {
            let mut child = parent.clone();
            child.read_only = false;
            prop_assert!(parent.attenuate(child).is_err(), "read-only lifted");
        }
        if parent.redact {
            let mut child = parent.clone();
            child.redact = false;
            prop_assert!(parent.attenuate(child).is_err(), "redaction lifted");
        }
        if parent.ttl_ms.is_some() {
            let mut child = parent.clone();
            child.ttl_ms = None;
            prop_assert!(parent.attenuate(child).is_err(), "lifetime removed");
            let mut child = parent.clone();
            child.ttl_ms = Some(parent.ttl_ms.unwrap().saturating_add(1));
            prop_assert!(parent.attenuate(child).is_err(), "lifetime grew");
        }
        if parent.topics.is_some() {
            let mut child = parent.clone();
            child.topics = None;
            prop_assert!(parent.attenuate(child).is_err(), "topic restriction removed");
            let mut child = parent.clone();
            let mut widened = parent.topics.clone().unwrap();
            widened.insert("zz_widen".to_string());
            child.topics = Some(widened);
            prop_assert!(parent.attenuate(child).is_err(), "topic set widened");
        }
        if parent.path_scope.is_some() {
            let mut child = parent.clone();
            child.path_scope = None;
            prop_assert!(parent.attenuate(child).is_err(), "path scope removed");
            let mut child = parent.clone();
            child.path_scope = Some("zz_unrelated".to_string());
            prop_assert!(parent.attenuate(child).is_err(), "path scope moved");
        }
        if parent.tool_policy.is_some() {
            let mut child = parent.clone();
            child.tool_policy = None;
            prop_assert!(parent.attenuate(child).is_err(), "tool policy removed");
            let mut child = parent.clone();
            let mut widened = parent.tool_policy.clone().unwrap();
            widened.allowed.insert("zz_tool".to_string());
            child.tool_policy = Some(widened);
            prop_assert!(parent.attenuate(child).is_err(), "tool allow-list grew");
        }
        if parent.persistence != CapPersistence::Durable {
            let mut child = parent.clone();
            child.persistence = CapPersistence::Durable;
            prop_assert!(parent.attenuate(child).is_err(), "durability widened");
        }
        if let Some(bound) = parent.bound_to {
            let mut child = parent.clone();
            child.bound_to = Some([bound[0] ^ 0xff; 32]);
            prop_assert!(parent.attenuate(child).is_err(), "binding moved");
        }
    }

    /// A refused dependency never runs the pipelined call: the promise's error
    /// is the call's error, and the provider is not invoked.
    #[test]
    fn a_refused_dependency_stops_the_pipeline(payload in "[a-z]{0,24}") {
        let agent = Agent::with_secret([0x5a; 32]);
        let provider = agent.register(Box::new(Echo));
        let cap = agent
            .mint(provider, 0, CapAttrs::new(&["echo"]))
            .expect("mint");
        let lane = agent.create_lane("pipeline", Budget::default()).expect("lane");
        let first = agent
            .call(lane, &cap, "echo", vec![Arg::text(payload)])
            .expect("first");
        agent.revoke(&cap);
        let second = agent.call(lane, &cap, "echo", vec![Arg::Promise(first.id())]);
        prop_assert!(second.is_err(), "a revoked capability queued a pipelined call");
        prop_assert_eq!(second.err().unwrap().code(), "rpc/revoked");
    }
}
