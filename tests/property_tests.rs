//! Property tests for the wire codec and attenuation algebra.
//!
//! `proptest` reports the case count; the properties are:
//!
//! 1. every generated envelope survives encode → decode → encode unchanged;
//! 2. a decoded envelope never has more args, caps or bytes than the limits;
//! 3. attenuation is monotone: a child's budget and method set never exceed the
//!    parent's, and any attempt to do so fails;
//! 4. arbitrary byte strings are rejected or decoded without panicking.
//! 5. budget attenuation is transitive, and `Budget::intersect` is the merge:
//!    commutative, associative, idempotent, and the greatest lower bound;
//! 6. a log of randomly decided receipts round-trips through append and
//!    verify, and refuses tampering and fabricated MACs;
//! 7. attenuation composes through the operation: a two-step attenuation
//!    agrees with the one-step attenuation except that an intermediate
//!    identity binding is inherited.

use std::collections::BTreeSet;

use active_rpc::budget::Budget;
use active_rpc::cap::{CapAttrs, CapId, CapPersistence, ToolPolicy};
use active_rpc::kernel::Provider;
use active_rpc::receipts::{derive_receipt_key, Decision, Receipt, ReceiptLog, LOG_HEADER_LEN};
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
        let provider = agent.register(Box::new(Echo)).expect("register provider");
        let cap = agent
            .mint(provider, 0, CapAttrs::new(&["echo"]))
            .expect("mint");
        let lane = agent
            .create_lane("property", Budget::default())
            .expect("lane");
        let promise = agent
            .call(lane, &cap, "echo", vec![Arg::text(payload)])
            .expect("queued");
        agent.revoke(&cap).expect("revoke");
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
        let provider = agent.register(Box::new(Echo)).expect("register provider");
        let cap = agent
            .mint(provider, 0, CapAttrs::new(&["echo"]))
            .expect("mint");
        let lane = agent.create_lane("pipeline", Budget::default()).expect("lane");
        let first = agent
            .call(lane, &cap, "echo", vec![Arg::text(payload)])
            .expect("first");
        agent.revoke(&cap).expect("revoke");
        let second = agent.call(lane, &cap, "echo", vec![Arg::Promise(first.id())]);
        prop_assert!(second.is_err(), "a revoked capability queued a pipelined call");
        prop_assert_eq!(second.err().unwrap().code(), "rpc/revoked");
    }
}

// ---------------------------------------------------------------------------
// TEST-07 — the audit found property testing narrow (2 `proptest!` blocks in
// this file, 3 in Infinity's) with no property tests for budget intersection,
// receipt-chain verification, merge, stream reassembly, or the promise
// graph. These three blocks close the RPC half of that gap:
//
// * budget algebra: `Budget::is_attenuation_of` is transitive and
//   `Budget::intersect` is the merge (commutative, associative, idempotent,
//   greatest lower bound). There is no `merge` function in this repo —
//   `git grep -i merge -- src` finds only a comment in `cap.rs:378` — so
//   `intersect`, documented as "the strongest attenuation of two budgets",
//   is the merge operation the audit's fix names.
// * receipt log: a log of randomly decided receipts round-trips through
//   append and verify, and refuses tampering and fabricated MACs.
// * attenuation composition: a two-step attenuation agrees with the
//   one-step attenuation, except that an intermediate identity binding is
//   inherited (see the test). The raw `CapAttrs::is_attenuation_of`
//   predicate is NOT transitive — a bound parent, an unbound middle and a
//   differently bound child are pairwise monotone but the child is not an
//   attenuation of the parent — so transitivity is pinned on the operation,
//   not the predicate (F1-NF-09).
//
// Stream reassembly and the promise graph are still unpropertied; see the
// TEST-07 record for why they are follow-ups, not this fix.
// ---------------------------------------------------------------------------

/// A budget narrowed from `parent`: every ceiling is drawn from `1..=parent`,
/// so the result is an attenuation of `parent` by construction.
fn narrowed_budget_strategy(parent: Budget) -> impl Strategy<Value = Budget> {
    (
        1u64..=parent.max_calls,
        1u64..=parent.max_bytes,
        1u64..=parent.max_wall_ms,
        1u64..=parent.max_nodes,
        1u64..=parent.max_depth,
        1u64..=parent.max_array_len,
        1u64..=parent.max_value_size,
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

/// A chain `child <= mid <= parent` of budgets, each step narrowed from the
/// previous one.
fn budget_chain_strategy() -> impl Strategy<Value = (Budget, Budget, Budget)> {
    budget_strategy().prop_flat_map(|parent| {
        narrowed_budget_strategy(parent).prop_flat_map(move |mid| {
            narrowed_budget_strategy(mid).prop_map(move |child| (parent, mid, child))
        })
    })
}

/// Two budgets and a narrowing of their merge, for the greatest-lower-bound
/// property.
fn intersect_chain_strategy() -> impl Strategy<Value = (Budget, Budget, Budget)> {
    (budget_strategy(), budget_strategy()).prop_flat_map(|(a, b)| {
        let merged = a.intersect(&b);
        narrowed_budget_strategy(merged).prop_map(move |narrow| (a, b, narrow))
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// `is_attenuation_of` is a preorder on budgets: reflexive, and
    /// transitive across a generated chain. The chain premises guard the
    /// generator — if narrowing ever produced a widening, the test fails
    /// here instead of passing vacuously.
    #[test]
    fn budget_attenuation_is_transitive((parent, mid, child) in budget_chain_strategy()) {
        prop_assert!(mid.is_attenuation_of(&parent), "mid is not an attenuation of parent");
        prop_assert!(child.is_attenuation_of(&mid), "child is not an attenuation of mid");
        prop_assert!(parent.is_attenuation_of(&parent), "parent is not an attenuation of itself");
        prop_assert!(mid.is_attenuation_of(&mid), "mid is not an attenuation of itself");
        prop_assert!(child.is_attenuation_of(&child), "child is not an attenuation of itself");
        prop_assert!(
            child.is_attenuation_of(&parent),
            "transitivity failed: child <= mid <= parent but child is not an attenuation of parent"
        );
        // The intersect of a chain pair is the smaller side.
        prop_assert_eq!(child.intersect(&parent), child);
        prop_assert_eq!(mid.intersect(&parent), mid);
        prop_assert_eq!(child.intersect(&mid), child);
    }

    /// `intersect` is the merge of two budgets: commutative, associative,
    /// idempotent, and an attenuation of both sides.
    #[test]
    fn budget_intersect_is_the_merge(
        a in budget_strategy(),
        b in budget_strategy(),
        c in budget_strategy(),
    ) {
        let merged = a.intersect(&b);
        prop_assert_eq!(merged, b.intersect(&a), "intersect is not commutative");
        prop_assert_eq!(a.intersect(&a), a, "intersect is not idempotent");
        prop_assert_eq!(b.intersect(&b), b, "intersect is not idempotent");
        prop_assert_eq!(
            merged.intersect(&c),
            a.intersect(&b.intersect(&c)),
            "intersect is not associative"
        );
        prop_assert!(
            merged.is_attenuation_of(&a),
            "the merge is not an attenuation of its left side"
        );
        prop_assert!(
            merged.is_attenuation_of(&b),
            "the merge is not an attenuation of its right side"
        );
    }

    /// The merge is the *greatest* lower bound: any narrowing of it is
    /// still an attenuation of both sides. This is transitivity applied
    /// through the merge, and it is what makes `intersect` the merge rather
    /// than just a lower bound.
    #[test]
    fn budget_intersect_is_the_greatest_lower_bound(
        (a, b, narrow) in intersect_chain_strategy(),
    ) {
        let merged = a.intersect(&b);
        prop_assert!(
            narrow.is_attenuation_of(&merged),
            "the narrowing is not an attenuation of the merge"
        );
        prop_assert!(
            narrow.is_attenuation_of(&a),
            "the narrowing is not an attenuation of the left side"
        );
        prop_assert!(
            narrow.is_attenuation_of(&b),
            "the narrowing is not an attenuation of the right side"
        );
    }
}

/// One receipt's random fields. The sequence is assigned in order and the
/// time is a cumulative sum of the deltas, so the generated log always
/// satisfies the append ordering rules (sequence continues exactly, time
/// never runs backwards, every stamp is far below the future horizon).
fn receipt_spec_strategy() -> impl Strategy<Value = (u64, String, u64, Decision, Option<[u8; 16]>)>
{
    (
        any::<u64>(),
        "[a-z][a-z0-9_]{0,12}",
        0u64..=1000,
        prop_oneof![
            Just(Decision::Admitted),
            Just(Decision::Refused("rpc/revoked".to_string())),
            Just(Decision::Refused("rpc/budget".to_string())),
            Just(Decision::Refused("rpc/denied".to_string())),
            Just(Decision::Refused("rpc/expired".to_string())),
            Just(Decision::Refused("rpc/not-found".to_string())),
        ],
        prop::option::of(any::<[u8; 16]>()),
    )
}

/// A temp dir that removes itself when the case ends, so 256 property cases
/// never leave 256 dirs behind on the machine.
struct ReceiptSandbox {
    dir: std::path::PathBuf,
}

impl ReceiptSandbox {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "active-rpc-property-receipts-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("sandbox");
        Self { dir }
    }
}

impl Drop for ReceiptSandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// A log of randomly decided receipts round-trips: `append_all`, then
    /// `records`, `verify_chain`, `verify_bytes` on the file, and a reopen
    /// all return exactly the receipts that were appended, in order, with
    /// the head pinned. The negative controls are part of the property, not
    /// an afterthought: a fabricated receipt (zero MAC) never verifies, the
    /// authenticated append path refuses the batch, `verify_macs` refuses
    /// the fabricated log, a byte flipped in the middle of the records
    /// region is refused, and a mis-sequenced or backwards-dated append is
    /// refused without changing the log.
    #[test]
    fn receipt_log_round_trips_random_decisions(
        specs in prop::collection::vec(receipt_spec_strategy(), 0..9),
    ) {
        let mut receipts = Vec::new();
        let mut at_ms = 0u64;
        for (index, (cap_seed, method, delta, decision, caller)) in
            specs.into_iter().enumerate()
        {
            at_ms += delta;
            receipts.push(Receipt {
                sequence: index as u64 + 1,
                cap: format!("{cap_seed:016x}"),
                method,
                at_ms,
                decision,
                mac: [0u8; 32],
                caller,
            });
        }
        let key = derive_receipt_key(&[0x5a; 32]);
        let sandbox = ReceiptSandbox::new();
        let path = sandbox.dir.join("receipts.arrl");
        let log = ReceiptLog::create(&path).expect("create");
        // A fabricated receipt never verifies, under any key: the MAC is
        // all zeros and nothing seals it.
        for receipt in &receipts {
            prop_assert!(!receipt.verify(&key), "a fabricated receipt verified");
        }
        // The authenticated append path refuses the fabricated batch before
        // writing anything.
        if !receipts.is_empty() {
            prop_assert!(
                log.append_verified(&key, &receipts).is_err(),
                "append_verified accepted fabricated MACs"
            );
            prop_assert_eq!(log.len().expect("len"), 0, "a refused append changed the log");
        }
        log.append_all(&receipts).expect("append");
        prop_assert_eq!(log.records().expect("records"), receipts.clone());
        log.verify_chain().expect("chain");
        prop_assert_eq!(log.len().expect("len"), receipts.len() as u64);
        prop_assert_eq!(log.start_sequence().expect("start"), 1);
        let head = log.head_hash().expect("head");
        if receipts.is_empty() {
            prop_assert_eq!(head, [0u8; 32], "an empty log has a non-zero head");
        } else {
            prop_assert_ne!(head, [0u8; 32], "a non-empty log has a zero head");
            // The MACs are fabricated, so the keyed verification must fail:
            // a `verify_macs` that passed here would be vacuous.
            prop_assert!(
                log.verify_macs(&key).is_err(),
                "verify_macs passed fabricated MACs"
            );
        }
        log.verify_against(head).expect("head pin");
        // The bytes on disk verify to the same receipts.
        let bytes = std::fs::read(log.path()).expect("read");
        prop_assert_eq!(
            ReceiptLog::verify_bytes(&bytes).expect("verify bytes"),
            receipts.clone()
        );
        // A fresh handle over the same file reads the same log.
        let reopened = ReceiptLog::open(&path).expect("reopen");
        prop_assert_eq!(reopened.records().expect("records"), receipts.clone());
        prop_assert_eq!(reopened.head_hash().expect("head"), head);
        // A byte flipped in the middle of the records region breaks the
        // chain: the round-trip above is content-sensitive, not just a
        // count check.
        if !receipts.is_empty() {
            let mut tampered = bytes.clone();
            let middle = LOG_HEADER_LEN + (tampered.len() - LOG_HEADER_LEN) / 2;
            tampered[middle] ^= 0x01;
            let error =
                ReceiptLog::verify_bytes(&tampered).expect_err("a tampered log must be refused");
            prop_assert_eq!(error.code(), "rpc/receipt");
        }
        // A mis-sequenced append and a backwards-dated append are both
        // refused, and neither changes the log. The backwards check needs a
        // last time above zero: when every generated delta is 0 the log's
        // last time is 0 and no earlier stamp exists, so it is skipped.
        let mut wrong = Receipt {
            sequence: receipts.len() as u64 + 2,
            cap: "0123456789abcdef".to_string(),
            method: "echo".to_string(),
            at_ms,
            decision: Decision::Admitted,
            mac: [0u8; 32],
            caller: None,
        };
        prop_assert!(
            log.append(&wrong).is_err(),
            "a mis-sequenced append was accepted"
        );
        if !receipts.is_empty() && at_ms > 0 {
            wrong.sequence = receipts.len() as u64 + 1;
            wrong.at_ms = at_ms - 1;
            prop_assert!(
                log.append(&wrong).is_err(),
                "a backwards-dated append was accepted"
            );
        }
        prop_assert_eq!(
            log.records().expect("records"),
            receipts,
            "a refused append changed the log"
        );
    }
}

/// A non-empty subset of `items`, chosen by a per-element include mask; an
/// all-false mask falls back to the full set, so the result is never empty.
fn subset_or_full(items: &[String], mask: &[bool]) -> BTreeSet<String> {
    let chosen: BTreeSet<String> = items
        .iter()
        .zip(mask.iter())
        .filter(|(_, keep)| **keep)
        .map(|(item, _)| item.clone())
        .collect();
    if chosen.is_empty() {
        items.iter().cloned().collect()
    } else {
        chosen
    }
}

/// A subset of `items`, possibly empty.
fn subset_of(items: &[String], mask: &[bool]) -> BTreeSet<String> {
    items
        .iter()
        .zip(mask.iter())
        .filter(|(_, keep)| **keep)
        .map(|(item, _)| item.clone())
        .collect()
}

/// A tool policy narrowed from `parent`: a subset of the allowed tools, a
/// byte ceiling no larger than the parent's, and process execution only when
/// the parent grants it.
fn narrowed_tool_strategy(parent: ToolPolicy) -> impl Strategy<Value = ToolPolicy> {
    let allowed: Vec<String> = parent.allowed.iter().cloned().collect();
    let allow_process = parent.allow_process;
    let count = allowed.len();
    (
        prop::collection::vec(any::<bool>(), count),
        0u64..=parent.max_arg_bytes,
        any::<bool>(),
    )
        .prop_map(move |(mask, max_arg_bytes, process)| ToolPolicy {
            allowed: subset_of(&allowed, &mask),
            max_arg_bytes,
            allow_process: allow_process && process,
        })
}

/// A capability narrowed from `parent`: every field moves only in the
/// narrowing direction `is_attenuation_of` defines — a non-empty subset of
/// the methods, a narrowed budget, read-only/redaction only added, a path
/// scope only deepened, topics only shrunk, the publish grant only dropped,
/// a tool policy only narrowed (against the parent's effective policy when
/// the parent carries none), durability only when the parent is durable, a
/// binding kept or dropped when the parent is bound, and a lifetime only
/// shortened.
fn narrowed_attrs_strategy(parent: CapAttrs) -> impl Strategy<Value = CapAttrs> {
    let methods: Vec<String> = parent.methods.iter().cloned().collect();
    let method_count = methods.len();
    let path: BoxedStrategy<Option<String>> = match &parent.path_scope {
        Some(scope) => {
            let scope = scope.clone();
            prop::option::of("[a-z]{1,6}")
                .prop_map(move |segment| match segment {
                    None => Some(scope.clone()),
                    Some(part) => Some(format!("{scope}.{part}")),
                })
                .boxed()
        }
        None => prop::option::of(("[a-z]{1,6}", prop::collection::vec("[a-z]{1,6}", 0..3)))
            .prop_map(|choice| {
                choice.map(|(head, tail)| {
                    let mut scope = head;
                    for part in tail {
                        scope.push('.');
                        scope.push_str(&part);
                    }
                    scope
                })
            })
            .boxed(),
    };
    let topics: BoxedStrategy<Option<BTreeSet<String>>> = match &parent.topics {
        Some(set) => {
            let items: Vec<String> = set.iter().cloned().collect();
            let count = items.len();
            prop::collection::vec(any::<bool>(), count)
                .prop_map(move |mask| Some(subset_of(&items, &mask)))
                .boxed()
        }
        None => prop::option::of(prop::collection::btree_set("[a-z]{1,6}", 0..3)).boxed(),
    };
    let tool: BoxedStrategy<Option<ToolPolicy>> = match &parent.tool_policy {
        Some(policy) => narrowed_tool_strategy(policy.clone())
            .prop_map(Some)
            .boxed(),
        None => {
            let effective = parent.effective_tool_policy();
            prop::option::of(narrowed_tool_strategy(effective)).boxed()
        }
    };
    let bound_to: BoxedStrategy<Option<[u8; 32]>> = match parent.bound_to {
        Some(peer) => prop::option::of(Just(peer)).boxed(),
        None => prop::option::of(any::<[u8; 32]>()).boxed(),
    };
    let ttl: BoxedStrategy<Option<u64>> = match parent.ttl_ms {
        Some(limit) => (1u64..=limit).prop_map(Some).boxed(),
        None => prop::option::of(1u64..10_000).boxed(),
    };
    let read_only = parent.read_only;
    let redact = parent.redact;
    let publish = parent.publish;
    let durable = parent.persistence == CapPersistence::Durable;
    (
        prop::collection::vec(any::<bool>(), method_count),
        narrowed_budget_strategy(parent.budget),
        any::<(bool, bool, bool, bool)>(),
        path,
        topics,
        tool,
        bound_to,
        ttl,
    )
        .prop_map(
            move |(
                mask,
                budget,
                (ro, red, pub_bit, dur_bit),
                path,
                topics,
                tool,
                bound_to,
                ttl,
            )| {
                CapAttrs {
                    methods: subset_or_full(&methods, &mask),
                    budget,
                    read_only: read_only || ro,
                    redact: redact || red,
                    path_scope: path,
                    topics,
                    publish: publish && pub_bit,
                    tool_policy: tool,
                    persistence: if durable && dur_bit {
                        CapPersistence::Durable
                    } else {
                        CapPersistence::Ephemeral
                    },
                    bound_to,
                    ttl_ms: ttl,
                }
            },
        )
}

/// A chain `child <= mid <= parent` of capabilities, each step narrowed from
/// the previous one, built on the existing `attrs_strategy()` generator.
fn attenuation_chain_strategy() -> impl Strategy<Value = (CapAttrs, CapAttrs, CapAttrs)> {
    attrs_strategy().prop_flat_map(|parent| {
        let root = parent.clone();
        narrowed_attrs_strategy(parent).prop_flat_map(move |mid| {
            let root = root.clone();
            let middle = mid.clone();
            narrowed_attrs_strategy(mid)
                .prop_map(move |child| (root.clone(), middle.clone(), child))
        })
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Attenuation composes through the operation: a two-step attenuation
    /// (`parent -> mid -> child`) and the one-step attenuation
    /// (`parent -> child`) agree on success — both accept, or both refuse —
    /// and when both accept they agree in every field except the identity
    /// binding, where the two-step result inherits the intermediate's
    /// binding when the child omits one (`one_step.or(mid)`) and the
    /// one-step result is unbound. That is the inheritance rule applied
    /// twice, not a divergence: the two-step result is never wider than
    /// the one-step result, and both are attenuations of the root.
    ///
    /// Deliberately NOT asserted: transitivity of the raw
    /// `CapAttrs::is_attenuation_of` predicate. It does not hold: a parent
    /// bound to peer P, an unbound middle, and a child bound to peer Q are
    /// pairwise monotone — the middle inherits P under `attenuate`, the
    /// child is free under an unbound middle — but the child is not an
    /// attenuation of the parent. The predicate models the merge, not a
    /// preorder (F1-NF-09); the composition law above is the property that
    /// does hold, and the chain premises guard the narrowing generator.
    #[test]
    fn attenuation_composes_through_the_operation(
        (parent, mid, child) in attenuation_chain_strategy(),
    ) {
        prop_assert!(mid.is_attenuation_of(&parent), "mid is not an attenuation of parent");
        prop_assert!(child.is_attenuation_of(&mid), "child is not an attenuation of mid");
        let first = parent.attenuate(mid.clone()).expect("mid attenuates");
        prop_assert!(
            first.is_attenuation_of(&parent),
            "the first step is not an attenuation of the root"
        );
        let two_step = first.attenuate(child.clone());
        let one_step = parent.attenuate(child);
        prop_assert_eq!(
            two_step.is_ok(),
            one_step.is_ok(),
            "two-step and one-step attenuation disagree on success"
        );
        if let (Ok(two), Ok(one)) = (two_step, one_step) {
            prop_assert!(
                two.is_attenuation_of(&parent),
                "the two-step result is not an attenuation of the root"
            );
            prop_assert!(
                one.is_attenuation_of(&parent),
                "the one-step result is not an attenuation of the root"
            );
            let one_bound = one.bound_to;
            let mut normalized = two.clone();
            normalized.bound_to = one_bound;
            prop_assert_eq!(
                normalized,
                one.clone(),
                "two-step and one-step results differ beyond the binding"
            );
            prop_assert_eq!(
                two.bound_to,
                one_bound.or(mid.bound_to),
                "the two-step binding is not the one-step binding inherited through the middle"
            );
        }
    }
}
