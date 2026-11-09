//! The budget's shape ceilings bind on every boundary a value crosses.
//!
//! `Budget::max_depth`, `max_array_len` and `max_value_size` are declared,
//! intersected and exported, so a grant can name them; before R-20 the kernel
//! never checked them, and an in-process caller could hand a provider a value
//! 10 000 levels deep under a grant that said "depth 2". A peer's value is
//! refused by `WireLimits` on ingress, which is why the gap was invisible from
//! the wire.
//!
//! Four boundaries are covered here, because a ceiling enforced on only one of
//! them is a ceiling a caller can go around: a call's arguments (queue time), a
//! promise's resolved value (dispatch time), a provider's response (egress), and
//! lane traffic (`send`, `publish`). The queue-time charge also covers the
//! envelope's non-argument bytes — the method name and any capability
//! descriptors or table delta (RPC-52) — so a peer cannot move a descriptor
//! table past a meter that only counted arguments.
//!
//! `max_value_size` is the materialised size of one value — the same number
//! `Value::wire_size` reports — so a list of ten thousand `Null` is 10 000 bytes
//! of payload and not "size 1".

use std::collections::{BTreeMap, BTreeSet};

use active_rpc::cap::{CapAttrs, CapId};
use active_rpc::channel::Direction;
use active_rpc::identity::PeerIdentity;
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::wire::{cap_table_hash, CapDescriptor, CapTableDelta, Envelope};
use active_rpc::{Agent, Budget};

/// A provider that answers `ping` with a fixed value and counts its calls.
struct Reply {
    calls: std::rc::Rc<std::cell::Cell<usize>>,
    reply: Value,
}

impl Provider for Reply {
    fn name(&self) -> &'static str {
        "reply"
    }

    fn methods(&self) -> Vec<String> {
        vec!["ping".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        self.calls.set(self.calls.get() + 1);
        Ok(Response::Value(self.reply.clone()))
    }
}

struct Fixture {
    agent: Agent,
    calls: std::rc::Rc<std::cell::Cell<usize>>,
    provider: active_rpc::ProviderId,
    cap: active_rpc::CapHandle,
    lane: active_rpc::LaneId,
}

fn fixture_with(budget: Budget, reply: Value) -> Fixture {
    fixture_parts(budget, budget, reply)
}

fn fixture_parts(cap_budget: Budget, lane_budget: Budget, reply: Value) -> Fixture {
    let agent = Agent::with_secret([0x6b; 32]);
    let calls = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let provider = agent.register(Box::new(Reply {
        calls: std::rc::Rc::clone(&calls),
        reply,
    }));
    let mut attrs = CapAttrs::new(&["ping"]);
    attrs.budget = cap_budget;
    let cap = agent.mint(provider, 0, attrs).expect("mint");
    let lane = agent.create_lane("shape", lane_budget).expect("lane");
    Fixture {
        agent,
        calls,
        provider,
        cap,
        lane,
    }
}

fn nested(depth: usize) -> Value {
    let mut value = Value::Int(1);
    for _ in 0..depth {
        value = Value::List(vec![value]);
    }
    value
}

fn budget() -> Budget {
    Budget {
        max_depth: 2,
        max_array_len: 3,
        max_value_size: 64,
        ..Budget::default()
    }
}

/// The refusal code, and the fact that the provider never ran.
fn refused(fixture: &Fixture, value: Value) -> String {
    let before = fixture.calls.get();
    let error = fixture
        .agent
        .call(fixture.lane, &fixture.cap, "ping", vec![Arg::Value(value)])
        .expect_err("the shape ceiling must bind");
    assert_eq!(
        fixture.calls.get(),
        before,
        "the provider ran for a value the grant refuses"
    );
    error.code().to_string()
}

fn admitted(fixture: &Fixture, value: Value) {
    let before = fixture.calls.get();
    let promise = fixture
        .agent
        .call(fixture.lane, &fixture.cap, "ping", vec![Arg::Value(value)])
        .expect("a value inside the budget is admitted");
    assert_eq!(promise.value().expect("value"), Value::text("ok"));
    assert_eq!(fixture.calls.get(), before + 1, "the provider ran once");
}

// --- queue time -----------------------------------------------------------

#[test]
fn a_value_deeper_than_max_depth_is_refused() {
    let fixture = fixture_with(budget(), Value::text("ok"));
    assert_eq!(refused(&fixture, nested(3)), "rpc/budget-exceeded");
}

#[test]
fn a_list_wider_than_max_array_len_is_refused() {
    let fixture = fixture_with(budget(), Value::text("ok"));
    let wide = Value::list((0..4).map(Value::Int));
    assert_eq!(refused(&fixture, wide), "rpc/budget-exceeded");
}

#[test]
fn a_value_larger_than_max_value_size_is_refused() {
    let fixture = fixture_with(budget(), Value::text("ok"));
    // 5 + 60 = 65 bytes of wire format.
    assert_eq!(
        refused(&fixture, Value::text("x".repeat(60))),
        "rpc/budget-exceeded"
    );
}

#[test]
fn a_list_of_scalars_over_max_value_size_is_refused() {
    // The review's case: `max_value_size: 8` is not satisfied by a list of five
    // hundred bytes' worth of scalars just because each scale is small.
    let fixture = fixture_with(
        Budget {
            max_value_size: 8,
            ..budget()
        },
        Value::text("ok"),
    );
    let many = Value::list((0..200).map(|_| Value::Null));
    assert_eq!(refused(&fixture, many), "rpc/budget-exceeded");
}

#[test]
fn a_map_key_counts_towards_max_value_size() {
    // A key is payload too: it arrives on the wire and reaches the provider.
    let fixture = fixture_with(budget(), Value::text("ok"));
    let mut entries = BTreeMap::new();
    entries.insert("x".repeat(60), Value::Int(1));
    assert_eq!(
        refused(&fixture, Value::Map(entries)),
        "rpc/budget-exceeded"
    );
}

#[test]
fn a_narrow_lane_cannot_mass_transfer_capabilities() {
    // One message carries at most `MAX_CAPS_PER_MESSAGE` handles. The ceiling is
    // a fixed kernel bound, so a lane whose budget is narrow still cannot sweep
    // the registry in a single send.
    let fixture = fixture_parts(Budget::default(), Budget::calls(1), Value::text("ok"));
    let channel = fixture
        .agent
        .create_channel("caps", Direction::Both)
        .expect("channel");
    let mut caps = Vec::new();
    for _ in 0..=1024 {
        caps.push(
            fixture
                .agent
                .attenuate(&fixture.cap, CapAttrs::new(&["ping"]))
                .expect("attenuated child"),
        );
    }
    let error = fixture
        .agent
        .send(fixture.lane, channel, Value::text("sweep"), &caps)
        .expect_err("a message beyond the cap ceiling is refused");
    assert_eq!(error.code(), "rpc/budget-exceeded");
    assert!(
        error.to_string().contains("caps per message"),
        "unexpected refusal: {error}"
    );
}

#[test]
fn lane_attenuation_after_queue_binds_dispatched_promise() {
    // A call is authorized at queue time and dispatched later. Narrowing the
    // lane in between must bind the dispatch: the grant the provider runs under
    // is the capability's budget intersected with the lane's current one.
    let fixture = fixture_with(Budget::default(), Value::text("ok"));
    let wide = Value::list((0..8).map(Value::Int));
    let promise = fixture
        .agent
        .call(fixture.lane, &fixture.cap, "ping", vec![Arg::Value(wide)])
        .expect("a value inside the wide lane is queued");
    fixture
        .agent
        .attenuate_lane(
            fixture.lane,
            Budget {
                max_array_len: 3,
                ..Budget::default()
            },
        )
        .expect("attenuate the lane");
    let error = promise
        .value()
        .expect_err("the narrowed lane must bind the queued call");
    assert_eq!(error.code(), "rpc/budget-exceeded");
    assert_eq!(
        fixture.calls.get(),
        0,
        "the provider ran under a grant the lane no longer allows"
    );
}

#[test]
fn a_million_wide_list_is_refused_without_a_full_walk() {
    // Measuring the whole value before comparing it to the ceilings made the
    // refusal cost the value's real size. A hostile in-process caller can build
    // a list of a million elements under a grant of three, so the check must
    // stop at the first violation. Both halves are timed in the same process,
    // which makes the assertion about the walk rather than about the machine.
    let wide = Value::list((0..1_000_000).map(|_| Value::Null));

    let mut full_walk = u128::MAX;
    for _ in 0..3 {
        let start = std::time::Instant::now();
        assert_eq!(wide.shape().widest, 1_000_000);
        full_walk = full_walk.min(start.elapsed().as_nanos());
    }

    let mut bounded = u128::MAX;
    for _ in 0..3 {
        let start = std::time::Instant::now();
        assert_eq!(wide.shape_exceeded(&budget()), Some("array_len"));
        bounded = bounded.min(start.elapsed().as_nanos());
    }

    assert!(
        bounded.saturating_mul(10) < full_walk,
        "the bounded check ({bounded} ns) walked the whole value ({full_walk} ns)"
    );

    // And the kernel takes that path: the same value is refused, and the
    // provider never runs.
    let fixture = fixture_with(budget(), Value::text("ok"));
    assert_eq!(refused(&fixture, wide), "rpc/budget-exceeded");
}

#[test]
fn a_nested_accumulator_over_the_size_ceiling_is_refused_early() {
    // Round 4: the size ceiling was compared only when a container folded into
    // its parent, so a list of a million 32-byte texts under a 1 KiB ceiling was
    // walked in full first. A container's accumulator only grows, so it is
    // refused as soon as it passes the ceiling.
    let budget = Budget {
        max_array_len: 2_000_000,
        max_value_size: 1_024,
        ..Budget::default()
    };
    let wide = Value::list((0..1_000_000).map(|_| Value::text("x".repeat(32))));

    let mut full_walk = u128::MAX;
    for _ in 0..3 {
        let start = std::time::Instant::now();
        assert!(wide.shape().size > 1_024);
        full_walk = full_walk.min(start.elapsed().as_nanos());
    }

    let mut bounded = u128::MAX;
    for _ in 0..3 {
        let start = std::time::Instant::now();
        assert_eq!(wide.shape_exceeded(&budget), Some("value_size"));
        bounded = bounded.min(start.elapsed().as_nanos());
    }

    assert!(
        bounded.saturating_mul(10) < full_walk,
        "the bounded check ({bounded} ns) walked the whole value ({full_walk} ns)"
    );
}

#[test]
fn a_violation_in_the_first_element_is_found_without_walking_the_rest() {
    // Round 4: every child of a container was pushed before any was visited and
    // the stack popped last-first, so a violation in element 0 was the last
    // thing checked. The walk now visits elements in order, one frame per open
    // container.
    let budget = Budget {
        max_depth: 2,
        max_array_len: 2_000_000,
        ..Budget::default()
    };
    let mut items = vec![nested(5)];
    items.extend((0..1_000_000).map(|_| Value::Null));
    let wide = Value::list(items);

    let mut full_walk = u128::MAX;
    for _ in 0..3 {
        let start = std::time::Instant::now();
        assert_eq!(wide.shape().depth, 6);
        full_walk = full_walk.min(start.elapsed().as_nanos());
    }

    let mut bounded = u128::MAX;
    for _ in 0..3 {
        let start = std::time::Instant::now();
        assert_eq!(wide.shape_exceeded(&budget), Some("depth"));
        bounded = bounded.min(start.elapsed().as_nanos());
    }

    assert!(
        bounded.saturating_mul(10) < full_walk,
        "the bounded check ({bounded} ns) walked the whole value ({full_walk} ns)"
    );
}

#[test]
fn a_list_of_small_lists_is_refused_by_the_parent_ceiling() {
    // Round 5 (N1): a child only counted against its parent when the parent
    // folded, and that fold skipped the ceiling check, so a list of a hundred
    // thousand one-element lists was built in full before the root refused.
    let budget = Budget {
        max_array_len: 200_000,
        max_value_size: 1_024,
        ..Budget::default()
    };
    let nested_lists = Value::list(
        (0..100_000).map(|_| Value::list(std::iter::once(Value::text("x".repeat(32))))),
    );

    let mut full_walk = u128::MAX;
    for _ in 0..3 {
        let start = std::time::Instant::now();
        assert!(nested_lists.shape().size > 1_024);
        full_walk = full_walk.min(start.elapsed().as_nanos());
    }

    let mut bounded = u128::MAX;
    for _ in 0..3 {
        let start = std::time::Instant::now();
        assert_eq!(nested_lists.shape_exceeded(&budget), Some("value_size"));
        bounded = bounded.min(start.elapsed().as_nanos());
    }

    assert!(
        bounded.saturating_mul(10) < full_walk,
        "the bounded check ({bounded} ns) walked the whole value ({full_walk} ns)"
    );
}

#[test]
fn a_hostile_value_is_refused_before_the_kernel_measures_it() {
    // Round 5 (N2): the queue path measured the arguments with `wire_size()`
    // (a full walk) before the shape gate, and the path-scope walk ran first
    // too. The gate now comes before every traversal, so the refusal costs the
    // ceiling and the provider never sees the call.
    let fixture = fixture_with(budget(), Value::text("ok"));
    // Three independent values, built outside the measurements: a `Value` clone
    // is itself a full walk, and it would hide the kernel's own cost.
    let wide: Vec<Value> = (0..3)
        .map(|_| Value::list((0..500_000).map(|_| Value::Null)))
        .collect();

    let mut full_walk = u128::MAX;
    for _ in 0..3 {
        let start = std::time::Instant::now();
        assert_eq!(wide[0].shape().widest, 500_000);
        full_walk = full_walk.min(start.elapsed().as_nanos());
    }

    let mut refused_at = u128::MAX;
    for value in wide {
        let start = std::time::Instant::now();
        let code = refused(&fixture, value);
        refused_at = refused_at.min(start.elapsed().as_nanos());
        assert_eq!(code, "rpc/budget-exceeded");
    }

    // The refusal also drops the value it was handed, and dropping a list is
    // linear, so the comparison is against a walk that costs far more per
    // element (3x headroom against ~10x measured). The round-4 order measured
    // the value in full first, which put the refusal at or above `full_walk`.
    assert!(
        refused_at.saturating_mul(3) < full_walk,
        "the refusal ({refused_at} ns) measured the whole value ({full_walk} ns)"
    );
    assert_eq!(fixture.calls.get(), 0);
}

#[test]
fn an_idempotent_call_refuses_a_hostile_value_before_hashing_it() {
    // Round 5 (N3): the idempotency fingerprint hashed the whole value before
    // any shape check, so the key path had the same unbounded first walk.
    let fixture = fixture_with(budget(), Value::text("ok"));
    let wide: Vec<Value> = (0..3)
        .map(|_| Value::list((0..500_000).map(|_| Value::Null)))
        .collect();

    let mut full_walk = u128::MAX;
    for _ in 0..3 {
        let start = std::time::Instant::now();
        assert_eq!(wide[0].shape().widest, 500_000);
        full_walk = full_walk.min(start.elapsed().as_nanos());
    }

    let mut refused_at = u128::MAX;
    for (index, value) in wide.into_iter().enumerate() {
        let key = format!("hostile-{index}");
        let start = std::time::Instant::now();
        let error = fixture
            .agent
            .call_idempotent(
                fixture.lane,
                &fixture.cap,
                "ping",
                vec![Arg::Value(value)],
                &key,
            )
            .expect_err("the shape ceiling binds on the keyed path too");
        refused_at = refused_at.min(start.elapsed().as_nanos());
        assert_eq!(error.code(), "rpc/budget-exceeded");
    }

    assert!(
        refused_at.saturating_mul(3) < full_walk,
        "the refusal ({refused_at} ns) hashed the whole value ({full_walk} ns)"
    );
    assert_eq!(fixture.calls.get(), 0);
}

#[test]
fn a_hostile_publish_is_refused_before_the_kernel_measures_it() {
    // Round 6 (#1): publish measured the payload with `wire_size` before the
    // shape gate, the same order the call path had already fixed.
    let fixture = fixture_with(budget(), Value::text("ok"));
    let channel = fixture
        .agent
        .create_channel("gate", Direction::Both)
        .expect("channel");
    let publisher = fixture
        .agent
        .mint(
            fixture.provider,
            0,
            CapAttrs::new(&["ping", "publish"]).restrict_topics(&["t"]),
        )
        .expect("publisher");
    let wide: Vec<Value> = (0..3)
        .map(|_| Value::list((0..500_000).map(|_| Value::Null)))
        .collect();

    let mut full_walk = u128::MAX;
    for _ in 0..3 {
        let start = std::time::Instant::now();
        assert_eq!(wide[0].shape().widest, 500_000);
        full_walk = full_walk.min(start.elapsed().as_nanos());
    }

    let mut refused_at = u128::MAX;
    for value in wide {
        let start = std::time::Instant::now();
        let error = fixture
            .agent
            .publish(fixture.lane, channel, &publisher, "t", value)
            .expect_err("the shape ceiling binds on publish");
        refused_at = refused_at.min(start.elapsed().as_nanos());
        assert_eq!(error.code(), "rpc/budget-exceeded");
    }

    assert!(
        refused_at.saturating_mul(3) < full_walk,
        "the refusal ({refused_at} ns) measured the whole payload ({full_walk} ns)"
    );
}

#[test]
fn the_idempotent_gate_uses_the_lane_intersection() {
    // Round 6 (#4): the keyed path gated on the capability budget alone, so a
    // value the lane refuses was hashed first.
    let fixture = fixture_parts(
        Budget::default(),
        Budget {
            max_value_size: 1_024,
            ..Budget::default()
        },
        Value::text("ok"),
    );
    let value = Value::text("x".repeat(4_096));
    let error = fixture
        .agent
        .call_idempotent(
            fixture.lane,
            &fixture.cap,
            "ping",
            vec![Arg::Value(value)],
            "lane-gate",
        )
        .expect_err("the lane ceiling binds on the keyed path");
    assert_eq!(error.code(), "rpc/budget-exceeded");
    assert_eq!(fixture.calls.get(), 0);
}

#[test]
fn an_oversized_method_name_is_refused_before_it_is_copied() {
    // Round 6 (#6): a method that cannot be granted was still cloned into the
    // refusal, so its length was unbounded work outside every budget.
    let fixture = fixture_with(budget(), Value::text("ok"));
    let error = fixture
        .agent
        .call(fixture.lane, &fixture.cap, &"m".repeat(2_048), Vec::new())
        .expect_err("a method longer than a grant cannot be called");
    assert_eq!(error.code(), "rpc/invalid-argument");
}

#[test]
fn a_deep_path_nest_is_walked_iteratively() {
    // Round 6 (#3): the path-scope walk recursed, so a deep value could abort
    // the process in the check that exists to refuse it. Fifty levels is half
    // the absolute wire ceiling (the kernel refuses anything deeper before this
    // walk), and enough to exercise the explicit stack.
    let mut value = Value::path("secret/leaf");
    for _ in 0..50 {
        value = Value::list(std::iter::once(value));
    }
    let mut fixture = fixture_parts(
        Budget {
            max_depth: 3_000,
            max_value_size: 10_000_000,
            ..Budget::default()
        },
        Budget {
            max_depth: 3_000,
            max_value_size: 10_000_000,
            ..Budget::default()
        },
        Value::text("ok"),
    );
    let wide = Budget {
        max_depth: 3_000,
        max_value_size: 10_000_000,
        ..Budget::default()
    };
    fixture.cap = fixture
        .agent
        .attenuate(
            &fixture.cap,
            CapAttrs::new(&["ping"])
                .with_budget(wide)
                .with_path("allowed"),
        )
        .expect("scoped cap");
    assert_eq!(refused(&fixture, value), "rpc/path-not-granted");
}

#[test]
fn an_out_of_band_resolve_is_bound_by_the_grant() {
    // Round 7 (F1): `resolve` stored any value with no shape or byte check,
    // which was a hole through every budget the call path enforces.
    let fixture = fixture_with(budget(), Value::text("ok"));
    let promise = fixture
        .agent
        .call(fixture.lane, &fixture.cap, "ping", Vec::new())
        .expect("queued");
    let error = fixture
        .agent
        .resolve(&promise, Value::text("x".repeat(100)))
        .expect_err("the size ceiling binds an out-of-band answer too");
    assert_eq!(error.code(), "rpc/budget-exceeded");
    assert!(
        !promise.is_settled(),
        "a refused resolve settled the promise"
    );
}

#[test]
fn a_deep_resolved_value_is_refused_before_the_dispatch_clone() {
    // Round 7 (F2): dispatch cloned a resolved value before any gate, and
    // `Value::clone` recurses.
    let fixture = fixture_with(Budget::default(), Value::text("ok"));
    let pending = fixture
        .agent
        .call(fixture.lane, &fixture.cap, "ping", Vec::new())
        .expect("queued");
    let _dependent = fixture
        .agent
        .call(
            fixture.lane,
            &fixture.cap,
            "ping",
            vec![Arg::Promise(pending.id())],
        )
        .expect("dependent");
    // Inside the capability's depth ceiling (256) but past the wire's 64: the
    // resolve gate refuses it, so the dispatch never sees such a value.
    let error = fixture
        .agent
        .resolve(&pending, nested(100))
        .expect_err("the absolute wire ceiling binds an out-of-band answer");
    assert_eq!(error.code(), "rpc/budget-exceeded");
    assert!(!pending.is_settled());
}

#[test]
fn an_idempotent_call_bounds_its_method_before_copying_it() {
    // Round 7 (F3): the key map held a copy of the method before any bound.
    let fixture = fixture_with(budget(), Value::text("ok"));
    let error = fixture
        .agent
        .call_idempotent(
            fixture.lane,
            &fixture.cap,
            &"m".repeat(2_048),
            Vec::new(),
            "method-bound",
        )
        .expect_err("a method longer than a grant cannot be called");
    assert_eq!(error.code(), "rpc/invalid-argument");
}

#[test]
fn an_unbounded_argument_list_is_refused_before_any_walk() {
    // Round 7 (F4): the wire caps a message at 4 096 arguments; an in-process
    // caller could hand the kernel a vector of any length.
    let fixture = fixture_with(budget(), Value::text("ok"));
    let args: Vec<Arg> = (0..5_000).map(|_| Arg::Value(Value::Null)).collect();
    let error = fixture
        .agent
        .call(fixture.lane, &fixture.cap, "ping", args)
        .expect_err("the argument ceiling binds an in-process call");
    assert_eq!(error.code(), "rpc/budget-exceeded");
    assert_eq!(fixture.calls.get(), 0);
}

#[test]
fn a_value_queued_under_a_wide_lane_is_gated_after_attenuation() {
    // Round 8 (#1): dispatch cloned the queued arguments before any gate, so a
    // value queued under a wide lane and then narrowed was copied first.
    let fixture = fixture_with(Budget::default(), Value::text("ok"));
    let wide = Value::list((0..64).map(Value::Int));
    let promise = fixture
        .agent
        .call(fixture.lane, &fixture.cap, "ping", vec![Arg::Value(wide)])
        .expect("queued under the wide lane");
    fixture
        .agent
        .attenuate_lane(
            fixture.lane,
            Budget {
                max_array_len: 3,
                ..Budget::default()
            },
        )
        .expect("attenuate");
    let error = promise
        .value()
        .expect_err("the narrowed lane binds the queued value");
    assert_eq!(error.code(), "rpc/budget-exceeded");
    assert_eq!(fixture.calls.get(), 0);
}

#[test]
fn an_out_of_band_resolve_rechecks_the_authority() {
    // Round 8 (#2): resolve settled a promise whose capability was revoked or
    // whose lane was gone, while dispatch refuses both.
    let revoked = fixture_with(Budget::default(), Value::text("ok"));
    let promise = revoked
        .agent
        .call(revoked.lane, &revoked.cap, "ping", Vec::new())
        .expect("queued");
    revoked.agent.revoke(&revoked.cap).expect("revoke");
    let error = revoked
        .agent
        .resolve(&promise, Value::Int(1))
        .expect_err("a revoked capability cannot answer out of band");
    assert_eq!(error.code(), "rpc/revoked");

    let gone = fixture_with(Budget::default(), Value::text("ok"));
    let promise = gone
        .agent
        .call(gone.lane, &gone.cap, "ping", Vec::new())
        .expect("queued");
    gone.agent.destroy_lane(gone.lane).expect("destroy");
    let error = gone
        .agent
        .resolve(&promise, Value::Int(1))
        .expect_err("a destroyed lane cannot answer out of band");
    // `destroy_lane` already rejected the queued job, so the answer cannot
    // replace it; the lane check itself covers a job that is still running.
    assert_eq!(error.code(), "rpc/promise-resolved");
}

#[test]
fn an_idempotent_body_is_fingerprinted_by_content() {
    // Round 8 (#8): the keyed entry with a payload size could not tell two
    // same-length bodies apart; the body-aware entry hashes the content.
    let fixture = fixture_with(Budget::default(), Value::text("ok"));
    let first = fixture
        .agent
        .call_idempotent_as_with_body(
            None,
            fixture.lane,
            &fixture.cap,
            "ping",
            Vec::new(),
            b"body-a",
            "body-key",
        )
        .expect("first body");
    fixture.agent.run();
    first.value().expect("value");
    let error = fixture
        .agent
        .call_idempotent_as_with_body(
            None,
            fixture.lane,
            &fixture.cap,
            "ping",
            Vec::new(),
            b"body-b",
            "body-key",
        )
        .expect_err("a different body under the same key is a different call");
    assert_eq!(error.code(), "rpc/invalid-argument");
}

#[test]
fn a_deep_queued_value_is_refused_before_the_dispatch_clone() {
    // Round 9 (F1): the queue-time gate is budget-relative, and a lane may allow
    // a depth that the derived `Clone` cannot survive. The absolute wire ceiling
    // binds the queued path too.
    let fixture = fixture_parts(
        Budget {
            max_depth: 100_000,
            max_value_size: 10_000_000,
            ..Budget::default()
        },
        Budget {
            max_depth: 100_000,
            max_value_size: 10_000_000,
            ..Budget::default()
        },
        Value::text("ok"),
    );
    let error = fixture
        .agent
        .call(
            fixture.lane,
            &fixture.cap,
            "ping",
            vec![Arg::Value(nested(2_000))],
        )
        .expect_err("a value deeper than the wire allows is refused at the queue");
    assert_eq!(error.code(), "rpc/budget-exceeded");
    assert_eq!(fixture.calls.get(), 0);
}

#[test]
fn a_bound_capability_needs_its_peer_to_resolve() {
    // Round 9 (F2): `resolve` had no peer, so it settled a call dispatch would
    // have refused for the wrong identity.
    let agent = Agent::with_secret([0x81; 32]);
    let provider = agent.register(Box::new(Reply {
        calls: std::rc::Rc::new(std::cell::Cell::new(0)),
        reply: Value::text("ok"),
    }));
    let owner = active_rpc::identity::IdentityPolicy::default()
        .admit(
            Some(&active_rpc::identity::PeerIdentity::from_certificate(
                b"owner",
            )),
            true,
        )
        .expect("admit");
    let cap = agent
        .mint_bound(&owner, provider, 0, CapAttrs::new(&["ping"]))
        .expect("bound cap");
    let lane = agent.create_lane("bound", Budget::default()).expect("lane");
    let promise = agent
        .call_as(Some(owner.identity()), lane, &cap, "ping", Vec::new())
        .expect("queued by the bound peer");
    let error = agent
        .resolve(&promise, Value::Int(1))
        .expect_err("a bound capability cannot be answered anonymously");
    assert_eq!(error.code(), "rpc/identity");
    agent
        .resolve_as(Some(owner.identity()), &promise, Value::Int(1))
        .expect("the bound peer can answer");
    assert_eq!(promise.value().expect("settled"), Value::Int(1));
}

#[test]
fn a_wall_clock_expiry_binds_an_out_of_band_resolve() {
    // Round 9 (F3): resolve compared against a stale clock in wall-clock mode.
    let agent = Agent::with_secret([0x82; 32]);
    agent.use_wall_clock(true);
    let provider = agent.register(Box::new(Reply {
        calls: std::rc::Rc::new(std::cell::Cell::new(0)),
        reply: Value::text("ok"),
    }));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["ping"]).with_ttl_ms(30))
        .expect("cap");
    let lane = agent.create_lane("ttl", Budget::default()).expect("lane");
    let promise = agent.call(lane, &cap, "ping", Vec::new()).expect("queued");
    std::thread::sleep(std::time::Duration::from_millis(80));
    let error = agent
        .resolve(&promise, Value::Int(1))
        .expect_err("the ttl elapsed");
    assert_eq!(error.code(), "rpc/revoked");
}

#[test]
fn an_idempotent_body_reaches_the_provider() {
    // Round 9 (F4): the body-aware entry charged for the body but delivered an
    // empty payload on the miss path.
    struct PayloadLen;

    impl Provider for PayloadLen {
        fn name(&self) -> &'static str {
            "payload-len"
        }

        fn methods(&self) -> Vec<String> {
            vec!["len".to_string()]
        }

        fn mutating(&self, _method: &str) -> bool {
            false
        }

        fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
            Ok(Response::Value(Value::Int(call.payload.len() as i64)))
        }
    }

    let agent = Agent::with_secret([0x83; 32]);
    let provider = agent.register(Box::new(PayloadLen));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["len"]))
        .expect("cap");
    let lane = agent.create_lane("body", Budget::default()).expect("lane");
    let promise = agent
        .call_idempotent_as_with_body(
            None,
            lane,
            &cap,
            "len",
            Vec::new(),
            b"payload-body",
            "body-delivery",
        )
        .expect("queued");
    agent.run();
    assert_eq!(
        promise.value().expect("value"),
        Value::Int(12),
        "the provider did not receive the body the call was charged for"
    );
}

#[test]
fn a_promise_handle_names_its_own_kernel() {
    // Round 3 (F1): promise ids are a per-kernel counter, so a handle from one
    // agent that named the same id in another read, cancelled or answered the
    // other tenant's call.
    let first = fixture_with(Budget::default(), Value::text("first"));
    let second = fixture_with(Budget::default(), Value::text("second"));
    let promise = first
        .agent
        .call(first.lane, &first.cap, "ping", Vec::new())
        .expect("queued");
    assert_eq!(
        second
            .agent
            .await_promise(&promise)
            .expect_err("a foreign handle cannot be awaited")
            .code(),
        "rpc/unknown-promise"
    );
    assert_eq!(
        second
            .agent
            .resolve(&promise, Value::text("forged"))
            .expect_err("a foreign handle cannot be answered")
            .code(),
        "rpc/unknown-promise"
    );
    assert_eq!(
        second
            .agent
            .cancel(&promise)
            .expect_err("a foreign handle cannot be cancelled")
            .code(),
        "rpc/unknown-promise"
    );
    assert_eq!(
        second
            .agent
            .resolve_as(None, &promise, Value::text("forged"))
            .expect_err("a foreign handle cannot be answered with a peer")
            .code(),
        "rpc/unknown-promise"
    );
    first.agent.run();
    assert_eq!(promise.value().expect("own kernel"), Value::text("first"));
}

#[test]
fn an_out_of_band_answer_obeys_the_egress_policy() {
    // Round 10 (#1): resolve stored a secret-bearing module and skipped the
    // redaction policy dispatch applies.
    use active_infinity::{encode, InfinityModule, Inode};

    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(active_infinity::SecretBytes::new(b"canary")));
    let key = module.push(Inode::Str("password".to_string()));
    let root = module.push(Inode::Table {
        fields: vec![("k".to_string(), key), ("v".to_string(), secret)],
    });
    module.set_root(Some(root));
    let bytes = encode(&module).expect("encode");

    let fixture = fixture_with(Budget::default(), Value::text("ok"));
    let promise = fixture
        .agent
        .call(fixture.lane, &fixture.cap, "ping", Vec::new())
        .expect("queued");
    let error = fixture
        .agent
        .resolve(&promise, Value::Module(bytes))
        .expect_err("a secret-bearing module is refused");
    assert_eq!(error.code(), "rpc/provider");
    assert!(!promise.is_settled());
}

#[test]
fn a_cached_replay_obeys_the_narrowed_lane() {
    // Round 10 (#3): the hit path returned a cached value the lane would now
    // refuse, with no charge.
    let fixture = fixture_with(Budget::default(), Value::text("ok"));
    let args = vec![Arg::Value(Value::list((0..64).map(Value::Int)))];
    let first = fixture
        .agent
        .call_idempotent(fixture.lane, &fixture.cap, "ping", args, "narrowed")
        .expect("queued");
    fixture.agent.run();
    first.value().expect("value");
    fixture
        .agent
        .attenuate_lane(
            fixture.lane,
            Budget {
                max_array_len: 3,
                ..Budget::default()
            },
        )
        .expect("attenuate");
    let error = fixture
        .agent
        .call_idempotent(
            fixture.lane,
            &fixture.cap,
            "ping",
            vec![Arg::Value(Value::list((0..64).map(Value::Int)))],
            "narrowed",
        )
        .expect_err("a replay is held to the current grant");
    assert_eq!(error.code(), "rpc/budget-exceeded");
}

#[test]
fn a_provider_answer_deeper_than_the_wire_is_a_budget_refusal() {
    // Round 10 (#4): the same condition was a generic provider fault on one
    // side and a budget refusal on the other, so the dimension and the
    // `budget.exhausted` event were lost.
    struct DeepReply;

    impl Provider for DeepReply {
        fn name(&self) -> &'static str {
            "deep"
        }

        fn methods(&self) -> Vec<String> {
            vec!["go".to_string()]
        }

        fn mutating(&self, _method: &str) -> bool {
            false
        }

        fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
            let mut value = Value::Int(1);
            for _ in 0..200 {
                value = Value::list(std::iter::once(value));
            }
            Ok(Response::Value(value))
        }
    }

    let agent = Agent::with_secret([0x84; 32]);
    let provider = agent.register(Box::new(DeepReply));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["go"]))
        .expect("cap");
    let lane = agent
        .create_lane("deep-answer", Budget::default())
        .expect("lane");
    let promise = agent.call(lane, &cap, "go", Vec::new()).expect("queued");
    let error = promise.value().expect_err("the answer is too deep");
    assert_eq!(error.code(), "rpc/budget-exceeded");
}

#[test]
fn a_module_larger_than_max_value_size_is_refused() {
    let fixture = fixture_with(budget(), Value::text("ok"));
    assert_eq!(
        refused(&fixture, Value::Module(vec![0u8; 60])),
        "rpc/budget-exceeded"
    );
}

#[test]
fn a_value_exactly_at_every_ceiling_is_admitted() {
    // Off-by-one guard: `depth 2`, a list of 3 and a 59-byte text (5 + 59 = 64)
    // are the largest admitted at this grant.
    let depth_fixture = fixture_with(budget(), Value::text("ok"));
    admitted(&depth_fixture, nested(2));

    let wide_fixture = fixture_with(budget(), Value::text("ok"));
    admitted(
        &wide_fixture,
        Value::list((0..3).map(|index| Value::Int(i64::from(index)))),
    );

    let size_fixture = fixture_with(budget(), Value::text("ok"));
    admitted(&size_fixture, Value::text("x".repeat(59)));
}

#[test]
fn a_deep_value_is_refused_without_a_recursive_walk() {
    // Deeper than the grant by an order of magnitude. The value is built and
    // dropped by derived `Clone`/`Drop`, which recurse, so this test stays at a
    // depth those survive; the kernel's own walk is iterative, so it adds no
    // frame per level (a value from a peer is bounded by `MAX_VALUE_DEPTH`).
    let deep_fixture = fixture_with(
        Budget {
            max_depth: 64,
            max_bytes: u64::MAX / 2,
            ..Budget::default()
        },
        Value::text("ok"),
    );
    assert_eq!(refused(&deep_fixture, nested(512)), "rpc/budget-exceeded");
}

#[test]
fn nested_ceilings_apply_at_any_level() {
    // The wide list is two levels down, under a scalar: a check that only looks
    // at the top level would admit it.
    let nested_fixture = fixture_with(budget(), Value::text("ok"));
    let deep_and_wide = Value::List(vec![Value::List(vec![Value::list((0..4).map(Value::Int))])]);
    assert_eq!(
        refused(&nested_fixture, deep_and_wide),
        "rpc/budget-exceeded"
    );
}

#[test]
fn the_default_grant_admits_ordinary_values() {
    let default_fixture = fixture_with(Budget::default(), Value::text("ok"));
    admitted(&default_fixture, nested(3));
    admitted(&default_fixture, Value::list((0..100).map(Value::Int)));
    admitted(&default_fixture, Value::Module(vec![0u8; 1024]));
}

#[test]
fn a_secret_marker_is_not_measured() {
    // The size of a secret is not read: that would be an oracle. A marker is
    // one byte of wire format, so it satisfies even a one-byte ceiling — on the
    // way in and on the way out.
    let secret_fixture = fixture_with(
        Budget {
            max_value_size: 1,
            ..budget()
        },
        Value::Secret,
    );
    let promise = secret_fixture
        .agent
        .call(
            secret_fixture.lane,
            &secret_fixture.cap,
            "ping",
            vec![Arg::Value(Value::Secret)],
        )
        .expect("a marker is not measured");
    assert_eq!(promise.value().expect("value"), Value::Secret);
}

// --- dispatch time (a promise's value) ------------------------------------

#[test]
fn a_promise_argument_is_measured_when_it_resolves() {
    // The bypass the review found: a wide value produced through a permissive
    // capability, consumed through a narrow one with `Arg::Promise`. Queue time
    // sees a placeholder, so the check has to run again at dispatch.
    let agent = Agent::with_secret([0x7c; 32]);
    let calls = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let wide = Value::list((0..100).map(Value::Int));
    let provider = agent.register(Box::new(Reply {
        calls: std::rc::Rc::clone(&calls),
        reply: wide,
    }));
    let mut wide_attrs = CapAttrs::new(&["ping"]);
    wide_attrs.budget = Budget::default();
    let wide_cap = agent.mint(provider, 0, wide_attrs).expect("wide mint");
    let mut narrow_attrs = CapAttrs::new(&["ping"]);
    narrow_attrs.budget = budget();
    let narrow_cap = agent.mint(provider, 0, narrow_attrs).expect("narrow mint");
    let lane = agent
        .create_lane("promise", Budget::default())
        .expect("lane");

    let produced = agent
        .call(lane, &wide_cap, "ping", vec![])
        .expect("the wide grant admits its own response");
    agent.run();
    assert!(produced.value().expect("value").wire_size() > 64);

    let consumed = agent
        .call(lane, &narrow_cap, "ping", vec![Arg::Promise(produced.id())])
        .expect("queued: the placeholder is not the value");
    let error = consumed
        .value()
        .expect_err("the resolved value must be refused");
    assert_eq!(error.code(), "rpc/budget-exceeded");
}

// --- egress ---------------------------------------------------------------

#[test]
fn a_response_wider_than_the_grant_is_refused() {
    let fixture = fixture_with(budget(), Value::list((0..4).map(Value::Int)));
    let error = fixture
        .agent
        .call(fixture.lane, &fixture.cap, "ping", vec![])
        .expect("queued")
        .value()
        .expect_err("a response outside the grant must not settle");
    assert_eq!(error.code(), "rpc/budget-exceeded");
}

#[test]
fn a_response_deeper_than_the_grant_is_refused() {
    let fixture = fixture_with(budget(), nested(3));
    let error = fixture
        .agent
        .call(fixture.lane, &fixture.cap, "ping", vec![])
        .expect("queued")
        .value()
        .expect_err("a deep response must not settle");
    assert_eq!(error.code(), "rpc/budget-exceeded");
}

// --- lane traffic ---------------------------------------------------------

#[test]
fn a_send_over_the_lane_shape_ceilings_is_refused() {
    let fixture = fixture_with(Budget::default(), Value::text("ok"));
    let narrow = fixture.agent.create_lane("narrow", budget()).expect("lane");
    let channel = fixture
        .agent
        .create_channel("send", Direction::Both)
        .expect("channel");
    let error = fixture
        .agent
        .send(narrow, channel, Value::list((0..4).map(Value::Int)), &[])
        .expect_err("a message outside the lane's grant must be refused");
    assert_eq!(error.code(), "rpc/budget-exceeded");
}

#[test]
fn a_publish_over_the_capability_shape_ceilings_is_refused() {
    let agent = Agent::with_secret([0x8d; 32]);
    let calls = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let provider = agent.register(Box::new(Reply {
        calls: std::rc::Rc::clone(&calls),
        reply: Value::text("ok"),
    }));
    let mut attrs = CapAttrs::new(&["ping"]).allow_publish();
    attrs.budget = budget();
    let cap = agent.mint(provider, 0, attrs).expect("mint");
    let lane = agent
        .create_lane("publish", Budget::default())
        .expect("lane");
    let channel = agent
        .create_channel("publish", Direction::Both)
        .expect("channel");
    let error = agent
        .publish(
            lane,
            channel,
            &cap,
            "topic",
            Value::list((0..4).map(Value::Int)),
        )
        .expect_err("a publish outside the grant must be refused");
    assert_eq!(error.code(), "rpc/budget-exceeded");
}

/// `wire_size` is one iterative walk, so a value deeper than the Rust stack is
/// measured (and refused by the depth ceiling), never an abort. The earlier
/// test used a depth a recursive walk would survive (R-20 round 3, L4).
#[test]
fn a_deep_value_is_measured_iteratively() {
    let mut value = Value::Null;
    for _ in 0..100_000 {
        value = Value::List(vec![value]);
    }
    let size = value.wire_size();
    assert!(size >= 100_000, "the depth is accounted: {size}");
    let memory = value.memory_bytes();
    assert!(
        memory >= 100_000 * std::mem::size_of::<Value>() as u64,
        "the memory walk is iterative too: {memory}"
    );
    // Dropping the 100 000-deep value would recurse through `Drop`.
    std::mem::forget(value);
}

// --- queue time: envelope descriptor bytes (RPC-52) ------------------------
//
// The queue-time charge is arguments plus payload plus the envelope's
// non-argument bytes — the method name and any capability descriptors or
// table delta. Before RPC-52 the last leg was zero, so a peer with a
// 100-byte grant could push ~1.3 MiB of descriptor bytes per call.

/// One descriptor granting `methods`, for the RPC-52 envelope tests.
fn descriptor(id: u8, methods: &[&str]) -> CapDescriptor {
    CapDescriptor {
        id: CapId([id; 16]),
        methods: methods.iter().map(|name| name.to_string()).collect(),
        budget: Budget::default(),
        read_only: false,
        redact: false,
        path_scope: None,
    }
}

/// Decode an envelope the way a transport would, so the test exercises the
/// path a peer's frame takes.
fn decoded(envelope: &Envelope) -> Envelope {
    let bytes = envelope.encode().expect("encode");
    Envelope::decode(&bytes).expect("decode")
}

/// The refusal code for an envelope call, and the fact that the provider
/// never ran.
fn envelope_refused(fixture: &Fixture, envelope: &Envelope) -> String {
    let before = fixture.calls.get();
    let error = fixture
        .agent
        .call_from_envelope(None, fixture.lane, &fixture.cap, envelope)
        .expect_err("the envelope bytes must be refused");
    assert_eq!(
        fixture.calls.get(),
        before,
        "the provider ran for an envelope the grant refuses"
    );
    error.code().to_string()
}

/// An envelope call inside the budget is admitted and the provider runs once.
fn envelope_admitted(fixture: &Fixture, envelope: &Envelope) {
    let before = fixture.calls.get();
    let promise = fixture
        .agent
        .call_from_envelope(None, fixture.lane, &fixture.cap, envelope)
        .expect("an envelope inside the budget is admitted");
    fixture.agent.run();
    assert_eq!(promise.value().expect("value"), Value::text("ok"));
    assert_eq!(fixture.calls.get(), before + 1, "the provider ran once");
}

/// RPC-52: a 1.25 MiB descriptor table does not run against a 100-byte grant.
#[test]
fn a_descriptor_table_larger_than_the_byte_budget_is_refused() {
    let fixture = fixture_with(
        Budget {
            max_bytes: 100,
            ..Budget::default()
        },
        Value::text("ok"),
    );
    let mut caps = Vec::new();
    for i in 0..100u8 {
        let mut id = [0u8; 16];
        id[0] = i + 1;
        let mut methods = BTreeSet::new();
        for m in 0..64 {
            methods.insert(format!("method-{m:02}-{}", "x".repeat(180)));
        }
        caps.push(CapDescriptor {
            id: CapId(id),
            methods,
            budget: Budget::default(),
            read_only: false,
            redact: false,
            path_scope: None,
        });
    }
    let envelope = decoded(&Envelope::request(1, "ping", vec![]).with_caps(caps));
    assert_eq!(envelope_refused(&fixture, &envelope), "rpc/budget-exceeded");
}

/// RPC-52: the charge is exact — one byte under the descriptor size refuses,
/// the size plus the response admits.
#[test]
fn a_descriptor_table_at_the_byte_budget_boundary() {
    let envelope =
        decoded(&Envelope::request(1, "ping", vec![]).with_caps(vec![descriptor(1, &["m"])]));
    let charge = envelope.non_argument_wire_size();
    // One byte under the charge refuses, and the provider never runs.
    let under = fixture_with(
        Budget {
            max_bytes: charge - 1,
            ..Budget::default()
        },
        Value::text("ok"),
    );
    assert_eq!(envelope_refused(&under, &envelope), "rpc/budget-exceeded");
    // The charge plus exactly the response's bytes admits, and the provider
    // runs once: the response charge stacks on the queue-time charge, so
    // this also pins the charge from above — any over-charge would eat the
    // response headroom and settle the promise as budget-exceeded.
    let exact = fixture_with(
        Budget {
            max_bytes: charge + Value::text("ok").wire_size(),
            ..Budget::default()
        },
        Value::text("ok"),
    );
    envelope_admitted(&exact, &envelope);
}

/// RPC-52: a 1,024-byte method name is charged too, not just the descriptors.
#[test]
fn a_long_method_name_is_charged_to_the_byte_budget() {
    struct LongMethod {
        calls: std::rc::Rc<std::cell::Cell<usize>>,
        method: String,
    }
    impl Provider for LongMethod {
        fn name(&self) -> &'static str {
            "long"
        }
        fn methods(&self) -> Vec<String> {
            vec![self.method.clone()]
        }
        fn mutating(&self, _method: &str) -> bool {
            false
        }
        fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
            self.calls.set(self.calls.get() + 1);
            Ok(Response::Value(Value::text("ok")))
        }
    }
    let method = "m".repeat(1_024);
    let calls = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let agent = Agent::with_secret([0x6c; 32]);
    let provider = agent.register(Box::new(LongMethod {
        calls: std::rc::Rc::clone(&calls),
        method: method.clone(),
    }));
    let envelope = decoded(&Envelope::request(1, method, vec![]));
    let charge = envelope.non_argument_wire_size();
    // One byte under the charge refuses.
    let under_budget = Budget {
        max_bytes: charge - 1,
        ..Budget::default()
    };
    let mut attrs = CapAttrs::new(&[envelope.method.as_str()]);
    attrs.budget = under_budget;
    let cap = agent.mint(provider, 0, attrs).expect("mint");
    let lane = agent.create_lane("long", under_budget).expect("lane");
    let error = agent
        .call_from_envelope(None, lane, &cap, &envelope)
        .expect_err("a 1,024-byte method name must be charged");
    assert_eq!(error.code(), "rpc/budget-exceeded");
    assert_eq!(calls.get(), 0, "the provider never ran");
    // The charge plus the response admits.
    let exact_budget = Budget {
        max_bytes: charge + Value::text("ok").wire_size(),
        ..Budget::default()
    };
    let mut attrs = CapAttrs::new(&[envelope.method.as_str()]);
    attrs.budget = exact_budget;
    let cap = agent.mint(provider, 0, attrs).expect("mint");
    let lane = agent.create_lane("long-exact", exact_budget).expect("lane");
    let promise = agent
        .call_from_envelope(None, lane, &cap, &envelope)
        .expect("the method charge plus the response admits");
    agent.run();
    assert_eq!(promise.value().expect("value"), Value::text("ok"));
    assert_eq!(calls.get(), 1, "the provider ran once");
}

/// RPC-52: a capability-table delta is charged — removed ids and added
/// descriptors alike — not just the table itself.
#[test]
fn a_capability_table_delta_is_charged_to_the_byte_budget() {
    let delta = CapTableDelta {
        base: cap_table_hash(&[]).expect("hash of the empty table"),
        removed: vec![CapId([7u8; 16]), CapId([8u8; 16])],
        added: vec![descriptor(9, &["m"])],
    };
    let envelope = decoded(&Envelope::request(1, "ping", vec![]).with_cap_delta(delta));
    let charge = envelope.non_argument_wire_size();
    let under = fixture_with(
        Budget {
            max_bytes: charge - 1,
            ..Budget::default()
        },
        Value::text("ok"),
    );
    assert_eq!(envelope_refused(&under, &envelope), "rpc/budget-exceeded");
    let exact = fixture_with(
        Budget {
            max_bytes: charge + Value::text("ok").wire_size(),
            ..Budget::default()
        },
        Value::text("ok"),
    );
    envelope_admitted(&exact, &envelope);
}

/// RPC-52: the idempotent envelope entry point charges descriptor bytes too,
/// and the charge is part of the call's fingerprint.
///
/// The calls here present a peer identity: an anonymous peer's idempotent
/// envelope call can never replay today (the owner check compares the stored
/// `from_peer` flag against `peer.is_some()` — F1-NF-06, found while writing
/// this test), so the replay half needs a named peer. The charge itself is
/// peer-independent.
#[test]
fn an_idempotent_envelope_call_charges_its_descriptor_bytes() {
    let peer = PeerIdentity::from_certificate(b"rpc52-peer");
    let mut caps = Vec::new();
    for i in 0..100u8 {
        let mut id = [0u8; 16];
        id[0] = i + 1;
        let mut methods = BTreeSet::new();
        for m in 0..64 {
            methods.insert(format!("method-{m:02}-{}", "x".repeat(180)));
        }
        caps.push(CapDescriptor {
            id: CapId(id),
            methods,
            budget: Budget::default(),
            read_only: false,
            redact: false,
            path_scope: None,
        });
    }
    let big = decoded(&Envelope::request(1, "ping", vec![]).with_caps(caps));
    let small =
        decoded(&Envelope::request(1, "ping", vec![]).with_caps(vec![descriptor(1, &["m"])]));
    let charge = small.non_argument_wire_size();
    let fixture = fixture_with(
        Budget {
            max_bytes: charge + Value::text("ok").wire_size(),
            ..Budget::default()
        },
        Value::text("ok"),
    );
    // The big table is refused before the provider runs, key or no key.
    let error = fixture
        .agent
        .call_idempotent_from_envelope(Some(&peer), fixture.lane, &fixture.cap, &big, "big")
        .expect_err("a 1.25 MiB descriptor table must be refused");
    assert_eq!(error.code(), "rpc/budget-exceeded");
    assert_eq!(fixture.calls.get(), 0, "the provider never ran");
    // The same small envelope under one key replays: the provider runs once.
    let first = fixture
        .agent
        .call_idempotent_from_envelope(Some(&peer), fixture.lane, &fixture.cap, &small, "small")
        .expect("the small envelope is admitted");
    fixture.agent.run();
    assert_eq!(first.value().expect("value"), Value::text("ok"));
    assert_eq!(fixture.calls.get(), 1, "the provider ran once");
    let replay = fixture
        .agent
        .call_idempotent_from_envelope(Some(&peer), fixture.lane, &fixture.cap, &small, "small")
        .expect("the same envelope replays");
    fixture.agent.run();
    assert_eq!(replay.value().expect("value"), Value::text("ok"));
    assert_eq!(fixture.calls.get(), 1, "the replay runs no provider");
    // The same key with a changed descriptor table is a different call.
    let changed = decoded(
        &Envelope::request(1, "ping", vec![])
            .with_caps(vec![descriptor(1, &["m"]), descriptor(2, &["n"])]),
    );
    let error = fixture
        .agent
        .call_idempotent_from_envelope(Some(&peer), fixture.lane, &fixture.cap, &changed, "small")
        .expect_err("a changed descriptor table is a different call");
    assert_eq!(error.code(), "rpc/invalid-argument");
}

/// RPC-52: an in-process call charges no descriptor bytes — the charge lives
/// only in the envelope entry points, because only they see an envelope.
#[test]
fn an_in_process_call_charges_no_descriptor_bytes() {
    let fixture = fixture_with(
        Budget {
            max_bytes: 1,
            ..Budget::default()
        },
        Value::text("ok"),
    );
    // No arguments, no payload: the in-process call charges nothing and is
    // admitted at queue time. (Only queue-time admission is asserted here:
    // whether the response settles is the egress boundary's business,
    // covered elsewhere.)
    let _admitted = fixture
        .agent
        .call(fixture.lane, &fixture.cap, "ping", vec![])
        .expect("an in-process call with no bytes is admitted");
    fixture.agent.run();
    // The same call from an envelope charges the method name (4+4) plus the
    // empty capability table (4) — 12 bytes against a 1-byte grant.
    let envelope = decoded(&Envelope::request(1, "ping", vec![]));
    assert_eq!(envelope.non_argument_wire_size(), 12);
    assert_eq!(envelope_refused(&fixture, &envelope), "rpc/budget-exceeded");
}
