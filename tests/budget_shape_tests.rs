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
//! lane traffic (`send`, `publish`).
//!
//! `max_value_size` is the materialised size of one value — the same number
//! `Value::wire_size` reports — so a list of ten thousand `Null` is 10 000 bytes
//! of payload and not "size 1".

use std::collections::BTreeMap;

use active_rpc::cap::CapAttrs;
use active_rpc::channel::Direction;
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Response, Value};
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
    // the process in the check that exists to refuse it. The depth is two
    // thousand, well past the wire's 64: `Value` is a public type with a derived
    // (recursive) destructor, so a deeper value would also overflow while this
    // test's own temporary is dropped.
    let mut value = Value::path("secret/leaf");
    for _ in 0..2_000 {
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
    let dependent = fixture
        .agent
        .call(
            fixture.lane,
            &fixture.cap,
            "ping",
            vec![Arg::Promise(pending.id())],
        )
        .expect("dependent");
    // Inside the capability's depth ceiling (256) but past the wire's 64.
    fixture
        .agent
        .resolve(&pending, nested(100))
        .expect("resolve accepts a value inside the grant");
    let error = dependent
        .value()
        .expect_err("the dispatch refuses a value deeper than the wire allows");
    assert_eq!(error.code(), "rpc/budget-exceeded");
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
