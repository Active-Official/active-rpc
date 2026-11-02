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
