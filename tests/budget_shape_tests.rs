//! The budget's shape ceilings bind on a call's arguments.
//!
//! `Budget::max_depth`, `max_array_len` and `max_value_size` are declared,
//! intersected and exported, so a grant can name them; before R-20 the kernel
//! never checked them, and an in-process caller could hand a provider a value
//! 10 000 levels deep under a grant that said "depth 2". A peer's value is
//! refused by `WireLimits` on ingress, which is why the gap was invisible from
//! the wire.

use std::collections::BTreeMap;

use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, Budget};

struct Echo {
    calls: std::rc::Rc<std::cell::Cell<usize>>,
}

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

    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        self.calls.set(self.calls.get() + 1);
        Ok(Response::Value(Value::text("ok")))
    }
}

struct Fixture {
    agent: Agent,
    calls: std::rc::Rc<std::cell::Cell<usize>>,
    cap: active_rpc::CapHandle,
    lane: active_rpc::LaneId,
}

fn fixture(budget: Budget) -> Fixture {
    let agent = Agent::with_secret([0x6b; 32]);
    let calls = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let provider = agent.register(Box::new(Echo {
        calls: std::rc::Rc::clone(&calls),
    }));
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.budget = budget;
    let cap = agent.mint(provider, 0, attrs).expect("mint");
    let lane = agent.create_lane("shape", Budget::default()).expect("lane");
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

/// The refusal code and the fact that the provider never ran.
fn refused(fixture: &Fixture, value: Value) -> String {
    let before = fixture.calls.get();
    let error = fixture
        .agent
        .call(fixture.lane, &fixture.cap, "echo", vec![Arg::Value(value)])
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
        .call(fixture.lane, &fixture.cap, "echo", vec![Arg::Value(value)])
        .expect("a value inside the budget is admitted");
    assert_eq!(promise.value().expect("value"), Value::text("ok"));
    assert_eq!(fixture.calls.get(), before + 1, "the provider ran once");
}

fn budget() -> Budget {
    Budget {
        max_depth: 2,
        max_array_len: 3,
        max_value_size: 8,
        ..Budget::default()
    }
}

#[test]
fn a_value_deeper_than_max_depth_is_refused() {
    let fixture = fixture(budget());
    assert_eq!(refused(&fixture, nested(3)), "rpc/budget-exceeded");
}

#[test]
fn a_list_wider_than_max_array_len_is_refused() {
    let fixture = fixture(budget());
    let wide = Value::list((0..4).map(Value::Int));
    assert_eq!(refused(&fixture, wide), "rpc/budget-exceeded");
}

#[test]
fn a_text_longer_than_max_value_size_is_refused() {
    let fixture = fixture(budget());
    assert_eq!(
        refused(&fixture, Value::text("123456789")),
        "rpc/budget-exceeded"
    );
}

#[test]
fn a_map_key_longer_than_max_value_size_is_refused() {
    // A key is payload too: it arrives on the wire and reaches the provider.
    let fixture = fixture(budget());
    let mut entries = BTreeMap::new();
    entries.insert("123456789".to_string(), Value::Int(1));
    assert_eq!(
        refused(&fixture, Value::Map(entries)),
        "rpc/budget-exceeded"
    );
}

#[test]
fn a_module_larger_than_max_value_size_is_refused() {
    let fixture = fixture(budget());
    assert_eq!(
        refused(&fixture, Value::Module(vec![0u8; 9])),
        "rpc/budget-exceeded"
    );
}

#[test]
fn a_value_exactly_at_every_ceiling_is_admitted() {
    // Off-by-one guard: `depth 2` is the deepest admitted at `max_depth 2`.
    let depth_fixture = fixture(budget());
    admitted(&depth_fixture, nested(2));

    let wide_fixture = fixture(Budget {
        max_calls: 10,
        max_bytes: u64::MAX / 2,
        ..budget()
    });
    admitted(
        &wide_fixture,
        Value::list((0..3).map(|index| Value::Int(i64::from(index)))),
    );

    let size_fixture = fixture(Budget {
        max_calls: 10,
        ..budget()
    });
    admitted(&size_fixture, Value::text("12345678"));
}

#[test]
fn a_deep_value_is_refused_without_a_recursive_walk() {
    // Deeper than the grant by an order of magnitude. The value is built and
    // dropped by derived `Clone`/`Drop`, which recurse, so this test stays at a
    // depth those survive; the kernel's own walk is iterative, so it adds no
    // frame per level (a value from a peer is bounded by `MAX_VALUE_DEPTH`).
    let deep_fixture = fixture(Budget {
        max_depth: 64,
        max_bytes: u64::MAX / 2,
        ..Budget::default()
    });
    assert_eq!(refused(&deep_fixture, nested(512)), "rpc/budget-exceeded");
}

#[test]
fn nested_ceilings_apply_at_any_level() {
    // The wide list is two levels down, under a scalar: a check that only looks
    // at the top level would admit it.
    let nested_fixture = fixture(budget());
    let deep_and_wide = Value::List(vec![Value::List(vec![Value::list((0..4).map(Value::Int))])]);
    assert_eq!(
        refused(&nested_fixture, deep_and_wide),
        "rpc/budget-exceeded"
    );
}

#[test]
fn the_default_grant_admits_ordinary_values() {
    let default_fixture = fixture(Budget::default());
    admitted(&default_fixture, nested(3));
    admitted(&default_fixture, Value::list((0..100).map(Value::Int)));
    admitted(&default_fixture, Value::Module(vec![0u8; 1024]));
}

#[test]
fn a_secret_marker_is_not_measured() {
    // The size of a secret is not read: that would be an oracle. A marker
    // therefore satisfies any `max_value_size`.
    let secret_fixture = fixture(Budget {
        max_calls: 2,
        ..budget()
    });
    admitted(&secret_fixture, Value::Secret);
}
