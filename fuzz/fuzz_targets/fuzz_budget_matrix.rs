#![no_main]

//! Budget matrix: each ceiling alone, and zero ceilings everywhere.
//!
//! Invariants under test (I-8):
//!
//! 1. A budget with any zero ceiling is refused at lane creation and at mint.
//! 2. Calls stop at `max_calls`.
//! 3. A value over `max_bytes`, `max_depth`, `max_array_len` or
//!    `max_value_size` is refused before the provider runs.
//!
//! Run with `cargo +nightly fuzz run fuzz_budget_matrix -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_rpc::{Budget, CapAttrs, Value};

#[path = "common.rs"]
mod common;

fn nested(depth: usize) -> Value {
    let mut value = Value::Int(1);
    for _ in 0..depth {
        value = Value::List(vec![value]);
    }
    value
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let agent = common::agent(data);
    let provider = agent.register(Box::new(common::Echo::default()));
    let budget = common::budget_from(data);
    let lane = agent
        .create_lane("matrix", budget)
        .expect("a non-zero budget is accepted");
    let cap = common::mint(&agent, provider, &["ping"], budget);

    // 1. Calls stop at the call ceiling, and the refusal is the ceiling itself:
    //    "some call failed" used to satisfy this, which a lane that refuses
    //    everything also does.
    let mut calls = 0u64;
    let mut refusal: Option<String> = None;
    for _ in 0..32 {
        match agent.call(lane, &cap, "ping", vec![]) {
            Ok(promise) => {
                calls += 1;
                let _ = promise.value();
            }
            Err(error) => {
                refusal = Some(error.code().to_string());
                break;
            }
        }
    }
    assert!(calls <= budget.max_calls, "the call budget did not bind");
    if calls < 32 {
        assert_eq!(
            refusal.as_deref(),
            Some("rpc/budget-exceeded"),
            "the refusal after {calls} calls must be the budget ceiling"
        );
        assert_eq!(
            calls, budget.max_calls,
            "the ceiling binds after exactly max_calls calls"
        );
    }

    // 2. A zero ceiling in every field is refused.
    let zeros = [
        Budget {
            max_calls: 0,
            ..Budget::default()
        },
        Budget {
            max_bytes: 0,
            ..Budget::default()
        },
        Budget {
            max_wall_ms: 0,
            ..Budget::default()
        },
        Budget {
            max_nodes: 0,
            ..Budget::default()
        },
        Budget {
            max_depth: 0,
            ..Budget::default()
        },
        Budget {
            max_array_len: 0,
            ..Budget::default()
        },
        Budget {
            max_value_size: 0,
            ..Budget::default()
        },
    ];
    for zero in zeros {
        let error = agent
            .create_lane("zero", zero)
            .expect_err("a zero ceiling must be refused");
        assert_eq!(error.code(), "rpc/invalid-argument");
        let error = agent
            .mint(provider, 0, CapAttrs::new(&["ping"]).with_budget(zero))
            .expect_err("a zero ceiling must be refused at mint");
        assert_eq!(error.code(), "rpc/invalid-argument");
    }

    // 3. A value past one shape ceiling is refused for *that* dimension. The
    //    ceilings come from the input and each probe is built past its own
    //    ceiling; `max_bytes` stays generous so a byte refusal cannot satisfy
    //    the assertion instead. The message names the dimension, because the
    //    code is `rpc/budget-exceeded` for every one of them.
    let depth = 2 + usize::from(data[0] % 8);
    let width = 2 + usize::from(data.get(1).copied().unwrap_or(0) % 12);
    let per_value = 8 * (1 + usize::from(data.get(2).copied().unwrap_or(1) % 16));
    let tight = Budget {
        max_depth: depth as u64,
        max_array_len: width as u64,
        max_value_size: per_value as u64,
        max_bytes: 1 << 20,
        ..Budget::default()
    };
    let tight_lane = agent.create_lane("tight", tight).expect("tight lane");
    let tight_cap = common::mint(&agent, provider, &["ping"], tight);

    let probes = [
        ("depth", nested(depth + 4)),
        ("array_len", Value::List(vec![Value::Int(7); width + 4])),
        (
            "value_size",
            Value::text("x".repeat(per_value.saturating_add(16))),
        ),
    ];
    for (dimension, value) in probes {
        match agent.call(
            tight_lane,
            &tight_cap,
            "ping",
            vec![active_rpc::Arg::Value(value)],
        ) {
            Ok(promise) => {
                let _ = promise.value();
                panic!("a value past max_{dimension} was admitted");
            }
            Err(error) => {
                assert_eq!(
                    error.code(),
                    "rpc/budget-exceeded",
                    "a value past max_{dimension} must be a budget refusal, got {error}"
                );
                let text = error.to_string();
                assert!(
                    text.contains(dimension),
                    "the refusal must name the dimension that bound: {text}"
                );
            }
        }
    }
});
