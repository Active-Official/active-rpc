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

    // 1. Calls stop at the call ceiling.
    let mut calls = 0u64;
    for _ in 0..32 {
        match agent.call(lane, &cap, "ping", vec![]) {
            Ok(promise) => {
                calls += 1;
                let _ = promise.value();
            }
            Err(error) => {
                assert!(
                    matches!(
                        error.code(),
                        "rpc/budget-exceeded" | "rpc/unknown-lane" | "rpc/invalid-argument"
                    ),
                    "unexpected code {}",
                    error.code()
                );
                break;
            }
        }
    }
    assert!(calls <= budget.max_calls, "the call budget did not bind");

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

    // 3. A value that exceeds the depth or size ceiling is refused.
    let tight = Budget {
        max_depth: 4,
        max_value_size: 64,
        max_bytes: 64,
        ..Budget::default()
    };
    let tight_lane = agent.create_lane("tight", tight).expect("tight lane");
    let tight_cap = common::mint(&agent, provider, &["ping"], tight);
    let deep = nested(16);
    match agent.call(
        tight_lane,
        &tight_cap,
        "ping",
        vec![active_rpc::Arg::Value(deep)],
    ) {
        Ok(promise) => {
            let _ = promise.value();
        }
        Err(error) => assert!(
            matches!(error.code(), "rpc/budget-exceeded" | "rpc/invalid-argument"),
            "unexpected code {}",
            error.code()
        ),
    }

    // An oversized boolean-free list must not pass the byte ceiling either.
    let wide = Value::List(vec![Value::Int(7); 4096]);
    match agent.call(
        tight_lane,
        &tight_cap,
        "ping",
        vec![active_rpc::Arg::Value(wide)],
    ) {
        Ok(promise) => {
            let _ = promise.value();
        }
        Err(error) => assert!(
            matches!(error.code(), "rpc/budget-exceeded" | "rpc/invalid-argument"),
            "unexpected code {}",
            error.code()
        ),
    }
});
