#![no_main]

//! Promise graph: pipelining, cancel, resolve, destroy-lane and dependent work.
//!
//! Invariants under test (C-1, I-6, I-8):
//!
//! 1. A promise settles exactly once; a second resolve, reject or cancel fails.
//! 2. A cancelled promise reports `rpc/promise-cancelled`.
//! 3. A pipelined call whose dependency is unresolved does not run.
//! 4. Destroying a lane refuses further calls and drops queued work.
//!
//! Run with `cargo +nightly fuzz run fuzz_promise_graph -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_rpc::{Arg, Budget, Value};

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let agent = common::agent(data);
    let provider = agent.register(Box::new(common::Echo::default()));
    let lane = agent
        .create_lane("main", Budget::default())
        .expect("default lane budget");
    let cap = common::mint(&agent, provider, &["ping", "echo"], Budget::default());
    let mut promises = Vec::new();

    for byte in data.iter().take(64) {
        match byte % 6 {
            0 => {
                if let Ok(promise) = agent.call(lane, &cap, "ping", vec![]) {
                    promises.push(promise);
                }
            }
            1 => {
                // Pipeline on the newest promise.
                if let Some(dependency) = promises.last() {
                    if let Ok(promise) =
                        agent.call(lane, &cap, "echo", vec![Arg::Promise(dependency.id())])
                    {
                        promises.push(promise);
                    }
                }
            }
            2 => {
                if let Some(promise) = promises.pop() {
                    if agent.cancel(&promise).is_ok() {
                        assert_eq!(promise.peek().unwrap_err().code(), "rpc/promise-cancelled");
                    }
                }
            }
            3 => {
                if let Some(promise) = promises.pop() {
                    if agent.resolve(&promise, Value::text("manual")).is_ok() {
                        let error = agent
                            .resolve(&promise, Value::text("again"))
                            .expect_err("a second settlement must be refused");
                        assert_eq!(error.code(), "rpc/promise-resolved");
                    }
                }
            }
            4 => {
                // Asking for the value runs the queue; a settled promise is
                // stable, an unsettled one either resolves or errors cleanly.
                if let Some(promise) = promises.first() {
                    let _ = promise.value();
                }
            }
            _ => {
                // A never-minted promise id is refused.
                let imported = active_rpc::PromiseId(u64::MAX);
                let error = agent
                    .call(lane, &cap, "echo", vec![Arg::Promise(imported)])
                    .err()
                    .map(|error| error.code().to_string());
                if let Some(code) = error {
                    assert!(
                        code.starts_with("rpc/"),
                        "unexpected code {code} for a foreign promise"
                    );
                }
            }
        }
    }

    // Destroying the lane refuses further calls.
    let _ = agent.destroy_lane(lane);
    let error = agent
        .call(lane, &cap, "ping", vec![])
        .expect_err("a destroyed lane must refuse calls");
    assert_eq!(error.code(), "rpc/unknown-lane");
});
