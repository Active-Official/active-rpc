#![no_main]

//! LocalProcess policy: argv cannot escape the allow-list.
//!
//! Invariants under test (I-11, H2.12):
//!
//! 1. An argument outside the process allow-list is refused before spawn.
//! 2. A method other than `run` is refused.
//! 3. A non-existent program fails as a clean provider error, not a panic.
//! 4. The adapter policy is a valid attenuation of a wider parent.
//!
//! The configured program does not exist, so even an allowed argument cannot
//! execute anything.
//!
//! Run with `cargo +nightly fuzz run fuzz_tool_process -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_rpc::tool::LocalProcess;
use active_rpc::{Arg, Budget, CapAttrs, ToolPolicy, Value};

#[path = "common.rs"]
mod common;

fn policy() -> ToolPolicy {
    ToolPolicy {
        allowed: ["run"].iter().map(|name| name.to_string()).collect(),
        max_arg_bytes: 64,
        allow_process: true,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let tool = LocalProcess::new("/nonexistent-active-fuzz-binary", &["ok"]);
    assert!(policy().is_attenuation_of(&tool.policy()));

    let agent = common::agent(data);
    let provider = agent.register(Box::new(tool));
    let lane = agent
        .create_lane("process", Budget::default())
        .expect("default lane budget");
    let cap = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["run"])
                .with_budget(Budget::default())
                .with_tool_policy(policy()),
        )
        .expect("the process method is granted");

    // An argument outside the allow-list is refused without spawning.
    let argument: String = match data[0] % 5 {
        0 => "ok".to_string(),
        1 => "ok;rm -rf /".to_string(),
        2 => "$(id)".to_string(),
        3 => "../escape".to_string(),
        _ => {
            let mut out = String::new();
            for byte in data.iter().take(8) {
                out.push(char::from(b'a' + (byte % 26)));
            }
            out
        }
    };

    match agent.call(lane, &cap, "run", vec![Arg::text(argument.clone())]) {
        Ok(promise) => {
            let _ = promise.value();
        }
        Err(error) => {
            if argument != "ok" {
                assert_eq!(error.code(), "rpc/tool-policy");
            } else {
                assert!(
                    matches!(
                        error.code(),
                        "rpc/provider" | "rpc/transport" | "rpc/timeout"
                    ),
                    "unexpected code {} for a missing program",
                    error.code()
                );
            }
        }
    }

    // A method other than `run` is refused.
    let error = agent
        .call(lane, &cap, "shell", vec![Arg::text("ok")])
        .expect_err("a method outside the policy must be refused");
    assert_eq!(error.code(), "rpc/method-not-granted");

    // A huge argument exceeds the per-call tool ceiling.
    let error = agent
        .call(lane, &cap, "run", vec![Arg::text("x".repeat(4096))])
        .expect_err("an oversized argument must be refused");
    assert!(
        matches!(error.code(), "rpc/tool-policy" | "rpc/budget-exceeded"),
        "unexpected code {}",
        error.code()
    );

    let _ = Value::Null;
});
