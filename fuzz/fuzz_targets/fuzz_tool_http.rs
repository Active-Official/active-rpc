#![no_main]

//! HTTP tool policy: method and path allow-lists cannot be escaped.
//!
//! Invariants under test (I-11, I-12):
//!
//! 1. A path outside the allow-list is refused with `rpc/tool-policy` before any
//!    network call.
//! 2. A method outside the capability's tool policy is refused before the
//!    adapter runs.
//! 3. An oversized body is refused by the per-call byte ceiling.
//! 4. The adapter's own policy is a valid attenuation of a wider parent.
//!
//! The base URL points at port 1 on loopback, so even an allowed call fails
//! immediately with a transport error instead of reaching a network service.
//!
//! Run with `cargo +nightly fuzz run fuzz_tool_http -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_rpc::tool::HttpTool;
use active_rpc::{Arg, Budget, CapAttrs, ToolPolicy, Value};

#[path = "common.rs"]
mod common;

fn policy() -> ToolPolicy {
    ToolPolicy {
        allowed: ["get", "post", "request"]
            .iter()
            .map(|name| name.to_string())
            .collect(),
        max_arg_bytes: 1024,
        allow_process: false,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let tool = HttpTool::new("http://127.0.0.1:1", &[("GET", "/safe")]);
    let adapter_policy = tool.policy();
    assert!(policy().is_attenuation_of(&adapter_policy));

    let agent = common::agent(data);
    let provider = agent.register(Box::new(tool));
    let lane = agent
        .create_lane("http", Budget::default())
        .expect("default lane budget");
    let cap = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["get", "post", "request"])
                .with_budget(Budget::default())
                .with_tool_policy(policy()),
        )
        .expect("the HTTP methods are granted");

    let path: String = match data[0] % 6 {
        0 => "/safe".to_string(),
        1 => "/safe/../admin".to_string(),
        2 => "http://127.0.0.1:1/admin".to_string(),
        3 => "/safe%2f..%2fadmin".to_string(),
        4 => "/safe?x=1".to_string(),
        _ => {
            let mut out = String::from("/safe");
            for byte in data.iter().take(12) {
                out.push(char::from(b'a' + (byte % 26)));
            }
            out
        }
    };

    // A path outside the adapter allow-list is refused when the promise is
    // settled, before any network call.
    if path != "/safe" {
        let promise = agent
            .call(lane, &cap, "get", vec![Arg::text(path)])
            .expect("the call is queued");
        let error = promise
            .value()
            .expect_err("an escaped path must be refused");
        assert!(
            matches!(error.code(), "rpc/tool-policy" | "rpc/invalid-argument"),
            "unexpected code {}",
            error.code()
        );
    }

    // A method outside the capability's tool policy is refused first.
    let error = agent
        .call(lane, &cap, "delete", vec![Arg::text("/safe")])
        .expect_err("a method outside the policy must be refused");
    assert_eq!(error.code(), "rpc/method-not-granted");

    // An oversized body exceeds the per-call tool ceiling.
    let huge = "x".repeat(4096);
    let error = agent
        .call(lane, &cap, "post", vec![Arg::text(huge)])
        .expect_err("an oversized body must be refused");
    assert!(
        matches!(error.code(), "rpc/tool-policy" | "rpc/budget-exceeded"),
        "unexpected code {}",
        error.code()
    );

    let _ = Value::Null;
});
