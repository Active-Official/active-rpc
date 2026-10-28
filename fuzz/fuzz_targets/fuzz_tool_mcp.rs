#![no_main]

//! MCP session over MemoryTransport: adversarial JSON-RPC sequences.
//!
//! Invariants under test (I-11, I-8):
//!
//! 1. The handshake is not counted as a tool call.
//! 2. A tool name outside the discovered policy is refused before invocation.
//! 3. Arbitrary argument shapes do not panic the JSON conversion or the policy.
//! 4. Malformed server responses produce a stable provider error.
//!
//! Run with `cargo +nightly fuzz run fuzz_tool_mcp -- -runs=200000`.

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;

use active_rpc::tool::{McpSession, MemoryTransport};
use active_rpc::{Arg, Budget, CapAttrs, Provider, Value};

#[path = "common.rs"]
mod common;

fn responses() -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert(
        "initialize".into(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fuzz","version":"0"}}}"#.into(),
    );
    map.insert(
        "tools/list".into(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echo"}]}}"#
            .into(),
    );
    map.insert(
        "tools/call".into(),
        r#"{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"ok"}]}}"#.into(),
    );
    map
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let Ok(session) = McpSession::handshake(MemoryTransport::new(responses())) else {
        return;
    };
    assert_eq!(session.tools().len(), 1, "the handshake discovers one tool");
    assert_eq!(session.tools()[0].name, "echo");

    let policy = session.policy();
    let agent = common::agent(data);
    let provider = agent.register(Box::new(session));
    let lane = agent
        .create_lane("tools", Budget::default())
        .expect("default lane budget");
    let cap = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["echo"])
                .with_budget(Budget::default())
                .with_tool_policy(policy),
        )
        .expect("the discovered tool is granted");

    // The call is admitted only when the method matches the discovered tool;
    // the argument shape is arbitrary.
    let text: String = data
        .iter()
        .take(24)
        .map(|byte| char::from(b'a' + (byte % 26)))
        .collect();
    let args = match data[0] % 4 {
        0 => vec![Arg::text(text)],
        1 => vec![Arg::Value(Value::List(vec![Value::Int(1); 4]))],
        2 => vec![Arg::Value(Value::Map(std::collections::BTreeMap::from([
            ("k".into(), Value::text(text)),
        ])))],
        _ => vec![Arg::text(text), Arg::Value(Value::Int(7))],
    };
    match agent.call(lane, &cap, "echo", args) {
        Ok(promise) => {
            let _ = promise.value();
        }
        Err(error) => assert!(
            error.code().starts_with("rpc/"),
            "unexpected {}",
            error.code()
        ),
    }

    // A tool outside the policy is refused.
    let error = agent
        .call(lane, &cap, "not_discovered", vec![])
        .expect_err("an undiscovered tool must be refused");
    assert_eq!(error.code(), "rpc/method-not-granted");

    // A session whose handshake fails is an error, not a panic.
    let mut broken = BTreeMap::new();
    broken.insert(
        "initialize".into(),
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"no"}}"#.into(),
    );
    assert!(McpSession::handshake(MemoryTransport::new(broken)).is_err());

    // Malformed JSON from the server is a stable provider error.
    let mut malformed = BTreeMap::new();
    malformed.insert("initialize".into(), "not json".into());
    assert!(McpSession::handshake(MemoryTransport::new(malformed)).is_err());

    let _ = Provider::name(&common::Echo::default());
});
