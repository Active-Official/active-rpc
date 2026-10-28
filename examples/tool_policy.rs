//! A tool capability can only invoke the tools its policy names.
//!
//! Run with `cargo run --example tool_policy`.
//!
//! The MCP session is backed by a canned transport so the example runs offline.
//! The important part is the kernel path: the capability grants two method
//! names, the tool policy names one, and the second call is refused before the
//! transport sees it.

use std::collections::BTreeMap;

use active_rpc::cap::CapAttrs;
use active_rpc::tool::{McpSession, MemoryTransport};
use active_rpc::{Agent, Budget, Value};

fn main() {
    let mut responses = BTreeMap::new();
    responses.insert(
        "initialize".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"stub"}}}"#
            .to_string(),
    );
    responses.insert(
        "tools/list".to_string(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echo back"}]}}"#
            .to_string(),
    );
    responses.insert(
        "tools/call".to_string(),
        r#"{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"pong"}]}}"#
            .to_string(),
    );

    let session = McpSession::handshake(MemoryTransport::new(responses)).expect("handshake");
    let policy = session.policy();
    println!("discovered tools: {:?}", policy.allowed);

    let agent = Agent::with_secret([11u8; 32]);
    let provider = agent.register(Box::new(session));
    let lane = agent.create_lane("tools", Budget::default()).expect("lane");

    // Method grant is necessary, not sufficient: the tool policy must also
    // name the tool. This capability grants `echo` but its policy does not.
    let cap = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["echo"]).with_tool_policy(policy.clone()),
        )
        .expect("granted cap");

    let promise = agent
        .call(lane, &cap, "echo", vec![active_rpc::Arg::text("hi")])
        .expect("allowed tool");
    let value = promise.value().expect("value");
    assert!(matches!(value, Value::Map(_) | Value::Text(_)));
    println!("echo -> {value:?}");

    let restricted = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["echo"]).with_tool_policy(active_rpc::ToolPolicy::allow(&["other"])),
        )
        .expect("restricted cap");
    let error = agent
        .call(lane, &restricted, "echo", vec![active_rpc::Arg::text("hi")])
        .expect_err("tool policy must refuse");
    println!("restricted echo -> {} ({})", error.code(), error);
    assert_eq!(error.code(), "rpc/tool-policy");
}
