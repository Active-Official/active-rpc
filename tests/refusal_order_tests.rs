//! One refusal order for every adapter: budget, payload, secret, scope,
//! argument bytes, method.
//!
//! The same malformed call must report the same first code whichever handle it
//! reaches. A per-adapter difference is a fingerprint: a caller can tell a
//! process handle from an HTTP handle, and can probe whether a scope or a
//! process grant is present, by reading which refusal comes back (round 40,
//! F2).

use std::collections::VecDeque;

use active_rpc::budget::Budget;
use active_rpc::error::Error;
use active_rpc::kernel::Provider;
use active_rpc::tool::{HttpTool, LocalProcess, McpSession, McpTransport};
use active_rpc::value::{Arg, Call, Value};

/// An MCP transport with scripted answer lines and no socket.
struct Scripted {
    queue: VecDeque<String>,
}

impl Scripted {
    fn new(lines: &[&str]) -> Self {
        Self {
            queue: lines.iter().map(|line| line.to_string()).collect(),
        }
    }
}

impl McpTransport for Scripted {
    fn send_line(&mut self, _line: &str) -> active_rpc::Result<()> {
        Ok(())
    }

    fn recv_line(&mut self) -> active_rpc::Result<String> {
        self.queue.pop_front().ok_or(Error::Provider {
            code: "mcp/no-response".to_string(),
        })
    }
}

fn session() -> McpSession<Scripted> {
    McpSession::handshake(Scripted::new(&[
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{}}}"#,
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"x"}]}}"#,
    ]))
    .expect("the scripted handshake answers both steps")
}

fn process() -> LocalProcess {
    // The refusal happens before the spawn, so the program is only resolved.
    LocalProcess::new(
        std::env::current_exe()
            .expect("the test executable has a path")
            .display()
            .to_string(),
        &["*"],
    )
    .expect("an absolute program resolves")
}

fn http() -> HttpTool {
    HttpTool::new("http://127.0.0.1:9", &[("GET", "/safe")])
}

/// The first refusal for one `Call`, from any adapter.
fn first_refusal(provider: &mut dyn Provider, call: &Call) -> String {
    match provider.invoke(0, call) {
        Ok(response) => panic!("the hostile call was accepted: {response:?}"),
        Err(error) => error.code().to_string(),
    }
}

fn all_four(call: &Call) -> Vec<String> {
    let mut process = process();
    let mut http = http();
    let mut mcp = session();
    #[allow(unused_mut)]
    let mut codes = vec![
        first_refusal(&mut process, call),
        first_refusal(&mut http, call),
        first_refusal(&mut mcp, call),
    ];
    #[cfg(feature = "wasm-tools")]
    {
        let module = wat::parse_str(
            r#"(module
                 (memory (export "memory") 1)
                 (func (export "run") (param i32) (result i32) i32.const 0))"#,
        )
        .expect("the fixture is valid WAT");
        let mut wasm = active_rpc::wasm_tool::WasmTool::from_bytes(
            &module,
            active_rpc::wasm_tool::WasmLimits::default(),
        )
        .expect("the fixture compiles");
        codes.push(first_refusal(&mut wasm, call));
    }
    codes
}

fn assert_uniform(call: &Call, expected: &str) {
    for (index, code) in all_four(call).iter().enumerate() {
        assert_eq!(
            code, expected,
            "adapter {index} reported {code} instead of {expected}"
        );
    }
}

#[test]
fn a_secret_is_the_same_first_refusal_in_every_adapter() {
    let mut call = Call::new("not-granted", vec![Arg::Value(Value::Secret)]);
    call.path_scope = Some("a.b".to_string());
    // Room for the arguments, so the secret is the first fault.
    call.budget = Budget {
        max_bytes: 1 << 20,
        ..Budget::default()
    };
    assert_uniform(&call, "rpc/tool-policy");
}

#[test]
fn a_scope_is_the_same_first_refusal_in_every_adapter() {
    let mut call = Call::new(
        "not-granted",
        vec![Arg::Value(Value::Text("x".repeat(4096)))],
    );
    call.path_scope = Some("a.b".to_string());
    // The argument is past the grant as well, so the scope has to come first.
    call.budget = Budget {
        max_bytes: 8,
        ..Budget::default()
    };
    assert_uniform(&call, "rpc/tool-policy");
}

#[test]
fn oversized_arguments_are_the_same_first_refusal_in_every_adapter() {
    let call = {
        let mut call = Call::new(
            "not-granted",
            vec![Arg::Value(Value::Text("x".repeat(4096)))],
        );
        call.budget = Budget {
            max_bytes: 8,
            ..Budget::default()
        };
        call
    };
    assert_uniform(&call, "rpc/budget-exceeded");
}

#[test]
fn a_bad_method_is_the_same_last_refusal_in_every_adapter() {
    let call = {
        // The wasm adapter takes exactly one input, so a shape-only call would
        // report the input rule instead; one text argument keeps every adapter
        // on the method step.
        let mut call = Call::new(
            "not-granted",
            vec![Arg::Value(Value::Text("x".to_string()))],
        );
        call.budget = Budget {
            max_bytes: 1 << 20,
            ..Budget::default()
        };
        call
    };
    assert_uniform(&call, "rpc/method-not-granted");
}
