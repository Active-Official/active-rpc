//! R-08 round 41: the inbound grant bound on an MCP answer, the wasm argument
//! order, the MCP method/index order, the HTTP static request ceiling, a
//! zero-length HTTP body at the exact grant, and a process handle's `Debug`.

use std::io::{Read, Write};
use std::net::TcpListener;

use active_rpc::budget::Budget;
use active_rpc::kernel::Provider;
use active_rpc::tool::HttpTool;
use active_rpc::value::{Arg, Call, Value};

/// A 4 KiB answer that is not JSON: before round 41 it was parsed (and failed)
/// before the grant refused it.
#[test]
fn an_mcp_answer_past_the_grant_is_refused_before_the_parse() {
    use active_rpc::tool::{McpSession, MemoryTransport};

    let mut responses = std::collections::BTreeMap::new();
    responses.insert(
        "initialize".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#.to_string(),
    );
    responses.insert(
        "tools/list".to_string(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"x"}]}}"#
            .to_string(),
    );
    responses.insert("tools/call".to_string(), "x".repeat(4_096));
    let mut session = McpSession::handshake(MemoryTransport::new(responses)).expect("handshake");
    let mut call = Call::new("echo", vec![Arg::Value(Value::Int(1))]);
    call.budget = Budget {
        max_bytes: 2_048,
        ..Budget::default()
    };
    for _ in 0..2 {
        let error = session
            .invoke(0, &call)
            .expect_err("the answer is past the grant");
        assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    }
}

/// A bad method on an MCP call is reported before the tool index, as it is on
/// the other three adapters (round 41, F3).
#[test]
fn a_bad_mcp_method_is_reported_before_the_tool_index() {
    use active_rpc::tool::{McpSession, MemoryTransport};

    let mut responses = std::collections::BTreeMap::new();
    responses.insert(
        "initialize".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#.to_string(),
    );
    responses.insert(
        "tools/list".to_string(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"x"}]}}"#
            .to_string(),
    );
    let mut session = McpSession::handshake(MemoryTransport::new(responses)).expect("handshake");
    let mut call = Call::new("not-granted", vec![Arg::Value(Value::Int(1))]);
    call.budget = Budget {
        max_bytes: 1 << 20,
        ..Budget::default()
    };
    let error = session
        .invoke(99, &call)
        .expect_err("the method is refused first");
    assert_eq!(error.code(), "rpc/method-not-granted", "{error}");
}

/// The wasm adapter sums the argument bytes before its shape loop and its
/// method check, so the same malformed call reports the same code there
/// (round 41, F2).
#[cfg(feature = "wasm-tools")]
#[test]
fn the_wasm_adapter_reports_the_budget_before_the_method() {
    use active_rpc::wasm_tool::{WasmLimits, WasmTool};

    let module = wat::parse_str(
        r#"(module
             (memory (export "memory") 1)
             (func (export "run") (param i32) (result i32) i32.const 0))"#,
    )
    .expect("valid WAT");
    let mut tool =
        WasmTool::from_bytes(&module, WasmLimits::default()).expect("the fixture compiles");

    let mut over = Call::new(
        "not-granted",
        vec![
            Arg::Value(Value::Text("x".repeat(16))),
            Arg::Value(Value::Text("y".repeat(16))),
        ],
    );
    over.budget = Budget {
        max_bytes: 10,
        ..Budget::default()
    };
    let error = tool
        .invoke(0, &over)
        .expect_err("the sum is over the grant");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");

    let mut shaped = Call::new("not-granted", vec![Arg::Value(Value::Int(1))]);
    shaped.budget = Budget {
        max_bytes: 1 << 20,
        ..Budget::default()
    };
    let error = tool
        .invoke(0, &shaped)
        .expect_err("the method is refused before the shape");
    assert_eq!(error.code(), "rpc/method-not-granted", "{error}");
}

fn serve_once(response: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address").to_string();
    let handle = std::thread::spawn(move || {
        let Ok((mut socket, _)) = listener.accept() else {
            return;
        };
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .ok();
        let mut scratch = [0u8; 4096];
        let _ = socket.read(&mut scratch);
        let _ = socket.write_all(&response);
        let _ = socket.flush();
        let _ = socket.shutdown(std::net::Shutdown::Write);
        let _ = socket.read(&mut scratch);
    });
    (address, handle)
}

/// The static request ceiling is part of the serialization cap: an argument
/// past it is refused during the write with the code the spec names, instead of
/// being built in full and refused afterwards (round 41, F4).
#[test]
fn the_http_static_request_ceiling_refuses_during_serialization() {
    let (address, server) =
        serve_once(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok".to_vec());
    let mut tool = HttpTool::new(format!("http://{address}"), &[("POST", "/safe")]);
    tool.max_request = 64;
    let mut call = Call::new(
        "post",
        vec![
            Arg::Value(Value::Path("/safe".to_string())),
            Arg::Value(Value::Map(
                [("note".to_string(), Value::Text("x".repeat(4_096)))]
                    .into_iter()
                    .collect(),
            )),
        ],
    );
    call.budget = Budget {
        max_bytes: 1 << 20,
        ..Budget::default()
    };
    let error = tool
        .invoke(0, &call)
        .expect_err("the body is past the request ceiling");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");
    drop(server);
}

/// At the exact grant boundary a peer must not choose success or refusal by
/// choosing a framing: an empty body fits whether or not it announces
/// `content-length: 0` (round 41, F5).
#[test]
fn a_zero_length_http_body_fits_the_exact_grant() {
    for response in [
        "HTTP/1.0 200\r\n\r\n".to_string(),
        "HTTP/1.0 200\r\ncontent-length: 0\r\n\r\n".to_string(),
    ] {
        let (address, server) = serve_once(response.clone().into_bytes());
        let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/safe")]);
        let mut call = Call::new("get", vec![Arg::Value(Value::Path("/safe".to_string()))]);
        call.budget = Budget {
            max_bytes: response.len() as u64,
            ..Budget::default()
        };
        let answer = tool
            .invoke(0, &call)
            .unwrap_or_else(|error| panic!("{response:?}: {error}"));
        assert_eq!(
            answer,
            active_rpc::value::Response::Value(Value::Text(String::new()))
        );
        drop(server);
    }
}

/// A process handle's `Debug` names the environment keys and redacts every
/// value: a deployment log or a panic message must not carry the child's token
/// (round 41, F6).
#[test]
fn a_process_debug_does_not_print_environment_values() {
    use active_rpc::tool::LocalProcess;

    let mut tool = LocalProcess::new(
        std::env::current_exe()
            .expect("the test executable has a path")
            .display()
            .to_string(),
        &["*"],
    )
    .expect("an absolute program resolves");
    tool.env
        .insert("ACTIVE_RPC_TOKEN".to_string(), "canary-value".to_string());
    let rendered = format!("{tool:?}");
    assert!(
        rendered.contains("ACTIVE_RPC_TOKEN"),
        "the key is configuration and stays visible: {rendered}"
    );
    assert!(
        !rendered.contains("canary-value"),
        "the value is a credential and must be redacted: {rendered}"
    );
}
