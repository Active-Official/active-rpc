//! R-08/R-09 round-49 lows: the poisoned-session counter, the HTTP body depth
//! gate, the shared-memory size class, and the table decoder's byte ceiling.

use active_rpc::budget::Budget;
use active_rpc::kernel::Provider;
use active_rpc::transport::shm::{SharedMemoryTransport, SharedSegment};
use active_rpc::transport::Transport;
use active_rpc::value::{Arg, Call, Value};
use active_rpc::wire::WireLimits;

/// A poisoned-session refusal is not a served call (round 48, F-8; round 49,
/// L-2): the counter moves only after the poison check.
#[test]
fn a_poisoned_refusal_is_not_a_served_call() {
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
    call.read_only = true;
    call.budget = Budget {
        max_bytes: 2_048,
        ..Budget::default()
    };
    let _ = session
        .invoke(0, &call)
        .expect_err("the answer is past the grant");
    let admitted = session.calls;
    assert_eq!(admitted, 1, "the refusal was a served call");
    let again = session
        .invoke(0, &call)
        .expect_err("the session is poisoned");
    assert_eq!(again.provider_code(), Some("mcp/desync"), "{again}");
    assert_eq!(session.calls, admitted, "a poisoned refusal counts nothing");
}

/// An HTTP body one level past the wire depth is refused before the recursive
/// clone, as a bad argument (round 49, L-4).
#[test]
fn a_body_past_the_wire_depth_is_a_bad_argument() {
    use active_rpc::tool::HttpTool;

    let mut value = Value::Null;
    for _ in 0..70 {
        value = Value::Map([("n".to_string(), value)].into_iter().collect());
    }
    let mut tool = HttpTool::new("http://127.0.0.1:9", &[("POST", "/safe")]);
    let mut call = Call::new(
        "post",
        vec![
            Arg::Value(Value::Path("/safe".to_string())),
            Arg::Value(value),
        ],
    );
    call.budget = Budget {
        max_bytes: 1 << 20,
        ..Budget::default()
    };
    let error = tool.invoke(0, &call).expect_err("the body is too deep");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
}

/// A frame that can never fit the ring is a wire fault, not a transport
/// condition; a merely full ring stays retryable (round 19, R-9#4; round 21,
/// finding 4).
#[test]
fn a_frame_that_cannot_fit_the_segment_is_a_wire_fault() {
    let segment = SharedSegment::new(1 << 10);
    let mut sender = SharedMemoryTransport::new(segment.clone());
    let mut big = active_rpc::wire::Envelope::request(1, "x", Vec::new());
    big.payload = vec![0u8; 2 << 10];
    let error = sender.send(&big).expect_err("the ring cannot hold it");
    assert_eq!(error.code(), "rpc/wire", "{error}");
}

/// The reply-budget ceiling is a second, independent budget (round 21,
/// finding 3): `MAX_INFLIGHT_REPLY` is its own constant, not the request one.
#[cfg(feature = "quic")]
#[test]
fn the_reply_ceiling_is_its_own_constant() {
    assert_eq!(
        active_rpc::transport::quic::MAX_INFLIGHT_REPLY,
        256 << 20,
        "the reply ceiling is documented as its own bound"
    );
}

/// A malformed answer with many unrepresentable literals is still a bad number,
/// not text: the repair covers every literal, not a capped prefix (round 50,
/// F-1).
#[test]
fn a_body_with_many_bad_literals_is_not_text() {
    use active_rpc::value::Response as ToolResponse;

    let literals = ["1e400"; 12];
    let body = format!("[{}]", literals.join(","));
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address").to_string();
    let server = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let (mut socket, _) = listener.accept().expect("accept");
        let mut scratch = [0u8; 4096];
        let _ = socket.read(&mut scratch);
        let _ = socket.write_all(response.as_bytes());
        let _ = socket.flush();
        let _ = socket.shutdown(std::net::Shutdown::Write);
        let _ = socket.read(&mut scratch);
    });
    let mut tool = active_rpc::tool::HttpTool::new(format!("http://{address}"), &[("GET", "/x")]);
    let mut call = Call::new("get", vec![Arg::Value(Value::Path("/x".to_string()))]);
    call.read_only = true;
    call.budget = Budget {
        max_bytes: 1 << 20,
        ..Budget::default()
    };
    let outcome = tool.invoke(0, &call);
    match outcome {
        Ok(ToolResponse::Value(Value::Text(_))) => panic!("a bad-number answer was served as text"),
        Ok(other) => panic!("unexpected success: {other:?}"),
        Err(error) => assert_eq!(error.provider_code(), Some("http/bad-number"), "{error}"),
    }
    drop(server);
}

/// A table past the byte ceiling uses the table class, like every other table
/// limit (round 22, N6).
#[test]
fn a_table_past_the_byte_ceiling_is_a_table_fault() {
    let bytes = [0u8; 64];
    let limits = WireLimits {
        max_bytes: 16,
        ..WireLimits::strict()
    };
    let error = active_rpc::wire::decode_capability_table_with(&bytes, &limits)
        .expect_err("past the byte ceiling");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");
}
