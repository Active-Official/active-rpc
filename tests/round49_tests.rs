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

/// The table decoder honours the caller's byte ceiling, like every other
/// decoder in the module (round 21, finding 6).
#[test]
fn a_table_past_the_byte_ceiling_is_refused() {
    let bytes = [0u8; 64];
    let limits = WireLimits {
        max_bytes: 16,
        ..WireLimits::strict()
    };
    let error = active_rpc::wire::decode_capability_table_with(&bytes, &limits)
        .expect_err("past the byte ceiling");
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
