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

/// A 2xx body nested past serde's own limit is the documented `http/too-complex`,
/// not text: a chain of arrays has no tokens, so only a depth scan sees it
/// (round 51, finding 1).
#[test]
fn a_body_nested_past_the_parser_limit_is_too_complex() {
    let mut nested = String::from("[");
    for _ in 0..200 {
        nested.push('[');
    }
    nested.push('0');
    for _ in 0..201 {
        nested.push(']');
    }
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        nested.len(),
        nested
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
    let error = tool.invoke(0, &call).expect_err("too deep to be text");
    assert_eq!(error.provider_code(), Some("http/too-complex"), "{error}");
    drop(server);
}

/// A query-only base is a credential home too: `Debug` cuts at `?` and `#`
/// (round 51, finding 2).
#[test]
fn a_query_only_base_is_redacted() {
    let tool = active_rpc::tool::HttpTool::new("http://127.0.0.1:9?token=CANARY", &[("GET", "/x")]);
    let rendered = format!("{tool:?}");
    assert!(!rendered.contains("CANARY"), "the query leaked: {rendered}");
    assert!(rendered.contains("127.0.0.1:9"), "{rendered}");
    // The base is cut to its authority at construction, so resolution sees an
    // address rather than `host?query` (round 51, finding 5).
    assert!(rendered.contains("http://127.0.0.1:9\""), "{rendered}");
}

/// A base with a path is a configuration fault: `try_new` refuses it and `new`
/// refuses every call, rather than silently retargeting the request at another
/// resource on the same authority (round 52, F-1).
#[test]
fn a_base_with_a_path_is_refused() {
    let error =
        active_rpc::tool::HttpTool::try_new("http://127.0.0.1:9/admin-api", &[("POST", "/users")])
            .expect_err("a path in the base is refused at construction");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");

    let mut tool =
        active_rpc::tool::HttpTool::new("http://127.0.0.1:9/admin-api", &[("POST", "/users")]);
    let mut call = Call::new(
        "post",
        vec![
            Arg::Value(Value::Path("/users".to_string())),
            Arg::Value(Value::Map(
                [("n".to_string(), Value::Int(1))].into_iter().collect(),
            )),
        ],
    );
    call.budget = Budget {
        max_bytes: 1 << 20,
        ..Budget::default()
    };
    let error = tool.invoke(0, &call).expect_err("the base is a fault");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");
}

/// A control character in the authority would inject a line into the request
/// head and into the handle's `Debug` (round 52, F-5).
#[test]
fn a_base_with_a_control_character_is_refused() {
    let mut tool =
        active_rpc::tool::HttpTool::new("http://127.0.0.1:9\r\nX-Injected: 1", &[("GET", "/x")]);
    let rendered = format!("{tool:?}");
    assert!(
        !rendered.contains("Injected"),
        "the head leaked: {rendered}"
    );
    let call = Call::new("get", vec![Arg::Value(Value::Path("/x".to_string()))]);
    let error = tool.invoke(0, &call).expect_err("the base is a fault");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");
}

/// The construction gate covers the whole base, scheme included, and refuses an
/// empty authority. `try_new` is the documented place a configuration fault is
/// caught, so a base it cannot render safely must not reach `Debug` or a socket
/// (round 53, M-1; round 53, L-2).
#[test]
fn try_new_refuses_a_base_it_could_not_render_safely() {
    for base in [
        "ht\rtp://host",
        "http\r\n://host",
        "http://ho st:9",
        "http://ex\u{00e4}mple.test",
        "http://",
        "http://:9",
        "://host",
        "ht:tp://host",
        "http://host/",
        // Shapes `perform` cannot reach: a permanently dead endpoint must not
        // surface as the retryable `http/resolve` class (round 54, M-1).
        "http://example.com",
        "http://host",
        "http://host:",
        "http://host:99999",
        "http://host:0",
        "http://user:pw@host:80",
        "http://user@host:80",
        "http://host:extra:80",
        "http://[::1:8080",
        "http://ho%73t:80",
        "http://999.999.999.999:80",
        "http://192.168.1:80",
        "http://1.2.3.4.5:80",
        "http://a..b:80",
        "http://-:80",
        "http://host:+80",
        "http://:80",
        "https://host:443",
        "ftp://host:21",
    ] {
        let error = active_rpc::tool::HttpTool::try_new(base, &[("GET", "/x")])
            .err()
            .unwrap_or_else(|| panic!("{base:?} was admitted"));
        assert_eq!(error.code(), "rpc/tool-policy", "{base:?}: {error}");
    }
    active_rpc::tool::HttpTool::try_new("http://127.0.0.1:9", &[("GET", "/x")])
        .expect("a plain base is admitted");
    // The scheme is matched case-insensitively and stored in the form `perform`
    // strips, so an upper-case operator value is not a dead endpoint.
    let upper = active_rpc::tool::HttpTool::try_new("HTTP://127.0.0.1:9", &[("GET", "/x")])
        .expect("an upper-case scheme is normalised");
    assert_eq!(upper.base(), "http://127.0.0.1:9");
    // A bracketed IPv6 literal is a host this adapter can reach.
    let v6 = active_rpc::tool::HttpTool::try_new("http://[::1]:9", &[("GET", "/x")])
        .expect("a bracketed IPv6 literal is admitted");
    assert_eq!(v6.base(), "http://[::1]:9");
}

/// A base that is refused at construction must also be refused at dispatch as a
/// policy fault: reporting `http/resolve` would invite a retry of a permanent
/// configuration error (round 54, M-1).
#[test]
fn an_unusable_base_is_a_policy_fault_and_never_a_resolve_fault() {
    for base in [
        "http://example.com",
        "http://user:pw@host:80",
        "https://host:443",
        "http://host:extra:80",
        "http://[::1:8080",
    ] {
        let mut tool = active_rpc::tool::HttpTool::new(base, &[("GET", "/x")]);
        let call = Call::new("get", vec![Arg::Value(Value::Path("/x".to_string()))]);
        let error = tool.invoke(0, &call).expect_err("the base is unusable");
        assert_eq!(error.code(), "rpc/tool-policy", "{base}: {error}");
        assert_eq!(tool.base(), "", "{base} kept an authority it cannot use");
    }
}

/// A control character before `://` is dropped at construction, so it can never
/// forge a `Debug` line (round 53, M-1).
#[test]
fn a_forged_base_never_reaches_debug() {
    let tool = active_rpc::tool::HttpTool::new("http\r\nX-Injected: 1://host", &[("GET", "/x")]);
    let rendered = format!("{tool:?}");
    assert!(
        !rendered.contains("Injected"),
        "the head leaked: {rendered}"
    );
    assert!(
        !rendered.contains('\r') && !rendered.contains('\n'),
        "a control character reached Debug: {rendered:?}"
    );
}

/// A matrix parameter is not a dot segment but a container peer strips it
/// before resolving, so the allowlist would name another resource
/// (round 53, L-3).
#[test]
fn a_matrix_parameter_in_an_allowlist_path_is_refused() {
    for path in ["/users/..;/admin", "/x;/../admin", "/a;b"] {
        let error = active_rpc::tool::HttpTool::try_new("http://127.0.0.1:9", &[("GET", path)])
            .err()
            .unwrap_or_else(|| panic!("{path} was admitted"));
        assert_eq!(error.code(), "rpc/tool-policy", "{path}: {error}");

        // `new` drops the entry: a dead entry is safer than a silently widened
        // one.
        let mut tool = active_rpc::tool::HttpTool::new("http://127.0.0.1:9", &[("GET", path)]);
        let call = Call::new("get", vec![Arg::Value(Value::Path(path.to_string()))]);
        let error = tool
            .invoke(0, &call)
            .expect_err("the entry is not on the allowlist");
        assert_eq!(error.code(), "rpc/tool-policy", "{path}: {error}");
    }
}
