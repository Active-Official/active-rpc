//! R-08 round 57: numeric hosts beyond decimal, the MCP lifecycle notification,
//! poisoning on a malformed error code, and an allowlist that cannot be widened
//! after construction.

use std::cell::RefCell;
use std::rc::Rc;

use active_rpc::budget::Budget;
use active_rpc::kernel::Provider;
use active_rpc::tool::{HttpTool, McpSession, McpTransport};
use active_rpc::value::{Arg, Call, Value};
use active_rpc::Error;

/// Every base shape the adapter cannot reach, at construction and at dispatch.
const UNUSABLE: &[&str] = &[
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
    "ftp://host:21",
    "http://0x7f.0.0.1:8080",
    "http://0x7f000001:8080",
    "http://",
    "://host",
    "ht:tp://host",
    "http://host/",
];

#[test]
fn every_unusable_base_is_refused_at_both_ends() {
    for base in UNUSABLE {
        let error = HttpTool::try_new(*base, &[("GET", "/x")])
            .err()
            .unwrap_or_else(|| panic!("{base:?} was admitted"));
        assert_eq!(error.code(), "rpc/tool-policy", "{base:?}: {error}");

        let mut tool = HttpTool::new(*base, &[("GET", "/x")]);
        assert_eq!(tool.base(), "", "{base:?} kept an authority");
        let call = Call::new("get", vec![Arg::Value(Value::Path("/x".to_string()))]);
        let error = tool
            .invoke(0, &call)
            .expect_err("the base is unusable at dispatch too");
        assert_eq!(error.code(), "rpc/tool-policy", "{base:?}: {error}");
    }
    // A real numeric literal and a DNS name are still admitted.
    // `https://` bases are admitted too (RPC-38): the adapter speaks TLS
    // with operator-pinned roots, so `https://host:443` left the
    // unusable list above. Only when the feature compiled the TLS stack
    // in: without it an `https://` base is still refused at construction,
    // exactly as before TLS existed (pinned by the no-feature lib test).
    for base in [
        "http://127.0.0.1:9",
        "http://[::1]:9",
        "http://api.internal:8080",
    ] {
        HttpTool::try_new(base, &[("GET", "/x")]).unwrap_or_else(|error| panic!("{base}: {error}"));
    }
    #[cfg(feature = "http-tls")]
    for base in ["https://127.0.0.1:443", "https://api.internal:8443"] {
        HttpTool::try_new(base, &[("GET", "/x")]).unwrap_or_else(|error| panic!("{base}: {error}"));
    }
}

/// Without http-tls, an https:// base is still refused at construction:
/// the build cannot speak TLS, exactly as before TLS existed (RPC-38,
/// CI-FIX-RPC-11: pins the no-feature side of scheme_supported).
#[test]
#[cfg(not(feature = "http-tls"))]
fn https_base_is_refused_without_tls() {
    for base in ["https://127.0.0.1:443", "https://api.internal:8443"] {
        let error = HttpTool::try_new(base, &[("GET", "/x")])
            .err()
            .unwrap_or_else(|| panic!("{base} was admitted without the http-tls feature"));
        assert_eq!(error.code(), "rpc/tool-policy", "{base}: {error}");
    }
}

/// A long authority is named by its length, not printed whole (round 57, L-5).
#[test]
fn a_long_authority_is_not_printed_whole() {
    // Four labels of 60 bytes: a legal DNS name whose authority is long enough
    // to be cut.
    let label = "a".repeat(60);
    let host = format!("{label}.{label}.{label}.{label}");
    let tool = HttpTool::new(format!("http://{host}:80"), &[("GET", "/x")]);
    let rendered = format!("{tool:?}");
    let authority = host.len() + 3;
    assert!(
        rendered.contains(&format!("<{authority} bytes>")),
        "{rendered}"
    );
    assert!(!rendered.contains(&label), "the host leaked whole");
}

/// The allowlist is the tool's authority: an entry added after construction
/// still passes the ambiguity gate (round 57, L-4).
#[test]
fn an_entry_added_later_is_still_gated() {
    let mut tool = HttpTool::new("http://127.0.0.1:9", &[("GET", "/a")]);
    let error = tool
        .allow_path("POST", "/users/..;/admin")
        .expect_err("ambiguous");
    assert_eq!(error.code(), "rpc/tool-policy");
    tool.allow_path("POST", "/b").expect("a plain path");
    assert_eq!(tool.max_body(), 1 << 20);
    let tool = tool.with_max_body(64).with_max_request(32);
    assert_eq!(tool.max_body(), 64);
    assert_eq!(tool.max_request(), 32);
}

/// A transport that records what it was sent and answers from a queue.
struct Recorder {
    sent: Rc<RefCell<Vec<String>>>,
    answers: Vec<String>,
}

impl McpTransport for Recorder {
    fn send_line(&mut self, line: &str) -> Result<(), Error> {
        self.sent.borrow_mut().push(line.to_string());
        Ok(())
    }

    fn recv_line(&mut self) -> Result<String, Error> {
        if self.answers.is_empty() {
            return Err(Error::Provider {
                code: "mcp/no-response".to_string(),
            });
        }
        Ok(self.answers.remove(0))
    }
}

fn recorder(answers: Vec<&str>) -> (Recorder, Rc<RefCell<Vec<String>>>) {
    let sent = Rc::new(RefCell::new(Vec::new()));
    (
        Recorder {
            sent: Rc::clone(&sent),
            answers: answers.into_iter().map(str::to_string).collect(),
        },
        sent,
    )
}

/// MCP 2025-06-18: the client confirms the lifecycle, so a server that enforces
/// it will serve `tools/list` (round 57, L-6).
#[test]
fn the_handshake_confirms_the_lifecycle() {
    let (transport, sent) = recorder(vec![
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#,
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}"#,
    ]);
    let session = McpSession::handshake(transport).expect("handshake");
    assert!(session.tools().is_empty());
    let lines = sent.borrow();
    assert_eq!(lines.len(), 3, "{lines:?}");
    let notification: serde_json::Value = serde_json::from_str(&lines[1]).expect("a JSON line");
    assert_eq!(notification["method"], "notifications/initialized");
    assert!(notification.get("id").is_none(), "a notification has no id");
}

/// An `error` without an integer code poisons the session: the frame was
/// consumed, but its shape broke the contract (round 57, L-3).
#[test]
fn a_malformed_error_code_poisons_the_session() {
    let (transport, _sent) = recorder(vec![
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#,
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo"}]}}"#,
        r#"{"jsonrpc":"2.0","id":3,"error":{"message":"no code"}}"#,
        r#"{"jsonrpc":"2.0","id":4,"result":{"content":[]}}"#,
    ]);
    let mut session = McpSession::handshake(transport).expect("handshake");
    let mut call = Call::new("echo", vec![Arg::Value(Value::Int(1))]);
    call.read_only = true;
    call.budget = Budget::default();
    let error = session.invoke(0, &call).expect_err("the code is missing");
    assert_eq!(error.provider_code(), Some("mcp/bad-response"), "{error}");
    let again = session
        .invoke(0, &call)
        .expect_err("the session is poisoned");
    assert_eq!(again.provider_code(), Some("mcp/desync"), "{again}");
}

/// A tool list with duplicate names is refused, and the handshake is over.
#[test]
fn a_duplicate_tool_name_refuses_the_handshake() {
    let (transport, _sent) = recorder(vec![
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#,
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo"},{"name":"echo"}]}}"#,
    ]);
    let error = match McpSession::handshake(transport) {
        Ok(_) => panic!("a duplicate tool name must refuse the handshake"),
        Err(error) => error,
    };
    assert_eq!(error.provider_code(), Some("mcp/tool-name"), "{error}");
}

/// A handshake whose `initialize` result is not an object is malformed.
#[test]
fn a_non_object_initialize_result_is_refused() {
    let (transport, _sent) = recorder(vec![r#"{"jsonrpc":"2.0","id":1,"result":7}"#]);
    let error = match McpSession::handshake(transport) {
        Ok(_) => panic!("a non-object initialize result must be refused"),
        Err(error) => error,
    };
    assert_eq!(error.provider_code(), Some("mcp/bad-response"), "{error}");
}

/// A server on another protocol version is refused before the lifecycle
/// notification is sent (round 59, L-1).
#[test]
fn a_server_on_another_protocol_version_is_refused() {
    let (transport, sent) = recorder(vec![
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05"}}"#,
    ]);
    let error = match McpSession::handshake(transport) {
        Ok(_) => panic!("an older version must be refused"),
        Err(error) => error,
    };
    assert_eq!(error.provider_code(), Some("mcp/bad-response"), "{error}");
    assert_eq!(sent.borrow().len(), 1, "the notification was sent anyway");
}

/// The lifecycle notification travels with the handshake deadline: a transport
/// whose deadline-free `send_line` is unusable must not be used for it
/// (round 59, L-3).
#[test]
fn the_notification_carries_the_handshake_deadline() {
    struct DeadlineOnly {
        answers: Vec<String>,
        deadlines: Rc<RefCell<Vec<Option<std::time::Instant>>>>,
    }
    impl McpTransport for DeadlineOnly {
        fn send_line(&mut self, _line: &str) -> Result<(), Error> {
            panic!("the deadline-free send was used");
        }
        fn recv_line(&mut self) -> Result<String, Error> {
            Ok(self.answers.remove(0))
        }
        fn send_line_within(
            &mut self,
            _line: &str,
            deadline: Option<std::time::Instant>,
        ) -> Result<(), Error> {
            self.deadlines.borrow_mut().push(deadline);
            Ok(())
        }
    }
    let deadlines = Rc::new(RefCell::new(Vec::new()));
    let transport = DeadlineOnly {
        answers: vec![
            r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#.to_string(),
            r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}"#.to_string(),
        ],
        deadlines: Rc::clone(&deadlines),
    };
    McpSession::handshake(transport).expect("handshake");
    let seen = deadlines.borrow();
    assert_eq!(seen.len(), 3, "init, notification and tools/list");
    assert!(
        seen.iter().all(|deadline| deadline.is_some()),
        "a frame was sent without a deadline"
    );
}

/// The DNS bounds are exact (round 59, L-3).
#[test]
fn the_dns_bounds_are_exact() {
    let long_name = format!("{}:80", "a".repeat(254));
    assert!(
        HttpTool::try_new(format!("http://{long_name}"), &[("GET", "/x")]).is_err(),
        "a 254-byte name is refused"
    );
    let long_label = format!("{}:80", "a".repeat(64));
    assert!(
        HttpTool::try_new(format!("http://{long_label}"), &[("GET", "/x")]).is_err(),
        "a 64-byte label is refused"
    );
    let ok_label = format!("{}:80", "a".repeat(63));
    HttpTool::try_new(format!("http://{ok_label}"), &[("GET", "/x")])
        .expect("a 63-byte label is a legal name");
}

/// A `tools/call` result that is not an object poisons the session
/// (round 59, L-3).
#[test]
fn a_non_object_call_result_poisons() {
    let (transport, _sent) = recorder(vec![
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#,
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo"}]}}"#,
        r#"{"jsonrpc":"2.0","id":3,"result":"ok"}"#,
    ]);
    let mut session = McpSession::handshake(transport).expect("handshake");
    let mut call = Call::new("echo", vec![Arg::Value(Value::Int(1))]);
    call.read_only = true;
    call.budget = Budget::default();
    let error = session
        .invoke(0, &call)
        .expect_err("a string result is malformed");
    assert_eq!(error.provider_code(), Some("mcp/bad-response"), "{error}");
    let again = session
        .invoke(0, &call)
        .expect_err("the session is poisoned");
    assert_eq!(again.provider_code(), Some("mcp/desync"), "{again}");
}

/// A declared length past `usize` is the static ceiling, not a framing fault
/// (round 60, L-1).
#[test]
fn a_declared_length_past_usize_is_the_static_ceiling() {
    use active_rpc::cap::CapId;
    use std::io::Write;
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buffer = [0u8; 1024];
            let _ = std::io::Read::read(&mut stream, &mut buffer);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 18446744073709551616\r\nconnection: close\r\n\r\n",
            );
            let _ = stream.flush();
        }
    });
    let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/huge")]);
    let mut call = Call::new("get", vec![Arg::Value(Value::Path("/huge".to_string()))]);
    call.read_only = true;
    call.budget = Budget {
        max_bytes: 1 << 20,
        ..Budget::default()
    };
    let _ = CapId([0; 16]);
    let error = tool
        .invoke(0, &call)
        .expect_err("the length is past every ceiling");
    assert_eq!(
        error.provider_code(),
        Some("http/body-too-large"),
        "{error}"
    );
}

/// A grant that cannot hold even an empty answer refuses before the wire
/// (round 60, L-2).
#[test]
fn a_grant_that_cannot_hold_an_answer_is_refused_before_the_wire() {
    fn session() -> (McpSession<Recorder>, Rc<RefCell<Vec<String>>>) {
        let (transport, sent) = recorder(vec![
            r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#,
            r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo"}]}}"#,
            r#"{"jsonrpc":"2.0","id":3,"result":{"content":[]}}"#,
        ]);
        (McpSession::handshake(transport).expect("handshake"), sent)
    }

    // Learn the request line length from a generous grant.
    let (mut probe, sent) = session();
    let mut call = Call::new("echo", vec![Arg::text("x".repeat(64))]);
    call.read_only = true;
    call.budget = Budget {
        max_bytes: 1 << 20,
        ..Budget::default()
    };
    probe.invoke(0, &call).expect("the call runs");
    let line_len = sent.borrow().last().expect("the request line").len() as u64;

    // One byte past the line leaves no room for an answer.
    let (mut session, sent) = session();
    let mut tight = Call::new("echo", vec![Arg::text("x".repeat(64))]);
    tight.read_only = true;
    tight.budget = Budget {
        max_bytes: line_len + 1,
        ..Budget::default()
    };
    let error = session
        .invoke(0, &tight)
        .expect_err("no room for the answer");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    assert_eq!(sent.borrow().len(), 3, "only the handshake was sent");
}
