//! Malicious MCP adapter suite.
//!
//! Every hostile JSON-RPC sequence must fail closed with an `mcp/...` code:
//! no panic, no unbounded buffering, and no accepting an answer meant for a
//! different request.

use std::collections::VecDeque;

use active_rpc::error::Error;
use active_rpc::kernel::Provider;
use active_rpc::tool::{McpSession, McpTransport, MAX_MCP_LINE_BYTES};
use active_rpc::value::{Arg, Call, Response, Value};

struct Scripted {
    queue: VecDeque<String>,
    sent: Vec<String>,
}

impl Scripted {
    fn new(lines: &[&str]) -> Self {
        Self {
            queue: lines.iter().map(|line| line.to_string()).collect(),
            sent: Vec::new(),
        }
    }
}

impl McpTransport for Scripted {
    fn send_line(&mut self, line: &str) -> active_rpc::Result<()> {
        self.sent.push(line.to_string());
        Ok(())
    }

    fn recv_line(&mut self) -> active_rpc::Result<String> {
        self.queue.pop_front().ok_or(Error::Provider {
            code: "mcp/no-response".to_string(),
        })
    }
}

fn code<T>(result: active_rpc::Result<T>) -> String {
    match result {
        Ok(_) => panic!("hostile MCP input was accepted"),
        Err(Error::Provider { code }) => code,
        Err(error) => error.code().to_string(),
    }
}

#[test]
fn non_json_line_is_rejected() {
    let session = McpSession::handshake(Scripted::new(&["not json at all"]));
    assert_eq!(code(session), "mcp/bad-response");
}

#[test]
fn empty_line_is_rejected() {
    let session = McpSession::handshake(Scripted::new(&[""]));
    assert_eq!(code(session), "mcp/bad-response");
}

#[test]
fn a_response_for_another_request_is_rejected() {
    // The session sends id 1; a server answering id 99 is confused or hostile.
    let session =
        McpSession::handshake(Scripted::new(&[r#"{"jsonrpc":"2.0","id":99,"result":{}}"#]));
    assert_eq!(code(session), "mcp/id-mismatch");
}

#[test]
fn an_id_of_another_json_type_is_rejected() {
    // JSON-RPC allows string ids; this client sends integers, so an answer with
    // `"id":"1"` or `"id":1.0` is not the answer to the request.
    for id in [r#""1""#, "1.0", "null", "true", "-1"] {
        let line = format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{{}}}}"#);
        let session = McpSession::handshake(Scripted::new(&[line.as_str()]));
        assert_eq!(code(session), "mcp/id-mismatch", "id {id} was accepted");
    }
}

#[test]
fn a_response_without_result_or_error_is_rejected() {
    let session = McpSession::handshake(Scripted::new(&[r#"{"jsonrpc":"2.0","id":1}"#]));
    assert_eq!(code(session), "mcp/bad-response");
}

#[test]
fn a_json_scalar_is_not_a_response() {
    let session = McpSession::handshake(Scripted::new(&[r#""ok""#]));
    assert_eq!(code(session), "mcp/bad-response");
}

#[test]
fn an_error_on_initialize_is_refused() {
    let session = McpSession::handshake(Scripted::new(&[
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"nope"}}"#,
    ]));
    assert_eq!(code(session), "mcp/initialize:-32601");
}

#[test]
fn deeply_nested_json_is_rejected_without_a_stack_overflow() {
    let mut nested = String::new();
    for _ in 0..600 {
        nested.push('[');
    }
    nested.push('0');
    for _ in 0..600 {
        nested.push(']');
    }
    let line = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{nested}}}"#);
    let session = McpSession::handshake(Scripted::new(&[line.as_str()]));
    // A chain of arrays has no tokens: the depth scan names it before the
    // parse (round 51, finding 1).
    assert_eq!(code(session), "mcp/too-complex");
}

#[test]
fn an_oversized_line_is_rejected_before_it_is_parsed() {
    let mut line = String::with_capacity(MAX_MCP_LINE_BYTES + 16);
    line.push_str(r#"{"jsonrpc":"2.0","id":1,"result":""#);
    line.push_str(&"a".repeat(MAX_MCP_LINE_BYTES));
    line.push_str(r#""}"#);
    let session = McpSession::handshake(Scripted::new(&[line.as_str()]));
    assert_eq!(code(session), "mcp/line-too-long");
}

/// The cap is inclusive: a line of exactly `MAX_MCP_LINE_BYTES` bytes is a
/// legal answer, and one byte more is refused before parsing
/// (round 15, F-3).
#[test]
fn the_line_cap_is_inclusive_and_one_byte_over_is_refused() {
    let head = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"padding":""#;
    let tail = r#""}}"#;
    let fill = MAX_MCP_LINE_BYTES - head.len() - tail.len();
    let build = |padding: usize| format!("{head}{}{tail}", "a".repeat(padding));

    let exact = build(fill);
    assert_eq!(exact.len(), MAX_MCP_LINE_BYTES);
    // The padded line answers `initialize`; the list answers `tools/list`.
    let mut lines = vec![exact];
    lines.push(handshake_responses().1);
    // The padded initialize still parses: the cap is about size, not shape.
    let session = McpSession::handshake(Scripted::new(
        &lines.iter().map(String::as_str).collect::<Vec<_>>(),
    ));
    assert!(
        session.is_ok(),
        "an exact-cap line must be accepted: {:?}",
        session.err()
    );

    let over = build(fill + 1);
    assert_eq!(over.len(), MAX_MCP_LINE_BYTES + 1);
    let session = McpSession::handshake(Scripted::new(&[over.as_str()]));
    assert_eq!(code(session), "mcp/line-too-long");
}

fn handshake_responses() -> (String, String) {
    (
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{}}}"#
            .to_string(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read","description":"read a file"}]}}"#
            .to_string(),
    )
}

#[test]
fn a_tool_error_maps_to_an_mcp_code() {
    let (initialize, list) = handshake_responses();
    let mut session = McpSession::handshake(Scripted::new(&[
        initialize.as_str(),
        list.as_str(),
        r#"{"jsonrpc":"2.0","id":3,"error":{"code":-32000,"message":"denied"}}"#,
    ]))
    .expect("handshake");
    let call = Call::new("read", Vec::new());
    let result = session.invoke(0, &call);
    assert_eq!(code(result), "mcp/-32000");
}

#[test]
fn a_tool_response_without_a_result_is_rejected() {
    let (initialize, list) = handshake_responses();
    let mut session = McpSession::handshake(Scripted::new(&[
        initialize.as_str(),
        list.as_str(),
        r#"{"jsonrpc":"2.0","id":3}"#,
    ]))
    .expect("handshake");
    let mut call = Call::new("read", Vec::new());
    call.read_only = true;
    let result = session.invoke(0, &call);
    assert_eq!(code(result), "mcp/bad-response");
}

#[test]
fn a_tool_call_with_the_wrong_name_is_refused_before_the_wire() {
    let (initialize, list) = handshake_responses();
    let mut session = McpSession::handshake(Scripted::new(&[initialize.as_str(), list.as_str()]))
        .expect("handshake");
    let result = session.invoke(0, &Call::new("write", Vec::new()));
    assert_eq!(code(result), "rpc/method-not-granted");
}

#[test]
fn a_hostile_tool_list_is_refused() {
    // A handshake that answers no tool array is malformed: an empty session
    // hid it and looked usable (R-08 round 7, #2).
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#;
    let hostile = r#"{"jsonrpc":"2.0","id":2,"result":{"tools":"not an array"}}"#;
    let error = match McpSession::handshake(Scripted::new(&[initialize, hostile])) {
        Ok(_) => panic!("a non-array tool list is refused"),
        Err(error) => error,
    };
    assert_eq!(
        error.provider_code(),
        Some("mcp/tools"),
        "the refusal names the list fault: {error}"
    );
}

#[test]
fn tool_output_is_carried_as_a_value() {
    let (initialize, list) = handshake_responses();
    let mut session = McpSession::handshake(Scripted::new(&[
        initialize.as_str(),
        list.as_str(),
        r#"{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"ok"}]}}"#,
    ]))
    .expect("handshake");
    let response = session
        .invoke(0, &Call::new("read", Vec::new()))
        .expect("call");
    assert!(matches!(response, Response::Value(Value::Map(_))));
}

fn tool_list_response(names: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":2,"result":{{"tools":{names}}}}}"#)
}

#[test]
fn a_tool_name_with_a_bidi_override_is_refused() {
    // `read` + RIGHT-TO-LEFT OVERRIDE + `pyf` renders as `read` in a UI while
    // the allow-list entry is a different string.
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#;
    let list = tool_list_response(r#"[{"name":"read\u202Epyf"}]"#);
    let session = McpSession::handshake(Scripted::new(&[initialize, list.as_str()]));
    assert_eq!(code(session), "mcp/tool-name");
}

#[test]
fn a_tool_name_with_a_control_character_is_refused() {
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#;
    for name in [
        r#"na\u0000me"#,
        r#"line\nbreak"#,
        r#"tab\there"#,
        r#"spa ce"#,
    ] {
        let list = tool_list_response(&format!(r#"[{{"name":"{name}"}}]"#));
        let session = McpSession::handshake(Scripted::new(&[initialize, list.as_str()]));
        assert_eq!(code(session), "mcp/tool-name", "name {name} was accepted");
    }
}

#[test]
fn an_overlong_tool_name_is_refused() {
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#;
    let list = tool_list_response(&format!(
        r#"[{{"name":"{}"}}]"#,
        "a".repeat(active_rpc::tool::MAX_MCP_TOOL_NAME_BYTES + 1)
    ));
    let session = McpSession::handshake(Scripted::new(&[initialize, list.as_str()]));
    assert_eq!(code(session), "mcp/tool-name");
}

#[test]
fn duplicate_tool_names_are_refused() {
    // Two entries with one name make the allow-list ambiguous: the index
    // selects one entry and the name selects the other.
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#;
    let list = tool_list_response(r#"[{"name":"read"},{"name":"read"}]"#);
    let session = McpSession::handshake(Scripted::new(&[initialize, list.as_str()]));
    assert_eq!(code(session), "mcp/tool-name");
}

#[test]
fn a_tool_description_is_capped_and_stripped_of_control_characters() {
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#;
    let list = tool_list_response(&format!(
        r#"[{{"name":"read","description":"esc\u001b[31mred\u200F{}"}}]"#,
        "x".repeat(active_rpc::tool::MAX_MCP_DESCRIPTION_BYTES)
    ));
    let session =
        McpSession::handshake(Scripted::new(&[initialize, list.as_str()])).expect("handshake");
    let description = &session.tools()[0].description;
    assert!(
        description.len() <= active_rpc::tool::MAX_MCP_DESCRIPTION_BYTES,
        "description was not capped: {} bytes",
        description.len()
    );
    assert!(
        !description.chars().any(char::is_control),
        "control characters survived: {description:?}"
    );
    assert!(
        !description.contains('\u{200F}'),
        "a bidi override survived: {description:?}"
    );
    assert!(description.starts_with("esc [31mred "), "{description:?}");
}

#[test]
fn a_tool_call_response_for_another_request_is_refused() {
    let (initialize, list) = handshake_responses();
    let mut session = McpSession::handshake(Scripted::new(&[
        initialize.as_str(),
        list.as_str(),
        r#"{"jsonrpc":"2.0","id":99,"result":{"content":[]}}"#,
    ]))
    .expect("handshake");
    // The session sends id 3 for the tool call; a server answering 99 is not
    // answering this call.
    let mut call = Call::new("read", Vec::new());
    call.read_only = true;
    let result = session.invoke(0, &call);
    assert_eq!(code(result), "mcp/id-mismatch");
}

#[test]
fn an_ordinary_tool_name_still_passes() {
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#;
    let list = tool_list_response(r#"[{"name":"fs.read-file_2"}]"#);
    let session =
        McpSession::handshake(Scripted::new(&[initialize, list.as_str()])).expect("handshake");
    assert_eq!(session.tools().len(), 1);
    assert_eq!(session.tools()[0].name, "fs.read-file_2");
}

/// The cap counts bytes, so a multi-byte character must not be able to straddle
/// it and overshoot by its remaining bytes.
#[test]
fn a_multibyte_character_cannot_straddle_the_description_ceiling() {
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#;
    let prefix = "x".repeat(active_rpc::tool::MAX_MCP_DESCRIPTION_BYTES - 1);
    let list = tool_list_response(&format!(r#"[{{"name":"read","description":"{prefix}é"}}]"#));
    let session =
        McpSession::handshake(Scripted::new(&[initialize, list.as_str()])).expect("handshake");
    let description = &session.tools()[0].description;
    assert_eq!(
        description.len(),
        active_rpc::tool::MAX_MCP_DESCRIPTION_BYTES - 1,
        "the straddling character must be dropped, not truncated"
    );
    assert!(description.is_char_boundary(description.len()));
}

/// U+2028/U+2029 are separators, not control characters, and a log line splits
/// on `\n`/`\r` only: an unscrubbed one renders as two records.
#[test]
fn a_description_cannot_inject_a_line_separator() {
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#;
    let list = tool_list_response(
        r#"[{"name":"read","description":"ok\u2028fake record\u2029\u061C\u200B\uFEFF\u00AD"}]"#,
    );
    let session =
        McpSession::handshake(Scripted::new(&[initialize, list.as_str()])).expect("handshake");
    let description = &session.tools()[0].description;
    for separator in [
        '\u{2028}', '\u{2029}', '\u{061C}', '\u{200B}', '\u{FEFF}', '\u{00AD}',
    ] {
        assert!(
            !description.contains(separator),
            "U+{:04X} survived: {description:?}",
            separator as u32
        );
    }
    assert!(
        description.starts_with("ok fake record "),
        "the visible text is kept: {description:?}"
    );
}

/// A spec-compliant server sends notifications (`notifications/progress`,
/// `notifications/message`) between the request and its answer. Those frames
/// have no `id` and are not answers, so the session skips them.
#[test]
fn a_notification_before_the_response_is_skipped() {
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#;
    let list = tool_list_response(r#"[{"name":"read"}]"#);
    let note = r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}"#;
    let session = McpSession::handshake(Scripted::new(&[note, initialize, note, note, &list]))
        .expect("a notification is not a desync");
    assert_eq!(session.tools().len(), 1);
}

/// An unbounded stream of notifications is not an answer: the session fails
/// closed and stays poisoned, so a later answer cannot be attributed to a call
/// that was already abandoned.
#[test]
fn a_notification_stream_poisons_the_session() {
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#;
    let list = tool_list_response(r#"[{"name":"read"}]"#);
    let note = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{}}"#;
    let mut lines = vec![initialize.to_string(), list];
    for _ in 0..=active_rpc::tool::MAX_MCP_NOTIFICATIONS {
        lines.push(note.to_string());
    }
    // A well-formed answer that must never be read: after a desync the next
    // line may belong to a request already abandoned.
    lines.push(r#"{"jsonrpc":"2.0","id":3,"result":{"content":[]}}"#.to_string());
    let borrowed: Vec<&str> = lines.iter().map(String::as_str).collect();
    let mut session = McpSession::handshake(Scripted::new(&borrowed)).expect("handshake");

    let mut call = Call::new("read", Vec::new());
    call.read_only = true;
    let result = session.invoke(0, &call);
    assert_eq!(code(result), "mcp/desync");
    let result = session.invoke(0, &call);
    assert_eq!(code(result), "mcp/desync", "the session must stay poisoned");
}

/// The bound is inclusive: exactly `MAX_MCP_NOTIFICATIONS` notifications are
/// skipped and the answer that follows is accepted.
#[test]
fn exactly_the_notification_ceiling_is_skipped() {
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#;
    let list = tool_list_response(r#"[{"name":"read"}]"#);
    let note = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{}}"#;
    let mut lines = vec![initialize.to_string(), list];
    for _ in 0..active_rpc::tool::MAX_MCP_NOTIFICATIONS {
        lines.push(note.to_string());
    }
    lines.push(r#"{"jsonrpc":"2.0","id":3,"result":{"content":[]}}"#.to_string());
    let borrowed: Vec<&str> = lines.iter().map(String::as_str).collect();
    let mut session = McpSession::handshake(Scripted::new(&borrowed)).expect("handshake");
    let response = session
        .invoke(0, &Call::new("read", Vec::new()))
        .expect("the answer after the ceiling is accepted");
    assert!(matches!(response, Response::Value(Value::Map(_))));
}

/// A server-initiated request carries its own `id` and a `method`. It is not an
/// answer to anything this session sent, and skipping it would leave the server
/// waiting forever, so the session fails closed.
#[test]
fn a_server_request_poisons_the_session() {
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#;
    let list = tool_list_response(r#"[{"name":"read"}]"#);
    let request = r#"{"jsonrpc":"2.0","id":5,"method":"sampling/createMessage","params":{}}"#;
    let mut session =
        McpSession::handshake(Scripted::new(&[initialize, &list, request])).expect("handshake");
    let mut call = Call::new("read", Vec::new());
    call.read_only = true;
    let result = session.invoke(0, &call);
    assert_eq!(code(result), "mcp/id-mismatch");
    let result = session.invoke(0, &call);
    assert_eq!(code(result), "mcp/desync", "the session must stay poisoned");
}

/// A framing fault poisons the session: the stream no longer lines up, so the
/// next line may answer a request that was already abandoned.
#[test]
fn a_framing_fault_poisons_the_session() {
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#;
    let list = tool_list_response(r#"[{"name":"read"}]"#);
    let garbage = "not a json line";
    let mut session =
        McpSession::handshake(Scripted::new(&[initialize, &list, garbage])).expect("handshake");
    // A read-only call has no effect to withhold, so the answer's own code
    // survives (a writable one reports provider/reply-withheld).
    let mut call = Call::new("read", Vec::new());
    call.read_only = true;
    let result = session.invoke(0, &call);
    assert_eq!(code(result), "mcp/bad-response");
    let result = session.invoke(0, &call);
    assert_eq!(code(result), "mcp/desync");
}

/// A transport that records what it was asked to send.
struct Spy {
    sent: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
}

impl McpTransport for Spy {
    fn send_line(&mut self, line: &str) -> active_rpc::Result<()> {
        self.sent.borrow_mut().push(line.to_string());
        Ok(())
    }

    fn recv_line(&mut self) -> active_rpc::Result<String> {
        Err(Error::Provider {
            code: "spy/empty".to_string(),
        })
    }
}

/// An already-expired deadline must refuse the call before the frame leaves:
/// once it is sent, the server can act and the refusal is a lie.
#[test]
fn an_expired_deadline_sends_no_frame() {
    let sent = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let transport = Spy { sent: sent.clone() };
    let result = McpSession::handshake_within(transport, Some(std::time::Instant::now()));
    // Nothing was written, and the code says so (round 35, N3).
    assert_eq!(code(result), "mcp/not-sent");
    assert!(
        sent.borrow().is_empty(),
        "a frame was sent: {:?}",
        sent.borrow()
    );
}

/// `has_method` answers from the stored table instead of cloning every name on
/// every admitted call.
#[test]
fn has_method_does_not_rebuild_the_method_table() {
    use active_rpc::kernel::Provider;

    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#;
    let count = active_rpc::tool::MAX_MCP_TOOLS;
    let mut tools = String::from("[");
    for index in 0..count {
        if index > 0 {
            tools.push(',');
        }
        tools.push_str(&format!(r#"{{"name":"tool{index}"}}"#));
    }
    tools.push(']');
    let list = tool_list_response(&tools);
    let session =
        McpSession::handshake(Scripted::new(&[initialize, list.as_str()])).expect("handshake");
    let last = format!("tool{}", count - 1);
    let started = std::time::Instant::now();
    for _ in 0..1_000 {
        assert!(session.has_method(&last));
        assert!(!session.has_method("missing"));
    }
    let elapsed = started.elapsed();
    assert!(
        // A quadratic scan takes tens of seconds at this size; 1 s still
        // separates the two on a loaded machine.
        elapsed < std::time::Duration::from_secs(1),
        "2 000 membership checks over {count} tools took {elapsed:?}"
    );
}

/// A frame that reuses our id but carries a `method` is a server-initiated
/// request, not the answer to our call (round 18, L-3).
#[test]
fn a_server_request_with_our_id_is_not_an_answer() {
    let (initialize, list) = handshake_responses();
    let response = r#"{"jsonrpc":"2.0","id":3,"method":"sampling/createMessage","result":{}}"#;
    let mut session = McpSession::handshake(Scripted::new(&[
        initialize.as_str(),
        list.as_str(),
        response,
    ]))
    .expect("handshake");
    let mut call = Call::new("read", vec![Arg::text("x")]);
    call.tool_allows_process = true;
    call.read_only = true;
    let error = Provider::invoke(&mut session, 0, &call).expect_err("a request is not an answer");
    assert_eq!(error.provider_code(), Some("mcp/id-mismatch"), "{error}");
}

/// A failed `tools/list` keeps the server pair's code, as `initialize` does
/// (round 18, L-4).
#[test]
fn a_tools_list_error_keeps_the_server_code() {
    let (initialize, _) = handshake_responses();
    let list = r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"nope"}}"#;
    let session = McpSession::handshake(Scripted::new(&[initialize.as_str(), list]));
    assert_eq!(code(session), "mcp/-32000");
}

/// The byte grant bounds the MCP line the adapter buffers for a call
/// (round 19, M2).
#[test]
fn an_answer_past_the_byte_grant_is_refused() {
    let (initialize, list) = handshake_responses();
    let response = r#"{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"ok"}]}}"#;
    let mut session = McpSession::handshake(Scripted::new(&[
        initialize.as_str(),
        list.as_str(),
        response,
    ]))
    .expect("handshake");
    let mut call = Call::new("read", vec![Arg::Value(Value::Int(1))]);
    call.tool_allows_process = true;
    call.budget.max_bytes = 8;
    let error = Provider::invoke(&mut session, 0, &call).expect_err("past the grant");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

/// A tool name made only of dots is a path segment with a tool name on: the
/// handshake refuses it (round 38, #6).
#[test]
fn a_dot_only_tool_name_is_refused() {
    use active_rpc::tool::{McpSession, McpTransport};

    struct Scripted {
        replies: std::cell::RefCell<Vec<String>>,
    }
    impl McpTransport for Scripted {
        fn send_line(&mut self, _line: &str) -> active_rpc::error::Result<()> {
            Ok(())
        }
        fn recv_line(&mut self) -> active_rpc::error::Result<String> {
            let reply = self.replies.borrow_mut().remove(0);
            Ok(reply)
        }
    }

    let session = McpSession::handshake(Scripted {
        replies: std::cell::RefCell::new(vec![
            r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"stub"}}}"#
                .to_string(),
            r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"..","description":"x"}]}}"#
                .to_string(),
        ]),
    });
    let error = match session {
        Ok(_) => panic!("a dot-only tool name is not a tool"),
        Err(error) => error,
    };
    // The provider class alone would pass for any handshake fault; the inner
    // code is what this test is about (round 39, F5).
    assert_eq!(error.provider_code(), Some("mcp/tool-name"), "{error}");
}

/// The static line ceiling is a protocol limit: a line past it is
/// `mcp/line-too-long` whatever the grant, and the session is poisoned
/// (round 39, F1 — the rule is deliberate, and this pins it).
#[test]
fn a_line_past_the_static_ceiling_is_illegal_whatever_the_grant() {
    use active_rpc::tool::{McpSession, McpTransport, MemoryTransport};

    struct Huge {
        inner: MemoryTransport,
        replies: usize,
    }
    impl McpTransport for Huge {
        fn send_line(&mut self, line: &str) -> active_rpc::error::Result<()> {
            self.inner.send_line(line)
        }
        fn recv_line(&mut self) -> active_rpc::error::Result<String> {
            self.inner.recv_line()
        }
        fn recv_line_within(
            &mut self,
            deadline: Option<std::time::Instant>,
        ) -> active_rpc::error::Result<String> {
            self.replies += 1;
            if self.replies <= 2 {
                return self.inner.recv_line_within(deadline);
            }
            Ok(format!(
                r#"{{"jsonrpc":"2.0","id":3,"result":"{}"}}"#,
                "x".repeat(2 << 20)
            ))
        }
    }

    let mut responses = std::collections::BTreeMap::new();
    responses.insert(
        "initialize".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"stub"}}}"#
            .to_string(),
    );
    responses.insert(
        "tools/list".to_string(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echo"}]}}"#
            .to_string(),
    );
    let mut session = McpSession::handshake(Huge {
        inner: MemoryTransport::new(responses),
        replies: 0,
    })
    .expect("handshake");
    let mut call = Call::new("echo", vec![Arg::Value(Value::Int(1))]);
    call.tool_allows_process = true;
    // Enough for the request line, far less than the answer: the static
    // ceiling is what refuses, and it is a protocol limit regardless.
    call.budget.max_bytes = 200;
    let error = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect_err("past the static ceiling");
    // The request left, so a writable call reports a withheld reply; the
    // session is poisoned either way (round 42, H-1/M-1).
    assert_eq!(
        error.provider_code(),
        Some("provider/reply-withheld"),
        "{error}"
    );
    let again = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect_err("the session is poisoned");
    assert_eq!(again.provider_code(), Some("mcp/desync"), "{again}");
}

/// A writable MCP call whose answer cannot be accepted reports a withheld reply:
/// the peer may have run the tool, so the class must not invite a retry, and the
/// session is dead because the refused frame may have been a notification with
/// the answer still queued (round 42, H-1 and M-1).
#[test]
fn a_writable_call_with_a_refused_answer_withholds_the_reply() {
    use active_rpc::tool::{McpSession, MemoryTransport};

    let mut responses = std::collections::BTreeMap::new();
    responses.insert(
        "initialize".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#.to_string(),
    );
    responses.insert(
        "tools/list".to_string(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"write","description":"x"}]}}"#
            .to_string(),
    );
    responses.insert("tools/call".to_string(), "x".repeat(4_096));
    let mut session = McpSession::handshake(MemoryTransport::new(responses)).expect("handshake");
    let mut call = Call::new("write", vec![Arg::Value(Value::Int(1))]);
    call.budget.max_bytes = 2_048;
    let error = Provider::invoke(&mut session, 0, &call).expect_err("the answer is past the grant");
    assert_eq!(
        error.provider_code(),
        Some("provider/reply-withheld"),
        "{error}"
    );
    let again = Provider::invoke(&mut session, 0, &call).expect_err("the session is poisoned");
    assert_eq!(again.provider_code(), Some("mcp/desync"), "{again}");
}

/// A closed writer never took the frame: the session is poisoned, but the call
/// is not reported as a withheld reply, so an idempotency key is not burned for
/// an effect that cannot exist (round 44, L-7; round 45, finding 6).
#[test]
fn a_closed_writer_does_not_claim_the_effect() {
    use active_rpc::error::Error as RpcError;
    use active_rpc::tool::{McpSession, McpTransport};

    struct Closed {
        queue: std::collections::VecDeque<String>,
        sends: usize,
    }
    impl McpTransport for Closed {
        fn send_line(&mut self, _line: &str) -> active_rpc::error::Result<()> {
            Ok(())
        }
        fn recv_line(&mut self) -> active_rpc::error::Result<String> {
            self.queue.pop_front().ok_or(RpcError::Provider {
                code: "mcp/no-response".to_string(),
            })
        }
        fn send_line_within(
            &mut self,
            _line: &str,
            _deadline: Option<std::time::Instant>,
        ) -> active_rpc::error::Result<()> {
            self.sends += 1;
            // The two handshake lines go out; the tool call meets a dead writer.
            if self.sends <= 3 {
                return Ok(());
            }
            Err(RpcError::Provider {
                code: "mcp/write:closed".to_string(),
            })
        }
    }

    let mut queue = std::collections::VecDeque::new();
    queue.push_back(
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#.to_string(),
    );
    queue.push_back(
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"x"}]}}"#
            .to_string(),
    );
    let mut session = McpSession::handshake(Closed { queue, sends: 0 }).expect("handshake");
    let mut call = Call::new("echo", vec![Arg::Value(Value::Int(1))]);
    call.budget.max_bytes = 1 << 20;
    let error = Provider::invoke(&mut session, 0, &call).expect_err("the writer is closed");
    assert_eq!(error.provider_code(), Some("mcp/write:closed"), "{error}");
    // The session is dead; the next call says so rather than claiming an effect.
    let again = Provider::invoke(&mut session, 0, &call).expect_err("the session is poisoned");
    assert_eq!(again.provider_code(), Some("mcp/desync"), "{again}");
}

/// A frame the writer took and then lost is a withheld reply for a writable
/// call, while a read-only call keeps the code: the idempotency key is spent
/// only when an effect could stand (round 47, L-3).
#[test]
fn a_lost_write_ack_is_withheld_only_for_a_writable_call() {
    use active_rpc::error::Error as RpcError;
    use active_rpc::tool::{McpSession, McpTransport};

    struct Lost {
        queue: std::collections::VecDeque<String>,
        sends: usize,
    }
    impl McpTransport for Lost {
        fn send_line(&mut self, _line: &str) -> active_rpc::error::Result<()> {
            Ok(())
        }
        fn recv_line(&mut self) -> active_rpc::error::Result<String> {
            self.queue.pop_front().ok_or(RpcError::Provider {
                code: "mcp/no-response".to_string(),
            })
        }
        fn send_line_within(
            &mut self,
            _line: &str,
            _deadline: Option<std::time::Instant>,
        ) -> active_rpc::error::Result<()> {
            self.sends += 1;
            if self.sends <= 3 {
                return Ok(());
            }
            Err(RpcError::Provider {
                code: "mcp/write:lost".to_string(),
            })
        }
    }

    fn session() -> McpSession<Lost> {
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(
            r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#.to_string(),
        );
        queue.push_back(
            r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"x"}]}}"#
                .to_string(),
        );
        McpSession::handshake(Lost { queue, sends: 0 }).expect("handshake")
    }

    let mut writable = session();
    let mut call = Call::new("echo", vec![Arg::Value(Value::Int(1))]);
    call.budget.max_bytes = 1 << 20;
    let error = Provider::invoke(&mut writable, 0, &call).expect_err("the writer died");
    assert_eq!(
        error.provider_code(),
        Some("provider/reply-withheld"),
        "{error}"
    );

    let mut read_only = session();
    call.read_only = true;
    let error = Provider::invoke(&mut read_only, 0, &call).expect_err("the writer died");
    assert_eq!(error.provider_code(), Some("mcp/write:lost"), "{error}");
}
