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
    assert_eq!(code(session), "mcp/bad-response");
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
    let result = session.invoke(0, &Call::new("read", Vec::new()));
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
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
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
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
    let list = tool_list_response(r#"[{"name":"read\u202Epyf"}]"#);
    let session = McpSession::handshake(Scripted::new(&[initialize, list.as_str()]));
    assert_eq!(code(session), "mcp/tool-name");
}

#[test]
fn a_tool_name_with_a_control_character_is_refused() {
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
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
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
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
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
    let list = tool_list_response(r#"[{"name":"read"},{"name":"read"}]"#);
    let session = McpSession::handshake(Scripted::new(&[initialize, list.as_str()]));
    assert_eq!(code(session), "mcp/tool-name");
}

#[test]
fn a_tool_description_is_capped_and_stripped_of_control_characters() {
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
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
    let result = session.invoke(0, &Call::new("read", Vec::new()));
    assert_eq!(code(result), "mcp/id-mismatch");
}

#[test]
fn an_ordinary_tool_name_still_passes() {
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
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
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
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
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
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
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
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
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
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

    let result = session.invoke(0, &Call::new("read", Vec::new()));
    assert_eq!(code(result), "mcp/desync");
    let result = session.invoke(0, &Call::new("read", Vec::new()));
    assert_eq!(code(result), "mcp/desync", "the session must stay poisoned");
}

/// The bound is inclusive: exactly `MAX_MCP_NOTIFICATIONS` notifications are
/// skipped and the answer that follows is accepted.
#[test]
fn exactly_the_notification_ceiling_is_skipped() {
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
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
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
    let list = tool_list_response(r#"[{"name":"read"}]"#);
    let request = r#"{"jsonrpc":"2.0","id":5,"method":"sampling/createMessage","params":{}}"#;
    let mut session =
        McpSession::handshake(Scripted::new(&[initialize, &list, request])).expect("handshake");
    let result = session.invoke(0, &Call::new("read", Vec::new()));
    assert_eq!(code(result), "mcp/id-mismatch");
    let result = session.invoke(0, &Call::new("read", Vec::new()));
    assert_eq!(code(result), "mcp/desync", "the session must stay poisoned");
}

/// A framing fault poisons the session: the stream no longer lines up, so the
/// next line may answer a request that was already abandoned.
#[test]
fn a_framing_fault_poisons_the_session() {
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
    let list = tool_list_response(r#"[{"name":"read"}]"#);
    let garbage = "not a json line";
    let mut session =
        McpSession::handshake(Scripted::new(&[initialize, &list, garbage])).expect("handshake");
    let result = session.invoke(0, &Call::new("read", Vec::new()));
    assert_eq!(code(result), "mcp/bad-response");
    let result = session.invoke(0, &Call::new("read", Vec::new()));
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
    assert_eq!(code(result), "rpc/timeout");
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

    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
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
