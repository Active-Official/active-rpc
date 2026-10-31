//! Malicious MCP adapter suite.
//!
//! Every hostile JSON-RPC sequence must fail closed with an `mcp/...` code:
//! no panic, no unbounded buffering, and no accepting an answer meant for a
//! different request.

use std::collections::VecDeque;

use active_rpc::error::Error;
use active_rpc::kernel::Provider;
use active_rpc::tool::{McpSession, McpTransport, MAX_MCP_LINE_BYTES};
use active_rpc::value::{Call, Response, Value};

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
    assert_eq!(code(session), "mcp/initialize");
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
fn a_hostile_tool_list_does_not_break_the_handshake() {
    let initialize = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
    let hostile = r#"{"jsonrpc":"2.0","id":2,"result":{"tools":"not an array"}}"#;
    let session = McpSession::handshake(Scripted::new(&[initialize, hostile])).expect("handshake");
    assert!(session.tools().is_empty());
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
