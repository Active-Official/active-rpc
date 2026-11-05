//! Tool handles: MCP sessions, HTTP/OpenAPI endpoints, local processes.
//!
//! Tools are capabilities like everything else, which means a tool handle
//! inherits the same guarantees: no ambient authority, attenuation-only
//! narrowing, budget accounting and drop notification.
//!
//! | Adapter | What it talks to |
//! |---------|------------------|
//! | [`McpSession`] | an MCP server, over an injected line transport (stdio or in-memory) |
//! | [`HttpTool`] | an HTTP endpoint restricted to an allowlist of `METHOD path` pairs |
//! | [`LocalProcess`] | a sandboxed child process: allowlisted program, no shell, scrubbed environment |
//!
//! Every adapter returns a [`Response::Value`] built from JSON, never a raw
//! string dump, and every adapter refuses a call outside its policy with
//! `rpc/tool-policy`.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use serde_json::{json, Value as Json};

use crate::cap::ToolPolicy;
use crate::error::{Error, Result};
use crate::kernel::Provider;
use crate::value::Response;
use crate::value::{Arg, Call, Value};

/// Whether a JSON text has more structural tokens than the adapter will parse.
///
/// `serde_json` allocates the whole tree before any post-parse check can run,
/// so the node ceiling has to be enforced on the text: counting the separators
/// outside strings is O(bytes), allocation-free, and exceeds the node count
/// (each element or field costs at least one) (round 14, F-2).
pub fn json_text_too_complex(text: &str, limit: usize) -> bool {
    let mut tokens = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for byte in text.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b',' | b':' => {
                tokens = tokens.saturating_add(1);
                if tokens > limit {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// Whether a decoded tree holds a number with no `Value` form.
///
/// This sees only what the decoder kept. A literal that overflowed `i64` or a
/// float is validated on the text by [`json_text_bad_number`] before or beside
/// this check: `serde_json` rounds a past-`i64` integer to an `f64` and refuses
/// an overflowing float outright (round 11, #3; round 15, F-1).
pub fn json_has_unrepresentable_number(value: &Json) -> bool {
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            Json::Number(number) => {
                // A non-negative integer past `i64::MAX` has no `Value` form,
                // and `Value::Float` is a form only for a finite float
                // (round 11, #3).
                let representable = number.as_i64().is_some()
                    || (number.is_f64() && number.as_f64().is_some_and(f64::is_finite));
                if !representable {
                    return true;
                }
            }
            Json::Array(items) => stack.extend(items.iter()),
            Json::Object(map) => stack.extend(map.values()),
            _ => {}
        }
    }
    false
}

/// Spans of numeric literals in `text` that no `Value` form represents.
///
/// The scan runs bytewise outside strings. A literal with a fraction or an
/// exponent must parse to a finite `f64`; an integer must parse to `i64` or
/// `u64` (a `u64` past `i64::MAX` is caught by
/// [`json_has_unrepresentable_number`] on the decoded tree). Scanning the text
/// is what sees a literal the decoder would round, turn into an infinity, or
/// refuse before any tree exists (round 15, F-1).
/// Largest number of unrepresentable literals this scan collects.
///
/// A document with more is either text or a refusal; collecting one 16-byte
/// span per two-byte literal let a peer answer allocate eight times its size
/// outside the grant (round 49, L-3).
const MAX_NUMBER_SPANS: usize = 8;

fn bad_number_spans(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut index = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        match byte {
            b'"' => {
                in_string = true;
                index += 1;
            }
            b'-' | b'0'..=b'9' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && matches!(bytes[index], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
                {
                    index += 1;
                }
                let literal = &text[start..index];
                // A lone `-` outside a string is not a number: a plain-text
                // answer that opens with one must stay text (round 16, F-1).
                if literal.bytes().any(|byte| byte.is_ascii_digit())
                    && literal_has_no_value_form(literal)
                {
                    spans.push((start, index));
                    if spans.len() >= MAX_NUMBER_SPANS {
                        return spans;
                    }
                }
            }
            _ => index += 1,
        }
    }
    spans
}

/// Whether one JSON numeric literal has no `Value` form.
fn literal_has_no_value_form(literal: &str) -> bool {
    let is_float = literal.contains('.') || literal.contains('e') || literal.contains('E');
    if is_float {
        return !matches!(literal.parse::<f64>(), Ok(value) if value.is_finite());
    }
    literal.parse::<i64>().is_err() && literal.parse::<u64>().is_err()
}

/// Whether a JSON text holds a numeric literal with no `Value` form.
pub fn json_text_bad_number(text: &str) -> bool {
    !bad_number_spans(text).is_empty()
}

/// Whether text that failed to parse would parse once each unrepresentable
/// literal is replaced by `0`.
///
/// This separates "the answer is JSON and one of its numbers is out of range"
/// from "the answer is not JSON at all": only a document that opens as an
/// object, an array or a number is re-examined, so a plain-text body is never
/// accused of carrying a bad number (round 15, F-1; round 16, F-1).
fn text_fails_only_on_a_number(text: &str) -> bool {
    let trimmed = text.trim();
    let json_start = trimmed.starts_with('{') || trimmed.starts_with('[');
    if !json_start {
        // A bare body is re-examined only when it is a number token: a date, a
        // version or a score opens with a digit too, and the repair heuristic
        // would turn it into `0` and report a provider fault for benign text
        // (round 31, F3). A bare `1e400` is a number token, so it still
        // reports `bad-number` (round 16, F-1).
        return is_number_token(trimmed);
    }
    match repair_bad_numbers(text) {
        Some(repaired) => serde_json::from_str::<Json>(&repaired).is_ok(),
        None => false,
    }
}

/// Replace every unrepresentable literal with `0` in one pass.
///
/// No span vector: `bad_number_spans` is capped so a peer cannot make the scan
/// allocate eight times its own size, and repairing only the capped prefix left
/// a document with nine literals unparsed, so it was served as text (round 50,
/// F-1). `None` when there is nothing to repair, or when a span is not one
/// number token (the scan groups `1-2` or `1e`, and repairing those would report
/// a framing fault as a bad number, round 33, M2).
fn repair_bad_numbers(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut repaired = String::with_capacity(text.len());
    let mut index = 0usize;
    let mut last = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut replaced = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        match byte {
            b'"' => {
                in_string = true;
                index += 1;
            }
            b'-' | b'0'..=b'9' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && matches!(bytes[index], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
                {
                    index += 1;
                }
                let literal = &text[start..index];
                if literal.bytes().any(|byte| byte.is_ascii_digit())
                    && literal_has_no_value_form(literal)
                {
                    if !is_number_token(literal) {
                        return None;
                    }
                    repaired.push_str(&text[last..start]);
                    repaired.push('0');
                    last = index;
                    replaced += 1;
                }
            }
            _ => index += 1,
        }
    }
    if replaced == 0 {
        return None;
    }
    repaired.push_str(&text[last..]);
    Some(repaired)
}

/// Whether `text` is exactly one JSON number token.
///
/// `-?digits[.digits][e[+-]digits]`; anything else (a date, a version, a
/// word) is text. Used to tell an out-of-range number from a benign body that
/// happens to open with a digit (round 31, F3).
fn is_number_token(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut index = 0usize;
    if bytes[index] == b'-' {
        index += 1;
    }
    let int_start = index;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    // JSON requires at least one integer digit and forbids a leading zero:
    // `-.5` and `00` are not numbers (round 32, #4; round 33, M1).
    if index == int_start {
        return false;
    }
    if index - int_start > 1 && bytes[int_start] == b'0' {
        return false;
    }
    if index < bytes.len() && bytes[index] == b'.' {
        index += 1;
        // JSON requires at least one fraction digit: `1.` and `0.e1` are not
        // numbers, and reporting them as a bad number blamed the wrong party
        // (round 34, #5).
        let fraction = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == fraction {
            return false;
        }
    }
    if index < bytes.len() && (bytes[index] == b'e' || bytes[index] == b'E') {
        index += 1;
        if index < bytes.len() && (bytes[index] == b'+' || bytes[index] == b'-') {
            index += 1;
        }
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == start {
            return false;
        }
    }
    index == bytes.len()
}

/// Whether a decoded tree holds more nodes than the adapter accepts.
///
/// The token gate refuses a huge body before parsing; this is the second line
/// for a shape whose token count understates its node count (a chain of
/// single-element arrays adds a node without adding a token), and it reports
/// the size refusal under its own code (round 16, F-2).
pub fn json_too_many_nodes(value: &Json) -> bool {
    let mut stack = vec![value];
    let mut nodes = 0usize;
    while let Some(value) = stack.pop() {
        // The decoded tree is far larger than the body: a 1 MiB array of zeros
        // is half a million values. Bound the node count, not just the bytes
        // (round 13, F-8).
        nodes = nodes.saturating_add(1);
        if nodes > MAX_JSON_NODES {
            return true;
        }
        match value {
            Json::Array(items) => stack.extend(items.iter()),
            Json::Object(map) => stack.extend(map.values()),
            _ => {}
        }
    }
    false
}

/// Convert JSON into an RPC value.
///
/// The conversion is partial for one class: a JSON integer past `i64::MAX` has
/// no `Int` form, and it becomes `Value::Null` because no float is that
/// integer. Both adapters refuse such a tree first with
/// [`json_has_unrepresentable_number`] or [`json_text_bad_number`], so no peer
/// answer is ever converted this way; a direct caller must run the same gate.
pub fn json_to_value(value: &Json) -> Value {
    match value {
        Json::Null => Value::Null,
        Json::Bool(flag) => Value::Bool(*flag),
        Json::Number(number) => {
            // A u64 past `i64::MAX` has no `Value` form; rounding it through
            // `f64` handed the caller a number the peer never wrote
            // (round 11, #3).
            if number.as_i64().is_none() && number.as_u64().is_some() {
                return Value::Null;
            }
            if let Some(int) = number.as_i64() {
                Value::Int(int)
            } else {
                // A number with no finite `f64` form becomes `Null`, never an
                // invented `0.0` (round 17, F-4).
                match number.as_f64() {
                    Some(float) => Value::Float(float),
                    None => Value::Null,
                }
            }
        }
        Json::String(text) => Value::Text(text.clone()),
        Json::Array(items) => Value::List(items.iter().map(json_to_value).collect()),
        Json::Object(entries) => Value::Map(
            entries
                .iter()
                .map(|(key, value)| (key.clone(), json_to_value(value)))
                .collect(),
        ),
    }
}

/// Convert an RPC value into JSON.
pub fn value_to_json(value: &Value) -> Json {
    match value {
        Value::Null => Json::Null,
        Value::Bool(flag) => Json::Bool(*flag),
        Value::Int(number) => json!(number),
        Value::Float(number) => json!(number),
        Value::Text(text) => Json::String(text.clone()),
        Value::List(items) => Json::Array(items.iter().map(value_to_json).collect()),
        Value::Map(entries) => Json::Object(
            entries
                .iter()
                .map(|(key, value)| (key.clone(), value_to_json(value)))
                .collect(),
        ),
        Value::Secret => Json::String("***SECRET***".to_string()),
        Value::Module(bytes) => json!({ "$module_bytes": bytes.len() }),
        Value::Path(path) => Json::String(path.clone()),
    }
}

/// Whether a value carries a module payload anywhere in its shape.
///
/// A module's JSON form is its byte length, not its content, so any adapter
/// that serialised one handed the peer a request the caller never made. The
/// check is recursive: a map or a list is a legal body, and a module nested
/// inside it would otherwise pass the top-level shape check (round 5, #2).
fn contains_module(value: &Value) -> bool {
    // Iterative: a direct `Provider::invoke` bypasses the kernel's depth gate,
    // and a recursive walk of a caller-built value aborts the stack
    // (round 7, #1). Same doctrine as `Value::is_tainted`.
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            Value::Module(_) => return true,
            Value::List(items) => stack.extend(items.iter()),
            Value::Map(entries) => stack.extend(entries.values()),
            _ => {}
        }
    }
    false
}

/// Whether a value carries a non-finite float anywhere in its shape.
///
/// JSON has no NaN or infinities: `value_to_json` maps them to `null`, so any
/// adapter that serialised one handed the peer a null nobody wrote. Refused
/// like a module (round 6): same doctrine, same position.
fn contains_nonfinite(value: &Value) -> bool {
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            Value::Float(number) if !number.is_finite() => return true,
            Value::List(items) => stack.extend(items.iter()),
            Value::Map(entries) => stack.extend(entries.values()),
            _ => {}
        }
    }
    false
}

/// Whether an environment entry reaches the child as written.
///
/// An empty key, a `=` in a key, or a NUL on either side never reaches the
/// child as written: `Command` asserts on a NUL, and an empty or `=`-bearing
/// key fails at spawn or is silently mangled into another variable. A bad entry
/// is refused here instead of reaching `Command` at all (round 6; round 5
/// covered NUL only).
fn valid_env_entry(key: &str, value: &str) -> bool {
    !key.is_empty() && !key.contains('=') && !key.contains('\0') && !value.contains('\0')
}

// ---------------------------------------------------------------------------
// MCP
// ---------------------------------------------------------------------------

/// A line-oriented JSON-RPC transport used by [`McpSession`].
pub trait McpTransport {
    /// Send one JSON line.
    fn send_line(&mut self, line: &str) -> Result<()>;
    /// Read one JSON line (blocking).
    fn recv_line(&mut self) -> Result<String>;

    /// Send one JSON line, giving up at `deadline`.
    ///
    /// The default ignores the deadline: an in-memory transport answers at once.
    /// A transport that writes to another process overrides this, because a
    /// server that stops reading fills the pipe and blocks the writer
    /// (round 3, #2).
    fn send_line_within(&mut self, line: &str, deadline: Option<std::time::Instant>) -> Result<()> {
        let _ = deadline;
        self.send_line(line)
    }

    /// Read one JSON line, giving up at `deadline`.
    ///
    /// The default ignores the deadline: an in-memory transport answers at
    /// once. A transport that blocks on another process overrides this, so the
    /// capability's wall ceiling reaches the wait instead of only measuring it
    /// after the call returns.
    fn recv_line_within(&mut self, deadline: Option<std::time::Instant>) -> Result<String> {
        let _ = deadline;
        self.recv_line()
    }
}

/// Largest JSON tree the HTTP adapter will decode from one answer.
///
/// An MCP answer is bounded by [`MAX_MCP_LINE_BYTES`] instead (a 1 MiB line
/// holds far fewer nodes), so this ceiling is not applied there
/// (round 19, L5).
const MAX_JSON_NODES: usize = 1 << 20;

/// Largest child output this adapter will buffer.
const MAX_OUTPUT_BYTES: usize = 16 << 20;

/// Process reader threads that may still be draining an earlier child.
///
/// On Windows the cleanup kills the leader only (ARPC-004), so a descendant
/// that holds the pipe keeps its reader blocked in `read` until it exits. The
/// count is capped so a timeout loop cannot exhaust the process
/// (round 33, H3).
static LIVE_READERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Cap for [`LIVE_READERS`]; well above any legitimate concurrency.
const MAX_LIVE_READERS: usize = 256;

/// One reserved place in [`LIVE_READERS`], released when the reader ends.
///
/// A guard rather than paired calls: a thread that fails to spawn drops the
/// closure, so a failed spawn cannot leak a place and eventually refuse every
/// process call (round 33, H3).
struct ReaderSlot;

impl ReaderSlot {
    fn acquire() -> Option<Self> {
        if LIVE_READERS.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= MAX_LIVE_READERS {
            LIVE_READERS.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            return None;
        }
        Some(Self)
    }
}

impl Drop for ReaderSlot {
    fn drop(&mut self) {
        let _ = LIVE_READERS.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Largest HTTP request body a caller may configure.
///
/// The field is public; a static ceiling at use keeps a misconfiguration from
/// turning a grant into an unbounded write (round 21, F10).
pub const MAX_REQUEST_BYTES: usize = 64 << 20;

/// Largest HTTP response body this adapter will buffer.
///
/// A public `max_body` past this is clamped: the peer names the length, and an
/// unbounded buffer is an allocation abort (round 11, #14).
const MAX_RESPONSE_BYTES: usize = 64 << 20;

/// Default ceiling for a handshake that names none.
const DEFAULT_HANDSHAKE_MS: u64 = DEFAULT_MCP_HANDSHAKE_TIMEOUT_MS;

/// Lines the reader thread may hold while the session is busy.
///
/// The session consumes at most one answer per request, so a peer that streams
/// notifications would otherwise fill host memory at pipe speed.
pub const MAX_MCP_QUEUED_LINES: usize = 64;

/// Largest JSON-RPC line a session accepts, in bytes.
///
/// One MiB matches the default MCP argument policy. A server that needs more
/// is not speaking MCP at this size; the session fails closed instead of
/// buffering an unbounded line.
pub const MAX_MCP_LINE_BYTES: usize = 1 << 20;

/// How many notification frames one request may skip before the session is
/// poisoned.
///
/// MCP servers send notifications (`notifications/progress`,
/// `notifications/message`) that are not answers to any request. Skipping a
/// bounded number keeps a spec-compliant server usable; an unbounded skip would
/// let a server starve the caller with frames it never asked for, so the
/// session fails closed once the bound is passed.
pub const MAX_MCP_NOTIFICATIONS: usize = 16;

/// Most tools one session keeps.
///
/// A handshake reply is capped at one MiB, so this is not a memory fix so much
/// as a deterministic bound on the method table every dispatch walks.
pub const MAX_MCP_TOOLS: usize = 4_096;

/// Default ceiling for the MCP handshake, in milliseconds.
///
/// `initialize` and `tools/list` are requests like any other, but they run
/// before a capability has a budget, so they need their own bound: a server
/// that accepts the connection and stays silent would otherwise hold the
/// dispatch thread forever.
pub const DEFAULT_MCP_HANDSHAKE_TIMEOUT_MS: u64 = 5_000;

/// The longest tool name a session accepts, in bytes.
pub const MAX_MCP_TOOL_NAME_BYTES: usize = 128;

/// Whether an advertised tool name is plain identifier text.
///
/// Tool names reach an operator-facing allow-list and the method table. A bidi
/// override or a control character would let a hostile server advertise
/// `read\u{202E}pyf` and have a UI render it as `read`. Dots are allowed because
/// real servers use them for namespacing.
fn valid_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_MCP_TOOL_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        // A name made only of dots is a path segment (`.` or `..`) wearing a
        // tool name: a renderer that joins names into a path would step
        // through it (round 38, #6).
        && !name.bytes().all(|byte| byte == b'.')
}

/// The longest tool description a session keeps, in bytes.
pub const MAX_MCP_DESCRIPTION_BYTES: usize = 4 << 10;

/// Cap a description and replace control characters and invisible formatting
/// with spaces.
///
/// The text is still untrusted: a renderer must escape it for its own output
/// context. Replacing these characters here means a description can never carry
/// a terminal escape, reorder rendered text, or start a new line in a log.
/// `char::is_control` covers C0 and C1, but not the Unicode separators (Zl/Zp)
/// or the format characters that render as nothing.
fn bounded_description(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(MAX_MCP_DESCRIPTION_BYTES));
    for character in text.chars() {
        // Reserve the whole encoded character: checking only the current length
        // would let a multi-byte character straddle the ceiling by up to three
        // bytes.
        if out.len() + character.len_utf8() > MAX_MCP_DESCRIPTION_BYTES {
            break;
        }
        if character.is_control() || is_invisible_or_reordering(character) {
            out.push(' ');
        } else {
            out.push(character);
        }
    }
    out
}

use crate::security::is_invisible_or_reordering;

/// An in-memory transport: requests are answered by a closure.
pub struct MemoryTransport {
    responses: BTreeMap<String, String>,
    queue: Vec<String>,
    sent: Vec<String>,
}

impl MemoryTransport {
    /// Build from `method -> response` pairs.
    pub fn new(responses: BTreeMap<String, String>) -> Self {
        Self {
            responses,
            queue: Vec::new(),
            sent: Vec::new(),
        }
    }

    /// Lines sent by the client (tests).
    pub fn sent(&self) -> &[String] {
        &self.sent
    }
}

impl McpTransport for MemoryTransport {
    fn send_line(&mut self, line: &str) -> Result<()> {
        self.sent.push(line.to_string());
        let request: Json = serde_json::from_str(line).map_err(|_| Error::Provider {
            code: "mcp/bad-json".to_string(),
        })?;
        let method = request.get("method").and_then(Json::as_str).unwrap_or("");
        let id = request.get("id").cloned().unwrap_or(Json::Null);
        let mut response = self.responses.get(method).cloned().unwrap_or_else(|| {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": "method not found" }
            })
            .to_string()
        });
        // A real server echoes the request id. A canned response carrying a
        // fixed id desynchronises the session on its second call, which is a
        // property of this test double and not of the client under test.
        if let Ok(mut parsed) = serde_json::from_str::<Json>(&response) {
            if let Some(object) = parsed.as_object_mut() {
                if object.contains_key("id") {
                    object.insert("id".to_string(), id);
                    response = parsed.to_string();
                }
            }
        }
        self.queue.push(response);
        Ok(())
    }

    fn recv_line(&mut self) -> Result<String> {
        if self.queue.is_empty() {
            return Err(Error::Provider {
                code: "mcp/no-response".to_string(),
            });
        }
        Ok(self.queue.remove(0))
    }
}

/// Longest HTTP status line accepted, in bytes.
pub const MAX_HTTP_STATUS_LINE: usize = 1024;

/// Smallest answer a byte grant must carry: the shortest status line
/// (`HTTP/1.0 200\r\n`, 14 bytes) and the empty end-of-head line (2 bytes).
/// A smaller grant can never receive an answer, so the refusal is a budget
/// fault rather than a provider fault (round 24, #4).
pub const MIN_HTTP_ANSWER_BYTES: usize = 16;

/// Longest single HTTP header line accepted, in bytes.
pub const MAX_HTTP_HEADER_LINE: usize = 8 * 1024;

/// Largest HTTP header block accepted, in bytes.
pub const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;

/// Largest number of HTTP header fields accepted.
pub const MAX_HTTP_HEADER_FIELDS: usize = 128;

/// Whether a request method is defined to carry content.
///
/// Only these get a body and a `content-length` header. A request that carries
/// content anyway (RFC 9110 permits it for GET) makes simple servers and
/// intermediaries reset the connection instead of answering, so the adapter
/// sends none.
fn takes_request_body(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH")
}

/// Time left before `deadline`, or `rpc/timeout` when it has passed.
fn remaining_until(deadline: std::time::Instant) -> Result<std::time::Duration> {
    deadline
        .checked_duration_since(std::time::Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or(Error::Timeout)
}

/// A post-spawn process refusal.
///
/// The child ran, so its effect may stand: the class says the reply was
/// withheld, which keeps the kernel from sealing `Refused` and from re-forking
/// the process on an idempotent retry (round 43, F-4). The inner class (a
/// deadline, an output overrun) is replaced, as the MCP and HTTP mappings
/// replace theirs.
fn reply_withheld(_error: Error) -> Error {
    Error::Provider {
        code: "provider/reply-withheld".to_string(),
    }
}

/// A refusal decided after the request reached the peer.
///
/// The peer may have run the tool, so the class must say the reply was withheld
/// rather than that nothing happened: the kernel then seals an admitted receipt
/// and an idempotent retry returns this outcome instead of executing a second
/// time (round 42, M-1). `mutating` is the caller's judgement that the method
/// could have changed something; when it is false the specific code survives.
/// A frame that never left always keeps its own class.
fn withhold_after_send(error: Error, mutating: bool) -> Error {
    if !mutating {
        return error;
    }
    if let Error::Provider { code } = &error {
        if code == "mcp/not-sent" || code == "mcp/queue" {
            return error;
        }
        if code == "provider/reply-withheld" {
            return error;
        }
    }
    Error::Provider {
        code: "provider/reply-withheld".to_string(),
    }
}

/// A response reader whose every read is bounded by one wall deadline.
///
/// `set_read_timeout` bounds a single `read` syscall, not the call: a server
/// that drips one byte per timeout period would otherwise hold the dispatch
/// thread for (bytes x timeout). Each read here gets only the time that is
/// left, and the deadline is re-checked afterwards, so the ceiling is a
/// ceiling.
struct DeadlineReader {
    reader: BufReader<TcpStream>,
    deadline: std::time::Instant,
}

impl DeadlineReader {
    fn new(stream: TcpStream, deadline: std::time::Instant) -> Self {
        Self {
            reader: BufReader::new(stream),
            deadline,
        }
    }

    /// Arm the socket with the time that is left.
    ///
    /// A failure to set the timeout is a failure to bound the call: reporting it
    /// beats reading with no ceiling at all (round 3, #9).
    fn arm(&self) -> Result<()> {
        let left = remaining_until(self.deadline)?;
        self.reader
            .get_ref()
            .set_read_timeout(Some(left))
            .map_err(|_| Error::Timeout)?;
        Ok(())
    }

    /// Read one line under a byte cap and the wall deadline.
    ///
    /// One `fill_buf` is at most one syscall, and the deadline is re-checked
    /// after every chunk: a peer that drips a byte per read timeout used to keep
    /// a multi-kilobyte line alive long past the ceiling, because `read_line`
    /// loops internally and each byte resets the socket timeout (round 3, #1).
    fn line(&mut self, cap: usize) -> Result<String> {
        let mut line = Vec::new();
        loop {
            self.arm()?;
            let available = self.reader.fill_buf().map_err(map_http_read)?;
            if available.is_empty() {
                return Err(Error::Provider {
                    code: "http/read:truncated".to_string(),
                });
            }
            let (take, done) = match available.iter().position(|byte| *byte == b'\n') {
                Some(index) => (index + 1, true),
                None => (available.len(), false),
            };
            if line.len() + take > cap {
                return Err(Error::Provider {
                    code: "http/line-too-long".to_string(),
                });
            }
            line.extend_from_slice(&available[..take]);
            self.reader.consume(take);
            remaining_until(self.deadline)?;
            if done {
                break;
            }
        }
        String::from_utf8(line).map_err(|_| Error::Provider {
            code: "http/header-not-utf8".to_string(),
        })
    }

    /// Read exactly `length` body bytes under the wall deadline.
    fn body_exact(&mut self, length: usize) -> Result<Vec<u8>> {
        // Grow with the bytes that actually arrive: a peer-declared 64 MiB
        // body used to be allocated before the first read, and a short body
        // paid the whole reservation (round 18, L-6).
        let mut body = Vec::with_capacity(length.min(64 * 1024));
        let mut chunk = [0u8; 4_096];
        while body.len() < length {
            self.arm()?;
            let want = (length - body.len()).min(chunk.len());
            let read = self
                .reader
                .read(&mut chunk[..want])
                .map_err(map_http_read)?;
            if read == 0 {
                return Err(Error::Provider {
                    code: "http/read:truncated-body".to_string(),
                });
            }
            body.extend_from_slice(&chunk[..read]);
            remaining_until(self.deadline)?;
        }
        Ok(body)
    }

    /// Read the rest of the body under a byte cap and the wall deadline.
    fn body_rest(&mut self, cap: usize) -> Result<Vec<u8>> {
        let mut rest = Vec::new();
        let mut chunk = [0u8; 4_096];
        loop {
            self.arm()?;
            let read = self.reader.read(&mut chunk).map_err(map_http_read)?;
            if read == 0 {
                break;
            }
            if rest.len().saturating_add(read) > cap {
                return Err(Error::Provider {
                    code: "http/body-too-large".to_string(),
                });
            }
            rest.extend_from_slice(&chunk[..read]);
            remaining_until(self.deadline)?;
        }
        Ok(rest)
    }
}

/// Write `bytes` under one deadline.
///
/// Each syscall is bounded by the time left, and a short write costs one loop
/// iteration with a fresh timeout: a peer that accepts a byte at a time cannot
/// stretch the phase past the ceiling.
fn write_within(
    stream: &mut std::net::TcpStream,
    bytes: &[u8],
    deadline: std::time::Instant,
) -> (usize, Result<()>) {
    const CHUNK: usize = 4 << 10;
    let mut sent = 0usize;
    while sent < bytes.len() {
        let left = match remaining_until(deadline) {
            Ok(left) => left,
            Err(error) => return (sent, Err(error)),
        };
        if stream.set_write_timeout(Some(left)).is_err() {
            return (sent, Err(Error::Timeout));
        }
        let end = (sent + CHUNK).min(bytes.len());
        match std::io::Write::write(stream, &bytes[sent..end]) {
            Ok(0) => {
                return (
                    sent,
                    Err(Error::Provider {
                        code: "http/write:short write".to_string(),
                    }),
                )
            }
            Ok(written) => sent += written,
            Err(error) => return (sent, Err(map_http_write(error))),
        }
        if sent < bytes.len() {
            // Only between chunks: a head that is fully on the wire, terminator
            // included, must not be reported as a pre-send timeout (round 44,
            // L-6). The next phase arms its own deadline.
            if let Err(error) = remaining_until(deadline) {
                return (sent, Err(error));
            }
        }
    }
    (sent, Ok(()))
}

/// A socket read that hit its timeout is the call's ceiling, not an I/O fault.
fn map_http_read(error: std::io::Error) -> Error {
    map_http_io(error, "read")
}

/// A socket write fault, named for the operation.
///
/// A retry policy keyed on `http/read` would retry a half-sent POST and
/// duplicate its side effect, so the direction is part of the code
/// (round 5, #3). A timeout is still the ceiling on both sides.
fn map_http_write(error: std::io::Error) -> Error {
    map_http_io(error, "write")
}

fn map_http_io(error: std::io::Error, direction: &'static str) -> Error {
    if matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ) {
        Error::Timeout
    } else {
        Error::Provider {
            code: format!("http/{direction}:{error}"),
        }
    }
}

/// A child-process MCP transport speaking JSON-RPC over stdin/stdout.
pub struct StdioTransport {
    child: Child,
    /// Lines handed to the writer thread, each with the channel its outcome goes
    /// back on.
    writer: std::sync::mpsc::SyncSender<(String, std::sync::mpsc::Sender<Result<()>>)>,
    /// Lines read by the reader thread. Reading on a thread is what makes a
    /// deadline possible: a child pipe has no portable read timeout, and a
    /// silent server would otherwise block the single-threaded kernel for as
    /// long as it stays quiet.
    lines: std::sync::mpsc::Receiver<Result<String>>,
}

impl StdioTransport {
    /// Spawn an MCP server process (no shell, no inherited environment beyond
    /// what the caller passes).
    ///
    /// The environment is cleared, so the caller supplies everything the server
    /// needs. On Windows that includes `SystemRoot`: a process started without
    /// it exits at once, and the session sees `mcp/eof` before its first line.
    /// Reads happen on a thread, so [`McpTransport::recv_line_within`] can
    /// abandon a server that stays silent.
    ///
    /// `program` must be an absolute path, for the same reason as
    /// [`LocalProcess::new`]: a bare name is resolved from the parent's `PATH`.
    /// The working directory is pinned to this process's current directory
    /// instead of being inherited when the child is spawned.
    pub fn spawn(program: &str, args: &[&str], env: &BTreeMap<String, String>) -> Result<Self> {
        // A NUL never reaches an exec: `Command` reports it as an OS error, a
        // peer fault for what is a configuration mistake (round 8, F5).
        if program.contains('\0') || args.iter().any(|arg| arg.contains('\0')) {
            return Err(Error::InvalidArgument(
                "an MCP program or argument contains a NUL byte",
            ));
        }
        let program = pin_program(program, "an MCP server")?;
        let workdir = std::env::current_dir()
            .and_then(std::fs::canonicalize)
            .map_err(|_| Error::Provider {
                code: "mcp/cwd".to_string(),
            })?;
        let mut command = Command::new(&program);
        command
            .args(args)
            .current_dir(&workdir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_clear();
        #[cfg(unix)]
        {
            // Its own group, so dropping the session can end helpers the server
            // started; otherwise they keep the pipes and outlive the session.
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        for (key, value) in env {
            // A bad entry never reaches the child as written: `Command` asserts
            // on a NUL, and an empty or `=`-bearing key fails at spawn (or is
            // silently mangled), so a configuration typo is refused here.
            if !valid_env_entry(key, value) {
                return Err(Error::InvalidArgument(
                    "an MCP environment entry is not a valid variable",
                ));
            }
            command.env(key, value);
        }
        let mut child = command.spawn().map_err(|error| Error::Provider {
            code: format!("mcp/spawn:{error}"),
        })?;
        let stdin = child.stdin.take().ok_or_else(|| {
            // `Child::Drop` neither kills nor reaps (round 13, F-7).
            kill_process_tree(&mut child);
            Error::Provider {
                code: "mcp/stdin".to_string(),
            }
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            kill_process_tree(&mut child);
            Error::Provider {
                code: "mcp/stdout".to_string(),
            }
        })?;
        // A bounded queue: a server that streams frames forever must fill the
        // pipe and block, not grow the host's memory (round 8, F1).
        let (sender, lines) = std::sync::mpsc::sync_channel(MAX_MCP_QUEUED_LINES);
        std::thread::Builder::new()
            .name("active-rpc-mcp-stdio".to_string())
            .spawn(move || {
                // One bounded slot, as the process adapter takes: on Windows a
                // descendant that inherits the pipe keeps this thread blocked
                // for the life of the process, so abandoned sessions must not
                // leak threads without bound (round 49, L-5).
                let Some(_slot) = ReaderSlot::acquire() else {
                    let _ = sender.send(Err(Error::Provider {
                        code: "mcp/thread:too many readers".to_string(),
                    }));
                    return;
                };
                let mut reader = BufReader::new(stdout);
                loop {
                    let mut line = String::new();
                    // The take() allows the two delimiter bytes, so a read
                    // that fills it without a newline is a line past the cap:
                    // trimming it would accept an overlong frame and leave
                    // its tail in the pipe for the next request
                    // (round 16, F-7). The caller's length check stays as the
                    // second line of defence (round 13, F-9).
                    let read = reader
                        .by_ref()
                        .take((MAX_MCP_LINE_BYTES + 2) as u64)
                        .read_line(&mut line);
                    let outcome = match read {
                        Ok(0) => Err(Error::Provider {
                            code: "mcp/eof".to_string(),
                        }),
                        Ok(read) if read == MAX_MCP_LINE_BYTES + 2 && !line.ends_with('\n') => {
                            Err(Error::Provider {
                                code: "mcp/line-too-long".to_string(),
                            })
                        }
                        Ok(_) => Ok(line.trim_end().to_string()),
                        Err(error) => Err(Error::Provider {
                            code: format!("mcp/read:{error}"),
                        }),
                    };
                    let finished = outcome.is_err();
                    if sender.send(outcome).is_err() || finished {
                        return;
                    }
                }
            })
            .map_err(|error| {
                // `Child`'s Drop neither kills nor reaps: the server would
                // outlive the error return (round 9, F-5).
                kill_process_tree(&mut child);
                Error::Provider {
                    code: format!("mcp/thread:{error}"),
                }
            })?;
        // The writer runs on its own thread for the same reason the reader
        // does: a server that stops reading fills the pipe and a blocking write
        // would hold the kernel past every ceiling (round 3, #2).
        // One command in flight: the caller owns the deadline, and the writer
        // never holds a backlog (round 8, F1).
        let (writer, commands) =
            std::sync::mpsc::sync_channel::<(String, std::sync::mpsc::Sender<Result<()>>)>(1);
        std::thread::Builder::new()
            .name("active-rpc-mcp-writer".to_string())
            .spawn(move || {
                let mut stdin = stdin;
                while let Ok((line, reply)) = commands.recv() {
                    let outcome = stdin
                        .write_all(line.as_bytes())
                        .and_then(|_| stdin.write_all(b"\n"))
                        .and_then(|_| stdin.flush())
                        .map_err(|error| Error::Provider {
                            code: format!("mcp/write:{error}"),
                        });
                    let failed = outcome.is_err();
                    let _ = reply.send(outcome);
                    if failed {
                        return;
                    }
                }
            })
            .map_err(|error| {
                // The reader's arm already kills the child; this one must too
                // (`Child::Drop` neither kills nor reaps) (round 10, F-1).
                kill_process_tree(&mut child);
                Error::Provider {
                    code: format!("mcp/thread:{error}"),
                }
            })?;
        Ok(Self {
            child,
            writer,
            lines,
        })
    }
}

impl McpTransport for StdioTransport {
    fn send_line(&mut self, line: &str) -> Result<()> {
        self.send_line_within(line, None)
    }

    fn send_line_within(&mut self, line: &str, deadline: Option<std::time::Instant>) -> Result<()> {
        // Check before enqueueing: a frame handed to the writer thread after
        // the deadline returns `Timeout` but still reaches the wire, and the
        // stream is then one request ahead of the session's state
        // (round 5, #5).
        // The session checks the ceiling before calling in; repeating it here
        // made a spent deadline look like a frame that may have left, which
        // poisons a session that was never touched (round 13, F-5).
        // A frame handed over after the deadline is written anyway, which is
        // the desync the round-5 fix existed to prevent (round 19, L1).
        if let Some(deadline) = deadline {
            if std::time::Instant::now() >= deadline {
                // Nothing was written, and a distinct code says so: an
                // `rpc/timeout` here is indistinguishable from an ack timeout,
                // where the frame may be in flight and the session is
                // desynchronised (round 34, #7).
                return Err(Error::Provider {
                    code: "mcp/not-sent".to_string(),
                });
            }
        }
        let (reply, outcome) = std::sync::mpsc::channel();
        // A blocking `send` on the capacity-1 queue has no ceiling: a writer
        // stuck in `write_all` leaves the queue full and the next send waits
        // forever (round 11, #1). `try_send` under the deadline keeps the
        // promise the trait makes.
        let mut command = (line.to_string(), reply);
        // A caller with no deadline still gets bounded waits: the writer blocks
        // while the child does not read, so the enqueue waits 5 s and the ack
        // 5 s (round 18, L-7; round 30, #4). A far deadline does not buy a
        // longer enqueue wait: a full queue is backpressure, not work
        // (round 33, M3).
        let enqueue_now = std::time::Instant::now();
        let enqueue_cap = enqueue_now
            .checked_add(std::time::Duration::from_secs(5))
            .unwrap_or(enqueue_now);
        let enqueue_deadline = deadline.map_or(enqueue_cap, |value| value.min(enqueue_cap));
        loop {
            match self.writer.try_send(command) {
                Ok(()) => break,
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                    return Err(Error::Provider {
                        code: "mcp/write:closed".to_string(),
                    })
                }
                Err(std::sync::mpsc::TrySendError::Full(returned)) => {
                    command = returned;
                    if std::time::Instant::now() >= enqueue_deadline {
                        // The frame never reached the writer, so the session is
                        // not desynced: a distinct code lets the caller keep it
                        // (round 29, F1).
                        return Err(Error::Provider {
                            code: "mcp/queue".to_string(),
                        });
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }
        }
        match deadline {
            None => outcome
                // A direct caller with no deadline still gets a bounded wait:
                // 30 s held the dispatch thread with no capability ceiling
                // (round 30, #4). A dead writer is reported as such, not as a
                // timeout (round 31, F1).
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|error| match error {
                    std::sync::mpsc::RecvTimeoutError::Timeout => Error::Timeout,
                    std::sync::mpsc::RecvTimeoutError::Disconnected => Error::Provider {
                        code: "mcp/write:lost".to_string(),
                    },
                })?,
            Some(deadline) => {
                let left = deadline
                    .checked_duration_since(std::time::Instant::now())
                    .ok_or(Error::Timeout)?;
                outcome.recv_timeout(left).map_err(|error| match error {
                    std::sync::mpsc::RecvTimeoutError::Timeout => Error::Timeout,
                    std::sync::mpsc::RecvTimeoutError::Disconnected => Error::Provider {
                        code: "mcp/write:lost".to_string(),
                    },
                })?
            }
        }
    }

    fn recv_line(&mut self) -> Result<String> {
        self.recv_line_within(None)
    }

    fn recv_line_within(&mut self, deadline: Option<std::time::Instant>) -> Result<String> {
        // A direct caller with no deadline still gets a bounded wait: an
        // unbounded `recv` held the dispatch thread for as long as the server
        // stayed silent (round 32, #2).
        let Some(deadline) = deadline
            .or_else(|| std::time::Instant::now().checked_add(std::time::Duration::from_secs(5)))
        else {
            return Err(Error::Timeout);
        };
        let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) else {
            return Err(Error::Timeout);
        };
        self.lines.recv_timeout(left).map_err(|error| match error {
            std::sync::mpsc::RecvTimeoutError::Timeout => Error::Timeout,
            std::sync::mpsc::RecvTimeoutError::Disconnected => Error::Provider {
                code: "mcp/eof".to_string(),
            },
        })?
    }
}

impl Drop for StdioTransport {
    fn drop(&mut self) {
        kill_process_tree(&mut self.child);
    }
}

/// One tool exposed by an MCP server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpToolDef {
    /// Tool name.
    pub name: String,
    /// Free-form description.
    pub description: String,
}

/// A provider backed by an MCP session.
///
/// `object` selects the tool index; `method` is the tool name. The session
/// performs the real JSON-RPC handshake (`initialize`, `tools/list`) and then
/// `tools/call` per invocation.
pub struct McpSession<T: McpTransport> {
    transport: T,
    tools: Vec<McpToolDef>,
    next_id: u64,
    /// Set when a frame broke the request/response stream. A poisoned session
    /// refuses every later call: after a desync the next line may be the answer
    /// to a request already abandoned, so accepting it would attribute one
    /// call's result to another.
    poisoned: bool,
    /// Tool invocations issued through this session (the handshake is not
    /// counted).
    pub calls: u64,
    /// Whether the last refusal happened after the request left: the peer may
    /// have run the tool, so the caller must see a withheld reply rather than a
    /// call that did not happen (round 42, M-1).
    after_send: bool,
}

impl<T: McpTransport> McpSession<T> {
    /// Perform the MCP handshake and discover tools.
    pub fn handshake(transport: T) -> Result<Self> {
        let deadline = std::time::Instant::now()
            .checked_add(std::time::Duration::from_millis(
                DEFAULT_MCP_HANDSHAKE_TIMEOUT_MS,
            ))
            .unwrap_or_else(std::time::Instant::now);
        Self::handshake_within(transport, Some(deadline))
    }

    /// Perform the MCP handshake under an explicit deadline.
    ///
    /// The whole handshake (`initialize` and `tools/list`) shares one deadline:
    /// a server that answers `initialize` and then stalls on the list is just
    /// as stuck as one that never answers.
    pub fn handshake_within(transport: T, deadline: Option<std::time::Instant>) -> Result<Self> {
        // A handshake without a ceiling would hold the dispatch thread for as
        // long as a silent server stays silent (round 8, F8).
        let deadline = Some(deadline.unwrap_or_else(|| {
            std::time::Instant::now()
                .checked_add(std::time::Duration::from_millis(DEFAULT_HANDSHAKE_MS))
                .unwrap_or_else(std::time::Instant::now)
        }));
        let mut session = McpSession {
            transport,
            tools: Vec::new(),
            next_id: 0,
            poisoned: false,
            calls: 0,
            after_send: false,
        };
        let initialize = session.request_within(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "active-rpc", "version": env!("CARGO_PKG_VERSION") }
            }),
            deadline,
            None,
        )?;
        if let Some(error) = initialize.get("error") {
            // Keep the server's numeric code, as `tools/list` does: a retry or
            // alert rule can tell a refused method from a server fault
            // (round 21, F9).
            let code = match error.get("code").and_then(Json::as_i64) {
                Some(code) => format!("mcp/initialize:{code}"),
                None => "mcp/initialize".to_string(),
            };
            return Err(Error::Provider { code });
        }
        let list = session.request_within("tools/list", json!({}), deadline, None)?;
        if let Some(error) = list.get("error") {
            // A failed list was reported as a missing array and the server's
            // code was lost. `initialize` keeps its own class
            // (`mcp/initialize`), so this is the one handshake step that
            // carries the numeric code (round 18, L-4).
            let Some(code) = error.get("code").and_then(Json::as_i64) else {
                return Err(Error::Provider {
                    code: "mcp/bad-response".to_string(),
                });
            };
            return Err(Error::Provider {
                code: format!("mcp/{code}"),
            });
        }
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let Some(items) = list
            .get("result")
            .and_then(|result| result.get("tools"))
            .and_then(Json::as_array)
        else {
            // A handshake that answers no tool array is malformed: an empty
            // session hides it (round 7, #2).
            return Err(Error::Provider {
                code: "mcp/tools".to_string(),
            });
        };
        {
            for item in items {
                let name = item.get("name").and_then(Json::as_str).unwrap_or("");
                if name.is_empty() {
                    // A nameless entry cannot be granted, and skipping it made a
                    // malformed list look usable (round 7, #2).
                    return Err(Error::Provider {
                        code: "mcp/tool-name".to_string(),
                    });
                }
                // A tool name reaches an operator-facing allow-list and the
                // method table, so it must be plain ASCII identifier text. A
                // bidi override or control character would let a hostile server
                // advertise `read\u{202E}fpd` and have it render as `read`.
                if !valid_tool_name(name) {
                    return Err(Error::Provider {
                        code: "mcp/tool-name".to_string(),
                    });
                }
                // A set: a 1 MiB tool list is ~50 000 entries, and a scan per
                // entry made a handshake quadratic (12.7 s measured at 32 000).
                // Two entries with one name make the allow-list ambiguous: the
                // index selects one entry and the name selects the other.
                if !seen.insert(name.to_string()) {
                    return Err(Error::Provider {
                        code: "mcp/tool-name".to_string(),
                    });
                }
                if session.tools.len() >= MAX_MCP_TOOLS {
                    return Err(Error::Provider {
                        code: "mcp/tool-count".to_string(),
                    });
                }
                // The description is free text shown to an operator. It is
                // capped so a hostile server cannot make the client buffer a
                // megabyte per tool, and control characters (including ANSI
                // escapes) are replaced so the text cannot drive a terminal.
                let description = bounded_description(
                    item.get("description").and_then(Json::as_str).unwrap_or(""),
                );
                session.tools.push(McpToolDef {
                    name: name.to_string(),
                    description,
                });
            }
        }
        Ok(session)
    }

    fn request_within(
        &mut self,
        method: &str,
        params: Json,
        deadline: Option<std::time::Instant>,
        grant: Option<usize>,
    ) -> Result<Json> {
        if self.poisoned {
            return Err(Error::Provider {
                code: "mcp/desync".to_string(),
            });
        }
        // Check the ceiling before the frame leaves: once it is sent, the call
        // can no longer be refused without the server having acted on it.
        if let Some(deadline) = deadline {
            if std::time::Instant::now() >= deadline {
                // Nothing has been written: the caller may keep the session
                // (round 35, N3).
                return Err(Error::Provider {
                    code: "mcp/not-sent".to_string(),
                });
            }
        }
        // Nothing has left yet: a refusal until the send succeeds keeps its
        // own class (round 42, M-1).
        self.after_send = false;
        // JSON-RPC ids wrap rather than panic in a long-lived session; id 0 is
        // skipped because it is the conventional "no id" notification value.
        self.next_id = self.next_id.wrapping_add(1);
        if self.next_id == 0 {
            self.next_id = 1;
        }
        let id = self.next_id;
        let payload = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        // Serialize into a capped buffer: a text-heavy argument becomes up to
        // six bytes per byte on the wire, so summing `Arg::wire_size` first
        // undercounts the JSON and the artifact was still built before the
        // ceiling refused it (round 40, F1).
        // Equality is the grant's case too: at `grant == MAX` no larger grant can
        // help, so the budget class is the honest one, as in the HTTP adapter
        // (round 43, F-9).
        let static_bound = grant.is_none_or(|grant| grant > MAX_MCP_LINE_BYTES);
        let cap = grant.map_or(MAX_MCP_LINE_BYTES, |grant| grant.min(MAX_MCP_LINE_BYTES));
        let mut writer = CappedWriter::new(cap);
        if serde_json::to_writer(&mut writer, &payload).is_err() {
            return Err(if !writer.exceeded {
                Error::InvalidArgument("the MCP request cannot be serialised")
            } else if static_bound {
                // Past only the static ceiling: no budget makes it legal
                // (round 27, #1 keeps the same code as the post-check).
                Error::InvalidArgument("the MCP request exceeds the line ceiling")
            } else {
                Error::BudgetExceeded("byte")
            });
        }
        let line = String::from_utf8(writer.out).map_err(|_| {
            Error::InvalidArgument("the MCP request is not valid UTF-8 after serialising")
        })?;
        if let Some(grant) = grant {
            if grant < MAX_MCP_LINE_BYTES && line.len() > grant {
                // The grant is the tighter bound: a request past it is a budget
                // exhaustion (round 26, #4).
                return Err(Error::BudgetExceeded("byte"));
            }
        }
        if line.len() > MAX_MCP_LINE_BYTES {
            // Past the static ceiling: a bad argument unless the grant is the
            // tighter bound at equality, where no larger grant helps and the
            // budget is the honest class (round 27, #1; round 44, L-10).
            // Belt and braces: CappedWriter already refused this line during
            // serialisation, so this arm is not reachable through invoke.
            return Err(if static_bound {
                Error::InvalidArgument("the MCP request exceeds the line ceiling")
            } else {
                Error::BudgetExceeded("byte")
            });
        }
        // The request spent part of the grant; only the remainder is available
        // to the answer (round 33, H1).
        let sent_bytes = line.len();
        // A ceiling already spent means nothing has been written: the session
        // stays usable, and the caller may retry (round 5, #5). The code says
        // so, so a caller does not treat it as an in-flight timeout
        // (round 35, N3).
        if let Some(deadline) = deadline {
            if std::time::Instant::now() >= deadline {
                return Err(Error::Provider {
                    code: "mcp/not-sent".to_string(),
                });
            }
        }
        if let Err(error) = self.transport.send_line_within(&line, deadline) {
            // A partial write desynchronises the stream: the next read could
            // answer this request with the previous call's remainder
            // (round 3, #3). A timeout takes the same path, because a frame the
            // writer thread already took may have reached the wire.
            // `mcp/queue` and `mcp/not-sent` are the exceptions: the writer
            // never took the frame, so the session stays usable
            // (round 29, F1; round 34, #7).
            let handed_over = !matches!(&error, Error::Provider { code }
                if code == "mcp/queue" || code == "mcp/not-sent" || code == "mcp/write:closed");
            if handed_over {
                self.poisoned = true;
                // The writer took the frame, so it may have reached the peer:
                // a writable call reports a withheld reply rather than a call
                // that did not happen (round 43, F-5).
                self.after_send = true;
            } else if !matches!(&error, Error::Provider { code }
                if code == "mcp/queue" || code == "mcp/not-sent")
            {
                // A closed writer never took the frame, but the session is
                // unusable: poison it without claiming the effect (round 44,
                // L-7).
                self.poisoned = true;
            }
            return Err(error);
        }
        // The frame left: from here a refusal is a withheld reply.
        self.after_send = true;
        let mut skipped = 0usize;
        // What the call has buffered so far: the request line plus every
        // notification frame read before the answer. A skipped frame is bytes
        // this call pays for, and sixteen of them under a small grant held
        // 16 MiB (round 35, N1).
        let mut spent = sent_bytes;
        loop {
            let line = match self.transport.recv_line_within(deadline) {
                Ok(line) => line,
                Err(error) => {
                    // The frame has already left (a send failure returned
                    // above), so a timeout here means the answer is still in
                    // flight: retrying would read it as the next answer while
                    // the peer has already run the (possibly mutating) tool
                    // (round 10, F-3).
                    self.poisoned = true;
                    return Err(error);
                }
            };
            if line.len() > MAX_MCP_LINE_BYTES {
                // A line past the static ceiling is illegal whatever the grant:
                // the peer wrote it, so the session is desynced and poisoned
                // (round 32, #3). A line that is only past the grant stays a
                // non-poisoning budget refusal below.
                self.poisoned = true;
                return Err(Error::Provider {
                    code: "mcp/line-too-long".to_string(),
                });
            }
            // The answer shares the grant with the request and every skipped
            // frame, and the parse is work the grant must authorise: a 1 MiB
            // line under a 200-byte grant decoded into a tree of megabytes
            // before the budget refused it (round 41, F1). A line that cannot
            // fit the remainder is refused here, before the text scan and the
            // parse. The refusal poisons the session: before the parse the
            // client cannot tell an over-grant notification (whose answer is
            // still queued) from the answer itself (round 42, H-1).
            if let Some(grant) = grant {
                let cap = grant.saturating_sub(spent).min(MAX_MCP_LINE_BYTES);
                if line.len() > cap {
                    // Poison whatever the line is: before the parse the client
                    // cannot tell an over-budget notification (the answer is
                    // still queued) from the answer itself, and continuing
                    // would let the next call's request reach the peer before
                    // the stale answer is read (round 42, H-1). This is the
                    // same fail-closed side as `mcp/line-too-long`. The class
                    // is the budget on a read-only call and a withheld reply on
                    // a writable one, decided in `invoke` (round 42, M-1).
                    self.poisoned = true;
                    return Err(Error::BudgetExceeded("byte"));
                }
            }
            // The node ceiling is enforced on the text before the tree exists:
            // a one-megabyte array of zeros decodes to half a million values,
            // and the HTTP adapter has refused that shape since round 13 while
            // this one built it (round 38, #4). The line is the peer's, so the
            // session is poisoned like any other illegal answer.
            if json_text_too_complex(&line, MAX_JSON_NODES) {
                self.poisoned = true;
                return Err(Error::Provider {
                    code: "mcp/too-complex".to_string(),
                });
            }
            let response: Json = match serde_json::from_str(&line) {
                // A shape whose token count understates its node count (a chain
                // of single-element arrays) is caught on the tree.
                Ok(response) if json_too_many_nodes(&response) => {
                    self.poisoned = true;
                    return Err(Error::Provider {
                        code: "mcp/too-complex".to_string(),
                    });
                }
                // A number the decoder rounded or an overflowing float is not
                // the answer the server wrote (round 15, F-1).
                Ok(response)
                    if json_text_bad_number(&line)
                        || json_has_unrepresentable_number(&response) =>
                {
                    self.poisoned = true;
                    return Err(Error::Provider {
                        code: "mcp/bad-number".to_string(),
                    });
                }
                Ok(response) => response,
                Err(_) if text_fails_only_on_a_number(&line) => {
                    self.poisoned = true;
                    return Err(Error::Provider {
                        code: "mcp/bad-number".to_string(),
                    });
                }
                Err(_) => {
                    self.poisoned = true;
                    return Err(Error::Provider {
                        code: "mcp/bad-response".to_string(),
                    });
                }
            };
            // A response must be an object and must answer *this* request. A
            // mismatched id means the peer is confused or hostile; do not accept
            // its payload as the answer to a different call.
            let Some(object) = response.as_object() else {
                self.poisoned = true;
                return Err(Error::Provider {
                    code: "mcp/bad-response".to_string(),
                });
            };
            match object.get("id") {
                // A frame carrying a `method` is a server-initiated request,
                // whatever id it reuses: answering it as our result lets a
                // peer choose the shape of our answer (round 18, L-3).
                Some(value) if value.as_u64() == Some(id) && !object.contains_key("method") => {
                    // The grant bound was applied to the line before the parse
                    // (round 41, F1), so the answer is already paid for.
                    let has_result = object.get("result").is_some();
                    let has_error = object.get("error").is_some();
                    if !has_result && !has_error {
                        self.poisoned = true;
                        return Err(Error::Provider {
                            code: "mcp/bad-response".to_string(),
                        });
                    }
                    if has_result && has_error {
                        // JSON-RPC forbids both members; preferring `error`
                        // let a peer choose which outcome the caller sees
                        // (round 24, #6).
                        self.poisoned = true;
                        return Err(Error::Provider {
                            code: "mcp/bad-response".to_string(),
                        });
                    }
                    return Ok(response);
                }
                // A notification has no `id` and is not an answer to this
                // request. Skip a bounded number so progress and log
                // notifications do not break a spec-compliant server.
                None if object.contains_key("method") => {
                    // The frame is buffered like any other, so it spends the
                    // grant. The line was already bounded by the remainder
                    // before the parse, so this only reaches the grant itself
                    // and never passes it (round 41, F1).
                    spent = spent.saturating_add(line.len());
                    skipped += 1;
                    if skipped > MAX_MCP_NOTIFICATIONS {
                        self.poisoned = true;
                        return Err(Error::Provider {
                            code: "mcp/desync".to_string(),
                        });
                    }
                }
                Some(_) => {
                    // A server-initiated request (its own id) or a stale
                    // answer. Either way the stream no longer lines up with
                    // the requests this session sent.
                    self.poisoned = true;
                    return Err(Error::Provider {
                        code: "mcp/id-mismatch".to_string(),
                    });
                }
                None => {
                    self.poisoned = true;
                    return Err(Error::Provider {
                        code: "mcp/bad-response".to_string(),
                    });
                }
            }
        }
    }

    /// Discovered tools.
    pub fn tools(&self) -> &[McpToolDef] {
        &self.tools
    }

    /// A policy allowing exactly the discovered tools.
    pub fn policy(&self) -> ToolPolicy {
        let mut policy = ToolPolicy::default();
        for tool in &self.tools {
            policy.allowed.insert(tool.name.clone());
        }
        // A frame ceiling minus the JSON envelope: an argument exactly at the
        // advertised size would be refused after being charged (round 8, F9).
        // A JSON frame escapes a control character six-fold, so the
        // deliverable size is a sixth of the frame minus the envelope
        // (round 9, F-2).
        policy.max_arg_bytes = (MAX_MCP_LINE_BYTES as u64 / 6).saturating_sub(256);
        policy
    }
}

impl<T: McpTransport> Provider for McpSession<T> {
    fn name(&self) -> &'static str {
        "mcp"
    }

    fn methods(&self) -> Vec<String> {
        self.tools.iter().map(|tool| tool.name.clone()).collect()
    }

    /// Answer the membership question without building the method table.
    ///
    /// The default implementation calls [`Self::methods`], which clones every
    /// name on every admitted call: with a few thousand tools that is about a
    /// megabyte of allocation per dispatch.
    fn has_method(&self, method: &str) -> bool {
        self.tools.iter().any(|tool| tool.name == method)
    }

    fn mutating(&self, _method: &str) -> bool {
        true
    }

    fn invoke(&mut self, object: u64, call: &Call) -> Result<Response> {
        if call.budget.max_wall_ms == 0 {
            return Err(Error::BudgetExceeded("wall"));
        }
        if call.budget.max_bytes == 0 {
            // A zero-byte grant cannot carry the answer. Checking it first
            // reports the budget for every argument size; the static line
            // ceiling used to mask it on a large request (round 24, #9).
            return Err(Error::BudgetExceeded("byte"));
        }
        if !call.payload.is_empty() {
            // The adapter builds `arguments` from the arguments; an envelope
            // payload would be dropped without the caller knowing
            // (round 3, #6).
            return Err(Error::InvalidArgument(
                "the MCP adapter does not accept an envelope payload",
            ));
        }
        if args_contain_secret(&call.args) {
            return Err(Error::ToolPolicy(
                "a secret argument cannot be sent to an external peer",
            ));
        }
        if call.path_scope.is_some() {
            // JSON arguments are not `Value::Path`: the kernel cannot check
            // them, so a scope here would be inert (round 9, F-1).
            return Err(Error::ToolPolicy(
                "this adapter cannot enforce a path scope",
            ));
        }
        // The grant bounds the arguments before they are serialized: a JSON
        // line built from a ten-megabyte map under a one-byte grant was work
        // the budget refused only afterwards (round 39, F2). The uniform
        // prefix is budget, payload, secret, scope, argument bytes, method
        // (round 40, F2).
        // checked_add, as the process and wasm adapters use: a debug build
        // must refuse an impossible sum rather than panic inside the adapter
        // (round 48, F-5).
        let mut arg_bytes = 0u64;
        for arg in &call.args {
            let Some(next) = arg_bytes.checked_add(Arg::wire_size(arg)) else {
                return Err(Error::BudgetExceeded("byte"));
            };
            arg_bytes = next;
        }
        if arg_bytes > call.budget.max_bytes {
            return Err(Error::BudgetExceeded("byte"));
        }
        // The method before the tool lookup: an out-of-range object and a bad
        // method reported the object refusal here while the other three
        // reported the method, which fingerprints the adapter (round 41, F3).
        if !self.tools.iter().any(|tool| tool.name == call.method) {
            return Err(Error::MethodNotGranted {
                method: call.method.clone(),
            });
        }
        let index =
            usize::try_from(object).map_err(|_| Error::InvalidArgument("unknown MCP tool"))?;
        let tool = self
            .tools
            .get(index)
            .ok_or(Error::InvalidArgument("unknown MCP tool"))?;
        if tool.name != call.method {
            return Err(Error::MethodNotGranted {
                method: call.method.clone(),
            });
        }
        let mut arguments = serde_json::Map::new();
        for (index, arg) in call.args.iter().enumerate() {
            match arg {
                Arg::Value(value) => {
                    if contains_module(value) {
                        // The JSON form is the byte length, so the peer would
                        // act on a request the caller never made (round 5, #2).
                        return Err(Error::InvalidArgument(
                            "an MCP argument cannot carry a module",
                        ));
                    }
                    if contains_nonfinite(value) {
                        // JSON has no NaN or infinities: serialising one hands
                        // the peer a null nobody wrote (round 6).
                        return Err(Error::InvalidArgument(
                            "an MCP argument cannot carry a non-finite number",
                        ));
                    }
                    if crate::kernel::value_too_deep(value, crate::wire::MAX_VALUE_DEPTH) {
                        // `value_to_json` recurses; a caller-built value past
                        // the wire depth would abort the stack where no
                        // `catch_unwind` can help (round 25, #1).
                        return Err(Error::InvalidArgument(
                            "an MCP argument is nested too deeply",
                        ));
                    }
                    arguments.insert(format!("arg{index}"), value_to_json(value));
                }
                // A capability or a promise is authority, not JSON text: the
                // adapter used to drop it and call the tool with the rest
                // (round 4, #3).
                Arg::Cap(_) | Arg::Promise(_) => {
                    return Err(Error::InvalidArgument("an MCP argument must be a value"))
                }
            }
        }
        // The capability's wall ceiling bounds the wait, not only the total: a
        // silent server must not hold the kernel for its own timeout.
        // A `u64::MAX` grant overflowed `checked_add` and became an instant
        // timeout; clamp the same way `LocalProcess` does (round 22, F-E).
        let ceiling = std::time::Duration::from_millis(call.budget.max_wall_ms.clamp(1, 300_000));
        let deadline = std::time::Instant::now()
            .checked_add(ceiling)
            .unwrap_or_else(std::time::Instant::now);
        let grant = usize::try_from(call.budget.max_bytes).unwrap_or(usize::MAX);
        // The raw grant, not the smaller of the two: `request_within` reports
        // the static ceiling separately so a line past both is a budget
        // refusal and a line past only the static ceiling is a bad argument
        // (round 27, #1).
        let max_line = grant;
        if self.poisoned {
            // Nothing leaves a poisoned session, so this refusal is not a
            // withheld reply (the post-send mapping below assumes the request
            // left), and it is not a served call either (round 48, F-8).
            return Err(Error::Provider {
                code: "mcp/desync".to_string(),
            });
        }
        // Count admitted calls only: a zero-grant or policy refusal is not a
        // served call (round 31, F7).
        self.calls += 1;
        let response = match self.request_within(
            "tools/call",
            json!({ "name": tool.name, "arguments": Json::Object(arguments) }),
            Some(deadline),
            Some(max_line),
        ) {
            Ok(response) => response,
            // The request left, so the peer may have run the tool: the class
            // says the reply was withheld; a send failure keeps its own code
            // (round 42, M-1).
            Err(error) => {
                let after_send = self.after_send;
                return Err(if after_send {
                    // An MCP tool has no read-only declaration of its own; the
                    // capability's flag is the only signal (round 42, M-1).
                    withhold_after_send(error, !call.read_only)
                } else {
                    error
                });
            }
        };
        if let Some(error) = response.get("error") {
            let Some(code) = error.get("code").and_then(Json::as_i64) else {
                // A missing or non-integer code is a malformed answer, not
                // code 0 (round 10, F-7). The answer arrived, so a writable
                // call reports a withheld reply (round 43, F-3).
                return Err(withhold_after_send(
                    Error::Provider {
                        code: "mcp/bad-response".to_string(),
                    },
                    !call.read_only,
                ));
            };
            return Err(Error::Provider {
                code: format!("mcp/{code}"),
            });
        }
        // `request_within` already refused a response whose tree or text holds
        // a number with no `Value` form, so the result is representable here.
        let result = response.get("result").cloned().unwrap_or(Json::Null);
        let value = json_to_value(&result);
        if crate::kernel::value_too_deep(&value, crate::wire::MAX_VALUE_DEPTH) {
            // A tree past the wire shape is an illegal answer, not a caller
            // budget: the session is poisoned like any other malformed frame
            // (round 49, L-4), and a writable call reports it as withheld
            // because the tool already ran (round 50, F-2).
            self.poisoned = true;
            return Err(withhold_after_send(
                Error::Provider {
                    code: "mcp/too-complex".to_string(),
                },
                !call.read_only,
            ));
        }
        Ok(Response::Value(value))
    }
}

// ---------------------------------------------------------------------------
// HTTP / OpenAPI
// ---------------------------------------------------------------------------

/// An HTTP endpoint restricted to an allowlist.
///
/// The allowlist is `(METHOD, path)` pairs. There is no redirect following, no
/// chunked encoding, and the body is bounded by `max_body`. A URL outside the
/// allowlist is `rpc/tool-policy`.
pub struct HttpTool {
    /// Base URL, e.g. `http://127.0.0.1:8080`.
    pub base: String,
    /// Allowed `(method, path)` pairs.
    pub allow: BTreeSet<(String, String)>,
    /// Maximum response bytes.
    pub max_body: usize,
    /// Maximum request bytes.
    pub max_request: usize,
    /// Calls served.
    pub calls: u64,
    /// Whether the last exchange put bytes on the wire. A refusal after that
    /// point may have applied its effect, so it is reported as a withheld
    /// reply for a mutating method (round 43, F-2).
    after_send: bool,
}

/// A base URL with any userinfo and path replaced by a length.
///
/// An exact allowlist entry is a credential home, and so is a base such as
/// `http://host/hooks/<token>`: `Debug` names the scheme and authority only
/// (round 49, L-1).
fn redacted_base(base: &str) -> String {
    let Some((scheme, rest)) = base.split_once("://") else {
        return format!("<{} bytes>", base.len());
    };
    let authority_raw = rest.split('/').next().unwrap_or(rest);
    let authority = authority_raw.rsplit('@').next().unwrap_or(authority_raw);
    let tail = rest.len().saturating_sub(authority_raw.len());
    if tail > 0 {
        format!("{scheme}://{authority}/<{} bytes>", tail.saturating_sub(1))
    } else {
        format!("{scheme}://{authority}")
    }
}

impl std::fmt::Debug for HttpTool {
    /// Names and shapes, never an allowlisted path: an exact entry is the
    /// natural home of a fixed credential (a signed URL, a hook token), the
    /// same rule `LocalProcess` follows (round 48, F-1).
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let allow: Vec<String> = self
            .allow
            .iter()
            .map(|(method, path)| format!("{method} <{} bytes>", path.len()))
            .collect();
        formatter
            .debug_struct("HttpTool")
            .field("base", &redacted_base(&self.base))
            .field("allow", &allow)
            .field("max_body", &self.max_body)
            .field("max_request", &self.max_request)
            .field("calls", &self.calls)
            .finish()
    }
}

impl HttpTool {
    /// Whether an exact-match allow-list entry is ambiguous for a peer.
    ///
    /// The adapter sends the path verbatim and compares it as a string while a
    /// server normalizes: a dot segment, percent escape, query, fragment,
    /// backslash, double slash or non-printable byte can name a different
    /// resource than the allowlisted string (round 27, #4; round 29, F4).
    fn ambiguous_path(path: &str) -> bool {
        !path.starts_with('/')
            || path.contains('%')
            || path.contains('?')
            || path.contains('#')
            || path.contains('\\')
            || path.contains("//")
            || path
                .split('/')
                .any(|segment| segment == ".." || segment == ".")
            || path.bytes().any(|byte| !(0x21..=0x7e).contains(&byte))
    }

    /// Build a tool for `base` with an allowlist.
    ///
    /// An ambiguous entry is dropped: the peer normalizes, so such an entry
    /// could name a different resource, and a dead entry is safer than a
    /// silently widened one. [`HttpTool::try_new`] refuses at construction
    /// instead.
    pub fn new(base: impl Into<String>, allow: &[(&str, &str)]) -> Self {
        Self {
            base: base.into(),
            allow: allow
                .iter()
                // `invoke` uppercases the requested method, so a lowercase
                // allowlist entry used to match nothing and the capability was
                // permanently dead (round 16, F-8).
                .filter(|(_, path)| !Self::ambiguous_path(path))
                .map(|(method, path)| (method.to_ascii_uppercase(), path.to_string()))
                .collect(),
            max_body: 1 << 20,
            max_request: 1 << 20,
            calls: 0,
            after_send: false,
        }
    }

    /// [`HttpTool::new`] that refuses an ambiguous allowlist entry.
    pub fn try_new(base: impl Into<String>, allow: &[(&str, &str)]) -> Result<Self> {
        if allow.iter().any(|(_, path)| Self::ambiguous_path(path)) {
            return Err(Error::ToolPolicy(
                "an allowlist entry has an ambiguous path",
            ));
        }
        Ok(Self::new(base, allow))
    }

    /// Build a tool policy for a capability.
    pub fn policy(&self) -> ToolPolicy {
        ToolPolicy {
            allowed: ["get", "post", "request"]
                .iter()
                .map(|method| method.to_string())
                .collect(),
            // The serialised body adds keys, quotes and up to six-fold escaping.
            max_arg_bytes: ((self.max_request.min(MAX_REQUEST_BYTES) as u64) / 6)
                .saturating_sub(256),
            allow_process: false,
        }
    }

    // One exchange needs the method, the path, the body, the wall ceiling and
    // three byte limits; grouping the limits would add an allocation-free struct
    // for a private helper.
    #[allow(clippy::too_many_arguments)]
    fn perform(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        ceiling_ms: u64,
        static_ceiling: usize,
        grant: usize,
    ) -> Result<(u16, Vec<u8>)> {
        // A cap-derived refusal is a budget exhaustion when the capability's
        // grant set the cap, and a provider framing fault otherwise
        // (round 25, #7).
        let capped = |code: &'static str, grant_bound: bool| {
            if grant_bound {
                Error::BudgetExceeded("byte")
            } else {
                Error::Provider {
                    code: code.to_string(),
                }
            }
        };
        let base = self
            .base
            .strip_prefix("http://")
            .ok_or(Error::ToolPolicy("only http:// endpoints are supported"))?;
        // The request head is part of what the capability pays for: an
        // unbounded `base` or an allowlisted long path could otherwise write
        // megabytes before any response check (round 26, #2). A GET carries no
        // `content-length` and no body (the request ends at the empty line).
        let head = {
            let mut head =
                format!("{method} {path} HTTP/1.1\r\nhost: {base}\r\nconnection: close\r\n");
            if let Some(body) = body {
                head.push_str(&format!("content-length: {}\r\n", body.len()));
            }
            head.push_str("\r\n");
            head
        };
        // Most of the head is fixed adapter framing (method, version, host
        // header), so a small allowance is free; what exceeds it is data the
        // capability pays for. A megabyte of `base` or an allowlisted long path
        // must not be written under a tiny grant (round 26, #2).
        const HEAD_ALLOWANCE: usize = 256;
        let charged = head
            .len()
            .saturating_sub(HEAD_ALLOWANCE)
            .saturating_add(body.map_or(0, <[u8]>::len));
        if charged > grant {
            return Err(Error::BudgetExceeded("byte"));
        }
        // The request spent part of the grant; only the remainder is available
        // to the answer (round 33, H1). Whether the grant left less than the
        // static ceiling is decided here, after the charge (round 34, #3).
        let max_body = static_ceiling.min(grant.saturating_sub(charged));
        let grant_bound = max_body < static_ceiling;
        // A grant too small to hold the head cannot pay for the answer; the
        // static ceiling was its only bound (round 20, M3).
        if max_body < MIN_HTTP_ANSWER_BYTES {
            // No answer of any shape fits. When the capability's grant set the
            // cap it is a budget refusal; when the adapter's own `max_body` did,
            // the refusal is a provider/configuration one (round 24, #4;
            // round 30, #3).
            return Err(if grant_bound {
                Error::BudgetExceeded("byte")
            } else {
                Error::Provider {
                    code: "http/body-too-large".to_string(),
                }
            });
        }
        let header_cap = MAX_HTTP_HEADER_BYTES.min(max_body.max(1));
        // Resolution is not peer-controlled: the base URL is the operator's
        // endpoint, so the system resolver's own timeout applies here and its
        // time is not charged against the grant (round 16, F-3).
        let addresses: Vec<std::net::SocketAddr> = std::net::ToSocketAddrs::to_socket_addrs(base)
            .map_err(|error| Error::Provider {
                code: format!("http/resolve:{error}"),
            })?
            .collect();
        // The adapter's fixed ten seconds and the capability's wall ceiling both
        // bound the wait; the smaller one wins. This is one deadline for the
        // whole exchange, not a per-syscall timeout: a timeout bounds one
        // `read`, so a server that drips one byte per period would otherwise
        // hold the dispatch thread for (bytes x timeout).
        let deadline = std::time::Instant::now()
            .checked_add(
                std::time::Duration::from_millis(ceiling_ms.max(1))
                    .min(std::time::Duration::from_secs(10)),
            )
            .unwrap_or_else(std::time::Instant::now);
        let mut connected = None;
        let mut last = None;
        for address in addresses {
            // Every attempt gets only the time that is left, so a host with
            // many addresses cannot multiply the ceiling.
            let remaining = remaining_until(deadline)?;
            match TcpStream::connect_timeout(&address, remaining) {
                Ok(stream) => {
                    connected = Some(stream);
                    break;
                }
                Err(error) => last = Some(error),
            }
        }
        let mut stream = match connected {
            Some(stream) => stream,
            // A connect that timed out is the ceiling (a blackhole burns the
            // whole grant); anything else is a transport fault
            // (round 4, #2).
            None => {
                let timed_out = last.is_some_and(|error| {
                    matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    )
                });
                return Err(if timed_out {
                    Error::Timeout
                } else {
                    Error::Provider {
                        code: "http/connect".to_string(),
                    }
                });
            }
        };
        stream
            .set_write_timeout(Some(remaining_until(deadline)?))
            .map_err(|_| Error::Timeout)?;
        // The timeout above is per write syscall. A peer that reads one byte
        // per (ceiling - epsilon) makes every write return `Ok(1)`, so the phase
        // would cost body_len * interval; the deadline is re-armed and re-checked
        // per chunk instead (round 8, F3).
        // Nothing has left yet; the head carries the method and the path, so
        // once it is written the peer may act (round 43, F-2).
        self.after_send = false;
        // A head written in chunks can fail after its first chunk: any byte on
        // the wire means the peer may act, even though the line is incomplete
        // (round 47, L-4).
        let (head_written, head_result) = write_within(&mut stream, head.as_bytes(), deadline);
        if head_written > 0 {
            self.after_send = true;
        }
        head_result?;
        if let Some(body) = body {
            let (_, body_result) = write_within(&mut stream, body, deadline);
            body_result?;
        }
        stream.flush().map_err(map_http_write)?;
        let mut reader = DeadlineReader::new(stream, deadline);
        // Every line is read under a cap, and the block has its own budget: a
        // hostile endpoint that streams headers would otherwise grow a `String`
        // until the allocator aborts the process (outside `catch_unwind`).
        let mut status_line = reader
            .line(MAX_HTTP_STATUS_LINE.min(header_cap).max(1))
            .map_err(|error| match &error {
                Error::Provider { code } if grant_bound && code == "http/line-too-long" => {
                    Error::BudgetExceeded("byte")
                }
                _ => error,
            })?;
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            // Exactly three digits: `+200` and `000200` are not statuses
            // (round 12, F-8).
            .filter(|code| code.len() == 3 && code.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|code| code.parse().ok())
            .ok_or(Error::Provider {
                code: "http/status".to_string(),
            })?;
        // `HTTP/1.<digit>` followed by a space: a prefix check accepted
        // `HTTP/1.1x 200` and `HTTP/1.12 200` (round 14, F-4).
        let bytes = status_line.as_bytes();
        let version_ok = bytes.starts_with(b"HTTP/1.")
            && bytes.get(7).is_some_and(u8::is_ascii_digit)
            && bytes.get(8) == Some(&b' ');
        if !version_ok {
            return Err(Error::Provider {
                code: "http/status".to_string(),
            });
        }
        if (100..200).contains(&status) {
            return Err(Error::Provider {
                code: "http/interim".to_string(),
            });
        }
        if !(200..=599).contains(&status) {
            // A three-digit status outside the defined ranges is a malformed
            // answer, not a success: `099` used to be read as one
            // (round 3, #8).
            return Err(Error::Provider {
                code: "http/status".to_string(),
            });
        }
        // The status line is part of the head the grant pays for
        // (round 23, #2).
        let mut header_bytes = status_line.len();
        status_line.clear();
        let mut content_length: Option<usize> = None;
        let mut fields = 0usize;
        loop {
            let line = reader
                .line(MAX_HTTP_HEADER_LINE.min(header_cap).max(1))
                .map_err(|error| match &error {
                    Error::Provider { code } if grant_bound && code == "http/line-too-long" => {
                        Error::BudgetExceeded("byte")
                    }
                    _ => error,
                })?;
            if line == "\r\n" || line == "\n" {
                // The empty line is part of the head the grant pays for. Not
                // counting it left the body cap two bytes too generous
                // (round 25, #5).
                header_bytes = header_bytes.saturating_add(line.len());
                break;
            }
            if line.trim().is_empty() {
                // A whitespace-only line is obsolete line folding, not the end
                // of the block: accepting it let a field written after it reach
                // the caller as body (round 9, F-3).
                return Err(Error::Provider {
                    code: "http/headers".to_string(),
                });
            }
            header_bytes = header_bytes.saturating_add(line.len());
            fields += 1;
            if header_bytes > header_cap {
                return Err(capped("http/headers", grant_bound));
            }
            if fields > MAX_HTTP_HEADER_FIELDS {
                // A field *count* is never a grant matter: the same answer is a
                // header fault whatever the byte grant (round 50, F-6).
                return Err(Error::Provider {
                    code: "http/headers".to_string(),
                });
            }
            let Some((name, value)) = line.split_once(':') else {
                // A header line without a colon is a framing fault: ignoring it
                // let a peer hide a field from the check that follows
                // (round 3, #8).
                return Err(Error::Provider {
                    code: "http/headers".to_string(),
                });
            };
            // A space before the colon is obsolete line folding syntax that
            // some peers accept: `transfer-encoding : chunked` used to slip past
            // the check below and the caller received chunk framing
            // (round 8, F2). A field name is an RFC 9110 token.
            if name.is_empty() || !name.bytes().all(is_http_token) {
                return Err(Error::Provider {
                    code: "http/headers".to_string(),
                });
            }
            {
                if name.eq_ignore_ascii_case("transfer-encoding")
                    && !value.trim().eq_ignore_ascii_case("identity")
                {
                    // Chunked framing is not a body: returning it as payload
                    // would hand the caller protocol bytes to parse.
                    return Err(Error::Provider {
                        code: "http/transfer-encoding".to_string(),
                    });
                }
                if name.eq_ignore_ascii_case("content-length") {
                    // A repeated or unparsable length is a framing ambiguity:
                    // silently switching to read-to-end would let the peer
                    // choose how the message is delimited.
                    // Digits only: `+2`, `0x2` and a sign are not a length.
                    let trimmed = value.trim();
                    if trimmed.is_empty() || !trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
                        return Err(Error::Provider {
                            code: "http/headers".to_string(),
                        });
                    }
                    let value: usize = trimmed.parse().map_err(|_| Error::Provider {
                        code: "http/headers".to_string(),
                    })?;
                    if content_length.replace(value).is_some() {
                        return Err(Error::Provider {
                            code: "http/headers".to_string(),
                        });
                    }
                }
            }
        }
        // A HEAD reply, 204 and 304 carry no content even when the headers
        // describe one: `content-length` there belongs to the representation,
        // not to this message. Reading it would block until the ceiling.
        if method.eq_ignore_ascii_case("HEAD") || status == 204 || status == 304 {
            return Ok((status, Vec::new()));
        }
        // A non-2xx answer is a refusal: the adapter returns `http/<status>`
        // and never hands the body to the caller, so a hostile endpoint cannot
        // force up to the grant of buffering per 404 (round 29, F3). The
        // connection is `close`, so abandoning the body is safe.
        if !(200..300).contains(&status) {
            return Ok((status, Vec::new()));
        }
        // The head already spent part of the grant; the body may use the rest
        // (round 22, F-F).
        let body_cap = max_body.saturating_sub(header_bytes);
        if content_length == Some(0) {
            // A declared empty body needs no room. Refusing it at the exact
            // grant boundary while the same empty answer without a
            // `content-length` succeeded let the peer choose the outcome by
            // choosing a framing (round 41, F5).
            return Ok((status, Vec::new()));
        }
        let body = match content_length {
            Some(length) => {
                // The peer names this length; a caller-set `max_body` past a
                // sane ceiling would turn it into an allocation abort
                // (round 11, #14).
                if length > MAX_RESPONSE_BYTES {
                    return Err(capped("http/body-too-large", grant_bound));
                }
                if length > body_cap {
                    // The same code as the read-to-end arm: a peer must not
                    // choose the code by choosing a framing (round 12, F-5).
                    return Err(capped("http/body-too-large", grant_bound));
                }
                reader.body_exact(length)?
            }
            None => {
                // `body_rest` already enforces `min(max_body, MAX_RESPONSE_BYTES)`
                // and answers `http/body-too-large` (round 13, F-4).
                reader.body_rest(body_cap.min(MAX_RESPONSE_BYTES)).map_err(
                    |error| match &error {
                        Error::Provider { code }
                            if grant_bound && code == "http/body-too-large" =>
                        {
                            Error::BudgetExceeded("byte")
                        }
                        _ => error,
                    },
                )?
            }
        };
        Ok((status, body))
    }
}

impl Provider for HttpTool {
    fn name(&self) -> &'static str {
        "http"
    }

    fn methods(&self) -> Vec<String> {
        ["get", "post", "request"]
            .iter()
            .map(|method| method.to_string())
            .collect()
    }

    fn mutating(&self, method: &str) -> bool {
        method != "get"
    }

    fn invoke(&mut self, _object: u64, call: &Call) -> Result<Response> {
        if call.budget.max_wall_ms == 0 {
            // A zero grant is a refusal, not a one-millisecond grant: the
            // adapters used `.max(1)` and did the work anyway (round 4, #5).
            return Err(Error::BudgetExceeded("wall"));
        }
        if call.budget.max_bytes == 0 {
            // A zero-byte grant cannot carry an answer; do not open a socket
            // (round 21, F7).
            return Err(Error::BudgetExceeded("byte"));
        }
        if !call.payload.is_empty() {
            // This adapter sends the body it builds from the arguments; an
            // envelope payload would be silently dropped (round 3, #6).
            return Err(Error::InvalidArgument(
                "the HTTP adapter does not accept an envelope payload",
            ));
        }
        if args_contain_secret(&call.args) {
            // The placeholder is not the value: an external peer that acts on
            // `***SECRET***` acts on data the caller never approved
            // (round 3, #7).
            return Err(Error::ToolPolicy(
                "a secret argument cannot be sent to an external peer",
            ));
        }
        if call.path_scope.is_some() {
            // The kernel's scope check compares dotted paths, which means
            // nothing for a `/`-separated URL path: a scoped HTTP capability
            // would look confined while only the allow-list confined it
            // (round 26, #1). The other adapters refuse the same way.
            return Err(Error::ToolPolicy(
                "this adapter cannot enforce a path scope",
            ));
        }
        // The grant bounds the argument bytes before the adapter serializes
        // them: a one-byte grant with a ten-megabyte map built the JSON first
        // and only then refused (round 39, F2).
        // checked_add, as the process and wasm adapters use: a debug build
        // must refuse an impossible sum rather than panic inside the adapter
        // (round 48, F-5).
        let mut arg_bytes = 0u64;
        for arg in &call.args {
            let Some(next) = arg_bytes.checked_add(Arg::wire_size(arg)) else {
                return Err(Error::BudgetExceeded("byte"));
            };
            arg_bytes = next;
        }
        if arg_bytes > call.budget.max_bytes {
            return Err(Error::BudgetExceeded("byte"));
        }
        // Method before shape: the other three adapters report the method
        // refusal first, and the difference fingerprints the adapter for the
        // same malformed call (round 39, F3).
        if !matches!(call.method.as_str(), "get" | "post" | "request") {
            return Err(Error::MethodNotGranted {
                method: call.method.clone(),
            });
        }
        let takes_method_text = call.method == "request";
        for arg in &call.args {
            match arg {
                // The request is built from a method text, a path and a body
                // map; any other shape used to be dropped silently
                // (round 4, #3).
                Arg::Value(Value::Text(_)) if takes_method_text => {}
                Arg::Value(Value::Text(_)) => {
                    // `get` and `post` name their method in the capability:
                    // a text argument reached them and was dropped, so the
                    // peer acted without data the caller approved
                    // (round 5, #1).
                    return Err(Error::InvalidArgument(
                        "get and post take no method text; use request",
                    ));
                }
                Arg::Value(Value::Path(_)) | Arg::Value(Value::Map(_)) => {}
                Arg::Value(_) | Arg::Cap(_) | Arg::Promise(_) => {
                    return Err(Error::InvalidArgument(
                        "an HTTP argument is a method text, a path or a body object",
                    ))
                }
            }
        }
        let method: String = match call.method.as_str() {
            "get" => "GET".to_string(),
            "post" => "POST".to_string(),
            "request" => {
                let requested: Vec<&str> = call
                    .args
                    .iter()
                    .filter_map(|arg| match arg {
                        Arg::Value(Value::Text(text)) => Some(text.as_str()),
                        _ => None,
                    })
                    .collect();
                // One method, and only ASCII: `to_uppercase` maps `ß` to `SS`,
                // which aliases an allowlisted method into another one
                // (round 3, #5).
                if requested.len() > 1 {
                    return Err(Error::InvalidArgument("an HTTP request names one method"));
                }
                requested
                    .first()
                    .map(|text| text.to_ascii_uppercase())
                    // Guessing `GET` would act on a method the caller never
                    // named (round 11, #5).
                    .ok_or(Error::InvalidArgument("an HTTP request names one method"))?
            }
            other => {
                return Err(Error::MethodNotGranted {
                    method: other.to_string(),
                })
            }
        };
        // The method text is interpolated into the request line, where only
        // token characters are legal: anything else would split the request.
        // RFC 9110 token characters, not "A-Z only": `M-SEARCH` and the digits
        // in a vendor method are legal, and anything outside the token set
        // splits the request line.
        if method.is_empty() || !method.bytes().all(is_http_token) {
            return Err(Error::ToolPolicy("the HTTP method is not a token"));
        }
        // The path is a `Value::Path` and nothing else. Accepting a text
        // argument that starts with `/` would give a caller a second, invisible
        // route to the path: the kernel's path scope walks `Value::Path`, so a
        // text path would reach the adapter without ever being checked.
        let paths: Vec<&String> = call
            .args
            .iter()
            .filter_map(|arg| match arg {
                Arg::Value(Value::Path(path)) => Some(path),
                _ => None,
            })
            .collect();
        if paths.len() > 1 {
            // The adapter used to take the first and drop the rest, so a caller
            // could hand it two paths and believe both were used
            // (round 3, #6).
            return Err(Error::InvalidArgument("an HTTP request names one path"));
        }
        let path = paths
            .first()
            .map(|path| (*path).clone())
            .ok_or(Error::InvalidArgument("an HTTP path argument is required"))?;
        // The path reaches the request line verbatim. The allowlist gates it,
        // but a configuration entry that contains a control character would be
        // request splitting, so refuse the bytes outright.
        if path.bytes().any(|byte| !(0x21..=0x7e).contains(&byte)) {
            // Control characters split the request; bytes above ASCII are not
            // percent-encoded by this adapter and would reach the wire as
            // non-ASCII in a request line (round 3, #8).
            return Err(Error::ToolPolicy(
                "a path argument must be printable ASCII without spaces",
            ));
        }
        // The allow-list is an exact string match while the peer normalizes:
        // an ambiguous path is refused before the allowlist is consulted, and
        // `new` drops such an entry (round 27, #4; round 29, F4).
        if Self::ambiguous_path(&path) {
            return Err(Error::ToolPolicy(
                "a path with a dot segment, escape, query or fragment is refused",
            ));
        }
        // The base is the operator's endpoint, but a control character in it is a
        // request split waiting for a configuration mistake (round 3, #8).
        if self.base.bytes().any(|byte| !(0x21..=0x7e).contains(&byte)) {
            return Err(Error::ToolPolicy(
                "the HTTP base contains whitespace or a control character",
            ));
        }
        if !self.allow.contains(&(method.to_string(), path.clone())) {
            return Err(Error::ToolPolicy("path is not on the allowlist"));
        }
        let bodies: Vec<&std::collections::BTreeMap<String, Value>> = call
            .args
            .iter()
            .filter_map(|arg| match arg {
                Arg::Value(Value::Map(entries)) => Some(entries),
                _ => None,
            })
            .collect();
        if bodies.len() > 1 {
            return Err(Error::InvalidArgument(
                "an HTTP request names one body object",
            ));
        }
        if !takes_request_body(&method) && !bodies.is_empty() {
            // A body on a method defined without content is dropped by the old
            // adapter: the caller believes it sent data that never left
            // (round 3, #6).
            return Err(Error::InvalidArgument(
                "this HTTP method does not carry a body",
            ));
        }
        let body = if takes_request_body(&method) {
            // A bodyless POST used to send the four bytes `null` under
            // `content-length: 4`: a lax peer then acted on a JSON null nobody
            // wrote (round 5, #4). No body object means an empty body.
            let body = match bodies.first() {
                Some(entries) => {
                    // The clone below is recursive: a caller-built map past the
                    // wire depth would abort the stack before the gate on the value
                    // ran. The walk is over borrowed values, so it costs no copy
                    // (round 48, F-3).
                    if entries.values().any(|value| {
                        crate::kernel::value_too_deep(value, crate::wire::MAX_VALUE_DEPTH - 1)
                    }) {
                        return Err(Error::InvalidArgument("an HTTP body is nested too deeply"));
                    }
                    let value = Value::Map((*entries).clone());
                    if contains_module(&value) {
                        // The JSON form of a module is its length: the peer
                        // would act on a body the caller never wrote
                        // (round 5, #2).
                        return Err(Error::InvalidArgument("an HTTP body cannot carry a module"));
                    }
                    if contains_nonfinite(&value) {
                        // JSON has no NaN or infinities: serialising one hands
                        // the peer a null nobody wrote (round 6).
                        return Err(Error::InvalidArgument(
                            "an HTTP body cannot carry a non-finite number",
                        ));
                    }
                    if crate::kernel::value_too_deep(&value, crate::wire::MAX_VALUE_DEPTH) {
                        // `value_to_json` recurses (round 25, #1).
                        return Err(Error::InvalidArgument("an HTTP body is nested too deeply"));
                    }
                    {
                        // Same cap as the request line: JSON escaping can
                        // multiply a text argument (round 40, F1). The static
                        // request ceiling is part of the cap too, so an
                        // artifact past it is never built; the refusal keeps
                        // the tool-policy code the spec names for that ceiling
                        // (round 41, F4).
                        let grant_cap =
                            usize::try_from(call.budget.max_bytes).unwrap_or(usize::MAX);
                        let static_cap = self.max_request.min(MAX_REQUEST_BYTES);
                        let static_bound = static_cap < grant_cap;
                        let mut writer = CappedWriter::new(grant_cap.min(static_cap));
                        if serde_json::to_writer(&mut writer, &value_to_json(&value)).is_err() {
                            return Err(if !writer.exceeded {
                                Error::InvalidArgument("the HTTP body cannot be serialised")
                            } else if static_bound {
                                Error::ToolPolicy("request too large")
                            } else {
                                Error::BudgetExceeded("byte")
                            });
                        }
                        writer.out
                    }
                }
                None => Vec::new(),
            };
            let grant = usize::try_from(call.budget.max_bytes).unwrap_or(usize::MAX);
            // A public field can be set past any sane ceiling; the static cap
            // bounds it regardless of the grant (round 21, F10).
            if body.len() > grant {
                // The capability's grant is the tighter authority, so the
                // refusal names the budget rather than a tool policy
                // (round 25, #2).
                return Err(Error::BudgetExceeded("byte"));
            }
            if body.len() > self.max_request.min(MAX_REQUEST_BYTES) {
                return Err(Error::ToolPolicy("request too large"));
            }
            Some(body)
        } else {
            None
        };
        let grant = usize::try_from(call.budget.max_bytes).unwrap_or(usize::MAX);
        let static_ceiling = self.max_body.min(MAX_RESPONSE_BYTES);
        // The axis is the capability's method, not the resolution: a `get`
        // cannot change anything, so its 404 keeps its status, while `post`
        // and `request` withhold whatever method text they carry - the same
        // axis the kernel's `Provider::mutating` sees (round 43, F-1;
        // round 45, finding 1; round 47, L-2).
        let mutating = self.mutating(&call.method);
        // Count admitted calls only (round 31, F7).
        self.calls += 1;
        self.after_send = false;
        let (status, response) = match self.perform(
            &method,
            &path,
            body.as_deref(),
            call.budget.max_wall_ms,
            static_ceiling,
            grant,
        ) {
            Ok(pair) => pair,
            // Withhold only when the request actually left: a resolve, connect or
            // pre-send budget refusal must keep its class, or a deployment that
            // cannot resolve a name records an applied write and burns the key
            // (round 43, F-2).
            Err(error) => {
                let sent = self.after_send;
                return Err(if sent {
                    withhold_after_send(error, mutating)
                } else {
                    error
                });
            }
        };
        if !(200..300).contains(&status) {
            // A 3xx is not a completed call: the adapter does not follow
            // redirects, so a caller that saw `Ok` would believe a mutating
            // request ran (round 12, F-7). A writable call may have run anyway,
            // so it reports the withheld reply (round 42, M-1).
            return Err(withhold_after_send(
                Error::Provider {
                    code: format!("http/{status}"),
                },
                mutating,
            ));
        }
        // A binary answer is not text: transcoding it inserts replacement
        // characters the peer never wrote (round 12, F-6).
        // `from_utf8` returns the bytes on failure, so no clone is needed.
        let text = match String::from_utf8(response) {
            Ok(text) => text,
            Err(error) => return Ok(Response::Value(Value::Module(error.into_bytes()))),
        };
        // RFC 8259 lets a parser ignore a leading byte-order mark; serde_json
        // does not, and an unstripped one would hide a huge array from the size
        // gate and the number scan (round 17, F-5). Whitespace and repeated
        // marks are skipped too: one `strip_prefix` let `" \u{feff}[huge]"`
        // through as text (round 18, L-2).
        let json_text = text.trim_start_matches(|character: char| {
            character.is_whitespace() || character == '\u{feff}'
        });
        // Only an object or an array can hold more nodes than the ceiling (a
        // top-level scalar is one node), so a large non-JSON body — a CSV or a
        // log extract — is left as text (round 15, F-6). The token gate runs
        // first so the decode is bounded; a tree the gate lets through but that
        // still holds too many nodes (a chain of single-element arrays adds
        // nodes without tokens) is answered from the tree with the same code
        // (round 16, F-2).
        let trimmed = json_text.trim_start();
        if (trimmed.starts_with('{') || trimmed.starts_with('['))
            && json_text_too_complex(json_text, MAX_JSON_NODES)
        {
            // The answer arrived: for a mutating method the effect may stand,
            // and a pre-effect class would let the caller retry a write
            // (round 43, F-3).
            return Err(withhold_after_send(
                Error::Provider {
                    code: "http/too-complex".to_string(),
                },
                mutating,
            ));
        }
        let value = match serde_json::from_str::<Json>(json_text) {
            Ok(json) if json_too_many_nodes(&json) => {
                return Err(withhold_after_send(
                    Error::Provider {
                        code: "http/too-complex".to_string(),
                    },
                    mutating,
                ));
            }
            Ok(json)
                if json_has_unrepresentable_number(&json) || json_text_bad_number(json_text) =>
            {
                return Err(withhold_after_send(
                    Error::Provider {
                        code: "http/bad-number".to_string(),
                    },
                    mutating,
                ));
            }
            Ok(json) => {
                let value = json_to_value(&json);
                if crate::kernel::value_too_deep(&value, crate::wire::MAX_VALUE_DEPTH) {
                    // The answer's shape is the peer's fault, not the caller's
                    // budget (round 49, L-4).
                    return Err(withhold_after_send(
                        Error::Provider {
                            code: "http/too-complex".to_string(),
                        },
                        mutating,
                    ));
                }
                value
            }
            Err(_) if text_fails_only_on_a_number(json_text) => {
                return Err(withhold_after_send(
                    Error::Provider {
                        code: "http/bad-number".to_string(),
                    },
                    mutating,
                ));
            }
            Err(_) => Value::Text(text),
        };
        Ok(Response::Value(value))
    }
}

/// Characters that make a shell interpret an argument as syntax.
///
/// `cmd.exe` separates commands with `& | < > ^ ( )` and the quoted forms; a
/// POSIX shell adds `;`, and both expand `$`, backticks and (for `cmd`) `%`.
/// A newline or NUL ends the line outright.
const SHELL_METACHARACTERS: &[char] = &[
    '&', '|', '<', '>', '^', '(', ')', ';', '"', '\'', '$', '`', '%', '\n', '\r', '\u{0}',
    // Globs, braces, tilde and the comment character are expansion syntax too:
    // `echo /*` lists the filesystem through a prefix grant (round 3, #4).
    '*', '?', '[', ']', '{', '}', '~', '#', '!',
];

/// A writer that refuses once the artifact would pass a ceiling.
///
/// `serde_json` serializes into a `Vec` with no bound, so a text-heavy argument
/// (one control byte becomes `\u00XX`) could build six times the grant before
/// the post-check refused it. The cap makes the refusal happen during the
/// serialization (round 40, F1).
struct CappedWriter {
    out: Vec<u8>,
    cap: usize,
    exceeded: bool,
}

impl CappedWriter {
    fn new(cap: usize) -> Self {
        Self {
            out: Vec::new(),
            cap,
            exceeded: false,
        }
    }
}

impl std::io::Write for CappedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.out.len().saturating_add(buf.len()) > self.cap {
            self.exceeded = true;
            return Err(std::io::Error::other("capped"));
        }
        self.out.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// RFC 9110 token characters, the only bytes legal in a request method.
pub(crate) fn is_http_token(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
    )
}

/// Whether any argument carries a secret marker.
pub(crate) fn args_contain_secret(args: &[Arg]) -> bool {
    args.iter().any(|arg| match arg {
        Arg::Value(value) => value.is_tainted(),
        Arg::Promise(_) | Arg::Cap(_) => false,
    })
}

/// End a child's process tree and reap the leader.
///
/// On Unix the caller puts the child in its own process group, so one signal
/// reaches every descendant it started. `/bin/kill` and `/usr/bin/kill` are
/// tried because this crate forbids `unsafe` and std has no signal API; a
/// platform with neither still loses the leader.
///
/// On Windows only the leader is killed. The previous implementation spawned
/// `%SystemRoot%\System32\taskkill.exe`, and `SystemRoot` is a mutable process
/// environment value: a poisoned environment chose the binary that ran during
/// every error path (audit ARPC-004). A job object is the complete fix and
/// needs `unsafe` FFI, which this crate forbids; until that lands, a descendant
/// that outlives its leader is a recorded residual (STATUS.md), and no helper
/// executable is ever launched.
fn kill_process_tree(child: &mut Child) {
    #[cfg(windows)]
    {
        let _ = child.kill();
    }
    #[cfg(unix)]
    {
        // The negative pid is the process group the callers create. The leader
        // may have exited already; the group stays allocated while any member
        // is alive, which is exactly the case this has to handle.
        let group = format!("-{}", child.id());
        for candidate in ["/bin/kill", "/usr/bin/kill"] {
            let killed = Command::new(candidate)
                .args(["-KILL", "--", group.as_str()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|status| status.success())
                .unwrap_or(false);
            if killed {
                break;
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// Local process
// ---------------------------------------------------------------------------

/// Resolve and pin a program path for an adapter.
///
/// A bare or relative name would be resolved from the parent's `PATH` or its
/// working directory, which is ambient authority: anything that can write an
/// earlier `PATH` entry picks the binary a capability runs. The canonical path
/// is pinned so a symlink swapped in before the first spawn cannot redirect the
/// exec, so the program must resolve now: a path that does not exist is
/// refused rather than carried to a later spawn (round 17, F-3).
fn pin_program(program: &str, refusal: &'static str) -> Result<PathBuf> {
    // A NUL never reaches an exec, and `canonicalize` would fail into a raw
    // path and a spawn-time provider fault (round 9, F-7).
    if program.contains('\0') {
        return Err(Error::InvalidArgument("a program path contains a NUL byte"));
    }
    if !Path::new(program).is_absolute() {
        return Err(Error::InvalidArgument(refusal));
    }
    std::fs::canonicalize(program)
        .map_err(|_| Error::InvalidArgument("the program path does not resolve"))
}

/// Whether an encoded path carries an interior NUL.
///
/// `Command` panics on one, and the panic is not a provider fault a retry
/// policy can interpret (round 18, L-5).
fn has_nul(path: &std::path::Path) -> bool {
    path.as_os_str().as_encoded_bytes().contains(&0)
}

/// A sandboxed local process tool.
///
/// The allowlist is the program plus its permitted argument prefixes. The child
/// gets a scrubbed environment (only what the caller allows), no shell, a pinned
/// working directory and a byte-bounded stdout. Anything else is
/// `rpc/tool-policy`.
/// A local program under capability control.
///
/// `Debug` is written by hand: `env` conventionally holds a child's token, and
/// a derived formatter would print every value into a log line or a panic
/// message (round 41, F6).
pub struct LocalProcess {
    /// Absolute program path as given to [`LocalProcess::new`].
    ///
    /// Private: `invoke` runs the canonical path pinned at construction, so a
    /// later assignment would silently keep running the old binary
    /// (round 30, #6). The advertised form is [`LocalProcess::program`].
    program: String,
    /// Arguments the caller may pass (each must be an exact match or a prefix
    /// when it ends with `*`).
    pub allow_args: Vec<String>,
    /// Environment variables the child inherits.
    pub env: BTreeMap<String, String>,
    /// Directory the child runs in. Pinned at construction (canonicalised) and
    /// never inherited at spawn time, so a later `chdir` in this process cannot
    /// move the child. Private: an in-process assignment cannot repoint it
    /// (audit ARPC-005); see [`LocalProcess::working_directory`].
    workdir: PathBuf,
    /// Maximum output bytes.
    pub max_output: usize,
    /// Maximum wall-clock time one invocation may take before the child is
    /// killed. Bounded on purpose: a tool that never returns must not hold the
    /// caller forever (H2.44).
    pub timeout_ms: u64,
    /// Calls served.
    pub calls: u64,
    /// Canonical program path pinned at construction.
    resolved: PathBuf,
}

impl std::fmt::Debug for LocalProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Keys are configuration; values are credentials. A deployment log or
        // a panic message must not carry a child's token (round 41, F6).
        let mut env = std::collections::BTreeMap::new();
        for key in self.env.keys() {
            env.insert(key, "<redacted>");
        }
        // An exact allowlist entry is the natural home of a fixed credential
        // ("--api-key", "sk-...") while a prefix rule is configuration: only the
        // rule's shape and an entry's length are printed (round 47, L-5).
        let allow: Vec<String> = self
            .allow_args
            .iter()
            .map(|rule| {
                if rule.ends_with('*') {
                    rule.clone()
                } else {
                    format!("<{} bytes>", rule.len())
                }
            })
            .collect();
        formatter
            .debug_struct("LocalProcess")
            .field("program", &self.program)
            .field("allow_args", &allow)
            .field("env", &env)
            .field("workdir", &self.workdir)
            .field("max_output", &self.max_output)
            .field("timeout_ms", &self.timeout_ms)
            .field("calls", &self.calls)
            .finish()
    }
}

impl LocalProcess {
    /// Build a tool for an absolute `program` path with an argument allowlist.
    ///
    /// The program must be an absolute path: a bare name is resolved from the
    /// parent's `PATH`, so anything that can write an earlier `PATH` entry
    /// would choose the binary the capability runs. The canonical path is
    /// pinned here, and the working directory is pinned to this process's
    /// current directory (see [`LocalProcess::with_current_dir`]).
    pub fn new(program: impl Into<String>, allow_args: &[&str]) -> Result<Self> {
        let program = program.into();
        let resolved = pin_program(&program, "a local process program must be an absolute path")?;
        let workdir = std::env::current_dir().map_err(|_| Error::Provider {
            code: "process/cwd".to_string(),
        })?;
        // Canonical now, so a symlink swapped in later does not change what the
        // stored path names (audit ARPC-005). A directory that cannot be
        // canonicalised is refused: falling back to the raw path let a later
        // link swap redirect the child (round 25, #6).
        let workdir = std::fs::canonicalize(&workdir).map_err(|_| Error::Provider {
            code: "process/cwd".to_string(),
        })?;
        Ok(Self {
            program,
            allow_args: allow_args.iter().map(|arg| arg.to_string()).collect(),
            env: BTreeMap::new(),
            workdir,
            max_output: 1 << 20,
            timeout_ms: 10_000,
            calls: 0,
            resolved,
        })
    }

    /// Pin the child's working directory.
    ///
    /// The directory must be absolute; a relative one would resolve against
    /// whatever the parent's working directory happens to be at spawn time.
    pub fn with_current_dir(mut self, directory: impl Into<PathBuf>) -> Result<Self> {
        let directory = directory.into();
        if !directory.is_absolute() {
            return Err(Error::InvalidArgument(
                "a process working directory must be absolute",
            ));
        }
        if has_nul(&directory) {
            return Err(Error::InvalidArgument(
                "a process working directory contains a NUL byte",
            ));
        }
        // Resolve now: the stored path is what the child gets, and an
        // unresolvable directory is refused at construction rather than at
        // spawn (audit ARPC-005).
        let directory = std::fs::canonicalize(&directory).map_err(|_| {
            Error::InvalidArgument("the process working directory does not resolve")
        })?;
        self.workdir = directory;
        Ok(self)
    }

    /// The working directory this tool pins.
    pub fn working_directory(&self) -> &Path {
        &self.workdir
    }

    /// The absolute program path this tool was built with.
    ///
    /// `invoke` runs the canonical path pinned at construction, which may differ
    /// from this string (a symlink, a different spelling); this accessor reports
    /// what the operator configured.
    pub fn program(&self) -> &str {
        &self.program
    }

    /// Set the per-invocation wall-clock ceiling.
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        // Clamp to a sane window: zero would make every call flaky, and an
        // enormous value would overflow the deadline arithmetic.
        self.timeout_ms = timeout_ms.clamp(1, 300_000);
        self
    }

    /// Policy for a capability: process execution must be granted explicitly.
    pub fn policy(&self) -> ToolPolicy {
        ToolPolicy {
            allowed: ["run"].iter().map(|method| method.to_string()).collect(),
            max_arg_bytes: 64 << 10,
            allow_process: true,
        }
    }

    fn permitted(&self, arg: &str) -> bool {
        self.allow_args.iter().any(|allowed| {
            if let Some(prefix) = allowed.strip_suffix('*') {
                arg.starts_with(prefix)
            } else {
                allowed == arg
            }
        })
    }

    /// Whether any `*` rule would admit `arg`.
    ///
    /// A prefix rule is a *command-line* prefix, not an argument match: with a
    /// shell as the program (`cmd /C`, `sh -c`) the rest of the line is code.
    /// The adapter cannot make an arbitrary command line safe, so an argument
    /// that only a prefix rule admits may not carry shell metacharacters.
    fn permitted_by_prefix_only(&self, arg: &str) -> bool {
        let exact = self
            .allow_args
            .iter()
            .any(|allowed| !allowed.ends_with('*') && allowed == arg);
        !exact
            && self.allow_args.iter().any(|allowed| {
                allowed
                    .strip_suffix('*')
                    .is_some_and(|prefix| arg.starts_with(prefix))
            })
    }
}

impl Provider for LocalProcess {
    fn name(&self) -> &'static str {
        "local-process"
    }

    fn methods(&self) -> Vec<String> {
        vec!["run".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        true
    }

    fn invoke(&mut self, _object: u64, call: &Call) -> Result<Response> {
        if call.budget.max_wall_ms == 0 {
            // Before the spawn: a zero grant must not start a child and kill it
            // (round 4, #5).
            return Err(Error::BudgetExceeded("wall"));
        }
        if call.budget.max_bytes == 0 {
            // The grant is checked before the method, the payload and every
            // argument rule: a zero-byte capability does no work, and the
            // refusal class must not depend on the other inputs
            // (round 25, #4; round 29, F2).
            return Err(Error::BudgetExceeded("byte"));
        }
        if !call.payload.is_empty() {
            return Err(Error::InvalidArgument(
                "the process adapter does not accept an envelope payload",
            ));
        }
        // The uniform prefix: budget, payload, secret, scope, method. Every
        // adapter uses it so the same malformed call reports the same code
        // whichever handle it reached (round 38, #5).
        if args_contain_secret(&call.args) {
            // Before the shape loop: `Value::Secret` used to be reported as a
            // malformed argument there, so this policy branch never ran
            // (round 23, #1; round 24, #1 was the same gap still live here).
            return Err(Error::ToolPolicy(
                "a secret argument cannot be passed to a process",
            ));
        }
        if call.path_scope.is_some() {
            // Every process argument is text and the kernel only inspects
            // `Value::Path`: a scope attached here would read as confinement
            // while enforcing nothing (round 9, F-1). Fail closed.
            return Err(Error::ToolPolicy(
                "this adapter cannot enforce a path scope",
            ));
        }
        // The grant bounds the argument line too: a direct caller could pass a
        // 10 MiB argv under a one-byte grant because only the output was
        // counted (round 32, #1). The kernel charges the same bytes at
        // dispatch; this is the adapter's own gate. The uniform prefix puts it
        // before the method (round 40, F2).
        let mut arg_bytes = 0u64;
        for arg in &call.args {
            let Some(next) = arg_bytes.checked_add(Arg::wire_size(arg)) else {
                return Err(Error::BudgetExceeded("byte"));
            };
            arg_bytes = next;
        }
        if arg_bytes > call.budget.max_bytes {
            return Err(Error::BudgetExceeded("byte"));
        }
        if call.method != "run" {
            return Err(Error::MethodNotGranted {
                method: call.method.clone(),
            });
        }
        // The authority checks come before the argument allowlist: a direct
        // caller without the process grant must not learn allowlist membership
        // from which refusal it receives (round 27, #3).
        if !call.tool_allows_process {
            return Err(Error::ToolPolicy("process execution not granted"));
        }
        let mut args = Vec::new();
        for arg in &call.args {
            // A process argument is text. Anything else would be executed as
            // something the caller did not validate (a dropped operand turns
            // `--target X` into the program's own default).
            let Arg::Value(Value::Text(text)) = arg else {
                return Err(Error::InvalidArgument(
                    "a process argument must be a text value",
                ));
            };
            // `Command` asserts on an interior NUL: the kernel would catch the
            // unwind, but a caller-supplied argument must not reach a panic at
            // all (round 5, #6).
            if text.contains('\0') {
                return Err(Error::InvalidArgument(
                    "a process argument contains a NUL byte",
                ));
            }
            if !self.permitted(text) {
                return Err(Error::ToolPolicy("argument is not allowed"));
            }
            if self.permitted_by_prefix_only(text)
                && text
                    .chars()
                    .any(|character| SHELL_METACHARACTERS.contains(&character))
            {
                // `cmd /C` and `sh -c` treat these as syntax, so a prefix rule
                // would otherwise be a grant to run an arbitrary command line.
                return Err(Error::ToolPolicy(
                    "a prefix-matched argument contains a shell metacharacter",
                ));
            }
            args.push(text.clone());
        }
        // The fields are public, so the pinning is checked again here: a caller
        // that assigned a relative directory would have it resolved against the
        // process's current directory, which is what `with_current_dir`
        // refuses (round 8, F6).
        if !self.workdir.is_absolute() {
            return Err(Error::InvalidArgument(
                "a process working directory must be absolute",
            ));
        }
        if has_nul(&self.workdir) {
            return Err(Error::InvalidArgument(
                "a process working directory contains a NUL byte",
            ));
        }
        let mut command = Command::new(&self.resolved);
        command
            .args(&args)
            .current_dir(&self.workdir)
            .env_clear()
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .stdout(Stdio::piped());
        #[cfg(unix)]
        {
            // Its own process group, so a timeout can signal the whole tree.
            // Without this a shell's background descendants outlive the direct
            // child and keep running after the capability was refunded.
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        for (key, value) in &self.env {
            // Same rule as the transport: a bad entry never reaches `Command`.
            if !valid_env_entry(key, value) {
                return Err(Error::InvalidArgument(
                    "a process environment entry is not a valid variable",
                ));
            }
            command.env(key, value);
        }
        // Count admitted calls only (round 31, F7).
        self.calls += 1;
        let mut child = command.spawn().map_err(|error| Error::Provider {
            code: format!("process/spawn:{error}"),
        })?;
        // Drain both pipes on their own threads. A child that writes more than
        // the ceiling stops being drained, blocks on the pipe, and is killed at
        // the deadline instead of growing our memory.
        // The readers report over a channel, so the *wait* is bounded too: a
        // descendant that inherited the pipe keeps it open after the child
        // exits, and joining a thread that is blocked in `read_to_end` would
        // exceed the wall ceiling without any way to interrupt it.
        // A caller-set ceiling feeds the reader's allocation, so it is clamped
        // at use (round 12, F-2).
        // The adapter's ceiling and the capability's byte grant both bound
        // what is read: a call with an 8-byte grant must not make the host
        // buffer a megabyte (round 19, M2).
        let grant = usize::try_from(call.budget.max_bytes).unwrap_or(usize::MAX);
        // One grant for the call: what the argument line spends is not
        // available to the output (round 33, H1).
        let share = grant.saturating_sub(arg_bytes as usize);
        let max_output = self.max_output.min(MAX_OUTPUT_BYTES).min(share);
        // One budget for both pipes: each reader used to take a full ceiling,
        // so transient buffering reached twice the grant (round 21, F1).
        let shared = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(
            max_output.saturating_add(1),
        ));
        // `(stream, bytes)`: 1 is stdout and 2 is stderr. Two threads sharing
        // one channel report in completion order, and a child that writes both
        // pipes quickly would otherwise have its streams swapped.
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut readers = 0usize;
        let mut spawn_error: Option<std::io::Error> = None;
        let mut drain =
            |sender: std::sync::mpsc::Sender<(u8, Vec<u8>)>,
             tag: u8,
             mut stream: Option<Box<dyn std::io::Read + Send>>| {
                if let Some(mut stream) = stream.take() {
                    let shared = std::sync::Arc::clone(&shared);
                    // Every reader of a descendant-held pipe outlives its call
                    // on Windows; a timeout loop must not be able to exhaust
                    // the process (round 33, H3).
                    let Some(slot) = ReaderSlot::acquire() else {
                        // Short enough that the provider code survives the
                        // receipt's 64-byte ceiling: a longer reason turned
                        // `process/thread:…` into a generic `rpc/provider`
                        // (round 34, #6).
                        spawn_error = Some(std::io::Error::other("too many process readers"));
                        return;
                    };
                    // `thread::spawn` panics on failure; a named builder
                    // reports it, and the child is killed rather than leaked
                    // (round 10, F-4).
                    let spawned = std::thread::Builder::new()
                        .name("active-rpc-process-reader".to_string())
                        .spawn(move || {
                            use std::io::Read;
                            let _slot = slot;
                            let mut buffer = Vec::new();
                            let mut chunk = [0u8; 8 * 1024];
                            loop {
                                match stream.read(&mut chunk) {
                                    Ok(0) => break,
                                    Ok(read) => {
                                        // A plain compare-exchange loop: the
                                        // `fetch_update` API is deprecated on
                                        // newer toolchains and `try_update` is
                                        // past this crate's MSRV.
                                        let before = loop {
                                            let left =
                                                shared.load(std::sync::atomic::Ordering::SeqCst);
                                            if left == 0 {
                                                break 0;
                                            }
                                            match shared.compare_exchange(
                                                left,
                                                left.saturating_sub(read),
                                                std::sync::atomic::Ordering::SeqCst,
                                                std::sync::atomic::Ordering::SeqCst,
                                            ) {
                                                Ok(_) => break left,
                                                // A failed exchange means
                                                // another reader moved the
                                                // counter; retry rather than
                                                // buffering the bytes free
                                                // (round 22, F-C).
                                                Err(_) => continue,
                                            }
                                        };
                                        if before == 0 {
                                            break;
                                        }
                                        let take = read.min(before);
                                        buffer.extend_from_slice(&chunk[..take]);
                                        if take < read {
                                            break;
                                        }
                                    }
                                    Err(error)
                                        if error.kind() == std::io::ErrorKind::Interrupted =>
                                    {
                                        continue
                                    }
                                    Err(_) => break,
                                }
                            }
                            let _ = sender.send((tag, buffer));
                        });
                    match spawned {
                        Ok(_) => readers += 1,
                        Err(error) => spawn_error = Some(error),
                    }
                }
            };
        drain(
            sender.clone(),
            1,
            child
                .stdout
                .take()
                .map(|stream| Box::new(stream) as Box<dyn std::io::Read + Send>),
        );
        drain(
            sender.clone(),
            2,
            child
                .stderr
                .take()
                .map(|stream| Box::new(stream) as Box<dyn std::io::Read + Send>),
        );
        if let Some(error) = spawn_error {
            kill_process_tree(&mut child);
            // The child was already spawned, so it may have acted: the refusal is
            // a withheld reply (round 44, M-1).
            return Err(reply_withheld(Error::Provider {
                code: format!("process/thread:{error}"),
            }));
        }
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut received = 0usize;

        // The capability's wall budget can be tighter than the adapter default;
        // the effective ceiling is the smaller of the two.
        let ceiling_ms = self
            .timeout_ms
            .clamp(1, 300_000)
            .min(call.budget.max_wall_ms.max(1));
        let deadline = std::time::Instant::now()
            .checked_add(std::time::Duration::from_millis(ceiling_ms))
            .unwrap_or_else(std::time::Instant::now);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    // A reader that hit the cap reports without EOF: the child
                    // is blocked on a full pipe, so waiting for it to exit
                    // would burn the whole grant and answer `Timeout` instead
                    // of the output refusal (round 10, F-2).
                    while let Ok((tag, buffer)) = receiver.try_recv() {
                        received += 1;
                        if tag == 1 {
                            stdout = buffer;
                        } else {
                            stderr = buffer;
                        }
                        // Both pipes together: checking each separately let a
                        // grant pay for twice the bytes (round 20, M2).
                        if stdout.len().saturating_add(stderr.len()) > max_output {
                            kill_process_tree(&mut child);
                            // The child ran: the effect may stand, so a retry
                            // must not fork it again (round 43, F-4).
                            return Err(reply_withheld(Error::ToolPolicy("output too large")));
                        }
                    }
                    if std::time::Instant::now() >= deadline {
                        // The whole tree is killed, not just the direct child:
                        // the leader may have exited already while a descendant
                        // still holds the pipes.
                        kill_process_tree(&mut child);
                        return Err(reply_withheld(Error::Timeout));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(error) => {
                    kill_process_tree(&mut child);
                    return Err(reply_withheld(Error::Provider {
                        code: format!("process/wait:{error}"),
                    }));
                }
            }
        };
        // The leader can exit while a descendant it started still holds the
        // pipes. The readers are then still blocked, so the same deadline
        // applies here, and it kills the tree too: a refunded call must not
        // leave a background process acting on the capability's behalf.
        while received < readers {
            let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) else {
                kill_process_tree(&mut child);
                return Err(reply_withheld(Error::Timeout));
            };
            match receiver.recv_timeout(left) {
                Ok((tag, buffer)) => {
                    received += 1;
                    if tag == 1 {
                        stdout = buffer;
                    } else {
                        stderr = buffer;
                    }
                    // A descendant that outlives the leader can flood after it
                    // exits; refuse at the same ceiling instead of waiting out
                    // the grant (round 11, #2).
                    if stdout.len().saturating_add(stderr.len()) > max_output {
                        kill_process_tree(&mut child);
                        return Err(reply_withheld(Error::ToolPolicy("output too large")));
                    }
                }
                Err(_) => {
                    kill_process_tree(&mut child);
                    // The child ran; the drain deadline is a withheld reply
                    // (round 43, F-4).
                    return Err(reply_withheld(Error::Timeout));
                }
            }
        }
        if stdout.len().saturating_add(stderr.len()) > max_output {
            // The child ran to completion; the output still exceeds the share,
            // and the class says the reply was withheld (round 43, F-4).
            return Err(reply_withheld(Error::ToolPolicy("output too large")));
        }
        let mut map = BTreeMap::new();
        // A child killed by a signal has no exit code. Reporting `-1` as a
        // status made an externally killed mutating tool look successful in
        // the receipt (round 24, #3).
        // A signalled child ran to completion (something killed it): the
        // effect may stand, so the class is a withheld reply (round 44, M-2).
        let status_code = match status.code() {
            Some(code) => code,
            None => {
                return Err(reply_withheld(Error::Provider {
                    code: "process/signalled".to_string(),
                }))
            }
        };
        map.insert("status".to_string(), Value::Int(i64::from(status_code)));
        // A binary stream is not text: transcoding it inserts replacement
        // characters, so two different byte strings would compare equal
        // (round 13, F-6).
        // `from_utf8` hands the bytes back on failure: no clone per stream.
        let stream = |bytes: Vec<u8>| match String::from_utf8(bytes) {
            Ok(text) => Value::Text(text),
            Err(error) => Value::Module(error.into_bytes()),
        };
        map.insert("stdout".to_string(), stream(stdout));
        map.insert("stderr".to_string(), stream(stderr));
        Ok(Response::Value(Value::Map(map)))
    }
}

#[cfg(test)]
mod reader_slot_tests {
    use super::{ReaderSlot, MAX_LIVE_READERS};

    /// The reservation is a hard cap and a drop always gives the place back,
    /// including when the thread that took it never started
    /// (round 33, H3).
    #[test]
    fn the_reader_cap_refuses_beyond_its_ceiling_and_releases_on_drop() {
        let mut held = Vec::new();
        while let Some(slot) = ReaderSlot::acquire() {
            held.push(slot);
            assert!(
                held.len() <= MAX_LIVE_READERS,
                "the cap admitted {} reservations",
                held.len()
            );
        }
        assert_eq!(held.len(), MAX_LIVE_READERS);
        assert!(ReaderSlot::acquire().is_none(), "the cap is full");

        // A dropped reservation is reusable: a reader that ends (or a spawn
        // that fails) must not consume a place for the life of the process.
        held.pop();
        let again = ReaderSlot::acquire().expect("a released place is reusable");
        drop(again);
        drop(held);

        // And every place is back.
        let mut recovered = Vec::new();
        while let Some(slot) = ReaderSlot::acquire() {
            recovered.push(slot);
        }
        assert_eq!(recovered.len(), MAX_LIVE_READERS);
    }
}

#[cfg(test)]
mod write_tests {
    use super::write_within;

    /// The byte count survives a failure: a head written in chunks can fail
    /// after the first one, and the caller needs that count to mark the call as
    /// possibly applied (round 47, L-4; round 49, L-2).
    #[test]
    fn a_partial_write_reports_what_it_sent() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buffer = vec![0u8; 4096];
            let _ = std::io::Read::read(&mut stream, &mut buffer);
            // Close with the rest unread: the next chunk fails.
            drop(stream);
        });
        let mut client = std::net::TcpStream::connect(address).expect("connect");
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        let payload = vec![b'x'; 3 << 20];
        let (sent, result) = write_within(&mut client, &payload, deadline);
        assert!(result.is_err(), "a closed peer fails a later chunk");
        assert!(sent > 0, "the bytes already written are reported");
        assert!(sent < payload.len(), "the write did not complete");
        let _ = server.join();
    }
}
