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

/// Convert JSON into an RPC value.
pub fn json_to_value(value: &Json) -> Value {
    match value {
        Json::Null => Value::Null,
        Json::Bool(flag) => Value::Bool(*flag),
        Json::Number(number) => {
            if let Some(int) = number.as_i64() {
                Value::Int(int)
            } else {
                Value::Float(number.as_f64().unwrap_or(0.0))
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

// ---------------------------------------------------------------------------
// MCP
// ---------------------------------------------------------------------------

/// A line-oriented JSON-RPC transport used by [`McpSession`].
pub trait McpTransport {
    /// Send one JSON line.
    fn send_line(&mut self, line: &str) -> Result<()>;
    /// Read one JSON line (blocking).
    fn recv_line(&mut self) -> Result<String>;

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
    fn arm(&self) -> Result<()> {
        let left = remaining_until(self.deadline)?;
        self.reader.get_ref().set_read_timeout(Some(left)).ok();
        Ok(())
    }

    /// Read one line under a byte cap and the wall deadline.
    fn line(&mut self, cap: usize) -> Result<String> {
        self.arm()?;
        let mut line = String::new();
        let read = self
            .reader
            .by_ref()
            .take((cap + 1) as u64)
            .read_line(&mut line)
            .map_err(map_http_read)?;
        if read > cap {
            return Err(Error::Provider {
                code: "http/line-too-long".to_string(),
            });
        }
        remaining_until(self.deadline)?;
        Ok(line)
    }

    /// Read exactly `length` body bytes under the wall deadline.
    fn body_exact(&mut self, length: usize) -> Result<Vec<u8>> {
        self.arm()?;
        let mut body = vec![0u8; length];
        self.reader.read_exact(&mut body).map_err(map_http_read)?;
        remaining_until(self.deadline)?;
        Ok(body)
    }

    /// Read the rest of the body under a byte cap and the wall deadline.
    fn body_rest(&mut self, cap: usize) -> Result<Vec<u8>> {
        self.arm()?;
        let mut rest = Vec::new();
        self.reader
            .by_ref()
            .take(cap as u64 + 1)
            .read_to_end(&mut rest)
            .map_err(map_http_read)?;
        remaining_until(self.deadline)?;
        Ok(rest)
    }
}

/// A socket read that hit its timeout is the call's ceiling, not an I/O fault.
fn map_http_read(error: std::io::Error) -> Error {
    if matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ) {
        Error::Timeout
    } else {
        Error::Provider {
            code: format!("http/read:{error}"),
        }
    }
}

/// A child-process MCP transport speaking JSON-RPC over stdin/stdout.
pub struct StdioTransport {
    child: Child,
    stdin: std::process::ChildStdin,
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
        let program = pin_program(program, "an MCP server")?;
        let workdir = std::env::current_dir().map_err(|_| Error::Provider {
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
            command.env(key, value);
        }
        let mut child = command.spawn().map_err(|error| Error::Provider {
            code: format!("mcp/spawn:{error}"),
        })?;
        let stdin = child.stdin.take().ok_or(Error::Provider {
            code: "mcp/stdin".to_string(),
        })?;
        let stdout = child.stdout.take().ok_or(Error::Provider {
            code: "mcp/stdout".to_string(),
        })?;
        let (sender, lines) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("active-rpc-mcp-stdio".to_string())
            .spawn(move || {
                let mut reader = BufReader::new(stdout);
                loop {
                    let mut line = String::new();
                    let read = reader
                        .by_ref()
                        .take((MAX_MCP_LINE_BYTES + 1) as u64)
                        .read_line(&mut line);
                    let outcome = match read {
                        Ok(0) => Err(Error::Provider {
                            code: "mcp/eof".to_string(),
                        }),
                        Ok(read) if read > MAX_MCP_LINE_BYTES => Err(Error::Provider {
                            code: "mcp/line-too-long".to_string(),
                        }),
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
            .map_err(|error| Error::Provider {
                code: format!("mcp/thread:{error}"),
            })?;
        Ok(Self {
            child,
            stdin,
            lines,
        })
    }
}

impl McpTransport for StdioTransport {
    fn send_line(&mut self, line: &str) -> Result<()> {
        self.stdin
            .write_all(line.as_bytes())
            .and_then(|_| self.stdin.write_all(b"\n"))
            .and_then(|_| self.stdin.flush())
            .map_err(|error| Error::Provider {
                code: format!("mcp/write:{error}"),
            })
    }

    fn recv_line(&mut self) -> Result<String> {
        self.recv_line_within(None)
    }

    fn recv_line_within(&mut self, deadline: Option<std::time::Instant>) -> Result<String> {
        let Some(deadline) = deadline else {
            return self.lines.recv().map_err(|_| Error::Provider {
                code: "mcp/eof".to_string(),
            })?;
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
        let mut session = McpSession {
            transport,
            tools: Vec::new(),
            next_id: 0,
            poisoned: false,
            calls: 0,
        };
        let initialize = session.request_within(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "active-rpc", "version": env!("CARGO_PKG_VERSION") }
            }),
            deadline,
        )?;
        if initialize.get("error").is_some() {
            return Err(Error::Provider {
                code: "mcp/initialize".to_string(),
            });
        }
        let list = session.request_within("tools/list", json!({}), deadline)?;
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        if let Some(items) = list
            .get("result")
            .and_then(|result| result.get("tools"))
            .and_then(Json::as_array)
        {
            for item in items {
                let name = item.get("name").and_then(Json::as_str).unwrap_or("");
                if name.is_empty() {
                    continue;
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
                return Err(Error::Timeout);
            }
        }
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
        let line = payload.to_string();
        if line.len() > MAX_MCP_LINE_BYTES {
            // The peer refuses a line of this size; refuse it here instead of
            // sending a frame that can only be a desync.
            return Err(Error::InvalidArgument(
                "the MCP request exceeds the line ceiling",
            ));
        }
        self.transport.send_line(&line)?;
        let mut skipped = 0usize;
        loop {
            let line = self.transport.recv_line_within(deadline)?;
            if line.len() > MAX_MCP_LINE_BYTES {
                self.poisoned = true;
                return Err(Error::Provider {
                    code: "mcp/line-too-long".to_string(),
                });
            }
            let response: Json = match serde_json::from_str(&line) {
                Ok(response) => response,
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
                Some(value) if value.as_u64() == Some(id) => {
                    if object.get("result").is_none() && object.get("error").is_none() {
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
        policy.max_arg_bytes = 1 << 20;
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
        self.calls += 1;
        let tool = self
            .tools
            .get(object as usize)
            .ok_or(Error::InvalidArgument("unknown MCP tool"))?;
        if tool.name != call.method {
            return Err(Error::MethodNotGranted {
                method: call.method.clone(),
            });
        }
        let mut arguments = serde_json::Map::new();
        for (index, arg) in call.args.iter().enumerate() {
            if let Arg::Value(value) = arg {
                arguments.insert(format!("arg{index}"), value_to_json(value));
            }
        }
        // The capability's wall ceiling bounds the wait, not only the total: a
        // silent server must not hold the kernel for its own timeout.
        let ceiling = std::time::Duration::from_millis(call.budget.max_wall_ms.max(1));
        let deadline = std::time::Instant::now()
            .checked_add(ceiling)
            .unwrap_or_else(std::time::Instant::now);
        let response = self.request_within(
            "tools/call",
            json!({ "name": tool.name, "arguments": Json::Object(arguments) }),
            Some(deadline),
        )?;
        if let Some(error) = response.get("error") {
            return Err(Error::Provider {
                code: format!(
                    "mcp/{}",
                    error.get("code").and_then(Json::as_i64).unwrap_or(0)
                ),
            });
        }
        let result = response.get("result").cloned().unwrap_or(Json::Null);
        Ok(Response::Value(json_to_value(&result)))
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
#[derive(Debug)]
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
}

impl HttpTool {
    /// Build a tool for `base` with an allowlist.
    pub fn new(base: impl Into<String>, allow: &[(&str, &str)]) -> Self {
        Self {
            base: base.into(),
            allow: allow
                .iter()
                .map(|(method, path)| (method.to_string(), path.to_string()))
                .collect(),
            max_body: 1 << 20,
            max_request: 1 << 20,
            calls: 0,
        }
    }

    /// Build a tool policy for a capability.
    pub fn policy(&self) -> ToolPolicy {
        ToolPolicy {
            allowed: ["get", "post", "request"]
                .iter()
                .map(|method| method.to_string())
                .collect(),
            max_arg_bytes: self.max_request as u64,
            allow_process: false,
        }
    }

    fn perform(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        ceiling_ms: u64,
    ) -> Result<(u16, Vec<u8>)> {
        let base = self
            .base
            .strip_prefix("http://")
            .ok_or(Error::ToolPolicy("only http:// endpoints are supported"))?;
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
        // Resolution is not peer-controlled: the base URL is the operator's
        // endpoint, so the system resolver's own timeout applies here. The
        // peer's part of the exchange (connect, write, read) is under
        // `deadline`.
        let addresses: Vec<std::net::SocketAddr> = std::net::ToSocketAddrs::to_socket_addrs(base)
            .map_err(|error| Error::Provider {
                code: format!("http/resolve:{error}"),
            })?
            .collect();
        let mut connected = None;
        for address in addresses {
            // Every attempt gets only the time that is left, so a host with
            // many addresses cannot multiply the ceiling.
            let remaining = remaining_until(deadline)?;
            match TcpStream::connect_timeout(&address, remaining) {
                Ok(stream) => {
                    connected = Some(stream);
                    break;
                }
                Err(error) if connected.is_none() => {
                    connected = None;
                    let _ = error;
                }
                Err(_) => {}
            }
        }
        let mut stream = connected.ok_or(Error::Provider {
            code: "http/connect".to_string(),
        })?;
        stream
            .set_write_timeout(Some(remaining_until(deadline)?))
            .ok();
        let head = {
            // A method defined without content sends no `content-length` and no
            // body. A GET that carries one makes simple servers and
            // intermediaries reset the connection instead of answering: the
            // request is already complete at the empty line, so the extra bytes
            // are unread data.
            let mut head =
                format!("{method} {path} HTTP/1.1\r\nhost: {base}\r\nconnection: close\r\n");
            if let Some(body) = body {
                head.push_str(&format!("content-length: {}\r\n", body.len()));
            }
            head.push_str("\r\n");
            head
        };
        stream
            .write_all(head.as_bytes())
            .and_then(|_| match body {
                Some(body) => stream.write_all(body),
                None => Ok(()),
            })
            .and_then(|_| stream.flush())
            .map_err(|error| Error::Provider {
                code: format!("http/write:{error}"),
            })?;
        let mut reader = DeadlineReader::new(stream, deadline);
        // Every line is read under a cap, and the block has its own budget: a
        // hostile endpoint that streams headers would otherwise grow a `String`
        // until the allocator aborts the process (outside `catch_unwind`).
        let mut status_line = reader.line(MAX_HTTP_STATUS_LINE)?;
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .ok_or(Error::Provider {
                code: "http/status".to_string(),
            })?;
        if !status_line.starts_with("HTTP/1.") {
            return Err(Error::Provider {
                code: "http/status".to_string(),
            });
        }
        if (100..200).contains(&status) {
            return Err(Error::Provider {
                code: "http/interim".to_string(),
            });
        }
        status_line.clear();
        let mut content_length: Option<usize> = None;
        let mut header_bytes = 0usize;
        let mut fields = 0usize;
        loop {
            let line = reader.line(MAX_HTTP_HEADER_LINE)?;
            if line.trim().is_empty() {
                break;
            }
            header_bytes = header_bytes.saturating_add(line.len());
            fields += 1;
            if header_bytes > MAX_HTTP_HEADER_BYTES || fields > MAX_HTTP_HEADER_FIELDS {
                return Err(Error::Provider {
                    code: "http/headers".to_string(),
                });
            }
            if let Some((name, value)) = line.split_once(':') {
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
                    let value: usize = value.trim().parse().map_err(|_| Error::Provider {
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
        let body = match content_length {
            Some(length) => {
                if length > self.max_body {
                    return Err(Error::ToolPolicy("response too large"));
                }
                reader.body_exact(length)?
            }
            None => {
                let rest = reader.body_rest(self.max_body)?;
                if rest.len() > self.max_body {
                    return Err(Error::ToolPolicy("response too large"));
                }
                rest
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
        self.calls += 1;
        let method: String = match call.method.as_str() {
            "get" => "GET".to_string(),
            "post" => "POST".to_string(),
            "request" => call
                .args
                .iter()
                .find_map(|arg| match arg {
                    Arg::Value(Value::Text(text)) => Some(text.to_uppercase()),
                    _ => None,
                })
                .unwrap_or_else(|| "GET".to_string()),
            other => {
                return Err(Error::MethodNotGranted {
                    method: other.to_string(),
                })
            }
        };
        // The method text is interpolated into the request line, where only
        // token characters are legal: anything else would split the request.
        if !method.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(Error::ToolPolicy("the HTTP method is not a token"));
        }
        // The path is a `Value::Path` and nothing else. Accepting a text
        // argument that starts with `/` would give a caller a second, invisible
        // route to the path: the kernel's path scope walks `Value::Path`, so a
        // text path would reach the adapter without ever being checked.
        let path = call
            .args
            .iter()
            .find_map(|arg| match arg {
                Arg::Value(Value::Path(path)) => Some(path.clone()),
                _ => None,
            })
            .ok_or(Error::InvalidArgument("an HTTP path argument is required"))?;
        // The path reaches the request line verbatim. The allowlist gates it,
        // but a configuration entry that contains a control character would be
        // request splitting, so refuse the bytes outright.
        if path.bytes().any(|byte| byte < 0x21 || byte == 0x7f) {
            return Err(Error::ToolPolicy(
                "a path argument contains a control character",
            ));
        }
        if !self.allow.contains(&(method.to_string(), path.clone())) {
            return Err(Error::ToolPolicy("path is not on the allowlist"));
        }
        let body = if takes_request_body(&method) {
            let body = serde_json::to_vec(
                &call
                    .args
                    .iter()
                    .filter_map(|arg| match arg {
                        Arg::Value(Value::Map(entries)) => {
                            Some(value_to_json(&Value::Map(entries.clone())))
                        }
                        _ => None,
                    })
                    .next()
                    .unwrap_or(Json::Null),
            )
            .unwrap_or_default();
            if body.len() > self.max_request {
                return Err(Error::ToolPolicy("request too large"));
            }
            Some(body)
        } else {
            None
        };
        let (status, response) =
            self.perform(&method, &path, body.as_deref(), call.budget.max_wall_ms)?;
        if status >= 400 {
            return Err(Error::Provider {
                code: format!("http/{status}"),
            });
        }
        let text = String::from_utf8_lossy(&response).to_string();
        let value = serde_json::from_str::<Json>(&text)
            .map(|json| json_to_value(&json))
            .unwrap_or(Value::Text(text));
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
];

/// End a child's whole process tree and reap the leader.
///
/// On Windows `taskkill /T` walks the tree, with the executable resolved from
/// the system directory rather than `PATH` (the same ambient-authority argument
/// as the program itself). On Unix the caller puts the child in its own process
/// group, so one signal reaches every descendant it started. `/bin/kill` and
/// `/usr/bin/kill` are tried because this crate forbids `unsafe` and std has no
/// signal API; a platform with neither still loses the leader.
fn kill_process_tree(child: &mut Child) {
    #[cfg(windows)]
    {
        let root = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("C:\\Windows"));
        let _ = Command::new(root.join("System32").join("taskkill.exe"))
            .args(["/T", "/F", "/PID", &child.id().to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
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
/// is pinned so a symlink swapped in after construction cannot redirect the
/// exec. A path that does not exist yet keeps its absolute form and fails at
/// spawn with the operating system's own error.
fn pin_program(program: &str, refusal: &'static str) -> Result<PathBuf> {
    if !Path::new(program).is_absolute() {
        return Err(Error::InvalidArgument(refusal));
    }
    Ok(std::fs::canonicalize(program).unwrap_or_else(|_| PathBuf::from(program)))
}

/// A sandboxed local process tool.
///
/// The allowlist is the program plus its permitted argument prefixes. The child
/// gets a scrubbed environment (only what the caller allows), no shell, a pinned
/// working directory and a byte-bounded stdout. Anything else is
/// `rpc/tool-policy`.
#[derive(Debug)]
pub struct LocalProcess {
    /// Absolute program path as given to [`LocalProcess::new`].
    pub program: String,
    /// Arguments the caller may pass (each must be an exact match or a prefix
    /// when it ends with `*`).
    pub allow_args: Vec<String>,
    /// Environment variables the child inherits.
    pub env: BTreeMap<String, String>,
    /// Directory the child runs in. Pinned at construction and never inherited
    /// at spawn time, so a later `chdir` in this process cannot move the child.
    pub workdir: PathBuf,
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
        self.workdir = directory;
        Ok(self)
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
        self.calls += 1;
        if call.method != "run" {
            return Err(Error::MethodNotGranted {
                method: call.method.clone(),
            });
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
        // The policy in the capability must have granted process execution.
        if !call.tool_allows_process {
            return Err(Error::ToolPolicy("process execution not granted"));
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
            command.env(key, value);
        }
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
        let ceiling = self.max_output as u64 + 1;
        // `(stream, bytes)`: 1 is stdout and 2 is stderr. Two threads sharing
        // one channel report in completion order, and a child that writes both
        // pipes quickly would otherwise have its streams swapped.
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut readers = 0usize;
        let mut drain =
            |sender: std::sync::mpsc::Sender<(u8, Vec<u8>)>,
             tag: u8,
             mut stream: Option<Box<dyn std::io::Read + Send>>| {
                if let Some(stream) = stream.take() {
                    std::thread::spawn(move || {
                        let mut buffer = Vec::new();
                        let _ = stream.take(ceiling).read_to_end(&mut buffer);
                        let _ = sender.send((tag, buffer));
                    });
                    readers += 1;
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
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut received = 0usize;

        // The capability's wall budget can be tighter than the adapter default;
        // the effective ceiling is the smaller of the two.
        let ceiling_ms = self.timeout_ms.min(call.budget.max_wall_ms);
        let deadline = std::time::Instant::now()
            .checked_add(std::time::Duration::from_millis(ceiling_ms))
            .unwrap_or_else(std::time::Instant::now);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        // The whole tree is killed, not just the direct child:
                        // the leader may have exited already while a descendant
                        // still holds the pipes.
                        kill_process_tree(&mut child);
                        return Err(Error::Timeout);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(error) => {
                    kill_process_tree(&mut child);
                    return Err(Error::Provider {
                        code: format!("process/wait:{error}"),
                    });
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
                return Err(Error::Timeout);
            };
            match receiver.recv_timeout(left) {
                Ok((tag, buffer)) => {
                    received += 1;
                    if tag == 1 {
                        stdout = buffer;
                    } else {
                        stderr = buffer;
                    }
                }
                Err(_) => {
                    kill_process_tree(&mut child);
                    return Err(Error::Timeout);
                }
            }
        }
        if stdout.len() > self.max_output || stderr.len() > self.max_output {
            return Err(Error::ToolPolicy("output too large"));
        }
        let mut map = BTreeMap::new();
        map.insert(
            "status".to_string(),
            Value::Int(status.code().unwrap_or(-1) as i64),
        );
        map.insert(
            "stdout".to_string(),
            Value::Text(String::from_utf8_lossy(&stdout).to_string()),
        );
        map.insert(
            "stderr".to_string(),
            Value::Text(String::from_utf8_lossy(&stderr).to_string()),
        );
        Ok(Response::Value(Value::Map(map)))
    }
}
