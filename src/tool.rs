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
}

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
        let response = self.responses.get(method).cloned().unwrap_or_else(|| {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": "method not found" }
            })
            .to_string()
        });
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

/// A child-process MCP transport speaking JSON-RPC over stdin/stdout.
pub struct StdioTransport {
    child: Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
}

impl StdioTransport {
    /// Spawn an MCP server process (no shell, no inherited environment beyond
    /// what the caller passes).
    pub fn spawn(program: &str, args: &[&str], env: &BTreeMap<String, String>) -> Result<Self> {
        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_clear();
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
        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
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
        let mut line = String::new();
        let read = self
            .stdout
            .read_line(&mut line)
            .map_err(|error| Error::Provider {
                code: format!("mcp/read:{error}"),
            })?;
        if read == 0 {
            return Err(Error::Provider {
                code: "mcp/eof".to_string(),
            });
        }
        Ok(line.trim_end().to_string())
    }
}

impl Drop for StdioTransport {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
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
    /// Tool invocations issued through this session (the handshake is not
    /// counted).
    pub calls: u64,
}

impl<T: McpTransport> McpSession<T> {
    /// Perform the MCP handshake and discover tools.
    pub fn handshake(transport: T) -> Result<Self> {
        let mut session = McpSession {
            transport,
            tools: Vec::new(),
            next_id: 0,
            calls: 0,
        };
        let initialize = session.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "active-rpc", "version": env!("CARGO_PKG_VERSION") }
            }),
        )?;
        if initialize.get("error").is_some() {
            return Err(Error::Provider {
                code: "mcp/initialize".to_string(),
            });
        }
        let list = session.request("tools/list", json!({}))?;
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
                session.tools.push(McpToolDef {
                    name: name.to_string(),
                    description: item
                        .get("description")
                        .and_then(Json::as_str)
                        .unwrap_or("")
                        .to_string(),
                });
            }
        }
        Ok(session)
    }

    fn request(&mut self, method: &str, params: Json) -> Result<Json> {
        self.next_id += 1;
        let payload = json!({
            "jsonrpc": "2.0",
            "id": self.next_id,
            "method": method,
            "params": params,
        });
        self.transport.send_line(&payload.to_string())?;
        let line = self.transport.recv_line()?;
        serde_json::from_str(&line).map_err(|_| Error::Provider {
            code: "mcp/bad-response".to_string(),
        })
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
        let response = self.request(
            "tools/call",
            json!({ "name": tool.name, "arguments": Json::Object(arguments) }),
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

    fn perform(&self, method: &str, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>)> {
        let base = self
            .base
            .strip_prefix("http://")
            .ok_or(Error::ToolPolicy("only http:// endpoints are supported"))?;
        let mut stream = TcpStream::connect(base).map_err(|error| Error::Provider {
            code: format!("http/connect:{error}"),
        })?;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .ok();
        let head = format!(
            "{method} {path} HTTP/1.1\r\nhost: {base}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(head.as_bytes())
            .and_then(|_| stream.write_all(body))
            .and_then(|_| stream.flush())
            .map_err(|error| Error::Provider {
                code: format!("http/write:{error}"),
            })?;
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader
            .read_line(&mut status_line)
            .map_err(|error| Error::Provider {
                code: format!("http/read:{error}"),
            })?;
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .ok_or(Error::Provider {
                code: "http/status".to_string(),
            })?;
        let mut content_length: Option<usize> = None;
        loop {
            let mut line = String::new();
            let read = reader
                .read_line(&mut line)
                .map_err(|error| Error::Provider {
                    code: format!("http/read:{error}"),
                })?;
            if read == 0 || line.trim().is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().ok();
                }
            }
        }
        let mut body = Vec::new();
        match content_length {
            Some(length) => {
                if length > self.max_body {
                    return Err(Error::ToolPolicy("response too large"));
                }
                body.resize(length, 0);
                reader
                    .read_exact(&mut body)
                    .map_err(|error| Error::Provider {
                        code: format!("http/body:{error}"),
                    })?;
            }
            None => {
                let mut rest = Vec::new();
                reader
                    .take(self.max_body as u64 + 1)
                    .read_to_end(&mut rest)
                    .map_err(|error| Error::Provider {
                        code: format!("http/body:{error}"),
                    })?;
                if rest.len() > self.max_body {
                    return Err(Error::ToolPolicy("response too large"));
                }
                body = rest;
            }
        }
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
        let path = call
            .args
            .iter()
            .find_map(|arg| match arg {
                Arg::Value(Value::Text(text)) if text.starts_with('/') => Some(text.clone()),
                Arg::Value(Value::Path(path)) => Some(path.clone()),
                _ => None,
            })
            .ok_or(Error::InvalidArgument("an HTTP path argument is required"))?;
        if !self.allow.contains(&(method.to_string(), path.clone())) {
            return Err(Error::ToolPolicy("path is not on the allowlist"));
        }
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
        let (status, response) = self.perform(&method, &path, &body)?;
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

// ---------------------------------------------------------------------------
// Local process
// ---------------------------------------------------------------------------

/// A sandboxed local process tool.
///
/// The allowlist is the program plus its permitted argument prefixes. The child
/// gets a scrubbed environment (only what the caller allows), no shell, and a
/// byte-bounded stdout. Anything else is `rpc/tool-policy`.
#[derive(Debug)]
pub struct LocalProcess {
    /// Absolute program path or allowlisted name.
    pub program: String,
    /// Arguments the caller may pass (each must be an exact match or a prefix
    /// when it ends with `*`).
    pub allow_args: Vec<String>,
    /// Environment variables the child inherits.
    pub env: BTreeMap<String, String>,
    /// Maximum output bytes.
    pub max_output: usize,
    /// Maximum wall-clock time one invocation may take before the child is
    /// killed. Bounded on purpose: a tool that never returns must not hold the
    /// caller forever (H2.44).
    pub timeout_ms: u64,
    /// Calls served.
    pub calls: u64,
}

impl LocalProcess {
    /// Build a tool for `program` with an argument allowlist.
    pub fn new(program: impl Into<String>, allow_args: &[&str]) -> Self {
        Self {
            program: program.into(),
            allow_args: allow_args.iter().map(|arg| arg.to_string()).collect(),
            env: BTreeMap::new(),
            max_output: 1 << 20,
            timeout_ms: 10_000,
            calls: 0,
        }
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
            if let Arg::Value(Value::Text(text)) = arg {
                if !self.permitted(text) {
                    return Err(Error::ToolPolicy("argument is not allowed"));
                }
                args.push(text.clone());
            }
        }
        // The policy in the capability must have granted process execution.
        if !call.tool_allows_process {
            return Err(Error::ToolPolicy("process execution not granted"));
        }
        let mut command = Command::new(&self.program);
        command
            .args(&args)
            .env_clear()
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .stdout(Stdio::piped());
        for (key, value) in &self.env {
            command.env(key, value);
        }
        let mut child = command.spawn().map_err(|error| Error::Provider {
            code: format!("process/spawn:{error}"),
        })?;
        // Drain both pipes on their own threads. A child that writes more than
        // the ceiling stops being drained, blocks on the pipe, and is killed at
        // the deadline instead of growing our memory.
        let ceiling = self.max_output as u64 + 1;
        let stdout = child.stdout.take().map(|stream| {
            std::thread::spawn(move || {
                let mut buffer = Vec::new();
                let _ = stream.take(ceiling).read_to_end(&mut buffer);
                buffer
            })
        });
        let stderr = child.stderr.take().map(|stream| {
            std::thread::spawn(move || {
                let mut buffer = Vec::new();
                let _ = stream.take(ceiling).read_to_end(&mut buffer);
                buffer
            })
        });

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
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(Error::Timeout);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(error) => {
                    return Err(Error::Provider {
                        code: format!("process/wait:{error}"),
                    })
                }
            }
        };
        let stdout = stdout
            .and_then(|handle| handle.join().ok())
            .unwrap_or_default();
        let stderr = stderr
            .and_then(|handle| handle.join().ok())
            .unwrap_or_default();
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
