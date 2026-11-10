//! Read-only MCP server over stdio.
//!
//! By default it attaches to a running control plane (`--attach` or
//! `http://127.0.0.1:8787`) so agents read the same snapshot the dashboard
//! shows. If the service is not running, it falls back to an embedded real
//! plane, says so on stderr, and marks every answer from the embedded plane
//! `degraded`, so an agent never mistakes it for the live plane's snapshot
//! (RPC-42). Plane responses are read with a 1 MiB ceiling; a larger body
//! is refused with an error, never truncated.

use std::io::{self, BufRead, Read, Write};
use std::sync::Mutex;

use serde_json::{json, Value as Json};

use crate::plane::PlaneCore;

const DEFAULT_ATTACH: &str = "http://127.0.0.1:8787";

/// Largest plane response body accepted, in bytes (RPC-42).
///
/// The plane's own `/metrics` is tens of KiB, so 1 MiB leaves an order of
/// magnitude of headroom for a legitimate snapshot — and it matches the
/// `MAX_REQUEST_LINE` ceiling already enforced on the MCP stdin side. The
/// bound is on bytes, not time: the 5 s `ureq` timeout is a time bound, and
/// on a fast local plane 15+ MB arrived inside it before the timeout fired.
/// A body past this ceiling is refused with an error, never truncated:
/// a truncated snapshot would still parse (or fail to parse) as if it were
/// the plane's real answer.
pub const MAX_RESPONSE_BYTES: usize = 1 << 20;

/// Read one plane response body as JSON, refusing one larger than
/// `MAX_RESPONSE_BYTES` (RPC-42).
///
/// `take(MAX_RESPONSE_BYTES + 1)` bounds the read itself: at most one byte
/// past the ceiling is ever buffered, however large the body the plane
/// serves, and the connection is dropped as soon as the ceiling is crossed
/// instead of draining the rest.
fn read_json(response: ureq::Response) -> Result<Json, String> {
    let mut reader = response.into_reader().take(MAX_RESPONSE_BYTES as u64 + 1);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(format!(
            "control-plane response exceeds the {MAX_RESPONSE_BYTES}-byte ceiling"
        ));
    }
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

struct Attach {
    base: String,
    /// Every attach request goes through one agent whose redirect policy is
    /// `0`: `ureq` follows five by default, so a `302` from whatever owns the
    /// port escaped the loopback check and its body was returned to the agent
    /// (R-19 round 3, L6).
    http: ureq::Agent,
    local: Option<Mutex<PlaneCore>>,
    read_only: bool,
}

impl Attach {
    fn new(base: String, read_only: bool) -> Self {
        let http = ureq::AgentBuilder::new().redirects(0).build();
        let reachable = http
            .get(&format!("{base}/health"))
            .timeout(std::time::Duration::from_millis(500))
            .call()
            .is_ok();
        if !reachable {
            eprintln!(
                "active-control-plane MCP: {base} is not reachable; using an embedded plane (answers are marked degraded)"
            );
        }
        let local = (!reachable).then(|| {
            let mut core = PlaneCore::new();
            if read_only {
                core.set_mode("read-only");
            }
            Mutex::new(core)
        });
        Self {
            base,
            http,
            local,
            read_only,
        }
    }

    fn get(&self, path: &str) -> Result<Json, String> {
        let response = self
            .http
            .get(&format!("{}{}", self.base, path))
            .timeout(std::time::Duration::from_secs(5))
            .call()
            .map_err(|error| error.to_string())?;
        read_json(response)
    }

    /// Whether this attach answers from the embedded plane (RPC-42).
    ///
    /// Derived from `local`, not stored separately: the embedded plane
    /// exists exactly when the attach target was unreachable at startup,
    /// so the two cannot drift apart.
    fn is_degraded(&self) -> bool {
        self.local.is_some()
    }

    /// Mark an answer that came from the embedded plane as `degraded`
    /// (RPC-42).
    ///
    /// The key goes inside the answer itself, so it is visible in the text
    /// the agent reads — a stderr line at startup is not enough, because
    /// the agent may never see it. A non-object answer (none of today's
    /// tools returns one) is wrapped instead of left unmarked, so the
    /// invariant "every embedded-plane answer carries `degraded`" holds
    /// structurally rather than by inspection of each tool.
    fn mark_degraded(&self, value: Json) -> Json {
        if !self.is_degraded() {
            return value;
        }
        match value {
            Json::Object(mut object) => {
                object.insert("degraded".to_string(), Json::Bool(true));
                Json::Object(object)
            }
            other => json!({"degraded": true, "value": other}),
        }
    }

    fn snapshot(&self) -> Result<Json, String> {
        if let Some(local) = &self.local {
            let mut core = local.lock().map_err(|_| "plane poisoned".to_string())?;
            return serde_json::to_value(core.snapshot()).map_err(|error| error.to_string());
        }
        self.get("/metrics")
    }

    fn engines(&self) -> Result<Json, String> {
        if let Some(local) = &self.local {
            let mut core = local.lock().map_err(|_| "plane poisoned".to_string())?;
            return serde_json::to_value(core.snapshot().engines)
                .map_err(|error| error.to_string());
        }
        self.get("/engines")
    }

    fn activity(&self) -> Result<Json, String> {
        if let Some(local) = &self.local {
            let mut core = local.lock().map_err(|_| "plane poisoned".to_string())?;
            return serde_json::to_value(core.snapshot().activity)
                .map_err(|error| error.to_string());
        }
        self.get("/activity")
    }

    fn scenario_results(&self) -> Result<Json, String> {
        if let Some(local) = &self.local {
            let mut core = local.lock().map_err(|_| "plane poisoned".to_string())?;
            return serde_json::to_value(core.snapshot().scenario_results)
                .map_err(|error| error.to_string());
        }
        self.get("/scenarios/results")
    }

    fn events_tail(&self, limit: usize) -> Result<Json, String> {
        if let Some(local) = &self.local {
            let mut core = local.lock().map_err(|_| "plane poisoned".to_string())?;
            let snapshot = core.snapshot();
            let start = snapshot.events.len().saturating_sub(limit);
            let events = snapshot.events[start..].to_vec();
            let oldest = snapshot.events.first().map(|event| event.id).unwrap_or(0);
            return Ok(crate::server::tail_envelope(
                events,
                oldest,
                snapshot.dropped_through,
            ));
        }
        self.get(&format!("/logs/tail?n={limit}"))
    }

    fn events_since(&self, cursor: u64) -> Result<Json, String> {
        if let Some(local) = &self.local {
            let mut core = local.lock().map_err(|_| "plane poisoned".to_string())?;
            let snapshot = core.snapshot();
            let oldest = snapshot.events.first().map(|event| event.id).unwrap_or(0);
            let newest = snapshot.events.last().map(|event| event.id).unwrap_or(0);
            let dropped_through = snapshot.dropped_through;
            let events = snapshot
                .events
                .into_iter()
                .filter(|event| event.id > cursor)
                .collect();
            return Ok(crate::server::since_envelope(
                events,
                cursor,
                oldest,
                dropped_through,
                newest,
            ));
        }
        self.get(&format!("/logs/since?id={cursor}"))
    }

    fn status_module(&self) -> Result<Json, String> {
        if let Some(local) = &self.local {
            let mut core = local.lock().map_err(|_| "plane poisoned".to_string())?;
            return core.status_module_json();
        }
        self.get("/status-module")
    }

    fn scenario(&self, id: &str) -> Result<Json, String> {
        if self.read_only {
            return Err("read-only plane: scenarios are disabled".to_string());
        }
        // The id is interpolated into a URL path. Accepting only the ids this
        // plane defines keeps a `/`, `?` or `#` from rewriting the request, and
        // the allowlist is enforced here as well as in the router.
        if crate::plane::scenario_def(id).is_none() {
            return Err(format!("unknown scenario {id}"));
        }
        if let Some(local) = &self.local {
            let mut core = local.lock().map_err(|_| "plane poisoned".to_string())?;
            return core.run_scenario(id).and_then(|result| {
                let snapshot = core.snapshot();
                serde_json::to_value(json!({"result": result, "metrics": snapshot.metrics}))
                    .map_err(|error| error.to_string())
            });
        }
        let response = self
            .http
            .post(&format!("{}/demo/scenario/{id}", self.base))
            .timeout(std::time::Duration::from_secs(60))
            .send_json(json!({}))
            .map_err(|error| error.to_string())?;
        read_json(response)
    }

    fn level(&self, level: u8, up_to: bool) -> Result<Json, String> {
        if self.read_only {
            return Err("read-only plane: scenarios are disabled".to_string());
        }
        if level > 6 {
            return Err("level must be 0..=6".to_string());
        }
        if let Some(local) = &self.local {
            let mut core = local.lock().map_err(|_| "plane poisoned".to_string())?;
            let results = core.run_level(level, up_to);
            let snapshot = core.snapshot();
            return serde_json::to_value(json!({
                "level": level,
                "up_to": up_to,
                "results": results,
                "metrics": snapshot.metrics,
            }))
            .map_err(|error| error.to_string());
        }
        let response = self
            .http
            .post(&format!("{}/demo/level/{level}?up_to={up_to}", self.base))
            .timeout(std::time::Duration::from_secs(120))
            .send_json(json!({}))
            .map_err(|error| error.to_string())?;
        read_json(response)
    }
}

fn tool(name: &str, description: &str, schema: Json) -> Json {
    json!({"name": name, "description": description, "inputSchema": schema})
}

fn tools() -> Json {
    json!([
        tool(
            "cp_metrics",
            "Latest real snapshot: kernel counters, Infinity timings and gauges (same values as the dashboard).",
            json!({"type": "object", "properties": {}, "additionalProperties": false})
        ),
        tool(
            "cp_activity_state",
            "Current Live activity mode, summary, real stages and lane occupancy.",
            json!({"type": "object", "properties": {}, "additionalProperties": false})
        ),
        tool(
            "cp_events_tail",
            "Last redacted structured events (ts, category, code, duration, bytes, lane, scenario id).",
            json!({"type": "object", "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 500}}, "additionalProperties": false})
        ),
        tool(
            "cp_events_since",
            "Structured events with an id greater than the cursor. Use the returned cursor to poll.",
            json!({"type": "object", "properties": {"cursor": {"type": "integer", "minimum": 0}}, "required": ["cursor"], "additionalProperties": false})
        ),
        tool(
            "cp_scenario_results",
            "Latest pass/fail result for each ladder scenario, with stable codes and timings.",
            json!({"type": "object", "properties": {}, "additionalProperties": false})
        ),
        tool(
            "cp_engines",
            "Real lane, channel and capability registries (counts and correlation ids only).",
            json!({"type": "object", "properties": {}, "additionalProperties": false})
        ),
        tool(
            "cp_run_scenario",
            "Run one allow-listed scenario from the L0-L6 ladder.",
            json!({"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"], "additionalProperties": false})
        ),
        tool(
            "cp_run_level",
            "Run one ladder level, or every level up to it. Returns every scenario result.",
            json!({"type": "object", "properties": {"level": {"type": "integer", "minimum": 0, "maximum": 6}, "up_to": {"type": "boolean"}}, "required": ["level"], "additionalProperties": false})
        ),
        tool(
            "cp_status_module",
            "Active Infinity status module: AINF bytes (base64), content hash and redacted JSON.",
            json!({"type": "object", "properties": {}, "additionalProperties": false})
        ),
    ])
}

/// Why a tool call produced no answer.
///
/// The JSON-RPC code says whose fault it is: bad arguments are invalid params
/// (-32602), a plane or transport failure is an internal error (-32603). Every
/// failure used to be -32602, so a down plane looked like a bad request
/// (R-19 round 4, F16).
#[derive(Debug)]
struct ToolFailure {
    code: i64,
    message: String,
}

impl ToolFailure {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            code: -32603,
            message: message.into(),
        }
    }
}

fn call(attach: &Attach, params: &Json) -> Result<Json, ToolFailure> {
    let name = params
        .get("name")
        .and_then(Json::as_str)
        .ok_or_else(|| ToolFailure::invalid("missing tool name"))?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let value = match name {
        "cp_metrics" => attach.snapshot().map_err(ToolFailure::internal)?,
        "cp_activity_state" => attach.activity().map_err(ToolFailure::internal)?,
        "cp_engines" => attach.engines().map_err(ToolFailure::internal)?,
        "cp_status_module" => attach.status_module().map_err(ToolFailure::internal)?,
        "cp_scenario_results" => attach.scenario_results().map_err(ToolFailure::internal)?,
        "cp_events_tail" => {
            let limit = arguments
                .get("limit")
                .and_then(Json::as_u64)
                .unwrap_or(40)
                .clamp(1, 500) as usize;
            attach.events_tail(limit).map_err(ToolFailure::internal)?
        }
        "cp_events_since" => {
            let cursor = arguments
                .get("cursor")
                .and_then(Json::as_u64)
                .ok_or_else(|| ToolFailure::invalid("missing cursor"))?;
            attach.events_since(cursor).map_err(ToolFailure::internal)?
        }
        "cp_run_scenario" => {
            let id = arguments
                .get("id")
                .and_then(Json::as_str)
                .ok_or_else(|| ToolFailure::invalid("missing scenario id"))?;
            attach.scenario(id).map_err(ToolFailure::internal)?
        }
        "cp_run_level" => {
            let level = arguments
                .get("level")
                .and_then(Json::as_u64)
                .ok_or_else(|| ToolFailure::invalid("missing level"))?;
            if level > 6 {
                return Err(ToolFailure::invalid("level must be 0..=6"));
            }
            let up_to = arguments
                .get("up_to")
                .and_then(Json::as_bool)
                .unwrap_or(false);
            attach
                .level(level as u8, up_to)
                .map_err(ToolFailure::internal)?
        }
        other => return Err(ToolFailure::invalid(format!("unknown tool {other}"))),
    };
    // One choke point for the degraded marking (RPC-42): every tool answer
    // from the embedded plane carries `degraded`, whichever tool produced
    // it, and a live-plane answer never does.
    let value = attach.mark_degraded(value);
    Ok(json!({
        "content": [{"type": "text", "text": serde_json::to_string_pretty(&value).unwrap_or_default()}],
        "isError": false
    }))
}

fn respond(request: &Json, attach: &Attach) -> Option<Json> {
    // A request without an id is a notification (initialized, cancelled, ...).
    let id = request.get("id")?.clone();
    let method = request.get("method").and_then(Json::as_str).unwrap_or("");
    let result = match method {
        "initialize" => Ok(json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "active-control-plane", "version": "0.1.0"}
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tools()})),
        "tools/call" => {
            let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
            call(attach, &params)
        }
        other => Err(ToolFailure::invalid(format!("method not found: {other}"))),
    };
    Some(match result {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err(failure) => {
            // An unknown JSON-RPC method is method-not-found; a tool call's
            // code comes from the failure itself.
            let code = if method == "tools/call" {
                failure.code
            } else {
                -32601
            };
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": code, "message": failure.message}
            })
        }
    })
}

/// Longest MCP request line accepted, in bytes.
///
/// `stdin.lines()` grows a `String` until it finds a newline, so a host that
/// never sends one could grow this process's memory without bound.
pub const MAX_REQUEST_LINE: usize = 1 << 20;

/// Read one `\n`-terminated line, refusing one longer than `limit` bytes.
///
/// Returns the number of bytes buffered (0 at end of input).
fn read_bounded_line(
    reader: &mut impl BufRead,
    buffer: &mut Vec<u8>,
    limit: usize,
) -> io::Result<usize> {
    loop {
        let available = match reader.fill_buf() {
            Ok(chunk) => chunk,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if available.is_empty() {
            return Ok(buffer.len());
        }
        match available.iter().position(|byte| *byte == b'\n') {
            Some(index) => {
                if buffer.len() + index > limit {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "MCP request line exceeds the ceiling",
                    ));
                }
                buffer.extend_from_slice(&available[..=index]);
                reader.consume(index + 1);
                return Ok(buffer.len());
            }
            None => {
                let length = available.len();
                if buffer.len() + length > limit {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "MCP request line exceeds the ceiling",
                    ));
                }
                buffer.extend_from_slice(available);
                reader.consume(length);
            }
        }
    }
}

pub fn run(attach_url: Option<String>, read_only: bool) -> io::Result<()> {
    let base = attach_url.unwrap_or_else(|| DEFAULT_ATTACH.to_string());
    // The plane is loopback-only, so a base that names another machine cannot
    // be the plane this process is supposed to read.
    if !crate::server::same_origin(&base, None) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("--attach must name a loopback origin, got {base}"),
        ));
    }
    let attach = Attach::new(base, read_only);
    let mut stdin = io::BufReader::new(io::stdin());
    let mut stdout = io::stdout();
    loop {
        let mut buffer = Vec::new();
        if read_bounded_line(&mut stdin, &mut buffer, MAX_REQUEST_LINE)? == 0 {
            break;
        }
        let line = String::from_utf8_lossy(&buffer).into_owned();
        if line.trim().is_empty() {
            continue;
        }
        let request: Json = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(error) => {
                let response = json!({
                    "jsonrpc": "2.0", "id": null,
                    "error": {"code": -32700, "message": format!("parse error: {error}")}
                });
                writeln!(stdout, "{response}")?;
                stdout.flush()?;
                continue;
            }
        };
        if let Some(response) = respond(&request, &attach) {
            writeln!(stdout, "{response}")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{read_bounded_line, Json, MAX_REQUEST_LINE, MAX_RESPONSE_BYTES};
    use serde_json::json;
    use std::io::Cursor;

    #[test]
    fn a_request_line_is_bounded() {
        let mut reader = Cursor::new(b"{\"jsonrpc\":\"2.0\"}\n".to_vec());
        let mut buffer = Vec::new();
        assert_eq!(
            read_bounded_line(&mut reader, &mut buffer, 64).expect("line"),
            18
        );
        assert_eq!(buffer, b"{\"jsonrpc\":\"2.0\"}\n");

        // A line that never ends is refused instead of buffered: `lines()`
        // would have grown this process's memory until the host stopped.
        let mut reader = Cursor::new(vec![b'x'; 4096]);
        let mut buffer = Vec::new();
        assert!(read_bounded_line(&mut reader, &mut buffer, 1024).is_err());
        assert!(buffer.len() <= 1024);

        // End of input is not an error.
        let mut reader = Cursor::new(Vec::new());
        let mut buffer = Vec::new();
        assert_eq!(
            read_bounded_line(&mut reader, &mut buffer, MAX_REQUEST_LINE).expect("eof"),
            0
        );
    }

    #[test]
    fn the_attach_base_must_be_loopback() {
        // The same predicate the client uses before it opens a socket.
        assert!(crate::server::same_origin("http://127.0.0.1:8787", None));
        assert!(crate::server::same_origin("http://localhost:8787", None));
        assert!(!crate::server::same_origin("http://example.com:8787", None));
        assert!(!crate::server::same_origin(
            "http://127.0.0.1.evil.example",
            None
        ));
    }

    /// A `3xx` from whatever owns the attach port must not be followed: the
    /// redirect target escapes the loopback check and its body would be handed
    /// to the agent as `cp_metrics` (R-19 round 3, L6).
    #[test]
    fn an_attach_redirect_is_not_followed() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("stub");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                counter.fetch_add(1, Ordering::SeqCst);
                let mut buffer = [0u8; 1024];
                let _ = stream.read(&mut buffer);
                let response = "HTTP/1.1 302 Found\r\nlocation: http://169.254.169.254/latest\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
                let _ = stream.write_all(response.as_bytes());
            }
        });

        let attach = super::Attach {
            base: base.clone(),
            http: ureq::AgentBuilder::new().redirects(0).build(),
            local: None,
            read_only: true,
        };
        let error = attach.get("/metrics").expect_err("a redirect is refused");
        assert!(!error.is_empty(), "the refusal carries no detail");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "the client followed the redirect"
        );
    }

    /// The embedded fallback and the HTTP route share one envelope: the same
    /// tool used to answer `{count,cursor,events}` without `oldest`,
    /// `truncated` or `gap` (R-19 round 3, L3).
    #[test]
    fn both_event_tools_carry_the_full_envelope() {
        let tail = crate::server::tail_envelope(Vec::new(), 7, 9);
        for key in ["count", "cursor", "oldest", "truncated", "events"] {
            assert!(tail.get(key).is_some(), "tail envelope is missing {key}");
        }
        assert_eq!(tail["truncated"], serde_json::Value::Bool(true));
        let since = crate::server::since_envelope(Vec::new(), 3, 7, 9, 12);
        for key in ["count", "cursor", "oldest", "gap", "events"] {
            assert!(since.get(key).is_some(), "since envelope is missing {key}");
        }
        assert_eq!(since["gap"], serde_json::Value::Bool(true));
        assert_eq!(since["cursor"], serde_json::Value::from(3u64));
    }

    /// Serve `body` for every request on a loopback stub, returning its
    /// base URL. The stub answers every path with `body`, whatever the
    /// method — the same shape as the redirect stub above, with the
    /// response body as the variable. Tests build `Attach` literally, so
    /// no `/health` check runs against the stub.
    fn serve(body: Vec<u8>) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::Arc;

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("stub");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let body = Arc::new(body);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let body = Arc::clone(&body);
                std::thread::spawn(move || {
                    // Read the whole request before answering: headers up
                    // to `\r\n\r\n`, then the `Content-Length` body, if
                    // any. Answering after a partial read leaves the
                    // request body unread, and closing with unread
                    // received data makes Windows reset the connection
                    // (os error 10054) while the client is still reading
                    // the response — which is exactly what a `POST` leg
                    // hit before this read loop existed.
                    let mut request = Vec::new();
                    let mut buffer = [0u8; 4096];
                    loop {
                        let Ok(read) = stream.read(&mut buffer) else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        request.extend_from_slice(&buffer[..read]);
                        let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n")
                        else {
                            continue;
                        };
                        let headers = String::from_utf8_lossy(&request[..end]);
                        let mut content_length = 0usize;
                        for line in headers.lines().skip(1) {
                            let mut parts = line.splitn(2, ':');
                            let name = parts.next().unwrap_or("");
                            let value = parts.next().unwrap_or("");
                            if name.eq_ignore_ascii_case("content-length") {
                                content_length = value.trim().parse().unwrap_or(0);
                            }
                        }
                        if request.len() >= end + 4 + content_length {
                            break;
                        }
                    }
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.write_all(&body);
                });
            }
        });
        base
    }

    /// A valid JSON body of exactly `size` bytes: `{"pad": "<x…>"}` — a
    /// 9-byte prefix (`{"pad": "`), the pad, and a 2-byte suffix (`"}`).
    fn json_body_of_size(size: usize) -> Vec<u8> {
        assert!(size >= 11, "body too small for the envelope");
        let body = format!("{{\"pad\": \"{}\"}}", "x".repeat(size - 11)).into_bytes();
        assert_eq!(body.len(), size, "body is not the requested size");
        body
    }

    fn attach_to(base: String, read_only: bool) -> super::Attach {
        super::Attach {
            base,
            http: ureq::AgentBuilder::new().redirects(0).build(),
            local: None,
            read_only,
        }
    }

    /// The text payload of a successful tool call, parsed back to JSON.
    fn tool_answer(result: &Json) -> Json {
        let text = result["content"][0]["text"]
            .as_str()
            .expect("tool answer carries text");
        serde_json::from_str(text).expect("tool answer text is JSON")
    }

    /// A loopback port nothing listens on: bind an ephemeral port, then
    /// close it, so the attach target is unreachable (connection refused).
    fn closed_loopback_port() -> u16 {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        port
    }

    /// A plane response past the ceiling is refused with an error naming
    /// the ceiling — never read in full, never truncated (RPC-42).
    ///
    /// W2's probe showed the pre-fix shape: a 20 MB `/metrics` body came
    /// back through `cp_metrics` whole (12.2 s, marker present), and at
    /// the audited head 15.3 MB had already been read before the 5 s
    /// timeout fired. The boundary is pinned too: exactly the ceiling
    /// parses, one byte past it is refused.
    #[test]
    fn an_oversized_plane_response_is_refused_not_read() {
        let big = attach_to(serve(json_body_of_size(MAX_RESPONSE_BYTES + 1)), true);
        let error = big.get("/metrics").expect_err("oversized body refused");
        assert!(
            error.contains("exceeds") && error.contains(&MAX_RESPONSE_BYTES.to_string()),
            "the refusal must name the ceiling, got: {error}"
        );

        let exact = attach_to(serve(json_body_of_size(MAX_RESPONSE_BYTES)), true);
        let value = exact.get("/metrics").expect("ceiling-sized body parses");
        assert_eq!(
            value["pad"].as_str().expect("pad").len(),
            MAX_RESPONSE_BYTES - 11,
            "the ceiling-sized body must arrive whole, not truncated"
        );

        let small = attach_to(serve(json_body_of_size(64)), true);
        let value = small.get("/metrics").expect("small body parses");
        assert_eq!(value["pad"].as_str().expect("pad").len(), 53);
    }

    /// The cap is on every plane response, not just `GET /metrics`: the
    /// scenario/level `POST` replies went through the same unbounded
    /// `into_json()` (RPC-42).
    #[test]
    fn a_posted_plane_response_is_capped_too() {
        let big = attach_to(serve(json_body_of_size(MAX_RESPONSE_BYTES + 1)), false);
        let error = big
            .level(0, false)
            .expect_err("oversized POST body refused");
        assert!(
            error.contains("exceeds") && error.contains(&MAX_RESPONSE_BYTES.to_string()),
            "the refusal must name the ceiling, got: {error}"
        );
    }

    /// Answers from the embedded plane carry `degraded`, and answers from
    /// a live plane never do (RPC-42).
    ///
    /// The fallback itself is preserved — offline use still answers —
    /// but the marking is applied at the one choke point in `call()`, so
    /// every tool is marked, not just `cp_metrics`.
    #[test]
    fn embedded_plane_answers_are_marked_degraded() {
        let port = closed_loopback_port();
        let embedded = super::Attach::new(format!("http://127.0.0.1:{port}"), true);
        assert!(embedded.is_degraded(), "unreachable target is degraded");

        for tool in ["cp_metrics", "cp_engines"] {
            let result = super::call(&embedded, &json!({"name": tool, "arguments": {}}))
                .expect("embedded plane answers");
            let answer = tool_answer(&result);
            assert_eq!(
                answer["degraded"],
                Json::Bool(true),
                "{tool} from the embedded plane must be marked degraded: {answer}"
            );
        }

        let live = attach_to(serve(json_body_of_size(64)), true);
        let result = super::call(&live, &json!({"name": "cp_metrics", "arguments": {}}))
            .expect("live plane answers");
        let answer = tool_answer(&result);
        assert!(
            answer.get("degraded").is_none(),
            "a live-plane answer must not be marked degraded: {answer}"
        );
        assert_eq!(answer["pad"].as_str().expect("pad").len(), 53);
    }
}
