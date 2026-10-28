//! Read-only MCP server over stdio.
//!
//! By default it attaches to a running control plane (`--attach` or
//! `http://127.0.0.1:8787`) so agents read the same snapshot the dashboard
//! shows. If the service is not running, it falls back to an embedded real
//! plane and says so on stderr.

use std::io::{self, BufRead, Write};
use std::sync::Mutex;

use serde_json::{json, Value as Json};

use crate::plane::PlaneCore;

const DEFAULT_ATTACH: &str = "http://127.0.0.1:8787";

struct Attach {
    base: String,
    local: Option<Mutex<PlaneCore>>,
    read_only: bool,
}

impl Attach {
    fn new(base: String, read_only: bool) -> Self {
        let reachable = ureq::get(&format!("{base}/health"))
            .timeout(std::time::Duration::from_millis(500))
            .call()
            .is_ok();
        if !reachable {
            eprintln!("active-control-plane MCP: {base} is not reachable; using an embedded plane");
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
            local,
            read_only,
        }
    }

    fn get(&self, path: &str) -> Result<Json, String> {
        ureq::get(&format!("{}{}", self.base, path))
            .timeout(std::time::Duration::from_secs(5))
            .call()
            .map_err(|error| error.to_string())?
            .into_json::<Json>()
            .map_err(|error| error.to_string())
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
            let cursor = events.last().map(|event| event.id).unwrap_or(0);
            return serde_json::to_value(json!({
                "count": events.len(),
                "cursor": cursor,
                "events": events,
            }))
            .map_err(|error| error.to_string());
        }
        self.get(&format!("/logs/tail?n={limit}"))
    }

    fn events_since(&self, cursor: u64) -> Result<Json, String> {
        if let Some(local) = &self.local {
            let core = local.lock().map_err(|_| "plane poisoned".to_string())?;
            let events = core.events_after(cursor);
            let next = events.last().map(|event| event.id).unwrap_or(cursor);
            return serde_json::to_value(json!({
                "count": events.len(),
                "cursor": next,
                "events": events,
            }))
            .map_err(|error| error.to_string());
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
        if let Some(local) = &self.local {
            let mut core = local.lock().map_err(|_| "plane poisoned".to_string())?;
            return core.run_scenario(id).and_then(|result| {
                let snapshot = core.snapshot();
                serde_json::to_value(json!({"result": result, "metrics": snapshot.metrics}))
                    .map_err(|error| error.to_string())
            });
        }
        ureq::post(&format!("{}/demo/scenario/{id}", self.base))
            .timeout(std::time::Duration::from_secs(60))
            .send_json(json!({}))
            .map_err(|error| error.to_string())?
            .into_json::<Json>()
            .map_err(|error| error.to_string())
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
        ureq::post(&format!("{}/demo/level/{level}?up_to={up_to}", self.base))
            .timeout(std::time::Duration::from_secs(120))
            .send_json(json!({}))
            .map_err(|error| error.to_string())?
            .into_json::<Json>()
            .map_err(|error| error.to_string())
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

fn call(attach: &Attach, params: &Json) -> Result<Json, String> {
    let name = params
        .get("name")
        .and_then(Json::as_str)
        .ok_or_else(|| "missing tool name".to_string())?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let value = match name {
        "cp_metrics" => attach.snapshot()?,
        "cp_activity_state" => attach.activity()?,
        "cp_engines" => attach.engines()?,
        "cp_status_module" => attach.status_module()?,
        "cp_scenario_results" => attach.scenario_results()?,
        "cp_events_tail" => {
            let limit = arguments
                .get("limit")
                .and_then(Json::as_u64)
                .unwrap_or(40)
                .clamp(1, 500) as usize;
            attach.events_tail(limit)?
        }
        "cp_events_since" => {
            let cursor = arguments
                .get("cursor")
                .and_then(Json::as_u64)
                .ok_or_else(|| "missing cursor".to_string())?;
            attach.events_since(cursor)?
        }
        "cp_run_scenario" => {
            let id = arguments
                .get("id")
                .and_then(Json::as_str)
                .ok_or_else(|| "missing scenario id".to_string())?;
            attach.scenario(id)?
        }
        "cp_run_level" => {
            let level = arguments
                .get("level")
                .and_then(Json::as_u64)
                .ok_or_else(|| "missing level".to_string())?;
            if level > 6 {
                return Err("level must be 0..=6".to_string());
            }
            let up_to = arguments
                .get("up_to")
                .and_then(Json::as_bool)
                .unwrap_or(false);
            attach.level(level as u8, up_to)?
        }
        other => return Err(format!("unknown tool {other}")),
    };
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
        other => Err(format!("method not found: {other}")),
    };
    Some(match result {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err(message) => {
            // A tool call with a bad name or argument is invalid params;
            // an unknown JSON-RPC method is method-not-found.
            let code = if method == "tools/call" {
                -32602
            } else {
                -32601
            };
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": code, "message": message}
            })
        }
    })
}

pub fn run(attach_url: Option<String>, read_only: bool) -> io::Result<()> {
    let attach = Attach::new(
        attach_url.unwrap_or_else(|| DEFAULT_ATTACH.to_string()),
        read_only,
    );
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
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
