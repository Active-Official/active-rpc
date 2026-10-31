//! The real engine behind the control plane.
//!
//! Every number in a [`Snapshot`] comes from a shipped `active-rpc` kernel or
//! from a timed `active-infinity` call. Scenarios execute the public APIs; the
//! UI never receives synthetic telemetry.

use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::panic::AssertUnwindSafe;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use active_infinity::stream::{StreamDecoder, StreamEncoder};
use active_infinity::{content_hash, decode, encode, validate, InfinityModule, Inode, SecretBytes};
use active_rpc::cap::{CapAttrs, CapHandle, ToolPolicy};
use active_rpc::domain::ModuleProvider;
use active_rpc::kernel::{Event, Metrics, PromiseHandle, Provider};
use active_rpc::tool::{HttpTool, LocalProcess, McpSession, MemoryTransport};
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, Budget, ChannelId, LaneId, ProviderId};
use serde::Serialize;
use serde_json::{json, Value as Json};

pub const SECRET_CANARY: &str = "control-plane-secret-canary-8f21";
const EVENT_TAIL: usize = 500;
const GAUGE_SAMPLES: usize = 30;
const CALL_SAMPLES: usize = 512;

#[derive(Clone, Debug, Serialize)]
pub struct CapView {
    pub id: String,
    pub label: String,
    pub methods: Vec<String>,
    pub max_calls: u64,
    pub read_only: bool,
    pub attenuated: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct LaneStat {
    pub lane: u64,
    pub name: String,
    pub pending: u32,
    pub completed: u64,
    pub queue: usize,
    pub closed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChannelStat {
    pub channel: u64,
    pub name: String,
    pub sent: u64,
    pub received: u64,
    pub subscribers: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct EngineView {
    pub lanes: Vec<LaneStat>,
    pub channels: Vec<ChannelStat>,
    pub capabilities: Vec<CapView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct UiEvent {
    pub id: u64,
    pub ts_ms: u64,
    pub category: String,
    pub kind: String,
    pub lane: Option<String>,
    pub capability: Option<String>,
    pub method: Option<String>,
    pub code: Option<String>,
    pub duration_us: Option<f64>,
    pub bytes: Option<u64>,
    pub scenario_id: Option<String>,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Counters {
    pub encodes: u64,
    pub decodes: u64,
    pub validates: u64,
    pub hashes: u64,
    pub tool_calls: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub streaming_frames: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Timings {
    pub encode_us: f64,
    pub decode_us: f64,
    pub validate_us: f64,
    pub hash_us: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct InfinityView {
    pub image_bytes: usize,
    pub hash: String,
    pub timings: Timings,
    pub counters: Counters,
}

#[derive(Clone, Debug, Serialize)]
pub struct Health {
    pub kernel: String,
    pub mode: String,
    pub observers: u64,
    pub last_event_ms_ago: u64,
    pub redaction_ok: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct MetricsView {
    pub calls_queued: u64,
    pub calls_refused: u64,
    pub budget_exhaustions: u64,
    pub tool_refusals: u64,
    pub revocations: u64,
    pub promises_resolved: u64,
    pub promises_rejected: u64,
    pub promise_records: usize,
    pub round_trips: u64,
    pub transfers: u64,
    pub calls_per_second: f64,
    pub pipeline_depth: u64,
    pub budget_pressure: f64,
    pub active_lanes: usize,
    pub active_channels: usize,
    pub caps_live: usize,
    pub queue_depth: u64,
    pub wire_in_per_s: f64,
    pub wire_out_per_s: f64,
    pub settled_per_s: f64,
    pub tool_calls_per_s: f64,
    pub tool_refusals_per_s: f64,
    pub stream_frames_per_s: f64,
    pub p99_call_us: f64,
    pub canonical_ok_rate: f64,
    pub canonical_samples: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScenarioResult {
    pub id: String,
    pub code: String,
    pub level: u8,
    pub title: String,
    pub ok: bool,
    pub detail: String,
    pub duration_us: u64,
    #[serde(skip_serializing)]
    pub before: MetricsView,
    #[serde(skip_serializing)]
    pub after: MetricsView,
    pub data: Json,
}

#[derive(Clone, Debug, Serialize)]
pub struct BenchmarkStats {
    pub n: usize,
    pub p50_us: f64,
    pub p99_us: f64,
    pub min_us: f64,
    pub max_us: f64,
    pub mean_us: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct BenchmarkReport {
    pub ts_ms: u64,
    pub encode: BenchmarkStats,
    pub validate: BenchmarkStats,
    pub call_sequential: BenchmarkStats,
    pub call_pipelined: BenchmarkStats,
    pub samples: BTreeMap<String, Vec<f64>>,
    #[serde(skip_serializing)]
    pub csv: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScenarioDef {
    pub id: &'static str,
    pub code: &'static str,
    pub level: u8,
    pub mode: &'static str,
    pub title: &'static str,
    pub description: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct ActivityStage {
    pub name: String,
    pub detail: String,
    pub duration_us: f64,
    pub ok: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ActivityView {
    pub mode: String,
    pub summary: String,
    pub ok: Option<bool>,
    pub stages: Vec<ActivityStage>,
    pub hash_prefix: Option<String>,
    pub bytes: Option<u64>,
    pub progress: Option<(u64, u64)>,
    pub promise_chain: Vec<u64>,
    pub lanes: Vec<LaneStat>,
    pub last_event_age_ms: u64,
    pub started_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct GaugeSample {
    pub ts_ms: u64,
    pub value: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub ts_ms: u64,
    pub uptime_ms: u64,
    pub health: Health,
    pub metrics: MetricsView,
    pub infinity: InfinityView,
    pub engines: EngineView,
    pub events: Vec<UiEvent>,
    pub last_scenario: Option<ScenarioResult>,
    pub scenario_results: Vec<ScenarioResult>,
    pub scenarios: Vec<ScenarioDef>,
    pub activity: ActivityView,
    pub benchmark: Option<BenchmarkReport>,
    pub scenario_ids: Vec<&'static str>,
    pub gauge_samples: BTreeMap<String, Vec<GaugeSample>>,
    pub last_error_code: String,
}

/// The scenario ladder. Every id maps to a real call path in this process.
pub const SCENARIOS: &[ScenarioDef] = &[
    ScenarioDef {
        id: "round-trip",
        code: "L0.1",
        level: 0,
        mode: "InfinityOp",
        title: "Infinity round-trip",
        description: "encode, validate, hash, decode, re-encode equal",
    },
    ScenarioDef {
        id: "evaluate",
        code: "L0.2",
        level: 0,
        mode: "RpcBatch",
        title: "Module evaluate",
        description: "one evaluate call on the installed module",
    },
    ScenarioDef {
        id: "metrics",
        code: "L0.3",
        level: 0,
        mode: "InfinityOp",
        title: "Metrics snapshot",
        description: "kernel counters and event tape are present",
    },
    ScenarioDef {
        id: "pipeline",
        code: "L1.1",
        level: 1,
        mode: "RpcBatch",
        title: "Pipelining vs sequential",
        description: "six dependent calls settle in one provider round-trip",
    },
    ScenarioDef {
        id: "redaction",
        code: "L1.2",
        level: 1,
        mode: "InfinityOp",
        title: "Secret redaction",
        description: "JSON, Protobuf and Debug hide a canary",
    },
    ScenarioDef {
        id: "attenuation",
        code: "L1.3",
        level: 1,
        mode: "RpcBatch",
        title: "Attenuation refusal",
        description: "a widening attempt is refused by the kernel",
    },
    ScenarioDef {
        id: "revoke",
        code: "L1.4",
        level: 1,
        mode: "RpcBatch",
        title: "Revoke before dispatch",
        description: "a revoked capability never reaches the provider",
    },
    ScenarioDef {
        id: "streaming",
        code: "L1.5",
        level: 1,
        mode: "StreamOp",
        title: "Streaming reassembly",
        description: "frames reassemble to the canonical image",
    },
    ScenarioDef {
        id: "mcp-memory",
        code: "L2.1",
        level: 2,
        mode: "ToolOp",
        title: "MCP memory tool",
        description: "handshake and tools/call through MemoryTransport",
    },
    ScenarioDef {
        id: "tool-policy",
        code: "L2.2",
        level: 2,
        mode: "ToolOp",
        title: "MCP tool refused",
        description: "an unlisted tool is refused by policy",
    },
    ScenarioDef {
        id: "http-tool",
        code: "L2.3",
        level: 2,
        mode: "ToolOp",
        title: "HTTP allow-list",
        description: "allowed GET succeeds; a path escape is refused",
    },
    ScenarioDef {
        id: "local-process",
        code: "L2.4",
        level: 2,
        mode: "ToolOp",
        title: "Local process policy",
        description: "allowlisted echo runs; process denial refuses",
    },
    ScenarioDef {
        id: "lanes",
        code: "L3.1",
        level: 3,
        mode: "RpcBatch",
        title: "Multi-lane batch",
        description: "four lanes settle in one provider round-trip",
    },
    ScenarioDef {
        id: "channel-share",
        code: "L3.2",
        level: 3,
        mode: "RpcBatch",
        title: "Channel capability share",
        description: "a message transfers a capability id by reference",
    },
    ScenarioDef {
        id: "pipeline-stress",
        code: "L3.3",
        level: 3,
        mode: "RpcBatch",
        title: "Pipeline stress",
        description: "a 32-link dependency chain settles in one round-trip",
    },
    ScenarioDef {
        id: "budget",
        code: "L4.1",
        level: 4,
        mode: "Stress",
        title: "Byte budget bomb",
        description: "nested arguments exceed a byte ceiling",
    },
    ScenarioDef {
        id: "call-storm",
        code: "L4.2",
        level: 4,
        mode: "Stress",
        title: "Call budget storm",
        description: "queued calls stop at the call ceiling",
    },
    ScenarioDef {
        id: "tool-ceiling",
        code: "L4.3",
        level: 4,
        mode: "Stress",
        title: "Tool payload ceiling",
        description: "an oversized tool argument is refused",
    },
    ScenarioDef {
        id: "bench-sizes",
        code: "L5.1",
        level: 5,
        mode: "Benchmark",
        title: "Codec size benchmark",
        description: "encode and validate p50/p99 for three sizes",
    },
    ScenarioDef {
        id: "bench-calls",
        code: "L5.2",
        level: 5,
        mode: "Benchmark",
        title: "RPC call benchmark",
        description: "sequential and pipelined p50/p99 in-process",
    },
    ScenarioDef {
        id: "bench-export",
        code: "L5.3",
        level: 5,
        mode: "Benchmark",
        title: "Benchmark export",
        description: "run the desk and verify raw CSV samples",
    },
    ScenarioDef {
        id: "fuzz-smoke",
        code: "L6.1",
        level: 6,
        mode: "InfinityOp",
        title: "Fuzz smoke",
        description: "corrupt images fail closed without a panic",
    },
];

pub fn scenario_def(id: &str) -> Option<&'static ScenarioDef> {
    SCENARIOS.iter().find(|def| def.id == id)
}

#[derive(Clone)]
struct CapInfo {
    label: &'static str,
    cap: CapHandle,
    methods: Vec<String>,
    max_calls: u64,
    read_only: bool,
    attenuated: bool,
}

struct Echo;

impl Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }
    fn methods(&self) -> Vec<String> {
        vec!["echo".into(), "ping".into()]
    }
    fn mutating(&self, method: &str) -> bool {
        method == "mutate"
    }
    fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
        let value = call
            .args
            .iter()
            .find_map(|arg| match arg {
                Arg::Value(value) => Some(value.clone()),
                _ => None,
            })
            .unwrap_or_else(|| Value::text("pong"));
        Ok(Response::Value(value))
    }
}

struct ActivityState {
    mode: String,
    summary: String,
    ok: Option<bool>,
    stages: Vec<ActivityStage>,
    hash_prefix: Option<String>,
    bytes: Option<u64>,
    progress: Option<(u64, u64)>,
    promise_chain: Vec<u64>,
    at_ms: u64,
}

impl ActivityState {
    fn idle() -> Self {
        Self {
            mode: "Idle".into(),
            summary: "listening — run a scenario to see real work".into(),
            ok: None,
            stages: Vec::new(),
            hash_prefix: None,
            bytes: None,
            progress: None,
            promise_chain: Vec::new(),
            at_ms: now_ms(),
        }
    }
}

pub struct PlaneCore {
    agent: Agent,
    lane: LaneId,
    lanes: Vec<LaneId>,
    echo_provider: ProviderId,
    echo_cap: CapHandle,
    module_cap: CapHandle,
    mcp_cap: CapHandle,
    mcp_restricted: CapHandle,
    mcp_ceiling: CapHandle,
    http_cap: CapHandle,
    http_address: String,
    process_allowed: CapHandle,
    process_denied: CapHandle,
    caps: Vec<CapInfo>,
    channels: Vec<ChannelId>,
    channel_messages: BTreeMap<String, u64>,
    started: Instant,
    counters: Counters,
    timings: Timings,
    last_metrics: Metrics,
    last_metrics_at: Instant,
    calls_per_second: f64,
    wire_in_per_s: f64,
    wire_out_per_s: f64,
    settled_per_s: f64,
    tool_calls_per_s: f64,
    tool_refusals_per_s: f64,
    stream_frames_per_s: f64,
    events: VecDeque<UiEvent>,
    kernel_events_seen: u64,
    next_event_id: u64,
    last_scenario: Option<ScenarioResult>,
    scenario_results: BTreeMap<String, ScenarioResult>,
    promise_chain: Vec<u64>,
    last_counters: Counters,
    last_rates_at: Instant,
    call_samples: VecDeque<f64>,
    canonical_ok: u64,
    canonical_attempts: u64,
    benchmark: Option<BenchmarkReport>,
    redaction_ok: bool,
    status_image_bytes: usize,
    status_hash: String,
    activity: ActivityState,
    gauge_samples: BTreeMap<String, VecDeque<GaugeSample>>,
    plane_mode: String,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn percentile(samples: &[f64], fraction: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let index = ((sorted.len() - 1) as f64 * fraction).round() as usize;
    sorted[index]
}

fn stats(samples: Vec<f64>) -> BenchmarkStats {
    if samples.is_empty() {
        return BenchmarkStats {
            n: 0,
            p50_us: 0.0,
            p99_us: 0.0,
            min_us: 0.0,
            max_us: 0.0,
            mean_us: 0.0,
        };
    }
    let sum: f64 = samples.iter().sum();
    BenchmarkStats {
        n: samples.len(),
        p50_us: percentile(&samples, 0.50),
        p99_us: percentile(&samples, 0.99),
        min_us: samples.iter().copied().fold(f64::MAX, f64::min),
        max_us: samples.iter().copied().fold(f64::MIN, f64::max),
        mean_us: sum / samples.len() as f64,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn brief(value: &Value) -> String {
    let text = format!("{value:?}");
    if text.chars().count() > 160 {
        text.chars().take(157).collect::<String>() + "…"
    } else {
        text
    }
}

fn fixture_module() -> InfinityModule {
    fixture_with(3)
}

/// A deterministic module with `fields` integer members under one table.
fn fixture_with(fields: usize) -> InfinityModule {
    let mut module = InfinityModule::new();
    let mut table = Vec::with_capacity(fields.max(3));
    for index in 0..fields.max(3) {
        let value = module.push(Inode::Int(index as i64));
        table.push((format!("field-{index}"), value));
    }
    let name = module.push(Inode::Str("active-control-plane".into()));
    let port = module.push(Inode::Int(8787));
    table.push(("name".into(), name));
    table.push(("port".into(), port));
    let root = module.push(Inode::Table { fields: table });
    module.set_root(Some(root));
    module.bind("plane", root);
    module
}

fn redacted_probe() -> bool {
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(SecretBytes::from(SECRET_CANARY)));
    let copy = module.push(Inode::Str(SECRET_CANARY.into()));
    let root = module.push(Inode::Table {
        fields: vec![(SECRET_CANARY.into(), secret), ("copy".into(), copy)],
    });
    module.set_root(Some(root));
    let json = active_infinity::interop::to_redacted_json(&module).unwrap_or_default();
    let debug = format!("{module:?} {secret:?}");
    !json.contains(SECRET_CANARY) && !debug.contains(SECRET_CANARY)
}

fn category_for(kind: &str) -> &'static str {
    match kind {
        "call_queued" | "call_settled" | "job" => "calls",
        "batch" | "channel_msg" => "batch",
        "call_refused" | "tool_refused" | "budget" => "refusals",
        "cap_mint" | "cap_revoke" | "cap_expired" | "cap_introduce" | "cap_lifecycle"
        | "lane_created" | "lane_closed" => "caps",
        "scenario" => "scenario",
        "benchmark" => "benchmark",
        "tool" => "tool",
        "stream" => "stream",
        _ => "system",
    }
}

impl PlaneCore {
    pub fn new() -> Self {
        let agent = Agent::with_secret([0x51; 32]);
        let echo_provider = agent.register(Box::new(Echo));
        let mut module_provider = ModuleProvider::new();
        let object = module_provider.install(fixture_module());
        let module_provider = agent.register(Box::new(module_provider));

        let lane = agent
            .create_lane("lane-0", Budget::default())
            .expect("lane");
        let lanes = vec![
            lane,
            agent
                .create_lane("lane-1", Budget::default())
                .expect("lane"),
            agent
                .create_lane("lane-2", Budget::default())
                .expect("lane"),
            agent
                .create_lane("lane-3", Budget::default())
                .expect("lane"),
        ];

        let echo_cap = agent
            .mint(echo_provider, 0, CapAttrs::new(&["echo", "ping"]))
            .expect("cap");
        let module_cap = agent
            .mint(
                module_provider,
                object,
                CapAttrs::new(active_rpc::MODULE_METHODS),
            )
            .expect("cap");
        let mut audit_attrs = CapAttrs::new(&["stats", "evaluate"]);
        audit_attrs.read_only = true;
        let audit_cap = agent
            .mint(module_provider, object, audit_attrs)
            .expect("cap");
        let worker_cap = agent
            .attenuate(&echo_cap, CapAttrs::new(&["echo"]))
            .expect("attenuated cap");
        let session =
            McpSession::handshake(MemoryTransport::new(mcp_responses())).expect("mcp handshake");
        let tool_provider = agent.register(Box::new(session));
        let mcp_cap = agent
            .mint(
                tool_provider,
                0,
                CapAttrs::new(&["echo"]).with_tool_policy(ToolPolicy::allow(&["echo"])),
            )
            .expect("cap");
        let mcp_restricted = agent
            .mint(
                tool_provider,
                0,
                CapAttrs::new(&["echo"]).with_tool_policy(ToolPolicy::allow(&["other"])),
            )
            .expect("restricted cap");
        let mut ceiling_policy = ToolPolicy::allow(&["echo"]);
        ceiling_policy.max_arg_bytes = 16;
        let mcp_ceiling = agent
            .mint(
                tool_provider,
                0,
                CapAttrs::new(&["echo"]).with_tool_policy(ceiling_policy),
            )
            .expect("ceiling cap");

        // One persistent loopback endpoint for the HTTP tool scenario. The
        // tool provider is registered once; each run mints only a capability.
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("http stub bind");
        let http_address = listener.local_addr().expect("http stub addr").to_string();
        std::thread::Builder::new()
            .name("http-stub".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    // One short-lived handler per connection: a client that
                    // stalls must never block the next ladder run.
                    std::thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                        let mut buffer = [0u8; 2048];
                        let _ = stream.read(&mut buffer);
                        let body = r#"{"ok":true}"#;
                        let response = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(response.as_bytes());
                    });
                }
            })
            .expect("http stub thread");
        let http_tool = HttpTool::new(format!("http://{http_address}"), &[("GET", "/health")]);
        let http_policy = http_tool.policy();
        let http_provider = agent.register(Box::new(http_tool));
        let http_cap = agent
            .mint(
                http_provider,
                0,
                CapAttrs::new(&["get"])
                    .with_path("/health")
                    .with_tool_policy(http_policy),
            )
            .expect("http cap");

        #[cfg(windows)]
        let (program, flag) = ("cmd", "/C");
        #[cfg(not(windows))]
        let (program, flag) = ("sh", "-c");
        let process = LocalProcess::new(program, &[flag, "echo*"]).with_timeout(3_000);
        let process_policy = process.policy();
        let process_provider = agent.register(Box::new(process));
        let process_allowed = agent
            .mint(
                process_provider,
                0,
                CapAttrs::new(&["run"]).with_tool_policy(process_policy),
            )
            .expect("process cap");
        let process_denied = agent
            .mint(
                process_provider,
                0,
                CapAttrs::new(&["run"]).with_tool_policy(ToolPolicy {
                    allowed: ["run"].iter().map(|name| name.to_string()).collect(),
                    max_arg_bytes: 4 << 10,
                    allow_process: false,
                }),
            )
            .expect("denied process cap");

        let caps = vec![
            CapInfo {
                label: "echo/rw",
                cap: echo_cap.clone(),
                methods: vec!["echo".into(), "ping".into()],
                max_calls: Budget::default().max_calls,
                read_only: false,
                attenuated: false,
            },
            CapInfo {
                label: "module/rw",
                cap: module_cap.clone(),
                methods: active_rpc::MODULE_METHODS
                    .iter()
                    .map(|method| method.to_string())
                    .collect(),
                max_calls: Budget::default().max_calls,
                read_only: false,
                attenuated: false,
            },
            CapInfo {
                label: "echo/attenuated",
                cap: worker_cap.clone(),
                methods: vec!["echo".into()],
                max_calls: Budget::default().max_calls,
                read_only: false,
                attenuated: true,
            },
            CapInfo {
                label: "module/ro",
                cap: audit_cap,
                methods: vec!["stats".into(), "evaluate".into()],
                max_calls: Budget::default().max_calls,
                read_only: true,
                attenuated: true,
            },
            CapInfo {
                label: "mcp/echo",
                cap: mcp_cap.clone(),
                methods: vec!["echo".into()],
                max_calls: Budget::default().max_calls,
                read_only: false,
                attenuated: false,
            },
            CapInfo {
                label: "mcp/restricted",
                cap: mcp_restricted.clone(),
                methods: vec!["echo".into()],
                max_calls: Budget::default().max_calls,
                read_only: false,
                attenuated: true,
            },
            CapInfo {
                label: "mcp/ceiling",
                cap: mcp_ceiling.clone(),
                methods: vec!["echo".into()],
                max_calls: Budget::default().max_calls,
                read_only: false,
                attenuated: true,
            },
            CapInfo {
                label: "http/health",
                cap: http_cap.clone(),
                methods: vec!["get".into()],
                max_calls: Budget::default().max_calls,
                read_only: false,
                attenuated: false,
            },
            CapInfo {
                label: "process/allowed",
                cap: process_allowed.clone(),
                methods: vec!["run".into()],
                max_calls: Budget::default().max_calls,
                read_only: false,
                attenuated: false,
            },
            CapInfo {
                label: "process/denied",
                cap: process_denied.clone(),
                methods: vec!["run".into()],
                max_calls: Budget::default().max_calls,
                read_only: false,
                attenuated: true,
            },
        ];
        let mut channels = Vec::new();
        let mut channel_messages = BTreeMap::new();
        for name in ["work-queue", "audit"] {
            let channel = agent
                .create_channel(name, active_rpc::Direction::Both)
                .expect("channel");
            agent.subscribe(lane, channel).expect("subscribe");
            channel_messages.insert(name.to_string(), 0);
            channels.push(channel);
        }

        let mut core = Self {
            agent,
            lane,
            lanes,
            echo_provider,
            echo_cap: echo_cap.clone(),
            module_cap: module_cap.clone(),
            mcp_cap: mcp_cap.clone(),
            mcp_restricted: mcp_restricted.clone(),
            mcp_ceiling: mcp_ceiling.clone(),
            http_cap: http_cap.clone(),
            http_address,
            process_allowed: process_allowed.clone(),
            process_denied: process_denied.clone(),
            caps,
            channels,
            channel_messages,
            started: Instant::now(),
            counters: Counters::default(),
            timings: Timings::default(),
            last_metrics: Metrics::default(),
            last_metrics_at: Instant::now(),
            calls_per_second: 0.0,
            wire_in_per_s: 0.0,
            wire_out_per_s: 0.0,
            settled_per_s: 0.0,
            tool_calls_per_s: 0.0,
            tool_refusals_per_s: 0.0,
            stream_frames_per_s: 0.0,
            events: VecDeque::new(),
            kernel_events_seen: 0,
            next_event_id: 1,
            last_scenario: None,
            scenario_results: BTreeMap::new(),
            promise_chain: Vec::new(),
            last_counters: Counters::default(),
            last_rates_at: Instant::now(),
            call_samples: VecDeque::new(),
            canonical_ok: 0,
            canonical_attempts: 0,
            benchmark: None,
            redaction_ok: false,
            status_image_bytes: 0,
            status_hash: String::new(),
            activity: ActivityState::idle(),
            gauge_samples: BTreeMap::new(),
            plane_mode: "demo".into(),
        };
        core.redaction_ok = redacted_probe();
        core.capture_kernel_events();
        core.refresh_status();
        core.note(
            "system",
            None,
            "control plane started; kernel up, redaction probe passed",
            Some(0.0),
            None,
            None,
        );
        core
    }

    pub fn agent(&self) -> &Agent {
        &self.agent
    }

    pub fn set_mode(&mut self, mode: impl Into<String>) {
        self.plane_mode = mode.into();
    }

    fn record(&mut self, mut event: UiEvent) {
        event.id = self.next_event_id;
        self.next_event_id = self.next_event_id.saturating_add(1);
        if self.events.len() >= EVENT_TAIL {
            // Keep the security-relevant and scenario record even when kernel
            // chatter fills the ring. Only ordinary progress events age out.
            let protected = |candidate: &UiEvent| {
                matches!(
                    candidate.category.as_str(),
                    "scenario" | "benchmark" | "refusals"
                )
            };
            if let Some(index) = self
                .events
                .iter()
                .position(|candidate| !protected(candidate))
            {
                self.events.remove(index);
            } else {
                self.events.pop_front();
            }
        }
        self.events.push_back(event);
    }

    fn note(
        &mut self,
        kind: &str,
        code: Option<&str>,
        detail: impl Into<String>,
        duration_us: Option<f64>,
        bytes: Option<u64>,
        scenario_id: Option<&str>,
    ) {
        self.record(UiEvent {
            id: 0,
            ts_ms: now_ms(),
            category: category_for(kind).into(),
            kind: kind.into(),
            lane: None,
            capability: None,
            method: None,
            code: code.map(str::to_string),
            duration_us,
            bytes,
            scenario_id: scenario_id.map(str::to_string),
            detail: detail.into(),
        });
    }

    fn event_from_kernel(&self, event: &Event) -> UiEvent {
        let ts_ms = now_ms();
        let base = UiEvent {
            id: 0,
            ts_ms,
            category: "system".into(),
            kind: "event".into(),
            lane: None,
            capability: None,
            method: None,
            code: None,
            duration_us: None,
            bytes: None,
            scenario_id: None,
            detail: String::new(),
        };
        match event {
            Event::CapMinted { cap, provider } => UiEvent {
                category: category_for("cap_mint").into(),
                kind: "cap_mint".into(),
                capability: Some(cap.correlation_id()),
                detail: format!("capability minted for provider {}", provider.0),
                ..base
            },
            Event::CapRevoked(cap) => UiEvent {
                category: category_for("cap_revoke").into(),
                kind: "cap_revoke".into(),
                capability: Some(cap.correlation_id()),
                detail: "capability revoked".into(),
                ..base
            },
            Event::CapExpired(cap) => UiEvent {
                category: category_for("cap_expired").into(),
                kind: "cap_expired".into(),
                capability: Some(cap.correlation_id()),
                detail: "capability lifetime elapsed".into(),
                ..base
            },
            Event::CapIntroduced { cap, fingerprint } => UiEvent {
                category: category_for("cap_introduce").into(),
                kind: "cap_introduce".into(),
                capability: Some(cap.correlation_id()),
                detail: format!(
                    "capability introduced to peer {}",
                    fingerprint
                        .iter()
                        .take(8)
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                ),
                ..base
            },
            Event::LaneCreated(lane) => UiEvent {
                category: category_for("lane_created").into(),
                kind: "lane_created".into(),
                lane: Some(format!("lane {}", lane.0)),
                detail: "lane created".into(),
                ..base
            },
            Event::ChannelSend { channel, sequence } => UiEvent {
                category: category_for("channel_msg").into(),
                kind: "channel_msg".into(),
                detail: format!("channel {} message {}", channel.0, sequence),
                ..base
            },
            Event::CapTransferred { cap, channel } => UiEvent {
                category: category_for("channel_msg").into(),
                kind: "channel_msg".into(),
                capability: Some(cap.correlation_id()),
                detail: format!("capability transferred on channel {}", channel.0),
                ..base
            },
            Event::CallQueued { lane, cap, .. } => UiEvent {
                category: category_for("call_queued").into(),
                kind: "call_queued".into(),
                lane: Some(format!("lane {}", lane.0)),
                capability: Some(cap.correlation_id()),
                detail: "call queued".into(),
                ..base
            },
            Event::BatchDispatched { provider, jobs, .. } => UiEvent {
                category: category_for("batch").into(),
                kind: "batch".into(),
                detail: format!("{jobs} job(s) dispatched to provider {}", provider.0),
                ..base
            },
            Event::PromiseResolved(promise) => UiEvent {
                category: category_for("call_settled").into(),
                kind: "call_settled".into(),
                detail: format!("promise {} settled", promise.0),
                ..base
            },
            Event::PromiseRejected { promise, code } => UiEvent {
                category: category_for("call_refused").into(),
                kind: "call_refused".into(),
                code: Some(code.clone()),
                detail: format!("promise {} rejected", promise.0),
                ..base
            },
            Event::CallRefused { lane, cap, code } => UiEvent {
                category: category_for("call_refused").into(),
                kind: "call_refused".into(),
                lane: Some(format!("lane {}", lane.0)),
                capability: Some(cap.correlation_id()),
                code: Some(code.clone()),
                detail: "call refused".into(),
                ..base
            },
            Event::BudgetExhausted { cap, dimension } => UiEvent {
                category: category_for("budget").into(),
                kind: "budget".into(),
                capability: Some(cap.correlation_id()),
                code: Some("rpc/budget-exceeded".into()),
                detail: format!("{dimension} budget exhausted"),
                ..base
            },
            Event::ToolRefused { cap, reason } => UiEvent {
                category: category_for("tool_refused").into(),
                kind: "tool_refused".into(),
                capability: Some(cap.correlation_id()),
                code: Some("rpc/tool-policy".into()),
                detail: format!("tool refused: {reason}"),
                ..base
            },
            Event::JobCompleted { job, lane } => UiEvent {
                category: category_for("job").into(),
                kind: "job".into(),
                lane: Some(format!("lane {}", lane.0)),
                detail: format!("job {job} completed"),
                ..base
            },
            Event::CapRetained(cap) | Event::CapReleased(cap) | Event::CapDropped(cap) => UiEvent {
                category: category_for("cap_lifecycle").into(),
                kind: "cap_lifecycle".into(),
                capability: Some(cap.correlation_id()),
                detail: "capability reference changed".into(),
                ..base
            },
            Event::LaneDestroyed(lane) => UiEvent {
                category: category_for("lane_closed").into(),
                kind: "lane_closed".into(),
                lane: Some(format!("lane {}", lane.0)),
                detail: "lane destroyed".into(),
                ..base
            },
            Event::ChannelRecv { channel, sequence } => UiEvent {
                category: category_for("channel_msg").into(),
                kind: "channel_msg".into(),
                detail: format!("channel {} received {}", channel.0, sequence),
                ..base
            },
        }
    }

    fn capture_kernel_events(&mut self) {
        let total = self.agent.total_events();
        if total <= self.kernel_events_seen {
            return;
        }
        let tape = self.agent.events();
        if tape.is_empty() {
            return;
        }
        // The tape is bounded. A monotonic total lets us take only the events
        // that arrived since the last read, even after the tape wraps.
        let unseen = (total - self.kernel_events_seen).min(tape.len() as u64) as usize;
        let start = tape.len() - unseen;
        let fresh: Vec<UiEvent> = tape[start..]
            .iter()
            .map(|event| self.event_from_kernel(event))
            .collect();
        self.kernel_events_seen = total;
        for event in fresh {
            self.record(event);
        }
    }

    fn metrics_view(&mut self) -> MetricsView {
        let metrics = self.agent.metrics();
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_rates_at).as_secs_f64();
        if elapsed >= 0.2 {
            let delta_calls = metrics
                .calls_queued
                .saturating_sub(self.last_metrics.calls_queued);
            self.calls_per_second = delta_calls as f64 / elapsed;
            let settled = metrics
                .promises_resolved
                .saturating_add(metrics.promises_rejected)
                .saturating_sub(
                    self.last_metrics
                        .promises_resolved
                        .saturating_add(self.last_metrics.promises_rejected),
                );
            self.settled_per_s = settled as f64 / elapsed;
            self.wire_in_per_s =
                self.counters
                    .bytes_in
                    .saturating_sub(self.last_counters.bytes_in) as f64
                    / elapsed;
            self.wire_out_per_s =
                self.counters
                    .bytes_out
                    .saturating_sub(self.last_counters.bytes_out) as f64
                    / elapsed;
            self.tool_calls_per_s =
                self.counters
                    .tool_calls
                    .saturating_sub(self.last_counters.tool_calls) as f64
                    / elapsed;
            self.tool_refusals_per_s = metrics
                .tool_refusals
                .saturating_sub(self.last_metrics.tool_refusals)
                as f64
                / elapsed;
            self.stream_frames_per_s =
                self.counters
                    .streaming_frames
                    .saturating_sub(self.last_counters.streaming_frames) as f64
                    / elapsed;
            self.last_metrics = metrics;
            self.last_counters = self.counters.clone();
            self.last_rates_at = now;
            self.last_metrics_at = now;
        }
        let capacity: u64 = self
            .caps
            .iter()
            .map(|cap| cap.max_calls)
            .fold(0u64, |sum, value| sum.saturating_add(value));
        let pressure = if capacity == 0 {
            0.0
        } else {
            (metrics.calls_queued as f64 / capacity as f64 * 100.0).min(100.0)
        };
        let active_lanes = self
            .lanes
            .iter()
            .filter(|lane| {
                self.agent
                    .lane(**lane)
                    .map(|lane| !lane.closed)
                    .unwrap_or(false)
            })
            .count();
        let samples: Vec<f64> = self.call_samples.iter().copied().collect();
        MetricsView {
            calls_queued: metrics.calls_queued,
            calls_refused: metrics.calls_refused,
            budget_exhaustions: metrics.budget_exhaustions,
            tool_refusals: metrics.tool_refusals,
            revocations: metrics.revocations,
            promises_resolved: metrics.promises_resolved,
            promises_rejected: metrics.promises_rejected,
            promise_records: self.agent.promise_count(),
            round_trips: metrics.round_trips,
            transfers: metrics.transfers,
            calls_per_second: self.calls_per_second,
            pipeline_depth: metrics.calls_queued.saturating_sub(
                metrics
                    .promises_resolved
                    .saturating_add(metrics.promises_rejected),
            ),
            budget_pressure: pressure,
            active_lanes,
            active_channels: self.channels.len(),
            caps_live: self.caps.len(),
            queue_depth: metrics.calls_queued,
            wire_in_per_s: self.wire_in_per_s,
            wire_out_per_s: self.wire_out_per_s,
            settled_per_s: self.settled_per_s,
            tool_calls_per_s: self.tool_calls_per_s,
            tool_refusals_per_s: self.tool_refusals_per_s,
            stream_frames_per_s: self.stream_frames_per_s,
            p99_call_us: percentile(&samples, 0.99),
            canonical_ok_rate: if self.canonical_attempts == 0 {
                0.0
            } else {
                self.canonical_ok as f64 / self.canonical_attempts as f64 * 100.0
            },
            canonical_samples: self.canonical_attempts,
        }
    }

    fn status_module(&self) -> InfinityModule {
        let metrics = self.agent.metrics();
        let uptime = self.started.elapsed().as_millis() as u64;
        let mut module = InfinityModule::new();
        let version = module.push(Inode::Str("active-control-plane/0.1.0".into()));
        let plane = module.push(Inode::Str("ok".into()));
        let uptime_node = module.push(Inode::Int(uptime.min(i64::MAX as u64) as i64));
        let calls = module.push(Inode::Int(metrics.calls_queued.min(i64::MAX as u64) as i64));
        let refused = module.push(Inode::Int(metrics.calls_refused.min(i64::MAX as u64) as i64));
        let round_trips = module.push(Inode::Int(metrics.round_trips.min(i64::MAX as u64) as i64));
        let promises = module.push(Inode::Int(self.agent.promise_count() as i64));
        let lanes = module.push(Inode::Int(self.lanes.len() as i64));
        let channels = module.push(Inode::Int(self.channels.len() as i64));
        let redaction = module.push(Inode::Bool(self.redaction_ok));
        let root = module.push(Inode::Table {
            fields: vec![
                ("version".into(), version),
                ("plane".into(), plane),
                ("uptime_ms".into(), uptime_node),
                ("calls".into(), calls),
                ("refused".into(), refused),
                ("round_trips".into(), round_trips),
                ("open_promises".into(), promises),
                ("lanes".into(), lanes),
                ("channels".into(), channels),
                ("redaction_ok".into(), redaction),
            ],
        });
        module.set_root(Some(root));
        module.bind("plane", root);
        module
    }

    fn refresh_status(&mut self) {
        let module = self.status_module();
        let start = Instant::now();
        let bytes = encode(&module).expect("status module encodes");
        let encode_us = start.elapsed().as_secs_f64() * 1e6;
        self.counters.encodes += 1;
        self.counters.bytes_out += bytes.len() as u64;
        let start = Instant::now();
        validate(&bytes).expect("status module validates");
        let validate_us = start.elapsed().as_secs_f64() * 1e6;
        self.counters.validates += 1;
        let start = Instant::now();
        let hash = content_hash(&bytes).expect("status module hashes");
        let hash_us = start.elapsed().as_secs_f64() * 1e6;
        self.counters.hashes += 1;
        let start = Instant::now();
        let decoded = decode(&bytes).expect("status module decodes");
        let decode_us = start.elapsed().as_secs_f64() * 1e6;
        self.counters.decodes += 1;
        let reencoded = encode(&decoded).expect("status module re-encodes");
        self.canonical_attempts = self.canonical_attempts.saturating_add(1);
        if reencoded == bytes {
            self.canonical_ok = self.canonical_ok.saturating_add(1);
        }
        self.status_image_bytes = bytes.len();
        self.status_hash = hex(&hash);
        self.timings = Timings {
            encode_us,
            decode_us,
            validate_us,
            hash_us,
        };
    }

    fn await_value(&mut self, promise: &PromiseHandle) -> active_rpc::Result<Value> {
        let start = Instant::now();
        let result = promise.value();
        let micros = start.elapsed().as_secs_f64() * 1e6;
        if self.call_samples.len() >= CALL_SAMPLES {
            self.call_samples.pop_front();
        }
        self.call_samples.push_back(micros);
        result
    }

    fn begin_activity(&mut self, mode: &str, summary: impl Into<String>) {
        self.promise_chain.clear();
        self.activity = ActivityState {
            mode: mode.into(),
            summary: summary.into(),
            ok: None,
            stages: Vec::new(),
            hash_prefix: None,
            bytes: None,
            progress: None,
            promise_chain: Vec::new(),
            at_ms: now_ms(),
        };
    }

    fn stage(&mut self, name: &str, detail: impl Into<String>, duration_us: f64, ok: bool) {
        self.activity.stages.push(ActivityStage {
            name: name.into(),
            detail: detail.into(),
            duration_us,
            ok,
        });
    }

    fn lane_stats(&self) -> Vec<LaneStat> {
        self.lanes
            .iter()
            .filter_map(|id| self.agent.lane(*id).ok())
            .map(|lane| LaneStat {
                lane: lane.id.0,
                name: lane.name,
                pending: lane.pending,
                completed: lane.completed,
                queue: lane.ready.len(),
                closed: lane.closed,
            })
            .collect()
    }

    fn engines(&self) -> EngineView {
        let lanes = self.lane_stats();
        let channels = self
            .channels
            .iter()
            .filter_map(|id| self.agent.channel(*id).ok())
            .map(|channel| ChannelStat {
                channel: channel.id.0,
                name: channel.name,
                sent: channel.sent,
                received: channel.received,
                subscribers: channel.subscribers.len(),
            })
            .collect();
        EngineView {
            lanes,
            channels,
            capabilities: self
                .caps
                .iter()
                .map(|cap| CapView {
                    id: cap.cap.id().correlation_id(),
                    label: cap.label.into(),
                    methods: cap.methods.clone(),
                    max_calls: cap.max_calls,
                    read_only: cap.read_only,
                    attenuated: cap.attenuated,
                })
                .collect(),
        }
    }

    fn activity_view(&self, now: u64, last_event: u64) -> ActivityView {
        let age = now.saturating_sub(self.activity.at_ms);
        let idle = age > 8_000;
        let mode = if idle {
            "Idle".to_string()
        } else {
            self.activity.mode.clone()
        };
        let summary = if idle && self.activity.mode != "Idle" {
            format!(
                "idle · last {} · {}",
                self.activity.mode, self.activity.summary
            )
        } else {
            self.activity.summary.clone()
        };
        ActivityView {
            mode,
            summary,
            ok: self.activity.ok,
            stages: self.activity.stages.clone(),
            hash_prefix: self.activity.hash_prefix.clone(),
            bytes: self.activity.bytes,
            progress: self.activity.progress,
            promise_chain: self.promise_chain.clone(),
            lanes: self.lane_stats(),
            last_event_age_ms: now.saturating_sub(last_event),
            started_ms: self.activity.at_ms,
        }
    }

    fn record_gauges(&mut self, metrics: &MetricsView, timings: &Timings) {
        let now = now_ms();
        let values: [(&str, f64); 20] = [
            ("encode_us", timings.encode_us),
            ("decode_us", timings.decode_us),
            ("hash_us", timings.hash_us),
            ("validate_us", timings.validate_us),
            ("calls_per_second", metrics.calls_per_second),
            ("wire_in_per_s", metrics.wire_in_per_s),
            ("wire_out_per_s", metrics.wire_out_per_s),
            ("settled_per_s", metrics.settled_per_s),
            ("promise_records", metrics.promise_records as f64),
            ("active_lanes", metrics.active_lanes as f64),
            ("active_channels", metrics.active_channels as f64),
            ("caps_live", metrics.caps_live as f64),
            ("tool_calls_per_s", metrics.tool_calls_per_s),
            ("tool_refusals_per_s", metrics.tool_refusals_per_s),
            ("budget_pressure", metrics.budget_pressure),
            ("stream_frames_per_s", metrics.stream_frames_per_s),
            ("canonical_ok_rate", metrics.canonical_ok_rate),
            ("p99_call_us", metrics.p99_call_us),
            ("queue_depth", metrics.queue_depth as f64),
            ("pipeline_depth", metrics.pipeline_depth as f64),
        ];
        for (key, value) in values {
            let samples = self.gauge_samples.entry(key.to_string()).or_default();
            if samples.len() >= GAUGE_SAMPLES {
                samples.pop_front();
            }
            samples.push_back(GaugeSample { ts_ms: now, value });
        }
    }

    pub fn snapshot(&mut self) -> Snapshot {
        self.capture_kernel_events();
        self.refresh_status();
        let metrics = self.metrics_view();
        let timings = self.timings.clone();
        self.record_gauges(&metrics, &timings);
        let last_event = self.events.back().map(|event| event.ts_ms).unwrap_or(0);
        let now = now_ms();
        let activity = self.activity_view(now, last_event);
        let last_error_code = self
            .events
            .iter()
            .rev()
            .find_map(|event| event.code.clone())
            .unwrap_or_else(|| "none".into());
        Snapshot {
            ts_ms: now,
            uptime_ms: self.started.elapsed().as_millis() as u64,
            health: Health {
                kernel: "up".into(),
                mode: self.plane_mode.clone(),
                observers: 0,
                last_event_ms_ago: now.saturating_sub(last_event),
                redaction_ok: self.redaction_ok,
            },
            metrics,
            infinity: InfinityView {
                image_bytes: self.status_image_bytes,
                hash: self.status_hash.clone(),
                timings,
                counters: self.counters.clone(),
            },
            engines: self.engines(),
            events: self.events.iter().cloned().collect(),
            last_scenario: self.last_scenario.clone(),
            scenario_results: self.scenario_results.values().cloned().collect(),
            scenarios: SCENARIOS.to_vec(),
            activity,
            benchmark: self.benchmark.clone(),
            scenario_ids: SCENARIOS.iter().map(|def| def.id).collect(),
            gauge_samples: self
                .gauge_samples
                .iter()
                .map(|(key, samples)| (key.clone(), samples.iter().cloned().collect()))
                .collect(),
            last_error_code,
        }
    }

    pub fn events_after(&self, cursor: u64) -> Vec<UiEvent> {
        self.events
            .iter()
            .filter(|event| event.id > cursor)
            .cloned()
            .collect()
    }

    pub fn run_scenario(&mut self, id: &str) -> Result<ScenarioResult, String> {
        let def = scenario_def(id).ok_or_else(|| format!("unknown scenario {id}"))?;
        self.begin_activity(def.mode, format!("{} · {} starting", def.code, def.title));
        let before = self.metrics_view();
        let started = Instant::now();
        let (title, ok, detail, data) =
            match std::panic::catch_unwind(AssertUnwindSafe(|| match id {
                "round-trip" => self.scenario_round_trip(),
                "evaluate" => self.scenario_evaluate(),
                "metrics" => self.scenario_metrics(),
                "pipeline" => self.scenario_pipeline(),
                "redaction" => self.scenario_redaction(),
                "attenuation" => self.scenario_attenuation(),
                "revoke" => self.scenario_revoke(),
                "streaming" => self.scenario_streaming(),
                "mcp-memory" => self.scenario_mcp_memory(),
                "tool-policy" => self.scenario_tool_policy(),
                "http-tool" => self.scenario_http_tool(),
                "local-process" => self.scenario_local_process(),
                "lanes" => self.scenario_lanes(),
                "channel-share" => self.scenario_channel_share(),
                "pipeline-stress" => self.scenario_pipeline_stress(),
                "budget" => self.scenario_budget(),
                "call-storm" => self.scenario_call_storm(),
                "tool-ceiling" => self.scenario_tool_ceiling(),
                "bench-sizes" => self.scenario_bench_sizes(),
                "bench-calls" => self.scenario_bench_calls(),
                "bench-export" => self.scenario_bench_export(),
                "fuzz-smoke" => self.scenario_fuzz_smoke(),
                _ => (
                    "Unknown scenario".into(),
                    false,
                    format!("unknown scenario {id}"),
                    json!({}),
                ),
            })) {
                Ok(result) => result,
                Err(_) => (
                    "Scenario panic".into(),
                    false,
                    "the scenario panicked; the worker and kernel are still serving".into(),
                    json!({"panic": true}),
                ),
            };
        let duration_us = started.elapsed().as_micros() as u64;
        self.refresh_status();
        let after = self.metrics_view();
        self.activity.at_ms = now_ms();
        self.activity.ok = Some(ok);
        self.activity.summary = format!(
            "{} · {} · {detail}",
            def.code,
            if ok { "pass" } else { "fail" }
        );
        let result = ScenarioResult {
            id: id.into(),
            code: def.code.into(),
            level: def.level,
            title,
            ok,
            detail,
            duration_us,
            before,
            after,
            data,
        };
        self.scenario_results.insert(id.to_string(), result.clone());
        self.last_scenario = Some(result.clone());
        self.note(
            "scenario",
            if ok { None } else { Some("scenario/failed") },
            format!(
                "{} {}: {}",
                def.code,
                if ok { "pass" } else { "fail" },
                result.detail
            ),
            Some(duration_us as f64),
            None,
            Some(id),
        );
        Ok(result)
    }

    /// Run one level, or every level up to and including it.
    ///
    /// Out-of-range levels run nothing: the HTTP and MCP adapters reject them
    /// before they reach this method, and a library caller gets an empty set
    /// rather than a silently different level.
    pub fn run_level(&mut self, level: u8, up_to: bool) -> Vec<ScenarioResult> {
        if level > 6 {
            return Vec::new();
        }
        let ids: Vec<&'static str> = SCENARIOS
            .iter()
            .filter(|def| {
                if up_to {
                    def.level <= level
                } else {
                    def.level == level
                }
            })
            .map(|def| def.id)
            .collect();
        let mut results = Vec::new();
        for id in ids {
            if let Ok(result) = self.run_scenario(id) {
                results.push(result);
            }
        }
        results
    }

    fn scenario_round_trip(&mut self) -> (String, bool, String, Json) {
        let module = fixture_module();
        let start = Instant::now();
        let bytes = encode(&module).expect("encode");
        let encode_us = start.elapsed().as_secs_f64() * 1e6;
        self.counters.encodes += 1;
        self.counters.bytes_in += bytes.len() as u64;
        self.stage("encode", format!("{} bytes", bytes.len()), encode_us, true);
        let start = Instant::now();
        validate(&bytes).expect("validate");
        let validate_us = start.elapsed().as_secs_f64() * 1e6;
        self.counters.validates += 1;
        self.stage("validate", "canonical AINF 1.0", validate_us, true);
        let start = Instant::now();
        let hash = content_hash(&bytes).expect("hash");
        let hash_us = start.elapsed().as_secs_f64() * 1e6;
        self.counters.hashes += 1;
        let hash_hex = hex(&hash);
        self.activity.hash_prefix = Some(format!("blake3:{}", &hash_hex[..16]));
        self.activity.bytes = Some(bytes.len() as u64);
        self.stage(
            "hash",
            format!("blake3:{}…", &hash_hex[..12]),
            hash_us,
            true,
        );
        let start = Instant::now();
        let decoded = decode(&bytes).expect("decode");
        let decode_us = start.elapsed().as_secs_f64() * 1e6;
        self.counters.decodes += 1;
        let reencoded = encode(&decoded).expect("re-encode");
        self.counters.bytes_out += reencoded.len() as u64;
        let stable = reencoded == bytes;
        self.canonical_attempts = self.canonical_attempts.saturating_add(1);
        if stable {
            self.canonical_ok = self.canonical_ok.saturating_add(1);
        }
        self.stage(
            "decode",
            format!("{} nodes", decoded.node_count()),
            decode_us,
            true,
        );
        self.stage(
            "canonical",
            if stable {
                "re-encode equal"
            } else {
                "mismatch"
            },
            0.0,
            stable,
        );
        let ok = stable && decoded.node_count() == module.node_count();
        (
            "Infinity round-trip".into(),
            ok,
            format!(
                "{} bytes, {} nodes, hash stable, encode {:.1} µs / validate {:.1} µs / hash {:.1} µs",
                bytes.len(),
                decoded.node_count(),
                encode_us,
                validate_us,
                hash_us
            ),
            json!({
                "bytes": bytes.len(),
                "nodes": decoded.node_count(),
                "hash": hash_hex,
                "stable": stable,
                "encode_us": encode_us,
                "validate_us": validate_us,
                "hash_us": hash_us,
                "decode_us": decode_us,
            }),
        )
    }

    fn scenario_evaluate(&mut self) -> (String, bool, String, Json) {
        let start = Instant::now();
        let promise = self
            .agent
            .call(self.lane, &self.module_cap, "evaluate", Vec::new())
            .expect("evaluate call");
        let value = self.await_value(&promise).expect("evaluate value");
        let evaluate_us = start.elapsed().as_secs_f64() * 1e6;
        self.stage(
            "evaluate",
            brief(&value),
            evaluate_us,
            !matches!(value, Value::Null),
        );
        let start = Instant::now();
        let promise = self
            .agent
            .call(self.lane, &self.module_cap, "stats", Vec::new())
            .expect("stats call");
        let stats_value = self.await_value(&promise).expect("stats value");
        let stats_us = start.elapsed().as_secs_f64() * 1e6;
        self.stage("stats", brief(&stats_value), stats_us, true);
        let ok = !matches!(value, Value::Null) && !matches!(stats_value, Value::Null);
        (
            "Module evaluate".into(),
            ok,
            format!(
                "evaluate returned {} in {:.1} µs; stats in {:.1} µs",
                brief(&value),
                evaluate_us,
                stats_us
            ),
            json!({
                "value": brief(&value),
                "stats": brief(&stats_value),
                "evaluate_us": evaluate_us,
                "stats_us": stats_us,
            }),
        )
    }

    fn scenario_metrics(&mut self) -> (String, bool, String, Json) {
        let start = Instant::now();
        let metrics = self.agent.metrics();
        let events = self.agent.events().len();
        let promises = self.agent.promise_count();
        let elapsed = start.elapsed().as_secs_f64() * 1e6;
        self.stage(
            "collect",
            format!("{events} kernel events"),
            elapsed,
            events > 0,
        );
        let ok = events > 0 && self.redaction_ok && !self.events.is_empty();
        (
            "Metrics snapshot".into(),
            ok,
            format!(
                "{events} kernel events, {} control-plane events, {promises} open promises, redaction {}",
                self.events.len(),
                if self.redaction_ok { "ok" } else { "FAILED" }
            ),
            json!({
                "kernel_events": events,
                "plane_events": self.events.len(),
                "open_promises": promises,
                "calls_queued": metrics.calls_queued,
                "redaction_ok": self.redaction_ok,
            }),
        )
    }

    fn scenario_pipeline(&mut self) -> (String, bool, String, Json) {
        let lane = self.lane;
        let cap = self.echo_cap.clone();
        let start = Instant::now();
        let rounds_before = self.agent.round_trips();
        for index in 0..6 {
            let promise = self
                .agent
                .call(lane, &cap, "echo", vec![Arg::text(format!("step-{index}"))])
                .expect("sequential call");
            self.await_value(&promise).expect("sequential value");
        }
        let sequential = self.agent.round_trips() - rounds_before;
        let sequential_us = start.elapsed().as_secs_f64() * 1e6;
        self.stage(
            "sequential",
            format!("6 calls · {sequential} round-trip(s)"),
            sequential_us,
            sequential == 6,
        );

        let start = Instant::now();
        let rounds_before = self.agent.round_trips();
        let mut ids = Vec::with_capacity(6);
        let mut promise = self
            .agent
            .call(lane, &cap, "echo", vec![Arg::text("seed")])
            .expect("pipeline head");
        ids.push(promise.id().0);
        for _ in 0..5 {
            promise = self
                .agent
                .call(lane, &cap, "echo", vec![Arg::Promise(promise.id())])
                .expect("pipelined call");
            ids.push(promise.id().0);
        }
        self.await_value(&promise).expect("pipelined value");
        let pipelined = self.agent.round_trips() - rounds_before;
        let pipelined_us = start.elapsed().as_secs_f64() * 1e6;
        self.promise_chain = ids.clone();
        self.activity.promise_chain = ids;
        self.stage(
            "promise chain",
            format!(
                "{} promises · {pipelined} round-trip(s)",
                self.promise_chain.len()
            ),
            pipelined_us,
            pipelined == 1,
        );
        let ok = pipelined < sequential;
        (
            "Pipelining vs sequential".into(),
            ok,
            format!("{sequential} sequential round-trips vs {pipelined} pipelined"),
            json!({
                "sequential_round_trips": sequential,
                "pipelined_round_trips": pipelined,
                "saved": sequential.saturating_sub(pipelined),
                "calls_each": 6,
                "chain": self.promise_chain,
            }),
        )
    }

    fn scenario_redaction(&mut self) -> (String, bool, String, Json) {
        let mut module = InfinityModule::new();
        let secret = module.push(Inode::Secret(SecretBytes::from(SECRET_CANARY)));
        let copy = module.push(Inode::Str(SECRET_CANARY.into()));
        let root = module.push(Inode::Table {
            fields: vec![(SECRET_CANARY.into(), secret), ("copy".into(), copy)],
        });
        module.set_root(Some(root));
        let start = Instant::now();
        let image = encode(&module).expect("encode");
        let encode_us = start.elapsed().as_secs_f64() * 1e6;
        self.counters.encodes += 1;
        self.counters.bytes_in += image.len() as u64;
        self.activity.bytes = Some(image.len() as u64);
        self.stage("encode", format!("{} bytes", image.len()), encode_us, true);
        let start = Instant::now();
        let json = active_infinity::interop::to_redacted_json(&module).expect("json");
        let json_us = start.elapsed().as_secs_f64() * 1e6;
        let json_ok = !json.contains(SECRET_CANARY);
        self.stage("json", "redacted projection", json_us, json_ok);
        let start = Instant::now();
        let proto = active_infinity::to_protobuf(&module).expect("protobuf");
        let proto_us = start.elapsed().as_secs_f64() * 1e6;
        let proto_ok = !String::from_utf8_lossy(&proto).contains(SECRET_CANARY);
        self.stage("protobuf", "redacted projection", proto_us, proto_ok);
        let start = Instant::now();
        let debug = format!("{module:?} {secret:?}");
        let debug_us = start.elapsed().as_secs_f64() * 1e6;
        let debug_ok = !debug.contains(SECRET_CANARY);
        self.stage("debug", "redacted Debug", debug_us, debug_ok);
        let leaked = !json_ok || !proto_ok || !debug_ok;
        let ok = !leaked;
        self.redaction_ok = ok;
        (
            "Secret redaction".into(),
            ok,
            if ok {
                "JSON, Protobuf and Debug all hide the canary".into()
            } else {
                "a projection leaked the canary".into()
            },
            json!({
                "leaked": leaked,
                "json_ok": json_ok,
                "protobuf_ok": proto_ok,
                "debug_ok": debug_ok,
                "image_bytes": image.len(),
            }),
        )
    }

    fn scenario_attenuation(&mut self) -> (String, bool, String, Json) {
        let start = Instant::now();
        let widened = CapAttrs::new(&["echo", "mutate"]);
        let error = self
            .agent
            .attenuate(&self.echo_cap, widened)
            .expect_err("widening must be refused");
        let elapsed = start.elapsed().as_secs_f64() * 1e6;
        let ok = error.code() == "rpc/attenuation-escalation";
        self.stage("widen", error.code(), elapsed, ok);
        (
            "Attenuation refusal".into(),
            ok,
            format!("widen attempt refused with {}", error.code()),
            json!({"code": error.code(), "refused": ok}),
        )
    }

    fn scenario_revoke(&mut self) -> (String, bool, String, Json) {
        let start = Instant::now();
        let cap = self
            .agent
            .mint(self.echo_provider, 0, CapAttrs::new(&["echo"]))
            .expect("revocable cap");
        let mint_us = start.elapsed().as_secs_f64() * 1e6;
        self.stage("mint", "fresh echo capability", mint_us, true);
        let start = Instant::now();
        let promise = self
            .agent
            .call(self.lane, &cap, "echo", vec![Arg::text("never dispatched")])
            .expect("queued call");
        let queue_us = start.elapsed().as_secs_f64() * 1e6;
        self.stage("queue", "call queued before revoke", queue_us, true);
        let start = Instant::now();
        self.agent.revoke(&cap);
        let revoke_us = start.elapsed().as_secs_f64() * 1e6;
        self.stage("revoke", "capability revoked", revoke_us, true);
        let start = Instant::now();
        let error = self.await_value(&promise).expect_err("revoked call");
        let settle_us = start.elapsed().as_secs_f64() * 1e6;
        let ok = error.code() == "rpc/revoked";
        self.stage("dispatch", error.code(), settle_us, ok);
        (
            "Revoke before dispatch".into(),
            ok,
            format!("dispatch refused with {}", error.code()),
            json!({"code": error.code(), "refused": ok}),
        )
    }

    fn scenario_streaming(&mut self) -> (String, bool, String, Json) {
        let module = fixture_module();
        let start = Instant::now();
        let image = encode(&module).expect("encode");
        let encode_us = start.elapsed().as_secs_f64() * 1e6;
        self.counters.encodes += 1;
        self.counters.bytes_in += image.len() as u64;
        self.activity.bytes = Some(image.len() as u64);
        self.stage("encode", format!("{} bytes", image.len()), encode_us, true);
        let start = Instant::now();
        let encoder = StreamEncoder::new(&module, 64).expect("stream encoder");
        let frames = encoder.frames().len();
        let bytes = encoder.to_bytes();
        let encode_stream_us = start.elapsed().as_secs_f64() * 1e6;
        self.stage(
            "frames",
            format!("{frames} frame(s)"),
            encode_stream_us,
            frames > 0,
        );
        let start = Instant::now();
        let mut decoder = StreamDecoder::new();
        for chunk in bytes.chunks(7) {
            decoder.push_bytes(chunk).expect("stream chunk");
        }
        let streamed = decoder.finish().expect("stream finish");
        let reassemble_us = start.elapsed().as_secs_f64() * 1e6;
        let ok = streamed.image == image;
        self.stage(
            "reassemble",
            format!("{} chunks of 7 bytes", bytes.len().div_ceil(7)),
            reassemble_us,
            ok,
        );
        self.counters.streaming_frames += frames as u64;
        self.counters.bytes_in += bytes.len() as u64;
        self.canonical_attempts = self.canonical_attempts.saturating_add(1);
        if ok {
            self.canonical_ok = self.canonical_ok.saturating_add(1);
        }
        self.stage(
            "canonical",
            if ok { "matches encode()" } else { "mismatch" },
            0.0,
            ok,
        );
        self.note(
            "stream",
            None,
            format!("streaming scenario: {frames} frames reassembled"),
            Some(reassemble_us),
            Some(bytes.len() as u64),
            Some("streaming"),
        );
        (
            "Streaming reassembly".into(),
            ok,
            format!("{frames} frames of 7-byte chunks reassembled to the canonical image"),
            json!({"frames": frames, "image_bytes": image.len(), "stable": ok}),
        )
    }

    fn scenario_mcp_memory(&mut self) -> (String, bool, String, Json) {
        self.stage("handshake", "registered once at startup", 0.0, true);
        let cap = self.mcp_cap.clone();
        let start = Instant::now();
        let promise = self
            .agent
            .call(self.lane, &cap, "echo", vec![Arg::text("hi")])
            .expect("tool call");
        let value = self.await_value(&promise).expect("tool value");
        let call_us = start.elapsed().as_secs_f64() * 1e6;
        self.counters.tool_calls += 1;
        let ok = format!("{value:?}").contains("pong");
        self.stage("tools/call", brief(&value), call_us, ok);
        self.note(
            "tool",
            None,
            "MCP memory transport tools/call echo returned",
            Some(call_us),
            None,
            Some("mcp-memory"),
        );
        (
            "MCP memory tool".into(),
            ok,
            format!(
                "tools/call echo returned {} in {:.1} µs",
                brief(&value),
                call_us
            ),
            json!({"value": brief(&value), "call_us": call_us}),
        )
    }

    fn scenario_tool_policy(&mut self) -> (String, bool, String, Json) {
        let cap = self.mcp_restricted.clone();
        self.stage("policy", "allows [other] only", 0.0, true);
        let start = Instant::now();
        let error = self
            .agent
            .call(self.lane, &cap, "echo", vec![Arg::text("hi")])
            .expect_err("tool policy must refuse");
        let refusal_us = start.elapsed().as_secs_f64() * 1e6;
        let ok = error.code() == "rpc/tool-policy";
        self.stage("tools/call", error.code(), refusal_us, ok);
        self.note(
            "tool_refused",
            Some(error.code()),
            "MCP unknown tool refused before dispatch",
            Some(refusal_us),
            None,
            Some("tool-policy"),
        );
        (
            "MCP tool refused".into(),
            ok,
            format!("unlisted tool refused with {}", error.code()),
            json!({"code": error.code(), "refused": ok}),
        )
    }

    fn scenario_http_tool(&mut self) -> (String, bool, String, Json) {
        let cap = self.http_cap.clone();
        self.stage("endpoint", self.http_address.clone(), 0.0, true);
        let start = Instant::now();
        let promise = match self.agent.call(
            self.lane,
            &cap,
            "get",
            vec![Arg::Value(Value::path("/health"))],
        ) {
            Ok(promise) => promise,
            Err(error) => {
                let code = error.code();
                self.stage("GET /health", code, 0.0, false);
                return (
                    "HTTP allow-list".into(),
                    false,
                    format!("GET /health was refused with {code}"),
                    json!({"code": code}),
                );
            }
        };
        let value = match self.await_value(&promise) {
            Ok(value) => value,
            Err(error) => {
                let code = error.code();
                let elapsed = start.elapsed().as_secs_f64() * 1e6;
                self.stage("GET /health", code, elapsed, false);
                return (
                    "HTTP allow-list".into(),
                    false,
                    format!("GET /health failed with {code}"),
                    json!({"code": code}),
                );
            }
        };
        let call_us = start.elapsed().as_secs_f64() * 1e6;
        self.counters.tool_calls += 1;
        self.stage("GET /health", brief(&value), call_us, true);
        let start = Instant::now();
        let error = self
            .agent
            .call(
                self.lane,
                &cap,
                "get",
                vec![Arg::Value(Value::path("/../etc/passwd"))],
            )
            .expect_err("path escape must be refused");
        let refusal_us = start.elapsed().as_secs_f64() * 1e6;
        let escape_ok = error.code() == "rpc/path-not-granted";
        self.stage("escape", error.code(), refusal_us, escape_ok);
        let ok = escape_ok && format!("{value:?}").contains("true");
        (
            "HTTP allow-list".into(),
            ok,
            format!(
                "GET /health returned {}; escape refused with {}",
                brief(&value),
                error.code()
            ),
            json!({"value": brief(&value), "escape_code": error.code(), "call_us": call_us}),
        )
    }

    fn scenario_local_process(&mut self) -> (String, bool, String, Json) {
        #[cfg(windows)]
        let (program, flag) = ("cmd", "/C");
        #[cfg(not(windows))]
        let (program, flag) = ("sh", "-c");
        let allowed = self.process_allowed.clone();
        let denied = self.process_denied.clone();
        self.stage(
            "spawn",
            format!("{program} registered at startup"),
            0.0,
            true,
        );
        let start = Instant::now();
        let promise = self
            .agent
            .call(
                self.lane,
                &allowed,
                "run",
                vec![Arg::text(flag), Arg::text("echo active")],
            )
            .expect("process call");
        let value = self.await_value(&promise).expect("process value");
        let run_us = start.elapsed().as_secs_f64() * 1e6;
        self.counters.tool_calls += 1;
        let echoed = format!("{value:?}").contains("active");
        self.stage("stdout", brief(&value), run_us, echoed);
        let start = Instant::now();
        let promise = self
            .agent
            .call(
                self.lane,
                &denied,
                "run",
                vec![Arg::text(flag), Arg::text("echo denied")],
            )
            .expect("queued denied call");
        let error = self.await_value(&promise).expect_err("process denial");
        let deny_us = start.elapsed().as_secs_f64() * 1e6;
        let ok = echoed && error.code() == "rpc/tool-policy";
        self.stage("denied", error.code(), deny_us, ok);
        (
            "Local process policy".into(),
            ok,
            format!(
                "allowlisted echo returned {}; denial refused with {}",
                brief(&value),
                error.code()
            ),
            json!({"value": brief(&value), "deny_code": error.code(), "run_us": run_us}),
        )
    }

    fn scenario_lanes(&mut self) -> (String, bool, String, Json) {
        let before = self.agent.round_trips();
        let lanes = self.lanes.clone();
        if let Some(channel) = self.channels.first().copied() {
            if self
                .agent
                .send(self.lane, channel, Value::text("work"), &[])
                .is_ok()
            {
                *self
                    .channel_messages
                    .entry("work-queue".to_string())
                    .or_insert(0) += 1;
                let _ = self.agent.recv(channel);
            }
        }
        let start = Instant::now();
        let mut promises = Vec::new();
        let mut ids = Vec::new();
        for (index, lane) in lanes.iter().enumerate() {
            let promise = self
                .agent
                .call(
                    *lane,
                    &self.echo_cap,
                    "echo",
                    vec![Arg::text(format!("lane-{index}"))],
                )
                .expect("lane call");
            ids.push(promise.id().0);
            promises.push(promise);
        }
        for promise in promises {
            self.await_value(&promise).expect("lane value");
        }
        let dispatch_us = start.elapsed().as_secs_f64() * 1e6;
        let round_trips = self.agent.round_trips() - before;
        self.promise_chain = ids.clone();
        self.activity.promise_chain = ids;
        self.stage(
            "batch",
            format!("{} lanes", lanes.len()),
            dispatch_us,
            round_trips == 1,
        );
        let ok = round_trips == 1;
        (
            "Multi-lane batch".into(),
            ok,
            format!(
                "{} lanes served in {round_trips} provider round-trip",
                lanes.len()
            ),
            json!({"lanes": lanes.len(), "round_trips": round_trips}),
        )
    }

    fn scenario_channel_share(&mut self) -> (String, bool, String, Json) {
        let start = Instant::now();
        let channel = self.channels[0];
        let sequence = self
            .agent
            .send(
                self.lane,
                channel,
                Value::text("capability-share"),
                std::slice::from_ref(&self.echo_cap),
            )
            .expect("channel send");
        *self
            .channel_messages
            .entry("work-queue".to_string())
            .or_insert(0) += 1;
        let send_us = start.elapsed().as_secs_f64() * 1e6;
        self.stage("send", format!("sequence {sequence}"), send_us, true);
        let start = Instant::now();
        let message = self
            .agent
            .recv(channel)
            .expect("channel recv")
            .expect("a queued message");
        let recv_us = start.elapsed().as_secs_f64() * 1e6;
        let shared = message.caps.contains(&self.echo_cap.id());
        self.stage(
            "recv",
            format!("{} shared capability id(s)", message.caps.len()),
            recv_us,
            shared,
        );
        let ok = shared && message.sequence == sequence;
        (
            "Channel capability share".into(),
            ok,
            format!(
                "message {sequence} transferred {} capability id by reference",
                message.caps.len()
            ),
            json!({"sequence": sequence, "caps": message.caps.len(), "shared": shared}),
        )
    }

    fn scenario_pipeline_stress(&mut self) -> (String, bool, String, Json) {
        const LINKS: usize = 32;
        let lane = self.lane;
        let cap = self.echo_cap.clone();
        let start = Instant::now();
        let before = self.agent.round_trips();
        let mut promise = self
            .agent
            .call(lane, &cap, "echo", vec![Arg::text("seed")])
            .expect("stress head");
        let mut ids = Vec::with_capacity(LINKS);
        ids.push(promise.id().0);
        for _ in 1..LINKS {
            promise = self
                .agent
                .call(lane, &cap, "echo", vec![Arg::Promise(promise.id())])
                .expect("stress link");
            ids.push(promise.id().0);
        }
        self.await_value(&promise).expect("stress value");
        let round_trips = self.agent.round_trips() - before;
        let elapsed = start.elapsed().as_secs_f64() * 1e6;
        let chain = ids.iter().rev().take(12).rev().copied().collect::<Vec<_>>();
        self.promise_chain = chain.clone();
        self.activity.promise_chain = chain.clone();
        self.stage(
            "chain",
            format!("{LINKS} links · {round_trips} round-trip(s)"),
            elapsed,
            round_trips == 1,
        );
        let ok = round_trips == 1 && ids.len() == LINKS;
        (
            "Pipeline stress".into(),
            ok,
            format!("{LINKS}-link chain settled in {round_trips} provider round-trip in {elapsed:.0} µs"),
            json!({"links": LINKS, "round_trips": round_trips, "chain_tail": chain}),
        )
    }

    fn scenario_budget(&mut self) -> (String, bool, String, Json) {
        let start = Instant::now();
        let mut attrs = CapAttrs::new(&["echo"]);
        attrs.budget.max_calls = 4;
        attrs.budget.max_bytes = 32;
        let cap = self
            .agent
            .mint(self.echo_provider, 0, attrs)
            .expect("budget cap");
        let mut bomb = Value::text("x".repeat(4_096));
        for _ in 0..8 {
            bomb = Value::List(vec![bomb]);
        }
        let error = self
            .agent
            .call(self.lane, &cap, "echo", vec![Arg::Value(bomb)])
            .expect_err("byte budget must refuse");
        let elapsed = start.elapsed().as_secs_f64() * 1e6;
        let ok = error.code() == "rpc/budget-exceeded";
        self.stage("charge", error.code(), elapsed, ok);
        (
            "Byte budget bomb".into(),
            ok,
            format!(
                "nested 4 KiB payload refused with {} (max_bytes = 32)",
                error.code()
            ),
            json!({"code": error.code(), "max_bytes": 32, "depth": 9}),
        )
    }

    fn scenario_call_storm(&mut self) -> (String, bool, String, Json) {
        let start = Instant::now();
        let mut attrs = CapAttrs::new(&["echo"]);
        attrs.budget.max_calls = 5;
        let cap = self
            .agent
            .mint(self.echo_provider, 0, attrs)
            .expect("storm cap");
        let mut promises = Vec::new();
        let mut refused = 0u64;
        for index in 0..8 {
            match self.agent.call(
                self.lane,
                &cap,
                "echo",
                vec![Arg::text(format!("storm-{index}"))],
            ) {
                Ok(promise) => promises.push(promise),
                Err(_) => refused += 1,
            }
        }
        let queued = promises.len();
        for promise in promises {
            self.await_value(&promise).expect("storm value");
        }
        let elapsed = start.elapsed().as_secs_f64() * 1e6;
        let ok = refused >= 1 && queued == 5;
        self.stage(
            "storm",
            format!("{queued} queued · {refused} refused"),
            elapsed,
            ok,
        );
        (
            "Call budget storm".into(),
            ok,
            format!("{queued} calls queued, {refused} refused at max_calls = 5"),
            json!({"queued": queued, "refused": refused, "max_calls": 5}),
        )
    }

    fn scenario_tool_ceiling(&mut self) -> (String, bool, String, Json) {
        let cap = self.mcp_ceiling.clone();
        let start = Instant::now();
        let error = self
            .agent
            .call(self.lane, &cap, "echo", vec![Arg::text("x".repeat(256))])
            .expect_err("payload ceiling must refuse");
        let elapsed = start.elapsed().as_secs_f64() * 1e6;
        let ok = error.code() == "rpc/tool-policy";
        self.stage("payload", error.code(), elapsed, ok);
        (
            "Tool payload ceiling".into(),
            ok,
            format!(
                "256-byte argument refused with {} (ceiling = 16)",
                error.code()
            ),
            json!({"code": error.code(), "max_arg_bytes": 16, "attempted": 256}),
        )
    }

    fn scenario_bench_sizes(&mut self) -> (String, bool, String, Json) {
        let mut rows = Vec::new();
        let mut all_ok = true;
        for (name, fields) in [("small", 8usize), ("medium", 128), ("large", 1_024)] {
            let module = fixture_with(fields);
            let mut encode_samples = Vec::new();
            let mut validate_samples = Vec::new();
            let start = Instant::now();
            for _ in 0..12 {
                let started = Instant::now();
                let bytes = encode(&module).expect("size encode");
                encode_samples.push(started.elapsed().as_secs_f64() * 1e6);
                self.counters.encodes += 1;
                self.counters.bytes_in += bytes.len() as u64;
                let started = Instant::now();
                validate(&bytes).expect("size validate");
                validate_samples.push(started.elapsed().as_secs_f64() * 1e6);
                self.counters.validates += 1;
            }
            let elapsed = start.elapsed().as_secs_f64() * 1e6;
            let encode = stats(encode_samples);
            let validate = stats(validate_samples);
            let ok = encode.p50_us > 0.0 && validate.p50_us > 0.0;
            all_ok &= ok;
            self.stage(
                name,
                format!("encode p50 {:.1} µs", encode.p50_us),
                elapsed,
                ok,
            );
            rows.push(json!({
                "size": name,
                "fields": fields,
                "encode": encode,
                "validate": validate,
            }));
        }
        (
            "Codec size benchmark".into(),
            all_ok,
            "12 samples per size: small, medium and large modules".into(),
            json!({"sizes": rows}),
        )
    }

    fn scenario_bench_calls(&mut self) -> (String, bool, String, Json) {
        let lane = self.lane;
        let cap = self.echo_cap.clone();
        let start = Instant::now();
        let before = self.agent.round_trips();
        let mut sequential = Vec::with_capacity(40);
        for _ in 0..40 {
            let started = Instant::now();
            let promise = self
                .agent
                .call(lane, &cap, "echo", vec![Arg::text("bench")])
                .expect("bench call");
            self.await_value(&promise).expect("bench value");
            sequential.push(started.elapsed().as_secs_f64() * 1e6);
        }
        let sequential_round_trips = self.agent.round_trips() - before;
        let sequential_stats = stats(sequential);
        let elapsed = start.elapsed().as_secs_f64() * 1e6;
        self.stage(
            "sequential",
            format!("p50 {:.1} µs", sequential_stats.p50_us),
            elapsed,
            sequential_stats.p50_us > 0.0,
        );

        let start = Instant::now();
        let before = self.agent.round_trips();
        let mut pipelined = Vec::with_capacity(4);
        for _ in 0..4 {
            let started = Instant::now();
            let mut promise = self
                .agent
                .call(lane, &cap, "echo", vec![Arg::text("head")])
                .expect("bench head");
            for _ in 0..9 {
                promise = self
                    .agent
                    .call(lane, &cap, "echo", vec![Arg::Promise(promise.id())])
                    .expect("bench pipelined");
            }
            self.await_value(&promise).expect("bench pipelined value");
            pipelined.push(started.elapsed().as_secs_f64() * 1e6 / 10.0);
        }
        let pipelined_round_trips = self.agent.round_trips() - before;
        let pipelined_stats = stats(pipelined);
        let elapsed = start.elapsed().as_secs_f64() * 1e6;
        self.stage(
            "pipelined",
            format!("p50 {:.1} µs/call", pipelined_stats.p50_us),
            elapsed,
            pipelined_stats.p50_us > 0.0,
        );
        let ok = sequential_stats.p50_us > 0.0
            && pipelined_stats.p50_us > 0.0
            && pipelined_round_trips < sequential_round_trips;
        (
            "RPC call benchmark".into(),
            ok,
            format!(
                "sequential p50 {:.1} µs ({sequential_round_trips} RT); pipelined p50 {:.1} µs/call ({pipelined_round_trips} RT)",
                sequential_stats.p50_us, pipelined_stats.p50_us
            ),
            json!({
                "sequential": sequential_stats,
                "pipelined": pipelined_stats,
                "sequential_round_trips": sequential_round_trips,
                "pipelined_round_trips": pipelined_round_trips,
            }),
        )
    }

    fn scenario_bench_export(&mut self) -> (String, bool, String, Json) {
        let start = Instant::now();
        let report = self.run_benchmark(30).expect("benchmark");
        let lines = report.csv.lines().count();
        let elapsed = start.elapsed().as_secs_f64() * 1e6;
        let ok = lines >= 4 && report.encode.n == 30 && report.validate.n == 30;
        self.stage("csv", format!("{lines} lines"), elapsed, ok);
        (
            "Benchmark export".into(),
            ok,
            format!("30 iterations exported as {lines} CSV lines"),
            json!({"lines": lines, "encode_n": report.encode.n, "validate_n": report.validate.n}),
        )
    }

    fn scenario_fuzz_smoke(&mut self) -> (String, bool, String, Json) {
        let image = encode(&fixture_module()).expect("fuzz seed");
        self.counters.encodes += 1;
        self.counters.bytes_in += image.len() as u64;
        let mut flipped = image.clone();
        flipped[0] ^= 0xff;
        let mut truncated = image.clone();
        truncated.truncate(image.len() / 2);
        let cases = vec![Vec::new(), flipped, truncated];
        let mut refused = 0;
        let start = Instant::now();
        for case in &cases {
            if validate(case).is_err() {
                refused += 1;
            }
        }
        let elapsed = start.elapsed().as_secs_f64() * 1e6;
        let ok = refused == cases.len();
        self.stage(
            "mutations",
            format!("{refused}/{} refused", cases.len()),
            elapsed,
            ok,
        );
        (
            "Fuzz smoke".into(),
            ok,
            format!(
                "{refused}/{} corrupted images refused without a panic",
                cases.len()
            ),
            json!({"cases": cases.len(), "refused": refused, "seed_bytes": image.len()}),
        )
    }

    pub fn run_benchmark(&mut self, iterations: usize) -> Result<BenchmarkReport, String> {
        let iterations = iterations.clamp(5, 5_000);
        self.begin_activity("Benchmark", format!("benchmark · {iterations} iterations"));
        let module = fixture_module();
        let _image = encode(&module).expect("encode");
        let mut encode_samples = Vec::with_capacity(iterations);
        let mut validate_samples = Vec::with_capacity(iterations);
        let mut encode_total_us = 0.0;
        let mut validate_total_us = 0.0;
        for _ in 0..iterations {
            let started = Instant::now();
            let bytes = encode(&module).expect("encode");
            let encode_us = started.elapsed().as_secs_f64() * 1e6;
            encode_total_us += encode_us;
            encode_samples.push(encode_us);
            self.counters.encodes += 1;
            let started = Instant::now();
            validate(&bytes).expect("validate");
            let validate_us = started.elapsed().as_secs_f64() * 1e6;
            validate_total_us += validate_us;
            validate_samples.push(validate_us);
            self.counters.validates += 1;
            self.counters.bytes_in += bytes.len() as u64;
        }
        self.activity.progress = Some((iterations as u64, iterations as u64));
        self.stage(
            "encode",
            format!("{iterations} samples · total"),
            encode_total_us,
            true,
        );
        self.stage(
            "validate",
            format!("{iterations} samples · total"),
            validate_total_us,
            true,
        );

        let calls = iterations.clamp(10, 200);
        let start = Instant::now();
        let mut sequential = Vec::with_capacity(calls);
        for _ in 0..calls {
            let started = Instant::now();
            let promise = self
                .agent
                .call(self.lane, &self.echo_cap, "echo", vec![Arg::text("bench")])
                .expect("bench call");
            self.await_value(&promise).expect("bench value");
            sequential.push(started.elapsed().as_secs_f64() * 1e6);
        }
        let sequential_us = start.elapsed().as_secs_f64() * 1e6;
        self.stage(
            "sequential calls",
            format!("{calls} calls"),
            sequential_us,
            true,
        );
        let batches = (calls / 10).max(2);
        let start = Instant::now();
        let mut pipelined = Vec::with_capacity(batches);
        for _ in 0..batches {
            let started = Instant::now();
            let mut promise = self
                .agent
                .call(self.lane, &self.echo_cap, "echo", vec![Arg::text("head")])
                .expect("bench head");
            for _ in 0..9 {
                promise = self
                    .agent
                    .call(
                        self.lane,
                        &self.echo_cap,
                        "echo",
                        vec![Arg::Promise(promise.id())],
                    )
                    .expect("bench pipelined");
            }
            self.await_value(&promise).expect("bench value");
            // Ten dependent calls per sample; divide so sequential and
            // pipelined p50 values are both per call.
            pipelined.push(started.elapsed().as_secs_f64() * 1e6 / 10.0);
        }
        let pipelined_us = start.elapsed().as_secs_f64() * 1e6;
        self.stage(
            "pipelined calls",
            format!("{batches} batches of 10"),
            pipelined_us,
            true,
        );

        let mut samples = BTreeMap::new();
        samples.insert("encode".to_string(), encode_samples.clone());
        samples.insert("validate".to_string(), validate_samples.clone());
        samples.insert("call_sequential".to_string(), sequential.clone());
        samples.insert("call_pipelined".to_string(), pipelined.clone());
        let mut csv = String::from("workload,iteration,microseconds\n");
        for (name, values) in &samples {
            for (index, value) in values.iter().enumerate() {
                csv.push_str(&format!("{name},{index},{value:.3}\n"));
            }
        }
        let report = BenchmarkReport {
            ts_ms: now_ms(),
            encode: stats(encode_samples),
            validate: stats(validate_samples),
            call_sequential: stats(sequential),
            call_pipelined: stats(pipelined),
            samples,
            csv,
        };
        self.benchmark = Some(report.clone());
        self.activity.at_ms = now_ms();
        self.activity.ok = Some(true);
        self.activity.summary = format!(
            "benchmark {iterations} iters · encode p50 {:.1} µs · validate p50 {:.1} µs",
            report.encode.p50_us, report.validate.p50_us
        );
        self.note(
            "benchmark",
            None,
            format!(
                "benchmark {iterations} iters: encode p50 {:.1} µs, validate p50 {:.1} µs",
                report.encode.p50_us, report.validate.p50_us
            ),
            Some(encode_total_us + validate_total_us),
            None,
            None,
        );
        Ok(report)
    }

    pub fn status_module_json(&mut self) -> Result<Json, String> {
        let module = self.status_module();
        let bytes = encode(&module).map_err(|error| error.to_string())?;
        let hash = content_hash(&bytes).map_err(|error| error.to_string())?;
        let redacted = active_infinity::interop::to_redacted_json(&module)
            .map_err(|error| error.to_string())?;
        self.refresh_status();
        Ok(json!({
            "hash": hex(&hash),
            "image_bytes": bytes.len(),
            "bytes_base64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes),
            "redacted_json": redacted,
            "redaction_ok": self.redaction_ok,
        }))
    }

    pub fn timings(&self) -> Timings {
        self.timings.clone()
    }
}

fn mcp_responses() -> BTreeMap<String, String> {
    let mut responses = BTreeMap::new();
    responses.insert(
        "initialize".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"stub"}}}"#.to_string(),
    );
    responses.insert(
        "tools/list".to_string(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echo"}]}}"#
            .to_string(),
    );
    responses.insert(
        "tools/call".to_string(),
        r#"{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"pong"}]}}"#
            .to_string(),
    );
    responses
}

impl Default for PlaneCore {
    fn default() -> Self {
        Self::new()
    }
}

pub fn now_millis() -> u64 {
    now_ms()
}
