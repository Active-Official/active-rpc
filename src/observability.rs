//! Observability: a stable event schema with correlation ids only.
//!
//! A mesh needs to answer "which call failed, on which lane, for which
//! capability" without turning its telemetry into a credential. Raw capability
//! ids are authority: a log line that contains one is a capability handout. The
//! projection in this module therefore carries a **correlation id** for every
//! capability, never the id itself, and never an argument value.
//!
//! Two documents are versioned here:
//!
//! - [`SCHEMA`] `active-rpc/observability/1`: one JSON object per kernel event.
//! - [`METRICS_SCHEMA`] `active-rpc/metrics/1`: a point-in-time counter snapshot.
//!
//! The event names are part of the schema. [`EVENT_NAMES`] is the closed set, and
//! `tests/observability_tests.rs` fails if a name is not documented in
//! `docs/spec/observability.md`.

use serde_json::{Map, Value};

use crate::kernel::{Event, Metrics};

/// Observability event schema version.
pub const SCHEMA: &str = "active-rpc/observability/1";
/// Metrics snapshot schema version.
pub const METRICS_SCHEMA: &str = "active-rpc/metrics/1";

/// Every event name this schema can emit.
pub const EVENT_NAMES: &[&str] = &[
    "cap.minted",
    "cap.retained",
    "cap.released",
    "cap.dropped",
    "cap.revoked",
    "cap.expired",
    "cap.introduced",
    "cap.transferred",
    "lane.created",
    "lane.destroyed",
    "call.queued",
    "call.refused",
    "batch.dispatched",
    "job.completed",
    "promise.resolved",
    "promise.rejected",
    "channel.send",
    "channel.recv",
    "budget.exhausted",
    "tool.refused",
];

/// One projected kernel event.
///
/// Fields are optional because the kernel event does not always carry them;
/// absent fields are omitted from the JSON, which keeps the record small and
/// unambiguous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEvent {
    sequence: u64,
    event: &'static str,
    lane: Option<u64>,
    cap: Option<String>,
    provider: Option<u64>,
    job: Option<u64>,
    promise: Option<u64>,
    channel: Option<u64>,
    sequence_on_channel: Option<u64>,
    code: Option<String>,
    dimension: Option<String>,
    identity: Option<String>,
    detail: Option<String>,
}

impl TraceEvent {
    /// Monotonic sequence within one kernel.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Event name (one of [`EVENT_NAMES`]).
    pub fn event(&self) -> &'static str {
        self.event
    }

    /// Correlation id of the capability involved, if any.
    pub fn cap_correlation(&self) -> Option<&str> {
        self.cap.as_deref()
    }

    /// Stable code carried by a refusal or rejection.
    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }

    /// JSON object for this event.
    pub fn to_json(&self) -> String {
        Value::Object(self.to_map()).to_string()
    }

    fn to_map(&self) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("schema".to_string(), Value::from(SCHEMA));
        map.insert("sequence".to_string(), Value::from(self.sequence));
        map.insert("event".to_string(), Value::from(self.event));
        if let Some(lane) = self.lane {
            map.insert("lane".to_string(), Value::from(lane));
        }
        if let Some(cap) = &self.cap {
            map.insert("cap".to_string(), Value::from(cap.clone()));
        }
        if let Some(provider) = self.provider {
            map.insert("provider".to_string(), Value::from(provider));
        }
        if let Some(job) = self.job {
            map.insert("job".to_string(), Value::from(job));
        }
        if let Some(promise) = self.promise {
            map.insert("promise".to_string(), Value::from(promise));
        }
        if let Some(channel) = self.channel {
            map.insert("channel".to_string(), Value::from(channel));
        }
        if let Some(sequence) = self.sequence_on_channel {
            map.insert("channel_sequence".to_string(), Value::from(sequence));
        }
        if let Some(code) = &self.code {
            map.insert("code".to_string(), Value::from(code.clone()));
        }
        if let Some(dimension) = &self.dimension {
            map.insert("dimension".to_string(), Value::from(dimension.clone()));
        }
        if let Some(identity) = &self.identity {
            map.insert("identity".to_string(), Value::from(identity.clone()));
        }
        if let Some(detail) = &self.detail {
            map.insert("detail".to_string(), Value::from(detail.clone()));
        }
        map
    }
}

/// Project a kernel event.
///
/// Capability ids become correlation ids (`CapId::correlation_id`), which are
/// stable per id and cannot be replayed as authority. Argument values and secret
/// material never enter the projection because [`Event`] never carries them.
pub fn project(event: &Event, sequence: u64) -> TraceEvent {
    let mut trace = TraceEvent {
        sequence,
        event: "unknown",
        lane: None,
        cap: None,
        provider: None,
        job: None,
        promise: None,
        channel: None,
        sequence_on_channel: None,
        code: None,
        dimension: None,
        identity: None,
        detail: None,
    };
    match event {
        Event::CapMinted { cap, provider } => {
            trace.event = "cap.minted";
            trace.cap = Some(cap.correlation_id());
            trace.provider = Some(provider.0);
        }
        Event::CapRetained(cap) => {
            trace.event = "cap.retained";
            trace.cap = Some(cap.correlation_id());
        }
        Event::CapReleased(cap) => {
            trace.event = "cap.released";
            trace.cap = Some(cap.correlation_id());
        }
        Event::CapDropped(cap) => {
            trace.event = "cap.dropped";
            trace.cap = Some(cap.correlation_id());
        }
        Event::CapRevoked(cap) => {
            trace.event = "cap.revoked";
            trace.cap = Some(cap.correlation_id());
        }
        Event::CapExpired(cap) => {
            trace.event = "cap.expired";
            trace.cap = Some(cap.correlation_id());
        }
        Event::CapIntroduced { cap, fingerprint } => {
            trace.event = "cap.introduced";
            trace.cap = Some(cap.correlation_id());
            trace.identity = Some(hex(fingerprint));
        }
        Event::LaneCreated(lane) => {
            trace.event = "lane.created";
            trace.lane = Some(lane.0);
        }
        Event::LaneDestroyed(lane) => {
            trace.event = "lane.destroyed";
            trace.lane = Some(lane.0);
        }
        Event::CallQueued { job, lane, cap } => {
            trace.event = "call.queued";
            trace.job = Some(*job);
            trace.lane = Some(lane.0);
            trace.cap = Some(cap.correlation_id());
        }
        Event::CallRefused { lane, cap, code } => {
            trace.event = "call.refused";
            trace.lane = Some(lane.0);
            trace.cap = Some(cap.correlation_id());
            trace.code = Some(code.clone());
        }
        Event::BatchDispatched {
            provider,
            jobs,
            lanes,
        } => {
            trace.event = "batch.dispatched";
            trace.provider = Some(provider.0);
            trace.detail = Some(format!("{jobs} jobs in {} lanes", lanes.len()));
        }
        Event::JobCompleted { job, lane } => {
            trace.event = "job.completed";
            trace.job = Some(*job);
            trace.lane = Some(lane.0);
        }
        Event::PromiseResolved(promise) => {
            trace.event = "promise.resolved";
            trace.promise = Some(promise.0);
        }
        Event::PromiseRejected { promise, code } => {
            trace.event = "promise.rejected";
            trace.promise = Some(promise.0);
            trace.code = Some(code.clone());
        }
        Event::ChannelSend { channel, sequence } => {
            trace.event = "channel.send";
            trace.channel = Some(channel.0);
            trace.sequence_on_channel = Some(*sequence);
        }
        Event::ChannelRecv { channel, sequence } => {
            trace.event = "channel.recv";
            trace.channel = Some(channel.0);
            trace.sequence_on_channel = Some(*sequence);
        }
        Event::CapTransferred { cap, channel } => {
            trace.event = "cap.transferred";
            trace.cap = Some(cap.correlation_id());
            trace.channel = Some(channel.0);
        }
        Event::BudgetExhausted { cap, dimension } => {
            trace.event = "budget.exhausted";
            trace.cap = Some(cap.correlation_id());
            trace.dimension = Some(dimension.clone());
        }
        Event::ToolRefused { cap, reason } => {
            trace.event = "tool.refused";
            trace.cap = Some(cap.correlation_id());
            trace.detail = Some(reason.clone());
        }
    }
    trace
}

/// Serialize a batch of events as a JSON array.
pub fn to_json_array(events: &[TraceEvent]) -> String {
    let values: Vec<Value> = events
        .iter()
        .map(|event| Value::Object(event.to_map()))
        .collect();
    Value::Array(values).to_string()
}

/// Counters plus gauges, as a JSON object.
///
/// Counter names are stable: a dashboard that reads `calls_refused` keeps
/// working when a new counter appears.
pub fn metrics_json(
    metrics: &Metrics,
    promises: usize,
    jobs: usize,
    lanes: usize,
    channels: usize,
) -> String {
    let mut counters = Map::new();
    counters.insert(
        "calls_queued".to_string(),
        Value::from(metrics.calls_queued),
    );
    counters.insert(
        "calls_refused".to_string(),
        Value::from(metrics.calls_refused),
    );
    counters.insert(
        "budget_exhaustions".to_string(),
        Value::from(metrics.budget_exhaustions),
    );
    counters.insert(
        "tool_refusals".to_string(),
        Value::from(metrics.tool_refusals),
    );
    counters.insert("revocations".to_string(), Value::from(metrics.revocations));
    counters.insert(
        "promises_resolved".to_string(),
        Value::from(metrics.promises_resolved),
    );
    counters.insert(
        "promises_rejected".to_string(),
        Value::from(metrics.promises_rejected),
    );
    counters.insert("round_trips".to_string(), Value::from(metrics.round_trips));
    counters.insert("transfers".to_string(), Value::from(metrics.transfers));
    counters.insert(
        "promises_double_settled".to_string(),
        Value::from(metrics.promises_double_settled),
    );
    counters.insert(
        "backpressure_refusals".to_string(),
        Value::from(metrics.backpressure_refusals),
    );
    counters.insert(
        "identity_refusals".to_string(),
        Value::from(metrics.identity_refusals),
    );
    let mut gauges = Map::new();
    gauges.insert("promises".to_string(), Value::from(promises as u64));
    gauges.insert("jobs".to_string(), Value::from(jobs as u64));
    gauges.insert("lanes".to_string(), Value::from(lanes as u64));
    gauges.insert("channels".to_string(), Value::from(channels as u64));
    let mut root = Map::new();
    root.insert("schema".to_string(), Value::from(METRICS_SCHEMA));
    root.insert("counters".to_string(), Value::Object(counters));
    root.insert("gauges".to_string(), Value::Object(gauges));
    Value::Object(root).to_string()
}

fn hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
