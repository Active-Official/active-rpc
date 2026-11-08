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
    "intro.skipped",
    "cap.minted",
    "cap.retained",
    "cap.released",
    "cap.dropped",
    "cap.revoked",
    "cap.expired",
    "cap.exported",
    "cap.restored",
    "cap.record-orphaned",
    "cap.rebound",
    "cap.rotation-carried",
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
    "channel.created",
    "channel.subscribed",
    "channel.unsubscribed",
    "channel.closed",
    "channel.destroyed",
    "budget.exhausted",
    "receipts.dropped",
    "provider.panicked",
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
        Event::CapExported(cap) => {
            trace.event = "cap.exported";
            trace.cap = Some(cap.correlation_id());
        }
        Event::CapRestored(cap) => {
            trace.event = "cap.restored";
            trace.cap = Some(cap.correlation_id());
        }
        Event::CapRecordOrphaned(cap) => {
            trace.event = "cap.record-orphaned";
            trace.cap = Some(cap.correlation_id());
        }
        Event::CapRebound { cap, from, to } => {
            trace.event = "cap.rebound";
            trace.cap = Some(cap.correlation_id());
            trace.identity = Some(format!("{}->{}", hex(from), hex(to)));
        }
        Event::RotationCarried {
            cap,
            jobs,
            promises,
            claims,
        } => {
            trace.event = "cap.rotation-carried";
            trace.cap = Some(cap.correlation_id());
            trace.detail = Some(format!("jobs {jobs} promises {promises} claims {claims}"));
        }
        Event::CapIntroduced { cap, fingerprint } => {
            trace.event = "cap.introduced";
            trace.cap = Some(cap.correlation_id());
            trace.identity = Some(hex(fingerprint));
        }
        Event::ProviderPanicked { provider, phase } => {
            trace.event = "provider.panicked";
            trace.provider = Some(provider.0);
            trace.detail = Some(label(phase));
        }
        Event::IntroSkipped { provider, reason } => {
            trace.event = "intro.skipped";
            trace.provider = Some(provider.0);
            trace.detail = Some(label(reason));
        }
        Event::LaneCreated(lane) => {
            trace.event = "lane.created";
            trace.lane = Some(lane.0);
        }
        Event::LaneDestroyed { lane, jobs } => {
            trace.event = "lane.destroyed";
            trace.lane = Some(lane.0);
            trace.detail = Some(jobs.to_string());
        }
        Event::CallQueued { job, lane, cap, .. } => {
            trace.event = "call.queued";
            trace.job = Some(*job);
            trace.lane = Some(lane.0);
            trace.cap = Some(cap.correlation_id());
        }
        Event::CallRefused { lane, cap, code } => {
            trace.event = "call.refused";
            trace.lane = Some(lane.0);
            // A refusal with no capability reports no capability: a synthetic
            // zero id would be indistinguishable from a real one.
            trace.cap = cap.map(|cap| cap.correlation_id());
            trace.code = Some(label(code));
        }
        Event::BatchDispatched {
            provider,
            jobs,
            lane_count,
        } => {
            trace.event = "batch.dispatched";
            trace.provider = Some(provider.0);
            trace.detail = Some(format!("{jobs} jobs in {lane_count} lanes"));
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
            trace.code = Some(label(code));
        }
        Event::ChannelSend { channel, sequence } => {
            trace.event = "channel.send";
            trace.channel = Some(channel.0);
            trace.sequence_on_channel = Some(*sequence);
        }
        Event::ChannelCreated(channel) => {
            trace.event = "channel.created";
            trace.channel = Some(channel.0);
        }
        Event::ChannelSubscribed { lane, channel } => {
            trace.event = "channel.subscribed";
            trace.lane = Some(lane.0);
            trace.channel = Some(channel.0);
        }
        Event::ChannelUnsubscribed { lane, channel } => {
            trace.event = "channel.unsubscribed";
            trace.lane = Some(lane.0);
            trace.channel = Some(channel.0);
        }
        Event::ChannelClosed(channel) => {
            trace.event = "channel.closed";
            trace.channel = Some(channel.0);
        }
        Event::ChannelDestroyed { channel, dropped } => {
            trace.event = "channel.destroyed";
            trace.channel = Some(channel.0);
            trace.detail = Some(dropped.to_string());
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
            trace.cap = cap.map(|cap| cap.correlation_id());
            trace.dimension = Some(label(dimension));
        }
        Event::ToolRefused { cap, reason } => {
            trace.event = "tool.refused";
            trace.cap = Some(cap.correlation_id());
            trace.detail = Some(label(reason));
        }
        Event::ReceiptsDropped { count } => {
            trace.event = "receipts.dropped";
            trace.detail = Some(format!("{count} dropped in total"));
        }
        Event::ReceiptsDisabled { count } => {
            trace.event = "receipts.disabled";
            trace.detail = Some(format!("{count} dropped in total"));
        }
        Event::ReceiptsEnabled => {
            trace.event = "receipts.enabled";
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
    counters.insert(
        "receipts_dropped".to_string(),
        Value::from(metrics.receipts_dropped),
    );
    counters.insert(
        "events_total".to_string(),
        Value::from(metrics.events_total),
    );
    counters.insert(
        "events_evicted".to_string(),
        Value::from(metrics.events_evicted),
    );
    let mut gauges = Map::new();
    // `promises` is retained records (pending plus settled-but-readable), which
    // is what the old gauge meant; `promises_pending` is the outstanding work an
    // operator actually watches.
    gauges.insert("promises".to_string(), Value::from(promises as u64));
    gauges.insert(
        "promises_kept".to_string(),
        Value::from(metrics.promises_retained),
    );
    gauges.insert(
        "promises_pending".to_string(),
        Value::from(metrics.promises_pending),
    );
    gauges.insert(
        "events_retained".to_string(),
        Value::from(metrics.events_retained),
    );
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

/// Longest label a trace carries, in bytes, including the ellipsis.
pub const MAX_LABEL_BYTES: usize = 128;

/// Bound and escape a free-form label before it enters a trace.
///
/// The fields that carry a label (`code`, `dimension`, `detail`, a provider
/// phase) are meant to be closed sets, but a provider-controlled code reaches
/// one of them, and a trace is text that a collector may write into a line log
/// or a terminal. Escaping and truncating here is the fail-closed boundary,
/// independent of what each producer does.
///
/// The result is at most [`MAX_LABEL_BYTES`] bytes and contains no control
/// character: the ellipsis is reserved for out of the budget, so the bound is
/// the constant and not the constant plus three.
pub fn label(text: &str) -> String {
    // The crate's one rule for text that must not reach a line log: control
    // characters and invisible/reordering ones. The fast path used to check
    // only `is_control`, so U+2028 and bidi overrides passed through
    // (round 38, F8).
    if text.len() <= MAX_LABEL_BYTES
        && !text.chars().any(|character| {
            character.is_control() || crate::security::is_invisible_or_reordering(character)
        })
    {
        return text.to_string();
    }
    let budget = MAX_LABEL_BYTES - '…'.len_utf8();
    let mut out = String::with_capacity(MAX_LABEL_BYTES);
    for ch in text.chars() {
        // `escape_debug` leaves some invisible characters alone (U+2800, the
        // Hangul fillers), so anything the crate's own rule flags is rendered as
        // an explicit escape (R-15 round 3, #2).
        let piece: String = if ch.is_control() || crate::security::is_invisible_or_reordering(ch) {
            format!("\\u{{{:x}}}", ch as u32)
        } else {
            ch.escape_debug().collect()
        };
        if out.len() + piece.len() > budget {
            out.push('…');
            return out;
        }
        out.push_str(&piece);
    }
    out
}
