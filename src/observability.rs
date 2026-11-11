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
//! - [`SCHEMA`] `active-rpc/observability/3`: one JSON object per kernel event.
//! - [`METRICS_SCHEMA`] `active-rpc/metrics/1`: a point-in-time counter snapshot.
//!
//! The event names are part of the schema. [`EVENT_NAMES`] is the closed set, and
//! `tests/observability_tests.rs` fails if a name is not documented in
//! `docs/spec/observability.md`.

use serde_json::{Map, Value};

use crate::kernel::{Event, Metrics};

/// Observability event schema version.
///
/// v3 (RPC-56) adds the caller identity prefix on `call.queued`: the first
/// 128 bits of the presented fingerprint, as `identity`, when the call
/// arrived from an authenticated peer. v2 (RPC-46) added the call-lifecycle
/// `method` label and the queued `args_bytes` count. No field was renamed or
/// removed: a v1 reader ignores the fields it does not know, but the version
/// moves because consumers that assert exact field sets (the control plane's
/// event match, the projection tests) must be updated with the shape, not
/// silently left behind.
pub const SCHEMA: &str = "active-rpc/observability/3";
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
    /// Bounded method label for a call-lifecycle event (`call.queued`,
    /// `call.refused`, `job.completed`). The label was computed once, at
    /// event creation, by the kernel's `method_event_label`: a 64-byte
    /// escaped prefix plus a digest tail for a longer name. The projection
    /// carries it verbatim — re-labelling a label would change its digest
    /// and break the queued/refused/completed join (RPC-46).
    method: Option<String>,
    /// Argument bytes the queued call was charged for (`call.queued` only).
    args_bytes: Option<u64>,
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

    /// Bounded method label carried by a call-lifecycle event, if any.
    pub fn method(&self) -> Option<&str> {
        self.method.as_deref()
    }

    /// Argument bytes the queued call was charged for, if any.
    pub fn args_bytes(&self) -> Option<u64> {
        self.args_bytes
    }

    /// Caller of the queued call, when it arrived from an authenticated peer:
    /// the first 128 bits of the presented fingerprint as 32 lowercase hex
    /// characters (RPC-56). Absent for a local call and for an anonymous peer.
    pub fn identity(&self) -> Option<&str> {
        self.identity.as_deref()
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
        if let Some(method) = &self.method {
            map.insert("method".to_string(), Value::from(method.clone()));
        }
        if let Some(args_bytes) = self.args_bytes {
            map.insert("args_bytes".to_string(), Value::from(args_bytes));
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
/// stable per id and cannot be replayed as authority. Argument values never
/// enter the projection because [`Event`] never carries them; secret-looking
/// text is a different case — a refusal reason is provider-controlled text,
/// so it reaches [`label()`], which scrubs secret-looking shapes before
/// they reach a trace line (RPC-48). The scrubber is the second line of
/// defence behind the rule that events carry no values.
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
        method: None,
        args_bytes: None,
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
        Event::CallQueued {
            job,
            lane,
            cap,
            method,
            args_bytes,
            caller,
        } => {
            trace.event = "call.queued";
            trace.job = Some(*job);
            trace.lane = Some(lane.0);
            trace.cap = Some(cap.correlation_id());
            // The label was computed once, at queue time, from the raw name:
            // carrying it verbatim keeps the queued label identical to the
            // refused and completed labels for the same call (RPC-46).
            trace.method = Some(method.clone());
            trace.args_bytes = Some(*args_bytes);
            // The caller is the first 128 bits of the presented fingerprint,
            // as 32 lowercase hex characters (RPC-56): the same public label
            // the receipt seals and the replay trace carries. Absent for a
            // local call and for an anonymous peer.
            trace.identity = caller.as_ref().map(crate::identity::fingerprint_prefix_hex);
        }
        Event::CallRefused {
            lane,
            cap,
            code,
            method,
        } => {
            trace.event = "call.refused";
            trace.lane = Some(lane.0);
            // A refusal with no capability reports no capability: a synthetic
            // zero id would be indistinguishable from a real one.
            trace.cap = cap.map(|cap| cap.correlation_id());
            trace.code = Some(label(code));
            // A refusal that names no call carries no method: the field is
            // absent, not invented (RPC-46).
            trace.method = method.clone();
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
        Event::JobCompleted { job, lane, method } => {
            trace.event = "job.completed";
            trace.job = Some(*job);
            trace.lane = Some(lane.0);
            // The same label the queued event carried for this job, so the
            // two records join on (`job`, `method`) (RPC-46).
            trace.method = Some(method.clone());
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

/// Marker that stands where a secret-looking value was removed from a
/// label (RPC-48). The marker is the whole replacement: the key name, the
/// scheme word, or the surrounding prose stays, so an operator still sees
/// *that* a credential was refused, never the credential itself.
pub const REDACTED: &str = "[redacted]";

/// Credential words a `key = value` / `key: value` assignment may use
/// (RPC-48). The match is case-insensitive, and a key also matches when it
/// ends in one of these after `_`, `-` or `.` (`my_token`,
/// `client_secret`), so an embedder's own key names are covered without
/// matching words that merely contain one (`monkey` is not `key`).
const CREDENTIAL_KEYS: &[&str] = &[
    "api_key",
    "apikey",
    "api-key",
    "access_token",
    "refresh_token",
    "auth_token",
    "client_secret",
    "password",
    "passwd",
    "secret",
    "token",
    "key",
];

/// True when `byte` joins a word: a letter, a digit, `_` or `-`. A `.`
/// separates dotted components, so it is a boundary here.
fn is_word_byte(byte: Option<u8>) -> bool {
    matches!(
        byte,
        Some(b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-')
    )
}

/// True when `key` is a credential word, or ends in one after `_`, `-` or
/// `.` (RPC-48). The comparison is case-insensitive: `API_KEY` and
/// `Api-Key` are the same assignment as `api_key`.
fn is_credential_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    CREDENTIAL_KEYS.iter().any(|word| {
        lower == *word
            || lower.ends_with(&format!("_{word}"))
            || lower.ends_with(&format!("-{word}"))
            || lower.ends_with(&format!(".{word}"))
    })
}

/// End of a PEM private-key block in `text`: the byte just past the closing
/// `-----` of an `-----END ... PRIVATE KEY-----` marker, or `None` when
/// there is no complete END marker.
fn pem_end(text: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(at) = text[from..].find("-----END ") {
        let start = from + at;
        let after = &text[start + "-----END ".len()..];
        // A missing closing run means no complete END marker exists later
        // either: any later marker would contain the run this search just
        // missed, so the question-mark ends the search exactly as the
        // explicit None did (clippy::question_mark).
        let end = after.find("-----")?;
        if after[..end].contains("PRIVATE KEY") {
            return Some(start + "-----END ".len() + end + 5);
        }
        from = start + 1;
    }
    None
}

/// What a secret-looking shape starting at `at` consumes, and what
/// replaces it: `(bytes consumed, replacement)`, or `None` when no pattern
/// starts at `at`. The replacement carries the preserved shape (a key
/// name, a scheme word) with the value replaced by [`REDACTED`].
fn secret_match_at(text: &str, at: usize) -> Option<(usize, String)> {
    let bytes = text.as_bytes();
    let rest = &text[at..];

    // A PEM private-key block: the BEGIN marker through the END marker, or
    // to the end of the label when the block is cut short. Everything
    // between the markers is key material, so the whole span is one
    // redaction; a certificate marker is not a private key and stays.
    for marker in ["-----BEGIN ", "-----END "] {
        if let Some(after) = rest.strip_prefix(marker) {
            if let Some(end) = after.find("-----") {
                let header = &after[..end];
                if header.contains("PRIVATE KEY") {
                    let consumed = marker.len() + end + 5;
                    if marker == "-----BEGIN " {
                        if let Some(end_at) = pem_end(&rest[consumed..]) {
                            return Some((consumed + end_at, REDACTED.to_string()));
                        }
                        return Some((rest.len(), REDACTED.to_string()));
                    }
                    return Some((consumed, REDACTED.to_string()));
                }
            }
        }
    }

    // `Bearer <token>` / `Basic <token>`: the scheme word stays, the token
    // goes. A short word after the scheme is prose ("Bearer token
    // required"), not a credential, so only a run of at least 8
    // characters is redacted.
    for scheme in ["Bearer", "Basic"] {
        // Byte comparison, not a rest[..6] slice: a multibyte character
        // straddling the sixth byte would panic the slice, and the text
        // here is provider-controlled (RPC-48).
        if rest.len() > scheme.len()
            && rest.as_bytes()[..scheme.len()].eq_ignore_ascii_case(scheme.as_bytes())
            && !is_word_byte(if at == 0 { None } else { Some(bytes[at - 1]) })
            && bytes[at + scheme.len()].is_ascii_whitespace()
        {
            let mut value = at + scheme.len();
            while value < bytes.len() && bytes[value].is_ascii_whitespace() {
                value += 1;
            }
            let mut end = value;
            while end < bytes.len() && !bytes[end].is_ascii_whitespace() {
                end += 1;
            }
            if end - value >= 8 {
                let replacement = format!("{} {REDACTED}", &text[at..at + scheme.len()]);
                return Some((end - at, replacement));
            }
        }
    }

    // URL userinfo: `scheme://user:pass@host` carries the credential
    // before the `@`, exactly the shape `redacted_base` removes from a
    // base URL. The `@` must come before any `/`, `?`, `#` or whitespace,
    // so a bare `user@host` without a scheme is untouched.
    if rest.starts_with("://") {
        let mut end = at + 3;
        while end < bytes.len()
            && bytes[end] != b'@'
            && bytes[end] != b'/'
            && bytes[end] != b'?'
            && bytes[end] != b'#'
            && !bytes[end].is_ascii_whitespace()
        {
            end += 1;
        }
        if end < bytes.len() && bytes[end] == b'@' && end > at + 3 {
            return Some((end + 1 - at, format!("://{REDACTED}@")));
        }
    }

    // Fixed credential prefixes: the prefix plus a run of token
    // characters, with a minimum run length so a short word that happens
    // to start the same way stays. The character before must not join a
    // word, so `task-...` never reads as a key.
    if !is_word_byte(if at == 0 { None } else { Some(bytes[at - 1]) }) {
        for (prefix, min_run) in [
            ("sk-", 16),
            ("sk_live_", 16),
            ("sk_test_", 16),
            ("ghp_", 20),
            ("gho_", 20),
            ("ghu_", 20),
            ("ghs_", 20),
            ("ghr_", 20),
            ("github_pat_", 20),
        ] {
            if let Some(after) = rest.strip_prefix(prefix) {
                let run = after
                    .bytes()
                    .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
                    .count();
                if run >= min_run {
                    return Some((prefix.len() + run, REDACTED.to_string()));
                }
            }
        }
        if let Some(after) = rest.strip_prefix("AKIA") {
            let run = after
                .bytes()
                .take_while(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
                .count();
            if run >= 16 {
                return Some((4 + run, REDACTED.to_string()));
            }
        }
    }

    // `key = value` / `key: value`: the key stays, the value goes. The key
    // must start at a word boundary, so `monkey` does not match through
    // its `key` tail. A quoted value is redacted inside its quotes. A
    // value that is just the scheme word `Bearer`/`Basic` is left for the
    // scheme arm above, which redacts the token that follows it instead
    // of the scheme word itself.
    if !is_word_byte(if at == 0 { None } else { Some(bytes[at - 1]) }) {
        let mut key_end = at;
        while key_end < bytes.len()
            && (bytes[key_end].is_ascii_alphanumeric()
                || matches!(bytes[key_end], b'_' | b'-' | b'.'))
        {
            key_end += 1;
        }
        // A JSON-quoted key: the closing quote ends the key and the
        // separator follows it. The quote only counts as a closer when
        // the same quote opened the key, so an apostrophe in prose
        // (`secret's: ...`) is not a key. Spaces may sit between the
        // key (or its closer) and the separator, and between the
        // separator and the value (`password = "x"`).
        let mut sep_at = key_end;
        if sep_at < bytes.len()
            && (bytes[sep_at] == b'"' || bytes[sep_at] == b'\'')
            && at > 0
            && bytes[at - 1] == bytes[sep_at]
        {
            sep_at += 1;
        }
        while sep_at < bytes.len() && (bytes[sep_at] == b' ' || bytes[sep_at] == b'\t') {
            sep_at += 1;
        }
        if key_end > at
            && sep_at < bytes.len()
            && (bytes[sep_at] == b'=' || bytes[sep_at] == b':')
            && is_credential_key(&text[at..key_end])
        {
            let mut value_start = sep_at + 1;
            while value_start < bytes.len()
                && (bytes[value_start] == b' ' || bytes[value_start] == b'\t')
            {
                value_start += 1;
            }
            if value_start < bytes.len()
                && (bytes[value_start] == b'"' || bytes[value_start] == b'\'')
            {
                let quote = bytes[value_start];
                let mut end = value_start + 1;
                while end < bytes.len() && bytes[end] != quote {
                    end += 1;
                }
                if end < bytes.len() {
                    let mut replacement = text[at..=value_start].to_string();
                    replacement.push_str(REDACTED);
                    replacement.push(quote as char);
                    return Some((end + 1 - at, replacement));
                }
            } else {
                let mut end = value_start;
                while end < bytes.len()
                    && !bytes[end].is_ascii_whitespace()
                    && !matches!(
                        bytes[end],
                        b'"' | b'\'' | b',' | b';' | b'&' | b'}' | b']' | b')'
                    )
                {
                    end += 1;
                }
                if end > value_start {
                    let value = &text[value_start..end];
                    if !value.eq_ignore_ascii_case("Bearer") && !value.eq_ignore_ascii_case("Basic")
                    {
                        let mut replacement = text[at..value_start].to_string();
                        replacement.push_str(REDACTED);
                        return Some((end - at, replacement));
                    }
                }
            }
        }
    }

    None
}

/// Scrub secret-looking shapes from a label before it enters a trace.
///
/// Defence in depth (RPC-48): the fields `label()` bounds are meant to be
/// closed sets, but a provider-controlled reason reaches one of them —
/// `tool.refused`'s detail used to be the refusal error verbatim — so the
/// first producer that embeds a value would turn telemetry into a
/// credential leak. The scrubber redacts the *value* and keeps the shape,
/// so a trace still shows that a credential was refused without carrying
/// the credential.
///
/// The patterns are fixed prefixes and `key = value` shapes the codebase
/// already treats as credential homes — `sk-...` API keys (the `--api-key`
/// shape in `src/tool.rs`), `Bearer` header values (redacted to lengths
/// there), PEM private keys, URL userinfo (the same rule
/// `redacted_base` applies to a base URL) — never a bare entropy or
/// length heuristic, so a hash, a correlation id, or a long method name
/// passes through untouched. What is redacted, exactly:
///
/// - a `key = value` or `key: value` assignment whose key is a credential
///   word ([`CREDENTIAL_KEYS`]) or ends in one; the key stays, the value
///   becomes [`REDACTED`]. A quoted value is redacted inside its quotes,
///   a JSON-quoted key (`"password": "hunter2"`) is covered, and spaces
///   around the separator are allowed (`password = "x"`).
/// - `Bearer <token>` / `Basic <token>` with a token of at least 8
///   characters; the scheme word stays. A short word (`Bearer token
///   required`) is prose, not a credential, and stays.
/// - a token with a fixed credential prefix: `sk-`, `sk_live_`,
///   `sk_test_` plus at least 16 characters; `ghp_`, `gho_`, `ghu_`,
///   `ghs_`, `ghr_`, `github_pat_` plus at least 20; `AKIA` plus 16
///   uppercase alphanumerics.
/// - a PEM private-key block: `-----BEGIN ... PRIVATE KEY-----` through
///   its `-----END ... PRIVATE KEY-----`, or to the end of the label when
///   the block is cut short. A lone `-----END ... PRIVATE KEY-----` is
///   redacted on its own. A `-----BEGIN CERTIFICATE-----` is not a
///   private key and stays.
/// - URL userinfo: `scheme://user:pass@host` becomes
///   `scheme://[redacted]@host`.
///
/// The scan is one left-to-right pass over the label and allocates only
/// when a pattern actually matches, so ordinary labels cost one pass and
/// no allocation.
fn scrub_secrets(text: &str) -> std::borrow::Cow<'_, str> {
    let bytes = text.as_bytes();
    let mut out: Option<String> = None;
    let mut copied = 0;
    let mut i = 0;
    while i < bytes.len() {
        if let Some((len, replacement)) = secret_match_at(text, i) {
            let out = out.get_or_insert_with(|| String::with_capacity(text.len()));
            out.push_str(&text[copied..i]);
            out.push_str(&replacement);
            i += len;
            copied = i;
        } else {
            // Advance one character, not one byte: labels are Unicode and
            // the scan must stay on char boundaries.
            i += text[i..].chars().next().map_or(1, |ch| ch.len_utf8());
        }
    }
    match out {
        Some(mut out) => {
            out.push_str(&text[copied..]);
            std::borrow::Cow::Owned(out)
        }
        None => std::borrow::Cow::Borrowed(text),
    }
}

/// Bound, scrub and escape a free-form label before it enters a trace.
///
/// The fields that carry a label (`code`, `dimension`, `detail`, a provider
/// phase) are meant to be closed sets, but a provider-controlled code reaches
/// one of them, and a trace is text that a collector may write into a line log
/// or a terminal. Escaping and truncating here is the fail-closed boundary,
/// independent of what each producer does. Secret-looking shapes are
/// scrubbed first, by `scrub_secrets`: the fast path below returns short
/// clean text unchanged, and a secret must not take it (RPC-48).
///
/// The result is at most [`MAX_LABEL_BYTES`] bytes and contains no control
/// character: the ellipsis is reserved for out of the budget, so the bound is
/// the constant and not the constant plus three.
pub fn label(text: &str) -> String {
    // Scrub before the fast path: a short secret-looking label must not
    // return unchanged below (RPC-48).
    let scrubbed = scrub_secrets(text);
    let text = scrubbed.as_ref();
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
