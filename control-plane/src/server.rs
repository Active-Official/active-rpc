//! HTTP, WebSocket and static dashboard adapters around [`PlaneCore`].
//!
//! The kernel is not `Send`, so it runs on one worker thread. Handlers exchange
//! immutable [`Snapshot`] values with that thread; no kernel borrow crosses a
//! thread boundary.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use crossbeam_channel::{bounded, RecvTimeoutError, Sender};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::broadcast;
use tower_http::services::ServeDir;

use crate::plane::{BenchmarkReport, PlaneCore, ScenarioResult, Snapshot};

pub enum Command {
    Scenario(
        String,
        tokio::sync::oneshot::Sender<Result<ScenarioResult, CommandFailure>>,
    ),
    Level(
        u8,
        bool,
        tokio::sync::oneshot::Sender<Result<Vec<ScenarioResult>, CommandFailure>>,
    ),
    Benchmark(
        usize,
        tokio::sync::oneshot::Sender<Result<BenchmarkReport, CommandFailure>>,
    ),
    Status(tokio::sync::oneshot::Sender<Result<serde_json::Value, CommandFailure>>),
}

/// Why a worker command produced no result.
///
/// The two cases need different HTTP statuses: a command the core refused
/// (unknown scenario, read-only plane) is the caller's fault, while a caught
/// panic is the plane's. Collapsing them into one string made a panic answer
/// `400` (R-19 round 3, L2).
#[derive(Debug, Clone)]
pub enum CommandFailure {
    /// The caller asked for something the plane does not do (an unknown
    /// scenario id, a read-only plane).
    Refused(String),
    /// The plane itself failed while producing the answer (a codec, hash or
    /// projection fault). Not the caller's fault, so not a 400 (R-19 round 4,
    /// F4).
    Internal(String),
    Panicked,
}

impl CommandFailure {
    fn status(&self) -> StatusCode {
        match self {
            CommandFailure::Refused(_) => StatusCode::BAD_REQUEST,
            CommandFailure::Internal(_) | CommandFailure::Panicked => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    fn into_response(self) -> Response {
        let status = self.status();
        let detail = match self {
            CommandFailure::Refused(detail) | CommandFailure::Internal(detail) => detail,
            CommandFailure::Panicked => "the kernel worker panicked".to_string(),
        };
        (status, detail).into_response()
    }
}

#[derive(Clone)]
pub struct AppState {
    pub tx: Sender<Command>,
    pub latest: Arc<Mutex<Snapshot>>,
    pub broadcast: broadcast::Sender<Snapshot>,
    pub read_only: bool,
    /// Last `uptime_ms` observed from a *fresh* snapshot, and when it was seen.
    ///
    /// The kernel runs on one thread: if it panics or hangs, `latest` freezes
    /// and every read route keeps answering 200 with stale data. `/health`
    /// compares the snapshot's uptime against the last one it saw, so a frozen
    /// worker reads as unhealthy instead of immortal.
    pub heartbeat: Arc<Mutex<Heartbeat>>,
    /// Sticky: the worker caught a panic, so every snapshot reads `kernel:
    /// "down"` until the process restarts (R-19 round 3, M2).
    pub down: Arc<AtomicBool>,
    /// Open dashboard sockets, reported by `/metrics` (round 3, L8).
    pub observers: Arc<AtomicU64>,
}

/// When the last snapshot was taken, and the uptime it carried.
#[derive(Debug, Clone, Copy)]
pub struct Heartbeat {
    uptime_ms: u64,
    seen: std::time::Instant,
}

impl Heartbeat {
    fn new(uptime_ms: u64) -> Self {
        Self {
            uptime_ms,
            seen: std::time::Instant::now(),
        }
    }

    /// Feed a snapshot's uptime; true while the worker is still ticking.
    fn observe(&mut self, uptime_ms: u64) -> bool {
        self.observe_within(uptime_ms, STALE_WORKER_AFTER)
    }

    /// [`Heartbeat::observe`] with the staleness limit spelled out (tests).
    fn observe_within(&mut self, uptime_ms: u64, limit: Duration) -> bool {
        if uptime_ms != self.uptime_ms {
            self.uptime_ms = uptime_ms;
            self.seen = std::time::Instant::now();
            return true;
        }
        self.seen.elapsed() < limit
    }
}

/// How long a snapshot may keep the same uptime before the worker is stale.
/// Open dashboard sockets this plane will serve.
const MAX_WS_CLIENTS: u64 = 64;

pub const STALE_WORKER_AFTER: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
struct BenchmarkRequest {
    #[serde(default = "default_iterations")]
    iterations: usize,
}

fn default_iterations() -> usize {
    200
}

#[derive(Deserialize)]
struct TailQuery {
    n: Option<usize>,
}

#[derive(Deserialize)]
struct SinceQuery {
    id: Option<u64>,
}

#[derive(Deserialize)]
struct LevelQuery {
    #[serde(default)]
    up_to: bool,
}

pub fn spawn_worker(read_only: bool) -> AppState {
    // Bounded on purpose: a flood of local writes must get backpressure, not
    // an unbounded queue behind the single kernel worker.
    let (tx, rx) = bounded::<Command>(8);
    let (broadcast, _) = broadcast::channel::<Snapshot>(64);
    // One core. The worker builds it, publishes its first snapshot and hands
    // back the shared cell; this function used to build a second core (a second
    // set of capabilities, a second HTTP stub, a second listener) only to have
    // an initial value.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Arc<Mutex<Snapshot>>>();
    let broadcast_thread = broadcast.clone();
    // One heartbeat, shared with `/health`: the worker used to build its own
    // and the API built a second, so the endpoint never advanced
    // (audit ARPC-003).
    let heartbeat: Arc<Mutex<Heartbeat>> = Arc::new(Mutex::new(Heartbeat::new(0)));
    let heartbeat_worker = Arc::clone(&heartbeat);
    let observers: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let down: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let down_worker = Arc::clone(&down);
    std::thread::Builder::new()
        .name("active-kernel".into())
        .spawn(move || {
            let mut core = PlaneCore::new();
            core.set_mode(if read_only { "read-only" } else { "demo" });
            // The first snapshot is worker code like any other: a panic here
            // used to block startup for 30 s and then panic the spawner
            // (R-19 round 4, F17).
            let first =
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| core.snapshot())) {
                    Ok(first) => first,
                    Err(_) => {
                        let mut fallback = PlaneCore::new().snapshot();
                        fallback.health.kernel = "down".to_string();
                        fallback
                    }
                };
            let latest: Arc<Mutex<Snapshot>> = Arc::new(Mutex::new(first.clone()));
            let heartbeat = heartbeat_worker;
            if let Ok(mut beat) = heartbeat.lock() {
                beat.observe(first.uptime_ms);
            }
            let _ = broadcast_thread.send(first);
            if ready_tx.send(Arc::clone(&latest)).is_err() {
                // The caller went away before the first snapshot; nothing to
                // serve.
                return;
            }
            // A panic inside `snapshot()` used to happen outside `catch_unwind`,
            // kill this thread, and leave `latest` frozen with `kernel: "up"`;
            // the flag makes the failure sticky so a later tick cannot publish
            // "up" over a core whose panic was never explained (R-19 r3, M2).
            let down = down_worker;
            let publish_down =
                |latest: &Arc<Mutex<Snapshot>>, broadcast: &broadcast::Sender<Snapshot>| {
                    let snapshot = mark_worker_down(latest);
                    let _ = broadcast.send(snapshot);
                };
            loop {
                // Everything that runs kernel or provider code goes through
                // `catch_unwind`: the API returns a refusal, and the health flag
                // goes down, instead of a thread that died silently.
                let guarded = |core: &mut PlaneCore,
                               latest: &Arc<Mutex<Snapshot>>,
                               broadcast: &broadcast::Sender<Snapshot>,
                               heartbeat: &Arc<Mutex<Heartbeat>>,
                               run: &mut dyn FnMut(&mut PlaneCore)|
                 -> Result<(), CommandFailure> {
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(core))) {
                        Ok(()) => publish_snapshot(core, latest, broadcast, heartbeat, &down),
                        Err(_) => {
                            down.store(true, Ordering::SeqCst);
                            publish_down(latest, broadcast);
                            Err(CommandFailure::Panicked)
                        }
                    }
                };
                match rx.recv_timeout(Duration::from_secs(1)) {
                    // After a sticky down the core's state is unverified, so a
                    // mutating command must not run on it
                    // (R-19 round 4, F18).
                    Ok(Command::Scenario(_, reply)) if down.load(Ordering::SeqCst) => {
                        let _ = reply.send(Err(CommandFailure::Internal(
                            "the kernel worker is down; restart the plane".to_string(),
                        )));
                    }
                    Ok(Command::Level(_, _, reply)) if down.load(Ordering::SeqCst) => {
                        let _ = reply.send(Err(CommandFailure::Internal(
                            "the kernel worker is down; restart the plane".to_string(),
                        )));
                    }
                    Ok(Command::Benchmark(_, reply)) if down.load(Ordering::SeqCst) => {
                        let _ = reply.send(Err(CommandFailure::Internal(
                            "the kernel worker is down; restart the plane".to_string(),
                        )));
                    }
                    Ok(Command::Scenario(id, reply)) => {
                        let mut result = None;
                        let outcome = guarded(
                            &mut core,
                            &latest,
                            &broadcast_thread,
                            &heartbeat,
                            &mut |core| result = Some(core.run_scenario(&id)),
                        );
                        match outcome {
                            Ok(()) => {
                                let result = result.unwrap_or_else(|| Err("no result".to_string()));
                                let _ = reply.send(result.map_err(CommandFailure::Refused));
                            }
                            Err(error) => {
                                let _ = reply.send(Err(error));
                            }
                        }
                    }
                    Ok(Command::Level(level, up_to, reply)) => {
                        let mut results = None;
                        let outcome = guarded(
                            &mut core,
                            &latest,
                            &broadcast_thread,
                            &heartbeat,
                            &mut |core| results = Some(core.run_level(level, up_to)),
                        );
                        // A caught panic used to answer nothing, so the HTTP
                        // handler waited out its timeout and returned 504
                        // (R-19 round 3, L2).
                        match outcome {
                            Ok(()) => {
                                let _ = reply.send(Ok(results.unwrap_or_default()));
                            }
                            Err(error) => {
                                let _ = reply.send(Err(error));
                            }
                        }
                    }
                    Ok(Command::Benchmark(iterations, reply)) => {
                        let mut report = None;
                        let outcome = guarded(
                            &mut core,
                            &latest,
                            &broadcast_thread,
                            &heartbeat,
                            &mut |core| report = Some(core.run_benchmark(iterations)),
                        );
                        match outcome {
                            Ok(()) => {
                                let report = report.unwrap_or_else(|| Err("no result".to_string()));
                                let _ = reply.send(report.map_err(CommandFailure::Internal));
                            }
                            Err(error) => {
                                let _ = reply.send(Err(error));
                            }
                        }
                    }
                    Ok(Command::Status(reply)) => {
                        let mut status = None;
                        let outcome = guarded(
                            &mut core,
                            &latest,
                            &broadcast_thread,
                            &heartbeat,
                            &mut |core| status = Some(core.status_module_json()),
                        );
                        match outcome {
                            Ok(()) => {
                                let status = status.unwrap_or_else(|| Err("no result".to_string()));
                                let _ = reply.send(status.map_err(CommandFailure::Internal));
                            }
                            Err(error) => {
                                let _ = reply.send(Err(error));
                            }
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        // A panic here is contained: the flag is set and the
                        // next tick serves `kernel: "down"`.
                        let _ = publish_snapshot(
                            &mut core,
                            &latest,
                            &broadcast_thread,
                            &heartbeat,
                            &down,
                        );
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
        })
        .expect("kernel worker thread");
    let latest = ready_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the worker's first snapshot");
    // Seed the heartbeat from the first snapshot so a fresh process does not
    // read as stale before the first tick.
    AppState {
        tx,
        latest,
        broadcast,
        read_only,
        heartbeat,
        down,
        observers,
    }
}

pub fn public_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("public")
}

pub fn app(state: AppState) -> Router {
    let static_dir = public_dir();
    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/engines", get(engines))
        .route("/activity", get(activity))
        .route("/scenarios", get(scenarios))
        .route("/scenarios/results", get(scenario_results))
        .route("/events", get(events))
        .route("/logs/tail", get(logs_tail))
        .route("/logs/since", get(logs_since))
        .route("/logs/export.jsonl", get(logs_export))
        .route("/benchmark/last", get(benchmark_last))
        .route("/benchmark/run", post(benchmark_run))
        .route("/benchmark/export.csv", get(benchmark_csv))
        .route("/demo/scenario/{id}", post(scenario))
        .route("/demo/level/{level}", post(level))
        .route("/status-module", get(status_module))
        .route("/ws", get(ws))
        .with_state(state)
        // A loopback bind is not an authorization boundary: a page on another
        // origin can POST to 127.0.0.1 (no preflight for a simple request) and
        // DNS rebinding makes the snapshot readable. Every route therefore
        // checks the Host it was addressed at, and a mutating route also checks
        // the Origin.
        //
        // The layer comes *after* the fallback: `Router::layer` only covers what
        // was already added, so a static asset installed first was served
        // without the guard.
        .fallback_service(ServeDir::new(static_dir))
        .layer(axum::middleware::from_fn(guard))
}

/// Refuse a request addressed at a name that is not this machine, and stamp a
/// framing policy on every response.
///
/// `Host` is attacker-controlled in a DNS-rebinding attack, which is exactly the
/// case a loopback bind does not cover: the page's requests arrive at
/// `127.0.0.1` but carry the attacker's name. A request with *no* `Host` is a
/// local non-browser client (the test client, a script), which already holds the
/// user's privileges, so it is allowed; a present but foreign name is refused.
///
/// A website can also *frame* the dashboard and let the user click "run": the
/// click then originates in the framed document, so the Host and Origin checks
/// both pass. `frame-ancestors 'none'` is what refuses that, and it is set here
/// rather than per route so a route added later cannot forget it.
async fn guard(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let host = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    // HTTP/2 carries `:authority`; axum does not copy it into `host`, so a
    // mutating h2c request with no `Host` used to skip both checks
    // (R-19 round 4, F12). HTTP/1.1 clients that omit Host are malformed but
    // are not the h2 case this closes.
    let authority = request.uri().authority().map(|value| value.to_string());
    let host = host.or(authority);
    if request.method() != axum::http::Method::GET
        && host.is_none()
        && request.version() == axum::http::Version::HTTP_2
    {
        return (
            StatusCode::FORBIDDEN,
            "a mutating request must name its Host",
        )
            .into_response();
    }
    if let Some(host) = &host {
        if !is_loopback_host(host) {
            return (StatusCode::FORBIDDEN, "unexpected Host").into_response();
        }
        // `is_loopback_host` splits on the first colon, so
        // `127.0.0.1:8787@evil.example` passed as loopback while `host_parts`
        // refused its port; `same_origin` then took its "no Host" arm and any
        // loopback port was accepted. A present-but-unparsable Host is refused
        // (R-19 round 3, L4).
        if host_parts(host).is_none() {
            return (StatusCode::FORBIDDEN, "unparsable Host").into_response();
        }
    }
    if request.method() != axum::http::Method::GET {
        // A browser sends `Origin` on a cross-site request; a local script does
        // not. A present but foreign origin is the cross-site case, and a
        // loopback origin on another *port* is another local program, not this
        // dashboard.
        if let Some(origin) = request
            .headers()
            .get(axum::http::header::ORIGIN)
            .and_then(|value| value.to_str().ok())
        {
            if !same_origin(origin, host.as_deref()) {
                return (StatusCode::FORBIDDEN, "cross-origin request refused").into_response();
            }
        }
    }
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        "x-frame-options",
        axum::http::HeaderValue::from_static("DENY"),
    );
    // `style-src 'unsafe-inline'` is required and alone: the dashboard draws its
    // bar widths with inline style attributes and `node.style`, which the
    // directive blocks without the keyword (a browser reports every one as a
    // violation, which is how this was found). Scripts stay `'self'` only, the
    // frame policy is `'none'`, and no form or base can be repointed.
    headers.insert(
        "content-security-policy",
        axum::http::HeaderValue::from_static(
            "frame-ancestors 'none'; default-src 'self'; script-src 'self'; \
             style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
             connect-src 'self' ws://127.0.0.1:*; base-uri 'none'; form-action 'none'",
        ),
    );
    headers.insert(
        "x-content-type-options",
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        "referrer-policy",
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    response
}

/// True when a `Host` header names this machine.
///
/// The bracketed IPv6 form is the only unambiguous one (a bare `::1` cannot
/// carry a port); `[::1]:8787` and `[::1]` are accepted, `::1` is refused.
pub fn is_loopback_host(host: &str) -> bool {
    let host = host.trim();
    if let Some(rest) = host.strip_prefix('[') {
        let Some((name, tail)) = rest.split_once(']') else {
            return false;
        };
        if !tail.is_empty() && !tail.starts_with(':') {
            return false;
        }
        // `[0:0:0:0:0:0:0:1]` is the same address as `[::1]`: parse it rather
        // than compare text (R-19 round 4, F13).
        return name
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|address| address.is_loopback());
    }
    if host.matches(':').count() > 1 {
        // A bare IPv6 address: ambiguous without brackets, so refused.
        return false;
    }
    let name = host.split_once(':').map(|(name, _)| name).unwrap_or(host);
    // A trailing dot is the same name in DNS (`localhost.`).
    let name = name.strip_suffix('.').unwrap_or(name);
    name.eq_ignore_ascii_case("127.0.0.1") || name.eq_ignore_ascii_case("localhost")
}

fn snapshot(state: &AppState) -> Snapshot {
    // A panic inside a critical section poisons the cell, and a plain
    // `Snapshot` has no invariant left to protect: recovering beats failing
    // every read route for the life of the process (R-19 round 3, L5).
    let guard = state
        .latest
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut snapshot = guard.clone();
    drop(guard);
    if state.down.load(Ordering::SeqCst) {
        snapshot.health.kernel = "down".to_string();
    }
    snapshot.health.observers = state.observers.load(Ordering::Relaxed);
    snapshot
}

/// Take a snapshot and publish it, containing a panic inside `snapshot()`.
///
/// It used to run outside `catch_unwind`: a panic killed the worker thread,
/// `mark_worker_down` was never reached, and `/metrics` kept serving a frozen
/// snapshot with `kernel: "up"` (R-19 round 3, M2).
fn publish_snapshot(
    core: &mut PlaneCore,
    latest: &Arc<Mutex<Snapshot>>,
    broadcast: &broadcast::Sender<Snapshot>,
    heartbeat: &Arc<Mutex<Heartbeat>>,
    down: &AtomicBool,
) -> Result<(), CommandFailure> {
    let snapshot = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| core.snapshot()))
    {
        Ok(snapshot) => snapshot,
        Err(_) => {
            down.store(true, Ordering::SeqCst);
            let snapshot = mark_worker_down(latest);
            let _ = broadcast.send(snapshot);
            return Err(CommandFailure::Panicked);
        }
    };
    let mut snapshot = snapshot;
    if down.load(Ordering::SeqCst) {
        // Sticky: the core's post-panic state was never verified, so no later
        // tick may claim it is healthy.
        snapshot.health.kernel = "down".to_string();
    }
    if let Ok(mut guard) = latest.lock() {
        *guard = snapshot.clone();
    }
    if let Ok(mut beat) = heartbeat.lock() {
        beat.observe(snapshot.uptime_ms);
    }
    let _ = broadcast.send(snapshot);
    Ok(())
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let snapshot = snapshot(&state);
    // A frozen snapshot is not a healthy one: the uptime has to move.
    let ticking = state
        .heartbeat
        .lock()
        .map(|mut beat| beat.observe(snapshot.uptime_ms))
        .unwrap_or(false);
    Json(json!({
        // A failed redaction probe and a spent fixture grant are unhealthy
        // states an operator must see here, not only on `/metrics`
        // (R-19 round 4, F9).
        "ok": snapshot.health.kernel == "up"
            && ticking
            && snapshot.health.redaction_ok
            && snapshot.health.fixture_calls_remaining > 0,
        "worker": if ticking { "live" } else { "stale" },
        "mode": snapshot.health.mode,
        "read_only": state.read_only,
        "redaction_ok": snapshot.health.redaction_ok,
        "audit_gap": snapshot.health.audit_gap,
        "fixture_calls_remaining": snapshot.health.fixture_calls_remaining,
        "uptime_ms": snapshot.uptime_ms,
    }))
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    Json(snapshot(&state))
}

async fn engines(State(state): State<AppState>) -> impl IntoResponse {
    Json(snapshot(&state).engines)
}

async fn activity(State(state): State<AppState>) -> impl IntoResponse {
    Json(snapshot(&state).activity)
}

async fn scenarios(State(state): State<AppState>) -> impl IntoResponse {
    Json(snapshot(&state).scenarios)
}

async fn scenario_results(State(state): State<AppState>) -> impl IntoResponse {
    Json(snapshot(&state).scenario_results)
}

async fn events(State(state): State<AppState>) -> impl IntoResponse {
    Json(snapshot(&state).events)
}

/// Whether a cursor has a hole in front of it.
///
/// The ring's `oldest` cannot answer this: a protected event pins the front
/// while later ids are evicted, so a cursor just below the pinned front was
/// told "no gap" over a real hole. The highest evicted id can answer it
/// (R-19 round 3, M1).
pub(crate) fn ring_gap(cursor: u64, dropped_through: u64) -> bool {
    cursor < dropped_through
}

/// Whether the ring has dropped any event at all.
pub(crate) fn ring_truncated(dropped_through: u64) -> bool {
    dropped_through > 0
}

/// The `/logs/tail` envelope.
///
/// One function for the HTTP route and the embedded MCP fallback: the fallback
/// used to build `{count,cursor,events}` and omit `oldest`/`truncated`, so the
/// same tool returned two shapes depending on one probe at startup, and the
/// truncation signal disappeared in the degraded mode (R-19 round 3, L3).
pub(crate) fn tail_envelope(
    events: Vec<crate::plane::UiEvent>,
    oldest: u64,
    dropped_through: u64,
) -> serde_json::Value {
    let cursor = events.last().map(|event| event.id).unwrap_or(0);
    json!({
        "count": events.len(),
        "cursor": cursor,
        "oldest": oldest,
        "truncated": ring_truncated(dropped_through),
        "events": events,
    })
}

/// The `/logs/since` envelope; same reason as [`tail_envelope`].
pub(crate) fn since_envelope(
    events: Vec<crate::plane::UiEvent>,
    cursor: u64,
    oldest: u64,
    dropped_through: u64,
    newest: u64,
) -> serde_json::Value {
    // A cursor above every id names another plane process: ids start at 1 and
    // never go back, so a poller from a previous epoch is stuck at
    // `count:0, gap:false` while the audit restarted under it (R-19 round 4,
    // F8). It is a gap, and the cursor restarts so the next poll sees the
    // whole window.
    let stale = cursor > 0 && newest > 0 && cursor > newest;
    let next = if stale {
        0
    } else {
        events.last().map(|event| event.id).unwrap_or(cursor)
    };
    json!({
        "count": events.len(),
        "cursor": next,
        "oldest": oldest,
        "gap": ring_gap(cursor, dropped_through) || stale,
        "events": events,
    })
}

async fn logs_tail(
    State(state): State<AppState>,
    Query(query): Query<TailQuery>,
) -> impl IntoResponse {
    let snapshot = snapshot(&state);
    let limit = query.n.unwrap_or(200).clamp(1, 500);
    let start = snapshot.events.len().saturating_sub(limit);
    let events = snapshot.events[start..].to_vec();
    let oldest = snapshot.events.first().map(|event| event.id).unwrap_or(0);
    // `truncated` says the 500-event ring has already dropped history: a poller
    // that asks for a tail is looking at a window, not at the whole run. A
    // protected event can pin `oldest`, so the eviction counter decides
    // (R-19 round 3, M1).
    Json(tail_envelope(events, oldest, snapshot.dropped_through))
}

async fn logs_since(
    State(state): State<AppState>,
    Query(query): Query<SinceQuery>,
) -> impl IntoResponse {
    let snapshot = snapshot(&state);
    let cursor = query.id.unwrap_or(0);
    let oldest = snapshot.events.first().map(|event| event.id).unwrap_or(0);
    let dropped_through = snapshot.dropped_through;
    let newest = snapshot.events.last().map(|event| event.id).unwrap_or(0);
    let events: Vec<_> = snapshot
        .events
        .into_iter()
        .filter(|event| event.id > cursor)
        .collect();
    // Any id at or below `dropped_through` is gone for ever. Comparing with
    // `oldest` alone missed it: a protected event pins the front while later
    // ids are evicted, so the poller was told "no gap" over a real hole
    // (R-19 round 3, M1).
    Json(since_envelope(
        events,
        cursor,
        oldest,
        dropped_through,
        newest,
    ))
}

async fn logs_export(State(state): State<AppState>) -> Response {
    let snapshot = snapshot(&state);
    let mut body = String::new();
    for event in &snapshot.events {
        if let Ok(line) = serde_json::to_string(event) {
            body.push_str(&line);
            body.push('\n');
        }
    }
    (
        StatusCode::OK,
        [("content-type", "application/x-ndjson; charset=utf-8")],
        body,
    )
        .into_response()
}

async fn benchmark_last(State(state): State<AppState>) -> impl IntoResponse {
    Json(snapshot(&state).benchmark)
}

async fn benchmark_csv(State(state): State<AppState>) -> Response {
    let snapshot = snapshot(&state);
    match snapshot.benchmark {
        Some(report) => (
            StatusCode::OK,
            [("content-type", "text/csv; charset=utf-8")],
            report.csv,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "no benchmark has run").into_response(),
    }
}

async fn scenario(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    if state.read_only {
        return (
            StatusCode::FORBIDDEN,
            "read-only plane: scenarios are disabled",
        )
            .into_response();
    }
    let (reply, rx) = tokio::sync::oneshot::channel();
    if state
        .tx
        .try_send(Command::Scenario(id.clone(), reply))
        .is_err()
    {
        return (StatusCode::SERVICE_UNAVAILABLE, "kernel busy or stopped").into_response();
    }
    match tokio::time::timeout(Duration::from_secs(60), rx).await {
        Ok(Ok(Ok(result))) => {
            let snapshot = snapshot(&state);
            Json(json!({"result": result, "metrics": snapshot.metrics})).into_response()
        }
        Ok(Ok(Err(failure))) => failure.into_response(),
        Ok(Err(_)) => (StatusCode::INTERNAL_SERVER_ERROR, "scenario reply dropped").into_response(),
        Err(_) => (StatusCode::GATEWAY_TIMEOUT, "scenario timed out").into_response(),
    }
}

async fn level(
    State(state): State<AppState>,
    Path(level): Path<u8>,
    Query(query): Query<LevelQuery>,
) -> Response {
    if level > 6 {
        return (StatusCode::BAD_REQUEST, "level must be 0..=6").into_response();
    }
    if state.read_only {
        return (
            StatusCode::FORBIDDEN,
            "read-only plane: scenarios are disabled",
        )
            .into_response();
    }
    let (reply, rx) = tokio::sync::oneshot::channel();
    if state
        .tx
        .try_send(Command::Level(level, query.up_to, reply))
        .is_err()
    {
        return (StatusCode::SERVICE_UNAVAILABLE, "kernel busy or stopped").into_response();
    }
    match tokio::time::timeout(Duration::from_secs(120), rx).await {
        Ok(Ok(Ok(results))) => {
            let snapshot = snapshot(&state);
            Json(json!({
                "level": level,
                "up_to": query.up_to,
                "results": results,
                "metrics": snapshot.metrics,
            }))
            .into_response()
        }
        Ok(Ok(Err(failure))) => failure.into_response(),
        Ok(Err(_)) => (StatusCode::INTERNAL_SERVER_ERROR, "level reply dropped").into_response(),
        Err(_) => (StatusCode::GATEWAY_TIMEOUT, "level timed out").into_response(),
    }
}

async fn benchmark_run(
    State(state): State<AppState>,
    Json(body): Json<BenchmarkRequest>,
) -> Response {
    if state.read_only {
        return (
            StatusCode::FORBIDDEN,
            "read-only plane: benchmarks are disabled",
        )
            .into_response();
    }
    let (reply, rx) = tokio::sync::oneshot::channel();
    let iterations = body.iterations.clamp(5, 5_000);
    if state
        .tx
        .try_send(Command::Benchmark(iterations, reply))
        .is_err()
    {
        return (StatusCode::SERVICE_UNAVAILABLE, "kernel busy or stopped").into_response();
    }
    match tokio::time::timeout(Duration::from_secs(120), rx).await {
        Ok(Ok(Ok(report))) => Json(report).into_response(),
        Ok(Ok(Err(failure))) => failure.into_response(),
        Ok(Err(_)) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "benchmark reply dropped").into_response()
        }
        Err(_) => (StatusCode::GATEWAY_TIMEOUT, "benchmark timed out").into_response(),
    }
}

async fn status_module(State(state): State<AppState>) -> Response {
    let (reply, rx) = tokio::sync::oneshot::channel();
    if state.tx.try_send(Command::Status(reply)).is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, "kernel busy or stopped").into_response();
    }
    match tokio::time::timeout(Duration::from_secs(20), rx).await {
        Ok(Ok(Ok(mut value))) => {
            // `/status-module` used to answer `plane: "ok"` after a caught
            // panic, contradicting every other read route
            // (R-19 round 4, F2).
            if state.down.load(Ordering::SeqCst) {
                if let Some(object) = value.as_object_mut() {
                    object.insert("plane".to_string(), serde_json::json!("down"));
                }
            }
            Json(value).into_response()
        }
        Ok(Ok(Err(failure))) => failure.into_response(),
        Ok(Err(_)) => (StatusCode::INTERNAL_SERVER_ERROR, "status reply dropped").into_response(),
        Err(_) => (StatusCode::GATEWAY_TIMEOUT, "status timed out").into_response(),
    }
}

async fn ws(ws: WebSocketUpgrade, headers: HeaderMap, State(state): State<AppState>) -> Response {
    // Same-origin dashboard connections carry the loopback Origin. Refuse a
    // page loaded from another site, so a localhost plane is not readable by
    // any website the user happens to visit. Non-browser clients omit Origin.
    let host = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    if let Some(origin) = headers.get("origin").and_then(|value| value.to_str().ok()) {
        if !same_origin(origin, host.as_deref()) {
            return (StatusCode::FORBIDDEN, "cross-origin websocket refused").into_response();
        }
    }
    // Every socket holds a full snapshot per tick; an unbounded set is a
    // local memory amplifier (R-19 round 4, F11).
    if state.observers.load(Ordering::Relaxed) >= MAX_WS_CLIENTS {
        return (StatusCode::SERVICE_UNAVAILABLE, "too many dashboards").into_response();
    }
    ws.on_upgrade(move |socket| stream_socket(socket, state))
}

/// Counts one open dashboard socket for `health.observers`.
struct ObserverGuard(Arc<AtomicU64>);

impl ObserverGuard {
    fn open(counter: &Arc<AtomicU64>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(Arc::clone(counter))
    }
}

impl Drop for ObserverGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn stream_socket(mut socket: WebSocket, state: AppState) {
    // `Health.observers` was a constant zero (R-19 round 3, L8).
    let _observer = ObserverGuard::open(&state.observers);
    let mut receiver = state.broadcast.subscribe();
    let initial = snapshot(&state);
    if let Ok(text) = serde_json::to_string(&initial) {
        if socket.send(Message::Text(text.into())).await.is_err() {
            return;
        }
    }
    loop {
        tokio::select! {
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Text(text))) if text == "snapshot" => {
                        let snapshot = snapshot(&state);
                        if let Ok(text) = serde_json::to_string(&snapshot) {
                            if socket.send(Message::Text(text.into())).await.is_err() { break; }
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                }
            }
            update = receiver.recv() => {
                match update {
                    Ok(snapshot) => {
                        if let Ok(text) = serde_json::to_string(&snapshot) {
                            if socket.send(Message::Text(text.into())).await.is_err() { break; }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        // Falling behind used to be silent: the dashboard kept
                        // its last value and read as "nothing happened". The
                        // skipped count is pushed as its own frame.
                        let frame = gap_frame(skipped, snapshot(&state).ts_ms);
                        if socket.send(Message::Text(frame.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

/// The frame a dashboard receives when the broadcast ring dropped snapshots.
///
/// It has the same shape as an audit-gap event so one client filter sees both
/// kinds of hole.
pub fn gap_frame(skipped: u64, ts_ms: u64) -> String {
    json!({
        "kind": "event_gap",
        "code": "rpc/audit-gap",
        "skipped": skipped,
        "ts_ms": ts_ms,
    })
    .to_string()
}

/// Republish the last snapshot with the kernel marked down.
///
/// Called when the worker panicked: the alternative is a process that keeps
/// answering 200 with a frozen snapshot while `/health` says `ok`.
fn mark_worker_down(latest: &Arc<Mutex<Snapshot>>) -> Snapshot {
    // A poisoned cell still holds the last snapshot; the down flag is the fact
    // that matters, so recover it (R-19 round 3, L5).
    let mut guard = latest
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.health.kernel = "down".to_string();
    guard.clone()
}

pub async fn serve(port: u16, read_only: bool) -> std::io::Result<()> {
    let state = spawn_worker(read_only);
    let router = app(state);
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(address).await?;
    println!("Active Control Plane listening on http://{address}");
    println!("  dashboard  http://{address}/");
    println!("  REST       /metrics /activity /engines /logs/tail?n=200 /status-module");
    println!("  MCP stdio  cargo run -- --mcp --attach http://{address}");
    if read_only {
        println!("  mode       read-only (scenarios and benchmarks are disabled)");
    }
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown())
        .await
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}

/// Split a `Host` header into its name and port.
fn host_parts(host: &str) -> Option<(String, u16)> {
    let host = host.trim();
    if let Some(rest) = host.strip_prefix('[') {
        let (name, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(port) => port.parse().ok()?,
            None if tail.is_empty() => 80,
            None => return None,
        };
        return Some((format!("[{}]", name.to_ascii_lowercase()), port));
    }
    match host.split_once(':') {
        Some((name, port)) => Some((name.to_ascii_lowercase(), port.parse().ok()?)),
        None => Some((host.to_ascii_lowercase(), 80)),
    }
}

/// True only for an Origin that is this dashboard's own origin.
///
/// Prefix matching is wrong here: `http://127.0.0.1.evil.com` starts with the
/// loopback string but is a different host. Comparing the host alone is also
/// wrong: another local program on a different port is another principal.
pub fn same_origin(origin: &str, host: Option<&str>) -> bool {
    let parsed = match origin.parse::<axum::http::Uri>() {
        Ok(uri) => uri,
        Err(_) => return false,
    };
    let Some(name) = parsed.host() else {
        return false;
    };
    let name = name.trim_matches(['[', ']']).to_ascii_lowercase();
    // The plane serves plain HTTP: an `https` origin is a different origin
    // even on the same host and port (R-19 round 4, F14).
    if parsed.scheme_str() != Some("http") {
        return false;
    }
    let default_port = 80;
    let port = parsed.port_u16().unwrap_or(default_port);
    match host.and_then(host_parts) {
        // The dashboard's own origin: the browser sent both, and they must agree.
        Some((expected, expected_port)) => {
            expected
                .trim_matches(['[', ']'])
                .eq_ignore_ascii_case(&name)
                && expected_port == port
        }
        // A client that sends `Origin` without `Host` (a raw script) still has
        // to name a loopback origin.
        None => matches!(name.as_str(), "127.0.0.1" | "localhost" | "::1"),
    }
}

/// True when `origin` names this machine (used by tests and by the WS check).
pub fn loopback_origin(origin: &str) -> bool {
    same_origin(origin, None)
}

#[cfg(test)]
mod tests {
    use super::{is_loopback_host, loopback_origin, same_origin};

    #[test]
    fn only_loopback_hosts_are_accepted_for_websockets() {
        assert!(loopback_origin("http://127.0.0.1:8787"));
        assert!(loopback_origin("http://localhost:8787"));
        assert!(loopback_origin("http://[::1]:8787"));
        assert!(!loopback_origin("http://127.0.0.1.evil.com"));
        assert!(!loopback_origin("https://evil.com/http://127.0.0.1"));
        assert!(!loopback_origin("null"));
    }

    #[test]
    fn a_host_header_names_this_machine_or_it_does_not() {
        for host in [
            "127.0.0.1:8787",
            "127.0.0.1",
            "localhost:8787",
            "LOCALHOST",
            "[::1]:8787",
            "[::1]",
        ] {
            assert!(is_loopback_host(host), "{host} should be accepted");
        }
        for host in [
            "evil.example",
            "127.0.0.1.evil.example",
            "::1",
            "[::1]evil",
            "[2001:db8::1]:8787",
            "",
        ] {
            assert!(!is_loopback_host(host), "{host} should be refused");
        }
    }

    #[test]
    fn a_frozen_worker_reads_as_stale() {
        use super::{Heartbeat, STALE_WORKER_AFTER};
        use std::time::Duration;

        let mut beat = Heartbeat::new(10);
        assert!(beat.observe_within(11, Duration::from_secs(60)));
        assert!(beat.observe_within(11, Duration::from_millis(50)));
        std::thread::sleep(Duration::from_millis(60));
        assert!(!beat.observe_within(11, Duration::from_millis(50)));
        // A new uptime clears the staleness.
        assert!(beat.observe_within(12, Duration::from_millis(50)));
        // The production limit is generous enough for a one-second tick.
        assert!(STALE_WORKER_AFTER >= Duration::from_secs(3));
    }

    #[test]
    fn a_lag_frame_names_the_hole() {
        let frame = super::gap_frame(7, 1_234);
        let parsed: serde_json::Value = serde_json::from_str(&frame).expect("json");
        assert_eq!(parsed["kind"], "event_gap");
        assert_eq!(parsed["code"], "rpc/audit-gap");
        assert_eq!(parsed["skipped"], 7);
        assert_eq!(parsed["ts_ms"], 1_234);
    }

    #[test]
    fn the_origin_must_share_the_host_and_the_port() {
        assert!(same_origin("http://127.0.0.1:8787", Some("127.0.0.1:8787")));
        // The plane serves plain HTTP: an `https` origin is a different
        // origin even on the same host (R-19 round 4, F14).
        assert!(!same_origin("https://localhost", Some("localhost:443")));
        assert!(!same_origin("https://localhost:443", Some("localhost")));
        assert!(same_origin("http://[::1]:8787", Some("[::1]:8787")));
        // Another local program is another principal.
        assert!(!same_origin(
            "http://127.0.0.1:9999",
            Some("127.0.0.1:8787")
        ));
        assert!(!same_origin(
            "http://localhost:8787",
            Some("127.0.0.1:8787")
        ));
        assert!(!same_origin(
            "http://127.0.0.1.evil.example:8787",
            Some("127.0.0.1:8787")
        ));
        assert!(!same_origin("null", Some("127.0.0.1:8787")));
        assert!(!same_origin("ftp://127.0.0.1:8787", Some("127.0.0.1:8787")));
    }
}

#[cfg(test)]
mod ring_arithmetic_tests {
    use super::{ring_gap, ring_truncated};

    #[test]
    fn a_cursor_below_the_dropped_high_water_mark_is_a_gap() {
        // A protected event can pin `oldest` at 37 while ids up to 40 were
        // dropped: a cursor at 36 has a hole in front of it even though
        // `cursor + 1 == oldest` (R-19 round 3, M1).
        assert!(ring_gap(36, 40));
        assert!(ring_gap(0, 1));
        // A cursor at or past the high-water mark has nothing missing.
        assert!(!ring_gap(40, 40));
        assert!(!ring_gap(41, 40));
        assert!(!ring_gap(0, 0));
    }

    #[test]
    fn truncation_is_any_eviction() {
        assert!(!ring_truncated(0));
        assert!(ring_truncated(1));
    }
}

#[cfg(test)]
mod worker_panic_tests {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use super::{publish_snapshot, snapshot, AppState, Command, CommandFailure, Heartbeat};
    use crate::plane::PlaneCore;
    use tokio::sync::broadcast;

    /// The three cells `publish_snapshot` writes through, plus the down flag.
    type PublishCells = (
        Arc<Mutex<crate::plane::Snapshot>>,
        broadcast::Sender<crate::plane::Snapshot>,
        Arc<Mutex<Heartbeat>>,
        AtomicBool,
    );

    fn cell(core: &mut PlaneCore) -> PublishCells {
        let latest = Arc::new(Mutex::new(core.snapshot()));
        let (broadcast, _) = broadcast::channel(8);
        let heartbeat = Arc::new(Mutex::new(Heartbeat::new(0)));
        (latest, broadcast, heartbeat, AtomicBool::new(false))
    }

    /// A panic inside `snapshot()` used to escape `catch_unwind`, kill the
    /// worker thread and leave `latest` frozen with `kernel: "up"`. It must be
    /// contained, and the down flag must survive later ticks (R-19 round 3, M2).
    #[test]
    fn a_panicking_snapshot_sticks_the_kernel_down() {
        let mut core = PlaneCore::new();
        let (latest, broadcast, heartbeat, down) = cell(&mut core);
        core.panic_next_snapshot();
        let outcome = publish_snapshot(&mut core, &latest, &broadcast, &heartbeat, &down);
        assert!(
            matches!(outcome, Err(CommandFailure::Panicked)),
            "the panic must be reported as a worker failure"
        );
        assert!(down.load(Ordering::SeqCst));
        assert_eq!(
            latest.lock().expect("latest").health.kernel,
            "down",
            "the published snapshot must name the dead kernel"
        );
        // The next tick succeeds, but a sticky failure must not turn "up".
        let outcome = publish_snapshot(&mut core, &latest, &broadcast, &heartbeat, &down);
        assert!(outcome.is_ok());
        assert_eq!(latest.lock().expect("latest").health.kernel, "down");
    }

    /// A reader must see the sticky flag even when the published snapshot is
    /// older than the panic.
    #[test]
    fn a_reader_sees_down_after_the_flag_is_set() {
        let mut core = PlaneCore::new();
        let (latest, broadcast, heartbeat, down) = cell(&mut core);
        let (tx, _rx) = crossbeam_channel::bounded::<Command>(1);
        let state = AppState {
            tx,
            latest: Arc::clone(&latest),
            broadcast,
            read_only: false,
            heartbeat,
            down: Arc::new(down),
            observers: Arc::new(AtomicU64::new(3)),
        };
        // The stored snapshot still says "up"; the flag from a caught panic is
        // what every read route consults.
        assert_eq!(latest.lock().expect("latest").health.kernel, "up");
        state.down.store(true, Ordering::SeqCst);
        let served = snapshot(&state);
        assert_eq!(served.health.kernel, "down");
        assert_eq!(
            served.health.observers, 3,
            "observers come from the live count"
        );
    }

    /// A caught panic maps to 500; a command the core refused maps to 400.
    #[test]
    fn a_worker_panic_is_a_server_error() {
        use axum::http::StatusCode;
        assert_eq!(
            CommandFailure::Panicked.status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            CommandFailure::Refused("bad level".to_string()).status(),
            StatusCode::BAD_REQUEST
        );
    }
}

#[cfg(test)]
mod round4_tests {
    use super::{since_envelope, CommandFailure};

    /// A cursor above every id names another plane process: it is a gap, and
    /// the cursor restarts so the next poll sees the window
    /// (R-19 round 4, F8).
    #[test]
    fn a_cursor_from_a_previous_epoch_is_a_gap() {
        let stale = since_envelope(Vec::new(), 9_000, 1, 0, 12);
        assert_eq!(stale["gap"], serde_json::Value::Bool(true));
        assert_eq!(stale["cursor"], serde_json::Value::from(0u64));
        // A current cursor with nothing new is not a gap.
        let current = since_envelope(Vec::new(), 12, 1, 0, 12);
        assert_eq!(current["gap"], serde_json::Value::Bool(false));
        assert_eq!(current["cursor"], serde_json::Value::from(12u64));
    }

    /// A plane-side failure is a 500; the caller's mistake stays a 400
    /// (R-19 round 4, F4).
    #[test]
    fn a_plane_side_failure_is_a_server_error() {
        use axum::http::StatusCode;
        assert_eq!(
            CommandFailure::Internal("encode".to_string()).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            CommandFailure::Refused("unknown scenario".to_string()).status(),
            StatusCode::BAD_REQUEST
        );
    }
}
