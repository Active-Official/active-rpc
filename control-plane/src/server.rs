//! HTTP, WebSocket and static dashboard adapters around [`PlaneCore`].
//!
//! The kernel is not `Send`, so it runs on one worker thread. Handlers exchange
//! immutable [`Snapshot`] values with that thread; no kernel borrow crosses a
//! thread boundary.

use std::net::SocketAddr;
use std::path::PathBuf;
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
        tokio::sync::oneshot::Sender<Result<ScenarioResult, String>>,
    ),
    Level(u8, bool, tokio::sync::oneshot::Sender<Vec<ScenarioResult>>),
    Benchmark(
        usize,
        tokio::sync::oneshot::Sender<Result<BenchmarkReport, String>>,
    ),
    Status(tokio::sync::oneshot::Sender<Result<serde_json::Value, String>>),
}

#[derive(Clone)]
pub struct AppState {
    pub tx: Sender<Command>,
    pub latest: Arc<Mutex<Snapshot>>,
    pub broadcast: broadcast::Sender<Snapshot>,
    pub read_only: bool,
}

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
    let initial = {
        let mut core = PlaneCore::new();
        core.set_mode(if read_only { "read-only" } else { "demo" });
        core.snapshot()
    };
    let latest = Arc::new(Mutex::new(initial));
    let latest_thread = Arc::clone(&latest);
    let broadcast_thread = broadcast.clone();
    std::thread::Builder::new()
        .name("active-kernel".into())
        .spawn(move || {
            let mut core = PlaneCore::new();
            core.set_mode(if read_only { "read-only" } else { "demo" });
            let publish = |core: &mut PlaneCore,
                           latest: &Arc<Mutex<Snapshot>>,
                           broadcast: &broadcast::Sender<Snapshot>| {
                let snapshot = core.snapshot();
                if let Ok(mut guard) = latest.lock() {
                    *guard = snapshot.clone();
                }
                let _ = broadcast.send(snapshot);
            };
            publish(&mut core, &latest_thread, &broadcast_thread);
            loop {
                match rx.recv_timeout(Duration::from_secs(1)) {
                    Ok(Command::Scenario(id, reply)) => {
                        let result = core.run_scenario(&id);
                        publish(&mut core, &latest_thread, &broadcast_thread);
                        let _ = reply.send(result);
                    }
                    Ok(Command::Level(level, up_to, reply)) => {
                        let results = core.run_level(level, up_to);
                        publish(&mut core, &latest_thread, &broadcast_thread);
                        let _ = reply.send(results);
                    }
                    Ok(Command::Benchmark(iterations, reply)) => {
                        let result = core.run_benchmark(iterations);
                        publish(&mut core, &latest_thread, &broadcast_thread);
                        let _ = reply.send(result);
                    }
                    Ok(Command::Status(reply)) => {
                        let result = core.status_module_json();
                        let _ = reply.send(result);
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        publish(&mut core, &latest_thread, &broadcast_thread);
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
        })
        .expect("kernel worker thread");
    AppState {
        tx,
        latest,
        broadcast,
        read_only,
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
        .fallback_service(ServeDir::new(static_dir))
}

fn snapshot(state: &AppState) -> Snapshot {
    state.latest.lock().expect("snapshot").clone()
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let snapshot = snapshot(&state);
    Json(json!({
        "ok": snapshot.health.kernel == "up",
        "mode": snapshot.health.mode,
        "read_only": state.read_only,
        "redaction_ok": snapshot.health.redaction_ok,
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

async fn logs_tail(
    State(state): State<AppState>,
    Query(query): Query<TailQuery>,
) -> impl IntoResponse {
    let snapshot = snapshot(&state);
    let limit = query.n.unwrap_or(200).clamp(1, 500);
    let start = snapshot.events.len().saturating_sub(limit);
    let events = snapshot.events[start..].to_vec();
    let cursor = events.last().map(|event| event.id).unwrap_or(0);
    Json(json!({"count": events.len(), "cursor": cursor, "events": events}))
}

async fn logs_since(
    State(state): State<AppState>,
    Query(query): Query<SinceQuery>,
) -> impl IntoResponse {
    let snapshot = snapshot(&state);
    let cursor = query.id.unwrap_or(0);
    let events: Vec<_> = snapshot
        .events
        .into_iter()
        .filter(|event| event.id > cursor)
        .collect();
    let cursor = events.last().map(|event| event.id).unwrap_or(cursor);
    Json(json!({"count": events.len(), "cursor": cursor, "events": events}))
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
        Ok(Ok(Err(error))) => (StatusCode::BAD_REQUEST, error).into_response(),
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
        Ok(Ok(results)) => {
            let snapshot = snapshot(&state);
            Json(json!({
                "level": level,
                "up_to": query.up_to,
                "results": results,
                "metrics": snapshot.metrics,
            }))
            .into_response()
        }
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
        Ok(Ok(Err(error))) => (StatusCode::BAD_REQUEST, error).into_response(),
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
        Ok(Ok(Ok(value))) => Json(value).into_response(),
        Ok(Ok(Err(error))) => (StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
        Ok(Err(_)) => (StatusCode::INTERNAL_SERVER_ERROR, "status reply dropped").into_response(),
        Err(_) => (StatusCode::GATEWAY_TIMEOUT, "status timed out").into_response(),
    }
}

async fn ws(ws: WebSocketUpgrade, headers: HeaderMap, State(state): State<AppState>) -> Response {
    // Same-origin dashboard connections carry the loopback Origin. Refuse a
    // page loaded from another site, so a localhost plane is not readable by
    // any website the user happens to visit. Non-browser clients omit Origin.
    if let Some(origin) = headers.get("origin").and_then(|value| value.to_str().ok()) {
        if !loopback_origin(origin) {
            return (StatusCode::FORBIDDEN, "cross-origin websocket refused").into_response();
        }
    }
    ws.on_upgrade(move |socket| stream_socket(socket, state))
}

async fn stream_socket(mut socket: WebSocket, state: AppState) {
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
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
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

/// True only for an Origin whose parsed host is loopback.
///
/// Prefix matching is wrong here: `http://127.0.0.1.evil.com` starts with the
/// loopback string but is a different host.
pub fn loopback_origin(origin: &str) -> bool {
    let host = origin.parse::<axum::http::Uri>().ok().and_then(|uri| {
        uri.host()
            .map(|host| host.trim_matches(['[', ']']).to_ascii_lowercase())
    });
    matches!(
        host.as_deref(),
        Some("127.0.0.1") | Some("localhost") | Some("::1")
    )
}

#[cfg(test)]
mod tests {
    use super::loopback_origin;

    #[test]
    fn only_loopback_hosts_are_accepted_for_websockets() {
        assert!(loopback_origin("http://127.0.0.1:8787"));
        assert!(loopback_origin("http://localhost:8787"));
        assert!(loopback_origin("http://[::1]:8787"));
        assert!(!loopback_origin("http://127.0.0.1.evil.com"));
        assert!(!loopback_origin("https://evil.com/http://127.0.0.1"));
        assert!(!loopback_origin("null"));
    }
}
