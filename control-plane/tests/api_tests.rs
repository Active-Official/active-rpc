//! HTTP surface tests against the real worker and kernel.

use active_control_plane::server::{app, spawn_worker};
use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use serde_json::Value as Json;
use tower::ServiceExt;

async fn body_json(response: axum::response::Response) -> Json {
    let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

#[tokio::test]
async fn logs_tail_since_activity_and_engines_are_served() {
    let app = app(spawn_worker(false));

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/logs/tail?n=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let tail = body_json(response).await;
    assert!(tail["count"].as_u64().unwrap() <= 2);
    assert!(tail["events"].is_array());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/activity")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let activity = body_json(response).await;
    assert!(activity["mode"].is_string());
    assert!(activity["lanes"].is_array());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/engines")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let engines = body_json(response).await;
    assert_eq!(engines["lanes"].as_array().unwrap().len(), 4);
    assert_eq!(engines["channels"].as_array().unwrap().len(), 2);
    assert!(engines.get("nodes").is_none());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/logs/since?id=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let since = body_json(response).await;
    assert!(since["cursor"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn jsonl_export_contains_structured_lines() {
    let app = app(spawn_worker(false));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/logs/export.jsonl")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/x-ndjson; charset=utf-8"
    );
    let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(!text.is_empty());
    for line in text.lines() {
        let value: Json = serde_json::from_str(line).expect("jsonl line");
        assert!(value["id"].as_u64().unwrap() > 0);
        assert!(value["category"].is_string());
        assert!(value["detail"].is_string());
    }
}

#[tokio::test]
async fn read_only_mode_refuses_scenario_posts() {
    let app = app(spawn_worker(true));
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/demo/scenario/round-trip")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/benchmark/run")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{\"iterations\":5}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/demo/level/0?up_to=false")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let health = body_json(response).await;
    assert_eq!(health["read_only"], true);
    assert_eq!(health["mode"], "read-only");
}

#[tokio::test]
async fn a_scenario_post_returns_the_real_result_envelope() {
    let app = app(spawn_worker(false));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/demo/scenario/round-trip")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value = body_json(response).await;
    assert_eq!(value["result"]["code"], "L0.1");
    assert_eq!(value["result"]["ok"], true);
    assert!(value["metrics"]["calls_queued"].is_u64());
}

/// A request addressed at a foreign Host is refused: a loopback bind does not
/// stop DNS rebinding, where the page's requests arrive at 127.0.0.1 carrying
/// the attacker's name.
#[tokio::test]
async fn a_foreign_host_is_refused() {
    let app = app(spawn_worker(false));
    let request = Request::builder()
        .uri("/health")
        .header("host", "evil.example")
        .body(Body::empty())
        .expect("request");
    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// A mutating request from another origin is refused, and one from loopback is
/// allowed.
#[tokio::test]
async fn a_cross_origin_post_is_refused() {
    let app = app(spawn_worker(false));
    let foreign = Request::builder()
        .method("POST")
        .uri("/demo/scenario/round-trip")
        .header("origin", "https://evil.example")
        .body(Body::empty())
        .expect("request");
    let response = app.clone().oneshot(foreign).await.expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let local = Request::builder()
        .method("POST")
        .uri("/demo/scenario/round-trip")
        .header("origin", "http://127.0.0.1:8787")
        .body(Body::empty())
        .expect("request");
    let response = app.oneshot(local).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

/// The static fallback is a route too: `Router::layer` only covered what had
/// been added before it, so `/app.js` used to answer 200 to a rebound name.
#[tokio::test]
async fn a_static_asset_with_a_foreign_host_is_refused() {
    let app = app(spawn_worker(false));
    for uri in ["/", "/app.js", "/style.css"] {
        let request = Request::builder()
            .uri(uri)
            .header("host", "evil.example")
            .body(Body::empty())
            .expect("request");
        let response = app.clone().oneshot(request).await.expect("response");
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{uri} answered a foreign Host"
        );
    }
    let request = Request::builder()
        .uri("/app.js")
        .body(Body::empty())
        .expect("request");
    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

/// A framed dashboard defeats the Host and Origin checks with one click: the
/// click comes from the framed document, so both headers are the plane's own.
#[tokio::test]
async fn every_response_refuses_framing() {
    let app = app(spawn_worker(false));
    for uri in ["/", "/app.js", "/health", "/metrics"] {
        let request = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request");
        let response = app.clone().oneshot(request).await.expect("response");
        let headers = response.headers();
        assert_eq!(
            headers.get("x-frame-options").and_then(|v| v.to_str().ok()),
            Some("DENY"),
            "{uri} can be framed"
        );
        let csp = headers
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            csp.contains("frame-ancestors 'none'"),
            "{uri} has no frame-ancestors: {csp}"
        );
        assert_eq!(
            headers
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );
    }
}

/// Another local program is another principal: a loopback Origin on a different
/// port is not this dashboard's own origin.
#[tokio::test]
async fn a_loopback_origin_on_another_port_is_refused() {
    let app = app(spawn_worker(false));
    let request = Request::builder()
        .method("POST")
        .uri("/demo/scenario/round-trip")
        .header("host", "127.0.0.1:8787")
        .header("origin", "http://127.0.0.1:9999")
        .body(Body::empty())
        .expect("request");
    let response = app.clone().oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let request = Request::builder()
        .method("POST")
        .uri("/demo/scenario/round-trip")
        .header("host", "127.0.0.1:8787")
        .header("origin", "http://127.0.0.1:8787")
        .body(Body::empty())
        .expect("request");
    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

/// `/health` must not answer `ok` for a snapshot that stopped moving.
#[tokio::test]
async fn a_down_kernel_reads_as_unhealthy() {
    let state = spawn_worker(false);
    state.latest.lock().expect("snapshot").health.kernel = "down".to_string();
    let app = app(state);
    let request = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .expect("request");
    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["ok"], serde_json::json!(false));
    assert_eq!(body["redaction_ok"], serde_json::json!(true));
}

/// `/logs/since` says when the ring dropped the events the caller asked for.
#[tokio::test]
async fn logs_since_reports_a_ring_gap() {
    let app = app(spawn_worker(false));
    // A cursor far in the future is not a gap (nothing has been skipped), while
    // a zero cursor on a full ring is: the envelopes must carry `oldest` so a
    // caller can tell the two apart.
    let request = Request::builder()
        .uri("/logs/since?id=0")
        .body(Body::empty())
        .expect("request");
    let response = app.oneshot(request).await.expect("response");
    let body = body_json(response).await;
    assert!(body["oldest"].as_u64().is_some());
    assert_eq!(body["gap"], serde_json::json!(false));
}
