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
