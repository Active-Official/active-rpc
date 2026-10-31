#![cfg(feature = "http2")]

//! HTTP/2 amplification budgets: header lists, field counts and in-flight bodies.
//!
//! An HPACK block expands: a few bytes on the wire can decode to a header list
//! larger than the frame that carried it, and a peer can open the allowed number
//! of streams with the largest allowed body. Both are refusal paths here, and
//! neither may reach the handler.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use active_rpc::transport::http2::{
    Http2Client, Http2Server, CONTENT_TYPE, MAX_HEADER_FIELDS, MAX_HEADER_LIST, PATH,
};
use active_rpc::wire::Envelope;
use active_rpc::Value;

fn echo(envelope: Envelope) -> Envelope {
    Envelope::response(envelope.request_id, Value::text("pong"))
}

#[test]
fn a_header_field_over_the_budget_never_reaches_the_handler() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let server = Http2Server::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let handle = std::thread::spawn(move || {
        server
            .serve(1, move |envelope| {
                counter.fetch_add(1, Ordering::SeqCst);
                echo(envelope)
            })
            .expect("serve")
    });

    let mut client = Http2Client::connect(&address).expect("connect");
    // One field of 40 KiB: over the 32 KiB decoded-list budget, and legal HTTP/2
    // until the receiver's SETTINGS say otherwise.
    let pad = "a".repeat(40 << 10);
    let refused = client.request_with_headers(PATH, CONTENT_TYPE, &[("x-pad", pad.as_str())], &[]);
    match refused {
        // Either the server refused the stream with a status...
        Ok((status, body)) => {
            assert_eq!(status.as_u16(), 431, "expected 431, body {body:?}");
        }
        // ...or the HTTP/2 layer reset it per our advertised limit.
        Err(error) => {
            let text = format!("{error:?}");
            assert!(
                text.contains("h2") || text.contains("stream") || text.contains("reset"),
                "expected an HTTP/2 refusal, got {text}"
            );
        }
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "an oversized header list must not reach the provider"
    );
    drop(client);
    handle.join().expect("server thread");
}

#[test]
fn too_many_header_fields_are_refused() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let server = Http2Server::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let handle = std::thread::spawn(move || {
        server
            .serve(1, move |envelope| {
                counter.fetch_add(1, Ordering::SeqCst);
                echo(envelope)
            })
            .expect("serve")
    });

    let mut client = Http2Client::connect(&address).expect("connect");
    // 200 small fields: under the byte budget, over the field-count budget.
    let names: Vec<String> = (0..200).map(|index| format!("x-pad-{index}")).collect();
    let headers: Vec<(&str, &str)> = names.iter().map(|name| (name.as_str(), "v")).collect();
    assert!(headers.len() > MAX_HEADER_FIELDS);
    let refused = client.request_with_headers(PATH, CONTENT_TYPE, &headers, &[]);
    if let Ok((status, _)) = refused {
        assert_eq!(status.as_u16(), 431);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    drop(client);
    handle.join().expect("server thread");
}

#[test]
fn a_normal_call_is_served_after_a_header_refusal() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let server = Http2Server::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let handle = std::thread::spawn(move || {
        server
            .serve(2, move |envelope| {
                counter.fetch_add(1, Ordering::SeqCst);
                echo(envelope)
            })
            .expect("serve")
    });

    // First connection: an oversized header list.
    let mut bad = Http2Client::connect(&address).expect("connect");
    let pad = "b".repeat(MAX_HEADER_LIST as usize + 1024);
    let _ = bad.request_with_headers(PATH, CONTENT_TYPE, &[("x-pad", pad.as_str())], &[]);
    drop(bad);

    // Second connection: a well-formed call still works.
    let mut good = Http2Client::connect(&address).expect("connect");
    let response = good
        .call(&Envelope::request(7, "ping", vec![]))
        .expect("a normal call is served after a refused one");
    assert_eq!(response.first_value(), Some(&Value::text("pong")));
    assert_eq!(calls.load(Ordering::SeqCst), 1, "only the good call ran");
    drop(good);
    handle.join().expect("server thread");
}

#[test]
fn a_body_over_the_connection_budget_is_refused_with_429() {
    // A tight budget makes the refusal deterministic with one stream: 200 KiB
    // of body against a 64 KiB connection budget.
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let server = Http2Server::bind_loopback()
        .expect("bind")
        .with_inflight_budget(64 << 10);
    let address = server.address().to_string();
    let handle = std::thread::spawn(move || {
        server
            .serve(1, move |envelope| {
                counter.fetch_add(1, Ordering::SeqCst);
                echo(envelope)
            })
            .expect("serve")
    });

    let mut client = Http2Client::connect(&address).expect("connect");
    let body = vec![0u8; 200 << 10];
    let (status, response) = client
        .request_raw(PATH, CONTENT_TYPE, &body)
        .expect("the server answers rather than resetting");
    assert_eq!(
        status.as_u16(),
        429,
        "a body over the connection budget is backpressure, got {response:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "the handler never ran");
    drop(client);
    handle.join().expect("server thread");
}

#[test]
fn a_body_within_the_budget_is_served() {
    let server = Http2Server::bind_loopback()
        .expect("bind")
        .with_inflight_budget(64 << 10);
    let address = server.address().to_string();
    let handle = std::thread::spawn(move || server.serve(1, echo).expect("serve"));

    let mut client = Http2Client::connect(&address).expect("connect");
    let response = client
        .call(&Envelope {
            payload: vec![0x7f; 32 << 10],
            ..Envelope::request(5, "ping", vec![])
        })
        .expect("a body under the budget is served");
    assert_eq!(response.first_value(), Some(&Value::text("pong")));
    drop(client);
    handle.join().expect("server thread");
}

#[test]
fn the_header_budget_is_generous_for_real_requests() {
    // The same call with tracing-sized headers is served: the budget must not
    // be a foot-gun for a normal proxy.
    let server = Http2Server::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let handle = std::thread::spawn(move || server.serve(1, echo).expect("serve"));

    let mut client = Http2Client::connect(&address).expect("connect");
    let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let (status, body) = client
        .request_with_headers(
            PATH,
            CONTENT_TYPE,
            &[
                ("traceparent", traceparent),
                ("tracestate", "active=1"),
                ("x-request-id", "0123456789abcdef"),
            ],
            &Envelope::request(3, "ping", vec![])
                .encode()
                .expect("encode"),
        )
        .expect("a normal request with tracing headers");
    assert_eq!(status.as_u16(), 200, "body {body:?}");
    drop(client);
    handle.join().expect("server thread");
}
