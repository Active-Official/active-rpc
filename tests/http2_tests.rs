//! Native HTTP/2 transport carrying ARP1 envelopes.
//!
//! These tests drive the shipped server and client over a real TCP socket: one
//! call, multiplexed concurrent calls on one connection, and the negative paths
//! a restricted network will eventually produce.

#![cfg(feature = "http2")]

use active_rpc::transport::http2::{Http2Client, Http2Server, CONTENT_TYPE, PATH};
use active_rpc::value::{Arg, Value};
use active_rpc::{Envelope, Kind, WireLimits};

fn sample_envelope(request_id: u64) -> Envelope {
    Envelope::request(
        request_id,
        "echo",
        vec![Arg::value(Value::text(format!("call-{request_id}")))],
    )
    .with_payload(vec![0x41, 0x52, 0x50, 0x31])
    .with_caps(Vec::new())
}

fn handler(envelope: Envelope) -> Envelope {
    let value = envelope.first_value().cloned().unwrap_or(Value::Null);
    Envelope::response(envelope.request_id, value).with_payload(envelope.payload.clone())
}

#[test]
fn http2_moves_an_envelope_and_returns_the_same_payload() {
    let server = Http2Server::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let serve = std::thread::spawn(move || server.serve(1, handler));

    let mut client = Http2Client::connect(&address).expect("connect");
    let request = sample_envelope(7);
    let response = client.call(&request).expect("call");
    assert_eq!(response.kind, Kind::Response);
    assert_eq!(response.request_id, 7);
    assert_eq!(response.first_value(), Some(&Value::text("call-7")));
    assert_eq!(response.payload, request.payload);
    drop(client);

    let served = serve.join().expect("join").expect("serve");
    assert_eq!(served, 1, "one request served");
}

#[test]
fn http2_carries_concurrent_streams_on_one_connection_in_request_order() {
    let server = Http2Server::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let serve = std::thread::spawn(move || server.serve(1, handler));

    let mut client = Http2Client::connect(&address).expect("connect");
    let requests: Vec<Envelope> = (1..=8).map(sample_envelope).collect();
    let responses = client.call_many(&requests).expect("multiplexed calls");
    assert_eq!(responses.len(), requests.len());
    for (index, response) in responses.iter().enumerate() {
        let id = index as u64 + 1;
        assert_eq!(response.request_id, id);
        assert_eq!(
            response.first_value(),
            Some(&Value::text(format!("call-{id}")))
        );
    }
    drop(client);

    let served = serve.join().expect("join").expect("serve");
    assert_eq!(served, 8, "eight streams on one connection");
}

#[test]
fn http2_rejects_a_wrong_path_a_wrong_media_type_and_a_malformed_body() {
    let server = Http2Server::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let serve = std::thread::spawn(move || server.serve(1, handler));

    let mut client = Http2Client::connect(&address).expect("connect");

    let (status, body) = client
        .request_raw("/not-the-service", CONTENT_TYPE, b"\x00")
        .expect("wrong path");
    assert_eq!(status.as_u16(), 404);
    assert_eq!(body, b"rpc/wire");

    let (status, body) = client
        .request_raw(PATH, "text/plain", b"\x00")
        .expect("wrong media type");
    assert_eq!(status.as_u16(), 415);
    assert_eq!(body, b"rpc/wire");

    let (status, body) = client
        .request_raw(PATH, CONTENT_TYPE, b"\xff\xff\xff")
        .expect("malformed body");
    assert_eq!(status.as_u16(), 400);
    assert_eq!(body, b"rpc/wire");

    // A request that does reach the handler is still answered normally.
    let response = client.call(&sample_envelope(3)).expect("valid call");
    assert_eq!(response.request_id, 3);

    drop(client);
    serve.join().expect("join").expect("serve");
}

/// A peer that connects and never sends the preface is dropped at the
/// connection deadline instead of holding the serve task (round 24, F2).
#[test]
fn a_silent_connection_is_dropped_at_the_deadline() {
    use std::time::{Duration, Instant};

    let server = Http2Server::bind_loopback()
        .expect("bind")
        .with_connection_deadline(Duration::from_millis(50));
    let address = server.address().to_string();
    let serve = std::thread::spawn(move || server.serve(1, handler));
    let quiet = std::net::TcpStream::connect(&address).expect("connect");
    let started = Instant::now();
    let served = serve.join().expect("join").expect("serve");
    assert_eq!(served, 0, "a silent peer served nothing");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "serve held for {:?}",
        started.elapsed()
    );
    drop(quiet);
}

/// A server that accepts, takes the preface and never answers cannot park the
/// call: the exchange has a deadline even when the caller set none
/// (round 25, #3). The client preface itself does not wait for the peer's
/// settings, so the bound is the header wait, not the connect.
#[test]
fn a_silent_h2_server_fails_the_call_within_the_deadline() {
    use std::time::{Duration, Instant};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address").to_string();
    let hold = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        std::thread::sleep(Duration::from_secs(4));
        drop(stream);
    });
    let mut client = Http2Client::connect(&address).expect("the preface does not wait");
    client = client.with_deadline(Duration::from_millis(200));
    let started = Instant::now();
    let error = client.call(&sample_envelope(1)).expect_err("a silent peer");
    assert_eq!(error.code(), "rpc/transport", "{error}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the call waited {:?}",
        started.elapsed()
    );
    hold.join().ok();
}

/// A query string names a different target than the service path, as the
/// HTTP/1.1 bridge already treats it (round 26, #2).
#[test]
fn http2_rejects_a_query_string_on_the_service_path() {
    let server = Http2Server::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let serve = std::thread::spawn(move || server.serve(1, handler));
    let mut client = Http2Client::connect(&address).expect("connect");
    let body = sample_envelope(6).encode().expect("encode");
    let (status, body) = client
        .request_raw(&format!("{PATH}?x=1"), CONTENT_TYPE, &body)
        .expect("query");
    assert_eq!(status.as_u16(), 404);
    assert_eq!(body, b"rpc/wire");
    drop(client);
    serve.join().expect("join").expect("serve");
}

/// A request body past the ceiling is refused before it is written
/// (round 26, #4).
#[test]
fn http2_refuses_an_oversized_request_before_sending() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address").to_string();
    let hold = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        std::thread::sleep(std::time::Duration::from_secs(2));
        drop(stream);
    });
    let mut client = Http2Client::connect(&address)
        .expect("connect")
        .with_limits(WireLimits::strict());
    let body = vec![0u8; 2 << 20];
    let error = client
        .request_raw(PATH, CONTENT_TYPE, &body)
        .expect_err("over the ceiling");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    hold.join().ok();
}

#[test]
fn http2_enforces_wire_limits_from_the_server_side() {
    let server = Http2Server::bind_loopback()
        .expect("bind")
        .with_limits(WireLimits::strict());
    let address = server.address().to_string();
    let serve = std::thread::spawn(move || server.serve(1, handler));

    let mut client = Http2Client::connect(&address).expect("connect");
    let oversized = Envelope::request(1, "x".repeat(256), Vec::new());
    let body = oversized.encode().expect("encode");
    let (status, body) = client
        .request_raw(PATH, CONTENT_TYPE, &body)
        .expect("oversized method");
    assert_eq!(status.as_u16(), 400);
    assert_eq!(body, b"rpc/wire");

    drop(client);
    serve.join().expect("join").expect("serve");
}

/// A connection over its in-flight budget answers backpressure, not a wire
/// fault: `rpc/wire` is fatal to a client, and a healthy server under load
/// must not be abandoned as hostile (round 24, F8).
#[test]
fn an_inflight_budget_refusal_is_backpressure() {
    let server = Http2Server::bind_loopback()
        .expect("bind")
        .with_inflight_budget(1);
    let address = server.address().to_string();
    let serve = std::thread::spawn(move || server.serve(1, handler));

    let mut client = Http2Client::connect(&address).expect("connect");
    let body = sample_envelope(5).encode().expect("encode");
    let (status, body) = client
        .request_raw(PATH, CONTENT_TYPE, &body)
        .expect("over budget");
    assert_eq!(status.as_u16(), 429);
    assert_eq!(body, b"rpc/backpressure");
    drop(client);
    serve.join().expect("join").expect("serve");
}

#[test]
fn one_bad_stream_does_not_break_the_connection() {
    let server = Http2Server::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let serve = std::thread::spawn(move || server.serve(1, handler));

    let mut client = Http2Client::connect(&address).expect("connect");
    let first = client.call(&sample_envelope(1)).expect("first call");
    assert_eq!(first.request_id, 1);

    let (status, body) = client
        .request_raw(PATH, CONTENT_TYPE, b"\xff\xff\xff")
        .expect("malformed stream");
    assert_eq!(status.as_u16(), 400);
    assert_eq!(body, b"rpc/wire");

    let second = client
        .call(&sample_envelope(2))
        .expect("connection survives");
    assert_eq!(second.request_id, 2);
    drop(client);
    let served = serve.join().expect("join").expect("serve");
    assert_eq!(served, 2, "only well-formed requests are counted");
}

#[test]
fn two_clients_are_served_while_the_first_connection_stays_open() {
    use std::sync::mpsc;
    use std::time::Duration;

    let server = Http2Server::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let serve = std::thread::spawn(move || server.serve(2, handler));

    let (tx, rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut first = Http2Client::connect(&address).expect("first connect");
        let first_response = first.call(&sample_envelope(1)).expect("first call");
        // Keep `first` open: a serial accept loop would never reach the second
        // client until this connection closed.
        let mut second = Http2Client::connect(&address).expect("second connect");
        let second_response = second.call(&sample_envelope(2)).expect("second call");
        tx.send((first_response.request_id, second_response.request_id))
            .ok();
        drop(first);
        drop(second);
    });

    let (first, second) = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("both clients served concurrently");
    assert_eq!((first, second), (1, 2));
    worker.join().expect("worker");
    let served = serve.join().expect("join").expect("serve");
    assert_eq!(served, 2);
}

#[test]
fn http2_client_surfaces_a_server_error_envelope_code() {
    let server = Http2Server::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let serve = std::thread::spawn(move || {
        server.serve(1, |envelope| {
            Envelope::error(envelope.request_id, &active_rpc::Error::Timeout)
        })
    });

    let mut client = Http2Client::connect(&address).expect("connect");
    let response = client.call(&sample_envelope(9)).expect("call");
    assert_eq!(response.kind, Kind::Error);
    assert_eq!(response.method, "rpc/timeout");
    drop(client);
    serve.join().expect("join").expect("serve");
}
