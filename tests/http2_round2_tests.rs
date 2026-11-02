#![cfg(feature = "http2")]

//! R-09 round 4, HTTP/2: a stream that sends bytes and never finishes must not
//! pin the server-wide body budget or the connection task forever.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use active_rpc::transport::http2::{Http2Client, Http2Server, CONTENT_TYPE, PATH};
use active_rpc::wire::Envelope;
use active_rpc::Value;

fn echo(envelope: Envelope) -> Envelope {
    Envelope::response(envelope.request_id, Value::text("pong"))
}

/// A stalled stream releases its reservation when the inactivity deadline
/// fires, so a real call on another connection is served and `serve` returns.
#[test]
fn a_stalled_stream_releases_the_budget_and_the_connection() {
    // The budget fits one real call plus the stalled prefix, but not both at
    // once: while the stalled reservation is held the real call is refused.
    let stalled_body = 60usize;
    let real = Envelope::request(1, "ping", vec![])
        .encode()
        .expect("encode")
        .len();
    let budget = real + 1 + stalled_body / 2;

    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let server = Http2Server::bind_loopback()
        .expect("bind")
        .with_inflight_budget(budget)
        .with_connection_deadline(Duration::from_millis(300));
    let address = server.address().to_string();
    let handle = std::thread::spawn(move || {
        server
            .serve(2, move |envelope| {
                counter.fetch_add(1, Ordering::SeqCst);
                echo(envelope)
            })
            .expect("serve")
    });

    // Connection one: a request head, one body byte, and no END_STREAM.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let stream = tokio::net::TcpStream::connect(&address)
            .await
            .expect("connect");
        let (mut sender, connection) = h2::client::handshake(stream).await.expect("handshake");
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(PATH)
            .header(http::header::CONTENT_TYPE, CONTENT_TYPE)
            .body(())
            .expect("request");
        let (_response, mut body) = sender.send_request(request, false).expect("send");
        body.send_data(bytes::Bytes::from(vec![b'x'; stalled_body]), false)
            .expect("a prefix that pins the budget");
        // Hold the stream open; the server's inactivity deadline is the only end.
        tokio::time::sleep(Duration::from_millis(900)).await;
        drop(body);
        driver.abort();
    });

    // Connection two: a real call. It must not see `429` from the pinned budget.
    std::thread::sleep(Duration::from_millis(400));
    let mut client = Http2Client::connect(&address)
        .expect("connect")
        .with_deadline(Duration::from_secs(10));
    let response = client
        .call(&Envelope::request(1, "ping", vec![]))
        .expect("a real call is served while another stream is stalled");
    assert_eq!(response.first_value(), Some(&Value::text("pong")));

    // The server joins both connections instead of waiting for the stalled one
    // forever.
    let started = std::time::Instant::now();
    let _ = handle.join().expect("serve returns");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "serve waited {:?} after the deadline",
        started.elapsed()
    );
    assert!(calls.load(Ordering::SeqCst) >= 1);
}

/// A drip that stays inside the per-chunk inactivity bound must still end: the
/// body has a total deadline (eight inactivity windows, capped at 30 s), so the
/// reservation is released and `serve` joins.
#[test]
fn a_dripping_body_cannot_hold_the_http2_budget_forever() {
    let stalled_body = 60usize;
    let real = Envelope::request(1, "ping", vec![])
        .encode()
        .expect("encode")
        .len();
    let budget = real + 1 + stalled_body / 2;

    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let server = Http2Server::bind_loopback()
        .expect("bind")
        .with_inflight_budget(budget)
        .with_connection_deadline(Duration::from_millis(300));
    let address = server.address().to_string();
    let handle = std::thread::spawn(move || {
        server
            .serve(2, move |envelope| {
                counter.fetch_add(1, Ordering::SeqCst);
                echo(envelope)
            })
            .expect("serve")
    });

    // Connection one: a prefix, then one byte every 100 ms — inside the 300 ms
    // inactivity window, so only the total body deadline can end it.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let stream = tokio::net::TcpStream::connect(&address)
            .await
            .expect("connect");
        let (mut sender, connection) = h2::client::handshake(stream).await.expect("handshake");
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(PATH)
            .header(http::header::CONTENT_TYPE, CONTENT_TYPE)
            .body(())
            .expect("request");
        let (_response, mut body) = sender.send_request(request, false).expect("send");
        body.send_data(bytes::Bytes::from(vec![b'x'; stalled_body]), false)
            .expect("prefix");
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if body
                .send_data(bytes::Bytes::from_static(b"y"), false)
                .is_err()
            {
                break;
            }
        }
        drop(body);
        driver.abort();
    });

    // The stalled reservation is gone, so a real call on a second connection is
    // served.
    let mut client = Http2Client::connect(&address)
        .expect("connect")
        .with_deadline(Duration::from_secs(10));
    let response = client
        .call(&Envelope::request(1, "ping", vec![]))
        .expect("a real call is served after the drip ends");
    assert_eq!(response.first_value(), Some(&Value::text("pong")));

    let started = std::time::Instant::now();
    let _ = handle.join().expect("serve returns");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "serve waited {:?} after the deadlines",
        started.elapsed()
    );
    assert!(calls.load(Ordering::SeqCst) >= 1);
}
