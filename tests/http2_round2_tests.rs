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
/// body has a total deadline (eight inactivity windows, capped at 30 s).
///
/// A second stream keeps issuing requests so the connection is not torn down by
/// the accept-inactivity deadline first; the body total is the only bound that
/// can end the drip, and the budget leaves room so a 429 cannot either.
#[test]
fn a_dripping_body_cannot_hold_the_http2_budget_forever() {
    let stalled_body = 60usize;
    let real = Envelope::request(1, "ping", vec![])
        .encode()
        .expect("encode")
        .len();
    // Room for the prefix, the drips and a real call.
    let budget = real + 1 + stalled_body + 4096;

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

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let drip_ended = runtime.block_on(async {
        let stream = tokio::net::TcpStream::connect(&address)
            .await
            .expect("connect");
        let (sender, connection) = h2::client::handshake(stream).await.expect("handshake");
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(PATH)
            .header(http::header::CONTENT_TYPE, CONTENT_TYPE)
            .body(())
            .expect("request");
        let (_response, mut body) = sender.clone().send_request(request, false).expect("send");
        body.send_data(bytes::Bytes::from(vec![b'x'; stalled_body]), false)
            .expect("prefix");

        let mut sent = 0usize;
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if body
                .send_data(bytes::Bytes::from_static(b"y"), false)
                .is_err()
            {
                break;
            }
            sent += 1;
            // Keep the connection's accept loop fresh so the accept-inactivity
            // deadline is not what ends the drip.
            {
                let ping = http::Request::builder()
                    .method(http::Method::POST)
                    .uri(PATH)
                    .header(http::header::CONTENT_TYPE, CONTENT_TYPE)
                    .body(())
                    .expect("request");
                if let Ok((response, mut send)) = sender.clone().send_request(ping, false) {
                    let _ = send.send_data(bytes::Bytes::new(), true);
                    let _ = tokio::time::timeout(Duration::from_secs(2), response).await;
                }
            }
        }
        drop(body);
        driver.abort();
        sent
    });
    assert!(
        drip_ended < 100,
        "the drip ran {drip_ended} rounds; only the total body deadline can end it"
    );

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

/// A stream whose handler is parked keeps its body charged: the reservation is
/// released only when the stream ends, so a second stream cannot pin another
/// body under the same budget (round 29, high).
#[test]
fn a_parked_handler_keeps_its_body_charged() {
    let (started, started_rx) = std::sync::mpsc::channel::<()>();
    let (release, release_rx) = std::sync::mpsc::channel::<()>();
    let server = Http2Server::bind_loopback()
        .expect("bind")
        .with_inflight_budget(4096)
        .with_connection_deadline(Duration::from_millis(500));
    let address = server.address().to_string();
    let handle = std::thread::spawn(move || {
        let mut started = Some(started);
        let mut release = Some(release_rx);
        server
            .serve(2, move |envelope| {
                if let Some(sender) = started.take() {
                    let _ = sender.send(());
                    if let Some(receiver) = release.take() {
                        let _ = receiver.recv();
                    }
                }
                echo(envelope)
            })
            .expect("serve")
    });

    let large = Envelope::request(2, "ping", Vec::new())
        .with_payload(vec![b'a'; 3_000])
        .encode()
        .expect("encode")
        .len();
    assert!(large < 4096, "the first body fits the budget: {large}");

    let mut first = Http2Client::connect(&address)
        .expect("connect")
        .with_deadline(Duration::from_secs(10));
    let first_request = Envelope::request(2, "ping", Vec::new()).with_payload(vec![b'a'; 3_000]);
    let first_client = std::thread::spawn(move || {
        let answer = first.call(&first_request);
        (first, answer)
    });
    // Wait until the parked handler holds the reservation.
    started_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the handler runs");

    let mut second = Http2Client::connect(&address)
        .expect("connect")
        .with_deadline(Duration::from_secs(10));
    let second_request = Envelope::request(3, "ping", Vec::new()).with_payload(vec![b'b'; 2_000]);
    let error = second
        .call(&second_request)
        .expect_err("the budget is still held by the parked stream");
    assert_eq!(error.provider_code(), Some("rpc/backpressure"), "{error}");

    let _ = release.send(());
    let (first, answer) = first_client.join().expect("first client");
    let answer = answer.expect("the first call still completes");
    assert_eq!(answer.first_value(), Some(&Value::text("pong")));
    drop(first);
    drop(second);
    let _ = handle.join().expect("serve returns");
}
