//! R-09 round 13: a truncated bridge body is a wire fault, an undecodable
//! frame poisons the TCP session, the TCP client checks that an answer belongs
//! to its call, and a served connection has a total bound.

use std::io::{Read, Write};
use std::net::TcpListener;

use active_rpc::transport::{serve_connection_within, TcpTransport, Transport};
use active_rpc::wire::Envelope;

fn frame(body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(body.len() + 4);
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(body);
    bytes
}

/// A frame whose body is not an envelope is a protocol fault, and the session
/// must not be reused: a caller that ignores the first error must not read the
/// next frame as if the peer were healthy (round 13, R-09 #2).
#[test]
fn a_frame_that_decodes_badly_poisons_the_session() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        stream.write_all(&frame(&[0xffu8; 8])).expect("bad frame");
        let good = Envelope::request(1, "ping", Vec::new())
            .encode()
            .expect("encode");
        stream.write_all(&frame(&good)).expect("good frame");
        let _ = stream.flush();
        // Hold the socket open until the client closed, so the second read is
        // answered by the poison check and not by end-of-stream.
        let mut sink = [0u8; 1024];
        let _ = stream.read(&mut sink);
    });
    let mut client = TcpTransport::connect(&address.to_string()).expect("connect");
    let first = client.recv().expect_err("the body is not an envelope");
    assert_eq!(first.code(), "rpc/wire", "{first}");
    let second = client
        .recv()
        .expect_err("an undecodable frame poisons the session");
    assert_eq!(second.code(), "rpc/transport", "{second}");
    drop(client);
    server.join().expect("server");
}

/// A byte stream has no reply channel of its own: without an id check a relay
/// can hand one call the answer to another (round 13, R-09 #3).
#[test]
fn a_tcp_call_refuses_an_answer_to_another_request() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut sink = [0u8; 4096];
        let _ = stream.read(&mut sink);
        let answer = Envelope::response(8, active_rpc::Value::Null)
            .encode()
            .expect("encode");
        // The call used id 7, so this is another call's answer.
        let _ = stream.write_all(&frame(&answer));
        let _ = stream.flush();
        let _ = stream.read(&mut sink);
    });
    let mut client = TcpTransport::connect(&address.to_string()).expect("connect");
    let error = client
        .call(&Envelope::request(7, "ping", Vec::new()))
        .expect_err("the answer belongs to another call");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    drop(client);
    server.join().expect("server");
}

/// A connection outlives its deadline only until the next frame: the loop
/// returns instead of serving a peer that keeps the per-frame deadline alive
/// forever (round 13, R-09 #4).
#[test]
fn a_served_connection_stops_at_its_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let transport = TcpTransport::new(stream).expect("wrap");
        serve_connection_within(
            transport,
            |envelope| Envelope::response(envelope.request_id, active_rpc::Value::Null),
            Some(std::time::Instant::now()),
        )
    });
    std::thread::sleep(std::time::Duration::from_millis(50));
    let _client = std::net::TcpStream::connect(address).expect("connect");
    let served = server
        .join()
        .expect("server thread")
        .expect("a past deadline is not an error");
    assert_eq!(served, 0, "a connection past its deadline serves nothing");
}

/// A slow handler must not freeze the server runtime: streams waiting on the
/// handler mutex would otherwise park every worker, and a fresh peer could not
/// even finish its handshake (round 14, F-4).
#[cfg(feature = "quic")]
#[test]
fn a_slow_handler_does_not_freeze_the_runtime() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use active_rpc::transport::quic::{QuicClient, QuicServer};

    let calls = Arc::new(AtomicUsize::new(0));
    let handler_calls = Arc::clone(&calls);
    let server = QuicServer::start(0, move |envelope: Envelope| {
        // Only the first call is slow: every later one queues behind it.
        if handler_calls.fetch_add(1, Ordering::SeqCst) == 0 {
            std::thread::sleep(std::time::Duration::from_millis(3_000));
        }
        Envelope::response(envelope.request_id, active_rpc::Value::Null)
    })
    .expect("server");

    let waiters = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(4)
        * 2;
    let mut threads = Vec::new();
    for index in 0..waiters {
        let address = server.address().to_string();
        let certificate = server.certificate().clone();
        threads.push(std::thread::spawn(move || {
            let client = QuicClient::connect(&address, &certificate).expect("client");
            let _ = client.call(&Envelope::request(100 + index as u64, "ping", Vec::new()));
        }));
    }
    // Let every waiter reach the handler mutex.
    std::thread::sleep(std::time::Duration::from_millis(200));

    let started = std::time::Instant::now();
    let fresh = QuicClient::connect(server.address(), server.certificate())
        .expect("a fresh peer still completes its handshake");
    let handshake = started.elapsed();
    drop(fresh);
    assert!(
        handshake < std::time::Duration::from_millis(2_000),
        "a parked handler froze the runtime: the handshake took {handshake:?}"
    );
    for thread in threads {
        thread.join().expect("waiter");
    }
    server.shutdown();
}

/// A peer that drips one byte just inside each socket timeout must not win a
/// second full deadline: the remaining frame time is re-armed before every read
/// (round 15, F-5).
#[test]
fn a_dripped_frame_does_not_get_a_second_deadline() {
    use std::time::{Duration, Instant};

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        // A four-byte length prefix, one byte every 100 ms, then nothing.
        for _ in 0..4 {
            if stream.write_all(&[0u8]).is_err() {
                return;
            }
            let _ = stream.flush();
            std::thread::sleep(Duration::from_millis(100));
        }
        std::thread::sleep(Duration::from_secs(2));
    });
    let stream = std::net::TcpStream::connect(address).expect("connect");
    let mut client = TcpTransport::with_timeout(stream, Duration::from_millis(150))
        .expect("a deadline-carrying transport");
    let started = Instant::now();
    client
        .recv()
        .expect_err("the frame deadline bounds the whole frame");
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(700),
        "a 150 ms frame deadline took {elapsed:?} against a dripping peer"
    );
    drop(server);
}
