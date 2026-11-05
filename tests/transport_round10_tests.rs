//! R-09 round 10: a bounded connect, an independent send half after a bad
//! frame, a truncated frame as a wire fault, and a raw QUIC exchange ceiling.

use std::io::Write;
use std::net::{TcpListener, TcpStream};

use active_rpc::transport::{TcpTransport, Transport};
use active_rpc::wire::{Envelope, WireLimits};

/// A connect with a deadline is bounded even when the peer never answers
/// (round 10, R-09 #1).
#[test]
fn a_connect_with_a_deadline_is_bounded() {
    let started = std::time::Instant::now();
    // TEST-NET-1: nothing answers, so the attempt is a timeout on a normal
    // network (and any other failure on an isolated one). Either way it must
    // return, not park the caller.
    let result =
        TcpTransport::connect_with_timeout("192.0.2.1:9", std::time::Duration::from_millis(300));
    assert!(result.is_err(), "a black hole does not answer");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the attempt took {:?}",
        started.elapsed()
    );
}

/// A refused inbound frame leaves the outbound half usable: the server can
/// still tell the peer why (round 10, R-09 #3).
#[test]
fn a_poisoned_receive_still_allows_the_error_reply() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let client = std::thread::spawn(move || {
        let mut stream = TcpStream::connect(address).expect("connect");
        // A header claiming two MiB, then the start of a body.
        stream
            .write_all(&(2u32 << 20).to_le_bytes())
            .expect("header");
        let mut reply = Vec::new();
        use std::io::Read;
        let _ = stream.read_to_end(&mut reply);
        reply
    });
    let (stream, _) = listener.accept().expect("accept");
    let mut server = TcpTransport::new(stream)
        .expect("transport")
        .with_limits(WireLimits::strict());
    let error = server.recv().expect_err("past the strict ceiling");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    // The outbound half is independent of the inbound framing.
    let reply = Envelope::error(1, &error);
    server.send(&reply).expect("the error reply leaves");
    // Close the connection so the peer's read reaches end of stream.
    drop(server);
    let reply = client.join().expect("client");
    assert!(!reply.is_empty(), "the peer received the refusal");
}

/// A frame that stops early is a wire fault on TCP, as it is on the other
/// transports (round 10, R-09 #4).
#[test]
fn a_truncated_frame_is_a_wire_fault() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let client = std::thread::spawn(move || {
        let mut stream = TcpStream::connect(address).expect("connect");
        stream.write_all(&(100u32).to_le_bytes()).expect("header");
        stream.write_all(&[1, 2, 3]).expect("body start");
        stream
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown");
    });
    let (stream, _) = listener.accept().expect("accept");
    let mut server = TcpTransport::new(stream).expect("transport");
    let error = server.recv().expect_err("the body stops early");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    client.join().expect("client");
}

/// The raw QUIC exchange obeys the client's ceiling before any I/O
/// (round 10, R-09 #6).
#[cfg(feature = "quic")]
#[test]
fn a_raw_quic_exchange_obeys_the_client_ceiling() {
    use active_rpc::transport::quic::{QuicClient, QuicServer};
    use active_rpc::{Arg, Value};

    let server = QuicServer::start(1, |envelope| {
        Envelope::response(envelope.request_id, Value::Null)
    })
    .expect("server");
    let client = QuicClient::connect(server.address(), server.certificate())
        .expect("client")
        .with_limits(WireLimits::strict());
    let payload = vec![0u8; (2 << 20) + 4];
    let error = client
        .exchange(&payload)
        .expect_err("past the strict ceiling");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    // The client still works for a legal frame.
    let response = client
        .call(&Envelope::request(
            1,
            "ping",
            vec![Arg::Value(Value::Int(1))],
        ))
        .expect("a legal call");
    assert_eq!(response.request_id, 1);
}
