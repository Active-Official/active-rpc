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

/// A peer that sends part of a header and then stalls leaves the stream off a
/// frame boundary: the next read must not parse its body as a header
/// (round 11, R-09 #1).
#[test]
fn a_partial_header_that_stalls_poisons_the_receive() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let client = std::thread::spawn(move || {
        let mut stream = TcpStream::connect(address).expect("connect");
        stream.write_all(&[1, 2]).expect("two header bytes");
        std::thread::sleep(std::time::Duration::from_secs(2));
    });
    let (stream, _) = listener.accept().expect("accept");
    let mut server = TcpTransport::with_timeout(stream, std::time::Duration::from_millis(150))
        .expect("transport");
    let error = server.recv().expect_err("the header never completes");
    assert_eq!(error.code(), "rpc/transport", "{error}");
    let error = server
        .recv()
        .expect_err("the inbound stream is off a frame boundary");
    assert!(
        error.to_string().contains("poisoned"),
        "the second read must not decode the stall: {error}"
    );
    client.join().ok();
}

/// A timeout set at construction is the bound that applies: `new` used to
/// overwrite it with the default (round 11, R-09 #2).
#[test]
fn a_chosen_timeout_is_not_overwritten_by_the_default() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let client = std::thread::spawn(move || {
        let stream = TcpStream::connect(address).expect("connect");
        std::thread::sleep(std::time::Duration::from_secs(2));
        drop(stream);
    });
    let (stream, _) = listener.accept().expect("accept");
    let mut server = TcpTransport::with_timeout(stream, std::time::Duration::from_millis(100))
        .expect("transport");
    let started = std::time::Instant::now();
    let error = server.recv().expect_err("a silent peer");
    assert_eq!(error.code(), "rpc/transport", "{error}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "the chosen bound was ignored: {:?}",
        started.elapsed()
    );
    client.join().ok();
}

/// The QUIC client accepts only an answer to its own call: a wrong id or a
/// request kind is a wire fault, as it is on the bridge and HTTP/2
/// (round 12, R-09 #1).
#[cfg(feature = "quic")]
#[test]
fn a_quic_answer_must_belong_to_the_call() {
    use active_rpc::transport::quic::{QuicClient, QuicServer};
    use active_rpc::Value;

    let wrong_id = QuicServer::start(1, |envelope| {
        Envelope::response(envelope.request_id + 1, Value::Null)
    })
    .expect("server");
    let client = QuicClient::connect(wrong_id.address(), wrong_id.certificate()).expect("client");
    let error = client
        .call(&Envelope::request(7, "ping", Vec::new()))
        .expect_err("the answer is for another request");
    assert_eq!(error.code(), "rpc/wire", "{error}");

    let wrong_kind = QuicServer::start(1, |envelope| {
        Envelope::request(envelope.request_id, "ping", Vec::new())
    })
    .expect("server");
    let client =
        QuicClient::connect(wrong_kind.address(), wrong_kind.certificate()).expect("client");
    let error = client
        .call(&Envelope::request(7, "ping", Vec::new()))
        .expect_err("a request is not an answer");
    assert_eq!(error.code(), "rpc/wire", "{error}");
}

/// A server whose budget is spent must not close the endpoint while an admitted
/// call is still answering: the first stream to finish used to close it and
/// abort the other connection's reply (round 47; a CI flake in the mutual-TLS
/// identity test).
#[cfg(feature = "quic")]
#[test]
fn the_last_admitted_call_closes_the_server_not_the_first_to_finish() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    use active_rpc::transport::quic::{QuicClient, QuicServer};
    use active_rpc::wire::Kind;

    let calls = Arc::new(AtomicUsize::new(0));
    let handler_calls = Arc::clone(&calls);
    let server = QuicServer::start(2, move |envelope: Envelope| {
        // Both calls are admitted before either answers. The first handler call
        // holds the endpoint open while the second is queued behind the handler
        // mutex, and the second then waits past the first call's close so a
        // premature shutdown is not a race but a certain lost reply.
        match handler_calls.fetch_add(1, Ordering::SeqCst) {
            0 => std::thread::sleep(std::time::Duration::from_millis(150)),
            _ => std::thread::sleep(std::time::Duration::from_millis(300)),
        }
        Envelope::response(envelope.request_id, active_rpc::Value::Null)
    })
    .expect("server");
    let clients = (0..2)
        .map(|_| QuicClient::connect(server.address(), server.certificate()).expect("client"))
        .collect::<Vec<_>>();
    let barrier = Arc::new(Barrier::new(2));
    let mut threads = Vec::new();
    for (index, client) in clients.into_iter().enumerate() {
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            let answer = client
                .call(&Envelope::request(index as u64 + 1, "ping", Vec::new()))
                .expect("every admitted call is answered");
            assert_eq!(answer.kind, Kind::Response);
        }));
    }
    for thread in threads {
        thread.join().expect("client thread");
    }
    server.shutdown();
}

/// An error may carry id 0, the id a peer writes when the frame was refused
/// before its id could be read. An error for another call and a response with
/// id 0 are not answers to this call (round 13, R-09 #6).
#[cfg(feature = "quic")]
#[test]
fn a_quic_error_id_zero_is_accepted_and_another_id_is_not() {
    use active_rpc::transport::quic::{QuicClient, QuicServer};
    use active_rpc::wire::Kind;
    use active_rpc::Error as RpcError;

    let unreadable = QuicServer::start(1, |_envelope| {
        Envelope::error(0, &RpcError::Wire("the frame could not be read"))
    })
    .expect("server");
    let client =
        QuicClient::connect(unreadable.address(), unreadable.certificate()).expect("client");
    let answer = client
        .call(&Envelope::request(7, "ping", Vec::new()))
        .expect("id 0 is legal for an error");
    assert_eq!(answer.kind, Kind::Error);
    drop(client);
    unreadable.shutdown();

    let for_another = QuicServer::start(1, |_envelope| {
        Envelope::error(8, &RpcError::Wire("another call"))
    })
    .expect("server");
    let client =
        QuicClient::connect(for_another.address(), for_another.certificate()).expect("client");
    let error = client
        .call(&Envelope::request(7, "ping", Vec::new()))
        .expect_err("an error for another call is refused");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    drop(client);
    for_another.shutdown();

    let zero_response = QuicServer::start(1, |_envelope| {
        Envelope::response(0, active_rpc::Value::Null)
    })
    .expect("server");
    let client =
        QuicClient::connect(zero_response.address(), zero_response.certificate()).expect("client");
    let error = client
        .call(&Envelope::request(7, "ping", Vec::new()))
        .expect_err("a response with id 0 is refused");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    drop(client);
    zero_response.shutdown();
}
