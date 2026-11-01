//! R-09 transport hardening: the round-1 review's highs and mediums, driven
//! through the shipped transports.
//!
//! Every test speaks to the real server: the bridge over raw TCP, the length
//! framed transport over `serve_connection`, and QUIC over quinn. A peer-caused
//! fault must end one connection, never the server.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use active_rpc::transport::connect::{BridgeServer, ConnectClient, CONNECT_TYPE, PATH};
use active_rpc::transport::{bind_loopback, serve_connection, TcpTransport, Transport};
use active_rpc::wire::{Envelope, Kind};
use active_rpc::Value;

fn echo(envelope: Envelope) -> Envelope {
    Envelope::response(envelope.request_id, Value::text("ok"))
}

fn read_reply(stream: &mut TcpStream) -> String {
    let mut reply = Vec::new();
    let _ = stream.read_to_end(&mut reply);
    String::from_utf8_lossy(&reply).to_string()
}

/// A head that is not UTF-8 used to end the bridge process: `read_line` returns
/// `InvalidData`, and `serve` propagated it. A header value is arbitrary bytes.
#[test]
fn a_non_utf8_request_head_is_a_400_and_the_bridge_keeps_serving() {
    let server = BridgeServer::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let handle = std::thread::spawn(move || server.serve(2, echo).expect("serve"));

    let mut raw = TcpStream::connect(&address).expect("connect");
    raw.write_all(b"POST /active.rpc.v1.Agent/Call HTTP/1.1\r\nhost: x\r\nx-raw: \xff\xfe\r\n\r\n")
        .expect("write");
    let reply = read_reply(&mut raw);
    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");

    let mut client = ConnectClient::connect(&address).expect("client");
    client
        .call(&Envelope::request(1, "ping", vec![]))
        .expect("the bridge still serves after a non-UTF-8 head");
    assert_eq!(handle.join().expect("join"), 1);
}

/// One connection that sends half a head and stops used to block every later
/// peer forever: `serve` accepts serially and `read_line` had no timeout.
#[test]
fn a_stalled_head_does_not_block_the_next_connection() {
    let server = BridgeServer::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let handle = std::thread::spawn(move || server.serve(2, echo).expect("serve"));

    let mut stalled = TcpStream::connect(&address).expect("connect");
    stalled
        .write_all(b"POST /active.rpc.v1.Agent/Call HTTP/1.1\r\nhost: x\r\n")
        .expect("write");
    // Deliberately no empty line and no close.

    let started = Instant::now();
    let mut client = ConnectClient::connect(&address).expect("client");
    client
        .call(&Envelope::request(1, "ping", vec![]))
        .expect("the next connection is served");
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "a stalled head held the bridge for {elapsed:?}"
    );
    drop(stalled);
    assert_eq!(handle.join().expect("join"), 1);
}

/// A head line without a newline used to be buffered in full before the ceiling
/// was checked.
#[test]
fn a_head_line_without_a_newline_is_refused_at_the_ceiling() {
    let server = BridgeServer::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let handle = std::thread::spawn(move || server.serve(2, echo).expect("serve"));

    let mut raw = TcpStream::connect(&address).expect("connect");
    let mut head = b"POST /active.rpc.v1.Agent/Call HTTP/1.1\r\nx-flood: ".to_vec();
    head.extend(std::iter::repeat_n(b'a', 32 << 10));
    let _ = raw.write_all(&head);
    let reply = read_reply(&mut raw);
    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");

    let mut client = ConnectClient::connect(&address).expect("client");
    client
        .call(&Envelope::request(1, "ping", vec![]))
        .expect("the bridge still serves after an oversized head");
    assert_eq!(handle.join().expect("join"), 1);
}

/// Two different `content-length` values, and any `transfer-encoding`, are a
/// framing ambiguity: a front proxy that resolves it differently would let a
/// second request ride in front of this one.
#[test]
fn conflicting_framing_headers_are_refused() {
    let server = BridgeServer::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let handle = std::thread::spawn(move || server.serve(3, echo).expect("serve"));

    for head in [
        format!(
            "POST {PATH} HTTP/1.1\r\nhost: x\r\ncontent-type: {CONNECT_TYPE}\r\ncontent-length: 5\r\ncontent-length: 6\r\n\r\n"
        ),
        format!(
            "POST {PATH} HTTP/1.1\r\nhost: x\r\ncontent-type: {CONNECT_TYPE}\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n"
        ),
    ] {
        let mut raw = TcpStream::connect(&address).expect("connect");
        raw.write_all(head.as_bytes()).expect("write");
        let reply = read_reply(&mut raw);
        assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
    }

    let mut client = ConnectClient::connect(&address).expect("client");
    client
        .call(&Envelope::request(1, "ping", vec![]))
        .expect("the bridge still serves after ambiguous framing");
    assert_eq!(handle.join().expect("join"), 1);
}

/// `serve_connection` returned the peer's error, so `peer.rs` and the CLI —
/// both of which use `?` — exited on one bad frame.
#[test]
fn a_malformed_frame_ends_the_connection_not_the_server() {
    let (listener, address) = bind_loopback().expect("bind");
    let handle = std::thread::spawn(move || {
        let mut served = 0u64;
        for _ in 0..2 {
            let (stream, _) = listener.accept().expect("accept");
            let transport = TcpTransport::new(stream).expect("wrap");
            served += serve_connection(transport, echo).expect("a bad frame is not fatal");
        }
        served
    });

    let mut raw = TcpStream::connect(&address).expect("connect");
    active_rpc::transport::write_frame(&mut raw, b"not an envelope").expect("write");
    let mut reply = Vec::new();
    let _ = raw.read_to_end(&mut reply);
    assert!(!reply.is_empty(), "the peer gets a stable refusal");

    let mut transport = None;
    for _ in 0..50 {
        if let Ok(stream) = TcpStream::connect(&address) {
            transport = Some(TcpTransport::new(stream).expect("wrap"));
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut transport = transport.expect("connect");
    transport
        .send(&Envelope::request(1, "ping", vec![]))
        .expect("send");
    let response = transport.recv().expect("recv").expect("response");
    assert_eq!(response.kind, Kind::Response);
    // Closing the connection ends the server loop, which is what `join` waits for.
    drop(transport);
    assert_eq!(handle.join().expect("join"), 1);
}

/// A response or error envelope is not a call: a relay must not be able to
/// forward one and have a server execute it.
#[test]
fn a_response_envelope_is_refused_on_the_framed_and_bridge_transports() {
    let (listener, address) = bind_loopback().expect("bind");
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        serve_connection(TcpTransport::new(stream).expect("wrap"), echo).expect("serve")
    });
    let mut transport = TcpTransport::connect(&address).expect("connect");
    transport
        .send(&Envelope::response(1, Value::text("smuggled")))
        .expect("send");
    let response = transport.recv().expect("recv").expect("reply");
    assert_eq!(response.kind, Kind::Error, "{response:?}");
    // Closing the connection ends the server loop, which is what `join` waits
    // for.
    drop(transport);
    assert_eq!(handle.join().expect("join"), 0);

    let server = BridgeServer::bind_loopback().expect("bind");
    let bridge = server.address().to_string();
    let handle = std::thread::spawn(move || server.serve(1, echo).expect("serve"));
    let mut client = ConnectClient::connect(&bridge).expect("client");
    let error = client
        .call(&Envelope::response(2, Value::text("smuggled")))
        .expect_err("a response is not a call");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    assert_eq!(handle.join().expect("join"), 0);
}

/// A stub that answers one HTTP request with a fixed status and body.
fn refusal_stub(status: u16, body: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address").to_string();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut scratch = [0u8; 4096];
        let _ = stream.read(&mut scratch);
        let head = format!(
            "HTTP/1.1 {status} X\r\ncontent-type: {CONNECT_TYPE}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(&body);
        let _ = stream.flush();
        // Close the write half first and wait for the client to hang up. On
        // Windows a plain close with queued data can reset the connection and
        // discard the body, which made a 1 MiB response flaky.
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut scratch = [0u8; 1024];
        let _ = stream.read(&mut scratch);
    });
    (address, handle)
}

/// The peer's refusal class survives the round trip, and an oversized body is
/// not copied into the error.
#[test]
fn the_client_preserves_a_peer_refusal_code() {
    let (address, stub) = refusal_stub(400, b"rpc/identity".to_vec());
    let mut client = ConnectClient::connect(&address).expect("client");
    let error = client
        .call(&Envelope::request(1, "ping", vec![]))
        .expect_err("a refusal");
    assert_eq!(error.code(), "rpc/provider");
    assert_eq!(error.provider_code(), Some("rpc/identity"));
    stub.join().expect("stub");

    let (address, stub) = refusal_stub(400, vec![b'x'; 1 << 20]);
    let mut client = ConnectClient::connect(&address).expect("client");
    let error = client
        .call(&Envelope::request(2, "ping", vec![]))
        .expect_err("a refusal");
    assert_eq!(error.provider_code(), Some("rpc/provider"));
    stub.join().expect("stub");
}

#[cfg(feature = "quic")]
mod quic {
    use super::*;
    use active_rpc::transport::quic::{QuicClient, QuicServer};
    use active_rpc::transport::{frame, read_frame, MAX_FRAME_BYTES};
    use active_rpc::wire::WireLimits;
    use std::sync::Arc;

    /// One stream is one frame: bytes after the frame are a second message the
    /// decoder never sees, so they are refused instead of ignored.
    #[test]
    fn trailing_bytes_after_a_quic_frame_are_refused() {
        let server = QuicServer::start(1, echo).expect("server");
        let client = QuicClient::connect(server.address(), server.certificate()).expect("client");
        let bytes = Envelope::request(7, "ping", vec![])
            .encode()
            .expect("encode");
        let mut payload = Vec::new();
        payload.extend_from_slice(&frame(bytes.len()).expect("frame"));
        payload.extend_from_slice(&bytes);
        payload.extend_from_slice(b"a second message");
        let response = client.exchange(&payload).expect("exchange");
        let mut cursor = std::io::Cursor::new(&response);
        let body = read_frame(&mut cursor, &WireLimits::default())
            .expect("frame")
            .expect("body");
        let envelope = Envelope::decode_with(&body, WireLimits::default()).expect("decode");
        assert_eq!(envelope.kind, Kind::Error, "{envelope:?}");
        assert_eq!(envelope.method, "rpc/wire");
    }

    /// A stream that never finishes used to park every later stream on the same
    /// connection, because streams were read serially with no deadline.
    #[test]
    fn a_stalled_stream_does_not_block_another_stream() {
        let server = QuicServer::start(2, echo).expect("server");
        let address = server.address().to_string();
        let certificate = server.certificate().clone();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(certificate).expect("trust");
            let client_config =
                quinn::ClientConfig::with_root_certificates(Arc::new(roots)).expect("config");
            let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("loopback"))
                .expect("endpoint");
            endpoint.set_default_client_config(client_config);
            let address = address.parse().expect("address");
            let connection = endpoint
                .connect(address, "localhost")
                .expect("connect")
                .await
                .expect("handshake");

            // Stream 1 announces a body and then stops.
            let (mut send, _recv) = connection.open_bi().await.expect("open");
            send.write_all(&(4096u32).to_le_bytes())
                .await
                .expect("prefix");

            // Stream 2 completes while stream 1 is stalled.
            let bytes = Envelope::request(9, "ping", vec![])
                .encode()
                .expect("encode");
            let mut payload = Vec::new();
            payload.extend_from_slice(&frame(bytes.len()).expect("frame"));
            payload.extend_from_slice(&bytes);
            let (mut send, mut recv) = connection.open_bi().await.expect("open");
            send.write_all(&payload).await.expect("write");
            send.finish().expect("finish");
            let reply =
                tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(MAX_FRAME_BYTES))
                    .await
                    .expect("stream 2 is answered while stream 1 stalls")
                    .expect("read");
            let mut cursor = std::io::Cursor::new(&reply);
            let body = read_frame(&mut cursor, &WireLimits::default())
                .expect("frame")
                .expect("body");
            let envelope = Envelope::decode_with(&body, WireLimits::default()).expect("decode");
            assert_eq!(envelope.kind, Kind::Response, "{envelope:?}");
            assert_eq!(envelope.request_id, 9);
            connection.close(0u32.into(), b"done");
        });
    }

    /// The server applies `WireLimits::strict()`: a method longer than the
    /// strict ceiling is refused instead of accepted under the default limits.
    #[test]
    fn quic_applies_the_server_wire_limits() {
        let server = QuicServer::start(1, echo)
            .expect("server")
            .with_limits(WireLimits::strict());
        let client = QuicClient::connect(server.address(), server.certificate()).expect("client");
        let long = "m".repeat(WireLimits::strict().max_method as usize + 1);
        let response = client
            .call(&Envelope::request(1, long, vec![]))
            .expect("the server answers with an error envelope");
        assert_eq!(response.kind, Kind::Error, "{response:?}");
        assert_eq!(response.method, "rpc/wire");
    }
}
