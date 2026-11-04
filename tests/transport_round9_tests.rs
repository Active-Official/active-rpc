//! R-09 round 9: a stream that delivered an illegal frame is poisoned, a peer
//! cannot choose the kernel's refusal class, and a strict transport refuses to
//! send a frame it would itself reject.

use std::io::{Read, Write};
use std::net::TcpListener;

use active_rpc::transport::connect::ConnectClient;
use active_rpc::transport::{TcpTransport, Transport};
use active_rpc::wire::{Envelope, WireLimits};
use active_rpc::{Arg, Value};

/// A frame past the ceiling leaves its body unread. The next read must not
/// parse that body as a header: the connection is poisoned (round 9, R-09 #6).
#[test]
fn an_oversize_frame_poisons_the_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address").to_string();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("accept");
        // Announce two MiB (past the strict one-MiB ceiling) and write a
        // plausible "next frame" into the unread body.
        let announced = 2u32 << 20;
        socket.write_all(&announced.to_le_bytes()).expect("header");
        let valid = Envelope::request(9, "ping", vec![])
            .encode()
            .expect("encode");
        let mut body = Vec::new();
        body.extend_from_slice(&(valid.len() as u32).to_le_bytes());
        body.extend_from_slice(&valid);
        body.resize(2 << 20, 0);
        let _ = socket.write_all(&body);
        let mut sink = Vec::new();
        let _ = socket.read_to_end(&mut sink);
    });

    let stream = std::net::TcpStream::connect(&address).expect("connect");
    let mut transport = TcpTransport::new(stream)
        .expect("transport")
        .with_limits(WireLimits::strict());
    let error = transport
        .recv()
        .expect_err("the frame is past the strict ceiling");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    let error = transport
        .recv()
        .expect_err("the connection is poisoned by the unread body");
    assert!(
        error.to_string().contains("poisoned"),
        "the next read must not parse the body as a header: {error}"
    );
    drop(transport);
    server.join().ok();
}

/// A peer's refusal body cannot name an authority class: `rpc/revoked` from the
/// bridge is a provider fault (round 9, R-09 #7).
#[test]
fn a_peer_cannot_choose_an_authority_refusal_class() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address").to_string();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("accept");
        let mut scratch = [0u8; 4096];
        let _ = socket.read(&mut scratch);
        let _ = socket.write_all(
            b"HTTP/1.1 403 Forbidden\r\ncontent-length: 10\r\nconnection: close\r\n\r\nrpc/revoked",
        );
        let _ = socket.flush();
        // Close the write half and wait for the client to hang up: a plain
        // close with queued data can reset the connection on Windows.
        let _ = socket.shutdown(std::net::Shutdown::Write);
        let mut sink = [0u8; 1024];
        let _ = socket.read(&mut sink);
    });
    let mut client = ConnectClient::connect(&address).expect("connect");
    let error = client
        .call(&Envelope::request(1, "ping", vec![]))
        .expect_err("the peer refused");
    assert_eq!(error.provider_code(), Some("rpc/provider"), "{error}");
    assert_ne!(error.code(), "rpc/revoked", "{error}");
    server.join().expect("server");
}

/// A strict transport refuses to write a frame its own reader would refuse
/// (round 9, R-09 #11).
#[test]
fn a_strict_transport_refuses_to_send_an_oversized_frame() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address").to_string();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("accept");
        let mut sink = Vec::new();
        let _ = socket.read_to_end(&mut sink);
    });
    let mut transport = TcpTransport::connect(&address).expect("connect");
    transport = transport.with_limits(WireLimits::strict());
    let big = Envelope::request(
        1,
        "ping",
        vec![Arg::Value(Value::text("x".repeat(2 << 20)))],
    );
    let error = transport.send(&big).expect_err("past the strict ceiling");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    drop(transport);
    server.join().ok();
}
