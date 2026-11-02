//! R-09 round 2: framing grammar, deadlines, panic isolation and the budgets a
//! hostile peer can actually reach.
//!
//! The bridge is the real `BridgeServer` on a loopback port; the head and body
//! are written as raw bytes so the grammar is exercised, not the client.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use active_rpc::transport::connect::{BridgeServer, CONNECTION_WAIT};
use active_rpc::transport::{serve_connection, TcpTransport, Transport};
use active_rpc::value::Value;
use active_rpc::wire::{Envelope, Kind};

fn echo(envelope: Envelope) -> Envelope {
    Envelope::response(envelope.request_id, Value::text("ok"))
}

fn read_reply(stream: &mut TcpStream) -> String {
    let mut out = Vec::new();
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                out.extend_from_slice(&chunk[..read]);
                if out.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn bridge() -> (String, std::thread::JoinHandle<u64>) {
    let server = BridgeServer::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let handle = std::thread::spawn(move || server.serve(2, echo).expect("serve"));
    (address, handle)
}

/// RFC 9112 requires CRLF; a proxy with different line splitting would see
/// different header boundaries than this server.
#[test]
fn a_bare_lf_head_is_refused() {
    let (address, handle) = bridge();
    let mut stream = TcpStream::connect(&address).expect("connect");
    stream
        .write_all(
            b"POST /active.rpc.v1.Agent/Call HTTP/1.1\nhost: x\ncontent-type: application/connect+active-infinity\n\n",
        )
        .expect("write");
    let reply = read_reply(&mut stream);
    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");

    let mut client = active_rpc::transport::connect::ConnectClient::connect(&address)
        .expect("the bridge keeps serving");
    client
        .call(&Envelope::request(1, "ping", vec![]))
        .expect("served");
    assert_eq!(handle.join().expect("join"), 1);
}

/// EOF before the blank line is an incomplete head, not a complete one.
#[test]
fn a_head_that_ends_at_eof_is_refused() {
    let (address, handle) = bridge();
    let mut stream = TcpStream::connect(&address).expect("connect");
    stream
        .write_all(b"POST /active.rpc.v1.Agent/Call HTTP/1.1\r\nhost: x\r\n")
        .expect("write");
    stream
        .shutdown(std::net::Shutdown::Write)
        .expect("shutdown");
    let reply = read_reply(&mut stream);
    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");

    let mut client = active_rpc::transport::connect::ConnectClient::connect(&address)
        .expect("the bridge keeps serving");
    client
        .call(&Envelope::request(1, "ping", vec![]))
        .expect("served");
    assert_eq!(handle.join().expect("join"), 1);
}

/// `content-length: +25` is not a decimal length; a front proxy may resolve it
/// differently from this server.
#[test]
fn a_signed_content_length_is_refused() {
    let server = BridgeServer::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let handle = std::thread::spawn(move || server.serve(1, echo).expect("serve"));
    let mut stream = TcpStream::connect(&address).expect("connect");
    stream
        .write_all(
            b"POST /active.rpc.v1.Agent/Call HTTP/1.1\r\nhost: x\r\ncontent-type: application/connect+active-infinity\r\ncontent-length: +25\r\n\r\n",
        )
        .expect("write");
    let reply = read_reply(&mut stream);
    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
    assert_eq!(handle.join().expect("join"), 0);
}

/// A body drip that stays inside a per-read timeout must still be bounded by
/// the connection deadline.
#[test]
fn a_dripping_body_cannot_stretch_the_bridge_connection() {
    let (address, handle) = bridge();
    let mut stream = TcpStream::connect(&address).expect("connect");
    let head = b"POST /active.rpc.v1.Agent/Call HTTP/1.1\r\nhost: x\r\ncontent-type: application/connect+active-infinity\r\ncontent-length: 1000\r\n\r\n";
    stream.write_all(head).expect("head");
    let started = Instant::now();
    // One byte, then silence: each read succeeds, so a per-read timeout never
    // fires.
    stream.write_all(&[0u8]).expect("byte");
    let reply = read_reply(&mut stream);
    let elapsed = started.elapsed();
    assert!(
        reply.is_empty() || reply.starts_with("HTTP/1.1 400") || reply.starts_with("HTTP/1.1 408"),
        "{reply}"
    );
    assert!(
        elapsed < CONNECTION_WAIT + Duration::from_secs(3),
        "the drip held the connection for {elapsed:?}"
    );

    let mut client = active_rpc::transport::connect::ConnectClient::connect(&address)
        .expect("the bridge keeps serving");
    client
        .call(&Envelope::request(1, "ping", vec![]))
        .expect("served");
    let _ = handle.join();
}

/// A strict bridge refuses the body before reading it, not after.
#[test]
fn a_strict_bridge_answers_413_without_reading_the_body() {
    let server = BridgeServer::bind_loopback()
        .expect("bind")
        .with_limits(active_rpc::WireLimits {
            max_bytes: 64,
            ..active_rpc::WireLimits::default()
        });
    let address = server.address().to_string();
    let handle = std::thread::spawn(move || server.serve(1, echo).expect("serve"));

    let mut stream = TcpStream::connect(&address).expect("connect");
    let head = b"POST /active.rpc.v1.Agent/Call HTTP/1.1\r\nhost: x\r\ncontent-type: application/connect+active-infinity\r\ncontent-length: 100000\r\n\r\n";
    stream.write_all(head).expect("head");
    let reply = read_reply(&mut stream);
    assert!(reply.starts_with("HTTP/1.1 413"), "{reply}");
    assert_eq!(handle.join().expect("join"), 0);
}

/// A panicking handler ends that call, not the server.
#[test]
fn a_panicking_handler_does_not_kill_the_connection() {
    let (listener, address) = active_rpc::transport::bind_loopback().expect("bind");
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let transport = TcpTransport::with_timeout(stream, Duration::from_secs(5)).expect("wrap");
        serve_connection(transport, |envelope| {
            if envelope.method == "boom" {
                panic!("provider exploded");
            }
            Envelope::response(envelope.request_id, Value::text("ok"))
        })
        .expect("serve")
    });

    let mut transport = TcpTransport::connect(&address).expect("connect");
    let boom = Envelope::request(1, "boom", vec![]);
    transport.send(&boom).expect("send");
    let response = transport.recv().expect("recv").expect("a response");
    assert_eq!(response.kind, Kind::Error);
    assert_eq!(response.method, "rpc/provider");

    // The same connection still serves the next request.
    let ping = Envelope::request(2, "ping", vec![]);
    transport.send(&ping).expect("send");
    let response = transport.recv().expect("recv").expect("a response");
    assert_eq!(response.kind, Kind::Response);
    assert_eq!(response.first_value(), Some(&Value::text("ok")));
    assert_eq!(handle.join().expect("join"), 2);
}
