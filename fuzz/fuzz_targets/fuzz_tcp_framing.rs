#![no_main]

//! TCP length-prefix framing over `TcpTransport`.
//!
//! Invariants:
//!
//! 1. A clean loopback call round-trips (fixed control).
//! 2. `frame` / `read_frame` / `write_frame` are total over arbitrary bytes:
//!    a length over the ceiling is refused, a truncated body is a transport
//!    error, never a panic, never an unbounded allocation — and a frame that
//!    does decode re-frames to itself.
//! 3. A server that receives mutated frame bytes answers with a catalogued
//!    error envelope or closes, never panics, and still serves the next
//!    connection.
//! 4. A peer that answers another request's id is refused with `rpc/wire`,
//!    never handed to the caller as this call's result; an error answer
//!    carrying id 0 is an error envelope, never a value.
//!
//! Run with `cargo +nightly fuzz run fuzz_tcp_framing -- -runs=200000`.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use libfuzzer_sys::fuzz_target;

use active_rpc::error::ERROR_CODES;
use active_rpc::transport::{
    bind_loopback, frame, read_frame, serve_connection_within, write_frame, TcpTransport,
    MAX_FRAME_BYTES,
};
use active_rpc::wire::{Envelope, Kind, WireLimits};
use active_rpc::Value;

#[path = "common.rs"]
mod common;

/// The server side for one run: accept exactly two connections (the mutated
/// one, then the clean one that proves liveness), serve each with a short
/// frame deadline, and return the total served. The accept loop is bounded by
/// the count, so the join at the end of the run cannot hang on a connection
/// that never comes.
fn serve_two(listener: std::net::TcpListener) -> u64 {
    let mut served = 0u64;
    for _ in 0..2 {
        let Ok((stream, _)) = listener.accept() else {
            return served;
        };
        let Ok(transport) = TcpTransport::with_timeout(stream, Duration::from_millis(250)) else {
            return served;
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        match serve_connection_within(
            transport,
            |envelope| Envelope::response(envelope.request_id, Value::text("pong")),
            Some(deadline),
        ) {
            Ok(count) => served += count,
            Err(_) => return served,
        }
    }
    served
}

fuzz_target!(|data: &[u8]| {
    // Fixed positive control: a clean loopback call answers `pong`, and the
    // listener serves a second clean call after it. Without it a transport
    // that refused every frame would satisfy every refusal assertion below.
    {
        let (listener, address) = bind_loopback().expect("the control listener binds");
        let served = std::thread::spawn(move || serve_two(listener));
        let mut client = TcpTransport::connect_with_timeout(&address, Duration::from_secs(2))
            .expect("the control client connects");
        let response = client
            .call(&Envelope::request(1, "ping", vec![]))
            .expect("the control call answers");
        assert_eq!(response.first_value(), Some(&Value::text("pong")));
        drop(client);
        let mut second = TcpTransport::connect_with_timeout(&address, Duration::from_secs(2))
            .expect("the control second client connects");
        let response = second
            .call(&Envelope::request(2, "ping", vec![]))
            .expect("the control second call answers");
        assert_eq!(response.first_value(), Some(&Value::text("pong")));
        drop(second);
        assert_eq!(served.join().expect("the control server thread"), 2);
    }
    if data.is_empty() {
        return;
    }

    // 1. Pure framing over a cursor: total, bounded, and a fixed point.
    {
        let mut cursor = std::io::Cursor::new(data);
        match read_frame(&mut cursor, &WireLimits::default()) {
            Ok(Some(body)) => {
                // A frame that decodes re-frames to itself, and its length
                // prefix is the one `frame` builds.
                let mut encoded = Vec::new();
                write_frame(&mut encoded, &body).expect("a decoded body re-frames");
                assert_eq!(&encoded[..4], frame(body.len()).expect("frame").as_slice());
                let mut again = std::io::Cursor::new(&encoded);
                assert_eq!(
                    read_frame(&mut again, &WireLimits::default())
                        .expect("re-read")
                        .as_deref(),
                    Some(body.as_slice()),
                    "framing is a fixed point"
                );
                assert_eq!(again.position(), encoded.len() as u64, "no trailing bytes");
            }
            Ok(None) => {
                // Clean close only: an empty input, or a header the reader
                // has not seen yet. A partial header is an error, not None.
                assert!(
                    data.is_empty() || cursor.position() == 0,
                    "a partial frame must not read as a clean close"
                );
            }
            Err(error) => {
                assert!(
                    ERROR_CODES.contains(&error.code()),
                    "an unexpected class for a bad frame: {error}"
                );
            }
        }
        // `frame` refuses exactly the lengths over the ceiling.
        let len = (data.len() * 1024).saturating_add(data.first().copied().unwrap_or(0) as usize);
        match frame(len) {
            Ok(prefix) => {
                assert!(len <= MAX_FRAME_BYTES);
                assert_eq!(prefix, (len as u32).to_le_bytes());
            }
            Err(error) => {
                assert!(len > MAX_FRAME_BYTES);
                assert_eq!(error.code(), "rpc/wire");
            }
        }
        // An over-declared length is refused before any body is read.
        let mut huge = vec![0xff, 0xff, 0xff, 0xff];
        huge.extend_from_slice(&data[..data.len().min(16)]);
        let mut cursor = std::io::Cursor::new(&huge);
        let error = read_frame(&mut cursor, &WireLimits::default())
            .expect_err("an over-declared frame must be refused");
        assert!(
            ERROR_CODES.contains(&error.code()),
            "an unexpected class for an over-declared frame: {error}"
        );
    }

    // 2. Live loopback: mutated frame bytes at a real server, then a clean
    // call proving the listener still serves.
    {
        let (listener, address) = bind_loopback().expect("the listener binds");
        let served = std::thread::spawn(move || serve_two(listener));
        // A mutated valid frame: the ping request with at least one byte
        // changed, or truncated, or extended — never the valid frame itself,
        // so this leg cannot pass by exercising only the clean path.
        let valid = Envelope::request(1, "ping", vec![])
            .encode()
            .expect("encode");
        let mut framed = frame(valid.len()).expect("frame").to_vec();
        framed.extend_from_slice(&valid);
        let mut mutated = framed.clone();
        match data[0] % 3 {
            0 => {
                let at = 1 + (data.len() % mutated.len().max(1));
                let at = at.min(mutated.len().saturating_sub(1));
                mutated[at] ^= 0xff;
            }
            1 => {
                mutated.truncate(1 + (data.len() % mutated.len().max(1)));
            }
            _ => {
                mutated.extend_from_slice(&data[..data.len().min(32)]);
            }
        }
        let mut raw = TcpStream::connect(&address).expect("the raw client connects");
        raw.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        raw.set_write_timeout(Some(Duration::from_secs(2)))
            .expect("write timeout");
        raw.write_all(&mutated).expect("the mutated bytes go out");
        raw.shutdown(std::net::Shutdown::Write).expect("half-close");
        // The server answers a malformed frame with an error envelope or
        // closes; it never leaves the peer waiting. A read timeout here
        // means the server wedged, and the target fails on purpose.
        let mut reply = Vec::new();
        match raw.read_to_end(&mut reply) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                panic!("the server left a malformed frame unanswered for 5 s");
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                panic!("the server left a malformed frame unanswered for 5 s");
            }
            Err(_) => {}
        }
        if !reply.is_empty() {
            // The reply may carry more than one frame: a mutated frame that
            // still decodes is answered, and the trailing bytes are then read
            // as a second frame and refused with a second error envelope.
            // Every frame in the reply must decode, and each must be a
            // response or an error naming a catalogued code.
            let mut cursor = std::io::Cursor::new(&reply);
            let mut frames = 0usize;
            while (cursor.position() as usize) < reply.len() {
                let body = read_frame(&mut cursor, &WireLimits::default())
                    .expect("the reply is framed")
                    .expect("the reply carries a body");
                let envelope = Envelope::decode(&body).expect("the reply decodes");
                assert!(
                    matches!(envelope.kind, Kind::Response | Kind::Error),
                    "the reply is a response or an error, not a request"
                );
                if envelope.kind == Kind::Error {
                    assert!(
                        ERROR_CODES.contains(&envelope.method.as_str()),
                        "an error reply names a catalogued code, got {}",
                        envelope.method
                    );
                }
                frames += 1;
            }
            assert!(frames >= 1, "a non-empty reply carries at least one frame");
        }
        drop(raw);
        let mut client = TcpTransport::connect_with_timeout(&address, Duration::from_secs(2))
            .expect("the clean client connects after the hostile frame");
        let response = client
            .call(&Envelope::request(2, "ping", vec![]))
            .expect("the listener still serves after a hostile frame");
        assert_eq!(response.first_value(), Some(&Value::text("pong")));
        drop(client);
        let served = served.join().expect("the server thread");
        assert!(served >= 1, "the listener served at least the clean call");
    }

    // 3. Answer identity: a peer that answers another request's id, and an
    // error answer carrying id 0.
    {
        let (listener, address) = bind_loopback().expect("the id listener binds");
        let wrong_id = data[0].is_multiple_of(2);
        let served = std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("read timeout");
            let Ok(Some(body)) = read_frame(&mut stream, &WireLimits::default()) else {
                return;
            };
            let Ok(request) = Envelope::decode(&body) else {
                return;
            };
            let answer = if wrong_id {
                Envelope::response(request.request_id + 1, Value::text("pong"))
            } else {
                Envelope::error(
                    0,
                    &active_rpc::Error::Provider {
                        code: "test/wrong".to_string(),
                    },
                )
            };
            let _ = write_frame(&mut stream, &answer.encode().expect("encode"));
            let _ = stream.read(&mut [0u8; 1]);
        });
        let mut client = TcpTransport::connect_with_timeout(&address, Duration::from_secs(2))
            .expect("the id client connects");
        if wrong_id {
            let error = client
                .call(&Envelope::request(1, "ping", vec![]))
                .expect_err("an answer for another request must be refused");
            assert_eq!(error.code(), "rpc/wire");
        } else {
            let answer = client
                .call(&Envelope::request(1, "ping", vec![]))
                .expect("an id-0 error answer is delivered, not refused as a transport fault");
            assert_eq!(
                answer.kind,
                Kind::Error,
                "an id-0 error is an error envelope, never a value"
            );
            // The error envelope carries the provider code the peer chose
            // ("test/wrong"), not a catalogued class: `Envelope::error`
            // keeps the inner code when it is short, ASCII and clean.
            assert_eq!(
                answer.method, "test/wrong",
                "the provider code survives the round-trip"
            );
        }
        drop(client);
        served.join().expect("the id server thread");
    }
});
