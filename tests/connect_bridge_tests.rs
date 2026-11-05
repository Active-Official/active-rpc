//! The Connect/gRPC bridge is interop: envelopes cross verbatim, the registry
//! stays authoritative, and the bridge neither adds nor widens authority.

use std::sync::mpsc;
use std::thread;

use active_rpc::cap::CapAttrs;
use active_rpc::identity::{IdentityPolicy, PeerIdentity};
use active_rpc::kernel::Provider;
use active_rpc::transport::connect::{BridgeServer, ConnectClient};
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::wire::{CapDescriptor, Envelope, Kind};
use active_rpc::{Agent, Budget, Error};

struct Echo;

impl Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn methods(&self) -> Vec<String> {
        vec!["echo".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::text("bridged")))
    }
}

fn dispatch(agent: &Agent, lane: active_rpc::LaneId, envelope: &Envelope) -> Envelope {
    let Some(descriptor) = envelope.caps.first() else {
        return Envelope::error(
            envelope.request_id,
            &Error::UnknownCapability(active_rpc::CapToken(0)),
        );
    };
    let cap = agent.import(descriptor.id);
    match agent.call_as(None, lane, &cap, &envelope.method, envelope.args.clone()) {
        Ok(promise) => {
            agent.run();
            match promise.value() {
                Ok(value) => {
                    let mut response = Envelope::response(envelope.request_id, value);
                    response.payload = envelope.payload.clone();
                    response
                }
                Err(error) => Envelope::error(envelope.request_id, &error),
            }
        }
        Err(error) => Envelope::error(envelope.request_id, &error),
    }
}

fn descriptor(id: active_rpc::CapId, methods: &[&str]) -> CapDescriptor {
    CapDescriptor {
        id,
        methods: methods.iter().map(|method| method.to_string()).collect(),
        budget: Budget::default(),
        read_only: false,
        redact: false,
        path_scope: None,
    }
}

fn request(id: u64, method: &str, caps: Vec<CapDescriptor>) -> Envelope {
    let mut envelope = Envelope::request(id, method, vec![Arg::text("payload")]);
    envelope.payload = b"payload".to_vec();
    envelope.caps = caps;
    envelope
}

/// Run `calls` requests through a bridge and return their responses.
fn over_bridge<F>(calls: Vec<Envelope>, dispatch: F) -> Vec<Envelope>
where
    F: FnMut(&Envelope) -> Envelope,
{
    let server = BridgeServer::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let count = calls.len();
    let (tx, rx) = mpsc::channel::<(Envelope, mpsc::Sender<Envelope>)>();
    let serving = thread::spawn(move || {
        server
            .serve(count, move |envelope| {
                let (reply_tx, reply_rx) = mpsc::channel();
                if tx.send((envelope, reply_tx)).is_err() {
                    return Envelope::error(0, &Error::Transport("kernel unavailable".to_string()));
                }
                reply_rx.recv().unwrap_or_else(|_| {
                    Envelope::error(0, &Error::Transport("kernel dropped".to_string()))
                })
            })
            .expect("serve")
    });
    let client = thread::spawn(move || {
        let mut client = ConnectClient::connect(&address).expect("connect");
        calls
            .into_iter()
            .map(|envelope| client.call(&envelope).expect("call"))
            .collect::<Vec<_>>()
    });
    let mut responses = Vec::new();
    let mut handler = dispatch;
    for (envelope, reply) in rx {
        let response = handler(&envelope);
        let _ = reply.send(response);
    }
    let _served = serving.join().expect("server");
    responses.extend(client.join().expect("client"));
    responses
}

#[test]
fn a_bridge_call_runs_through_the_real_kernel() {
    let agent = Agent::with_secret([0x4a; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent
        .create_lane("bridge", Budget::default())
        .expect("lane");
    let responses = over_bridge(
        vec![request(11, "echo", vec![descriptor(cap.id(), &["echo"])])],
        move |envelope| dispatch(&agent, lane, envelope),
    );
    let response = &responses[0];
    assert_eq!(response.kind, Kind::Response, "{}", response.method);
    assert_eq!(response.request_id, 11);
    assert_eq!(response.first_value(), Some(&Value::text("bridged")));
    assert_eq!(response.payload, b"payload");
}

#[test]
fn a_refusal_crosses_the_bridge_unchanged() {
    let agent = Agent::with_secret([0x4b; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent
        .create_lane("bridge", Budget::default())
        .expect("lane");
    // No capability at all: the refusal code and request id must survive.
    let responses = over_bridge(vec![request(12, "echo", Vec::new())], move |envelope| {
        dispatch(&agent, lane, envelope)
    });
    let response = &responses[0];
    assert_eq!(response.kind, Kind::Error);
    assert_eq!(response.request_id, 12);
    assert_eq!(response.method, "rpc/unknown-capability");
    let _ = cap;
}

#[test]
fn a_descriptor_cannot_widen_the_registry() {
    let agent = Agent::with_secret([0x4c; 32]);
    let provider = agent.register(Box::new(Echo));
    // The capability grants only `echo`.
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent
        .create_lane("bridge", Budget::default())
        .expect("lane");
    // The bridge client claims a wider method set in its descriptor.
    let responses = over_bridge(
        vec![request(
            13,
            "delete_everything",
            vec![descriptor(cap.id(), &["delete_everything"])],
        )],
        move |envelope| dispatch(&agent, lane, envelope),
    );
    let response = &responses[0];
    assert_eq!(response.kind, Kind::Error);
    assert_eq!(
        response.method, "rpc/method-not-granted",
        "the registry, not the descriptor, is the authority"
    );
}

#[test]
fn a_bound_capability_is_refused_over_the_bridge() {
    let agent = Agent::with_secret([0x4d; 32]);
    let provider = agent.register(Box::new(Echo));
    let peer = PeerIdentity::from_certificate(b"bridge-peer");
    let admitted = IdentityPolicy::default()
        .admit(Some(&peer), true)
        .expect("admit");
    let cap = agent
        .mint_bound(&admitted, provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent
        .create_lane("bridge", Budget::default())
        .expect("lane");
    // The bridge has no authenticated identity, so a bound capability is
    // useless through it.
    let responses = over_bridge(
        vec![request(14, "echo", vec![descriptor(cap.id(), &["echo"])])],
        move |envelope| dispatch(&agent, lane, envelope),
    );
    let response = &responses[0];
    assert_eq!(response.kind, Kind::Error);
    assert_eq!(response.method, "rpc/identity");
}

#[test]
fn a_revoked_capability_is_refused_over_the_bridge() {
    let agent = Agent::with_secret([0x4e; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent
        .create_lane("bridge", Budget::default())
        .expect("lane");
    agent.revoke(&cap).expect("revoke");
    let responses = over_bridge(
        vec![request(15, "echo", vec![descriptor(cap.id(), &["echo"])])],
        move |envelope| dispatch(&agent, lane, envelope),
    );
    let response = &responses[0];
    assert_eq!(response.kind, Kind::Error);
    assert_eq!(response.method, "rpc/revoked");
}

/// A head that stalls past the connection budget is a timeout, and the status
/// line names it (round 23, #1: the catch-all arm said `Internal Server
/// Error`).
#[test]
fn a_stalled_head_is_408_request_timeout() {
    use std::io::{Read, Write};

    let server = BridgeServer::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let client = thread::spawn(move || {
        let mut stream = std::net::TcpStream::connect(&address).expect("connect");
        // A request line and one header, then silence: the head never ends.
        stream
            .write_all(b"POST /active.rpc.v1.Agent/Call HTTP/1.1\r\nhost: active-rpc\r\n")
            .expect("write");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read");
        response
    });

    let mut served = 0;
    server
        .serve(1, |envelope| {
            served += 1;
            Envelope::error(
                envelope.request_id,
                &Error::Transport("unreachable".to_string()),
            )
        })
        .expect("serve");
    let response = client.join().expect("client");
    assert!(
        response.starts_with("HTTP/1.1 408 Request Timeout"),
        "expected a 408 with its reason, got {response:?}"
    );
    assert_eq!(served, 0);
}

/// A head line that is not UTF-8 is a wire fault, not text to decode lossily:
/// a `transfer-encoding` name carrying an invalid byte must not slip past the
/// refusal (round 23, #4).
#[test]
fn a_non_utf8_head_line_is_a_400() {
    use std::io::{Read, Write};

    let server = BridgeServer::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let client = thread::spawn(move || {
        let mut stream = std::net::TcpStream::connect(&address).expect("connect");
        stream
            .write_all(b"POST /active.rpc.v1.Agent/Call HTTP/1.1\r\nhost: active-rpc\r\ntransfer-enc\xffoding: chunked\r\n\r\n")
            .expect("write");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read");
        response
    });

    let mut served = 0;
    server
        .serve(1, |envelope| {
            served += 1;
            Envelope::error(
                envelope.request_id,
                &Error::Transport("unreachable".to_string()),
            )
        })
        .expect("serve");
    let response = client.join().expect("client");
    assert!(
        response.starts_with("HTTP/1.1 400"),
        "expected a 400, got {response:?}"
    );
    assert!(response.contains("rpc/wire"), "{response}");
    assert_eq!(served, 0);
}

/// A request that does not name this service is refused with a class the
/// closed registry holds, so a client can branch on it (round 23, #2). The
/// bridge answered `rpc/not-found`, which is not a kernel class.
#[test]
fn a_wrong_target_is_a_wire_refusal() {
    use std::io::{Read, Write};

    let server = BridgeServer::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let client = thread::spawn(move || {
        let mut stream = std::net::TcpStream::connect(&address).expect("connect");
        stream
            .write_all(
                b"POST /not-the-service HTTP/1.1\r\nhost: active-rpc\r\ncontent-type: application/connect+active-infinity\r\ncontent-length: 0\r\n\r\n",
            )
            .expect("write");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read");
        response
    });

    let mut served = 0;
    server
        .serve(1, |envelope| {
            served += 1;
            Envelope::error(
                envelope.request_id,
                &Error::Transport("unreachable".to_string()),
            )
        })
        .expect("serve");
    let response = client.join().expect("client");
    assert!(
        response.starts_with("HTTP/1.1 404 Not Found"),
        "expected a 404, got {response:?}"
    );
    assert!(response.ends_with("rpc/wire"), "{response}");
    assert_eq!(served, 0);
}

/// A folded or whitespace-only line, and a field whose name is not a token,
/// are refusals, not lines to skip: a gateway that ends the block at the
/// whitespace sees a different request (round 24, F3).
#[test]
fn a_folded_or_untokenized_head_line_is_refused() {
    use std::io::{Read, Write};

    let cases: [&[u8]; 2] = [
        b"POST /active.rpc.v1.Agent/Call HTTP/1.1\r\nhost: active-rpc\r\ncontent-length: 0\r\n \r\ncontent-length: 37\r\n\r\n",
        b"POST /active.rpc.v1.Agent/Call HTTP/1.1\r\nhost: active-rpc\r\nbad name: x\r\ncontent-length: 0\r\n\r\n",
    ];
    for request in cases {
        let server = BridgeServer::bind_loopback().expect("bind");
        let address = server.address().to_string();
        let bytes = request.to_vec();
        let client = thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(&address).expect("connect");
            stream.write_all(&bytes).expect("write");
            let mut response = String::new();
            stream.read_to_string(&mut response).expect("read");
            response
        });
        let mut served = 0;
        server
            .serve(1, |envelope| {
                served += 1;
                Envelope::error(
                    envelope.request_id,
                    &Error::Transport("unreachable".to_string()),
                )
            })
            .expect("serve");
        let response = client.join().expect("client");
        assert!(
            response.starts_with("HTTP/1.1 400"),
            "expected a 400, got {response:?}"
        );
        assert_eq!(served, 0);
    }
}

/// A body that runs past the connection budget is a timeout, matching the head
/// path and the interop spec (round 24, F4).
#[test]
fn a_stalled_body_is_408_request_timeout() {
    use std::io::{Read, Write};

    let server = BridgeServer::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let client = thread::spawn(move || {
        let mut stream = std::net::TcpStream::connect(&address).expect("connect");
        stream
            .write_all(
                b"POST /active.rpc.v1.Agent/Call HTTP/1.1\r\nhost: active-rpc\r\ncontent-type: application/connect+active-infinity\r\ncontent-length: 64\r\n\r\n",
            )
            .expect("write");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read");
        response
    });
    let mut served = 0;
    server
        .serve(1, |envelope| {
            served += 1;
            Envelope::error(
                envelope.request_id,
                &Error::Transport("unreachable".to_string()),
            )
        })
        .expect("serve");
    let response = client.join().expect("client");
    assert!(
        response.starts_with("HTTP/1.1 408 Request Timeout"),
        "expected a 408, got {response:?}"
    );
    assert!(response.contains("rpc/transport"), "{response}");
    assert_eq!(served, 0);
}

/// The client reads only a three-digit status: a lenient `u16` parse accepted
/// `+200` and treated an intermediary's non-status as success (round 24, F7).
#[test]
fn a_non_three_digit_status_is_a_wire_fault() {
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address").to_string();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut scratch = [0u8; 4096];
        let _ = stream.read(&mut scratch);
        stream
            .write_all(b"HTTP/1.1 +200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .expect("write");
        let _ = stream.flush();
        // Half-close and wait for the client: a plain drop with queued data can
        // reset the connection on Windows and discard the response, which made
        // this test fail under load (flake seen in the full suite).
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut sink = [0u8; 1024];
        let _ = stream.read(&mut sink);
    });
    let mut client = ConnectClient::connect(&address).expect("connect");
    let error = client
        .call(&request(18, "echo", Vec::new()))
        .expect_err("a signed status is not a status");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    server.join().expect("server");
}

/// A reader that consumes a byte just inside the write timeout cannot hold the
/// serial bridge: every write is bounded by the connection deadline
/// (round 25, #2).
#[test]
fn a_dripping_reader_cannot_hold_the_bridge_response() {
    use active_rpc::transport::connect::{grpc_frame, CONNECT_TYPE, PATH};
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let server = BridgeServer::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let body =
        grpc_frame(&request(29, "echo", Vec::new()).encode().expect("encode")).expect("frame");
    // The drip stops when the serve returns, so the test pays for the bridge's
    // bound and not for a fixed sleep; the flag and the read timeout keep the
    // join prompt even when the server closed the socket mid-drip.
    let finished = Arc::new(AtomicBool::new(false));
    let client_finished = Arc::clone(&finished);
    let client = thread::spawn(move || {
        let mut stream = std::net::TcpStream::connect(&address).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("read timeout");
        let head = format!(
            "POST {PATH} HTTP/1.1\r\nhost: active-rpc\r\ncontent-type: {CONNECT_TYPE}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).expect("head");
        stream.write_all(&body).expect("body");
        // One byte per 300 ms: each read resets the socket timeout the client
        // does not have, and each write is a little progress. The drip keeps
        // going while the serve is running, so a regression to an unbounded
        // write shows up as a serve that never returns rather than a margin a
        // loaded machine can eat.
        let mut one = [0u8; 1];
        // A hard stop turns a regression into a failed assertion rather than a
        // suite that never finishes.
        let until = Instant::now() + Duration::from_secs(12);
        while !client_finished.load(Ordering::SeqCst) && Instant::now() < until {
            match stream.read(&mut one) {
                Ok(0) => break,
                Ok(_) => std::thread::sleep(Duration::from_millis(300)),
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    });

    let started = Instant::now();
    let mut served = 0;
    server
        .serve(1, |envelope| {
            served += 1;
            Envelope::response(envelope.request_id, Value::text("x".repeat(200_000)))
        })
        .expect("serve");
    let elapsed = started.elapsed();
    finished.store(true, Ordering::SeqCst);
    assert_eq!(served, 1, "the call reached the handler");
    assert!(
        elapsed < Duration::from_secs(5),
        "a dripping reader held the bridge for {elapsed:?}"
    );
    client.join().expect("client");
}

/// A body the bridge can only refuse is refused before the write
/// (round 25, #5).
#[test]
fn an_oversized_post_is_refused_before_framing() {
    let client = ConnectClient::connect("127.0.0.1:9")
        .expect("connect")
        .with_limits(active_rpc::WireLimits::strict());
    let mut client = client;
    let body = vec![0u8; 2 << 20];
    let error = client.post_raw(&body).expect_err("over the ceiling");
    assert_eq!(error.code(), "rpc/wire", "{error}");
}

/// A repeated `content-type` and a request line with a fourth token are
/// ambiguities a proxy may resolve differently (round 25, #6).
#[test]
fn an_ambiguous_head_is_refused() {
    use std::io::{Read, Write};

    let cases: [&[u8]; 3] = [
        b"POST /active.rpc.v1.Agent/Call HTTP/1.1\r\nhost: active-rpc\r\ncontent-type: application/connect+active-infinity\r\ncontent-type: application/connect+active-infinity\r\ncontent-length: 0\r\n\r\n",
        b"POST /active.rpc.v1.Agent/Call HTTP/1.1 extra\r\nhost: active-rpc\r\ncontent-type: application/connect+active-infinity\r\ncontent-length: 0\r\n\r\n",
        b"POST /active.rpc.v1.Agent/Call HTTP/1.0\r\nhost: active-rpc\r\ncontent-type: application/connect+active-infinity\r\ncontent-length: 0\r\n\r\n",
    ];
    for request in cases {
        let server = BridgeServer::bind_loopback().expect("bind");
        let address = server.address().to_string();
        let bytes = request.to_vec();
        let client = thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(&address).expect("connect");
            stream.write_all(&bytes).expect("write");
            let mut response = String::new();
            stream.read_to_string(&mut response).expect("read");
            response
        });
        let mut served = 0;
        server
            .serve(1, |envelope| {
                served += 1;
                Envelope::error(
                    envelope.request_id,
                    &Error::Transport("unreachable".to_string()),
                )
            })
            .expect("serve");
        let response = client.join().expect("client");
        assert!(
            response.starts_with("HTTP/1.1 400"),
            "expected a 400, got {response:?}"
        );
        assert_eq!(served, 0);
    }
}

/// The two bridges agree on the status for a wrong method: 405
/// (round 26, #8).
#[test]
fn a_get_is_405_on_the_bridge() {
    use std::io::{Read, Write};

    let server = BridgeServer::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let client = thread::spawn(move || {
        let mut stream = std::net::TcpStream::connect(&address).expect("connect");
        stream
            .write_all(
                b"GET /active.rpc.v1.Agent/Call HTTP/1.1\r\nhost: active-rpc\r\ncontent-length: 0\r\n\r\n",
            )
            .expect("write");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read");
        response
    });
    let mut served = 0;
    server
        .serve(1, |envelope| {
            served += 1;
            Envelope::error(envelope.request_id, &Error::Transport("x".to_string()))
        })
        .expect("serve");
    let response = client.join().expect("client");
    assert!(
        response.starts_with("HTTP/1.1 405 Method Not Allowed"),
        "{response:?}"
    );
    assert!(
        response.to_ascii_lowercase().contains("allow: post"),
        "{response:?}"
    );
    assert_eq!(served, 0);
}

/// A response field the server would refuse is refused by the client too
/// (round 26, #3).
#[test]
fn a_malformed_response_head_line_is_a_wire_fault() {
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address").to_string();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut scratch = [0u8; 4096];
        let _ = stream.read(&mut scratch);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nbogus line without a colon\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .expect("write");
    });
    let mut client = ConnectClient::connect(&address).expect("connect");
    let error = client
        .call(&request(30, "echo", Vec::new()))
        .expect_err("a malformed field");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    server.join().expect("server");
}

/// An answer for another request is not this call's result
/// (round 28, low).
#[test]
fn an_answer_for_another_request_is_refused() {
    use active_rpc::transport::connect::{grpc_frame, CONNECT_TYPE};
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address").to_string();
    let body = grpc_frame(
        &Envelope::response(99, Value::Null)
            .encode()
            .expect("encode"),
    )
    .expect("frame");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut scratch = [0u8; 4096];
        let _ = stream.read(&mut scratch);
        let head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: {CONNECT_TYPE}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).expect("head");
        stream.write_all(&body).expect("body");
        // Close gracefully: a reset can discard the response on Windows.
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut sink = [0u8; 64];
        let _ = stream.read(&mut sink);
    });
    let mut client = ConnectClient::connect(&address).expect("connect");
    let error = client
        .call(&request(1, "echo", Vec::new()))
        .expect_err("a mismatched answer");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    server.join().expect("server");
}

/// A truncated body is one bad connection: the bridge answers 400 and keeps
/// accepting. Before this, the read error aborted `serve`, so one hostile
/// connection could refuse service to every later caller.
#[test]
fn a_truncated_body_gets_a_400_and_the_bridge_keeps_serving() {
    use std::io::{Read, Write};

    let agent = Agent::with_secret([0x4f; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent
        .create_lane("bridge", Budget::default())
        .expect("lane");
    let server = BridgeServer::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let cap_id = cap.id();

    let bad_address = address.clone();
    let bad = thread::spawn(move || {
        let mut stream = std::net::TcpStream::connect(&bad_address).expect("connect");
        // Announce 64 bytes, send three, then close the write side.
        stream
            .write_all(
                b"POST /active.rpc.v1.Agent/Call HTTP/1.1\r\nhost: active-rpc\r\ncontent-type: application/connect+active-infinity\r\ncontent-length: 64\r\n\r\nabc",
            )
            .expect("write");
        stream
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read");
        response
    });

    let mut served = 0;
    server
        .serve(1, |envelope| {
            served += 1;
            dispatch(&agent, lane, &envelope)
        })
        .expect("serve");
    let response = bad.join().expect("bad client");
    assert!(
        response.starts_with("HTTP/1.1 400"),
        "expected a 400, got {response:?}"
    );
    // The truncated connection never reached the kernel.
    assert_eq!(served, 0);

    // A healthy client still works against the same server object, which is
    // the point: one bad connection did not take the bridge down. The client
    // connects on its own thread because `serve` blocks on accept.
    let good_address = address.clone();
    let good = thread::spawn(move || {
        let mut client = ConnectClient::connect(&good_address).expect("connect");
        client
            .call(&request(16, "echo", vec![descriptor(cap_id, &["echo"])]))
            .expect("call")
    });
    server
        .serve(1, |envelope| {
            served += 1;
            dispatch(&agent, lane, &envelope)
        })
        .expect("serve");
    let response = good.join().expect("good client");
    assert_eq!(served, 1);
    assert_eq!(response.kind, Kind::Response);
    assert_eq!(response.first_value(), Some(&Value::text("bridged")));
}

/// A server that announces a large body and sends a few bytes makes the client
/// fail without allocating the announced size.
#[test]
fn a_short_response_body_is_a_transport_error() {
    use std::io::{BufRead, BufReader, Write};

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let address = listener.local_addr().expect("addr").to_string();
    let serving = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        // Consume the whole request head first: closing with unread bytes makes
        // Windows answer with a reset instead of a clean end of stream.
        {
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                if line.trim_end().is_empty() {
                    break;
                }
            }
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 60000000\r\n\r\nabcd")
            .expect("write");
        stream.flush().expect("flush");
        stream
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown write");
        // Keep the socket open briefly so the client observes end of stream
        // rather than a reset.
        thread::sleep(std::time::Duration::from_millis(200));
    });
    let mut client = ConnectClient::connect(&address).expect("connect");
    let error = client
        .call(&request(17, "echo", Vec::new()))
        .expect_err("a short body must be refused");
    assert!(
        error.to_string().contains("shorter than declared"),
        "{error}"
    );
    serving.join().expect("server");
}

/// A framed message past the bridge's body ceiling is refused, not asserted:
/// a direct caller may hold bytes the shipped paths never bound
/// (round 35, R-09 #2).
#[test]
fn grpc_frame_refuses_a_message_past_its_ceiling() {
    use active_rpc::transport::connect::grpc_frame;

    let small = grpc_frame(b"hello").expect("a small message frames");
    assert_eq!(small.len(), 5 + 5);
    let huge = vec![0u8; active_rpc::transport::connect::MAX_BODY + 1];
    let error = grpc_frame(&huge).expect_err("past the ceiling");
    assert_eq!(error.code(), "rpc/wire", "{error}");
}

/// A body that stops short of its declared length is a framing fault, not a
/// retryable network condition: retrying a mutating call because the answer was
/// truncated would execute it twice (round 13, R-09 #1).
#[test]
fn a_truncated_bridge_response_is_a_wire_fault() {
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address").to_string();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut sink = [0u8; 4096];
        let _ = stream.read(&mut sink);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 4096\r\nconnection: close\r\n\r\nshort")
            .expect("write");
        let _ = stream.flush();
        // Keep the socket open until the client gave up, so the short body is a
        // truncation and not an end-of-stream the reader could explain away.
        let mut tail = [0u8; 1024];
        let _ = stream.read(&mut tail);
    });
    let mut client = ConnectClient::connect(&address).expect("connect");
    let error = client
        .call(&request(21, "echo", Vec::new()))
        .expect_err("the body is shorter than declared");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    server.join().expect("server");
}

/// An error may carry id 0 when the bridge could not read the frame far enough
/// to learn the id; the bridge client accepts it, as QUIC, TCP and shared
/// memory do (round 14, F-5).
#[test]
fn a_bridge_error_with_id_zero_is_this_calls_answer() {
    use active_rpc::transport::connect::{grpc_frame, CONNECT_TYPE};
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address").to_string();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut scratch = [0u8; 4096];
        let _ = stream.read(&mut scratch);
        let error = Envelope::error(0, &Error::Wire("the frame could not be read"));
        let body = grpc_frame(&error.encode().expect("encode")).expect("frame");
        let mut head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: {CONNECT_TYPE}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        head.extend_from_slice(&body);
        stream.write_all(&head).expect("write");
        let _ = stream.flush();
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let _ = stream.read(&mut scratch);
    });
    let mut client = ConnectClient::connect(&address).expect("connect");
    let answer = client
        .call(&request(31, "echo", Vec::new()))
        .expect("id 0 is legal for an error");
    assert_eq!(answer.kind, Kind::Error);
    assert_eq!(answer.method, "rpc/wire");
    server.join().expect("server");
}
