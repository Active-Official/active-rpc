//! Transport × capability-binding matrix.
//!
//! A capability bound to an authenticated peer must be refused by every
//! transport that cannot present that identity, and an unbound capability must
//! keep working over each transport. QUIC mutual TLS lives in
//! `identity_tests.rs`; this file covers TCP, Connect and HTTP/2.

use std::thread;

#[cfg(feature = "http2")]
use std::sync::mpsc;

use active_rpc::cap::CapAttrs;
use active_rpc::identity::{IdentityPolicy, PeerIdentity};
use active_rpc::kernel::Provider;
use active_rpc::transport::connect::{BridgeServer, ConnectClient};
#[cfg(feature = "http2")]
use active_rpc::transport::http2::{Http2Client, Http2Server};
use active_rpc::transport::{bind_loopback, serve_connection, TcpTransport, Transport};
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::wire::{CapDescriptor, Envelope, Kind};
use active_rpc::{Agent, Budget, CapHandle, CapId};

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

    fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(
            call.args
                .iter()
                .find_map(|arg| match arg {
                    Arg::Value(value) => Some(value.clone()),
                    _ => None,
                })
                .unwrap_or(Value::text("ok")),
        ))
    }
}

struct Fixture {
    agent: Agent,
    lane: active_rpc::LaneId,
    bound: CapHandle,
    unbound: CapHandle,
}

fn fixture() -> Fixture {
    let agent = Agent::with_secret([0x5b; 32]);
    let provider = agent.register(Box::new(Echo));
    let peer = PeerIdentity::from_certificate(b"transport-matrix-peer");
    let admitted = IdentityPolicy::default()
        .admit(Some(&peer), true)
        .expect("admit");
    let bound = agent
        .mint_bound(&admitted, provider, 0, CapAttrs::new(&["echo"]))
        .expect("bound cap");
    let unbound = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("unbound cap");
    let lane = agent
        .create_lane("matrix", Budget::default())
        .expect("lane");
    Fixture {
        agent,
        lane,
        bound,
        unbound,
    }
}

fn descriptor(id: CapId) -> CapDescriptor {
    CapDescriptor {
        id,
        methods: ["echo".to_string()].into_iter().collect(),
        budget: Budget::default(),
        read_only: false,
        redact: false,
        path_scope: None,
    }
}

fn request(id: CapId) -> Envelope {
    let mut envelope = Envelope::request(7, "echo", vec![Arg::text("payload")]);
    envelope.caps = vec![descriptor(id)];
    envelope
}

/// Dispatch as an unauthenticated transport would: no peer identity.
fn dispatch_unauthenticated(
    agent: &Agent,
    lane: active_rpc::LaneId,
    envelope: &Envelope,
) -> Envelope {
    let Some(descriptor) = envelope.caps.first() else {
        return Envelope::error(
            envelope.request_id,
            &active_rpc::Error::UnknownCapability(active_rpc::CapToken(0)),
        );
    };
    let cap = agent.import(descriptor.id);
    match agent.call_as(None, lane, &cap, &envelope.method, envelope.args.clone()) {
        Ok(promise) => {
            agent.run();
            match promise.value() {
                Ok(value) => Envelope::response(envelope.request_id, value),
                Err(error) => Envelope::error(envelope.request_id, &error),
            }
        }
        Err(error) => Envelope::error(envelope.request_id, &error),
    }
}

fn assert_refused(response: &Envelope, code: &str) {
    assert_eq!(response.kind, Kind::Error, "expected a refusal");
    assert_eq!(response.method, code, "{}", response.method);
}

fn assert_response(response: &Envelope) {
    assert_eq!(response.kind, Kind::Response, "method={}", response.method);
}

#[test]
fn tcp_refuses_a_bound_capability_and_accepts_an_unbound_one() {
    let fixture = fixture();
    let (listener, address) = bind_loopback().expect("bind");
    let bound_id = fixture.bound.id();
    let unbound_id = fixture.unbound.id();
    let client = thread::spawn(move || {
        let mut transport = TcpTransport::connect(&address).expect("connect");
        transport.send(&request(bound_id)).expect("send");
        let bound = transport.recv().expect("recv").expect("response");
        transport.send(&request(unbound_id)).expect("send");
        let unbound = transport.recv().expect("recv").expect("response");
        (bound, unbound)
    });
    // Both requests travel on one connection; the client closes it afterwards.
    let (stream, _) = listener.accept().expect("accept");
    let transport = TcpTransport::new(stream).expect("transport");
    serve_connection(transport, |envelope| {
        dispatch_unauthenticated(&fixture.agent, fixture.lane, &envelope)
    })
    .expect("serve");
    let (bound, unbound) = client.join().expect("client");
    assert_refused(&bound, "rpc/identity");
    assert_response(&unbound);
}

#[test]
fn connect_refuses_a_bound_capability_and_accepts_an_unbound_one() {
    let fixture = fixture();
    let server = BridgeServer::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let bound_id = fixture.bound.id();
    let unbound_id = fixture.unbound.id();
    let client = thread::spawn(move || {
        let mut client = ConnectClient::connect(&address).expect("connect");
        let bound = client.call(&request(bound_id)).expect("call");
        let unbound = client.call(&request(unbound_id)).expect("call");
        (bound, unbound)
    });
    server
        .serve(2, |envelope| {
            dispatch_unauthenticated(&fixture.agent, fixture.lane, &envelope)
        })
        .expect("serve");
    let (bound, unbound) = client.join().expect("client");
    assert_refused(&bound, "rpc/identity");
    assert_response(&unbound);
}

#[cfg(feature = "http2")]
#[test]
fn http2_refuses_a_bound_capability_and_accepts_an_unbound_one() {
    let fixture = fixture();
    let server = Http2Server::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let bound_id = fixture.bound.id();
    let unbound_id = fixture.unbound.id();
    let (tx, rx) = mpsc::channel::<(Envelope, mpsc::Sender<Envelope>)>();
    let serving = thread::spawn(move || {
        server.serve(1, move |envelope| {
            let (reply_tx, reply_rx) = mpsc::channel();
            if tx.send((envelope, reply_tx)).is_err() {
                return Envelope::error(
                    0,
                    &active_rpc::Error::Transport("kernel unavailable".to_string()),
                );
            }
            reply_rx.recv().unwrap_or_else(|_| {
                Envelope::error(
                    0,
                    &active_rpc::Error::Transport("kernel dropped".to_string()),
                )
            })
        })
    });
    let client = thread::spawn(move || {
        let mut client = Http2Client::connect(&address).expect("connect");
        let bound = client.call(&request(bound_id)).expect("call");
        let unbound = client.call(&request(unbound_id)).expect("call");
        (bound, unbound)
    });
    for (envelope, reply) in rx {
        let response = dispatch_unauthenticated(&fixture.agent, fixture.lane, &envelope);
        let _ = reply.send(response);
    }
    let served = serving.join().expect("server").expect("serve");
    assert_eq!(served, 2);
    let (bound, unbound) = client.join().expect("client");
    assert_refused(&bound, "rpc/identity");
    assert_response(&unbound);
}
