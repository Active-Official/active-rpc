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
    agent.revoke(&cap);
    let responses = over_bridge(
        vec![request(15, "echo", vec![descriptor(cap.id(), &["echo"])])],
        move |envelope| dispatch(&agent, lane, envelope),
    );
    let response = &responses[0];
    assert_eq!(response.kind, Kind::Error);
    assert_eq!(response.method, "rpc/revoked");
}
