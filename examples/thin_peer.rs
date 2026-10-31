//! A real-kernel peer for the polyglot thin-client suite.
//!
//! It mints a capability for an `echo` provider, prints the bound address and
//! the capability id, then serves up to 64 TCP connections (one request each):
//!
//! ```text
//! 127.0.0.1:54321
//! cap 0123456789abcdef0123456789abcdef
//! ```
//!
//! A client must present the capability descriptor in the request's capability
//! table. An unknown or missing id is refused with `rpc/unknown-capability`, and
//! a method outside the grant with `rpc/method-not-granted`, so the test
//! exercises the real registry rather than a hard-coded answer.
//!
//! Run: `cargo run --example thin_peer`

use std::io::Write;

use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::transport::{bind_loopback, TcpTransport, Transport};
use active_rpc::value::{Arg, Value};
use active_rpc::wire::Envelope;
use active_rpc::{Agent, Budget, Call, CapToken, Error, Response};

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
        let value = call
            .args
            .iter()
            .find_map(|arg| match arg {
                Arg::Value(value) => Some(value.clone()),
                _ => None,
            })
            .unwrap_or(Value::text("ok"));
        Ok(Response::Value(value))
    }
}

fn dispatch(agent: &Agent, lane: active_rpc::LaneId, envelope: &Envelope) -> Result<Value, Error> {
    let descriptor = envelope
        .caps
        .first()
        .ok_or(Error::UnknownCapability(CapToken(0)))?;
    let cap = agent.import(descriptor.id);
    let promise = agent.call_with_payload(
        lane,
        &cap,
        &envelope.method,
        envelope.args.clone(),
        envelope.payload.len() as u64,
    )?;
    let _ = agent.run();
    promise.value()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let agent = Agent::with_secret([0x5a; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent.mint(provider, 0, CapAttrs::new(&["echo"]))?;
    let lane = agent.create_lane("thin", Budget::default())?;

    let (listener, address) = bind_loopback()?;
    println!("{address}");
    println!("cap {}", cap.id().hex());
    std::io::stdout().flush()?;

    for _ in 0..64 {
        let (stream, _) = match listener.accept() {
            Ok(pair) => pair,
            Err(_) => break,
        };
        let mut transport = TcpTransport::new(stream)?;
        if let Ok(Some(envelope)) = transport.recv() {
            let request_id = envelope.request_id;
            let payload = envelope.payload.clone();
            let response = match dispatch(&agent, lane, &envelope) {
                Ok(value) => Envelope::response(request_id, value).with_payload(payload),
                Err(error) => Envelope::error(request_id, &error),
            };
            let _ = transport.send(&response);
        }
    }
    Ok(())
}
