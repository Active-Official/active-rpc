//! A real-kernel peer for the polyglot thin-client suite.
//!
//! It mints a capability for an `echo` provider, prints the bound address and
//! the capability id, then serves up to 512 TCP connections (one request each):
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

/// Consecutive `accept` failures with no connection served before the peer
/// gives up. One aborted connection is transient; a broken listener is not.
const MAX_ACCEPT_FAILURES: u32 = 64;

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
    let promise = agent.call_from_envelope(None, lane, &cap, envelope)?;
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

    // One connection per request. The matrix runs three calls per client, so
    // the budget must cover every client in the polyglot row (24 today).
    //
    // A transient `accept` error must not end the peer: the client matrix is
    // long-lived and a single aborted connection (ECONNABORTED) would otherwise
    // silently close the listener, and every later client would see
    // ECONNREFUSED. Only a run of failures with no progress ends the loop, and
    // that path says why on stderr.
    let mut served = 0u64;
    let mut failures = 0u32;
    for _ in 0..512 {
        let (stream, _) = match listener.accept() {
            Ok(pair) => {
                failures = 0;
                pair
            }
            Err(error) => {
                failures += 1;
                eprintln!("thin_peer: accept failed ({failures}): {error}");
                if failures >= MAX_ACCEPT_FAILURES {
                    eprintln!("thin_peer: giving up after {served} connections");
                    return Err(error.into());
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
                continue;
            }
        };
        // A client that connects and never sends would block the loop forever.
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
        let Ok(mut transport) = TcpTransport::new(stream) else {
            continue;
        };
        if let Ok(Some(envelope)) = transport.recv() {
            served += 1;
            // A progress line every so often makes a CI log show how far the
            // matrix got, and how many connections it really used.
            if served.is_multiple_of(64) {
                eprintln!("thin_peer: served {served} connections");
            }
            let request_id = envelope.request_id;
            let payload = envelope.payload.clone();
            let response = match dispatch(&agent, lane, &envelope) {
                Ok(value) => Envelope::response(request_id, value).with_payload(payload),
                Err(error) => Envelope::error(request_id, &error),
            };
            let _ = transport.send(&response);
        }
    }
    eprintln!("thin_peer: served {served} connections");
    Ok(())
}
