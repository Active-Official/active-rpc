//! Cross-process peer for the integration tests and the agent-to-agent demo.
//!
//! ```bash
//! active-rpc-peer --listen 127.0.0.1:0
//! ```
//!
//! The peer prints `listening <address>` on stdout, serves envelopes until its
//! client closes the connection (or until `--calls N` calls are served), and
//! exposes:
//!
//! - `hello` — peer identity and capability id;
//! - `ping` — liveness;
//! - `pipeline` — two dependent calls with a promise between them, reported
//!   with the number of provider round-trips;
//! - `sequential` — the same two calls with a client wait between them;
//! - every domain method of a module capability installed from the embedded
//!   Active document.

use std::collections::BTreeMap;
use std::io::Write;

use active_rpc::cap::CapAttrs;
use active_rpc::domain::ModuleProvider;
use active_rpc::identity::IdentityPolicy;
use active_rpc::transport::{serve_connection, TcpTransport};
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::wire::{Envelope, Kind};
use active_rpc::{Agent, Budget, Error, Provider};

const SOURCE: &str = r#"
# @intent: "Peer module"
[peer]
name = "active-rpc-peer"
port = 7070

let timeout = 1500ms

[limits]
read_timeout = timeout * 2
secret_token = secret("peer-canary")
"#;

/// A tiny echo provider used to demonstrate pipelining without a module.
struct EchoProvider;

impl Provider for EchoProvider {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn methods(&self) -> Vec<String> {
        vec!["echo".to_string(), "upper".to_string()]
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
            .unwrap_or(Value::Null);
        let out = match call.method.as_str() {
            "upper" => {
                let upper = match &value {
                    Value::Text(text) => text.to_uppercase(),
                    other => format!("{other:?}").to_uppercase(),
                };
                Value::Text(upper)
            }
            _ => value,
        };
        Ok(Response::Value(out))
    }
}

/// How long one connection may stall before it is given up on.
///
/// The peer serves one connection at a time; without this a client that connects
/// and sends nothing holds every later peer in the accept backlog.
const CONNECTION_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Accept failures tolerated in a row before the peer gives up.
const MAX_ACCEPT_FAILURES: u32 = 64;

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut address = "127.0.0.1:0".to_string();
    let mut max_calls: usize = 0;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => address = args.next().unwrap_or_default(),
            "--calls" => {
                max_calls = args
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0)
            }
            other => return Err(format!("unknown argument {other}").into()),
        }
    }

    let module = active_rpc::domain::module_from_source(SOURCE, "peer.active")?;
    let mut module_provider = ModuleProvider::new();
    let module_object = module_provider.install(module)?;

    let agent = Agent::new();
    let module_provider_id = agent.register(Box::new(module_provider))?;
    let echo_provider_id = agent.register(Box::new(EchoProvider))?;
    let module_cap = agent.mint(
        module_provider_id,
        module_object,
        CapAttrs::new(active_rpc::MODULE_METHODS),
    )?;
    let echo_cap = agent.mint(echo_provider_id, 0, CapAttrs::new(&["echo", "upper"]))?;
    let lane = agent.create_lane("peer", Budget::default())?;

    let listener = std::net::TcpListener::bind(&address)?;
    let local = listener.local_addr()?;
    // A plain TCP peer carries no identity, so the only honest admission rule is
    // the loopback one: a local caller is a loopback peer (which cannot hold a
    // binding), and anything off-host is refused rather than silently admitted.
    let policy = IdentityPolicy::default();
    let bound = local.to_string();
    println!("listening {bound}");
    std::io::stdout().flush()?;

    let mut served = 0usize;
    let mut accept_failures = 0u32;
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => {
                accept_failures = 0;
                stream
            }
            // A peer that went away between the SYN and the accept is not the
            // server's failure, and a run of failures must back off instead of
            // spinning or exiting.
            Err(_) if accept_failures < MAX_ACCEPT_FAILURES => {
                accept_failures += 1;
                std::thread::sleep(std::time::Duration::from_millis(5));
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        // The flag describes this connection, not the listener: a wildcard bind
        // must still treat a remote client as remote, and must still serve a
        // genuinely local one.
        let loopback = stream
            .peer_addr()
            .map(|peer| peer.ip().is_loopback())
            .unwrap_or(false);
        // A silent client must not hold this serial loop forever: the socket
        // carries a read and write deadline, so a stalled connection ends and the
        // next peer is accepted.
        // A socket that was reset between accept and here is this connection;
        // the peer keeps serving.
        let transport = match TcpTransport::with_timeout(stream, CONNECTION_WAIT) {
            Ok(transport) => transport,
            Err(_) => continue,
        };
        // Serial by contract (RPC-57, R09-3): one handler at a time, no
        // deadline on handler time — a slow provider call stalls every later
        // peer. This is the local/dev server; deployments that need
        // concurrency use QUIC or HTTP/2.
        let handled = serve_connection(transport, |envelope| {
            handle(
                &agent,
                lane,
                &policy,
                loopback,
                &module_cap,
                &echo_cap,
                envelope,
            )
        })?;
        served += handled as usize;
        if max_calls != 0 && served >= max_calls {
            break;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle(
    agent: &Agent,
    lane: active_rpc::LaneId,
    policy: &IdentityPolicy,
    loopback: bool,
    module_cap: &active_rpc::CapHandle,
    echo_cap: &active_rpc::CapHandle,
    envelope: Envelope,
) -> Envelope {
    match dispatch(
        agent, lane, policy, loopback, module_cap, echo_cap, &envelope,
    ) {
        Ok(value) => Envelope::response(envelope.request_id, value),
        Err(error) => Envelope::error(envelope.request_id, &error),
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch(
    agent: &Agent,
    lane: active_rpc::LaneId,
    policy: &IdentityPolicy,
    loopback: bool,
    module_cap: &active_rpc::CapHandle,
    echo_cap: &active_rpc::CapHandle,
    envelope: &Envelope,
) -> active_rpc::Result<Value> {
    if envelope.kind != Kind::Request {
        return Err(Error::Wire("peer only serves requests"));
    }
    // Admission covers every arm, not only the one that forwards the caller's
    // authority: `pipeline` and `sequential` spend the peer's own capability and
    // the shared lane's call budget, so an unadmitted caller must not reach them
    // either.
    let admitted = policy.admit(None, loopback)?;
    match envelope.method.as_str() {
        "hello" => {
            let mut map = BTreeMap::new();
            map.insert("peer".to_string(), Value::text("active-rpc-peer"));
            map.insert("version".to_string(), Value::text(active_rpc::VERSION));
            map.insert("capability".to_string(), Value::text(module_cap.id().hex()));
            map.insert(
                "methods".to_string(),
                Value::Int(active_rpc::MODULE_METHODS.len() as i64),
            );
            Ok(Value::Map(map))
        }
        "ping" => Ok(Value::text("pong")),
        "pipeline" => {
            // Two dependent calls: `upper(echo("x"))` with the inner result
            // passed as a promise, both dispatched in one provider batch.
            let before = agent.round_trips();
            let first = agent.call(lane, echo_cap, "echo", vec![Arg::text("pipeline")])?;
            let second = agent.call(lane, echo_cap, "upper", vec![Arg::Promise(first.id())])?;
            let value = second.value()?;
            let round_trips = agent.round_trips() - before;
            let mut map = BTreeMap::new();
            map.insert("result".to_string(), value);
            map.insert("round_trips".to_string(), Value::Int(round_trips as i64));
            Ok(Value::Map(map))
        }
        "sequential" => {
            let before = agent.round_trips();
            let first = agent.call(lane, echo_cap, "echo", vec![Arg::text("sequential")])?;
            let inner = first.value()?;
            let second = agent.call(lane, echo_cap, "upper", vec![Arg::Value(inner)])?;
            let value = second.value()?;
            let round_trips = agent.round_trips() - before;
            let mut map = BTreeMap::new();
            map.insert("result".to_string(), value);
            map.insert("round_trips".to_string(), Value::Int(round_trips as i64));
            Ok(Value::Map(map))
        }
        _ => {
            // Charge the envelope payload against the capability's byte budget,
            // exactly as the thin-client peers do.
            let promise =
                agent.call_from_envelope(Some(admitted.identity()), lane, module_cap, envelope)?;
            promise.value()
        }
    }
}
