//! Production CLI for Active RPC.
//!
//! Commands are real: every peer mints a capability in a real kernel, every
//! call goes through the real transport stack, and the client surfaces the
//! stable `rpc/...` refusal codes. The kernel is single-threaded by design, so
//! the peer keeps it on the main thread and forwards envelopes from the
//! transport thread over a channel.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::transport::connect::{BridgeServer, ConnectClient};
use active_rpc::transport::http2::{Http2Client, Http2Server};
use active_rpc::transport::quic::{QuicClient, QuicServer};
use active_rpc::transport::{bind_loopback, serve_connection, TcpTransport, Transport};
use active_rpc::wire::{CapDescriptor, Envelope, Kind};
use active_rpc::{
    Agent, Arg, Budget, Call, CapId, CapToken, Error, LaneId, Response, Value, VERSION,
};

const EXIT_REFUSED: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_TRANSPORT: u8 = 3;

struct CliError {
    code: u8,
    message: String,
}

impl CliError {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_USAGE,
            message: message.into(),
        }
    }

    fn refused(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_REFUSED,
            message: message.into(),
        }
    }

    fn transport(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_TRANSPORT,
            message: message.into(),
        }
    }
}

type CliResult = Result<(), CliError>;

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {}", error.message);
            ExitCode::from(error.code)
        }
    }
}

fn run(args: Vec<String>) -> CliResult {
    let Some(command) = args.first().map(String::as_str) else {
        return Err(CliError::usage(help_text()));
    };
    match command {
        "doctor" => doctor(&args),
        "peer" => peer(&args),
        "call" => call(&args),
        "pipeline" => pipeline(&args),
        "loadgen" => loadgen(&args),
        "bridge" => bridge(&args),
        "events" => events(&args),
        "help" | "--help" | "-h" => {
            println!("{}", help_text());
            Ok(())
        }
        other => Err(CliError::usage(format!(
            "unknown command {other}\n\n{}",
            help_text()
        ))),
    }
}

/// Providers used by every demo peer.
struct Echo;

impl Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn methods(&self) -> Vec<String> {
        vec!["echo".to_string(), "sum".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
        if call.method == "sum" {
            let mut total = 0i64;
            for arg in &call.args {
                if let Arg::Value(Value::Int(value)) = arg {
                    total += value;
                }
            }
            return Ok(Response::Value(Value::Int(total)));
        }
        let value = call
            .args
            .iter()
            .find_map(|arg| match arg {
                Arg::Value(value) => Some(value.clone()),
                _ => None,
            })
            .unwrap_or_else(|| Value::text("ok"));
        Ok(Response::Value(value))
    }
}

struct Kernel {
    agent: Agent,
    lane: LaneId,
    // The minting handle must stay alive: dropping the last handle releases the
    // capability and the registry entry with it.
    cap: active_rpc::CapHandle,
}

fn kernel(methods: &[String]) -> Result<Kernel, CliError> {
    let agent = Agent::new();
    let provider = agent.register(Box::new(Echo));
    let methods: Vec<String> = methods.to_vec();
    let attrs = CapAttrs::new(&methods.iter().map(String::as_str).collect::<Vec<_>>());
    let cap = agent
        .mint(provider, 0, attrs)
        .map_err(|error| CliError::refused(error.to_string()))?;
    let lane = agent
        .create_lane("cli", Budget::default())
        .map_err(|error| CliError::refused(error.to_string()))?;
    Ok(Kernel { agent, lane, cap })
}

fn dispatch(kernel: &Agent, lane: LaneId, request: &Envelope) -> Envelope {
    let Some(descriptor) = request.caps.first() else {
        return Envelope::error(request.request_id, &Error::UnknownCapability(CapToken(0)));
    };
    let cap = kernel.import(descriptor.id);
    match kernel.call_with_payload(
        lane,
        &cap,
        &request.method,
        request.args.clone(),
        request.payload.len() as u64,
    ) {
        Ok(promise) => {
            let _ = kernel.run();
            match promise.value() {
                Ok(value) => {
                    let mut response = Envelope::response(request.request_id, value);
                    // Echo the payload: thin clients verify the round trip.
                    response.payload = request.payload.clone();
                    response
                }
                Err(error) => Envelope::error(request.request_id, &error),
            }
        }
        Err(error) => Envelope::error(request.request_id, &error),
    }
}

fn describe_value(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(flag) => flag.to_string(),
        Value::Int(number) => number.to_string(),
        Value::Float(number) => number.to_string(),
        Value::Text(text) => format!("{text:?}"),
        Value::List(items) => format!("[{} values]", items.len()),
        Value::Map(entries) => format!("{{{} fields}}", entries.len()),
        Value::Secret => "<secret>".to_string(),
        Value::Module(bytes) => format!("<module {} bytes>", bytes.len()),
        Value::Path(path) => format!("{path:?}"),
    }
}

fn describe_response(envelope: &Envelope) -> String {
    let kind = match envelope.kind {
        Kind::Request => "request",
        Kind::Response => "response",
        Kind::Error => "error",
        other => {
            return format!(
                "kind={other:?} id={} payload={}",
                envelope.request_id,
                envelope.payload.len()
            )
        }
    };
    let mut parts = vec![format!("kind={kind} id={}", envelope.request_id)];
    if !envelope.method.is_empty() {
        parts.push(format!("method={}", envelope.method));
    }
    parts.push(format!("payload={}", envelope.payload.len()));
    for arg in &envelope.args {
        if let Arg::Value(value) = arg {
            parts.push(format!("value={}", describe_value(value)));
        }
    }
    parts.join(" ")
}

fn capability_descriptor(cap: CapId, methods: &[String]) -> CapDescriptor {
    CapDescriptor {
        id: cap,
        methods: methods.iter().cloned().collect(),
        budget: Budget::default(),
        read_only: false,
        redact: false,
        path_scope: None,
    }
}

fn request(id: u64, method: &str, args: Vec<Arg>, payload: &[u8], cap: Option<CapId>) -> Envelope {
    let mut envelope = Envelope::request(id, method, args);
    envelope.payload = payload.to_vec();
    if let Some(cap) = cap {
        envelope.caps = vec![capability_descriptor(cap, &[method.to_string()])];
    }
    envelope
}

fn parse_cap(text: &str) -> Result<CapId, CliError> {
    if text.len() != 32 {
        return Err(CliError::usage(
            "--cap must be 32 hex characters (the peer prints it)",
        ));
    }
    let mut id = [0u8; 16];
    for (index, slot) in id.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| CliError::usage("--cap is not valid hex"))?;
    }
    Ok(CapId(id))
}

fn endpoint(flags: &BTreeMap<String, String>) -> Result<String, CliError> {
    flags
        .get("--addr")
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| CliError::usage("--addr host:port is required"))
}

fn method(flags: &BTreeMap<String, String>) -> String {
    flags
        .get("--method")
        .filter(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| "echo".to_string())
}

/// Largest payload the CLI will read from a file or send in one call.
const MAX_PAYLOAD_BYTES: u64 = 64 << 20;
/// Largest control-plane response the CLI will buffer.
const MAX_EVENT_BODY_BYTES: u64 = 8 << 20;

fn payload(flags: &BTreeMap<String, String>) -> Result<Vec<u8>, CliError> {
    if flags.get("--payload").is_some() && flags.get("--text").is_some() {
        return Err(CliError::usage("use either --payload or --text, not both"));
    }
    if let Some(path) = flags.get("--payload").filter(|value| !value.is_empty()) {
        // Read through a bounded reader: metadata can lie (pipes report zero)
        // and the file can grow between the check and the read.
        let file = std::fs::File::open(path)
            .map_err(|error| CliError::usage(format!("cannot read {path}: {error}")))?;
        let mut bytes = Vec::new();
        file.take(MAX_PAYLOAD_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| CliError::usage(format!("cannot read {path}: {error}")))?;
        if bytes.len() as u64 > MAX_PAYLOAD_BYTES {
            return Err(CliError::usage(format!(
                "{path} is larger than the {MAX_PAYLOAD_BYTES}-byte payload ceiling"
            )));
        }
        return Ok(bytes);
    }
    Ok(flags
        .get("--text")
        .map(|text| text.as_bytes().to_vec())
        .unwrap_or_default())
}

fn flag_number(
    flags: &BTreeMap<String, String>,
    name: &str,
    default: usize,
) -> Result<usize, CliError> {
    match flags.get(name) {
        None => Ok(default),
        Some(value) if value.is_empty() => Err(CliError::usage(format!("{name} needs a value"))),
        Some(value) => value
            .parse()
            .map_err(|_| CliError::usage(format!("{name} expects a number"))),
    }
}

fn split_args(args: &[String]) -> (Vec<String>, BTreeMap<String, String>) {
    let mut positional = Vec::new();
    let mut flags = BTreeMap::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(name) = arg.strip_prefix("--") {
            let key = format!("--{name}");
            if let Some(value) = args.get(index + 1) {
                if !value.starts_with("--") {
                    flags.insert(key, value.clone());
                    index += 2;
                    continue;
                }
            }
            flags.insert(key, String::new());
        } else {
            positional.push(arg.clone());
        }
        index += 1;
    }
    (positional, flags)
}

fn transport_name(flags: &BTreeMap<String, String>) -> String {
    flags
        .get("--transport")
        .filter(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| "tcp".to_string())
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

fn doctor(_args: &[String]) -> CliResult {
    println!(
        "active-rpc-cli {} (active-rpc {})",
        env!("CARGO_PKG_VERSION"),
        VERSION
    );
    println!("transports: tcp, connect, http2, quic, in-process, shared-memory");
    println!("features: quic http2");
    let budget = Budget::default();
    println!(
        "budget defaults: calls={} bytes={} wall_ms={} nodes={} depth={} array={} value={}",
        budget.max_calls,
        budget.max_bytes,
        budget.max_wall_ms,
        budget.max_nodes,
        budget.max_depth,
        budget.max_array_len,
        budget.max_value_size
    );
    println!("exit codes: 0 success, 1 refusal/failure, 2 usage, 3 transport");
    Ok(())
}

// ---------------------------------------------------------------------------
// peer
// ---------------------------------------------------------------------------

fn announce(transport: &str, address: &str, cap: CapId, cert: Option<&str>) -> CliResult {
    let mut out = io::stdout();
    writeln!(out, "transport={transport}")
        .map_err(|error| CliError::transport(error.to_string()))?;
    writeln!(out, "addr={address}").map_err(|error| CliError::transport(error.to_string()))?;
    writeln!(out, "cap={}", cap.hex()).map_err(|error| CliError::transport(error.to_string()))?;
    if let Some(path) = cert {
        writeln!(out, "cert={path}").map_err(|error| CliError::transport(error.to_string()))?;
    }
    out.flush()
        .map_err(|error| CliError::transport(error.to_string()))
}

fn peer(args: &[String]) -> CliResult {
    let (_, flags) = split_args(&args[1..]);
    let transport = transport_name(&flags);
    let limit = flag_number(&flags, "--limit", 1)?;
    let methods = flags
        .get("--methods")
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec!["echo".to_string(), "sum".to_string()]);
    let kernel = kernel(&methods)?;
    match transport.as_str() {
        "tcp" => peer_tcp(kernel, limit),
        "http2" => peer_http2(kernel, limit),
        "connect" => peer_connect(kernel, limit),
        "quic" => peer_quic(kernel, limit, &flags),
        other => Err(CliError::usage(format!(
            "unknown transport {other}; use tcp, http2, connect or quic"
        ))),
    }
}

fn peer_tcp(kernel: Kernel, limit: usize) -> CliResult {
    let (listener, address) =
        bind_loopback().map_err(|error| CliError::transport(error.to_string()))?;
    announce("tcp", &address, kernel.cap.id(), None)?;
    let mut served = 0usize;
    while limit == 0 || served < limit {
        let (stream, _) = listener
            .accept()
            .map_err(|error| CliError::transport(format!("accept: {error}")))?;
        let transport =
            TcpTransport::new(stream).map_err(|error| CliError::transport(error.to_string()))?;
        let Kernel { agent, lane, .. } = &kernel;
        serve_connection(transport, |envelope| dispatch(agent, *lane, &envelope))
            .map_err(|error| CliError::transport(error.to_string()))?;
        served += 1;
    }
    Ok(())
}

fn peer_http2(kernel: Kernel, limit: usize) -> CliResult {
    let server =
        Http2Server::bind_loopback().map_err(|error| CliError::transport(error.to_string()))?;
    let address = server.address().to_string();
    announce("http2", &address, kernel.cap.id(), None)?;
    let (tx, rx) = mpsc::channel::<(Envelope, mpsc::Sender<Envelope>)>();
    let server_thread = std::thread::spawn(move || {
        server.serve(limit.max(1), move |envelope| {
            let (reply_tx, reply_rx) = mpsc::channel();
            if tx.send((envelope, reply_tx)).is_err() {
                return Envelope::error(0, &Error::Transport("kernel unavailable".to_string()));
            }
            reply_rx.recv().unwrap_or_else(|_| {
                Envelope::error(0, &Error::Transport("kernel dropped the call".to_string()))
            })
        })
    });
    for (envelope, reply) in rx {
        let response = dispatch(&kernel.agent, kernel.lane, &envelope);
        let _ = reply.send(response);
    }
    server_thread
        .join()
        .map_err(|_| CliError::transport("http2 server thread panicked"))?
        .map_err(|error| CliError::transport(error.to_string()))?;
    Ok(())
}

fn peer_connect(kernel: Kernel, limit: usize) -> CliResult {
    let server =
        BridgeServer::bind_loopback().map_err(|error| CliError::transport(error.to_string()))?;
    let address = server.address().to_string();
    announce("connect", &address, kernel.cap.id(), None)?;
    let (tx, rx) = mpsc::channel::<(Envelope, mpsc::Sender<Envelope>)>();
    let server_thread = std::thread::spawn(move || {
        server.serve(limit.max(1), move |envelope| {
            let (reply_tx, reply_rx) = mpsc::channel();
            if tx.send((envelope, reply_tx)).is_err() {
                return Envelope::error(0, &Error::Transport("kernel unavailable".to_string()));
            }
            reply_rx.recv().unwrap_or_else(|_| {
                Envelope::error(0, &Error::Transport("kernel dropped the call".to_string()))
            })
        })
    });
    for (envelope, reply) in rx {
        let response = dispatch(&kernel.agent, kernel.lane, &envelope);
        let _ = reply.send(response);
    }
    server_thread
        .join()
        .map_err(|_| CliError::transport("connect server thread panicked"))?
        .map_err(|error| CliError::transport(error.to_string()))?;
    Ok(())
}

fn peer_quic(kernel: Kernel, limit: usize, flags: &BTreeMap<String, String>) -> CliResult {
    if limit == 0 {
        return Err(CliError::usage(
            "quic needs --limit N (the server stops after N calls)",
        ));
    }
    let (tx, rx) = mpsc::channel::<(Envelope, mpsc::Sender<Envelope>)>();
    let server = QuicServer::start(limit, move |envelope| {
        let (reply_tx, reply_rx) = mpsc::channel();
        if tx.send((envelope, reply_tx)).is_err() {
            return Envelope::error(0, &Error::Transport("kernel unavailable".to_string()));
        }
        reply_rx
            .recv()
            .unwrap_or_else(|_| Envelope::error(0, &Error::Transport("kernel dropped".to_string())))
    })
    .map_err(|error| CliError::transport(error.to_string()))?;
    let certificate = server.certificate().as_ref().to_vec();
    let cert_path = flags
        .get("--cert-out")
        .filter(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| "active-rpc.cert".to_string());
    std::fs::write(&cert_path, &certificate)
        .map_err(|error| CliError::transport(format!("cannot write {cert_path}: {error}")))?;
    announce("quic", server.address(), kernel.cap.id(), Some(&cert_path))?;

    let mut served = 0usize;
    for (envelope, reply) in rx {
        let response = dispatch(&kernel.agent, kernel.lane, &envelope);
        let _ = reply.send(response);
        served += 1;
        if served >= limit {
            break;
        }
    }
    // Wait for the serving task: it drains the last response and closes the
    // endpoint itself, so the client always reads its reply.
    server.wait();
    Ok(())
}

// ---------------------------------------------------------------------------
// call
// ---------------------------------------------------------------------------

fn call(args: &[String]) -> CliResult {
    let (_, flags) = split_args(&args[1..]);
    let transport = transport_name(&flags);
    let address = endpoint(&flags)?;
    let cap = flags
        .get("--cap")
        .filter(|value| !value.is_empty())
        .map(|value| parse_cap(value))
        .transpose()?;
    let method = method(&flags);
    let payload = payload(&flags)?;
    let envelope = request(42, &method, Vec::new(), &payload, cap);

    let response = match transport.as_str() {
        "tcp" => {
            let mut transport = TcpTransport::connect(&address)
                .map_err(|error| CliError::transport(error.to_string()))?;
            transport
                .send(&envelope)
                .map_err(|error| CliError::transport(error.to_string()))?;
            transport
                .recv()
                .map_err(|error| CliError::transport(error.to_string()))?
                .ok_or_else(|| CliError::transport("the peer closed without a response"))?
        }
        "connect" => ConnectClient::connect(&address)
            .map_err(|error| CliError::transport(error.to_string()))?
            .call(&envelope)
            .map_err(|error| CliError::transport(error.to_string()))?,
        "http2" => Http2Client::connect(&address)
            .map_err(|error| CliError::transport(error.to_string()))?
            .call(&envelope)
            .map_err(|error| CliError::transport(error.to_string()))?,
        "quic" => {
            let cert_path = flags
                .get("--cert")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| CliError::usage("quic needs --cert <file> from the peer"))?;
            let bytes = std::fs::read(cert_path)
                .map_err(|error| CliError::usage(format!("cannot read {cert_path}: {error}")))?;
            let certificate = rustls_pki_types::CertificateDer::from(bytes);
            QuicClient::connect(&address, &certificate)
                .map_err(|error| CliError::transport(error.to_string()))?
                .call(&envelope)
                .map_err(|error| CliError::transport(error.to_string()))?
        }
        other => {
            return Err(CliError::usage(format!(
                "unknown transport {other}; use tcp, http2, connect or quic"
            )))
        }
    };

    println!("{}", describe_response(&response));
    if response.kind == Kind::Error {
        return Err(CliError::refused(format!(
            "peer refused: {}",
            response.method
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// pipeline
// ---------------------------------------------------------------------------

fn pipeline(args: &[String]) -> CliResult {
    let (_, flags) = split_args(&args[1..]);
    let address = endpoint(&flags)?;
    let cap = parse_cap(
        flags
            .get("--cap")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| CliError::usage("--cap is required"))?,
    )?;
    let calls = flag_number(&flags, "--calls", 8)?;
    let method = method(&flags);
    let payload = payload(&flags)?;
    let mut transport =
        TcpTransport::connect(&address).map_err(|error| CliError::transport(error.to_string()))?;
    let started = Instant::now();
    for id in 0..calls as u64 {
        let envelope = request(id + 1, &method, Vec::new(), &payload, Some(cap));
        transport
            .send(&envelope)
            .map_err(|error| CliError::transport(error.to_string()))?;
    }
    let mut responses = Vec::with_capacity(calls);
    for _ in 0..calls {
        let response = transport
            .recv()
            .map_err(|error| CliError::transport(error.to_string()))?
            .ok_or_else(|| CliError::transport("the peer closed mid-pipeline"))?;
        responses.push(response);
    }
    let elapsed = started.elapsed();
    let refusals = responses
        .iter()
        .filter(|response| response.kind == Kind::Error)
        .count();
    println!(
        "calls={calls} round_trips=1 responses={} refusals={refusals} elapsed_ms={:.3}",
        responses.len(),
        elapsed.as_secs_f64() * 1_000.0
    );
    if refusals > 0 {
        return Err(CliError::refused(format!("{refusals} calls were refused")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// loadgen
// ---------------------------------------------------------------------------

fn loadgen(args: &[String]) -> CliResult {
    let (_, flags) = split_args(&args[1..]);
    let address = endpoint(&flags)?;
    let cap = parse_cap(
        flags
            .get("--cap")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| CliError::usage("--cap is required"))?,
    )?;
    let requests = flag_number(&flags, "--requests", 100)?;
    let concurrency = flag_number(&flags, "--concurrency", 4)?.max(1);
    let method = method(&flags);
    let payload = payload(&flags)?;
    let total = requests.max(concurrency);
    let started = Instant::now();
    let next_id = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1));
    let mut handles = Vec::new();
    for worker in 0..concurrency {
        let address = address.clone();
        let method = method.clone();
        let payload = payload.clone();
        let next_id = std::sync::Arc::clone(&next_id);
        let per_worker = total / concurrency + usize::from(worker < total % concurrency);
        handles.push(std::thread::spawn(move || {
            let mut latencies = Vec::with_capacity(per_worker);
            let mut errors = 0usize;
            let mut transport = match TcpTransport::connect(&address) {
                Ok(transport) => transport,
                // The worker could not open its connection: every request it
                // was assigned failed.
                Err(_) => return (Vec::new(), per_worker),
            };
            for _ in 0..per_worker {
                let id = next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let envelope = request(id, &method, Vec::new(), &payload, Some(cap));
                let started = Instant::now();
                let result = transport
                    .send(&envelope)
                    .and_then(|()| transport.recv())
                    .map(|response| response.map(|envelope| envelope.kind));
                match result {
                    Ok(Some(Kind::Response)) => latencies.push(started.elapsed()),
                    _ => errors += 1,
                }
            }
            (latencies, errors)
        }));
    }
    let mut latencies = Vec::new();
    let mut errors = 0usize;
    for handle in handles {
        match handle.join() {
            Ok((worker_latencies, worker_errors)) => {
                latencies.extend(worker_latencies);
                errors += worker_errors;
            }
            Err(_) => errors += 1,
        }
    }
    let elapsed = started.elapsed();
    latencies.sort();
    let percentile = |percent: usize| -> f64 {
        if latencies.is_empty() {
            return 0.0;
        }
        let index = (latencies.len().saturating_sub(1) * percent) / 100;
        latencies[index].as_secs_f64() * 1_000.0
    };
    let rate = latencies.len() as f64 / elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
    println!(
        "requests={total} concurrency={concurrency} ok={} errors={errors} elapsed_ms={:.3} \
         p50_ms={:.3} p95_ms={:.3} p99_ms={:.3} throughput_per_s={rate:.1}",
        latencies.len(),
        elapsed.as_secs_f64() * 1_000.0,
        percentile(50),
        percentile(95),
        percentile(99)
    );
    if errors > 0 {
        return Err(CliError::refused(format!("{errors} requests failed")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// bridge
// ---------------------------------------------------------------------------

fn bridge(args: &[String]) -> CliResult {
    let (_, flags) = split_args(&args[1..]);
    let limit = flag_number(&flags, "--limit", 1)?;
    let kernel = kernel(&["echo".to_string()])?;
    let server =
        BridgeServer::bind_loopback().map_err(|error| CliError::transport(error.to_string()))?;
    let address = server.address().to_string();
    println!(
        "transport=connect\naddr={address}\ncap={}",
        kernel.cap.id().hex()
    );
    io::stdout()
        .flush()
        .map_err(|error| CliError::transport(error.to_string()))?;
    let (tx, rx) = mpsc::channel::<(Envelope, mpsc::Sender<Envelope>)>();
    let server_thread = std::thread::spawn(move || {
        server.serve(limit.max(1), move |envelope| {
            let (reply_tx, reply_rx) = mpsc::channel();
            if tx.send((envelope, reply_tx)).is_err() {
                return Envelope::error(0, &Error::Transport("kernel unavailable".to_string()));
            }
            reply_rx.recv().unwrap_or_else(|_| {
                Envelope::error(0, &Error::Transport("kernel dropped the call".to_string()))
            })
        })
    });
    for (envelope, reply) in rx {
        let response = dispatch(&kernel.agent, kernel.lane, &envelope);
        let _ = reply.send(response);
    }
    server_thread
        .join()
        .map_err(|_| CliError::transport("bridge thread panicked"))?
        .map_err(|error| CliError::transport(error.to_string()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// events
// ---------------------------------------------------------------------------

fn events(args: &[String]) -> CliResult {
    let (_, flags) = split_args(&args[1..]);
    let plane = flags
        .get("--plane")
        .filter(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| "http://127.0.0.1:8787".to_string());
    let mut after = flag_number(&flags, "--after", 0)?;
    let follow = flags.contains_key("--follow");
    let interval = Duration::from_millis(flag_number(&flags, "--interval-ms", 500)? as u64);
    let mut last_body = String::new();
    loop {
        let body = http_get(&format!("{plane}/events?after={after}"))?;
        if body != last_body {
            if let Ok(events) = serde_json::from_str::<Vec<serde_json::Value>>(&body) {
                for event in &events {
                    if let Some(id) = event.get("id").and_then(|value| value.as_u64()) {
                        after = after.max(id as usize);
                    }
                    println!("{event}");
                }
            } else {
                println!("{body}");
            }
            last_body = body;
        }
        if !follow {
            return Ok(());
        }
        std::thread::sleep(interval);
    }
}

/// Minimal HTTP/1.1 GET for the control-plane event endpoint.
fn http_get(url: &str) -> Result<String, CliError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| CliError::usage("--plane must be an http:// URL"))?;
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let mut stream = TcpStream::connect(authority)
        .map_err(|error| CliError::transport(format!("connect {authority}: {error}")))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nAccept: application/json\r\n\
         Accept-Encoding: identity\r\nConnection: close\r\n\r\n"
    )
    .map_err(|error| CliError::transport(error.to_string()))?;
    let mut response = Vec::new();
    let mut limited = std::io::Read::by_ref(&mut stream).take(MAX_EVENT_BODY_BYTES + 1);
    limited
        .read_to_end(&mut response)
        .map_err(|error| CliError::transport(error.to_string()))?;
    if response.len() as u64 > MAX_EVENT_BODY_BYTES {
        return Err(CliError::transport(format!(
            "control-plane response exceeded the {MAX_EVENT_BODY_BYTES}-byte ceiling"
        )));
    }
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| CliError::transport("malformed HTTP response"))?;
    let head = String::from_utf8_lossy(&response[..split]).to_ascii_lowercase();
    if let Some(status) = head.lines().next() {
        if !status.contains(" 200 ") {
            return Err(CliError::refused(format!(
                "control plane answered {}",
                head.lines().next().unwrap_or_default()
            )));
        }
    }
    let body = &response[split + 4..];
    if head.contains("transfer-encoding: chunked") {
        return dechunk(body);
    }
    Ok(String::from_utf8_lossy(body).into_owned())
}

fn dechunk(body: &[u8]) -> Result<String, CliError> {
    let mut out = Vec::new();
    let mut cursor = 0;
    while cursor < body.len() {
        let Some(line_end) = body[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")
        else {
            break;
        };
        let size_text = String::from_utf8_lossy(&body[cursor..cursor + line_end]);
        let size = usize::from_str_radix(size_text.trim(), 16)
            .map_err(|_| CliError::transport("bad chunk size"))?;
        cursor += line_end + 2;
        if size == 0 {
            break;
        }
        if cursor + size > body.len() {
            return Err(CliError::transport("truncated chunk"));
        }
        out.extend_from_slice(&body[cursor..cursor + size]);
        cursor += size + 2;
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

// ---------------------------------------------------------------------------
// help
// ---------------------------------------------------------------------------

fn help_text() -> String {
    format!(
        "active-rpc-cli {} (active-rpc {VERSION})

usage: active-rpc-cli <command> [options]

  doctor
      Version, transports, features, budget defaults and exit codes.
  peer [--transport tcp|http2|connect|quic] [--limit N] [--methods echo,sum]
       [--cert-out PATH]
      Start a demo peer with a real kernel and a minted capability. Prints
      transport, addr, cap (and cert for quic). --limit is connections for
      tcp/http2, requests for connect, calls for quic; 0 serves until Ctrl-C on
      tcp.
  call --addr HOST:PORT [--transport ...] [--cap HEX] [--method M]
       [--payload FILE | --text TEXT] [--cert FILE]
      Issue one call and print kind, id, payload length and value.
  pipeline --addr HOST:PORT --cap HEX [--calls N] [--method M] [--payload FILE]
      Send N calls on one connection before reading any response; prints the
      round-trip count.
  loadgen --addr HOST:PORT --cap HEX [--requests N] [--concurrency C]
          [--method M] [--payload FILE]
      Controlled load over C connections; prints p50/p95/p99 and throughput.
  bridge [--limit N]
      Serve the Connect/gRPC interop bridge against the demo kernel.
  events [--plane URL] [--after ID] [--follow] [--interval-ms N]
      Tail the control-plane event stream (correlation ids only).
  help
      This text.

Exit codes: 0 success, 1 refusal or failed request, 2 usage, 3 transport or
codec failure.

Examples:
  active-rpc-cli peer --limit 4 > peer.txt
  active-rpc-cli call --addr 127.0.0.1:5000 --cap 00112233445566778899aabbccddeeff
  active-rpc-cli pipeline --addr 127.0.0.1:5000 --cap <hex> --calls 16
  active-rpc-cli loadgen --addr 127.0.0.1:5000 --cap <hex> --requests 200 --concurrency 8
  active-rpc-cli events --plane http://127.0.0.1:8787 --follow

Capabilities are printed as opaque ids; the CLI never prints authority bits.",
        env!("CARGO_PKG_VERSION")
    )
}
