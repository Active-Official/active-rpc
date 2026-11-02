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
use active_rpc::receipts::ReceiptLog;
use active_rpc::replay::{Recorder, ReplayPackage};
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
    // `std::env::args()` panics on a non-UTF-8 argument, which is exit 101: a
    // contract violation the caller cannot see coming. The OS-level argument is
    // refused instead.
    let mut args = Vec::new();
    for argument in std::env::args_os().skip(1) {
        match argument.into_string() {
            Ok(text) => args.push(text),
            Err(_) => {
                eprintln!("error: an argument is not valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // A closed pipe (`… | head`) is not a failure: the operator stopped
            // reading. Reporting it as the documented code, not a panic (101).
            if error.code == 1 && error.message.starts_with("stdout closed") {
                return ExitCode::SUCCESS;
            }
            eprintln!("error: {}", error.message);
            ExitCode::from(error.code)
        }
    }
}

/// Write one line to stdout, mapping a closed pipe to a clean stop.
///
/// `println!` panics on `EPIPE`/`ERROR_BROKEN_PIPE`, which exited 101 and broke
/// the documented 0/1/2/3 contract for the most ordinary use of `receipts show`
/// and `events --follow`: piping into `head`.
fn out_line(text: impl std::fmt::Display) -> CliResult {
    use std::io::Write;
    let mut out = std::io::stdout();
    match writeln!(out, "{text}").and_then(|()| out.flush()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {
            Err(CliError::transport("stdout closed"))
        }
        Err(error) => Err(CliError::transport(error.to_string())),
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
        "replay" => replay(&args),
        "receipts" => receipts(&args),
        "help" | "--help" | "-h" => {
            out_line(help_text())?;
            Ok(())
        }
        "version" | "--version" | "-V" => {
            out_line(format!(
                "active-rpc-cli {} (active-rpc {})",
                env!("CARGO_PKG_VERSION"),
                active_rpc::VERSION
            ))?;
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
            // `+=` panicked in a debug build on `i64::MAX + 1` from the wire and
            // wrapped in release, so one hostile call killed the demo peer
            // (exit 101) and its `--limit` was unreachable for everyone else.
            let mut total: i64 = 0;
            for arg in &call.args {
                if let Arg::Value(Value::Int(value)) = arg {
                    total = total
                        .checked_add(*value)
                        .ok_or(Error::InvalidArgument("sum overflows i64"))?;
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
    // Only a request is a call. A relay that forwards a response or an error
    // envelope must not be able to make this dispatcher execute it.
    if request.kind != Kind::Request {
        return Envelope::error(
            request.request_id,
            &Error::Wire("a server only serves requests"),
        );
    }
    let Some(descriptor) = request.caps.first() else {
        return Envelope::error(request.request_id, &Error::UnknownCapability(CapToken(0)));
    };
    let cap = kernel.import(descriptor.id);
    match kernel.call_from_envelope(None, lane, &cap, request) {
        Ok(promise) => {
            let _ = kernel.run();
            match promise.value() {
                Ok(value) => {
                    // The response is egress: the value plus the echoed payload,
                    // charged like the inbound side, so `max_bytes` bounds the
                    // round trip rather than one direction of it. Charging only
                    // `payload.len()` left the arguments free outbound.
                    let response_bytes = value.wire_size().saturating_add(request.payload.len() as u64);
                    if let Err(error) = kernel.charge_egress_bytes(lane, &cap, response_bytes) {
                        return Envelope::error(request.request_id, &error);
                    }
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
        // The method is wire text from the peer: a raw newline or an ANSI escape
        // forges a line in a terminal or a CI log, and this is an exit-0 path.
        parts.push(format!("method={:?}", envelope.method));
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

/// Read a capability id from a file, so it need not appear in `argv`.
///
/// `--cap HEX` is visible in the process table and in shell history, which the
/// help warns about. The file is read under the same ceiling and the same
/// world-readable check as a receipt key.
fn cap_from_file(path: &str) -> Result<CapId, CliError> {
    let bytes = read_bounded(path, 65)?;
    let text = String::from_utf8(bytes)
        .map_err(|_| CliError::usage(format!("{path} is not UTF-8")))?;
    parse_cap(text.trim())
}

/// The capability a command should use, from `--cap` or `--cap-file`.
fn capability(flags: &BTreeMap<String, String>) -> Result<CapId, CliError> {
    let inline = flags.get("--cap").filter(|value| !value.is_empty());
    let file = flags.get("--cap-file").filter(|value| !value.is_empty());
    match (inline, file) {
        (Some(_), Some(_)) => Err(CliError::usage(
            "pass --cap or --cap-file, not both".to_string(),
        )),
        (Some(text), None) => parse_cap(text),
        (None, Some(path)) => cap_from_file(path),
        (None, None) => Err(CliError::usage("--cap or --cap-file is required".to_string())),
    }
}

fn parse_cap(text: &str) -> Result<CapId, CliError> {
    // `len()` is bytes: a 32-byte string holding a multi-byte character would
    // make the slice below land inside a code point and panic (exit 101, outside
    // the documented 0/1/2/3 contract). The peer is the source of `--cap`.
    if text.len() != 32 || !text.is_ascii() {
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
            // `--name=value` is the form an operator writes and a script emits;
            // accepting only `--name value` silently dropped it (a transport
            // downgrade or an empty payload with exit 0).
            if let Some((name, value)) = name.split_once('=') {
                flags.insert(format!("--{name}"), value.to_string());
                index += 1;
                continue;
            }
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

/// Flags that are true by presence and take no value.
///
/// `reject_unknown` refused any flag with an empty value, so a bare
/// `--follow` was a usage error while the documented form is exactly that. A
/// boolean's *value* is still parsed (`flag_bool`), because presence is not
/// truth: `--emit-cap-hex=false` printed bearer authority.
const BOOLEAN_FLAGS: &[&str] = &[
    "--chain-only",
    "--emit-cap-hex",
    "--follow",
    "--up-to",
    "--read-only",
];

/// Parse a boolean flag.
///
/// A bare flag, `=true`, `=1` and `=yes` are true; `=false`, `=0` and `=no` are
/// false; anything else is a usage error. An absent flag is false.
fn flag_bool(flags: &BTreeMap<String, String>, name: &str) -> Result<bool, CliError> {
    match flags.get(name).map(String::as_str) {
        None => Ok(false),
        Some("") | Some("true") | Some("1") | Some("yes") => Ok(true),
        Some("false") | Some("0") | Some("no") => Ok(false),
        Some(other) => Err(CliError::usage(format!(
            "{name} takes true or false, got {other}"
        ))),
    }
}

/// Run one exchange with a deadline.
///
/// The connect, http2 and quic clients have no internal timeout, and neither
/// has the connect phase, so a peer that accepts and then says nothing hung the
/// process. The exchange runs on a helper thread and the caller waits at most
/// `deadline`; the process exit ends the thread, which is acceptable for a
/// one-shot CLI command.
fn with_deadline<T, F>(deadline: Duration, action: F) -> Result<T, CliError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, CliError> + Send + 'static,
{
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("exchange".into())
        .spawn(move || {
            let _ = sender.send(action());
        })
        .map_err(|error| CliError::transport(format!("could not start the exchange: {error}")))?;
    match receiver.recv_timeout(deadline) {
        Ok(result) => result,
        Err(_) => Err(CliError::transport(format!(
            "no answer within {} ms",
            deadline.as_millis()
        ))),
    }
}

/// Refuse any flag a command does not know.
///
/// An unknown flag used to be stored and ignored, so a typo (`--paylod`) or a
/// `=`-form the parser did not understand (`--transport=quic`) silently changed
/// the operation instead of failing: the operator believed they were exercising
/// QUIC and got plaintext TCP, or sent no payload at all and saw exit 0.
fn reject_unknown(flags: &BTreeMap<String, String>, allowed: &[&str]) -> CliResult {
    for name in flags.keys() {
        if !allowed.contains(&name.as_str()) {
            return Err(CliError::usage(format!(
                "unknown option {name}; expected one of {}",
                allowed.join(", ")
            )));
        }
    }
    for (name, value) in flags {
        if value.is_empty() && !BOOLEAN_FLAGS.contains(&name.as_str()) {
            return Err(CliError::usage(format!("{name} needs a value")));
        }
    }
    Ok(())
}


/// Largest certificate file the CLI will read.
const MAX_CERT_BYTES: u64 = 1 << 20;

/// Largest number of loadgen threads the CLI will spawn.
const MAX_CONCURRENCY: usize = 1_024;

/// Largest number of requests one loadgen run will issue.
const MAX_REQUESTS: usize = 1_000_000;

/// Largest pipeline the CLI will open in one round trip.
const MAX_PIPELINE_CALLS: usize = 100_000;

/// Bytes the pipeline keeps from a peer's replies before refusing.
const MAX_PIPELINE_BYTES: u64 = 64 << 20;

/// Default deadline for a client exchange, in milliseconds.
const DEFAULT_TIMEOUT_MS: u64 = 10_000;

/// Deadline for one served connection: a client that connects and then stalls
/// must not hold the server's only accepting thread forever.
const SERVER_DEADLINE: Duration = Duration::from_secs(10);

/// The read and write deadline for an exchange with a peer.
///
/// A peer that accepts a connection and then says nothing blocks a blocking
/// read forever: the operator sees a hung tool instead of an error, and a server
/// serving one connection at a time never reaches its `--limit`.
fn timeout(flags: &BTreeMap<String, String>) -> Result<Duration, CliError> {
    let ms = flag_number(flags, "--timeout-ms", DEFAULT_TIMEOUT_MS as usize)?;
    if ms == 0 || ms > 3_600_000 {
        return Err(CliError::usage(
            "--timeout-ms must be 1..=3600000 (one hour)".to_string(),
        ));
    }
    Ok(Duration::from_millis(ms as u64))
}

fn transport_name(flags: &BTreeMap<String, String>) -> Result<String, CliError> {
    let name = flags
        .get("--transport")
        .filter(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| "tcp".to_string());
    match name.as_str() {
        "tcp" | "connect" | "http2" | "quic" => Ok(name),
        other => Err(CliError::usage(format!(
            "unknown transport {other}; use tcp, http2, connect or quic"
        ))),
    }
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

fn doctor(_args: &[String]) -> CliResult {
    out_line(format!(
        "active-rpc-cli {} (active-rpc {})",
        env!("CARGO_PKG_VERSION"),
        VERSION
    ))?;
    out_line("transports: tcp, connect, http2, quic, in-process, shared-memory")?;
    out_line("features: quic http2")?;
    let budget = Budget::default();
    out_line(format!(
        "budget defaults: calls={} bytes={} wall_ms={} nodes={} depth={} array={} value={}",
        budget.max_calls,
        budget.max_bytes,
        budget.max_wall_ms,
        budget.max_nodes,
        budget.max_depth,
        budget.max_array_len,
        budget.max_value_size
    ))?;
    out_line("exit codes: 0 success, 1 refusal/failure, 2 usage, 3 transport")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// peer
// ---------------------------------------------------------------------------

/// Announce a listening peer.
///
/// `--emit-cap-hex` prints the raw bearer id, which is the transfer form and
/// must be handled as a secret: possession is authority while the kernel lives.
/// The default is the non-reversible correlation id, because stdout of a server
/// command lands in terminals, CI logs and files.
fn announce(
    transport: &str,
    address: &str,
    cap: CapId,
    cert: Option<&str>,
    emit_cap_hex: bool,
) -> CliResult {
    let mut out = io::stdout();
    writeln!(out, "transport={transport}")
        .map_err(|error| CliError::transport(error.to_string()))?;
    writeln!(out, "addr={address}").map_err(|error| CliError::transport(error.to_string()))?;
    if emit_cap_hex {
        writeln!(out, "cap={}", cap.hex())
            .map_err(|error| CliError::transport(error.to_string()))?;
    } else {
        writeln!(out, "cap_correlation={}", cap.correlation_id())
            .map_err(|error| CliError::transport(error.to_string()))?;
        // A `#` prefix: the documented `awk -F= '/^cap=/'` extraction must not
        // pick up a sentence where it expects 32 hex characters.
        writeln!(
            out,
            "# cap=<pass --emit-cap-hex to print the caller id; that is bearer authority>"
        )
        .map_err(|error| CliError::transport(error.to_string()))?;
    }
    if let Some(path) = cert {
        writeln!(out, "cert={path}").map_err(|error| CliError::transport(error.to_string()))?;
    }
    out.flush()
        .map_err(|error| CliError::transport(error.to_string()))
}

fn peer(args: &[String]) -> CliResult {
    let (_, flags) = split_args(&args[1..]);
    reject_unknown(&flags, &["--transport", "--limit", "--methods", "--cert-out", "--emit-cap-hex"])?;
    let transport = transport_name(&flags)?;
    let limit = flag_number(&flags, "--limit", 1)?;
    // Printing the raw capability id is a transfer of authority, so it is opt-in.
    let emit_hex = flag_bool(&flags, "--emit-cap-hex")?;
    if transport != "quic" && flags.contains_key("--cert-out") {
        return Err(CliError::usage(format!(
            "--cert-out is only meaningful with --transport quic, not {transport}"
        )));
    }
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
        "tcp" => peer_tcp(kernel, limit, emit_hex),
        "http2" => peer_http2(kernel, limit, emit_hex),
        "connect" => peer_connect(kernel, limit, emit_hex),
        "quic" => peer_quic(kernel, limit, &flags, emit_hex),
        other => Err(CliError::usage(format!(
            "unknown transport {other}; use tcp, http2, connect or quic"
        ))),
    }
}

fn peer_tcp(kernel: Kernel, limit: usize, emit_hex: bool) -> CliResult {
    let (listener, address) =
        bind_loopback().map_err(|error| CliError::transport(error.to_string()))?;
    announce("tcp", &address, kernel.cap.id(), None, emit_hex)?;
    let mut served = 0usize;
    while limit == 0 || served < limit {
        let (stream, _) = listener
            .accept()
            .map_err(|error| CliError::transport(format!("accept: {error}")))?;
        // A client that connects and says nothing must not hold the only
        // serving thread: without a deadline `--limit` is unreachable and the
        // second caller waits forever.
        let transport = TcpTransport::with_timeout(stream, SERVER_DEADLINE)
            .map_err(|error| CliError::transport(error.to_string()))?;
        let Kernel { agent, lane, .. } = &kernel;
        serve_connection(transport, |envelope| dispatch(agent, *lane, &envelope))
            .map_err(|error| CliError::transport(error.to_string()))?;
        served += 1;
    }
    Ok(())
}

fn peer_http2(kernel: Kernel, limit: usize, emit_hex: bool) -> CliResult {
    let server = Http2Server::bind_loopback()
        .map_err(|error| CliError::transport(error.to_string()))?
        .with_connection_deadline(SERVER_DEADLINE);
    let address = server.address().to_string();
    announce("http2", &address, kernel.cap.id(), None, emit_hex)?;
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

fn peer_connect(kernel: Kernel, limit: usize, emit_hex: bool) -> CliResult {
    let server =
        BridgeServer::bind_loopback().map_err(|error| CliError::transport(error.to_string()))?;
    let address = server.address().to_string();
    announce("connect", &address, kernel.cap.id(), None, emit_hex)?;
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

fn peer_quic(
    kernel: Kernel,
    limit: usize,
    flags: &BTreeMap<String, String>,
    emit_hex: bool,
) -> CliResult {
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
    announce(
        "quic",
        server.address(),
        kernel.cap.id(),
        Some(&cert_path),
        emit_hex,
    )?;

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
    reject_unknown(
        &flags,
        &[
            "--addr",
            "--transport",
            "--cap",
            "--cap-file",
            "--method",
            "--payload",
            "--text",
            "--cert",
            "--timeout-ms",
        ],
    )?;
    let transport = transport_name(&flags)?;
    let address = endpoint(&flags)?;
    let cap = flags
        .get("--cap")
        .or_else(|| flags.get("--cap-file"))
        .map(|_| capability(&flags))
        .transpose()?;
    // A certificate implies a verified identity. It is only meaningful to QUIC,
    // and accepting it on a cleartext transport told the operator a check had
    // happened that did not.
    if transport != "quic" && flags.contains_key("--cert") {
        return Err(CliError::usage(format!(
            "--cert is only meaningful with --transport quic, not {transport}"
        )));
    }
    let method = method(&flags);
    let deadline = timeout(&flags)?;
    let payload = payload(&flags)?;
    let envelope = request(42, &method, Vec::new(), &payload, cap);

    let cert_path = flags
        .get("--cert")
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());
    // Every transport, including the connect phase, is bounded by the same
    // deadline: only the tcp arm used to honour it.
    let exchange_transport = transport.clone();
    let exchange_address = address.clone();
    let response = with_deadline(deadline, move || match exchange_transport.as_str() {
        "tcp" => {
            let mut transport = TcpTransport::connect_with_timeout(&exchange_address, deadline)
                .map_err(|error| CliError::transport(error.to_string()))?;
            transport
                .send(&envelope)
                .map_err(|error| CliError::transport(error.to_string()))?;
            transport
                .recv()
                .map_err(|error| CliError::transport(error.to_string()))?
                .ok_or_else(|| CliError::transport("the peer closed without a response"))
        }
        "connect" => ConnectClient::connect(&exchange_address)
            .map_err(|error| CliError::transport(error.to_string()))?
            .call(&envelope)
            .map_err(|error| CliError::transport(error.to_string())),
        "http2" => Http2Client::connect(&exchange_address)
            .map_err(|error| CliError::transport(error.to_string()))?
            .call(&envelope)
            .map_err(|error| CliError::transport(error.to_string())),
        "quic" => {
            let cert_path = cert_path
                .clone()
                .ok_or_else(|| CliError::usage("quic needs --cert <file> from the peer"))?;
            // A certificate is an untrusted file, like every other input to
            // this command; it is read under the same ceiling.
            let bytes = read_bounded(&cert_path, MAX_CERT_BYTES)?;
            let certificate = rustls_pki_types::CertificateDer::from(bytes);
            QuicClient::connect(&exchange_address, &certificate)
                .map_err(|error| CliError::transport(error.to_string()))?
                .call(&envelope)
                .map_err(|error| CliError::transport(error.to_string()))
        }
        other => Err(CliError::usage(format!(
            "unknown transport {other}; use tcp, http2, connect or quic"
        ))),
    })?;

    out_line(describe_response(&response))?;
    // Only `Response` is a reply. `Hello`, `Request` and an error are not, and
    // treating them as success inverted the documented exit contract in front of
    // a hostile peer.
    if response.kind != Kind::Response {
        return Err(CliError::refused(format!(
            "the peer did not answer the call: {}",
            describe_response(&response)
        )));
    }
    if response.request_id != 42 {
        return Err(CliError::refused(format!(
            "the peer answered request {} instead of 42",
            response.request_id
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// pipeline
// ---------------------------------------------------------------------------

fn pipeline(args: &[String]) -> CliResult {
    let (_, flags) = split_args(&args[1..]);
    reject_unknown(&flags, &["--addr", "--cap", "--calls", "--method", "--payload", "--text", "--timeout-ms"])?;
    let address = endpoint(&flags)?;
    let cap = parse_cap(
        flags
            .get("--cap")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| CliError::usage("--cap is required"))?,
    )?;
    let calls = flag_number(&flags, "--calls", 8)?;
    if calls == 0 {
        // Zero calls reported `round_trips=1` for an exchange that never
        // happened.
        return Err(CliError::usage("--calls must be at least 1".to_string()));
    }
    if calls > MAX_PIPELINE_CALLS {
        return Err(CliError::usage(format!(
            "--calls is capped at {MAX_PIPELINE_CALLS}"
        )));
    }
    let method = method(&flags);
    let deadline = timeout(&flags)?;
    let payload = payload(&flags)?;
    let mut transport = TcpTransport::connect_with_timeout(&address, deadline)
        .map_err(|error| CliError::transport(error.to_string()))?;
    let started = Instant::now();
    for id in 0..calls as u64 {
        let envelope = request(id + 1, &method, Vec::new(), &payload, Some(cap));
        transport
            .send(&envelope)
            .map_err(|error| CliError::transport(error.to_string()))?;
    }
    let mut responses = Vec::with_capacity(calls);
    // Each reply must answer a request that is still outstanding, once. A peer
    // that answers `Response` with one id N times used to make the run look
    // clean: it replayed one answer and the counters believed it.
    let mut outstanding: std::collections::BTreeSet<u64> = (1..=calls as u64).collect();
    let mut uncorrelated = 0usize;
    let mut retained_bytes = 0u64;
    for _ in 0..calls {
        let response = transport
            .recv()
            .map_err(|error| CliError::transport(error.to_string()))?
            .ok_or_else(|| CliError::transport("the peer closed mid-pipeline"))?;
        // `calls` does not bound the memory a hostile peer can make this keep:
        // every reply may be the full body ceiling.
        retained_bytes = retained_bytes.saturating_add(
            response.payload.len() as u64
                + response
                    .args
                    .iter()
                    .map(active_rpc::Arg::wire_size)
                    .sum::<u64>(),
        );
        if retained_bytes > MAX_PIPELINE_BYTES {
            return Err(CliError::refused(format!(
                "the peer returned more than the {MAX_PIPELINE_BYTES}-byte pipeline ceiling"
            )));
        }
        if !outstanding.remove(&response.request_id) {
            uncorrelated += 1;
        }
        responses.push(response);
    }
    let elapsed = started.elapsed();
    let refusals = responses
        .iter()
        .filter(|response| response.kind != Kind::Response)
        .count()
        + uncorrelated
        + outstanding.len();
    out_line(format!(
        "calls={calls} round_trips=1 responses={} refusals={refusals} elapsed_ms={:.3}",
        responses.len().saturating_sub(refusals),
        elapsed.as_secs_f64() * 1_000.0
    ))?;
    if refusals > 0 {
        return Err(CliError::refused(format!(
            "{refusals} calls were not answered with their own response"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// loadgen
// ---------------------------------------------------------------------------

fn loadgen(args: &[String]) -> CliResult {
    let (_, flags) = split_args(&args[1..]);
    reject_unknown(
        &flags,
        &[
            "--addr",
            "--cap",
            "--cap-file",
            "--requests",
            "--concurrency",
            "--method",
            "--payload",
            "--text",
            "--timeout-ms",
        ],
    )?;
    let address = endpoint(&flags)?;
    let cap = parse_cap(
        flags
            .get("--cap")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| CliError::usage("--cap is required"))?,
    )?;
    let requests = flag_number(&flags, "--requests", 100)?;
    let concurrency = flag_number(&flags, "--concurrency", 4)?.max(1);
    let deadline = timeout(&flags)?;
    let method = method(&flags);
    let payload = std::sync::Arc::new(payload(&flags)?);
    // `requests.max(concurrency)` used to turn `--requests 2 --concurrency 4`
    // into four requests and print `requests=4 ok=4`: the operator's number was
    // silently rewritten. Threads are bounded too, or a spawn panics at the OS
    // limit (exit 101).
    if requests < concurrency {
        return Err(CliError::usage(format!(
            "--requests {requests} is below --concurrency {concurrency}"
        )));
    }
    if concurrency > MAX_CONCURRENCY {
        return Err(CliError::usage(format!(
            "--concurrency is capped at {MAX_CONCURRENCY}"
        )));
    }
    if requests > MAX_REQUESTS {
        return Err(CliError::usage(format!(
            "--requests is capped at {MAX_REQUESTS}"
        )));
    }
    // One shared payload, not one clone per worker: 64 MiB × 1024 threads was
    // 64 GiB of address space before the first request.
    let total = requests;
    let started = Instant::now();
    let next_id = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1));
    let mut handles = Vec::new();
    for worker in 0..concurrency {
        let address = address.clone();
        let method = method.clone();
        let payload = std::sync::Arc::clone(&payload);
        let next_id = std::sync::Arc::clone(&next_id);
        let per_worker = total / concurrency + usize::from(worker < total % concurrency);
        let spawned = std::thread::Builder::new()
            .name(format!("loadgen-{worker}"))
            .spawn(move || {
                let mut latencies = Vec::new();
                let mut errors = 0usize;
                let mut transport =
                    match TcpTransport::connect_with_timeout(&address, deadline) {
                        Ok(transport) => transport,
                        // The worker could not open its connection: every
                        // request it was assigned failed.
                        Err(_) => return (Vec::new(), per_worker),
                    };
                for _ in 0..per_worker {
                    let id = next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let envelope = request(id, &method, Vec::new(), &payload, Some(cap));
                    let started = Instant::now();
                    let result = transport
                        .send(&envelope)
                        .and_then(|()| transport.recv())
                        .map(|response| response.map(|envelope| (envelope.kind, envelope.request_id)));
                    match result {
                        // A reply must carry the id this request used: a peer that
                        // replays one answer stopped being counted as `ok`.
                        Ok(Some((Kind::Response, echoed))) if echoed == id => {
                            latencies.push(started.elapsed())
                        }
                        _ => errors += 1,
                    }
                }
                (latencies, errors)
            });
        match spawned {
            Ok(handle) => handles.push(handle),
            Err(error) => {
                return Err(CliError::transport(format!(
                    "could not start {concurrency} workers: {error}"
                )))
            }
        }
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
    out_line(format!(
        "requests={total} concurrency={concurrency} ok={} errors={errors} elapsed_ms={:.3} \
         p50_ms={:.3} p95_ms={:.3} p99_ms={:.3} throughput_per_s={rate:.1}",
        latencies.len(),
        elapsed.as_secs_f64() * 1_000.0,
        percentile(50),
        percentile(95),
        percentile(99)
    ))?;
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
    reject_unknown(&flags, &["--limit", "--emit-cap-hex"])?;
    let limit = flag_number(&flags, "--limit", 1)?;
    let emit_hex = flag_bool(&flags, "--emit-cap-hex")?;
    let kernel = kernel(&["echo".to_string()])?;
    let server =
        BridgeServer::bind_loopback().map_err(|error| CliError::transport(error.to_string()))?;
    let address = server.address().to_string();
    if emit_hex {
        out_line(format!(
            "transport=connect\naddr={address}\ncap={}",
            kernel.cap.id().hex()
        ))?;
    } else {
        // The `#` prefix keeps the documented `^cap=` extraction from picking up
        // a sentence where it expects 32 hex characters.
        out_line(format!(
            "transport=connect\naddr={address}\ncap_correlation={}\n# cap=<pass --emit-cap-hex to print the caller id; that is bearer authority>",
            kernel.cap.id().correlation_id()
        ))?;
    }
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
    reject_unknown(
        &flags,
        &["--plane", "--after", "--follow", "--interval-ms", "--timeout-ms"],
    )?;
    let plane = flags
        .get("--plane")
        .filter(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| "http://127.0.0.1:8787".to_string());
    let mut after = flag_number(&flags, "--after", 0)?;
    let follow = flag_bool(&flags, "--follow")?;
    let interval = Duration::from_millis(flag_number(&flags, "--interval-ms", 500)? as u64);
    let deadline = timeout(&flags)?;
    let mut last_body = String::new();
    loop {
        let url = format!("{plane}/events?after={after}");
        let body = with_deadline(deadline, move || http_get(&url))?;
        if body != last_body {
            // The plane is plain HTTP on a default port: a 200 that is not the
            // event array is a hijacked or broken endpoint, not data. Printing it
            // raw let a hostile response forge terminal and CI lines on an exit-0
            // path.
            let events: Vec<serde_json::Value> = serde_json::from_str(&body).map_err(|_| {
                CliError::refused("the plane answered 200 with a body that is not an event array")
            })?;
            for event in &events {
                if let Some(id) = event.get("id").and_then(|value| value.as_u64()) {
                    after = after.max(id as usize);
                }
                out_line(event)?;
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
    // A plane that accepts and then says nothing held the command forever.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
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
    let mut lines = head.lines();
    if let Some(status) = lines.next() {
        // "HTTP/1.1 200" with no reason phrase is a valid status line.
        let ok = status
            .split_whitespace()
            .nth(1)
            .is_some_and(|code| code == "200");
        if !ok {
            return Err(CliError::refused(format!(
                "control plane answered {}",
                status.trim()
            )));
        }
    }
    // Headers are matched by name. A substring search saw
    // `x-note: transfer-encoding: chunked` and dechunked a plain body.
    let mut chunked = false;
    let mut declared: Option<usize> = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim() {
            "transfer-encoding" => {
                if value.trim() != "identity" {
                    chunked = true;
                }
            }
            "content-length" => {
                declared = Some(value.trim().parse().map_err(|_| {
                    CliError::transport("the control plane sent a bad content-length")
                })?);
            }
            _ => {}
        }
    }
    let body = &response[split + 4..];
    if chunked {
        return dechunk(body);
    }
    if let Some(length) = declared {
        if body.len() < length {
            return Err(CliError::transport(format!(
                "the control plane declared {length} bytes and sent {}",
                body.len()
            )));
        }
        return Ok(String::from_utf8_lossy(&body[..length]).into_owned());
    }
    Ok(String::from_utf8_lossy(body).into_owned())
}

fn dechunk(body: &[u8]) -> Result<String, CliError> {
    let mut out = Vec::new();
    let mut cursor = 0;
    let mut terminated = false;
    while cursor < body.len() {
        let Some(line_end) = body[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")
        else {
            return Err(CliError::transport("truncated chunked body"));
        };
        let size_text = String::from_utf8_lossy(&body[cursor..cursor + line_end]);
        // A chunk size is attacker-controlled: `cursor + size` used to overflow,
        // and on a 64-bit build the wrapped value passed the bounds check and
        // panicked on an inverted range (exit 101 from a hostile server).
        let size = usize::from_str_radix(size_text.trim(), 16)
            .map_err(|_| CliError::transport("bad chunk size"))?;
        if size as u64 > MAX_EVENT_BODY_BYTES {
            return Err(CliError::transport("chunk over the body ceiling"));
        }
        cursor = cursor
            .checked_add(line_end + 2)
            .ok_or_else(|| CliError::transport("chunk framing overflows"))?;
        if size == 0 {
            terminated = true;
            break;
        }
        let end = cursor
            .checked_add(size)
            .ok_or_else(|| CliError::transport("chunk length overflows"))?;
        if end > body.len() {
            return Err(CliError::transport("truncated chunk"));
        }
        out.extend_from_slice(&body[cursor..end]);
        // Every chunk but the last is followed by CRLF; a body that ends on the
        // data is truncated, not complete.
        if body.get(end..end + 2) != Some(b"\r\n".as_slice()) {
            return Err(CliError::transport("a chunk is not followed by CRLF"));
        }
        cursor = end
            .checked_add(2)
            .ok_or_else(|| CliError::transport("chunk framing overflows"))?;
    }
    if !terminated {
        return Err(CliError::transport("the chunked body has no terminal chunk"));
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

// ---------------------------------------------------------------------------
// replay
// ---------------------------------------------------------------------------

/// Largest replay package the CLI will read.
const MAX_PACKAGE_BYTES: u64 = 64 << 20;

fn replay(args: &[String]) -> CliResult {
    let (positional, flags) = split_args(&args[1..]);
    match positional.first().map(String::as_str) {
        Some("dump") => {
            reject_unknown(&flags, &["--output", "--emit-cap-hex"])?;
            if positional.len() > 1 {
                return Err(CliError::usage(
                    "replay dump takes no positional arguments".to_string(),
                ));
            }
            let package = demo_package()?;
            let path = flags
                .get("--output")
                .filter(|value| !value.is_empty())
                .cloned()
                .unwrap_or_else(|| "session.arrp".to_string());
            let encoded = package.encode().map_err(refusal)?;
            std::fs::write(&path, encoded)
                .map_err(|error| CliError::transport(format!("cannot write {path}: {error}")))?;
            out_line(format!(
                "wrote {path} ops={} trace={}",
                package.ops.len(),
                package.trace.len()
            ))?;
            Ok(())
        }
        Some("run") => {
            reject_unknown(&flags, &[])?;
            if positional.len() > 2 {
                return Err(CliError::usage(
                    "replay run takes one package path".to_string(),
                ));
            }
            let path = positional
                .get(1)
                .ok_or_else(|| CliError::usage("replay run needs a package path"))?;
            let bytes = read_bounded(path, MAX_PACKAGE_BYTES)?;
            let package = ReplayPackage::decode(&bytes)
                .map_err(|error| CliError::refused(format!("{}: {error}", error.code())))?;
            package
                .replay()
                .map_err(|error| CliError::refused(format!("{}: {error}", error.code())))?;
            out_line(format!(
                "ok ops={} trace={} latency_ms={}",
                package.ops.len(),
                package.trace.len(),
                package.latency_ms
            ))?;
            Ok(())
        }
        _ => Err(CliError::usage(
            "usage: replay dump [--output PATH]\n       replay run <package>",
        )),
    }
}

/// A deterministic demo session: mint, calls, a refusal, attenuation, a TTL
/// expiration and a revocation, all against the real kernel.
fn demo_package() -> Result<ReplayPackage, CliError> {
    let mut recorder = Recorder::new(10).map_err(refusal)?;
    let echo = recorder.mint(&["echo", "sum"], None).map_err(refusal)?;
    recorder.call(echo, "echo", 12).map_err(refusal)?;
    recorder.call(echo, "refuse", 0).map_err(refusal)?;
    let child = recorder
        .attenuate(echo, &["echo"], Some(60_000))
        .map_err(refusal)?;
    recorder.call(child, "echo", 4).map_err(refusal)?;
    // The TTL is short enough that the fourth call lands after it.
    let ttl = recorder.mint(&["echo"], Some(25)).map_err(refusal)?;
    for _ in 0..4 {
        recorder.call(ttl, "echo", 0).map_err(refusal)?;
    }
    recorder.revoke(echo).map_err(refusal)?;
    recorder.call(echo, "echo", 0).map_err(refusal)?;
    recorder.package().map_err(refusal)
}

fn refusal(error: active_rpc::Error) -> CliError {
    CliError::refused(format!("{}: {error}", error.code()))
}

fn read_bounded(path: &str, ceiling: u64) -> Result<Vec<u8>, CliError> {
    let file = std::fs::File::open(path)
        .map_err(|error| CliError::usage(format!("cannot read {path}: {error}")))?;
    let mut bytes = Vec::new();
    file.take(ceiling + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| CliError::usage(format!("cannot read {path}: {error}")))?;
    if bytes.len() as u64 > ceiling {
        return Err(CliError::usage(format!(
            "{path} is larger than the {ceiling}-byte ceiling"
        )));
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// receipts
// ---------------------------------------------------------------------------

/// Secret of the demo kernel `receipts dump` records. The receipt key is derived
/// from it, so a test can verify the exported log without the CLI printing key
/// material; [`active_rpc::receipts::derive_receipt_key`] derives the same key.
const DEMO_SECRET: [u8; 32] = [0x5e; 32];

const RECEIPTS_USAGE: &str = "usage: receipts dump [--output PATH]\n       \
receipts verify <log> (--receipt-key-file PATH | --expect-head HEX | --chain-only)\n       \
receipts show <log> [--limit N]\n       \
receipts repair <log>";

fn receipts(args: &[String]) -> CliResult {
    let (positional, flags) = split_args(&args[1..]);
    match positional.first().map(String::as_str) {
        Some("dump") => {
            reject_unknown(&flags, &["--output"])?;
            if positional.len() > 1 {
                return Err(CliError::usage(
                    "receipts dump takes no positional arguments".to_string(),
                ));
            }
            receipts_dump(&flags)
        }
        Some("verify") => {
            reject_unknown(
                &flags,
                &["--receipt-key-file", "--expect-head", "--chain-only"],
            )?;
            if positional.len() > 2 {
                return Err(CliError::usage(
                    "receipts verify takes one log path".to_string(),
                ));
            }
            let path = positional
                .get(1)
                .ok_or_else(|| CliError::usage(RECEIPTS_USAGE.to_string()))?;
            receipts_verify(path, &flags)
        }
        Some("show") => {
            reject_unknown(&flags, &["--limit"])?;
            if positional.len() > 2 {
                return Err(CliError::usage(
                    "receipts show takes one log path".to_string(),
                ));
            }
            let path = positional
                .get(1)
                .ok_or_else(|| CliError::usage(RECEIPTS_USAGE.to_string()))?;
            let limit = match flags.get("--limit").filter(|value| !value.is_empty()) {
                Some(value) => value
                    .parse::<usize>()
                    .map_err(|_| CliError::usage("--limit expects a number".to_string()))?,
                None => usize::MAX,
            };
            receipts_show(path, limit)
        }
        Some("repair") => {
            reject_unknown(&flags, &[])?;
            if positional.len() > 2 {
                return Err(CliError::usage(
                    "receipts repair takes one log path".to_string(),
                ));
            }
            let path = positional
                .get(1)
                .ok_or_else(|| CliError::usage(RECEIPTS_USAGE.to_string()))?;
            receipts_repair(path)
        }
        _ => Err(CliError::usage(RECEIPTS_USAGE.to_string())),
    }
}

/// Record a demo session with receipts enabled and export the log.
fn receipts_dump(flags: &BTreeMap<String, String>) -> CliResult {
    let output = flags
        .get("--output")
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| CliError::usage(RECEIPTS_USAGE.to_string()))?;
    let agent = Agent::with_secret(DEMO_SECRET);
    agent.enable_receipts(true);
    let provider = agent.register(Box::new(DemoProvider));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo", "sum"]))
        .map_err(refusal)?;
    let lane = agent
        .create_lane("receipts", Budget::default())
        .map_err(refusal)?;
    for method in ["echo", "echo", "sum"] {
        let promise = agent
            .call(lane, &cap, method, vec![Arg::Value(Value::Int(2))])
            .map_err(refusal)?;
        agent.run();
        promise.value().map_err(refusal)?;
    }
    // A refusal at dispatch is a decision and is recorded as one. Queue the
    // call while the capability is live, revoke it, then run: the queue accepts
    // the call and dispatch refuses it, which is the window a queue-time seal
    // used to record as an authorization.
    let refused = agent
        .call(lane, &cap, "echo", Vec::new())
        .map_err(refusal)?;
    agent.revoke(&cap).map_err(refusal)?;
    agent.run();
    match refused.value() {
        Err(error) if error.code() == "rpc/revoked" => {}
        // A shipped binary reports; it does not assert. A behaviour change here
        // must be a refusal with a message, not a panic and exit 101.
        Err(error) => {
            return Err(CliError::refused(format!(
                "the demo refusal settled as {} instead of rpc/revoked",
                error.code()
            )))
        }
        Ok(_) => {
            return Err(CliError::refused(
                "the demo refusal was admitted".to_string(),
            ))
        }
    }
    let receipts = agent.receipts();
    let start = receipts.first().map_or(1, |receipt| receipt.sequence);
    // A wrapped ring exports its retained window, not "sequence 1 onwards".
    let log = ReceiptLog::create_starting_at(&output, start)
        .map_err(|error| CliError::refused(format!("{}: {error} ({output:?})", error.code())))?;
    // The owner path: the writer proves it holds the receipt key, so the log
    // cannot be extended with fabricated records.
    log.append_verified(&agent.receipt_key(), &receipts)
        .map_err(|error| CliError::refused(format!("{}: {error} ({output:?})", error.code())))?;
    out_line(format!(
        "wrote {} receipts to {:?} (demo key is public: this log proves the format, not a real kernel)",
        receipts.len(),
        output
    ))?;
    // Print the head of the same read the append verified, not a second read.
    let snapshot = log
        .snapshot()
        .map_err(|error| CliError::refused(format!("{}: {error} ({output:?})", error.code())))?;
    out_line(format!("head {}", hex32(&snapshot.head())))?;
    Ok(())
}

fn receipts_verify(path: &str, flags: &BTreeMap<String, String>) -> CliResult {
    let log = open_receipt_log(path)?;
    let key = match flags
        .get("--receipt-key-file")
        .filter(|value| !value.is_empty())
    {
        Some(file) => Some(read_receipt_key(file)?),
        None => None,
    };
    let expected = match flags.get("--expect-head").filter(|value| !value.is_empty()) {
        Some(text) => Some(parse_hex32(text).ok_or_else(|| {
            CliError::usage("--expect-head expects 64 hex characters".to_string())
        })?),
        None => None,
    };
    let chain_only = flags.contains_key("--chain-only");
    // An unauthenticated check cannot detect a forged record or a missing tail,
    // so `ok … exit 0` would mislead an operator or a CI gate. Opting into it is
    // explicit.
    if key.is_none() && expected.is_none() && !chain_only {
        return Err(CliError::usage(format!(
            "an unauthenticated check proves only the chain: pass --receipt-key-file \
             to verify authenticity, --expect-head to detect a truncated tail, or \
             --chain-only to accept the weaker check\n{RECEIPTS_USAGE}"
        )));
    }
    // One read: a second read could see a different file, and the printed head
    // would then be one the MAC check never covered.
    let snapshot = log
        .snapshot()
        .map_err(|error| CliError::refused(format!("{}: {error} ({path:?})", error.code())))?;
    if let Some(key) = key {
        snapshot
            .verify_macs(&key)
            .map_err(|error| CliError::refused(format!("{}: {error} ({path:?})", error.code())))?;
    }
    if let Some(expected) = expected {
        snapshot
            .verify_against(expected)
            .map_err(|error| CliError::refused(format!("{}: {error} ({path:?})", error.code())))?;
    }
    out_line(format!(
        "ok {} receipts, start {}, head {}{}",
        snapshot.len(),
        snapshot.start_sequence(),
        hex32(&snapshot.head()),
        match (key.is_some(), expected.is_some()) {
            (true, true) => ", macs verified, head pinned",
            (true, false) => ", macs verified",
            (false, true) => ", chain-only, head pinned",
            (false, false) => ", chain-only (unauthenticated)",
        }
    ))?;
    Ok(())
}

fn receipts_repair(path: &str) -> CliResult {
    // A missing path is a bad argument here too, so the exit class matches the
    // other receipts commands.
    if !std::path::Path::new(path).exists() {
        return Err(CliError::usage(format!("no receipt log at {path:?}")));
    }
    // Repair deliberately works without a valid handle: the file is damaged, so
    // `open` would refuse it.
    let discarded = ReceiptLog::repair(path)
        .map_err(|error| CliError::refused(format!("{}: {error} ({path:?})", error.code())))?;
    let log = open_receipt_log(path)?;
    let snapshot = log
        .snapshot()
        .map_err(|error| CliError::refused(format!("{}: {error} ({path:?})", error.code())))?;
    out_line(format!(
        "ok {} receipts kept, {} byte(s) of an interrupted write discarded, head {} \
         (structure only; pass a receipt key to verify authenticity)",
        snapshot.len(),
        discarded,
        hex32(&snapshot.head())
    ))?;
    Ok(())
}

fn receipts_show(path: &str, limit: usize) -> CliResult {
    if limit == 0 {
        return Err(CliError::usage(
            "--limit must be at least 1 (0 printed nothing and exited 0)".to_string(),
        ));
    }
    let log = open_receipt_log(path)?;
    let snapshot = log
        .snapshot()
        .map_err(|error| CliError::refused(format!("{}: {error} ({path:?})", error.code())))?;
    // The records are unverified structure: `verify` is the command that proves
    // who wrote them, and a reader must not mistake this listing for evidence.
    out_line(format!(
        "# {} record(s), structure unverified; run `receipts verify` for authenticity",
        snapshot.len()
    ))?;
    for receipt in snapshot.receipts().iter().take(limit) {
        // The method is quoted: it is stored text, and a raw newline would turn
        // one record into two lines of "evidence".
        out_line(format!(
            "{} {} {} {} {:?} {}",
            receipt.sequence,
            receipt.at_ms,
            receipt.cap,
            active_rpc::receipts::decision_label(&receipt.decision),
            receipt.method,
            match &receipt.decision {
                active_rpc::receipts::Decision::Refused(code) => code.as_str(),
                active_rpc::receipts::Decision::Admitted => "",
            }
        ))?;
    }
    Ok(())
}

/// Read a receipt key from a file: 64 hex characters, one line.
///
/// A file on a shared or world-readable path is refused on unix (mode `0o077`
/// must be clear): the key proves an audit log, and a leaked key lets a stranger
/// forge one. Windows ACLs are the deployment's responsibility, so the check is
/// unix-only and documented.
/// Read a 64-hex receipt key, tolerating a trailing line ending.
///
/// The ceiling used to be 65 bytes, so a Windows file of 64 hex plus CRLF was
/// refused as too large.
fn read_receipt_key(path: &str) -> Result<[u8; 32], CliError> {
    // 64 hex characters plus a line ending: a Windows file is 66 bytes, and the
    // old 65-byte ceiling refused a perfectly normal key file.
    let text = String::from_utf8(read_bounded(path, 68)?)
        .map_err(|_| CliError::usage(format!("{path:?} is not text")))?;
    let text = text.trim_end_matches(['\r', '\n']);
    #[cfg(unix)]
    {
        // The open handle, not the path: a rename between the read and the stat
        // would check a different file.
        use std::os::unix::fs::PermissionsExt;
        let file = std::fs::File::open(path)
            .map_err(|error| CliError::usage(format!("cannot open {path:?}: {error}")))?;
        let mode = file
            .metadata()
            .map_err(|error| CliError::usage(format!("cannot stat {path:?}: {error}")))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(CliError::usage(format!(
                "{path:?} is readable by other accounts (mode {mode:o}); chmod 600 it"
            )));
        }
    }
    parse_hex32(text.trim()).ok_or_else(|| {
        CliError::usage(format!(
            "{path:?} must hold 64 hex characters (the kernel's receipt key)"
        ))
    })
}

fn parse_hex32(text: &str) -> Option<[u8; 32]> {
    // A 64-*byte* non-ASCII string would make the two-byte slice below land
    // inside a character and panic; check the alphabet first.
    if text.len() != 64 || !text.is_ascii() {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

fn open_receipt_log(path: &str) -> Result<ReceiptLog, CliError> {
    // A path that does not exist is a bad argument, not a damaged log; saying so
    // keeps the exit class meaningful for a script.
    if !std::path::Path::new(path).exists() {
        return Err(CliError::usage(format!("no receipt log at {path:?}")));
    }
    ReceiptLog::open(path)
        .map_err(|error| CliError::refused(format!("{}: {error} ({path:?})", error.code())))
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The demo provider used by `receipts dump`: deterministic, free of I/O.
struct DemoProvider;

impl Provider for DemoProvider {
    fn name(&self) -> &'static str {
        "demo"
    }

    fn methods(&self) -> Vec<String> {
        vec!["echo".to_string(), "sum".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::Text(call.method.clone())))
    }
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
       [--cert-out PATH] [--emit-cap-hex]
      Start a demo peer with a real kernel and a minted capability. Prints
      transport, addr, cap_correlation (and cert for quic); --emit-cap-hex prints
      the raw caller id instead, which is bearer authority. --limit is
      connections for tcp/http2, requests for connect, calls for quic; 0 serves
      until Ctrl-C on tcp.
  call --addr HOST:PORT [--transport ...] [--cap HEX] [--method M]
       [--payload FILE | --text TEXT] [--cert FILE] [--timeout-ms N]
      Issue one call and print kind, id, payload length and value.
  pipeline --addr HOST:PORT --cap HEX [--calls N] [--method M] [--payload FILE]
           [--timeout-ms N]
      Send N calls on one connection before reading any response; prints the
      round-trip count.
  loadgen --addr HOST:PORT --cap HEX [--requests N] [--concurrency C]
          [--method M] [--payload FILE]
      Controlled load over C connections; prints p50/p95/p99 and throughput.
  bridge [--limit N]
      Serve the Connect/gRPC interop bridge against the demo kernel.
  events [--plane URL] [--after ID] [--follow] [--interval-ms N]
      Tail the control-plane event stream (correlation ids only).
  replay dump [--output PATH]
      Record a deterministic demo session (mint, calls, refusal, TTL expiry,
      revocation) into a replay package.
  replay run <package>
      Replay a package against a fresh kernel and compare every decision;
      a tampered or divergent package is refused.
  receipts dump [--output PATH]
      Record a demo session with receipts enabled into an append-only ARRL log
      (correlation ids, methods and times only; no arguments or secrets).
  receipts verify <log> (--receipt-key-file PATH | --expect-head HEX | --chain-only)
      Verify the log's record hashes and chain links. --receipt-key-file holds the
      kernel's 64-hex receipt key (Agent::receipt_key; 0600) and verifies every
      receipt MAC; --expect-head pins the head a verifier learned out of band,
      which detects a truncated tail; --chain-only accepts the weaker check that
      proves only integrity. One of the three is required, because an
      unauthenticated \"ok\" would mislead a gate.
  receipts repair <log>
      Cut an interrupted trailing write back to the last complete record, keeping
      the chain of the records that survived.
  receipts show <log> [--limit N]
      Print sequence, time, correlation id and method per record.
  help
      This text.
  version
      Print the CLI and kernel versions.

Exit codes: 0 success, 1 refusal or failed request, 2 usage, 3 transport or
codec failure.

Examples:
  active-rpc-cli peer --limit 4
  active-rpc-cli peer --limit 4 --emit-cap-hex > peer.txt   # bearer id: keep it private
  active-rpc-cli call --addr 127.0.0.1:5000 --cap 00112233445566778899aabbccddeeff
  active-rpc-cli pipeline --addr 127.0.0.1:5000 --cap <hex> --calls 16
  active-rpc-cli loadgen --addr 127.0.0.1:5000 --cap <hex> --requests 200 --concurrency 8
  active-rpc-cli events --plane http://127.0.0.1:8787 --follow
  active-rpc-cli replay dump --output session.arrp
  active-rpc-cli replay run session.arrp

A capability id printed with --emit-cap-hex is bearer authority: anyone who
reads it can call the peer while its kernel lives. Keep it out of shell history,
shared files and CI logs; the default output is the non-reversible correlation id.",
        env!("CARGO_PKG_VERSION")
    )
}
