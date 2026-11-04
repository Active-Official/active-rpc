//! gRPC / Connect bridge.
//!
//! The bridge lets an ordinary HTTP client — a gRPC toolchain, a Connect client,
//! or `curl` — exchange Active RPC envelopes without knowing the kernel. It
//! speaks the unary Connect protocol over HTTP/1.1 and carries messages in the
//! gRPC length-prefixed framing, so the same codec sits behind an HTTP/2 gRPC
//! server without changes:
//!
//! ```text
//! POST /active.rpc.v1.Agent/Call HTTP/1.1
//! content-type: application/connect+active-infinity
//!
//! [0x00][len u32 big-endian][envelope bytes]
//! ```
//!
//! A malformed frame, an oversized body or a bad content type is answered with a
//! `4xx` status and a stable code (`rpc/wire`), never a panic or a dropped
//! connection.
//!
//! ADR-0004 records why this is Connect over HTTP/1.1 rather than a full HTTP/2
//! stack: it is the interoperability surface, not the hot path, and it stays
//! dependency-free so the crate still builds on a bare toolchain.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};

use crate::error::{Error, Result};
use crate::wire::{Envelope, WireLimits};

/// Service path the bridge answers.
pub const PATH: &str = "/active.rpc.v1.Agent/Call";
/// Connect unary content type.
pub const CONNECT_TYPE: &str = "application/connect+active-infinity";
/// gRPC content type (accepted, same framing).
pub const GRPC_TYPE: &str = "application/grpc+active-infinity";

/// Largest request body the bridge accepts.
pub const MAX_BODY: usize = 64 << 20;
/// Largest request head (request line plus headers).
pub const MAX_HEAD: usize = 16 << 10;

/// How long one connection may take to deliver its head and body.
///
/// The bridge accepts one connection at a time, so a peer that sends `POST …`
/// and stops would otherwise hold every later peer forever. A local head is
/// small and immediate; two seconds is generous and bounds the stall.
pub const CONNECTION_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// Frame one message with the gRPC 5-byte prefix.
pub fn grpc_frame(payload: &[u8]) -> Result<Vec<u8>> {
    // A payload past the ceiling is a wire fault, not a slow path: wrapping the
    // length would make the peer read the tail as a second message
    // (round 25, #5; round 26, #1). A direct caller may hold untrusted bytes,
    // so this is a refusal and never an assertion (round 35, #2).
    if payload.len() > MAX_BODY {
        return Err(Error::Wire("bridge message exceeds the ceiling"));
    }
    let length = u32::try_from(payload.len()).map_err(|_| Error::Wire("bridge length overflow"))?;
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Split one gRPC-framed message off `body`, returning it and the rest.
pub fn grpc_unframe(body: &[u8]) -> Result<(&[u8], &[u8])> {
    if body.len() < 5 {
        return Err(Error::Wire("grpc frame shorter than its prefix"));
    }
    if body[0] != 0 {
        return Err(Error::Wire("compressed grpc frames are not supported"));
    }
    let len = u32::from_be_bytes(body[1..5].try_into().expect("4 bytes")) as usize;
    if len > MAX_BODY {
        return Err(Error::Wire("grpc frame exceeds the ceiling"));
    }
    let end = 5 + len;
    if end > body.len() {
        return Err(Error::Wire("truncated grpc frame"));
    }
    Ok((&body[5..end], &body[end..]))
}

/// A bridge server bound to a loopback port.
pub struct BridgeServer {
    listener: TcpListener,
    address: String,
    limits: WireLimits,
}

/// Accept failures tolerated in a row before `serve` gives up.
const MAX_ACCEPT_FAILURES: u32 = 64;

/// True for the accept errors that are the peer's, not the listener's.
fn is_transient_accept(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::Interrupted | std::io::ErrorKind::ConnectionAborted
    )
}

/// Set the socket timeout to the time left before `deadline`.
///
/// Returns false when the deadline has already passed, so a caller answers a
/// timeout instead of blocking.
fn arm_deadline(stream: &TcpStream, deadline: std::time::Instant) -> bool {
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
        return false;
    }
    stream.set_read_timeout(Some(remaining)).is_ok()
        && stream.set_write_timeout(Some(remaining)).is_ok()
}

/// Read one line, re-arming the connection deadline before every fill.
///
/// `BufRead::read_until` loops `fill_buf` internally, so a single call gets one
/// socket timeout for the whole line: a peer that sends one byte every second
/// keeps a 16 KiB line alive for hours. Reading a chunk at a time puts the
/// deadline back in charge.
fn read_line_before(
    reader: &mut BufReader<TcpStream>,
    max: usize,
    deadline: Option<std::time::Instant>,
) -> Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        if let Some(deadline) = deadline {
            if !arm_deadline(reader.get_ref(), deadline) {
                return Err(Error::Transport("request head timed out".to_string()));
            }
        }
        let available = reader
            .fill_buf()
            .map_err(|error| Error::Transport(format!("head: {error}")))?;
        if available.is_empty() {
            return Ok(if line.is_empty() { None } else { Some(line) });
        }
        let (take, done) = match available.iter().position(|byte| *byte == b'\n') {
            Some(index) => (index + 1, true),
            None => (available.len(), false),
        };
        if line.len() + take > max {
            return Err(Error::Wire("request head exceeds the ceiling"));
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if done {
            return Ok(Some(line));
        }
    }
}

/// Read exactly `length` bytes before `deadline`.
///
/// A drip that stays inside a per-read timeout is still bounded by the
/// connection deadline; the timeout is recomputed from the remaining time before
/// every read.
enum BodyFault {
    /// The peer closed or errored before the announced length arrived.
    Truncated,
    /// The deadline passed while the body was still arriving.
    TimedOut,
}

fn read_body_by_deadline(
    reader: &mut BufReader<TcpStream>,
    length: usize,
    deadline: std::time::Instant,
    body: &mut Vec<u8>,
) -> std::result::Result<(), BodyFault> {
    use std::io::Read;
    let mut chunk = [0u8; 16 * 1024];
    while body.len() < length {
        if !arm_deadline(reader.get_ref(), deadline) {
            return Err(BodyFault::TimedOut);
        }
        let want = (length - body.len()).min(chunk.len());
        match reader.read(&mut chunk[..want]) {
            Ok(0) => return Err(BodyFault::Truncated),
            Ok(read) => body.extend_from_slice(&chunk[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            // A socket timeout is a slow peer; anything else is a broken one.
            // Reporting a truncated body as a timeout made a framing fault
            // retryable and put an EOF and a stall in one class
            // (round 35, R-09 #5).
            Err(error)
                if error.kind() == std::io::ErrorKind::TimedOut
                    || error.kind() == std::io::ErrorKind::WouldBlock =>
            {
                return Err(BodyFault::TimedOut)
            }
            Err(_) => return Err(BodyFault::Truncated),
        }
    }
    if body.len() == length {
        Ok(())
    } else {
        Err(BodyFault::Truncated)
    }
}

impl BridgeServer {
    /// Bind an ephemeral loopback port.
    pub fn bind_loopback() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|error| Error::Transport(format!("bind: {error}")))?;
        let address = listener
            .local_addr()
            .map_err(|error| Error::Transport(error.to_string()))?
            .to_string();
        Ok(Self {
            listener,
            address,
            limits: WireLimits::default(),
        })
    }

    /// The bound address.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Use tighter wire limits.
    pub fn with_limits(mut self, limits: WireLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Serve `requests` connections, then return the number of calls served.
    pub fn serve<H>(&self, requests: usize, mut handler: H) -> Result<u64>
    where
        H: FnMut(Envelope) -> Envelope,
    {
        let mut served = 0u64;
        let mut failures = 0u32;
        // Count accepted connections, not loop iterations: a transient accept
        // failure used to consume one of the caller's `requests`, so a peer
        // that reset its connections could starve the ones that would work
        // (round 26, #7).
        let mut accepted_count = 0usize;
        while accepted_count < requests {
            let (stream, _) = match self.listener.accept() {
                Ok(accepted) => {
                    failures = 0;
                    accepted_count += 1;
                    accepted
                }
                // A transient accept failure (EINTR, ECONNABORTED) belongs to the
                // peer that went away; a persistent one (EMFILE) must not spin
                // or exit, so it backs off and gives the server a chance to
                // shed work.
                Err(error) if failures < MAX_ACCEPT_FAILURES => {
                    failures += 1;
                    if is_transient_accept(&error) {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    } else {
                        std::thread::sleep(std::time::Duration::from_millis(
                            5 * u64::from(failures),
                        ));
                    }
                    continue;
                }
                Err(error) => {
                    return Err(Error::Transport(format!("accept: {error}")));
                }
            };
            served += self.handle(stream, &mut handler);
        }
        Ok(served)
    }

    /// One connection.
    ///
    /// Every failure here belongs to this connection, never to the server: a
    /// truncated head, a stalled peer, a bad frame or a dead socket answers a
    /// `4xx` when it can and returns. `serve` keeps accepting.
    fn handle<H>(&self, mut stream: TcpStream, handler: &mut H) -> u64
    where
        H: FnMut(Envelope) -> Envelope,
    {
        let _ = stream.set_nodelay(true);
        // One deadline for the whole connection, recomputed into the socket
        // timeout before every read. A per-read timeout let a peer send one byte
        // just inside it forever, holding the (serial) bridge's only accept slot
        // while every later peer waited.
        let deadline = std::time::Instant::now() + CONNECTION_WAIT;
        let Ok(clone) = stream.try_clone() else {
            return 0;
        };
        let mut reader = BufReader::new(clone);
        if !arm_deadline(&stream, deadline) || !arm_deadline(reader.get_ref(), deadline) {
            let _ = write_http_response(&mut stream, 408, b"rpc/transport", deadline);
            drain_before_close(&mut stream);
            return 0;
        }
        let head = match read_head(&mut reader, MAX_HEAD, Some(deadline), true) {
            Ok(Some(head)) => head,
            Ok(None) => return 0,
            Err(_) => {
                // A head that ran out of time is a timeout, not a malformed
                // request: the operator can tell a drip from a bad grammar.
                let status = if std::time::Instant::now() >= deadline {
                    408
                } else {
                    400
                };
                let body: &[u8] = if status == 408 {
                    b"rpc/transport"
                } else {
                    b"rpc/wire"
                };
                let _ = write_http_response(&mut stream, status, body, deadline);
                drain_before_close(&mut stream);
                return 0;
            }
        };
        let request_line = head.first().cloned().unwrap_or_default();
        if !request_line
            .bytes()
            .all(|byte| byte == 0x20 || (0x21..=0x7e).contains(&byte))
        {
            // Unicode whitespace (a TAB, an NBSP) is not a separator in HTTP:
            // `split_whitespace` accepted what a proxy would not
            // (round 27, low).
            let _ = write_http_response(&mut stream, 400, b"rpc/wire", deadline);
            drain_before_close(&mut stream);
            return 0;
        }
        let mut parts = request_line.split(' ');
        let method = parts.next().unwrap_or_default();
        let target = parts.next().unwrap_or_default();
        let version = parts.next().unwrap_or_default();
        // A fourth token or another version is a request a proxy may read
        // differently; this bridge serves exactly one shape (round 25, #6).
        if parts.next().is_some() || version != "HTTP/1.1" {
            let _ = write_http_response(&mut stream, 400, b"rpc/wire", deadline);
            drain_before_close(&mut stream);
            return 0;
        }
        if method != "POST" {
            // The HTTP/2 bridge answers 405 for this mistake; one status per
            // property across both bridges (round 26, #8).
            let _ = write_http_response(&mut stream, 405, b"rpc/wire", deadline);
            drain_before_close(&mut stream);
            return 0;
        }
        if target != PATH {
            let _ = write_http_response(&mut stream, 404, b"rpc/wire", deadline);
            drain_before_close(&mut stream);
            return 0;
        }
        // Content-Length must be unambiguous and Transfer-Encoding absent: a
        // front proxy that resolves a conflict differently would let a second
        // request ride in front of this one.
        let mut lengths: Vec<usize> = Vec::new();
        let mut transfer_encoding = false;
        for (index, line) in head.iter().enumerate() {
            if index == 0 {
                // The request line is parsed on its own.
                continue;
            }
            // A field the server ignores is a field a gateway may act on: an
            // unparsable line or a name that is not a token is a refusal, not
            // something to skip (round 24, F3).
            let Some((name, value)) = line.split_once(':') else {
                let _ = write_http_response(&mut stream, 400, b"rpc/wire", deadline);
                drain_before_close(&mut stream);
                return 0;
            };
            if name.is_empty() || !name.bytes().all(crate::tool::is_http_token) {
                let _ = write_http_response(&mut stream, 400, b"rpc/wire", deadline);
                drain_before_close(&mut stream);
                return 0;
            }
            if name.eq_ignore_ascii_case("transfer-encoding") {
                transfer_encoding = true;
            }
            if name.eq_ignore_ascii_case("content-length") {
                // Plain decimal digits only: RFC 9112 has no sign or whitespace,
                // and `+25` is the kind of value a front proxy may resolve
                // differently from this server.
                let trimmed = value.trim();
                if trimmed.is_empty()
                    || trimmed.len() > 20
                    || !trimmed.bytes().all(|byte| byte.is_ascii_digit())
                {
                    let _ = write_http_response(&mut stream, 400, b"rpc/wire", deadline);
                    drain_before_close(&mut stream);
                    return 0;
                }
                match trimmed.parse::<usize>() {
                    Ok(length) => lengths.push(length),
                    Err(_) => {
                        let _ = write_http_response(&mut stream, 400, b"rpc/wire", deadline);
                        drain_before_close(&mut stream);
                        return 0;
                    }
                }
            }
        }
        if transfer_encoding || lengths.len() != 1 {
            let _ = write_http_response(&mut stream, 400, b"rpc/wire", deadline);
            drain_before_close(&mut stream);
            return 0;
        }
        let content_length = lengths[0];
        // The body ceiling is the wire limit, not only the protocol maximum: a
        // strict server must not read 64 MiB to discover it refuses the frame.
        let body_ceiling = MAX_BODY.min(self.limits.max_bytes);
        // `content-length` counts the framed message, prefix included.
        if content_length > body_ceiling.saturating_add(5) {
            let _ = write_http_response(&mut stream, 413, b"rpc/wire", deadline);
            drain_before_close(&mut stream);
            return 0;
        }
        let content_types: Vec<&str> = head
            .iter()
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-type") {
                    Some(value.trim())
                } else {
                    None
                }
            })
            .collect();
        if content_types.len() > 1 {
            // Two `content-type` lines leave the framing ambiguous; a proxy
            // that joins or takes the last value disagrees with this server
            // (round 25, #6).
            let _ = write_http_response(&mut stream, 400, b"rpc/wire", deadline);
            drain_before_close(&mut stream);
            return 0;
        }
        let content_type = content_types.first().copied().unwrap_or_default();
        if content_type != CONNECT_TYPE && content_type != GRPC_TYPE {
            let _ = write_http_response(&mut stream, 415, b"rpc/wire", deadline);
            drain_before_close(&mut stream);
            return 0;
        }
        let mut body = Vec::with_capacity(content_length.min(64 * 1024));
        if let Err(fault) = read_body_by_deadline(&mut reader, content_length, deadline, &mut body)
        {
            // A truncated body is one bad connection, not a server failure:
            // answer 400 for it and keep accepting the next one. Growing the
            // buffer with the bytes that arrive means a header that announces
            // 64 MiB and sends ten bytes costs 64 KiB, not 64 MiB. A body that
            // ran out of time is a timeout instead, the same discrimination
            // the head path makes (round 24, F4). The fault carries its own
            // reason, so an EOF inside the grace band is not called a timeout
            // (round 35, R-09 #5).
            let (status, code) = match fault {
                BodyFault::TimedOut => (408, &b"rpc/transport"[..]),
                BodyFault::Truncated => (400, &b"rpc/wire"[..]),
            };
            let _ = write_http_response(&mut stream, status, code, deadline);
            drain_before_close(&mut stream);
            return 0;
        }
        let (message, rest) = match grpc_unframe(&body) {
            Ok(parts) => parts,
            Err(error) => {
                let _ = write_http_response(&mut stream, 400, error.code().as_bytes(), deadline);
                drain_before_close(&mut stream);
                return 0;
            }
        };
        if !rest.is_empty() {
            let _ = write_http_response(&mut stream, 400, b"rpc/wire", deadline);
            drain_before_close(&mut stream);
            return 0;
        }
        let envelope = match Envelope::decode_with(message, self.limits) {
            Ok(envelope) => envelope,
            Err(error) => {
                let _ = write_http_response(&mut stream, 400, error.code().as_bytes(), deadline);
                drain_before_close(&mut stream);
                return 0;
            }
        };
        // A response or error envelope is not a call. Refusing it here keeps the
        // kind contract at the transport boundary, where a relay would otherwise
        // be able to smuggle one in.
        if envelope.kind != crate::wire::Kind::Request {
            let _ = write_http_response(&mut stream, 400, b"rpc/wire", deadline);
            drain_before_close(&mut stream);
            return 0;
        }
        // A provider panic on hostile input must not take the bridge down: the
        // handler runs on the serving thread, so the panic becomes a refusal.
        let request_id = envelope.request_id;
        let response =
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(envelope))) {
                Ok(response) => response,
                Err(_) => Envelope::error(
                    request_id,
                    &Error::Provider {
                        code: "rpc/provider".to_string(),
                    },
                ),
            };
        let bytes = match response.encode() {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = write_http_response(&mut stream, 500, error.code().as_bytes(), deadline);
                drain_before_close(&mut stream);
                return 0;
            }
        };
        if bytes.len() > MAX_BODY {
            let _ = write_http_response(&mut stream, 413, b"rpc/wire", deadline);
            drain_before_close(&mut stream);
            return 0;
        }
        let Ok(framed) = grpc_frame(&bytes) else {
            // The body was checked against `MAX_BODY` above, so this is the
            // length conversion failing on a 32-bit target.
            let _ = write_http_response(&mut stream, 413, b"rpc/wire", deadline);
            drain_before_close(&mut stream);
            return 0;
        };
        // The read deadline's remainder may be milliseconds after a body that
        // landed just in time; give the response its own budget.
        let _ = stream.set_write_timeout(Some(CONNECTION_WAIT));
        // A peer that never read the response was not served; counting it would
        // make --limit and the served metric lie.
        u64::from(write_http_response(&mut stream, 200, &framed, deadline).is_ok())
    }
}

/// Read one head line under the remaining budget.
///
/// `read_line` into a `String` grows until the peer sends a newline, so the
/// ceiling was only checked after the allocation. This reads bytes into a
/// fixed buffer bounded by what is left of the budget, and a line that does not
/// fit is refused without growing. A line that is not UTF-8 is a wire fault:
/// decoding it lossily would compare a header name the peer did not send
/// (round 23, #4).
fn read_head(
    reader: &mut BufReader<TcpStream>,
    max: usize,
    deadline: Option<std::time::Instant>,
    request_side: bool,
) -> Result<Option<Vec<String>>> {
    let mut head = Vec::new();
    let mut total = 0usize;
    loop {
        // The socket timeout is per read; a head that dribbles one byte just
        // inside it would hold the serial accept slot for hours. Re-arm the
        // connection deadline before every line, on the handle that reads.
        if let Some(deadline) = deadline {
            if !arm_deadline(reader.get_ref(), deadline) {
                return Err(Error::Transport("request head timed out".to_string()));
            }
        }
        let remaining = max.saturating_sub(total);
        let raw: Vec<u8> = read_line_before(reader, remaining + 1, deadline)?.unwrap_or_default();
        let read = raw.len();
        if read == 0 {
            if head.is_empty() {
                return Ok(None);
            }
            // EOF before the blank line: the head is incomplete, and a proxy
            // that waits for the rest would disagree about where it ends.
            return Err(Error::Wire("request head ended before its blank line"));
        }
        total += read;
        if total > max {
            return Err(Error::Wire("request head exceeds the ceiling"));
        }
        // RFC 9112: every line ends CRLF, and a bare CR inside a field is not a
        // value character. A proxy with different line splitting would otherwise
        // see different header boundaries than this server.
        let Some(body) = raw.strip_suffix(b"\r\n") else {
            return Err(Error::Wire("request head line is not CRLF-terminated"));
        };
        if body.contains(&b'\r') {
            return Err(Error::Wire(
                "request head line carries a bare carriage return",
            ));
        }
        if body.is_empty() {
            break;
        }
        // RFC 9112 has no folded line: a line that starts with a space or a
        // tab is obs-fold, and a front proxy that ends the block there while
        // this server reads the fold sees a different request (round 24, F3).
        if matches!(body.first(), Some(b' ' | b'\t')) {
            return Err(Error::Wire("request head line starts with whitespace"));
        }
        // An HTTP/1.1 field is an ASCII token plus a UTF-8 value. A lossy
        // decode turned an invalid byte into U+FFFD, so a `transfer-encoding`
        // name carrying one was not the name the peer sent and slipped past
        // the refusal (round 23, #4).
        let line = if request_side {
            let Ok(line) = String::from_utf8(body.to_vec()) else {
                return Err(Error::Wire("request head line is not UTF-8"));
            };
            line
        } else {
            // A response field value may carry obs-text; a lossy decode cannot
            // turn a field name into another token (round 24, F11).
            String::from_utf8_lossy(body).into_owned()
        };
        head.push(line);
    }
    Ok(Some(head))
}

/// Drain a peer that is still sending before the socket closes.
///
/// Closing a socket with unread data in its receive buffer makes the stack send
/// a reset, which discards the response just written: the client sees a
/// connection reset instead of the 400 (observed as a suite flake on Windows).
fn drain_before_close(stream: &mut TcpStream) {
    use std::io::Read;
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(100)));
    // Bounded by time, not by iterations: a 1 MiB body arriving in 4 KiB
    // segments is 256 reads, and stopping at 16 let the close reset it and
    // discard the refusal (round 19, #4).
    // Within the documented connection budget (2 s): the head already used
    // part of it, so the drain adds at most 100 ms (round 20, #5).
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(100);
    let mut sink = [0u8; 16 * 1024];
    while std::time::Instant::now() < deadline {
        match stream.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

/// Write every byte of `bytes` before `deadline`.
///
/// A per-syscall timeout bounds one `write`, so a peer that reads one byte
/// just inside it keeps making progress forever. The timeout is re-armed from
/// the time left before each write, which is what makes the connection budget
/// a budget for the write side too (round 25, #2).
fn write_all_before(
    stream: &mut TcpStream,
    bytes: &[u8],
    deadline: std::time::Instant,
) -> Result<()> {
    // A refusal owed at the deadline still gets a short grace to reach the
    // peer; the grace is a hard stop, so a drip-reader cannot extend it.
    let hard = deadline + std::time::Duration::from_millis(250);
    let mut written = 0usize;
    while written < bytes.len() {
        let now = std::time::Instant::now();
        if now >= hard {
            return Err(Error::Transport("write timed out".to_string()));
        }
        let left = hard.saturating_duration_since(now);
        stream
            .set_write_timeout(Some(left.max(std::time::Duration::from_millis(1))))
            .map_err(|error| Error::Transport(error.to_string()))?;
        match stream.write(&bytes[written..]) {
            Ok(0) => return Err(Error::Transport("write made no progress".to_string())),
            Ok(count) => written += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Error::Transport(error.to_string())),
        }
    }
    Ok(())
}

fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    body: &[u8],
    deadline: std::time::Instant,
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        _ => "Internal Server Error",
    };
    let allow = if status == 405 { "allow: POST\r\n" } else { "" };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: {CONNECT_TYPE}\r\n{allow}content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    write_all_before(stream, head.as_bytes(), deadline)
        .and_then(|()| write_all_before(stream, body, deadline))
        .and_then(|()| {
            stream
                .flush()
                .map_err(|error| Error::Transport(error.to_string()))
        })
}

/// Time left before `deadline`, or a transport timeout.
fn remaining(deadline: std::time::Instant) -> Result<std::time::Duration> {
    deadline
        .checked_duration_since(std::time::Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| Error::Transport("deadline elapsed".to_string()))
}

/// Resolve `address` within the time left before `deadline`.
///
/// `to_socket_addrs` calls the system resolver, which has no timeout of its
/// own; a resolver that never answers would hold a `with_deadline` client past
/// its deadline (round 23, #3). The lookup runs on a detached thread: a hung
/// resolver leaks that thread, while the call returns its transport refusal.
fn resolve_within(
    address: &str,
    deadline: std::time::Instant,
) -> Result<Vec<std::net::SocketAddr>> {
    use std::net::ToSocketAddrs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    // A resolver that never returns would otherwise leave one parked thread
    // per call; the process keeps at most this many, and a refused call is a
    // transport fault rather than an unbounded leak (round 24, F5).
    const MAX_LIVE_RESOLVERS: usize = 64;
    static LIVE_RESOLVERS: AtomicUsize = AtomicUsize::new(0);
    // An already-spent budget must not spawn anything.
    let left = remaining(deadline)?;
    // A compare-exchange loop, like the body budgets: increment-then-rollback
    // refused a caller while two others were merely arriving and leaving
    // (round 9, R-09 #10).
    let mut live = LIVE_RESOLVERS.load(Ordering::SeqCst);
    loop {
        if live >= MAX_LIVE_RESOLVERS {
            return Err(Error::Transport("resolver busy".to_string()));
        }
        match LIVE_RESOLVERS.compare_exchange(live, live + 1, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => break,
            Err(actual) => live = actual,
        }
    }
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let target = address.to_string();
    let spawned = std::thread::Builder::new()
        .name("active-rpc-resolve".to_string())
        .spawn(move || {
            let result = target
                .to_socket_addrs()
                .map(|addresses| addresses.collect::<Vec<_>>());
            let _ = sender.send(result);
            LIVE_RESOLVERS.fetch_sub(1, Ordering::SeqCst);
        });
    if let Err(error) = spawned {
        LIVE_RESOLVERS.fetch_sub(1, Ordering::SeqCst);
        return Err(Error::Transport(format!("resolve thread: {error}")));
    }
    match receiver.recv_timeout(left) {
        Ok(Ok(addresses)) => Ok(addresses),
        Ok(Err(error)) => Err(Error::Transport(format!("resolve: {error}"))),
        Err(_) => Err(Error::Transport("resolve timed out".to_string())),
    }
}

/// A Connect/gRPC bridge client.
pub struct ConnectClient {
    address: String,
    limits: WireLimits,
    /// Wall deadline for one request, when the caller sets one.
    deadline: Option<std::time::Duration>,
    /// Addresses from the first successful lookup, so a long-lived client
    /// resolves once (round 24, F5).
    resolved: Option<Vec<std::net::SocketAddr>>,
}

impl ConnectClient {
    /// Connect to a bridge.
    pub fn connect(address: &str) -> Result<Self> {
        // The bridge answers with `connection: close`, so the client dials per
        // request. A pooled variant would negotiate keep-alive instead.
        Ok(Self {
            address: address.to_string(),
            limits: WireLimits::default(),
            deadline: None,
            resolved: None,
        })
    }

    /// Use tighter limits.
    pub fn with_limits(mut self, limits: WireLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Bound one request in wall time.
    ///
    /// The client dials per request and both the connect and the read can block
    /// forever against a peer that accepts and says nothing.
    pub fn with_deadline(mut self, deadline: std::time::Duration) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Call the bridge with one envelope.
    pub fn call(&mut self, envelope: &Envelope) -> Result<Envelope> {
        let body = envelope.encode()?;
        if body.len() > MAX_BODY.min(self.limits.max_bytes) {
            // The frame boundary refuses this body; framing it first would hit
            // the release invariant as a panic (round 27, medium).
            return Err(Error::Wire("request exceeds the ceiling"));
        }
        let framed = grpc_frame(&body)?;
        let (status, response) = self.post(&framed, CONNECT_TYPE)?;
        if status != 200 {
            // The body is peer text; `refusal` keeps a short stable token and
            // refuses to carry the rest.
            return Err(crate::transport::refusal(&response));
        }
        let (message, rest) = grpc_unframe(&response)?;
        if !rest.is_empty() {
            return Err(Error::Wire("trailing bytes in bridge response"));
        }
        let answer = Envelope::decode_with(message, self.limits)?;
        // A bridge that mixes responses, replays one or echoes a request must
        // not have it accepted as this call's answer (round 28, low).
        if !matches!(
            answer.kind,
            crate::wire::Kind::Response | crate::wire::Kind::Error
        ) || answer.request_id != envelope.request_id
        {
            return Err(Error::Wire("the bridge answered a different request"));
        }
        Ok(answer)
    }

    /// Send a raw body (used to prove malformed frames are rejected).
    pub fn post_raw(&mut self, body: &[u8]) -> Result<(u16, Vec<u8>)> {
        self.post(body, CONNECT_TYPE)
    }

    /// Send a body with an explicit content type.
    pub fn post_typed(&mut self, body: &[u8], content_type: &str) -> Result<(u16, Vec<u8>)> {
        self.post(body, content_type)
    }

    fn post(&mut self, body: &[u8], content_type: &str) -> Result<(u16, Vec<u8>)> {
        if content_type.is_empty()
            || !content_type
                .bytes()
                .all(|byte| (0x21..=0x7e).contains(&byte))
        {
            // The value is interpolated into the head: a CR or LF would inject
            // a header (round 27, low).
            return Err(Error::Wire("invalid content type"));
        }
        // `body` is the framed message; the ceiling names the envelope, so
        // the 5-byte prefix is allowed on top (round 29, low).
        if body.len() > MAX_BODY.min(self.limits.max_bytes).saturating_add(5) {
            // Framing a body the bridge can only refuse wastes the write and
            // could wrap the 32-bit frame length (round 25, #5).
            return Err(Error::Wire("request exceeds the ceiling"));
        }
        let head = format!(
            "POST {PATH} HTTP/1.1\r\nhost: active-rpc\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        // A black-hole peer must not hold a `with_deadline` client: the
        // connect itself is bounded (round 22, #3), and so is the resolve that
        // precedes it (round 23, #3).
        let wait = self.deadline.unwrap_or(CONNECTION_WAIT);
        let deadline = std::time::Instant::now()
            .checked_add(wait)
            .unwrap_or_else(std::time::Instant::now);
        let addresses = match &self.resolved {
            Some(addresses) => addresses.clone(),
            None => {
                let addresses = resolve_within(&self.address, deadline)?;
                self.resolved = Some(addresses.clone());
                addresses
            }
        };
        if addresses.is_empty() {
            return Err(Error::Transport("no address".to_string()));
        }
        // Every address, not only the first: a resolver may list `::1` ahead of
        // `127.0.0.1`, and a single-address cache made that failure permanent
        // (round 30, L-9).
        let mut connected = None;
        let mut last = None;
        for address in &addresses {
            match TcpStream::connect_timeout(address, remaining(deadline)?) {
                Ok(stream) => {
                    connected = Some(stream);
                    break;
                }
                Err(error) => last = Some(error),
            }
        }
        let mut stream = match connected {
            Some(stream) => stream,
            None => {
                // The cache may describe a peer that moved; resolve next time.
                self.resolved = None;
                match last {
                    Some(error) => return Err(Error::Transport(format!("connect: {error}"))),
                    None => return Err(Error::Transport("no address".to_string())),
                }
            }
        };
        // A client with no explicit deadline still has one: a peer that drips a
        // byte per timeout would hold it forever, and `read_head` was called
        // with `None` (round 21, #2).
        stream
            .set_read_timeout(Some(wait))
            .and_then(|()| stream.set_write_timeout(Some(wait)))
            .map_err(|error| Error::Transport(error.to_string()))?;
        write_all_before(&mut stream, head.as_bytes(), deadline)?;
        write_all_before(&mut stream, body, deadline)?;
        stream
            .flush()
            .map_err(|error| Error::Transport(error.to_string()))?;
        // Half-close: a body that stops short of its declared frame lets the
        // server see EOF and answer instead of waiting for bytes that will
        // never come (the client sends exactly `content-length`).
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut reader = BufReader::new(stream);
        let Some(head) = read_head(&mut reader, MAX_HEAD, Some(deadline), false)? else {
            return Err(Error::Transport(
                "bridge closed without a response".to_string(),
            ));
        };
        let status: u16 = head
            .first()
            .and_then(|line| line.split_whitespace().nth(1))
            // `u16::from_str` accepts `+200` and `0200`; RFC 9112 defines three
            // digits, and a lenient parse lets an intermediary's non-status be
            // read as success (round 24, F7).
            .filter(|code| code.len() == 3 && code.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|code| code.parse().ok())
            .ok_or(Error::Wire("malformed status line"))?;
        // The server refuses `+25`, a duplicate length and a
        // `transfer-encoding`; the client applies the same rules so an
        // intermediary cannot desync the two (round 22, #4).
        let mut lengths: Vec<usize> = Vec::new();
        for (index, line) in head.iter().enumerate() {
            if index == 0 {
                continue;
            }
            // The server refuses an unparsable or untokenized field; a client
            // that skipped it saw a different message (round 26, #3).
            let Some((name, value)) = line.split_once(':') else {
                return Err(Error::Wire("malformed response head line"));
            };
            if name.is_empty() || !name.bytes().all(crate::tool::is_http_token) {
                return Err(Error::Wire("malformed response field name"));
            }
            if name.eq_ignore_ascii_case("transfer-encoding") {
                return Err(Error::Wire("transfer-encoding is not accepted"));
            }
            if name.eq_ignore_ascii_case("content-length") {
                let trimmed = value.trim();
                if trimmed.is_empty()
                    || trimmed.len() > 20
                    || !trimmed.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(Error::Wire("malformed response length"));
                }
                lengths.push(
                    trimmed
                        .parse()
                        .map_err(|_| Error::Wire("malformed response length"))?,
                );
            }
        }
        let length = match lengths.as_slice() {
            [length] => *length,
            [] => return Err(Error::Wire("missing response length")),
            _ => return Err(Error::Wire("repeated response length")),
        };
        if length > MAX_BODY.min(self.limits.max_bytes).saturating_add(5) {
            return Err(Error::Wire("response exceeds the ceiling"));
        }
        // Grow with the bytes that actually arrive: a hostile server that
        // announces 64 MiB and sends ten bytes must not cost a 64 MiB
        // allocation. `take` stops at the declared length.
        let mut response = Vec::with_capacity(length.min(64 * 1024));
        let mut chunk = [0u8; 8 * 1024];
        while response.len() < length {
            let left = deadline
                .checked_duration_since(std::time::Instant::now())
                .ok_or_else(|| Error::Transport("response body timed out".to_string()))?;
            reader
                .get_ref()
                .set_read_timeout(Some(left))
                .map_err(|error| Error::Transport(format!("response: {error}")))?;
            let want = (length - response.len()).min(chunk.len());
            let read = std::io::Read::read(&mut reader, &mut chunk[..want])
                .map_err(|error| Error::Transport(format!("response: {error}")))?;
            if read == 0 {
                break;
            }
            response.extend_from_slice(&chunk[..read]);
        }
        if response.len() != length {
            return Err(Error::Transport(
                "response body is shorter than declared".to_string(),
            ));
        }
        Ok((status, response))
    }
}
