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

use std::io::{BufRead, BufReader, Read, Write};
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
pub fn grpc_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
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

/// Read exactly `length` bytes before `deadline`.
///
/// A drip that stays inside a per-read timeout is still bounded by the
/// connection deadline; the timeout is recomputed from the remaining time before
/// every read.
fn read_body_by_deadline(
    reader: &mut BufReader<TcpStream>,
    stream: &TcpStream,
    length: usize,
    deadline: std::time::Instant,
    body: &mut Vec<u8>,
) -> bool {
    use std::io::Read;
    let mut chunk = [0u8; 16 * 1024];
    while body.len() < length {
        if !arm_deadline(stream, deadline) {
            return false;
        }
        let want = (length - body.len()).min(chunk.len());
        match reader.read(&mut chunk[..want]) {
            Ok(0) => return false,
            Ok(read) => body.extend_from_slice(&chunk[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return false,
        }
    }
    body.len() == length
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
        for _ in 0..requests {
            let (stream, _) = match self.listener.accept() {
                Ok(accepted) => {
                    failures = 0;
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
            let _ = write_http_response(&mut stream, 408, b"rpc/transport");
            return 0;
        }
        let head = match read_head(&mut reader, MAX_HEAD, Some((&stream, deadline))) {
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
                let _ = write_http_response(&mut stream, status, body);
                return 0;
            }
        };
        let request_line = head.first().cloned().unwrap_or_default();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default();
        let target = parts.next().unwrap_or_default();
        if method != "POST" || target != PATH {
            let _ = write_http_response(&mut stream, 404, b"rpc/not-found");
            return 0;
        }
        // Content-Length must be unambiguous and Transfer-Encoding absent: a
        // front proxy that resolves a conflict differently would let a second
        // request ride in front of this one.
        let mut lengths: Vec<usize> = Vec::new();
        let mut transfer_encoding = false;
        for line in &head {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
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
                    let _ = write_http_response(&mut stream, 400, b"rpc/wire");
                    return 0;
                }
                match trimmed.parse::<usize>() {
                    Ok(length) => lengths.push(length),
                    Err(_) => {
                        let _ = write_http_response(&mut stream, 400, b"rpc/wire");
                        return 0;
                    }
                }
            }
        }
        if transfer_encoding || lengths.len() != 1 {
            let _ = write_http_response(&mut stream, 400, b"rpc/wire");
            return 0;
        }
        let content_length = lengths[0];
        // The body ceiling is the wire limit, not only the protocol maximum: a
        // strict server must not read 64 MiB to discover it refuses the frame.
        let body_ceiling = MAX_BODY.min(self.limits.max_bytes);
        if content_length > body_ceiling {
            let _ = write_http_response(&mut stream, 413, b"rpc/wire");
            return 0;
        }
        let content_type = head
            .iter()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-type") {
                    Some(value.trim().to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();
        if content_type != CONNECT_TYPE && content_type != GRPC_TYPE {
            let _ = write_http_response(&mut stream, 415, b"rpc/wire");
            return 0;
        }
        let mut body = Vec::with_capacity(content_length.min(64 * 1024));
        let complete =
            read_body_by_deadline(&mut reader, &stream, content_length, deadline, &mut body);
        if !complete {
            // A truncated body is one bad connection, not a server failure:
            // answer 400 for it and keep accepting the next one. Growing the
            // buffer with the bytes that arrive means a header that announces
            // 64 MiB and sends ten bytes costs 64 KiB, not 64 MiB.
            let _ = write_http_response(&mut stream, 400, b"rpc/wire");
            return 0;
        }
        let (message, rest) = match grpc_unframe(&body) {
            Ok(parts) => parts,
            Err(error) => {
                let _ = write_http_response(&mut stream, 400, error.code().as_bytes());
                return 0;
            }
        };
        if !rest.is_empty() {
            let _ = write_http_response(&mut stream, 400, b"rpc/wire");
            return 0;
        }
        let envelope = match Envelope::decode_with(message, self.limits) {
            Ok(envelope) => envelope,
            Err(error) => {
                let _ = write_http_response(&mut stream, 400, error.code().as_bytes());
                return 0;
            }
        };
        // A response or error envelope is not a call. Refusing it here keeps the
        // kind contract at the transport boundary, where a relay would otherwise
        // be able to smuggle one in.
        if envelope.kind != crate::wire::Kind::Request {
            let _ = write_http_response(&mut stream, 400, b"rpc/wire");
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
                let _ = write_http_response(&mut stream, 500, error.code().as_bytes());
                return 0;
            }
        };
        let framed = grpc_frame(&bytes);
        let _ = write_http_response(&mut stream, 200, &framed);
        1
    }
}

/// Read one head line under the remaining budget.
///
/// `read_line` into a `String` grows until the peer sends a newline, so the
/// ceiling was only checked after the allocation. This reads bytes into a
/// fixed buffer bounded by what is left of the budget, and a line that does not
/// fit is refused without growing. Bytes are decoded lossily: a header value is
/// not required to be UTF-8, and a non-UTF-8 byte must not be able to end the
/// server.
fn read_head<R: BufRead>(
    reader: &mut R,
    max: usize,
    guard: Option<(&TcpStream, std::time::Instant)>,
) -> Result<Option<Vec<String>>> {
    let mut head = Vec::new();
    let mut total = 0usize;
    loop {
        // The socket timeout is per read; a head that dribbles one byte just
        // inside it would hold the serial accept slot for hours. Re-arm the
        // connection deadline before every line.
        if let Some((stream, deadline)) = guard {
            if !arm_deadline(stream, deadline) {
                return Err(Error::Transport("request head timed out".to_string()));
            }
        }
        let remaining = max.saturating_sub(total);
        let mut raw = Vec::new();
        let read = reader
            .by_ref()
            .take(remaining as u64 + 1)
            .read_until(b'\n', &mut raw)
            .map_err(|error| Error::Transport(format!("head: {error}")))?;
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
        head.push(String::from_utf8_lossy(body).into_owned());
    }
    Ok(Some(head))
}

fn write_http_response(stream: &mut TcpStream, status: u16, body: &[u8]) -> Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        _ => "Internal Server Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: {CONNECT_TYPE}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|_| stream.write_all(body))
        .and_then(|_| stream.flush())
        .map_err(|error| Error::Transport(error.to_string()))
}

/// A Connect/gRPC bridge client.
pub struct ConnectClient {
    address: String,
    limits: WireLimits,
    /// Wall deadline for one request, when the caller sets one.
    deadline: Option<std::time::Duration>,
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
        let framed = grpc_frame(&body);
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
        Envelope::decode_with(message, self.limits)
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
        let head = format!(
            "POST {PATH} HTTP/1.1\r\nhost: active-rpc\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        let mut stream = TcpStream::connect(&self.address)
            .map_err(|error| Error::Transport(format!("connect: {error}")))?;
        if let Some(deadline) = self.deadline {
            stream
                .set_read_timeout(Some(deadline))
                .and_then(|()| stream.set_write_timeout(Some(deadline)))
                .map_err(|error| Error::Transport(error.to_string()))?;
        }
        stream
            .write_all(head.as_bytes())
            .and_then(|_| stream.write_all(body))
            .and_then(|_| stream.flush())
            .map_err(|error| Error::Transport(error.to_string()))?;
        let mut reader = BufReader::new(stream);
        let Some(head) = read_head(&mut reader, MAX_HEAD, None)? else {
            return Err(Error::Transport(
                "bridge closed without a response".to_string(),
            ));
        };
        let status: u16 = head
            .first()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .ok_or(Error::Wire("malformed status line"))?;
        let length: usize = head
            .iter()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse().ok()
                } else {
                    None
                }
            })
            .ok_or(Error::Wire("missing response length"))?;
        if length > MAX_BODY {
            return Err(Error::Wire("response exceeds the ceiling"));
        }
        // Grow with the bytes that actually arrive: a hostile server that
        // announces 64 MiB and sends ten bytes must not cost a 64 MiB
        // allocation. `take` stops at the declared length.
        let mut response = Vec::with_capacity(length.min(64 * 1024));
        let read = reader
            .by_ref()
            .take(length as u64)
            .read_to_end(&mut response)
            .map_err(|error| Error::Transport(format!("response: {error}")))?;
        if read != length {
            return Err(Error::Transport(
                "response body is shorter than declared".to_string(),
            ));
        }
        Ok((status, response))
    }
}
