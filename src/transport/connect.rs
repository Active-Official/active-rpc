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
        for _ in 0..requests {
            let (stream, _) = self
                .listener
                .accept()
                .map_err(|error| Error::Transport(format!("accept: {error}")))?;
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
        // A stalled peer is bounded, not fatal: the next connection waits at
        // most this long rather than forever.
        let _ = stream.set_read_timeout(Some(CONNECTION_WAIT));
        let _ = stream.set_write_timeout(Some(CONNECTION_WAIT));
        let Ok(clone) = stream.try_clone() else {
            return 0;
        };
        let mut reader = BufReader::new(clone);
        let head = match read_head(&mut reader, MAX_HEAD) {
            Ok(Some(head)) => head,
            Ok(None) => return 0,
            Err(_) => {
                let _ = write_http_response(&mut stream, 400, b"rpc/wire");
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
                match value.trim().parse::<usize>() {
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
        if content_length > MAX_BODY {
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
        let read = reader
            .by_ref()
            .take(content_length as u64)
            .read_to_end(&mut body);
        if read.is_err() || body.len() != content_length {
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
        let response = handler(envelope);
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
fn read_head<R: BufRead>(reader: &mut R, max: usize) -> Result<Option<Vec<String>>> {
    let mut head = Vec::new();
    let mut total = 0usize;
    loop {
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
            break;
        }
        total += read;
        if total > max {
            return Err(Error::Wire("request head exceeds the ceiling"));
        }
        let line = String::from_utf8_lossy(&raw);
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        head.push(trimmed.to_string());
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
}

impl ConnectClient {
    /// Connect to a bridge.
    pub fn connect(address: &str) -> Result<Self> {
        // The bridge answers with `connection: close`, so the client dials per
        // request. A pooled variant would negotiate keep-alive instead.
        Ok(Self {
            address: address.to_string(),
            limits: WireLimits::default(),
        })
    }

    /// Use tighter limits.
    pub fn with_limits(mut self, limits: WireLimits) -> Self {
        self.limits = limits;
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
        stream
            .write_all(head.as_bytes())
            .and_then(|_| stream.write_all(body))
            .and_then(|_| stream.flush())
            .map_err(|error| Error::Transport(error.to_string()))?;
        let mut reader = BufReader::new(stream);
        let Some(head) = read_head(&mut reader, MAX_HEAD)? else {
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
