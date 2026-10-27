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
            served += self.handle(stream, &mut handler)?;
        }
        Ok(served)
    }

    fn handle<H>(&self, mut stream: TcpStream, handler: &mut H) -> Result<u64>
    where
        H: FnMut(Envelope) -> Envelope,
    {
        stream
            .set_nodelay(true)
            .map_err(|error| Error::Transport(error.to_string()))?;
        let mut reader = BufReader::new(
            stream
                .try_clone()
                .map_err(|error| Error::Transport(error.to_string()))?,
        );
        let Some(head) = read_head(&mut reader, MAX_HEAD)? else {
            return Ok(0);
        };
        let request_line = head.first().cloned().unwrap_or_default();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default();
        let target = parts.next().unwrap_or_default();
        if method != "POST" || target != PATH {
            write_http_response(&mut stream, 404, b"rpc/not-found")?;
            return Ok(0);
        }
        let Some(content_length) = head.iter().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        }) else {
            // A malformed request is a 400 for that connection, not a server
            // failure: `serve` must keep accepting.
            write_http_response(&mut stream, 400, b"rpc/wire")?;
            return Ok(1);
        };
        if content_length > MAX_BODY {
            write_http_response(&mut stream, 413, b"rpc/wire")?;
            return Ok(0);
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
            write_http_response(&mut stream, 415, b"rpc/wire")?;
            return Ok(0);
        }
        let mut body = vec![0u8; content_length];
        if let Err(error) = reader.read_exact(&mut body) {
            let _ = write_http_response(&mut stream, 400, b"rpc/wire");
            return Err(Error::Transport(format!("body: {error}")));
        }
        let (message, rest) = match grpc_unframe(&body) {
            Ok(parts) => parts,
            Err(error) => {
                write_http_response(&mut stream, 400, error.code().as_bytes())?;
                return Ok(1);
            }
        };
        if !rest.is_empty() {
            write_http_response(&mut stream, 400, b"rpc/wire")?;
            return Ok(1);
        }
        let envelope = match Envelope::decode_with(message, self.limits) {
            Ok(envelope) => envelope,
            Err(error) => {
                write_http_response(&mut stream, 400, error.code().as_bytes())?;
                return Ok(1);
            }
        };
        let response = handler(envelope);
        let bytes = match response.encode() {
            Ok(bytes) => bytes,
            Err(error) => {
                write_http_response(&mut stream, 500, error.code().as_bytes())?;
                return Ok(1);
            }
        };
        let framed = grpc_frame(&bytes);
        write_http_response(&mut stream, 200, &framed)?;
        Ok(1)
    }
}

fn read_head<R: BufRead>(reader: &mut R, max: usize) -> Result<Option<Vec<String>>> {
    let mut head = Vec::new();
    let mut total = 0usize;
    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
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
        let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
        if trimmed.is_empty() {
            break;
        }
        head.push(trimmed);
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
            let code = String::from_utf8_lossy(&response).trim().to_string();
            return Err(match code.as_str() {
                "rpc/wire" => Error::Wire("bridge rejected the frame"),
                other => Error::Provider {
                    code: other.to_string(),
                },
            });
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
        let mut response = vec![0u8; length];
        reader
            .read_exact(&mut response)
            .map_err(|error| Error::Transport(format!("response: {error}")))?;
        Ok((status, response))
    }
}
