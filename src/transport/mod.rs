//! Transports.
//!
//! A transport moves [`Envelope`]s. The kernel is independent of it, so the same
//! capability and promise semantics hold whether a call stays in the process,
//! crosses a shared-memory segment, goes over QUIC, or is bridged to a
//! gRPC/Connect client.
//!
//! | Transport | Module | Property |
//! |-----------|--------|----------|
//! | in-process | this module | no serialization: envelopes move by value |
//! | TCP | this module | length-prefixed envelopes, cross-process |
//! | shared memory | [`shm`] | length-prefixed frames in a ring, borrowed in place |
//! | QUIC | [`quic`] | real QUIC over loopback (feature `quic`) |
//! | Connect/gRPC bridge | [`connect`] | HTTP/1.1 Connect + gRPC message framing |
//!
//! Every transport rejects a malformed frame with a stable error instead of
//! panicking, and every transport carries the capability table in the same
//! envelope shape.

use std::collections::VecDeque;
use std::io::{BufReader, IoSlice, Read, Write};
use std::net::{TcpListener, TcpStream};

use crate::error::{Error, Result};
use crate::wire::{Envelope, Kind, WireLimits};

pub mod connect;
#[cfg(feature = "http2")]
pub mod http2;
#[cfg(feature = "quic")]
pub mod quic;
pub mod shm;

/// Largest frame a byte-oriented transport accepts.
pub const MAX_FRAME_BYTES: usize = 64 << 20;

/// Longest peer error body copied into an [`Error`].
///
/// The body is peer text: only a stable `rpc/...` token is meaningful, and an
/// error must not carry a megabyte of the peer's prose.
pub const MAX_ERROR_BODY: usize = 64;

/// Map a peer's refusal body to the matching error.
///
/// A frame rejection is a wire fault; every other refusal keeps its class in
/// [`Error::provider_code`] instead of being flattened into free text. Anything
/// that is not a short `rpc/...` token becomes `rpc/provider`.
pub(crate) fn refusal(body: &[u8]) -> Error {
    let text = std::str::from_utf8(&body[..body.len().min(MAX_ERROR_BODY)])
        .unwrap_or("rpc/provider")
        .trim();
    if text == "rpc/wire" {
        return Error::Wire("the peer rejected the frame");
    }
    let code = if text.starts_with("rpc/")
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'/' | b'-' | b'_'))
    {
        text.to_string()
    } else {
        "rpc/provider".to_string()
    };
    Error::Provider { code }
}

/// A bidirectional envelope pipe.
pub trait Transport {
    /// Stable transport name.
    fn name(&self) -> &'static str;

    /// Send one envelope.
    fn send(&mut self, envelope: &Envelope) -> Result<()>;

    /// Receive one envelope, if one is available.
    fn recv(&mut self) -> Result<Option<Envelope>>;

    /// Bytes written on the wire so far (zero for in-process transports).
    fn bytes_written(&self) -> u64 {
        0
    }
}

// ---------------------------------------------------------------------------
// In-process
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Mailboxes {
    a_to_b: VecDeque<Envelope>,
    b_to_a: VecDeque<Envelope>,
}

/// An in-process link: envelopes move by value, nothing is encoded.
///
/// The kernel sees the same `Envelope` type either way, so switching a peer from
/// in-process to TCP changes the transport and nothing else.
#[derive(Clone, Default)]
pub struct InProcessTransport {
    shared: Option<std::rc::Rc<std::cell::RefCell<Mailboxes>>>,
    /// True on the endpoint that owns the `a` side.
    is_a: bool,
    /// Envelopes pushed into this endpoint directly (single-ended mode).
    local: VecDeque<Envelope>,
}

impl std::fmt::Debug for InProcessTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InProcessTransport")
            .field("paired", &self.shared.is_some())
            .finish()
    }
}

impl InProcessTransport {
    /// A pipe pair. Sending on one end is receiving on the other.
    pub fn pair() -> (InProcessTransport, InProcessTransport) {
        let shared = std::rc::Rc::new(std::cell::RefCell::new(Mailboxes::default()));
        (
            InProcessTransport {
                shared: Some(std::rc::Rc::clone(&shared)),
                is_a: true,
                local: VecDeque::new(),
            },
            InProcessTransport {
                shared: Some(shared),
                is_a: false,
                local: VecDeque::new(),
            },
        )
    }

    /// A single-ended queue: `send` feeds `recv` on the same endpoint.
    pub fn queue() -> InProcessTransport {
        InProcessTransport::default()
    }
}

impl Transport for InProcessTransport {
    fn name(&self) -> &'static str {
        "in-process"
    }

    fn send(&mut self, envelope: &Envelope) -> Result<()> {
        // No serialization: the envelope is cloned in memory. A real in-process
        // link hands ownership to the peer task; the observable property is
        // that no bytes are produced.
        match &self.shared {
            Some(shared) => {
                let mut shared = shared.borrow_mut();
                if self.is_a {
                    shared.a_to_b.push_back(envelope.clone());
                } else {
                    shared.b_to_a.push_back(envelope.clone());
                }
            }
            None => self.local.push_back(envelope.clone()),
        }
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Envelope>> {
        match &self.shared {
            Some(shared) => {
                let mut shared = shared.borrow_mut();
                Ok(if self.is_a {
                    shared.b_to_a.pop_front()
                } else {
                    shared.a_to_b.pop_front()
                })
            }
            None => Ok(self.local.pop_front()),
        }
    }

    fn bytes_written(&self) -> u64 {
        0
    }
}

// ---------------------------------------------------------------------------
// TCP (cross-process)
// ---------------------------------------------------------------------------

/// A length-prefixed envelope channel over a TCP connection.
///
/// Reads go through an 8 KiB buffer: a header read and the body read that
/// follows it are served from the same `recv`, so one envelope costs one receive
/// syscall instead of two. Writes are a single vectored call for the header and
/// the body.
#[derive(Debug)]
pub struct TcpTransport {
    stream: BufReader<TcpStream>,
    inbox: VecDeque<Envelope>,
    written: u64,
    limits: WireLimits,
    /// Set when a write failed after it may have put bytes on the wire. Every
    /// later send would append a header to a half-written body, so the
    /// connection is unusable.
    poisoned: bool,
}

/// Receive buffer for one connection.
const TCP_READ_BUFFER: usize = 8 << 10;

impl TcpTransport {
    /// Wrap an established stream.
    pub fn new(stream: TcpStream) -> Result<Self> {
        stream
            .set_nodelay(true)
            .map_err(|error| Error::Transport(error.to_string()))?;
        Ok(Self {
            stream: BufReader::with_capacity(TCP_READ_BUFFER, stream),
            inbox: VecDeque::new(),
            written: 0,
            limits: WireLimits::default(),
            poisoned: false,
        })
    }

    /// Use tighter wire limits (server side of an untrusted connection).
    pub fn with_limits(mut self, limits: WireLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Connect to a peer.
    pub fn connect(address: &str) -> Result<Self> {
        let stream = TcpStream::connect(address)
            .map_err(|error| Error::Transport(format!("connect: {error}")))?;
        Self::new(stream)
    }
}

impl Transport for TcpTransport {
    fn name(&self) -> &'static str {
        "tcp"
    }

    fn send(&mut self, envelope: &Envelope) -> Result<()> {
        if self.poisoned {
            return Err(Error::Transport(
                "the connection is poisoned by a partial frame".to_string(),
            ));
        }
        let bytes = envelope.encode()?;
        if let Err(error) = write_frame(self.stream.get_mut(), &bytes) {
            // The header or the body (or part of either) may be on the wire, so
            // the peer's read position no longer matches a frame boundary.
            self.poisoned = true;
            return Err(error);
        }
        self.written += (bytes.len() + 4) as u64;
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Envelope>> {
        if self.poisoned {
            return Err(Error::Transport(
                "the connection is poisoned by a partial frame".to_string(),
            ));
        }
        if let Some(envelope) = self.inbox.pop_front() {
            return Ok(Some(envelope));
        }
        let Some(body) = read_frame(&mut self.stream, &self.limits)? else {
            return Ok(None);
        };
        Ok(Some(Envelope::decode_with(&body, self.limits)?))
    }

    fn bytes_written(&self) -> u64 {
        self.written
    }
}

/// Encode a frame length.
pub fn frame(len: usize) -> Result<[u8; 4]> {
    if len > MAX_FRAME_BYTES {
        return Err(Error::Wire("frame exceeds the transport ceiling"));
    }
    Ok((len as u32).to_le_bytes())
}

/// Serve one connection: read envelopes and answer each with `handler`.
///
/// A frame error or a broken socket ends *this* connection, not the server: the
/// reply carries the stable code and the call returns the count served so far.
/// A caller that is serving many connections keeps accepting.
pub fn serve_connection<H>(mut transport: TcpTransport, mut handler: H) -> Result<u64>
where
    H: FnMut(Envelope) -> Envelope,
{
    let mut served = 0u64;
    loop {
        match transport.recv() {
            Ok(Some(envelope)) => {
                // A response or error envelope is not a call. Refusing it at the
                // frame boundary keeps a relay from forwarding one as a request.
                if envelope.kind != Kind::Request {
                    let reply = Envelope::error(
                        envelope.request_id,
                        &Error::Wire("a server only serves requests"),
                    );
                    let _ = transport.send(&reply);
                    return Ok(served);
                }
                let response = handler(envelope);
                if transport.send(&response).is_err() {
                    // The peer is gone; the connection is over, the server is
                    // not.
                    return Ok(served);
                }
                served += 1;
            }
            Ok(None) => return Ok(served),
            Err(error) => {
                let reply = Envelope::error(0, &error);
                let _ = transport.send(&reply);
                return Ok(served);
            }
        }
    }
}

/// Bind a loopback listener on an ephemeral port.
pub fn bind_loopback() -> Result<(TcpListener, String)> {
    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|error| Error::Transport(error.to_string()))?;
    let address = listener
        .local_addr()
        .map_err(|error| Error::Transport(error.to_string()))?
        .to_string();
    Ok((listener, address))
}

/// Read one exact frame from a generic reader.
///
/// A partial header or body is a transport error, never a clean close: a cut
/// frame means the peer desynchronized, and treating it as EOF would let a
/// truncated message pass for an empty one. Nothing is reserved before it
/// arrives: a four-byte header must not allocate the ceiling while the peer is
/// free to send nothing.
pub fn read_frame<R: Read>(reader: &mut R, limits: &WireLimits) -> Result<Option<Vec<u8>>> {
    let mut header = [0u8; 4];
    let mut filled = 0usize;
    while filled < header.len() {
        match reader.read(&mut header[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => {
                return Err(Error::Transport(
                    "truncated frame header at end of stream".to_string(),
                ))
            }
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Error::Transport(error.to_string())),
        }
    }
    let len = u32::from_le_bytes(header) as usize;
    // `MAX_FRAME_BYTES` is the transport ceiling; a tighter `WireLimits` wins.
    let ceiling = limits.max_bytes.min(MAX_FRAME_BYTES);
    if len > ceiling {
        return Err(Error::Wire("frame exceeds the size ceiling"));
    }
    let mut body = Vec::with_capacity(len.min(64 << 10));
    reader
        .by_ref()
        .take(len as u64)
        .read_to_end(&mut body)
        .map_err(|error| Error::Transport(error.to_string()))?;
    if body.len() != len {
        return Err(Error::Transport(
            "truncated frame body at end of stream".to_string(),
        ));
    }
    Ok(Some(body))
}

/// Write one exact frame to a generic writer.
///
/// Header and body travel in one vectored write, so a TCP frame costs one send
/// syscall. `IoSlice::advance_slices` handles a short write; a zero write is an
/// error rather than a spin.
pub fn write_frame<W: Write>(writer: &mut W, body: &[u8]) -> Result<()> {
    let header = frame(body.len())?;
    let mut slices: [IoSlice<'_>; 2] = [IoSlice::new(&header), IoSlice::new(body)];
    let mut bufs: &mut [IoSlice<'_>] = &mut slices;
    while !bufs.is_empty() {
        match writer.write_vectored(bufs) {
            Ok(0) => return Err(Error::Transport("write returned zero bytes".to_string())),
            Ok(written) => IoSlice::advance_slices(&mut bufs, written),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Error::Transport(error.to_string())),
        }
    }
    writer
        .flush()
        .map_err(|error| Error::Transport(error.to_string()))
}
