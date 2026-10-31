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
//! | shared memory | [`shm`] | zero-copy frames inside one segment |
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
use crate::wire::{Envelope, WireLimits};

pub mod connect;
#[cfg(feature = "http2")]
pub mod http2;
#[cfg(feature = "quic")]
pub mod quic;
pub mod shm;

/// Largest frame a byte-oriented transport accepts.
pub const MAX_FRAME_BYTES: usize = 64 << 20;

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
        let bytes = envelope.encode()?;
        write_frame(self.stream.get_mut(), &bytes)?;
        self.written += (bytes.len() + 4) as u64;
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Envelope>> {
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
/// A malformed frame ends the connection with an error envelope instead of
/// crashing the server.
pub fn serve_connection<H>(mut transport: TcpTransport, mut handler: H) -> Result<u64>
where
    H: FnMut(Envelope) -> Envelope,
{
    let mut served = 0u64;
    loop {
        match transport.recv() {
            Ok(Some(envelope)) => {
                let response = handler(envelope);
                transport.send(&response)?;
                served += 1;
            }
            Ok(None) => return Ok(served),
            Err(error) => {
                let reply = Envelope::error(0, &error);
                let _ = transport.send(&reply);
                return Err(error);
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
pub fn read_frame<R: Read>(reader: &mut R, limits: &WireLimits) -> Result<Option<Vec<u8>>> {
    let mut header = [0u8; 4];
    match reader.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(Error::Transport(error.to_string())),
    }
    let len = u32::from_le_bytes(header) as usize;
    if len > limits.max_bytes {
        return Err(Error::Wire("frame exceeds the size ceiling"));
    }
    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .map_err(|error| Error::Transport(error.to_string()))?;
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
