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

/// Refusal classes a peer is allowed to choose.
///
/// Every other `rpc/…` token in the body becomes `rpc/provider`: a transport
/// may report a transport condition, not an authority decision.
/// `provider/reply-withheld` is here because a server decides it after its own
/// handler ran: it is a provider class, not an authority decision, and a client
/// that dropped it could never observe the contract (round 17, R16-4).
const PEER_REFUSAL_CLASSES: &[&str] = &[
    "rpc/transport",
    "rpc/backpressure",
    "rpc/provider",
    "provider/reply-withheld",
];

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
    // Only the classes a transport itself can decide. A peer that labels its
    // own refusal `rpc/revoked` or `rpc/identity` turned its HTTP body into a
    // kernel decision the kernel never made (round 9, R-09 #7).
    let code = if PEER_REFUSAL_CLASSES.contains(&text) {
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
    written: u64,
    limits: WireLimits,
    /// Set when a write failed after it may have put bytes on the wire. Every
    /// later send would append a header to a half-written body, so the
    /// connection is unusable.
    send_poisoned: bool,
    /// Set when a received frame was refused after its body was left unread.
    /// The inbound stream is no longer on a frame boundary, but the outbound
    /// half is independent: a server must still be able to send the error
    /// envelope that names the fault (round 10, R-09 #3).
    recv_poisoned: bool,
    /// Wall deadline for one received frame, set by `with_timeout`.
    frame_deadline: Option<std::time::Duration>,
}

/// Receive buffer for one connection.
const TCP_READ_BUFFER: usize = 8 << 10;

/// Default wall deadline for one frame on a connection that sets none.
///
/// The other transports have a bound; a bare `TcpTransport` used to have none,
/// so a peer that sent a byte just inside the socket timeout held a frame
/// forever (round 10, R-09 #2).
pub const DEFAULT_FRAME_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

impl TcpTransport {
    /// Wrap an established stream.
    pub fn new(stream: TcpStream) -> Result<Self> {
        stream
            .set_nodelay(true)
            .map_err(|error| Error::Transport(error.to_string()))?;
        // A default bound: a blocking `read` or `write_vectored` on a peer that
        // accepted and then went silent parked a serial server forever. The
        // other transports have a bound (bridge 2 s, QUIC 10 s, HTTP/2 60 s);
        // `with_timeout` still tightens this one (round 10, R-09 #2). A socket
        // that cannot carry a timeout is refused rather than used blocking
        // (round 13, R-09 #5).
        stream
            .set_read_timeout(Some(DEFAULT_FRAME_WAIT))
            .map_err(|error| Error::Transport(format!("read timeout: {error}")))?;
        stream
            .set_write_timeout(Some(DEFAULT_FRAME_WAIT))
            .map_err(|error| Error::Transport(format!("write timeout: {error}")))?;
        Ok(Self {
            stream: BufReader::with_capacity(TCP_READ_BUFFER, stream),
            written: 0,
            limits: WireLimits::default(),
            recv_poisoned: false,
            send_poisoned: false,
            frame_deadline: Some(DEFAULT_FRAME_WAIT),
        })
    }

    /// Use tighter wire limits (server side of an untrusted connection).
    pub fn with_limits(mut self, limits: WireLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Send one request and read its answer, which must belong to the call.
    ///
    /// A response echoes the request id and an error echoes it or carries id 0
    /// (the frame was refused before the id could be read). A relay, or an
    /// attacker on a plaintext connection, that replays another call's answer
    /// is refused with `rpc/wire` instead of being handed to the caller as this
    /// call's result (round 13, R-09 #3). `send`/`recv` stay available for
    /// protocols that do their own matching.
    pub fn call(&mut self, envelope: &Envelope) -> Result<Envelope> {
        self.send(envelope)?;
        let Some(answer) = self.recv()? else {
            return Err(Error::Transport(
                "the peer closed before answering".to_string(),
            ));
        };
        if !answer.answers(envelope.request_id) {
            return Err(Error::Wire("the answer belongs to another request"));
        }
        Ok(answer)
    }

    /// Connect to a peer.
    pub fn connect(address: &str) -> Result<Self> {
        let stream = TcpStream::connect(address)
            .map_err(|error| Error::Transport(format!("connect: {error}")))?;
        Self::new(stream)
    }

    /// Connect with a read and write deadline.
    ///
    /// A peer that accepts and then sends nothing blocks a blocking `read`
    /// forever. An operator tool that talks to an untrusted peer needs a
    /// deadline, and a server that serves one connection at a time needs one on
    /// the accepted socket or its `--limit` is unreachable.
    pub fn connect_with_timeout(address: &str, timeout: std::time::Duration) -> Result<Self> {
        let deadline = std::time::Instant::now() + timeout;
        // Name resolution is bounded too, by the same helper the bridge uses:
        // a slow resolver used to park the caller past its own deadline and to
        // report every failure as "timed out" (round 11, R-09 #4).
        let addresses = crate::transport::connect::resolve_within(address, deadline)?;
        if addresses.is_empty() {
            // A name with no address is a configuration fault, not a network
            // stall: the message must not send an operator to the network
            // (round 12, R-09 #3).
            return Err(Error::Transport(format!("no address for {address}")));
        }
        let mut last: Option<std::io::Error> = None;
        // `TcpStream::connect` has no bound: a black-holed SYN parked a caller
        // that asked for a deadline forever. Each attempt gets what is left
        // (round 10, R-09 #1), and the armed timeout is that remainder too, so
        // several addresses cannot spend the budget twice (round 11, R-09 #5).
        for address in addresses {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                break;
            }
            match TcpStream::connect_timeout(&address, left) {
                // The frame deadline is the caller's timeout, not the remainder
                // of the connect budget: a connect that stalls for most of the
                // budget used to yield a transport whose every read timed out
                // after a few milliseconds (round 14, F-6).
                Ok(stream) => return Self::with_timeout(stream, timeout),
                Err(error) => last = Some(error),
            }
        }
        Err(Error::Transport(match last {
            Some(error) => format!("connect: {error}"),
            None => "connect timed out".to_string(),
        }))
    }

    /// Wrap an accepted or connected stream with a read and write deadline.
    ///
    /// The socket timeout bounds one `read`; the transport also bounds one
    /// *frame* by it, because a peer that sends a byte just inside the read
    /// timeout would otherwise keep a frame alive forever.
    pub fn with_timeout(stream: TcpStream, timeout: std::time::Duration) -> Result<Self> {
        // `new` installs the default bound and swallows the socket call, so the
        // caller's timeout is applied afterwards and a failure is reported:
        // setting it first and letting `new` overwrite it made the tight bound
        // a no-op (round 11, R-09 #2).
        let mut transport = Self::new(stream)?;
        transport
            .stream
            .get_ref()
            .set_read_timeout(Some(timeout))
            .and_then(|()| transport.stream.get_ref().set_write_timeout(Some(timeout)))
            .map_err(|error| Error::Transport(error.to_string()))?;
        transport.frame_deadline = Some(timeout);
        Ok(transport)
    }
}

impl Transport for TcpTransport {
    fn name(&self) -> &'static str {
        "tcp"
    }

    fn send(&mut self, envelope: &Envelope) -> Result<()> {
        if self.send_poisoned {
            return Err(Error::Transport(
                "the connection is poisoned by a partial frame".to_string(),
            ));
        }
        let bytes = envelope.encode_with_limits(self.limits)?;
        // The transport's own limits bound what it sends, as they bound what it
        // reads: a strict peer must refuse locally instead of writing a frame
        // it would itself reject (round 9, R-09 #11).
        if bytes.len() > self.limits.max_bytes.min(MAX_FRAME_BYTES) {
            return Err(Error::Wire("frame exceeds the size ceiling"));
        }
        // A reader that stops must not hold a serial server for the whole
        // message: each frame gets one write budget, re-armed before every
        // write, so a peer that takes one byte per socket timeout cannot
        // stretch a frame (round 15, F-2).
        let deadline = self
            .frame_deadline
            .map(|wait| std::time::Instant::now() + wait);
        if let Err(error) = write_frame_before(self.stream.get_mut(), &bytes, deadline) {
            // The header or the body (or part of either) may be on the wire, so
            // the peer's read position no longer matches a frame boundary.
            self.send_poisoned = true;
            return Err(error);
        }
        self.written += (bytes.len() + 4) as u64;
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Envelope>> {
        if self.recv_poisoned {
            return Err(Error::Transport(
                "the connection is poisoned by a partial frame".to_string(),
            ));
        }
        // One deadline for the whole frame, and the socket timeout is re-armed
        // to the time left before each read: a blocked `read` would otherwise
        // outlive the deadline by its own timeout.
        let deadline = self
            .frame_deadline
            .map(|wait| std::time::Instant::now() + wait);

        // Count what the read consumed: any error after a byte has been taken
        // leaves the inbound stream off a frame boundary, whether it was a
        // ceiling refusal, a timeout mid-header or a stall mid-body. Only a
        // clean end-of-stream before the first byte keeps the session usable
        // (round 11, R-09 #1).
        struct Counted<'a> {
            inner: &'a mut BufReader<TcpStream>,
            read: usize,
            deadline: Option<std::time::Instant>,
            rearm_failed: bool,
        }
        impl std::io::Read for Counted<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                // One deadline for the whole frame, re-armed to the time left
                // before every read: a peer that sends one byte just before
                // each socket timeout used to win a second full deadline
                // (round 15, F-5). A socket that refuses the value keeps the
                // constructor's bound, silently weakening the caller's
                // deadline, so that ends the receive (round 14, F-8).
                if let Some(deadline) = self.deadline {
                    let now = std::time::Instant::now();
                    let remaining = deadline
                        .saturating_duration_since(now)
                        .max(std::time::Duration::from_millis(1));
                    if now >= deadline {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "frame deadline elapsed",
                        ));
                    }
                    if let Err(error) = self.inner.get_ref().set_read_timeout(Some(remaining)) {
                        self.rearm_failed = true;
                        return Err(std::io::Error::other(format!("read deadline: {error}")));
                    }
                }
                let read = self.inner.read(buf)?;
                self.read += read;
                Ok(read)
            }
        }
        let mut counted = Counted {
            inner: &mut self.stream,
            read: 0,
            deadline,
            rearm_failed: false,
        };
        let result = read_frame_before(&mut counted, &self.limits, deadline);
        if counted.rearm_failed {
            // The socket refused the deadline the caller asked for: the frame is
            // not where the reader thinks it is (round 14, F-8; restored in round
            // 16, F-5).
            self.recv_poisoned = true;
        }
        let consumed = counted.read;
        let body = match result {
            Ok(Some(body)) => body,
            Ok(None) => return Ok(None),
            Err(error) => {
                if consumed > 0 || matches!(error, Error::Wire(_)) {
                    self.recv_poisoned = true;
                }
                return Err(error);
            }
        };
        Ok(Some(match Envelope::decode_with(&body, self.limits) {
            Ok(envelope) => envelope,
            Err(error) => {
                // A frame whose body decodes badly is a protocol fault like a
                // malformed frame: the session must not be reused as if the
                // peer were healthy after its caller ignored the error
                // (round 13, R-09 #2).
                self.recv_poisoned = true;
                return Err(error);
            }
        }))
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

/// How long one served connection may live before the loop stops reading.
///
/// The per-frame deadline bounds one stalled read; without a total bound a peer
/// that sends a valid frame just inside every deadline holds a serial server
/// forever and starves every other peer. Ten minutes leaves a long-lived
/// session its run and bounds the starvation (round 13, R-09 #4).
pub const DEFAULT_CONNECTION_LIFETIME: std::time::Duration =
    std::time::Duration::from_secs(10 * 60);

/// Serve one connection: read envelopes and answer each with `handler`.
///
/// A frame error or a broken socket ends *this* connection, not the server: the
/// reply carries the stable code and the call returns the count served so far.
/// A caller that is serving many connections keeps accepting.
pub fn serve_connection<H>(transport: TcpTransport, handler: H) -> Result<u64>
where
    H: FnMut(Envelope) -> Envelope,
{
    let deadline = std::time::Instant::now()
        .checked_add(DEFAULT_CONNECTION_LIFETIME)
        .unwrap_or_else(std::time::Instant::now);
    serve_connection_within(transport, handler, Some(deadline))
}

/// [`serve_connection`] with an explicit connection deadline.
///
/// `None` removes the total bound; the per-frame deadline still applies.
pub fn serve_connection_within<H>(
    mut transport: TcpTransport,
    mut handler: H,
    deadline: Option<std::time::Instant>,
) -> Result<u64>
where
    H: FnMut(Envelope) -> Envelope,
{
    let mut served = 0u64;
    loop {
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            // The connection outlived its budget: stop reading. The caller
            // accepts the next peer instead of serving this one forever
            // (round 13, R-09 #4).
            return Ok(served);
        }
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
                // A provider panic is hostile-input reachable. On this
                // transport the handler runs on the serving thread, so without a
                // catch it would take the whole server down; the panic becomes a
                // refusal for this call, and the connection continues.
                let request_id = envelope.request_id;
                let response = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    handler(envelope)
                })) {
                    Ok(response) => response,
                    Err(_) => Envelope::error(
                        request_id,
                        &Error::Provider {
                            code: "rpc/provider".to_string(),
                        },
                    ),
                };
                match transport.send(&response) {
                    Ok(()) => served += 1,
                    // A local refusal (the reply is past this transport's own
                    // profile) wrote nothing: answer one small withheld envelope
                    // so the caller learns the effect stands, instead of seeing
                    // EOF and a retryable transport class (round 17, R16-2).
                    Err(Error::Wire(_)) | Err(Error::CapabilityTable(_)) => {
                        let withheld = Envelope::error(
                            request_id,
                            &Error::Provider {
                                code: "provider/reply-withheld".to_string(),
                            },
                        );
                        let _ = transport.send(&withheld);
                        return Ok(served + 1);
                    }
                    // The peer is gone; the connection is over, the server is
                    // not.
                    Err(_) => return Ok(served),
                }
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
    read_frame_before(reader, limits, None)
}

/// [`read_frame`] with one wall deadline for the whole frame.
///
/// A per-read socket timeout is not a frame bound: a peer that sends one byte
/// just inside it keeps the read alive forever. The deadline is checked between
/// reads, so a drip ends on schedule as long as no read is already blocked; a
/// caller reading from a socket must also arm the socket timeout to the time
/// left, which TcpTransport does.
pub fn read_frame_before<R: Read>(
    reader: &mut R,
    limits: &WireLimits,
    deadline: Option<std::time::Instant>,
) -> Result<Option<Vec<u8>>> {
    let expired = |deadline: Option<std::time::Instant>| {
        deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline)
    };
    let mut header = [0u8; 4];
    let mut filled = 0usize;
    while filled < header.len() {
        if expired(deadline) {
            return Err(Error::Transport("frame timed out".to_string()));
        }
        match reader.read(&mut header[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => {
                // A truncated frame is a framing fault, as it is on QUIC and
                // through the bridge: a retryable transport class made a
                // hostile short frame look like a network hiccup
                // (round 10, R-09 #4).
                return Err(Error::Wire("truncated frame header"));
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
    // Read in chunks so the deadline is checked while the body arrives; a single
    // `read_to_end` would only see it after the peer stopped.
    let mut chunk = [0u8; 16 * 1024];
    while body.len() < len {
        if expired(deadline) {
            return Err(Error::Transport("frame timed out".to_string()));
        }
        let want = (len - body.len()).min(chunk.len());
        match reader.read(&mut chunk[..want]) {
            Ok(0) => break,
            Ok(read) => body.extend_from_slice(&chunk[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Error::Transport(error.to_string())),
        }
    }
    if body.len() != len {
        return Err(Error::Wire("truncated frame body"));
    }
    Ok(Some(body))
}

/// Write one exact frame to a generic writer.
///
/// Header and body travel in one vectored write, so a TCP frame costs one send
/// syscall. `IoSlice::advance_slices` handles a short write; a zero write is an
/// error rather than a spin.
/// A writer whose socket timeout follows one frame deadline.
///
/// The default is a no-op, so an in-memory writer needs no deadline support.
pub trait DeadlineWrite: Write {
    /// Re-arm the underlying timeout for the time left, or fail once the
    /// deadline has passed.
    fn arm_deadline(&mut self, _deadline: Option<std::time::Instant>) -> std::io::Result<()> {
        Ok(())
    }
}

impl DeadlineWrite for TcpStream {
    fn arm_deadline(&mut self, deadline: Option<std::time::Instant>) -> std::io::Result<()> {
        let Some(deadline) = deadline else {
            return Ok(());
        };
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "frame deadline elapsed",
            ));
        }
        let left = deadline
            .saturating_duration_since(now)
            .max(std::time::Duration::from_millis(1));
        self.set_write_timeout(Some(left))
    }
}

/// Write one frame under a deadline, re-armed before every write.
///
/// A peer that accepts one byte per socket timeout used to stretch a frame
/// indefinitely: each successful partial write restarted the timeout. The dead
/// line is checked and the timeout recomputed before each write (round 15, F-2).
pub fn write_frame_before<W: DeadlineWrite + ?Sized>(
    writer: &mut W,
    body: &[u8],
    deadline: Option<std::time::Instant>,
) -> Result<()> {
    let header = frame(body.len())?;
    let mut slices: [IoSlice<'_>; 2] = [IoSlice::new(&header), IoSlice::new(body)];
    let mut bufs: &mut [IoSlice<'_>] = &mut slices;
    while !bufs.is_empty() {
        writer
            .arm_deadline(deadline)
            .map_err(|error| Error::Transport(format!("write deadline: {error}")))?;
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

/// Write one frame (header and body) to a writer with no deadline support.
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
