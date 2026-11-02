//! HTTP/2 transport carrying ARP1 (feature `http2`).
//!
//! [`transport::connect`](crate::transport::connect) is the interoperability
//! bridge: HTTP/1.1, one request per connection, gRPC framing. This module is
//! the *native* HTTP/2 option for networks where UDP/QUIC is blocked but
//! HTTP/2 is allowed (corporate proxies, TLS-terminating gateways, service
//! meshes). The payload is the same ARP1 envelope, unframed, with a single
//! media type:
//!
//! ```text
//! POST /active.rpc.v1.Agent/Call HTTP/2
//! content-type: application/arp1
//!
//! <envelope bytes>
//! ```
//!
//! One HTTP/2 connection carries many concurrent streams, so a client can keep
//! a single connection for the lifetime of an agent and issue calls in
//! parallel. The capability table rides in the envelope exactly as it does on
//! every other transport; nothing about authority depends on HTTP.
//!
//! A malformed body, an oversized body, a wrong path or a wrong media type is a
//! `4xx` with a stable `rpc/...` body. It is never a panic and never a silently
//! dropped stream.
//!
//! # Security posture
//!
//! The listener is cleartext HTTP/2 (h2c) bound to loopback by
//! [`Http2Server::bind_loopback`], the only constructor. A deployment places it
//! behind its TLS terminator, or uses the QUIC mutual-TLS transport when peer
//! authentication is required. This transport carries no `PeerIdentity`: a
//! capability bound to a peer cannot be introduced over it, because the
//! transport cannot prove who connected. Authority still comes only from the
//! envelope's capability table.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};

use crate::error::{Error, Result};
use crate::wire::{Envelope, WireLimits};

/// Service path the transport answers.
pub const PATH: &str = "/active.rpc.v1.Agent/Call";
/// Media type of an ARP1 envelope body.
pub const CONTENT_TYPE: &str = "application/arp1";
/// Largest request body the transport accepts.
pub const MAX_BODY: usize = 64 << 20;

/// Largest decoded header list, in RFC 9113 field bytes (name + value + 32 each).
///
/// An HPACK block can expand far beyond the bytes on the wire — one 100-byte
/// field can name a header the peer never sent — so the decoder, not the socket,
/// has to bound the result. 32 KiB is generous for `content-type` plus tracing
/// headers and small enough that 128 concurrent streams stay a bounded amount of
/// memory.
pub const MAX_HEADER_LIST: u32 = 32 << 10;
/// Largest number of header fields in one request.
pub const MAX_HEADER_FIELDS: usize = 64;

/// Consecutive `accept` failures before the listener is considered broken.
pub const MAX_ACCEPT_FAILURES: u32 = 64;

/// How long one connection may stay open without completing.
///
/// A client that connects and then says nothing (no preface, no HEADERS) holds
/// its task in the join set, and `serve` waits for every task: the peer's
/// `--limit` became unreachable. The deadline abandons such a connection.
pub const DEFAULT_CONNECTION_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);
/// Largest frame either side will emit or accept (RFC 9113 minimum).
pub const MAX_FRAME: u32 = 16 << 10;
/// Concurrent streams one connection may carry.
pub const MAX_CONCURRENT_STREAMS: u32 = 128;
/// Flow-control window for one stream.
pub const MAX_STREAM_WINDOW: u32 = 256 << 10;
/// Flow-control window for one connection.
pub const MAX_CONNECTION_WINDOW: u32 = 2 << 20;
/// Request-body bytes one connection may be accumulating across all streams.
///
/// A peer that opens every allowed stream with the largest allowed body would
/// otherwise pin `MAX_CONCURRENT_STREAMS * MAX_BODY` of memory. This is the cap
/// that turns that into a refusal. The default leaves room for two maximum-size
/// bodies in flight, so the documented per-request ceiling (`MAX_BODY`) is
/// reachable; [`Http2Server::with_inflight_budget`] tightens it per deployment.
pub const MAX_INFLIGHT_BODY: usize = 128 << 20;

/// An HTTP/2 server bound to a loopback port.
///
/// `serve` consumes the server: the listener is moved into the runtime, which
/// keeps the accept loop and every stream on one executor.
pub struct Http2Server {
    runtime: tokio::runtime::Runtime,
    listener: Option<std::net::TcpListener>,
    address: String,
    limits: WireLimits,
    inflight_budget: usize,
    connection_deadline: std::time::Duration,
}

impl std::fmt::Debug for Http2Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http2Server")
            .field("address", &self.address)
            .finish()
    }
}

impl Http2Server {
    /// Bind an ephemeral loopback port.
    pub fn bind_loopback() -> Result<Self> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|error| Error::Transport(format!("bind: {error}")))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| Error::Transport(format!("nonblocking: {error}")))?;
        let address = listener
            .local_addr()
            .map_err(|error| Error::Transport(error.to_string()))?
            .to_string();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| Error::Transport(format!("runtime: {error}")))?;
        Ok(Self {
            runtime,
            listener: Some(listener),
            address,
            limits: WireLimits::default(),
            inflight_budget: MAX_INFLIGHT_BODY,
            connection_deadline: DEFAULT_CONNECTION_DEADLINE,
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

    /// Cap the request-body bytes this server accumulates across every
    /// connection of this `serve` call.
    ///
    /// A body that would take a connection over the budget is refused with
    /// `429` before it is buffered. The default is [`MAX_INFLIGHT_BODY`], which
    /// leaves room for two maximum-size bodies; a deployment that serves many
    /// small calls can tighten it, and one that accepts maximum-size bodies must
    /// leave room for at least one.
    pub fn with_inflight_budget(mut self, bytes: usize) -> Self {
        self.inflight_budget = bytes.max(1);
        self
    }

    /// Abandon a connection that has not completed within `deadline`.
    ///
    /// `serve` waits for every connection task, so a client that connects and
    /// then goes silent held the server past its `--limit`.
    pub fn with_connection_deadline(mut self, deadline: std::time::Duration) -> Self {
        self.connection_deadline = deadline.max(std::time::Duration::from_millis(1));
        self
    }

    /// Accept `connections` HTTP/2 connections and return the calls served.
    ///
    /// Streams within one connection are handled concurrently. The call returns
    /// when the client closes every accepted connection.
    pub fn serve<H>(mut self, connections: usize, handler: H) -> Result<u64>
    where
        H: FnMut(Envelope) -> Envelope + Send + 'static,
    {
        let listener = self
            .listener
            .take()
            .ok_or(Error::Transport("server was already served".to_string()))?;
        let limits = self.limits;
        let inflight_budget = self.inflight_budget;
        let connection_deadline = self.connection_deadline;
        let handler = Arc::new(Mutex::new(handler));
        let served = Arc::new(AtomicU64::new(0));
        // One budget for the whole server. A per-connection budget let N
        // connections pin N x 128 MiB, which is not a bound an operator can
        // reason about.
        let inflight = Arc::new(AtomicUsize::new(0));
        self.runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener)
                .map_err(|error| Error::Transport(format!("listener: {error}")))?;
            let mut accepted = 0usize;
            let connection_budget = connections;
            // Connections are independent: a peer that resets mid-handshake must
            // not stall the listener or take other connections down. Each one
            // runs to completion on the runtime.
            let mut active = tokio::task::JoinSet::new();
            let mut refused = 0u32;
            while accepted < connection_budget {
                let (stream, _) = match listener.accept().await {
                    Ok(pair) => {
                        refused = 0;
                        pair
                    }
                    Err(error) => {
                        // A transient accept error (a connection reset before it
                        // was accepted, a temporary descriptor shortage) belongs
                        // to that connection. Only a listener that keeps failing
                        // is fatal.
                        refused += 1;
                        if refused > MAX_ACCEPT_FAILURES {
                            return Err(Error::Transport(format!("accept: {error}")));
                        }
                        // Back off: 64 immediate retries against EMFILE burn
                        // the runtime and exit just as fast as one.
                        tokio::time::sleep(std::time::Duration::from_millis(
                            5 * u64::from(refused.min(20)),
                        ))
                        .await;
                        continue;
                    }
                };
                accepted += 1;
                // A socket that was reset between accept and here is this
                // connection's problem; the listener keeps serving.
                let _ = stream.set_nodelay(true);
                let handler = Arc::clone(&handler);
                let served_for_task = Arc::clone(&served);
                let inflight = Arc::clone(&inflight);
                active.spawn(async move {
                    // A connection that never completes is abandoned at the
                    // deadline instead of holding the join set.
                    let _ = serve_connection(
                        stream,
                        handler,
                        served_for_task,
                        limits,
                        inflight,
                        inflight_budget,
                        connection_deadline,
                    )
                    .await;
                });
            }
            while let Some(joined) = active.join_next().await {
                // A connection error is that peer's problem; the served count
                // only reflects complete requests.
                let _ = joined;
            }
            Ok(served.load(Ordering::Relaxed))
        })
    }
}

async fn serve_connection<S, H>(
    io: S,
    handler: Arc<Mutex<H>>,
    served: Arc<AtomicU64>,
    limits: WireLimits,
    inflight: Arc<AtomicUsize>,
    inflight_budget: usize,
    connection_deadline: std::time::Duration,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    H: FnMut(Envelope) -> Envelope + Send + 'static,
{
    let mut builder = h2::server::Builder::new();
    builder
        .max_header_list_size(MAX_HEADER_LIST)
        .max_frame_size(MAX_FRAME)
        .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
        .initial_window_size(MAX_STREAM_WINDOW)
        .initial_connection_window_size(MAX_CONNECTION_WINDOW);
    let mut connection = builder
        .handshake(io)
        .await
        .map_err(|error| Error::Transport(format!("h2 handshake: {error}")))?;
    // Streams are handled concurrently; the join set keeps the connection alive
    // until every response has been written.
    let mut streams = tokio::task::JoinSet::new();
    loop {
        // The deadline bounds *inactivity*: a client that connects and then says
        // nothing is dropped, while an active connection lives as long as both
        // sides keep talking. Wrapping the whole connection instead cut every
        // long-lived agent off mid-session.
        let accepted = match tokio::time::timeout(connection_deadline, connection.accept()).await {
            Ok(Some(request)) => request,
            // The peer closed, or the connection went idle past the deadline.
            Ok(None) | Err(_) => break,
        };
        let (request, respond) = match accepted {
            Ok(parts) => parts,
            Err(error) => {
                return Err(Error::Transport(format!("h2 accept: {error}")));
            }
        };
        let handler = Arc::clone(&handler);
        let served = Arc::clone(&served);
        let inflight = Arc::clone(&inflight);
        streams.spawn(async move {
            let handled = handle_stream(
                request,
                respond,
                handler,
                limits,
                inflight,
                inflight_budget,
                connection_deadline,
            )
            .await?;
            if handled {
                served.fetch_add(1, Ordering::Relaxed);
            }
            Ok::<(), Error>(())
        });
    }
    while let Some(joined) = streams.join_next().await {
        // A stream that fails (reset, oversized body) ends that stream; HTTP/2
        // keeps the connection usable for the streams that follow.
        let _ = joined;
    }
    Ok(())
}

async fn handle_stream<H>(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    handler: Arc<Mutex<H>>,
    limits: WireLimits,
    inflight: Arc<AtomicUsize>,
    inflight_budget: usize,
    connection_deadline: std::time::Duration,
) -> Result<bool>
where
    H: FnMut(Envelope) -> Envelope,
{
    // Header budgets first: a compressed block can decode to far more than the
    // peer sent, so the decoded list is what is checked.
    let header_bytes: usize = request
        .headers()
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len() + 32)
        .sum();
    if header_bytes > MAX_HEADER_LIST as usize || request.headers().len() > MAX_HEADER_FIELDS {
        return respond_status(
            &mut respond,
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            b"rpc/wire",
        );
    }
    if request.method() != Method::POST {
        return respond_status(
            &mut respond,
            StatusCode::METHOD_NOT_ALLOWED,
            b"rpc/not-found",
        );
    }
    if request.uri().path() != PATH {
        return respond_status(&mut respond, StatusCode::NOT_FOUND, b"rpc/not-found");
    }
    let media_type = request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if media_type != CONTENT_TYPE {
        return respond_status(
            &mut respond,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            b"rpc/wire",
        );
    }
    let mut body = request.into_body();
    let mut bytes = Vec::new();
    let mut reservation = Reservation::new(inflight);
    // The caller's wire ceiling bounds the body; `MAX_BODY` is the hard cap.
    let ceiling = limits.max_bytes.min(MAX_BODY);
    // Two bounds. Per-chunk inactivity catches a stall; the total catches a drip
    // that stays just inside the inactivity window (one byte every 200 ms keeps
    // a per-chunk timeout alive forever). The total scales with the inactivity
    // bound so a test deadline stays fast and the default stays generous.
    let body_deadline = tokio::time::Instant::now()
        + connection_deadline
            .saturating_mul(8)
            .min(std::time::Duration::from_secs(30));
    loop {
        let next = {
            let inactivity = tokio::time::timeout(connection_deadline, body.data());
            match tokio::time::timeout_at(body_deadline, inactivity).await {
                Ok(Ok(next)) => next,
                Ok(Err(_)) | Err(_) => {
                    return respond_status(
                        &mut respond,
                        StatusCode::REQUEST_TIMEOUT,
                        b"rpc/transport",
                    )
                }
            }
        };
        match next {
            Some(Ok(chunk)) => {
                if bytes.len() + chunk.len() > ceiling {
                    return respond_status(
                        &mut respond,
                        StatusCode::PAYLOAD_TOO_LARGE,
                        b"rpc/wire",
                    );
                }
                if !reservation.reserve(chunk.len(), inflight_budget) {
                    // The connection already holds its budget in other streams.
                    return respond_status(
                        &mut respond,
                        StatusCode::TOO_MANY_REQUESTS,
                        b"rpc/wire",
                    );
                }
                let len = chunk.len();
                bytes.extend_from_slice(&chunk);
                let _ = body.flow_control().release_capacity(len);
            }
            Some(Err(_)) => {
                return respond_status(&mut respond, StatusCode::BAD_REQUEST, b"rpc/wire");
            }
            None => break,
        }
    }
    let envelope = match Envelope::decode_with(&bytes, limits) {
        Ok(envelope) => envelope,
        Err(error) => {
            return respond_status(
                &mut respond,
                StatusCode::BAD_REQUEST,
                error.code().as_bytes(),
            );
        }
    };
    // A response or error envelope is not a call; a relay must not be able to
    // forward one as a request.
    if envelope.kind != crate::wire::Kind::Request {
        return respond_status(&mut respond, StatusCode::BAD_REQUEST, b"rpc/wire");
    }
    let request_id = envelope.request_id;
    let response = {
        // A kernel handler is single-threaded and may block on the kernel
        // loop; `block_in_place` moves the runtime worker aside instead of
        // stalling every other stream on this runtime.
        tokio::task::block_in_place(|| {
            let mut handler = match handler.lock() {
                Ok(handler) => handler,
                Err(poisoned) => poisoned.into_inner(),
            };
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(envelope))) {
                Ok(response) => response,
                Err(_) => Envelope::error(
                    request_id,
                    &Error::Provider {
                        code: "rpc/provider".to_string(),
                    },
                ),
            }
        })
    };
    let encoded = match response.encode() {
        Ok(encoded) => encoded,
        Err(error) => {
            return respond_status(
                &mut respond,
                StatusCode::INTERNAL_SERVER_ERROR,
                error.code().as_bytes(),
            );
        }
    };
    respond_body(respond, encoded, connection_deadline).await
}

/// Bytes of request body one stream has reserved on its connection.
///
/// The guard releases everything it holds when the stream ends, on every path,
/// so a reset or a refused response cannot leak budget.
struct Reservation {
    budget: Arc<AtomicUsize>,
    held: usize,
}

impl Reservation {
    fn new(budget: Arc<AtomicUsize>) -> Self {
        Self { budget, held: 0 }
    }

    /// Reserve `bytes` if the connection stays under `limit`.
    fn reserve(&mut self, bytes: usize, limit: usize) -> bool {
        let total = self.budget.fetch_add(bytes, Ordering::Relaxed) + bytes;
        if total > limit {
            self.budget.fetch_sub(bytes, Ordering::Relaxed);
            return false;
        }
        self.held += bytes;
        true
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.held != 0 {
            self.budget.fetch_sub(self.held, Ordering::Relaxed);
        }
    }
}

/// Map a refusal body to the matching error.
///
/// Shared with the bridge client: only a short `rpc/...` token is read, so an
/// error cannot carry the peer's prose and a caller can still branch on the
/// class through [`Error::provider_code`].
fn refusal(body: &[u8]) -> Error {
    crate::transport::refusal(body)
}

fn respond_status(
    respond: &mut h2::server::SendResponse<Bytes>,
    status: StatusCode,
    body: &[u8],
) -> Result<bool> {
    let head = Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(http::header::CONTENT_LENGTH, body.len())
        .body(())
        .map_err(|error| Error::Transport(format!("response head: {error}")))?;
    let mut send = respond
        .send_response(head, false)
        .map_err(|error| Error::Transport(format!("send response: {error}")))?;
    send.send_data(Bytes::copy_from_slice(body), true)
        .map_err(|error| Error::Transport(format!("send body: {error}")))?;
    Ok(false)
}

/// Write one response body, bounded.
///
/// `send_data` awaits flow-control capacity: a peer that advertises a zero
/// window and never reads parks it forever, keeping the stream task and its
/// reservation alive. On expiry the stream is reset.
async fn respond_body(
    mut respond: h2::server::SendResponse<Bytes>,
    encoded: Vec<u8>,
    deadline: std::time::Duration,
) -> Result<bool> {
    // A piece per window grant: `send_data` without a reservation buffers
    // unboundedly, so the loop asks for capacity and waits with a deadline. A
    // peer that advertises a zero window and never reads parks the wait, and the
    // stream is reset instead of holding the task and its reservation.
    const PIECE: usize = 16 * 1024;
    let head = Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, CONTENT_TYPE)
        .header(http::header::CONTENT_LENGTH, encoded.len())
        .body(())
        .map_err(|error| Error::Transport(format!("response head: {error}")))?;
    let mut send = respond
        .send_response(head, false)
        .map_err(|error| Error::Transport(format!("send response: {error}")))?;
    let mut offset = 0usize;
    // One budget for the whole response, not one per piece: a peer that grants
    // a single byte per window would otherwise hold the task for pieces x
    // deadline.
    let total = tokio::time::Instant::now()
        + deadline
            .saturating_mul(8)
            .min(std::time::Duration::from_secs(30));
    while offset < encoded.len() {
        let want = (encoded.len() - offset).min(PIECE);
        send.reserve_capacity(want);
        let granted = match tokio::time::timeout_at(
            total,
            tokio::time::timeout(
                deadline,
                std::future::poll_fn(|context| send.poll_capacity(context)),
            ),
        )
        .await
        {
            Ok(Ok(Some(Ok(capacity)))) if capacity > 0 => capacity,
            Ok(Ok(Some(Err(error)))) => {
                return Err(Error::Transport(format!("send body: {error}")));
            }
            // Timed out, or the stream closed under us.
            _ => {
                send.send_reset(h2::Reason::CANCEL);
                return Ok(false);
            }
        };
        let take = granted.min(want).min(encoded.len() - offset);
        let end = offset + take == encoded.len();
        send.send_data(Bytes::copy_from_slice(&encoded[offset..offset + take]), end)
            .map_err(|error| Error::Transport(format!("send body: {error}")))?;
        offset += take;
    }
    Ok(true)
}

/// An HTTP/2 client that reuses one connection for every call.
pub struct Http2Client {
    runtime: tokio::runtime::Runtime,
    sender: h2::client::SendRequest<Bytes>,
    task: tokio::task::JoinHandle<()>,
    address: String,
    limits: WireLimits,
    /// Wall deadline for one request, when the caller sets one.
    deadline: Option<std::time::Duration>,
}

impl std::fmt::Debug for Http2Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http2Client")
            .field("address", &self.address)
            .finish()
    }
}

impl Http2Client {
    /// Connect and perform the HTTP/2 preface.
    pub fn connect(address: &str) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| Error::Transport(format!("runtime: {error}")))?;
        let target = address.to_string();
        let (sender, task) = runtime.block_on(async move {
            let stream = tokio::net::TcpStream::connect(&target)
                .await
                .map_err(|error| Error::Transport(format!("connect: {error}")))?;
            stream
                .set_nodelay(true)
                .map_err(|error| Error::Transport(format!("nodelay: {error}")))?;
            let (sender, connection) = {
                let mut builder = h2::client::Builder::new();
                // The same budgets bound what a hostile server can send us:
                // a response header block decodes into memory the client pays.
                builder
                    .max_header_list_size(MAX_HEADER_LIST)
                    .max_frame_size(MAX_FRAME);
                builder
                    .handshake(stream)
                    .await
                    .map_err(|error| Error::Transport(format!("h2 handshake: {error}")))?
            };
            let task = tokio::spawn(async move {
                // The connection future drives every stream; it ends when the
                // client closes the sender or the server goes away.
                let _ = connection.await;
            });
            Ok::<_, Error>((sender, task))
        })?;
        Ok(Self {
            runtime,
            sender,
            task,
            address: address.to_string(),
            limits: WireLimits::default(),
            deadline: None,
        })
    }

    /// Use tighter wire limits.
    pub fn with_limits(mut self, limits: WireLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Bound one request in wall time.
    ///
    /// The library has no internal deadline: a peer that accepts the connection
    /// and then stalls (or dribbles a response) would otherwise park the caller
    /// forever. Nothing is set by default, so existing callers see the old
    /// behaviour.
    pub fn with_deadline(mut self, deadline: std::time::Duration) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// The address this client dials.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Send one call and decode the response.
    pub fn call(&mut self, envelope: &Envelope) -> Result<Envelope> {
        let body = envelope.encode()?;
        let (status, response) = self.request(PATH, CONTENT_TYPE, &[], &body)?;
        if status != StatusCode::OK {
            return Err(refusal(&response));
        }
        Envelope::decode_with(&response, self.limits)
    }

    /// Send several calls concurrently over the one connection.
    ///
    /// HTTP/2 stream multiplexing is the reason this transport exists; the
    /// results are returned in request order regardless of completion order.
    pub fn call_many(&mut self, envelopes: &[Envelope]) -> Result<Vec<Envelope>> {
        let mut payloads = Vec::with_capacity(envelopes.len());
        for envelope in envelopes {
            payloads.push(envelope.encode()?);
        }
        let sender = self.sender.clone();
        let limits = self.limits;
        let deadline = self.deadline;
        let count = payloads.len();
        let responses = self.runtime.block_on(async move {
            let exchange = async move {
                // A `JoinSet` aborts its tasks when it is dropped, so a deadline
                // does not leave streams running behind the caller. Completion
                // order is not request order, so each task carries its index.
                let mut tasks = tokio::task::JoinSet::new();
                for (index, body) in payloads.into_iter().enumerate() {
                    let mut sender = sender.clone();
                    tasks.spawn(async move {
                        let decoded = async {
                            let request = Request::builder()
                                .method(Method::POST)
                                .uri(PATH)
                                .header(http::header::CONTENT_TYPE, CONTENT_TYPE)
                                .body(())
                                .map_err(|error| Error::Transport(format!("request: {error}")))?;
                            let (response, mut send) =
                                sender.send_request(request, false).map_err(|error| {
                                    Error::Transport(format!("send header: {error}"))
                                })?;
                            // The same early-answer case as `request`.
                            let _ = send.send_data(Bytes::from(body), true);
                            let response = response
                                .await
                                .map_err(|error| Error::Transport(format!("response: {error}")))?;
                            let (status, body) =
                                read_response(response, limits.max_bytes.min(MAX_BODY), deadline)
                                    .await?;
                            if status != StatusCode::OK {
                                Err(refusal(&body))
                            } else {
                                Envelope::decode_with(&body, limits)
                            }
                        };
                        (index, decoded.await)
                    });
                }
                let mut out: Vec<Option<Result<Envelope>>> = (0..count).map(|_| None).collect();
                while let Some(task) = tasks.join_next().await {
                    let (index, decoded) =
                        task.map_err(|error| Error::Transport(format!("stream task: {error}")))?;
                    if let Some(slot) = out.get_mut(index) {
                        *slot = Some(decoded);
                    }
                }
                Ok::<_, Error>(
                    out.into_iter()
                        .map(|slot| {
                            slot.unwrap_or_else(|| {
                                Err(Error::Transport(
                                    "a stream produced no response".to_string(),
                                ))
                            })
                        })
                        .collect::<Vec<_>>(),
                )
            };
            match deadline {
                Some(limit) => tokio::time::timeout(limit, exchange)
                    .await
                    .map_err(|_| Error::Transport("HTTP/2 call_many timed out".to_string()))?,
                None => exchange.await,
            }
        })?;
        responses.into_iter().collect()
    }

    /// Send a raw body with explicit headers (for negative-path tests).
    pub fn request_raw(
        &mut self,
        path: &str,
        content_type: &str,
        body: &[u8],
    ) -> Result<(StatusCode, Vec<u8>)> {
        self.request(path, content_type, &[], body)
    }

    /// Send a request with extra header fields (for header-budget tests).
    ///
    /// A refusal from the server's header budget arrives either as a `431`
    /// response or as a stream reset; both mean the request never reached the
    /// handler.
    pub fn request_with_headers(
        &mut self,
        path: &str,
        content_type: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<(StatusCode, Vec<u8>)> {
        self.request(path, content_type, headers, body)
    }

    fn request(
        &mut self,
        path: &str,
        content_type: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<(StatusCode, Vec<u8>)> {
        let mut sender = self.sender.clone();
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(http::header::CONTENT_TYPE, content_type);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let request = builder
            .body(())
            .map_err(|error| Error::Transport(format!("request: {error}")))?;
        let payload = Bytes::copy_from_slice(body);
        let limits = self.limits;
        let deadline = self.deadline;
        self.runtime.block_on(async move {
            let exchange = async move {
                let (response, mut send) = sender
                    .send_request(request, false)
                    .map_err(|error| Error::Transport(format!("send header: {error}")))?;
                // An early answer (a 415 before the body is read, say) closes the
                // stream underneath us; that response is the answer, so the send
                // error is not fatal. A server that never answers fails below.
                let _ = send.send_data(payload, true);
                let response = response
                    .await
                    .map_err(|error| Error::Transport(format!("response: {error}")))?;
                read_response(response, limits.max_bytes.min(MAX_BODY), deadline).await
            };
            match deadline {
                Some(limit) => tokio::time::timeout(limit, exchange)
                    .await
                    .map_err(|_| Error::Transport("HTTP/2 request timed out".to_string()))?,
                None => exchange.await,
            }
        })
    }
}

impl Drop for Http2Client {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_response(
    response: Response<h2::RecvStream>,
    ceiling: usize,
    deadline: Option<std::time::Duration>,
) -> Result<(StatusCode, Vec<u8>)> {
    // Inactivity bound per chunk plus a total bound: without them a server that
    // sends a byte and stops (or drips inside the window) parks the caller.
    let inactivity = deadline.unwrap_or(std::time::Duration::from_secs(30));
    let total = tokio::time::Instant::now()
        + inactivity
            .saturating_mul(8)
            .min(std::time::Duration::from_secs(30));
    let status = response.status();
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    loop {
        let next =
            match tokio::time::timeout_at(total, tokio::time::timeout(inactivity, body.data()))
                .await
            {
                Ok(Ok(next)) => next,
                Ok(Err(_)) | Err(_) => {
                    return Err(Error::Transport("HTTP/2 response timed out".to_string()))
                }
            };
        match next {
            Some(Ok(chunk)) => {
                if bytes.len() + chunk.len() > ceiling {
                    return Err(Error::Wire("HTTP/2 response exceeds the ceiling"));
                }
                let len = chunk.len();
                bytes.extend_from_slice(&chunk);
                let _ = body.flow_control().release_capacity(len);
            }
            Some(Err(error)) => {
                return Err(Error::Transport(format!("h2 response body: {error}")));
            }
            None => break,
        }
    }
    Ok((status, bytes))
}
