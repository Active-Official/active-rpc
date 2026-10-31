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

use std::sync::atomic::{AtomicU64, Ordering};
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

/// An HTTP/2 server bound to a loopback port.
///
/// `serve` consumes the server: the listener is moved into the runtime, which
/// keeps the accept loop and every stream on one executor.
pub struct Http2Server {
    runtime: tokio::runtime::Runtime,
    listener: Option<std::net::TcpListener>,
    address: String,
    limits: WireLimits,
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
        let handler = Arc::new(Mutex::new(handler));
        let served = Arc::new(AtomicU64::new(0));
        self.runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener)
                .map_err(|error| Error::Transport(format!("listener: {error}")))?;
            let mut accepted = 0usize;
            let connection_budget = connections;
            // Connections are independent: a peer that resets mid-handshake must
            // not stall the listener or take other connections down. Each one
            // runs to completion on the runtime.
            let mut active = tokio::task::JoinSet::new();
            while accepted < connection_budget {
                let (stream, _) = listener
                    .accept()
                    .await
                    .map_err(|error| Error::Transport(format!("accept: {error}")))?;
                accepted += 1;
                stream
                    .set_nodelay(true)
                    .map_err(|error| Error::Transport(format!("nodelay: {error}")))?;
                active.spawn(serve_connection(
                    stream,
                    Arc::clone(&handler),
                    Arc::clone(&served),
                    limits,
                ));
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
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    H: FnMut(Envelope) -> Envelope + Send + 'static,
{
    let mut connection = h2::server::handshake(io)
        .await
        .map_err(|error| Error::Transport(format!("h2 handshake: {error}")))?;
    // Streams are handled concurrently; the join set keeps the connection alive
    // until every response has been written.
    let mut streams = tokio::task::JoinSet::new();
    while let Some(request) = connection.accept().await {
        let (request, respond) = match request {
            Ok(parts) => parts,
            Err(error) => {
                return Err(Error::Transport(format!("h2 accept: {error}")));
            }
        };
        let handler = Arc::clone(&handler);
        let served = Arc::clone(&served);
        streams.spawn(async move {
            let handled = handle_stream(request, respond, handler, limits).await?;
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
) -> Result<bool>
where
    H: FnMut(Envelope) -> Envelope,
{
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
    // The caller's wire ceiling bounds the body; `MAX_BODY` is the hard cap.
    let ceiling = limits.max_bytes.min(MAX_BODY);
    loop {
        match body.data().await {
            Some(Ok(chunk)) => {
                if bytes.len() + chunk.len() > ceiling {
                    return respond_status(
                        &mut respond,
                        StatusCode::PAYLOAD_TOO_LARGE,
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
    let response = {
        // A kernel handler is single-threaded and may block on the kernel
        // loop; `block_in_place` moves the runtime worker aside instead of
        // stalling every other stream on this runtime.
        tokio::task::block_in_place(|| {
            let mut handler = match handler.lock() {
                Ok(handler) => handler,
                Err(poisoned) => poisoned.into_inner(),
            };
            handler(envelope)
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
    let head = Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, CONTENT_TYPE)
        .header(http::header::CONTENT_LENGTH, encoded.len())
        .body(())
        .map_err(|error| Error::Transport(format!("response head: {error}")))?;
    let mut send = respond
        .send_response(head, false)
        .map_err(|error| Error::Transport(format!("send response: {error}")))?;
    send.send_data(Bytes::from(encoded), true)
        .map_err(|error| Error::Transport(format!("send body: {error}")))?;
    Ok(true)
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

/// An HTTP/2 client that reuses one connection for every call.
pub struct Http2Client {
    runtime: tokio::runtime::Runtime,
    sender: h2::client::SendRequest<Bytes>,
    task: tokio::task::JoinHandle<()>,
    address: String,
    limits: WireLimits,
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
            let (sender, connection) = h2::client::handshake(stream)
                .await
                .map_err(|error| Error::Transport(format!("h2 handshake: {error}")))?;
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
        })
    }

    /// Use tighter wire limits.
    pub fn with_limits(mut self, limits: WireLimits) -> Self {
        self.limits = limits;
        self
    }

    /// The address this client dials.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Send one call and decode the response.
    pub fn call(&mut self, envelope: &Envelope) -> Result<Envelope> {
        let body = envelope.encode()?;
        let (status, response) = self.request(PATH, CONTENT_TYPE, &body)?;
        if status != StatusCode::OK {
            let code = String::from_utf8_lossy(&response).trim().to_string();
            return Err(match code.as_str() {
                "rpc/wire" => Error::Wire("HTTP/2 peer rejected the frame"),
                other => Error::Provider {
                    code: other.to_string(),
                },
            });
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
        let responses = self.runtime.block_on(async move {
            let mut tasks = Vec::with_capacity(payloads.len());
            for body in payloads {
                let mut sender = sender.clone();
                tasks.push(tokio::spawn(async move {
                    let request = Request::builder()
                        .method(Method::POST)
                        .uri(PATH)
                        .header(http::header::CONTENT_TYPE, CONTENT_TYPE)
                        .body(())
                        .map_err(|error| Error::Transport(format!("request: {error}")))?;
                    let (response, mut send) = sender
                        .send_request(request, false)
                        .map_err(|error| Error::Transport(format!("send header: {error}")))?;
                    send.send_data(Bytes::from(body), true)
                        .map_err(|error| Error::Transport(format!("send body: {error}")))?;
                    let response = response
                        .await
                        .map_err(|error| Error::Transport(format!("response: {error}")))?;
                    read_response(response, limits.max_bytes.min(MAX_BODY)).await
                }));
            }
            let mut out = Vec::with_capacity(tasks.len());
            for task in tasks {
                let (status, body) = task
                    .await
                    .map_err(|error| Error::Transport(format!("stream task: {error}")))??;
                if status != StatusCode::OK {
                    let code = String::from_utf8_lossy(&body).trim().to_string();
                    out.push(Err(match code.as_str() {
                        "rpc/wire" => Error::Wire("HTTP/2 peer rejected the frame"),
                        other => Error::Provider {
                            code: other.to_string(),
                        },
                    }));
                } else {
                    out.push(Envelope::decode_with(&body, limits));
                }
            }
            Ok::<_, Error>(out)
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
        self.request(path, content_type, body)
    }

    fn request(
        &mut self,
        path: &str,
        content_type: &str,
        body: &[u8],
    ) -> Result<(StatusCode, Vec<u8>)> {
        let mut sender = self.sender.clone();
        let request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(http::header::CONTENT_TYPE, content_type)
            .body(())
            .map_err(|error| Error::Transport(format!("request: {error}")))?;
        let payload = Bytes::copy_from_slice(body);
        let limits = self.limits;
        self.runtime.block_on(async move {
            let (response, mut send) = sender
                .send_request(request, false)
                .map_err(|error| Error::Transport(format!("send header: {error}")))?;
            send.send_data(payload, true)
                .map_err(|error| Error::Transport(format!("send body: {error}")))?;
            let response = response
                .await
                .map_err(|error| Error::Transport(format!("response: {error}")))?;
            read_response(response, limits.max_bytes.min(MAX_BODY)).await
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
) -> Result<(StatusCode, Vec<u8>)> {
    let status = response.status();
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    loop {
        match body.data().await {
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
