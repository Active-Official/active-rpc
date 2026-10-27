//! QUIC transport (feature `quic`).
//!
//! Real QUIC over UDP on loopback: a self-signed certificate, a quinn endpoint,
//! one bidirectional stream per call, and the same capability-bearing envelope
//! every other transport carries. Multiplexing and 0-RTT are QUIC's own; this
//! module only adds framing.
//!
//! The tests start a server, move a real Infinity payload plus a capability
//! table, prove a malformed frame is answered with an error envelope rather than
//! a panic, and run an agent-to-agent pipelined call over the wire.
//!
//! TLS is self-signed and loopback-only by design: internet-scale QUIC (public
//! CA, NAT traversal, load balancing) is explicitly out of scope.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::error::{Error, Result};
use crate::transport::{frame, read_frame, MAX_FRAME_BYTES};
use crate::wire::{Envelope, WireLimits};

/// A running QUIC server.
pub struct QuicServer {
    address: String,
    certificate: CertificateDer<'static>,
    runtime: tokio::runtime::Runtime,
    endpoint: quinn::Endpoint,
    task: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for QuicServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicServer")
            .field("address", &self.address)
            .finish()
    }
}

impl QuicServer {
    /// Bind a loopback server that answers `handler` for every call.
    ///
    /// `max_calls` stops the server after that many calls (0 = run until closed).
    pub fn start<H>(max_calls: usize, handler: H) -> Result<QuicServer>
    where
        H: FnMut(Envelope) -> Envelope + Send + 'static,
    {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .map_err(|error| Error::Transport(format!("certificate: {error}")))?;
        let certificate = CertificateDer::from(certified.cert.der().to_vec());
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let mut server_config =
            quinn::ServerConfig::with_single_cert(vec![certificate.clone()], key)
                .map_err(|error| Error::Transport(format!("server config: {error}")))?;
        server_config.transport_config(Arc::new(transport_config()));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| Error::Transport(format!("runtime: {error}")))?;
        let address: SocketAddr = "127.0.0.1:0".parse().expect("static loopback address");
        let endpoint = runtime
            .block_on(async { quinn::Endpoint::server(server_config, address) })
            .map_err(|error| Error::Transport(format!("bind: {error}")))?;
        let bound = endpoint
            .local_addr()
            .map_err(|error| Error::Transport(format!("local addr: {error}")))?
            .to_string();
        let handler = Arc::new(Mutex::new(handler));
        let endpoint_for_task = endpoint.clone();
        let task = runtime.spawn(async move {
            serve(endpoint_for_task, handler, max_calls).await;
        });
        Ok(QuicServer {
            address: bound,
            certificate,
            runtime,
            endpoint,
            task,
        })
    }

    /// The bound address (`host:port`).
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The self-signed certificate a client must trust.
    pub fn certificate(&self) -> &CertificateDer<'static> {
        &self.certificate
    }

    /// Stop the server and wait for the task.
    pub fn shutdown(self) {
        self.endpoint.close(0u32.into(), b"done");
        let runtime = self.runtime;
        let endpoint = self.endpoint;
        let task = self.task;
        runtime.block_on(async {
            let _ = task.await;
            endpoint.wait_idle().await;
        });
    }
}

async fn serve<H>(endpoint: quinn::Endpoint, handler: Arc<Mutex<H>>, max_calls: usize)
where
    H: FnMut(Envelope) -> Envelope + Send + 'static,
{
    let mut served = 0usize;
    while let Some(incoming) = endpoint.accept().await {
        let handler = Arc::clone(&handler);
        let connection = match incoming.await {
            Ok(connection) => connection,
            Err(_) => continue,
        };
        loop {
            let (mut send, mut recv) = match connection.accept_bi().await {
                Ok(stream) => stream,
                Err(_) => break,
            };
            let request = match recv.read_to_end(MAX_FRAME_BYTES).await {
                Ok(bytes) => bytes,
                Err(_) => break,
            };
            let envelope = match decode_call(&request) {
                Ok(envelope) => envelope,
                Err(error) => {
                    let response = Envelope::error(0, &error);
                    let _ = send_envelope(&mut send, &response).await;
                    let _ = send.finish();
                    let _ =
                        tokio::time::timeout(std::time::Duration::from_millis(250), send.stopped())
                            .await;
                    served += 1;
                    if max_calls != 0 && served >= max_calls {
                        endpoint.close(0u32.into(), b"served");
                        return;
                    }
                    continue;
                }
            };
            let response = {
                let mut handler = match handler.lock() {
                    Ok(handler) => handler,
                    Err(poisoned) => poisoned.into_inner(),
                };
                handler(envelope)
            };
            let _ = send_envelope(&mut send, &response).await;
            let _ = send.finish();
            served += 1;
            if max_calls != 0 && served >= max_calls {
                // Give the peer a moment to drain the stream before the
                // endpoint closes; closing first would abort the response.
                let _ = tokio::time::timeout(std::time::Duration::from_millis(250), send.stopped())
                    .await;
                endpoint.close(0u32.into(), b"served");
                return;
            }
        }
    }
}

fn decode_call(bytes: &[u8]) -> Result<Envelope> {
    let mut cursor = std::io::Cursor::new(bytes);
    let body =
        read_frame(&mut cursor, &WireLimits::default())?.ok_or(Error::Wire("empty QUIC call"))?;
    Envelope::decode_with(&body, WireLimits::default())
}

async fn send_envelope(send: &mut quinn::SendStream, envelope: &Envelope) -> Result<()> {
    let bytes = envelope.encode()?;
    let mut payload = Vec::with_capacity(bytes.len() + 4);
    payload.extend_from_slice(&frame(bytes.len())?);
    payload.extend_from_slice(&bytes);
    send.write_all(&payload)
        .await
        .map_err(|error| Error::Transport(format!("write: {error}")))
}

/// A client that speaks the QUIC transport.
pub struct QuicClient {
    runtime: tokio::runtime::Runtime,
    endpoint: quinn::Endpoint,
    address: SocketAddr,
    server_name: String,
}

impl QuicClient {
    /// Connect, trusting `certificate` for `localhost`.
    pub fn connect(address: &str, certificate: &CertificateDer<'static>) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| Error::Transport(format!("runtime: {error}")))?;
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(certificate.clone())
            .map_err(|error| Error::Transport(format!("trust: {error}")))?;
        let mut client_config = quinn::ClientConfig::with_root_certificates(Arc::new(roots))
            .map_err(|error| Error::Transport(format!("client config: {error}")))?;
        client_config.transport_config(Arc::new(transport_config()));
        let address: SocketAddr = address
            .parse()
            .map_err(|_| Error::Transport("invalid QUIC address".to_string()))?;
        let mut endpoint = runtime
            .block_on(async { quinn::Endpoint::client("127.0.0.1:0".parse().expect("loopback")) })
            .map_err(|error| Error::Transport(format!("client endpoint: {error}")))?;
        endpoint.set_default_client_config(client_config);
        Ok(QuicClient {
            runtime,
            endpoint,
            address,
            server_name: "localhost".to_string(),
        })
    }

    /// Send one call and read the response.
    pub fn call(&self, envelope: &Envelope) -> Result<Envelope> {
        let bytes = envelope.encode()?;
        let mut payload = Vec::with_capacity(bytes.len() + 4);
        payload.extend_from_slice(&frame(bytes.len())?);
        payload.extend_from_slice(&bytes);
        let response = self.exchange(&payload)?;
        let mut cursor = std::io::Cursor::new(&response);
        let body = read_frame(&mut cursor, &WireLimits::default())?
            .ok_or(Error::Wire("empty QUIC response"))?;
        Envelope::decode_with(&body, WireLimits::default())
    }

    /// Send raw bytes (for malformed-frame tests) and return the raw response.
    pub fn exchange(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let (endpoint, address, server_name) = (
            self.endpoint.clone(),
            self.address,
            self.server_name.clone(),
        );
        let request = payload.to_vec();
        self.runtime.block_on(async move {
            let connection = endpoint
                .connect(address, &server_name)
                .map_err(|error| Error::Transport(format!("connect: {error}")))?
                .await
                .map_err(|error| Error::Transport(format!("handshake: {error}")))?;
            let (mut send, mut recv) = connection
                .open_bi()
                .await
                .map_err(|error| Error::Transport(format!("open stream: {error}")))?;
            send.write_all(&request)
                .await
                .map_err(|error| Error::Transport(format!("write: {error}")))?;
            send.finish()
                .map_err(|error| Error::Transport(format!("finish: {error}")))?;
            let response = recv
                .read_to_end(MAX_FRAME_BYTES)
                .await
                .map_err(|error| Error::Transport(format!("read: {error}")))?;
            connection.close(0u32.into(), b"done");
            Ok(response)
        })
    }
}

/// Keep-alive and idle settings suitable for agent traffic.
fn transport_config() -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    config.max_idle_timeout(Some(
        std::time::Duration::from_secs(30)
            .try_into()
            .expect("valid idle timeout"),
    ));
    config
}
