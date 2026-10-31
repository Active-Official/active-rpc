//! QUIC transport (feature `quic`).
//!
//! Real QUIC over UDP on loopback: a self-signed certificate, a quinn endpoint,
//! one bidirectional stream per call, and the same capability-bearing envelope
//! every other transport carries. Multiplexing and 0-RTT are QUIC's own; this
//! module only adds framing.
//!
//! Two server modes exist:
//!
//! - [`QuicServer::start`] is the development mode: a self-signed server
//!   certificate, no client certificate. It is convenient on loopback and must
//!   not be used for a listener reachable off-host.
//! - [`QuicServer::start_mutual_tls`] verifies a client certificate against a
//!   generated CA and hands the authenticated [`PeerIdentity`] to the handler,
//!   which is what capability binding needs (see [`crate::identity`]).
//!
//! The tests start a real server, move an Infinity payload plus a capability
//! table, prove a malformed frame is answered with an error envelope rather than
//! a panic, and prove two client certificates produce two distinct identities.
//!
//! Concurrency: the endpoint accepts continuously and drives every connection in
//! its own task. A peer that connects and then goes quiet therefore holds one
//! connection slot (`MAX_CONNECTIONS`) instead of the accept loop, which is what
//! lets one agent's long-lived session coexist with the next agent's handshake.
//!
//! TLS is self-signed and loopback-only by design: internet-scale QUIC (public
//! CA, NAT traversal, load balancing) is explicitly out of scope.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::error::{Error, Result};
use crate::identity::PeerIdentity;
use crate::transport::{frame, read_frame, MAX_FRAME_BYTES};
use crate::wire::{Envelope, WireLimits};

/// A running QUIC server.
pub struct QuicServer {
    address: String,
    certificate: CertificateDer<'static>,
    /// Trust root clients must use (the test CA or a deployment CA).
    ca: Option<CertificateDer<'static>>,
    /// The in-process test CA, when this server minted one.
    test_ca: Option<TestCa>,
    client: Option<(CertificateDer<'static>, PrivateKeyDer<'static>)>,
    runtime: tokio::runtime::Runtime,
    endpoint: quinn::Endpoint,
    task: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for QuicServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicServer")
            .field("address", &self.address)
            .field("mutual_tls", &self.ca.is_some())
            .finish()
    }
}

impl QuicServer {
    /// Bind a loopback server that answers `handler` for every call.
    ///
    /// `max_calls` stops the server after that many calls (0 = run until closed).
    pub fn start<H>(max_calls: usize, mut handler: H) -> Result<QuicServer>
    where
        H: FnMut(Envelope) -> Envelope + Send + 'static,
    {
        Self::start_inner(max_calls, move |envelope, _peer| handler(envelope), false)
    }

    /// Bind a loopback server that requires a client certificate.
    ///
    /// The handler receives the authenticated peer identity. The client verifier
    /// refuses a handshake that carries no certificate, so a successful call
    /// always carries `Some(identity)`.
    pub fn start_mutual_tls<H>(max_calls: usize, handler: H) -> Result<QuicServer>
    where
        H: FnMut(Envelope, Option<PeerIdentity>) -> Envelope + Send + 'static,
    {
        Self::start_inner(max_calls, handler, true)
    }

    fn start_inner<H>(max_calls: usize, handler: H, mutual: bool) -> Result<QuicServer>
    where
        H: FnMut(Envelope, Option<PeerIdentity>) -> Envelope + Send + 'static,
    {
        let mut ca = None;
        let mut test_ca = None;
        let mut client = None;
        let (server_config, certificate) = if mutual {
            let material = mutual_tls_material()?;
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(material.ca.der.clone())
                .map_err(|error| Error::Transport(format!("client roots: {error}")))?;
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|error| Error::Transport(format!("client verifier: {error}")))?;
            let tls = rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(
                    vec![material.server.clone()],
                    material.server_key.clone_key(),
                )
                .map_err(|error| Error::Transport(format!("server tls: {error}")))?;
            let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
                .map_err(|error| Error::Transport(format!("quic config: {error}")))?;
            let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
            config.transport_config(Arc::new(transport_config()));
            client = Some((material.client.clone(), material.client_key));
            ca = Some(material.ca.der.clone());
            test_ca = Some(material.ca);
            (config, material.server)
        } else {
            let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                .map_err(|error| Error::Transport(format!("certificate: {error}")))?;
            let certificate = CertificateDer::from(certified.cert.der().to_vec());
            let key =
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
            let mut config = quinn::ServerConfig::with_single_cert(vec![certificate.clone()], key)
                .map_err(|error| Error::Transport(format!("server config: {error}")))?;
            config.transport_config(Arc::new(transport_config()));
            (config, certificate)
        };
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
            ca,
            test_ca,
            client,
            runtime,
            endpoint,
            task,
        })
    }
}

/// A deployment-supplied server identity: the certificate chain and its key.
///
/// The test server generates its own certificate; a deployment passes the
/// certificate its own CA issued, so clients can verify the server against the
/// trust root they already have.
pub struct ServerIdentity {
    /// Certificate chain, leaf first.
    pub chain: Vec<CertificateDer<'static>>,
    /// Private key for the leaf certificate.
    pub key: PrivateKeyDer<'static>,
}

impl QuicServer {
    /// Bind a server on `bind` with a deployment certificate and, optionally,
    /// mutual TLS rooted at `client_ca`.
    ///
    /// Unlike [`QuicServer::start_mutual_tls`], no certificate authority is
    /// generated and no client credentials are minted: the deployment owns its
    /// CA and its certificates. `client_ca` turns client authentication on; a
    /// client that presents no certificate, or one from another CA, fails the
    /// handshake.
    pub fn start_with_identity<H>(
        max_calls: usize,
        handler: H,
        bind: std::net::SocketAddr,
        identity: ServerIdentity,
        client_ca: Option<CertificateDer<'static>>,
    ) -> Result<QuicServer>
    where
        H: FnMut(Envelope, Option<PeerIdentity>) -> Envelope + Send + 'static,
    {
        if identity.chain.is_empty() {
            return Err(Error::Transport(
                "server identity has no certificate".to_string(),
            ));
        }
        let certificate = identity.chain[0].clone();
        let tls = match &client_ca {
            Some(ca) => {
                let mut roots = rustls::RootCertStore::empty();
                roots
                    .add(ca.clone())
                    .map_err(|error| Error::Transport(format!("client trust root: {error}")))?;
                let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .map_err(|error| Error::Transport(format!("client verifier: {error}")))?;
                rustls::ServerConfig::builder()
                    .with_client_cert_verifier(verifier)
                    .with_single_cert(identity.chain, identity.key)
                    .map_err(|error| Error::Transport(format!("server tls: {error}")))?
            }
            None => rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(identity.chain, identity.key)
                .map_err(|error| Error::Transport(format!("server tls: {error}")))?,
        };
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|error| Error::Transport(format!("quic config: {error}")))?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        config.transport_config(Arc::new(transport_config()));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| Error::Transport(format!("runtime: {error}")))?;
        let endpoint = runtime
            .block_on(async { quinn::Endpoint::server(config, bind) })
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
            ca: client_ca,
            test_ca: None,
            client: None,
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

    /// The certificate authority a mutual-TLS client must trust.
    pub fn ca_certificate(&self) -> Option<&CertificateDer<'static>> {
        self.ca.as_ref()
    }

    /// A client certificate and key signed by this server's CA.
    pub fn client_credentials(&self) -> Option<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
        self.client
            .as_ref()
            .map(|(certificate, key)| (certificate.clone(), key.clone_key()))
    }

    /// Issue another client certificate from this server's test CA.
    ///
    /// Used to prove that two distinct peers receive distinct identities. The CA
    /// is generated in-process and lives only for this server, so this is a
    /// single-host facility, not a certificate authority for a deployment.
    pub fn issue_client_credentials(
        &self,
        subject: &str,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
        let ca = self.test_ca.as_ref().ok_or(Error::TransportUnavailable(
            "server has no mutual-TLS certificate authority",
        ))?;
        ca.issue_client(subject)
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

    /// Wait for the server to serve its call budget and close on its own.
    ///
    /// The serving task drains the last response before it closes the endpoint,
    /// so this is the graceful counterpart to [`QuicServer::shutdown`]. It
    /// returns only after the task finished; a server started with
    /// `max_calls == 0` never returns on its own.
    pub fn wait(self) {
        let runtime = self.runtime;
        let endpoint = self.endpoint;
        let task = self.task;
        runtime.block_on(async {
            let _ = task.await;
            endpoint.wait_idle().await;
        });
    }
}

struct MutualMaterial {
    ca: TestCa,
    server: CertificateDer<'static>,
    server_key: PrivateKeyDer<'static>,
    client: CertificateDer<'static>,
    client_key: PrivateKeyDer<'static>,
}

/// A throwaway certificate authority for loopback mutual TLS.
///
/// The key exists so a test can issue a second client certificate and prove two
/// peers receive different identities. It never leaves the process and is not a
/// deployment CA: a real deployment supplies CA-signed certificates and a
/// verifier rooted in its own trust store.
struct TestCa {
    certificate: rcgen::Certificate,
    /// DER encoding of `certificate`, for trust stores.
    der: CertificateDer<'static>,
    key: rcgen::KeyPair,
}

impl TestCa {
    fn issue_client(
        &self,
        subject: &str,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
        use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair};
        if subject.is_empty() {
            return Err(Error::InvalidArgument(
                "a client certificate needs a subject",
            ));
        }
        let mut params = CertificateParams::new(Vec::new())
            .map_err(|error| Error::Transport(format!("client params: {error}")))?;
        params.distinguished_name.push(DnType::CommonName, subject);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let key = KeyPair::generate()
            .map_err(|error| Error::Transport(format!("client key: {error}")))?;
        let certificate = params
            .signed_by(&key, &self.certificate, &self.key)
            .map_err(|error| Error::Transport(format!("client cert: {error}")))?;
        Ok((
            CertificateDer::from(certificate.der().to_vec()),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        ))
    }
}

/// A throwaway CA with one server certificate and one client certificate.
fn mutual_tls_material() -> Result<MutualMaterial> {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    };

    let mut ca_params = CertificateParams::new(Vec::new())
        .map_err(|error| Error::Transport(format!("ca params: {error}")))?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "active-rpc test ca");
    let ca_key =
        KeyPair::generate().map_err(|error| Error::Transport(format!("ca key: {error}")))?;
    let ca_certificate = ca_params
        .self_signed(&ca_key)
        .map_err(|error| Error::Transport(format!("ca cert: {error}")))?;
    let der = CertificateDer::from(ca_certificate.der().to_vec());
    let ca = TestCa {
        certificate: ca_certificate,
        der,
        key: ca_key,
    };

    let mut server_params = CertificateParams::new(vec!["localhost".to_string()])
        .map_err(|error| Error::Transport(format!("server params: {error}")))?;
    server_params
        .distinguished_name
        .push(DnType::CommonName, "active-rpc server");
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key =
        KeyPair::generate().map_err(|error| Error::Transport(format!("server key: {error}")))?;
    let server = server_params
        .signed_by(&server_key, &ca.certificate, &ca.key)
        .map_err(|error| Error::Transport(format!("server cert: {error}")))?;

    let (client, client_key) = ca.issue_client("active-rpc client")?;

    Ok(MutualMaterial {
        ca,
        server: CertificateDer::from(server.der().to_vec()),
        server_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        client,
        client_key,
    })
}

/// Concurrent connections one server keeps open before it stops accepting.
///
/// A depleted slot drops the incoming connection, so a flood of half-open
/// handshakes costs one task each up to this bound and nothing beyond it.
const MAX_CONNECTIONS: usize = 256;

async fn serve<H>(endpoint: quinn::Endpoint, handler: Arc<Mutex<H>>, max_calls: usize)
where
    H: FnMut(Envelope, Option<PeerIdentity>) -> Envelope + Send + 'static,
{
    let served = Arc::new(AtomicUsize::new(0));
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    while let Some(incoming) = endpoint.accept().await {
        // Each connection is driven in its own task. `incoming.await` is where
        // an abandoned or refused handshake parks for its timeout; awaiting it
        // inline would hold the accept loop and stall every other peer.
        let permit = match Arc::clone(&slots).try_acquire_owned() {
            Ok(permit) => permit,
            // At the cap: dropping `incoming` closes the connection.
            Err(_) => continue,
        };
        let handler = Arc::clone(&handler);
        let served = Arc::clone(&served);
        let endpoint = endpoint.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let connection = match incoming.await {
                Ok(connection) => connection,
                Err(_) => return,
            };
            serve_connection(&endpoint, &handler, &served, max_calls, connection).await;
        });
    }
}

async fn serve_connection<H>(
    endpoint: &quinn::Endpoint,
    handler: &Arc<Mutex<H>>,
    served: &AtomicUsize,
    max_calls: usize,
    connection: quinn::Connection,
) where
    H: FnMut(Envelope, Option<PeerIdentity>) -> Envelope,
{
    let peer = peer_identity(&connection);
    loop {
        let (mut send, mut recv) = match connection.accept_bi().await {
            Ok(stream) => stream,
            Err(_) => return,
        };
        let request = match recv.read_to_end(MAX_FRAME_BYTES).await {
            Ok(bytes) => bytes,
            Err(_) => {
                // The stream failed mid-frame. Answering with an error
                // envelope is best-effort (the peer may be gone), but it
                // gives a live peer a stable code instead of silence.
                let response = Envelope::error(0, &Error::Wire("stream read failed"));
                let _ = send_envelope(&mut send, &response).await;
                let _ = send.finish();
                return;
            }
        };
        let envelope = match decode_call(&request) {
            Ok(envelope) => envelope,
            Err(error) => {
                let response = Envelope::error(0, &error);
                let _ = send_envelope(&mut send, &response).await;
                let _ = send.finish();
                let _ = tokio::time::timeout(std::time::Duration::from_millis(250), send.stopped())
                    .await;
                if exhausted(served, max_calls) {
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
            handler(envelope, peer.clone())
        };
        let _ = send_envelope(&mut send, &response).await;
        let _ = send.finish();
        if exhausted(served, max_calls) {
            // Give the peer a moment to drain the stream before the endpoint
            // closes; closing first would abort the response.
            let _ =
                tokio::time::timeout(std::time::Duration::from_millis(250), send.stopped()).await;
            endpoint.close(0u32.into(), b"served");
            return;
        }
    }
}

/// Count one served call and report whether the server's budget is spent.
fn exhausted(served: &AtomicUsize, max_calls: usize) -> bool {
    let total = served.fetch_add(1, Ordering::SeqCst) + 1;
    max_calls != 0 && total >= max_calls
}

/// The authenticated identity of a QUIC peer, when the session carried a
/// certificate.
///
/// Only a certificate the TLS stack verified reaches this function: an
/// unauthenticated session has no peer certificate and yields `None`.
pub fn peer_identity(connection: &quinn::Connection) -> Option<PeerIdentity> {
    let any = connection.peer_identity()?;
    let chain = any.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    let leaf = chain.first()?;
    Some(PeerIdentity::from_certificate(leaf.as_ref()))
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
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(certificate.clone())
            .map_err(|error| Error::Transport(format!("trust: {error}")))?;
        let mut client_config = quinn::ClientConfig::with_root_certificates(Arc::new(roots))
            .map_err(|error| Error::Transport(format!("client config: {error}")))?;
        client_config.transport_config(Arc::new(transport_config()));
        Self::from_config(address, client_config)
    }

    /// Connect with mutual TLS: trust `ca`, present `certificate` and `key`.
    ///
    /// This is the client half of [`QuicServer::start_mutual_tls`]. The server
    /// sees [`PeerIdentity::from_certificate`] for this certificate, which is
    /// what a bound capability compares against.
    pub fn connect_mutual_tls(
        address: &str,
        ca: &CertificateDer<'static>,
        certificate: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(ca.clone())
            .map_err(|error| Error::Transport(format!("trust: {error}")))?;
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![certificate], key)
            .map_err(|error| Error::Transport(format!("client auth: {error}")))?;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|error| Error::Transport(format!("client quic config: {error}")))?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        client_config.transport_config(Arc::new(transport_config()));
        Self::from_config(address, client_config)
    }

    fn from_config(address: &str, client_config: quinn::ClientConfig) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| Error::Transport(format!("runtime: {error}")))?;
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
