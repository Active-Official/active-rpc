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
    /// Wire limits for a decoded call. Shared with the serve task so
    /// [`QuicServer::with_limits`] applies to the next stream.
    limits: Arc<std::sync::RwLock<WireLimits>>,
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
        let limits = Arc::new(std::sync::RwLock::new(WireLimits::default()));
        let limits_for_task = Arc::clone(&limits);
        let task = runtime.spawn(async move {
            serve(endpoint_for_task, handler, max_calls, limits_for_task).await;
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
            limits,
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
        // Without a client CA every peer is anonymous, and an anonymous listener
        // reachable off-host serves anyone. The loopback bind is the only place
        // that is a deliberate choice; anything else must say `client_ca`.
        if client_ca.is_none() && !bind.ip().is_loopback() {
            return Err(Error::Transport(
                "an unauthenticated QUIC listener must bind a loopback address".to_string(),
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
        let limits = Arc::new(std::sync::RwLock::new(WireLimits::default()));
        let limits_for_task = Arc::clone(&limits);
        let task = runtime.spawn(async move {
            serve(endpoint_for_task, handler, max_calls, limits_for_task).await;
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
            limits,
        })
    }

    /// Tighten the wire limits applied to a decoded call.
    ///
    /// The serve task reads this through a lock per stream, so a value set here
    /// applies to every later call on the server.
    pub fn with_limits(self, limits: WireLimits) -> Self {
        *self
            .limits
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = limits;
        self
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

/// How long a handshake may hold a slot before it is abandoned.
///
/// Without it a peer that opens the handshake and stops holds one of
/// `MAX_CONNECTIONS` slots forever, and a few hundred such peers lock every
/// later one out.
pub const HANDSHAKE_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long one stream may take to deliver its frame.
///
/// The transport reads a stream before accepting the next one on a connection,
/// so a peer that sends four bytes and stops would otherwise park that
/// connection's traffic forever.
pub const STREAM_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Default wall ceiling for one client exchange when the caller sets none.
///
/// Three times `STREAM_WAIT`: a handshake, a write and a read each have their
/// own bound, and the whole exchange needs one (round 9, R-09 #9).
pub const DEFAULT_QUIC_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long to wait for a FIN after the frame, to notice trailing bytes.
///
/// A client that sends one frame closes the stream at once, so this is short. A
/// peer that sends a frame and keeps the stream open is treated as having sent
/// no trailing bytes; the alternative is waiting `STREAM_WAIT` on every call.
pub const STREAM_TAIL_WAIT: std::time::Duration = std::time::Duration::from_millis(250);

/// Body bytes every live stream may hold at once.
///
/// The stream and connection windows bound what a peer can pin *before* we read
/// it; this bounds what the server itself buffers after reading, across every
/// connection. 64 MiB per stream times 256 connections would be 16 GiB of
/// memory an unauthenticated peer could ask for.
pub const MAX_INFLIGHT_BODY: usize = 256 << 20;

/// Concurrent bidirectional streams (calls) one QUIC connection may carry.
pub const MAX_CONCURRENT_STREAMS: u32 = 256;
/// Receive window for one stream: bounded buffering per call.
pub const STREAM_RECEIVE_WINDOW: u32 = 1 << 20;
/// Receive window for one connection: the real cap on buffered bytes.
pub const CONNECTION_RECEIVE_WINDOW: u32 = 8 << 20;

async fn serve<H>(
    endpoint: quinn::Endpoint,
    handler: Arc<Mutex<H>>,
    max_calls: usize,
    limits: Arc<std::sync::RwLock<WireLimits>>,
) where
    H: FnMut(Envelope, Option<PeerIdentity>) -> Envelope + Send + 'static,
{
    let served = Arc::new(AtomicUsize::new(0));
    // Calls admitted and not yet answered. The endpoint closes when the budget
    // is spent *and* this reaches zero: closing on the first stream that
    // finished aborted a concurrent call's reply on another connection
    // (round 47; a CI flake in `quic_dispatches_a_bound_capability_only_for_the_bound_peer`).
    let active = Arc::new(AtomicUsize::new(0));
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    // Body bytes every live stream holds, across every connection.
    let inflight = Arc::new(AtomicUsize::new(0));
    // Encoded reply bytes held while a peer's flow-control credit is exhausted:
    // a stream with no receive window parks its whole reply for STREAM_WAIT,
    // and without a shared ceiling one peer could park tens of GiB (round 19,
    // R-9#2).
    let inflight_out = Arc::new(AtomicUsize::new(0));
    while let Some(incoming) = endpoint.accept().await {
        // Each connection is driven in its own task. `incoming.await` is where
        // an abandoned or refused handshake parks for its timeout; awaiting it
        // inline would hold the accept loop and stall every other peer.
        //
        // A full table drops the incoming connection instead of parking the
        // accept loop: waiting here let ~256 cheap connections (or half-open
        // handshakes) stop the listener for every peer, because each newcomer
        // blocked the loop for `HANDSHAKE_WAIT` in turn. Dropping is the
        // backpressure signal; the client retries.
        let permit = match Arc::clone(&slots).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => continue,
        };
        let handler = Arc::clone(&handler);
        let served = Arc::clone(&served);
        let endpoint = endpoint.clone();
        let limits = Arc::clone(&limits);
        let inflight = Arc::clone(&inflight);
        let inflight_out = Arc::clone(&inflight_out);
        let active = Arc::clone(&active);
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(connection) = tokio::time::timeout(HANDSHAKE_WAIT, incoming).await else {
                return;
            };
            let connection = match connection {
                Ok(connection) => connection,
                Err(_) => return,
            };
            serve_connection(
                &endpoint,
                &handler,
                &served,
                &active,
                max_calls,
                &limits,
                &inflight,
                &inflight_out,
                connection,
            )
            .await;
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_connection<H>(
    endpoint: &quinn::Endpoint,
    handler: &Arc<Mutex<H>>,
    served: &Arc<AtomicUsize>,
    active: &Arc<AtomicUsize>,
    max_calls: usize,
    limits: &Arc<std::sync::RwLock<WireLimits>>,
    inflight: &Arc<AtomicUsize>,
    inflight_out: &Arc<AtomicUsize>,
    connection: quinn::Connection,
) where
    H: FnMut(Envelope, Option<PeerIdentity>) -> Envelope + Send + 'static,
{
    let peer = peer_identity(&connection);
    // Streams are independent: a peer that opens one and never finishes it must
    // not park the calls on the other streams. Each runs on its own task with
    // its own read deadline.
    let mut streams = tokio::task::JoinSet::new();
    loop {
        // Reap finished streams before accepting another: `JoinSet` retains the
        // output of every task until it is joined, so a single long-lived
        // connection leaked about 2.4 KB per call (20 000 calls grew the server
        // by ~48 MB; round 14, F-1). HTTP/2 reaps the same way.
        while streams.try_join_next().is_some() {}
        let (send, recv) = match connection.accept_bi().await {
            Ok(stream) => stream,
            Err(_) => break,
        };
        let handler = Arc::clone(handler);
        let served = Arc::clone(served);
        let active = Arc::clone(active);
        let limits = Arc::clone(limits);
        let inflight = Arc::clone(inflight);
        let inflight_out = Arc::clone(inflight_out);
        let peer = peer.clone();
        let endpoint = endpoint.clone();
        streams.spawn(async move {
            serve_stream(
                &endpoint,
                handler,
                served,
                active,
                max_calls,
                limits,
                inflight,
                inflight_out,
                send,
                recv,
                peer,
            )
            .await;
        });
    }
    // Every stream carries its own deadline, so this drain is bounded.
    while streams.join_next().await.is_some() {}
}

/// One call on one bidirectional stream.
#[allow(clippy::too_many_arguments)]
async fn serve_stream<H>(
    endpoint: &quinn::Endpoint,
    handler: Arc<Mutex<H>>,
    served: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
    max_calls: usize,
    limits: Arc<std::sync::RwLock<WireLimits>>,
    inflight: Arc<AtomicUsize>,
    inflight_out: Arc<AtomicUsize>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    peer: Option<PeerIdentity>,
) where
    H: FnMut(Envelope, Option<PeerIdentity>) -> Envelope + Send + 'static,
{
    let wire = *limits
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Read the length prefix first: the announced size decides whether the body
    // is worth reserving, and nothing is buffered on the strength of four
    // unverified bytes beyond that decision.
    let mut header = [0u8; 4];
    let read = tokio::time::timeout(STREAM_WAIT, recv.read_exact(&mut header)).await;
    let prefix_fault = match read {
        Ok(Ok(())) => None,
        // A reset or a short read is a framing fault; a stall is a transport
        // condition the caller may retry (round 9, R-09 #8).
        Ok(Err(_)) => Some(Error::Wire("stream did not deliver a frame prefix")),
        Err(_) => Some(Error::Transport(
            "stream stalled before the frame prefix".to_string(),
        )),
    };
    if let Some(error) = prefix_fault {
        let response = Envelope::error(0, &error);
        reply(&mut send, &response).await;
        return;
    }
    let len = u32::from_le_bytes(header) as usize;
    let ceiling = wire.max_bytes.min(MAX_FRAME_BYTES);
    if len > ceiling {
        let error = Error::Wire("frame exceeds the size ceiling");
        let response = Envelope::error(0, &error);
        reply(&mut send, &response).await;
        return;
    }
    // The aggregate budget tracks bytes the server is actually holding. It is
    // reserved in steps as the body arrives: charging the announced length let
    // four idle streams that sent only a 4-byte header deny every other peer.
    let mut budget = BodyBudget::new(inflight.as_ref());
    let body = match read_frame_body(&mut recv, len, &mut budget).await {
        Ok(body) => body,
        Err(error) => {
            reply(&mut send, &Envelope::error(0, &error)).await;
            return;
        }
    };
    let envelope = match Envelope::decode_with(&body, wire) {
        Ok(envelope) => envelope,
        Err(error) => {
            reply(&mut send, &Envelope::error(0, &error)).await;
            let _ =
                tokio::time::timeout(std::time::Duration::from_millis(250), send.stopped()).await;
            return;
        }
    };
    // A response or error envelope is not a call.
    if envelope.kind != crate::wire::Kind::Request {
        let error = Error::Wire("a server only serves requests");
        let response = Envelope::error(envelope.request_id, &error);
        reply(&mut send, &response).await;
        return;
    }
    // One stream is one frame. A frame followed by more bytes would be a second
    // message the decoder never sees, so it is refused rather than ignored.
    //
    // The probe reads a byte, not to end-of-stream: `read_to_end` waits for the
    // peer to FINish, which held every response for the tail deadline even for
    // an honest peer that keeps the stream open for the reply.
    match tokio::time::timeout(STREAM_TAIL_WAIT, recv.read_chunk(1, true)).await {
        Ok(Ok(Some(chunk))) if !chunk.bytes.is_empty() => {
            let error = Error::Wire("trailing bytes after the QUIC frame");
            reply(&mut send, &Envelope::error(envelope.request_id, &error)).await;
            return;
        }
        _ => {}
    }
    // Admission control: count the slot before the handler runs. Counting
    // afterwards let concurrent streams all observe `served == 0` and overshoot
    // `max_calls` (audit ARPC-006).
    // Count this call as running before the admission decision: the closer
    // loads `served` and `active` separately, so a call admitted between the
    // two was invisible and the endpoint could close under it (round 14, F-3).
    active.fetch_add(1, Ordering::SeqCst);
    if max_calls != 0 {
        let mut current = served.load(Ordering::SeqCst);
        loop {
            if current >= max_calls {
                let error = Error::Transport("the server has served its calls".to_string());
                reply(&mut send, &Envelope::error(envelope.request_id, &error)).await;
                // No close here: an admitted call may still be running, and the
                // last one to finish closes the endpoint (round 47). This
                // stream is not admitted, but it was counted, so its decrement
                // may be the last one: without the same predicate here the
                // server stayed open forever after its budget was spent
                // (round 15, F-1).
                let running = active.fetch_sub(1, Ordering::SeqCst).saturating_sub(1);
                if running == 0 {
                    let _ = tokio::time::timeout(DRAIN_BEFORE_CLOSE, send.stopped()).await;
                    endpoint.close(0u32.into(), b"served");
                }
                return;
            }
            match served.compare_exchange(
                current,
                current.saturating_add(1),
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }
    // The guard decrements when this stream finishes on any path; the last one
    // to end closes the endpoint.
    let mut call = CallGuard {
        active: Arc::clone(&active),
        finished: false,
    };
    let request_id = envelope.request_id;
    // The handler is serialized by a `std::sync::Mutex`, so every other stream
    // parked on it would hold an async worker: on the default worker count one
    // slow provider call plus N streams froze the runtime, including this
    // server's driver and timers. `block_in_place` hands the parked worker back
    // to the runtime, as the HTTP/2 server already does (round 14, F-4).
    let guarded_handler = Arc::clone(&handler);
    let response = tokio::task::block_in_place(move || {
        let mut handler = match guarded_handler.lock() {
            Ok(handler) => handler,
            Err(poisoned) => poisoned.into_inner(),
        };
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(envelope, peer))) {
            Ok(response) => response,
            Err(_) => Envelope::error(
                request_id,
                &Error::Provider {
                    code: "rpc/provider".to_string(),
                },
            ),
        }
    });
    // The reply obeys the ceiling this server enforces on a request: a strict
    // profile must not emit a frame its own reader refuses (round 12, R-09 #2).
    let bytes = match response.encode_with_limits(wire) {
        // The handler ran: a reply past this server's own profile, or one that
        // cannot be encoded under it, is a withheld reply (round 18, R16-2).
        Ok(bytes) if bytes.len() > wire.max_bytes.min(MAX_FRAME_BYTES) => {
            let error = Error::Provider {
                code: "provider/reply-withheld".to_string(),
            };
            // Release the encoded reply before the awaits, as the budget arm
            // does: it is not charged and must not be held for STREAM_WAIT
            // (round 21, finding 1).
            drop(bytes);
            reply(&mut send, &Envelope::error(request_id, &error)).await;
            finish_call(&mut call, &served, max_calls, &mut send, endpoint).await;
            return;
        }
        Ok(bytes) => bytes,
        Err(_) => {
            let error = Error::Provider {
                code: "provider/reply-withheld".to_string(),
            };
            reply(&mut send, &Envelope::error(request_id, &error)).await;
            finish_call(&mut call, &served, max_calls, &mut send, endpoint).await;
            return;
        }
    };
    // A peer controls its own receive window: a response larger than the credit
    // it grants parks `write_all` forever, so every write is bounded below.
    // Charge the encoded reply against one shared ceiling before it is held for
    // a peer that may grant no flow-control credit; a reply that does not fit is
    // withheld rather than parked (round 19, R-9#2).
    let Some(_reply_budget) = ReplyBudget::try_reserve(&inflight_out, bytes.len()) else {
        let error = Error::Provider {
            code: "provider/reply-withheld".to_string(),
        };
        // Release the encoded reply before the await: otherwise the one reply
        // that was refused is the one held longest, outside every budget
        // (round 20, A).
        drop(bytes);
        reply(&mut send, &Envelope::error(request_id, &error)).await;
        finish_call(&mut call, &served, max_calls, &mut send, endpoint).await;
        return;
    };
    // Send the bytes encoded under this server's profile: encoding again inside
    // `reply` used the default profile (round 18, R16-6).
    reply_encoded(&mut send, &bytes).await;
    finish_call(&mut call, &served, max_calls, &mut send, endpoint).await;
}

/// Decrement the running count and, when the budget is spent and this was the
/// last admitted call, let the peer read the reply before closing the endpoint.
///
/// Every post-admission return path ends here, so an early refusal cannot leave
/// the server waiting for a close that never comes.
async fn finish_call(
    call: &mut CallGuard,
    served: &Arc<AtomicUsize>,
    max_calls: usize,
    send: &mut quinn::SendStream,
    endpoint: &quinn::Endpoint,
) {
    let running = call.finish();
    if max_calls != 0 && served.load(Ordering::SeqCst) >= max_calls && running == 0 {
        let _ = tokio::time::timeout(DRAIN_BEFORE_CLOSE, send.stopped()).await;
        endpoint.close(0u32.into(), b"served");
    }
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

/// Most body bytes one read step reserves.
///
/// The budget is charged per step as bytes arrive (and released when the body is
/// dropped), so an announcement alone reserves nothing.
const BODY_STEP: usize = 64 << 10;

/// A reservation against the server-wide QUIC body budget.
///
/// Bytes are added as they arrive and released only when the body is finished
/// with, so the aggregate bounds what every live stream actually holds.
struct BodyBudget<'a> {
    counter: &'a AtomicUsize,
    held: usize,
}

impl<'a> BodyBudget<'a> {
    fn new(counter: &'a AtomicUsize) -> Self {
        Self { counter, held: 0 }
    }

    fn reserve(&mut self, want: usize) -> Result<()> {
        // A compare-exchange loop, like the HTTP/2 `Reservation`: the earlier
        // increment-then-rollback let a transient overshoot refuse a caller that
        // would have fit (round 35, R-09 #4).
        let mut current = self.counter.load(Ordering::SeqCst);
        loop {
            if current.saturating_add(want) > MAX_INFLIGHT_BODY {
                return Err(Error::Backpressure("the server's QUIC body budget"));
            }
            match self.counter.compare_exchange(
                current,
                current + want,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        self.held += want;
        Ok(())
    }
}

impl Drop for BodyBudget<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(self.held, Ordering::SeqCst);
    }
}

/// Read exactly `len` body bytes in reserved steps.
///
/// Reading exactly the announced length (rather than to end-of-stream) means a
/// complete frame is answered without waiting for the peer to FINish, and a
/// stream longer than its announcement is caught by the trailing-byte probe.
async fn read_frame_body(
    recv: &mut quinn::RecvStream,
    len: usize,
    budget: &mut BodyBudget<'_>,
) -> Result<Vec<u8>> {
    // One deadline for the whole frame, not one per step: a peer that sends a
    // byte every few seconds keeps a per-step timeout alive forever.
    let deadline = tokio::time::Instant::now() + STREAM_WAIT;
    let mut body = Vec::new();
    let mut remaining = len;
    while remaining > 0 {
        let want = remaining.min(BODY_STEP);
        let chunk = match tokio::time::timeout_at(deadline, recv.read_chunk(want, true)).await {
            Ok(Ok(Some(chunk))) => chunk,
            // A short stream is a truncated frame; a reset is the peer's fault.
            Ok(Ok(None)) | Ok(Err(_)) => return Err(Error::Wire("truncated QUIC frame")),
            // The frame stalled past its deadline. The peer gets a stable code
            // instead of silence.
            Err(_) => return Err(Error::Transport("stream read timed out".to_string())),
        };
        let bytes = chunk.bytes;
        if bytes.is_empty() {
            return Err(Error::Wire("truncated QUIC frame"));
        }
        // Reserve what actually arrived. Charging a step before reading it let
        // 4096 stalled streams hold the whole budget while sending 4 bytes each.
        budget.reserve(bytes.len())?;
        body.try_reserve(bytes.len())
            .map_err(|_| Error::Backpressure("the server cannot buffer the frame"))?;
        body.extend_from_slice(&bytes);
        remaining = remaining.saturating_sub(bytes.len());
    }
    Ok(body)
}

/// How long the last served call waits for its peer to read the reply.
const DRAIN_BEFORE_CLOSE: std::time::Duration = std::time::Duration::from_millis(250);

/// Counts one admitted call, and closes the endpoint from the last one to end.
///
/// The serving task must outlive every admitted call even when its budget is
/// already spent: closing in the stream that happened to finish first aborted a
/// concurrent call's reply on another connection (round 47; seen as a CI flake
/// in `quic_dispatches_a_bound_capability_only_for_the_bound_peer`). `finish`
/// reports how many admitted calls are still running, so only the last one
/// closes.
struct CallGuard {
    active: Arc<AtomicUsize>,
    finished: bool,
}

impl CallGuard {
    fn finish(&mut self) -> usize {
        self.finished = true;
        self.active.fetch_sub(1, Ordering::SeqCst).saturating_sub(1)
    }
}

impl Drop for CallGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// Write one response and finish the stream, bounded.
///
/// Every reply path uses this: a peer that advertises a one-byte receive window
/// and never reads parks `write_all` after the first byte, so an unbounded early
/// error reply held the task (and its connection permit) forever.
/// Write one response and finish the stream, bounded.
///
/// Every reply path uses this: a peer that advertises a one-byte receive window
/// and never reads parks `write_all` after the first byte, so an unbounded early
/// error reply held the task (and its connection permit) forever.
async fn reply(send: &mut quinn::SendStream, response: &Envelope) {
    let written = tokio::time::timeout(STREAM_WAIT, async {
        if send_envelope(send, response).await.is_err() {
            return;
        }
        let _ = send.finish();
    })
    .await;
    if written.is_err() {
        let _ = send.reset(0u32.into());
    }
}

/// Largest aggregate value of encoded replies one server holds at once.
///
/// A second budget beside `MAX_INFLIGHT_BODY` (requests): the documented
/// per-server bound is the sum of the two (round 21, finding 3).
pub const MAX_INFLIGHT_REPLY: usize = 256 << 20;

/// Reply bytes held while a peer's flow-control credit is exhausted.
///
/// The guard releases its share when the reply task ends, and the shared
/// counter is the ceiling that keeps one peer from parking tens of GiB of
/// encoded replies across its streams (round 19, R-9#2).
struct ReplyBudget {
    counter: Arc<AtomicUsize>,
    amount: usize,
}

impl ReplyBudget {
    fn try_reserve(counter: &Arc<AtomicUsize>, amount: usize) -> Option<Self> {
        let mut current = counter.load(Ordering::SeqCst);
        loop {
            if current.saturating_add(amount) > MAX_INFLIGHT_REPLY {
                return None;
            }
            match counter.compare_exchange(
                current,
                current.saturating_add(amount),
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    return Some(Self {
                        counter: Arc::clone(counter),
                        amount,
                    })
                }
                Err(actual) => current = actual,
            }
        }
    }
}

impl Drop for ReplyBudget {
    fn drop(&mut self) {
        self.counter.fetch_sub(self.amount, Ordering::SeqCst);
    }
}

/// Write bytes that were already encoded under this server's profile.
///
/// The success path encodes once (so the bytes on the wire obey `wire`) and
/// sends those bytes: re-encoding inside `reply` used the default profile
/// (round 18, R16-6).
async fn reply_encoded(send: &mut quinn::SendStream, bytes: &[u8]) {
    let written = tokio::time::timeout(STREAM_WAIT, async {
        let Ok(prefix) = frame(bytes.len()) else {
            // A length the framing cannot express is a refusal, not an empty
            // answer (round 21, finding 9).
            let error = Error::Wire("response exceeds the size ceiling");
            let _ = send_envelope(send, &Envelope::error(0, &error)).await;
            let _ = send.finish();
            return;
        };
        let mut payload = Vec::with_capacity(bytes.len() + 4);
        payload.extend_from_slice(&prefix);
        payload.extend_from_slice(bytes);
        if send.write_all(&payload).await.is_err() {
            return;
        }
        let _ = send.finish();
    })
    .await;
    if written.is_err() {
        let _ = send.reset(0u32.into());
    }
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
/// The client trusts `certificate` for `server_name` and decodes responses
/// under `WireLimits::default()`.
pub struct QuicClient {
    runtime: tokio::runtime::Runtime,
    endpoint: quinn::Endpoint,
    address: SocketAddr,
    server_name: String,
    limits: WireLimits,
    /// Wall deadline for one exchange, when the caller sets one.
    deadline: Option<std::time::Duration>,
}

impl QuicClient {
    /// Connect, trusting `certificate` for `localhost`.
    pub fn connect(address: &str, certificate: &CertificateDer<'static>) -> Result<Self> {
        Self::connect_with_name(address, certificate, "localhost")
    }

    /// Connect, trusting `certificate` for `server_name`.
    ///
    /// The name is the SNI the client sends and the name the certificate must
    /// cover: a deployment whose certificate names `rpc.internal` could never
    /// verify with the hardcoded `localhost`.
    pub fn connect_with_name(
        address: &str,
        certificate: &CertificateDer<'static>,
        server_name: &str,
    ) -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(certificate.clone())
            .map_err(|error| Error::Transport(format!("trust: {error}")))?;
        let mut client_config = quinn::ClientConfig::with_root_certificates(Arc::new(roots))
            .map_err(|error| Error::Transport(format!("client config: {error}")))?;
        client_config.transport_config(Arc::new(transport_config()));
        Self::from_config(address, client_config, server_name)
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
        Self::connect_mutual_tls_with_name(address, "localhost", ca, certificate, key)
    }

    /// [`QuicClient::connect_mutual_tls`] for a server certificate that does not
    /// cover `localhost`.
    ///
    /// A deployment certificate names the service (`rpc.internal`, say); the
    /// fixed SNI of the plain entry point could never verify one, so the only
    /// transport that can enforce an identity-bound capability was unusable
    /// outside a test.
    pub fn connect_mutual_tls_with_name(
        address: &str,
        server_name: &str,
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
        Self::from_config(address, client_config, server_name)
    }

    fn from_config(
        address: &str,
        client_config: quinn::ClientConfig,
        server_name: &str,
    ) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| Error::Transport(format!("runtime: {error}")))?;
        // A hostname is resolved like the bridge's, and the client endpoint binds
        // the wildcard of the destination family: a hard 127.0.0.1:0 made the
        // documented off-host mutual-TLS deployment unreachable (round 16, F-2).
        let address = match address.parse::<SocketAddr>() {
            Ok(address) => address,
            Err(_) => {
                let deadline = std::time::Instant::now()
                    .checked_add(std::time::Duration::from_secs(5))
                    .unwrap_or_else(std::time::Instant::now);
                let resolved = crate::transport::connect::resolve_within(address, deadline)?;
                // Prefer IPv4 when a name publishes both families: a dual-stack
                // name resolves to `::1`-style addresses first on some hosts,
                // and a listener documented as `0.0.0.0:port` would never answer
                // (round 16, F-2).
                resolved
                    .iter()
                    .find(|address| address.is_ipv4())
                    .or_else(|| resolved.first())
                    .copied()
                    .ok_or_else(|| Error::Transport(format!("no address for {address}")))?
            }
        };
        let bind = if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let mut endpoint = runtime
            .block_on(async { quinn::Endpoint::client(bind.parse().expect("a static wildcard")) })
            .map_err(|error| Error::Transport(format!("client endpoint: {error}")))?;
        endpoint.set_default_client_config(client_config);
        Ok(QuicClient {
            runtime,
            endpoint,
            address,
            server_name: server_name.to_string(),
            limits: WireLimits::default(),
            deadline: None,
        })
    }

    /// Use tighter wire limits for a decoded response.
    pub fn with_limits(mut self, limits: WireLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Send one call and read the response.
    pub fn call(&self, envelope: &Envelope) -> Result<Envelope> {
        // Every limit the client's profile enforces, not only the byte ceiling:
        // a strict client that emitted a frame its own decoder refuses would
        // poison the session (round 16, F-1).
        let bytes = envelope.encode_with_limits(self.limits)?;
        // The client's own limits bound what it sends, as they bound what it
        // reads (round 9, R-09 #11).
        if bytes.len() > self.limits.max_bytes.min(MAX_FRAME_BYTES) {
            return Err(Error::Wire("frame exceeds the size ceiling"));
        }
        let mut payload = Vec::with_capacity(bytes.len() + 4);
        payload.extend_from_slice(&frame(bytes.len())?);
        payload.extend_from_slice(&bytes);
        let response = self.exchange(&payload)?;
        let mut cursor = std::io::Cursor::new(&response);
        let body =
            read_frame(&mut cursor, &self.limits)?.ok_or(Error::Wire("empty QUIC response"))?;
        // One stream is one frame: trailing bytes would let a peer smuggle a
        // second message past the decoder.
        if cursor.position() != response.len() as u64 {
            return Err(Error::Wire("trailing bytes after the QUIC frame"));
        }
        let answer = Envelope::decode_with(&body, self.limits)?;
        // The answer must be an answer to *this* call: a peer that replays
        // another response, or answers with a request, would otherwise have its
        // frame accepted as this call's result. The bridge and HTTP/2 clients
        // already enforce it (round 12, R-09 #1).
        //
        // An error carries id 0 when the server could not read the frame at
        // all (the length prefix is refused before there is an id to echo), so
        // that id is legal for an error and only there.
        if !answer.answers(envelope.request_id) {
            return Err(Error::Wire("the QUIC answer belongs to another request"));
        }
        Ok(answer)
    }

    /// Bound one exchange in wall time.
    ///
    /// Without it a peer that completes the handshake and then stalls parks the
    /// caller forever; the CLI hides that with a helper thread, a library
    /// consumer has nothing. The default is [`DEFAULT_QUIC_WAIT`], the same
    /// shape the HTTP/2 client uses (round 9, R-09 #9).
    pub fn with_deadline(mut self, deadline: std::time::Duration) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Send raw bytes (for malformed-frame tests) and return the raw response.
    pub fn exchange(&self, payload: &[u8]) -> Result<Vec<u8>> {
        // The raw path obeys the same ceiling as `call`: a caller holding
        // untrusted bytes must not write 100 MiB because it bypassed the
        // envelope check (round 10, R-09 #6).
        if payload.len() > self.limits.max_bytes.min(MAX_FRAME_BYTES).saturating_add(4) {
            return Err(Error::Wire("frame exceeds the size ceiling"));
        }
        let (endpoint, address, server_name) = (
            self.endpoint.clone(),
            self.address,
            self.server_name.clone(),
        );
        let request = payload.to_vec();
        // A client that sets no deadline still gets one: a peer that completes
        // the handshake and then stalls must not park the caller forever
        // (round 9, R-09 #9).
        let deadline = Some(self.deadline.unwrap_or(DEFAULT_QUIC_WAIT));
        // The stream carries a four-byte length and then the body; bound the
        // read by the caller's own limits, so a strict client does not buffer
        // the server's full 64 MiB before `read_frame` refuses it
        // (round 35, R-09 #1).
        let read_ceiling = self.limits.max_bytes.min(MAX_FRAME_BYTES).saturating_add(4);
        self.runtime.block_on(async move {
            let exchange = async move {
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
                let response = match recv.read_to_end(read_ceiling).await {
                    Ok(response) => response,
                    // A stream past the caller's ceiling is a wire fault: the
                    // peer framed a message this client will never accept
                    // (round 35, R-09 #1).
                    Err(quinn::ReadToEndError::TooLong) => {
                        return Err(Error::Wire("response exceeds the size ceiling"))
                    }
                    Err(error) => {
                        return Err(Error::Transport(format!("read: {error}")));
                    }
                };
                connection.close(0u32.into(), b"done");
                Ok(response)
            };
            match deadline {
                Some(limit) => tokio::time::timeout(limit, exchange)
                    .await
                    .map_err(|_| Error::Transport("QUIC exchange timed out".to_string()))?,
                None => exchange.await,
            }
        })
    }
}

/// Keep-alive and idle settings suitable for agent traffic.
///
/// The stream and flow-control limits are amplification bounds: ARP1 carries one
/// call per bidirectional stream, so the number of concurrent streams is the
/// number of calls a peer can have in flight, and the windows bound how many
/// bytes it can pin before we read them. Unidirectional streams are refused
/// because this transport never uses one.
fn transport_config() -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    // No keep-alive: a peer that holds a connection open without traffic keeps a
    // slot busy forever, and there are only `MAX_CONNECTIONS` of them. The idle
    // timeout then frees the slot after 30 s of silence. A caller that needs
    // NAT keep-alive can configure it on its own endpoint.
    config.max_idle_timeout(Some(
        std::time::Duration::from_secs(30)
            .try_into()
            .expect("valid idle timeout"),
    ));
    config.max_concurrent_bidi_streams(MAX_CONCURRENT_STREAMS.into());
    config.max_concurrent_uni_streams(0u32.into());
    config.stream_receive_window(STREAM_RECEIVE_WINDOW.into());
    config.receive_window(CONNECTION_RECEIVE_WINDOW.into());
    config
}
#[cfg(test)]
mod budget_tests {
    use super::{ReplyBudget, MAX_INFLIGHT_BODY};
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    /// The shared reply ceiling: a reservation that would pass it is refused,
    /// the guard releases on drop, and a nested reservation sees the first.
    #[test]
    fn the_reply_budget_admits_releases_and_refuses() {
        let counter = Arc::new(AtomicUsize::new(0));
        let first = ReplyBudget::try_reserve(&counter, MAX_INFLIGHT_BODY)
            .expect("the whole ceiling fits once");
        assert!(
            ReplyBudget::try_reserve(&counter, 1).is_none(),
            "a second byte is past the ceiling"
        );
        drop(first);
        let again = ReplyBudget::try_reserve(&counter, 1).expect("released");
        drop(again);
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 0);
        // A zero-length reservation is always admitted and harmless.
        let empty = ReplyBudget::try_reserve(&counter, 0).expect("zero bytes");
        drop(empty);
    }
}
