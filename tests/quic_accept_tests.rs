#![cfg(feature = "quic")]

//! The QUIC accept loop under a peer that stays connected.
//!
//! The server used to await a connection inline and then loop on that
//! connection's streams, so one idle peer held the accept loop for as long as
//! it kept its connection open and the next peer was never accepted (measured:
//! `a_held_connection_does_not_block_a_second_peer` times out at the 30 s
//! handshake deadline against that code). Each connection now runs in its own
//! task; these tests pin it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use active_rpc::transport::quic::{QuicClient, QuicServer};
use active_rpc::wire::Envelope;
use rustls::pki_types::CertificateDer;

fn server() -> QuicServer {
    QuicServer::start(64, |envelope| {
        Envelope::response(envelope.request_id, active_rpc::Value::text("pong"))
    })
    .expect("server starts")
}

/// A raw quinn client that keeps its connection open after the call.
///
/// The shipped `QuicClient` closes the connection at the end of every `call`, so
/// it cannot express "a peer that is still connected and idle" — which is what
/// a long-lived agent connection is. This helper drives quinn directly.
fn held_connection(
    address: &str,
    certificate: &CertificateDer<'static>,
) -> (tokio::runtime::Runtime, quinn::Endpoint, quinn::Connection) {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.clone()).expect("trust root");
    let mut client_config =
        quinn::ClientConfig::with_root_certificates(Arc::new(roots)).expect("client config");
    client_config.transport_config(Arc::new(quinn::TransportConfig::default()));
    // `Endpoint::client` needs a reactor, so the runtime exists first.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let socket: std::net::SocketAddr = address.parse().expect("address");
    let (endpoint, connection) = runtime.block_on(async {
        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().expect("loopback")).expect("endpoint");
        endpoint.set_default_client_config(client_config);
        let connection = endpoint
            .connect(socket, "localhost")
            .expect("connect")
            .await
            .expect("handshake");
        (endpoint, connection)
    });
    (runtime, endpoint, connection)
}

fn call_over(
    runtime: &tokio::runtime::Runtime,
    connection: &quinn::Connection,
    id: u64,
) -> Envelope {
    runtime.block_on(async {
        let (mut send, mut recv) = connection.open_bi().await.expect("stream");
        let request = Envelope::request(id, "ping", vec![]);
        let bytes = request.encode().expect("encode");
        let mut payload = active_rpc::transport::frame(bytes.len())
            .expect("frame")
            .to_vec();
        payload.extend_from_slice(&bytes);
        send.write_all(&payload).await.expect("write");
        send.finish().expect("finish");
        let response = recv
            .read_to_end(active_rpc::transport::MAX_FRAME_BYTES)
            .await
            .expect("read");
        assert!(response.len() > 4, "framed response");
        Envelope::decode(&response[4..]).expect("decode")
    })
}

#[test]
fn a_held_connection_does_not_block_a_second_peer() {
    let server = server();
    let address = server.address().to_string();

    // Connect and make one call, then keep the connection open and idle.
    let (runtime, endpoint, held) = held_connection(&address, server.certificate());
    let first = call_over(&runtime, &held, 1);
    assert_eq!(first.first_value(), Some(&active_rpc::Value::text("pong")));

    // The held connection is still open with no stream in flight. The accept
    // loop must not be parked on it: a second peer has to be served now.
    let started = Instant::now();
    let second = QuicClient::connect(&address, server.certificate())
        .expect("a second peer is accepted while the first is idle");
    let response = second
        .call(&Envelope::request(2, "ping", vec![]))
        .expect("second call is served");
    assert_eq!(
        response.first_value(),
        Some(&active_rpc::Value::text("pong"))
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "the accept loop was blocked for {elapsed:?} by an idle connection"
    );

    drop(held);
    drop(endpoint);
    drop(runtime);
    server.shutdown();
}

#[test]
fn an_idle_connection_does_not_block_a_second_peer() {
    let server = server();
    let address = server.address().to_string();

    let first = QuicClient::connect(&address, server.certificate()).expect("first connects");
    first
        .call(&Envelope::request(1, "ping", vec![]))
        .expect("first call is served");
    // `first` stays alive and idle: its connection remains open with no stream
    // in flight, which is exactly what used to park the accept loop.

    let started = Instant::now();
    let second = QuicClient::connect(&address, server.certificate())
        .expect("a second peer is accepted while the first is idle");
    let response = second
        .call(&Envelope::request(2, "ping", vec![]))
        .expect("second call is served");
    assert_eq!(
        response.first_value(),
        Some(&active_rpc::Value::text("pong"))
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "the accept loop was blocked for {elapsed:?} by an idle connection"
    );

    drop(first);
    drop(second);
    server.shutdown();
}

#[test]
fn many_idle_connections_are_all_served() {
    let server = server();
    let address = server.address().to_string();

    let mut clients = Vec::new();
    for id in 1..=8u64 {
        let client = QuicClient::connect(&address, server.certificate())
            .unwrap_or_else(|error| panic!("client {id}: {error}"));
        let response = client
            .call(&Envelope::request(id, "ping", vec![]))
            .expect("call");
        assert_eq!(
            response.first_value(),
            Some(&active_rpc::Value::text("pong")),
            "call {id}"
        );
        clients.push(client);
    }
    // Every connection is still open; the server closed nothing and served all.
    assert_eq!(clients.len(), 8);
    drop(clients);
    server.shutdown();
}

#[test]
fn a_spent_call_budget_closes_the_endpoint() {
    // The budget is enforced across connections: the endpoint closes once the
    // total is reached, and a later call fails with a transport error rather
    // than hanging.
    let server = QuicServer::start(1, |envelope| {
        Envelope::response(envelope.request_id, active_rpc::Value::text("one"))
    })
    .expect("server starts");
    let address = server.address().to_string();
    let client = QuicClient::connect(&address, server.certificate()).expect("client connects");
    let first = client
        .call(&Envelope::request(1, "ping", vec![]))
        .expect("first call is served");
    assert_eq!(first.first_value(), Some(&active_rpc::Value::text("one")));

    let second = client.call(&Envelope::request(2, "ping", vec![]));
    assert!(
        second.is_err(),
        "a spent budget must refuse the next call, got {second:?}"
    );
    server.shutdown();
}
