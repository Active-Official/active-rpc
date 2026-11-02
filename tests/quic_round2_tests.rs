#![cfg(feature = "quic")]

//! R-09 round 2, QUIC: the body budget follows bytes that arrive, and a complete
//! frame is answered without waiting for the peer to finish its send half.

use active_rpc::transport::quic::QuicServer;
use active_rpc::transport::{frame, read_frame};
use active_rpc::value::Value;
use active_rpc::wire::{Envelope, Kind, WireLimits};

fn echo(envelope: Envelope) -> Envelope {
    Envelope::response(envelope.request_id, Value::text("ok"))
}

/// The body budget is reserved from bytes that arrive, not from the announced
/// length: four idle streams that sent only a 4-byte header must not deny every
/// other peer. Before the fix this returned `rpc/backpressure` for the real
/// call.
#[test]
fn an_idle_announcement_does_not_consume_the_quic_body_budget() {
    let server = QuicServer::start(1, echo).expect("server");
    let address = server.address().to_string();
    let certificate = server.certificate().clone();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async move {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).expect("trust");
        let client_config = quinn::ClientConfig::with_root_certificates(std::sync::Arc::new(roots))
            .expect("config");
        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().expect("loopback")).expect("endpoint");
        endpoint.set_default_client_config(client_config);
        let connection = endpoint
            .connect(address.parse().expect("address"), "localhost")
            .expect("connect")
            .await
            .expect("handshake");

        // Four streams announce the whole ceiling and then send nothing.
        for _ in 0..4 {
            let (mut send, _recv) = connection.open_bi().await.expect("open");
            send.write_all(&(64u32 * 1024 * 1024).to_le_bytes())
                .await
                .expect("prefix");
            // No body, no finish: the stream stays idle.
        }

        // A real call on the same connection still works.
        let (mut send, mut recv) = connection.open_bi().await.expect("open");
        let bytes = Envelope::request(9, "ping", vec![])
            .encode()
            .expect("encode");
        let mut payload = Vec::new();
        payload.extend_from_slice(&frame(bytes.len()).expect("frame"));
        payload.extend_from_slice(&bytes);
        send.write_all(&payload).await.expect("write");
        send.finish().expect("finish");
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            recv.read_to_end(64 * 1024 * 1024),
        )
        .await
        .expect("the real call is not refused for backpressure")
        .expect("read");
        assert!(!response.is_empty(), "no response");
        let mut cursor = std::io::Cursor::new(&response);
        let body = read_frame(&mut cursor, &WireLimits::default())
            .expect("frame")
            .expect("body");
        let envelope = Envelope::decode_with(&body, WireLimits::default()).expect("decode");
        assert_eq!(envelope.kind, Kind::Response, "{envelope:?}");
        assert_eq!(envelope.first_value(), Some(&Value::text("ok")));
    });
}

/// A complete frame is answered without waiting for the peer to FINish its send
/// half: a client that keeps the stream open for the reply must not time out.
#[test]
fn a_complete_frame_without_fin_is_answered() {
    let server = QuicServer::start(1, echo).expect("server");
    let address = server.address().to_string();
    let certificate = server.certificate().clone();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async move {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).expect("trust");
        let client_config = quinn::ClientConfig::with_root_certificates(std::sync::Arc::new(roots))
            .expect("config");
        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().expect("loopback")).expect("endpoint");
        endpoint.set_default_client_config(client_config);
        let connection = endpoint
            .connect(address.parse().expect("address"), "localhost")
            .expect("connect")
            .await
            .expect("handshake");

        let (mut send, mut recv) = connection.open_bi().await.expect("open");
        let bytes = Envelope::request(5, "ping", vec![])
            .encode()
            .expect("encode");
        let mut payload = Vec::new();
        payload.extend_from_slice(&frame(bytes.len()).expect("frame"));
        payload.extend_from_slice(&bytes);
        send.write_all(&payload).await.expect("write");
        // Deliberately no `finish`: the peer keeps its send half open.

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            recv.read_to_end(64 * 1024 * 1024),
        )
        .await
        .expect("the frame is answered without FIN")
        .expect("read");
        assert!(!response.is_empty());
        send.finish().expect("finish");
    });
}
