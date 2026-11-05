//! R-09 round 13: a truncated bridge body is a wire fault, an undecodable
//! frame poisons the TCP session, the TCP and shared-memory clients check that
//! an answer belongs to their call, and a served connection has a total bound.

use std::io::{Read, Write};
use std::net::TcpListener;

use active_rpc::transport::{serve_connection_within, TcpTransport, Transport};
use active_rpc::wire::Envelope;

fn frame(body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(body.len() + 4);
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(body);
    bytes
}

/// A frame whose body is not an envelope is a protocol fault, and the session
/// must not be reused: a caller that ignores the first error must not read the
/// next frame as if the peer were healthy (round 13, R-09 #2).
#[test]
fn a_frame_that_decodes_badly_poisons_the_session() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        stream.write_all(&frame(&[0xffu8; 8])).expect("bad frame");
        let good = Envelope::request(1, "ping", Vec::new())
            .encode()
            .expect("encode");
        stream.write_all(&frame(&good)).expect("good frame");
        let _ = stream.flush();
        // Hold the socket open until the client closed, so the second read is
        // answered by the poison check and not by end-of-stream.
        let mut sink = [0u8; 1024];
        let _ = stream.read(&mut sink);
    });
    let mut client = TcpTransport::connect(&address.to_string()).expect("connect");
    let first = client.recv().expect_err("the body is not an envelope");
    assert_eq!(first.code(), "rpc/wire", "{first}");
    let second = client
        .recv()
        .expect_err("an undecodable frame poisons the session");
    assert_eq!(second.code(), "rpc/transport", "{second}");
    drop(client);
    server.join().expect("server");
}

/// A byte stream has no reply channel of its own: without an id check a relay
/// can hand one call the answer to another (round 13, R-09 #3).
#[test]
fn a_tcp_call_refuses_an_answer_to_another_request() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut sink = [0u8; 4096];
        let _ = stream.read(&mut sink);
        let answer = Envelope::response(8, active_rpc::Value::Null)
            .encode()
            .expect("encode");
        // The call used id 7, so this is another call's answer.
        let _ = stream.write_all(&frame(&answer));
        let _ = stream.flush();
        let _ = stream.read(&mut sink);
    });
    let mut client = TcpTransport::connect(&address.to_string()).expect("connect");
    let error = client
        .call(&Envelope::request(7, "ping", Vec::new()))
        .expect_err("the answer belongs to another call");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    drop(client);
    server.join().expect("server");
}

/// A shared segment has many writers, so the same id check applies there.
#[test]
fn a_shared_memory_call_refuses_an_answer_to_another_request() {
    use active_rpc::transport::shm::{SharedMemoryTransport, SharedSegment};

    let segment = SharedSegment::new(1 << 16);
    let mut peer = SharedMemoryTransport::new(segment.clone());
    peer.send(&Envelope::response(99, active_rpc::Value::Null))
        .expect("the other writer's answer");
    let mut client = SharedMemoryTransport::new(segment);
    let error = client
        .call(&Envelope::request(7, "ping", Vec::new()))
        .expect_err("the answer belongs to another call");
    assert_eq!(error.code(), "rpc/wire", "{error}");
}

/// A connection outlives its deadline only until the next frame: the loop
/// returns instead of serving a peer that keeps the per-frame deadline alive
/// forever (round 13, R-09 #4).
#[test]
fn a_served_connection_stops_at_its_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let transport = TcpTransport::new(stream).expect("wrap");
        serve_connection_within(
            transport,
            |envelope| Envelope::response(envelope.request_id, active_rpc::Value::Null),
            Some(std::time::Instant::now()),
        )
    });
    std::thread::sleep(std::time::Duration::from_millis(50));
    let _client = std::net::TcpStream::connect(address).expect("connect");
    let served = server
        .join()
        .expect("server thread")
        .expect("a past deadline is not an error");
    assert_eq!(served, 0, "a connection past its deadline serves nothing");
}
