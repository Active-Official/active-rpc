//! R-09 round 3: the amplifiers the round-2 verification found still open.
//!
//! Each test drives the shipped transport against a real socket and asserts the
//! *property* the fix is for, not a code path: an honest peer is served while a
//! hostile one is holding a resource.

use std::io::Write;
use std::net::TcpStream;
use std::time::{Duration, Instant};

use active_rpc::transport::connect::{BridgeServer, CONNECTION_WAIT};
use active_rpc::transport::{serve_connection, TcpTransport, Transport};
use active_rpc::value::Value;
use active_rpc::wire::Envelope;

fn echo(envelope: Envelope) -> Envelope {
    Envelope::response(envelope.request_id, Value::text("ok"))
}

/// A head that dribbles one byte at a time is still bounded by the connection
/// deadline: before the fix the per-read socket timeout was re-armed by every
/// byte, and a head drip held the serial accept slot for hours.
#[test]
fn a_dripping_head_cannot_stretch_the_bridge_connection() {
    let server = BridgeServer::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let handle = std::thread::spawn(move || server.serve(2, echo).expect("serve"));

    let mut drip = TcpStream::connect(&address).expect("connect");
    let head = b"POST /active.rpc.v1.Agent/Call HTTP/1.1\r\nhost:";
    for byte in head.iter() {
        if drip.write_all(&[*byte]).is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    // Keep the socket open with no empty line; the deadline must end it.

    let started = Instant::now();
    let mut client = active_rpc::transport::connect::ConnectClient::connect(&address)
        .expect("the bridge keeps serving")
        .with_deadline(Duration::from_secs(15));
    client
        .call(&Envelope::request(1, "ping", vec![]))
        .expect("the next connection is served");
    assert!(
        started.elapsed() < CONNECTION_WAIT + Duration::from_secs(5),
        "the head drip held the bridge for {:?}",
        started.elapsed()
    );
    drop(drip);
    let _ = handle.join();
}

/// A client that sends a valid frame header and then dribbles the body must not
/// keep a serial peer from accepting the next client.
#[test]
fn a_dripping_client_does_not_block_the_peer() {
    use std::process::{Command, Stdio};

    let mut child = Command::new(env!("CARGO_BIN_EXE_active-rpc-peer"))
        .args(["--listen", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn peer");
    let stdout = child.stdout.take().expect("stdout");
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    std::io::BufRead::read_line(&mut reader, &mut line).expect("listen line");
    let address = line
        .trim()
        .strip_prefix("listening ")
        .expect("address")
        .to_string();

    // A real envelope's length, then one body byte every 300 ms.
    let envelope = Envelope::request(1, "ping", vec![])
        .encode()
        .expect("encode");
    let mut drip = TcpStream::connect(&address).expect("connect");
    drip.write_all(&(envelope.len() as u32).to_le_bytes())
        .expect("header");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_writer = std::sync::Arc::clone(&stop);
    let drip_thread = std::thread::spawn(move || {
        while !stop_writer.load(std::sync::atomic::Ordering::Relaxed) {
            if drip.write_all(&[0u8]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    });

    let started = Instant::now();
    let mut transport =
        TcpTransport::connect_with_timeout(&address, Duration::from_secs(30)).expect("connect");
    transport
        .send(&Envelope::request(2, "ping", vec![]))
        .expect("send");
    let response = transport.recv().expect("recv").expect("a response");
    assert_eq!(response.first_value(), Some(&Value::text("pong")));
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "a dribbling client held the peer for {:?}",
        started.elapsed()
    );

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = drip_thread.join();
    let _ = child.kill();
    let _ = child.wait();
}

/// A served call still works when a previous connection's frame timed out: the
/// deadline is per frame, not a latched state.
#[test]
fn a_timed_out_frame_does_not_poison_the_next_connection() {
    let (listener, address) = active_rpc::transport::bind_loopback().expect("bind");
    let handle = std::thread::spawn(move || {
        let mut served = 0u64;
        for _ in 0..2 {
            let (stream, _) = listener.accept().expect("accept");
            let transport =
                TcpTransport::with_timeout(stream, Duration::from_millis(300)).expect("wrap");
            served += serve_connection(transport, echo).expect("serve");
        }
        served
    });

    let mut drip = TcpStream::connect(&address).expect("connect");
    drip.write_all(&(1024u32).to_le_bytes()).expect("header");
    drip.write_all(&[0u8]).expect("one byte");
    std::thread::sleep(Duration::from_millis(600));

    let mut client =
        TcpTransport::connect_with_timeout(&address, Duration::from_secs(10)).expect("connect");
    client
        .send(&Envelope::request(1, "ping", vec![]))
        .expect("send");
    let response = client.recv().expect("recv").expect("a response");
    assert_eq!(response.first_value(), Some(&Value::text("ok")));
    assert_eq!(handle.join().expect("join"), 1);
}
