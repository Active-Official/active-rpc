//! TCP loopback latency and throughput for ARP1 envelopes.
//!
//! ```text
//! cargo run --release --example tcp_bench -- [calls] [payload-bytes]
//! ```
//!
//! One client, one server thread, sequential round trips: each call is one
//! framed envelope out and one framed response back, so the numbers describe the
//! transport plus the wire codec and nothing else. The point of the tool is a
//! reproducible floor for the io_uring question (ADR-0023): how much per-call
//! time exists for syscall batching to remove in the first place.
//!
//! It prints one line per run so a shell loop can collect several:
//!
//! ```text
//! calls=20000 payload=256 p50=...us p95=...us p99=...us rps=... bytes_per_call=...
//! ```

use std::time::{Duration, Instant};

use active_rpc::transport::{bind_loopback, serve_connection, TcpTransport, Transport};
use active_rpc::wire::Envelope;
use active_rpc::Value;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let calls: usize = args
        .next()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(10_000);
    let payload_bytes: usize = args
        .next()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(256);
    if calls == 0 {
        return Err("calls must be greater than zero".into());
    }
    let payload = vec![0x41u8; payload_bytes];

    let (listener, address) = bind_loopback()?;
    let served_payload = payload.clone();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept one client");
        let transport = TcpTransport::new(stream).expect("server transport");
        serve_connection(transport, move |envelope| Envelope {
            payload: served_payload.clone(),
            ..Envelope::response(envelope.request_id, Value::Null)
        })
        .expect("serve")
    });

    let mut client = TcpTransport::connect(&address)?;
    // Warm up page cache, allocator and the TCP window before measuring.
    for id in 0..64u64 {
        let request = Envelope {
            payload: payload.clone(),
            ..Envelope::request(id, "ping", vec![])
        };
        client.send(&request)?;
        client.recv()?.expect("warmup response");
    }

    let mut samples = Vec::with_capacity(calls);
    let mut bytes_out = 0u64;
    let started = Instant::now();
    for id in 0..calls as u64 {
        let request = Envelope {
            payload: payload.clone(),
            ..Envelope::request(id, "ping", vec![])
        };
        let call_started = Instant::now();
        client.send(&request)?;
        let response = client.recv()?.expect("response");
        samples.push(call_started.elapsed());
        bytes_out += (response.payload.len() + 4) as u64;
    }
    let elapsed = started.elapsed();
    // Closing the client ends the server's read loop; join after the close, or
    // the tool waits for a connection that will never end.
    drop(client);
    let served = server.join().expect("server thread");

    samples.sort_unstable();
    let percentile = |p: f64| -> Duration {
        let index = ((samples.len() as f64 - 1.0) * p).round() as usize;
        samples[index]
    };
    let rps = calls as f64 / elapsed.as_secs_f64();
    println!(
        "calls={calls} payload={payload_bytes} served={served} p50={:?} p95={:?} p99={:?} \
         rps={rps:.0} bytes_out_per_call={} total={:?}",
        percentile(0.50),
        percentile(0.95),
        percentile(0.99),
        bytes_out / calls as u64,
        elapsed
    );
    Ok(())
}
