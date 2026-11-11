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

/// Largest payload the bench will allocate (matches the CLI's payload
/// ceiling): `vec![0x41; payload_bytes]` with no ceiling overflowed on a
/// huge argument (RPC-51c).
const MAX_PAYLOAD_BYTES: usize = 64 << 20;
/// Most calls one bench run will issue: the samples vector is sized by
/// `calls`, so an unbounded count is the same overflow shape (RPC-51c).
const MAX_CALLS: usize = 1_000_000;

/// One numeric argument, refusing a non-UTF-8 argument instead of panicking
/// on it (`std::env::args()` panics, exit 101 — RPC-51c).
fn arg_usize(value: std::ffi::OsString) -> Result<usize, Box<dyn std::error::Error>> {
    let text = value
        .into_string()
        .map_err(|_| "an argument is not valid UTF-8")?;
    Ok(text.parse()?)
}

/// Parse `[calls] [payload-bytes]` with the ceilings applied (RPC-51c):
/// a huge payload or call count is refused before anything is allocated
/// -- `vec![0x41; payload_bytes]` with no ceiling overflowed on a huge
/// argument, and the samples vector is sized by `calls`, the same shape.
/// Zero calls is refused too. Extracted from `main` so the refusals are
/// unit-testable (`cargo test --example tcp_bench`).
fn parse_bench_args(
    args: impl Iterator<Item = std::ffi::OsString>,
) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    let mut args = args;
    let calls: usize = args.next().map(arg_usize).transpose()?.unwrap_or(10_000);
    let payload_bytes: usize = args.next().map(arg_usize).transpose()?.unwrap_or(256);
    if calls == 0 {
        return Err("calls must be greater than zero".into());
    }
    if calls > MAX_CALLS {
        return Err(format!("calls is capped at {MAX_CALLS}").into());
    }
    if payload_bytes > MAX_PAYLOAD_BYTES {
        return Err(format!("payload-bytes is capped at {MAX_PAYLOAD_BYTES}").into());
    }
    Ok((calls, payload_bytes))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (calls, payload_bytes) = parse_bench_args(std::env::args_os().skip(1))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn defaults_apply_without_arguments() {
        assert_eq!(
            parse_bench_args(args(&[]).into_iter()).unwrap(),
            (10_000, 256)
        );
    }

    #[test]
    fn explicit_arguments_pass_through() {
        assert_eq!(
            parse_bench_args(args(&["10", "128"]).into_iter()).unwrap(),
            (10, 128)
        );
    }

    #[test]
    fn a_huge_payload_is_refused_not_allocated() {
        // The pre-fix shape: `vec![0x41; 18446744073709551615]` panicked
        // with `capacity overflow` (exit 101).
        let error = parse_bench_args(args(&["10", "18446744073709551615"]).into_iter())
            .expect_err("a payload past the ceiling must be refused");
        assert!(error.to_string().contains("capped at"), "{error}");
    }

    #[test]
    fn a_huge_call_count_is_refused() {
        let error = parse_bench_args(args(&["1000001"]).into_iter())
            .expect_err("calls past the ceiling must be refused");
        assert!(error.to_string().contains("capped at"), "{error}");
    }

    #[test]
    fn zero_calls_is_refused() {
        assert!(parse_bench_args(args(&["0"]).into_iter()).is_err());
    }

    #[test]
    fn a_non_numeric_argument_is_refused() {
        assert!(parse_bench_args(args(&["abc"]).into_iter()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_non_utf8_argument_is_refused_not_a_panic() {
        use std::os::unix::ffi::OsStringExt;
        let bad = OsString::from_vec(vec![0xff]);
        assert!(parse_bench_args(vec![bad].into_iter()).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn a_non_utf8_argument_is_refused_not_a_panic() {
        use std::os::windows::ffi::OsStringExt;
        let bad = OsString::from_wide(&[0xD800]);
        assert!(parse_bench_args(vec![bad].into_iter()).is_err());
    }
}
