//! Machine-portable performance matrix for the RPC regression gate.
//!
//! Emits JSON with p50/p95/p99 for envelope encode/decode and a kernel call
//! batch. `scripts/perf_gate.py` checks tail stability and linear scaling.
//!
//! ```text
//! cargo run --release --example perf_matrix --all-features
//! ```

use std::hint::black_box;
use std::time::Instant;

use active_rpc::cap::CapAttrs;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, Budget, Envelope, Provider};

struct Echo;

impl Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn methods(&self) -> Vec<String> {
        vec!["echo".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
        let value = call
            .args
            .iter()
            .find_map(|arg| match arg {
                Arg::Value(value) => Some(value.clone()),
                _ => None,
            })
            .unwrap_or(Value::Null);
        Ok(Response::Value(value))
    }
}

fn envelope(args: usize) -> Envelope {
    Envelope::request(
        1,
        "echo",
        (0..args)
            .map(|index| Arg::Value(Value::Int(index as i64)))
            .collect(),
    )
}

/// (p50, p95, p99) in nanoseconds.
fn measure(mut op: impl FnMut(), iterations: usize) -> (u64, u64, u64) {
    for _ in 0..5 {
        op();
    }
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        op();
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    let percentile = |fraction: f64| -> u64 {
        let index = ((samples.len() as f64 - 1.0) * fraction).round() as usize;
        samples[index].as_nanos() as u64
    };
    (percentile(0.50), percentile(0.95), percentile(0.99))
}

fn call_batch(calls: usize) {
    let agent = Agent::with_secret([0x77; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let lane = agent.create_lane("perf", Budget::default()).expect("lane");
    for _ in 0..calls {
        let promise = agent
            .call(lane, &cap, "echo", vec![Arg::Value(Value::Int(1))])
            .expect("call");
        black_box(promise.value().expect("value"));
    }
}

fn main() {
    let small = envelope(1_000);
    let large = envelope(4_000);
    let small_bytes = small.encode().expect("encode");
    let large_bytes = large.encode().expect("encode");

    let mut entries = Vec::new();
    let mut record = |name: &str, op: &mut dyn FnMut(), iterations: usize| {
        let (p50, p95, p99) = measure(op, iterations);
        entries.push(format!(
            "\"{name}\":{{\"p50_ns\":{p50},\"p95_ns\":{p95},\"p99_ns\":{p99}}}"
        ));
    };

    record(
        "encode_1k",
        &mut || {
            black_box(small.encode().expect("encode"));
        },
        300,
    );
    record(
        "encode_4k",
        &mut || {
            black_box(large.encode().expect("encode"));
        },
        120,
    );
    record(
        "decode_1k",
        &mut || {
            black_box(Envelope::decode(&small_bytes).expect("decode"));
        },
        300,
    );
    record(
        "decode_4k",
        &mut || {
            black_box(Envelope::decode(&large_bytes).expect("decode"));
        },
        120,
    );
    record("call_1k", &mut || call_batch(1_000), 20);
    record("call_4k", &mut || call_batch(4_000), 20);

    println!(
        "{{\"schema\":\"active-rpc/perf-matrix/1\",\"host\":{{\"os\":\"{}\",\"arch\":\"{}\"}},\"sizes\":{{\"small_bytes\":{},\"large_bytes\":{}}},\"ops\":{{{}}}}}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        small_bytes.len(),
        large_bytes.len(),
        entries.join(",")
    );
}
