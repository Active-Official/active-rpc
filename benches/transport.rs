//! Transport and kernel benchmarks.
//!
//! `cargo bench -p active-rpc`. Baselines are recorded in
//! `docs/spec/performance.md`.

use std::hint::black_box;

use active_rpc::cap::CapAttrs;
use active_rpc::domain::ModuleProvider;
use active_rpc::transport::shm::{SharedMemoryTransport, SharedSegment};
use active_rpc::transport::{InProcessTransport, Transport};
use active_rpc::value::{Arg, Value};
use active_rpc::wire::{CapDescriptor, Envelope};
use active_rpc::{Agent, Budget};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

const SOURCE: &str = r#"
[app]
name = "bench"
port = 8080

[server]
host = "127.0.0.1"
timeout = 1500ms
"#;

fn module_bytes() -> Vec<u8> {
    let module = active_rpc::domain::module_from_source(SOURCE, "bench.active").expect("module");
    active_infinity::encode(&module).expect("encode")
}

fn envelope(module: &[u8]) -> Envelope {
    Envelope::request(1, "evaluate", vec![Arg::Value(Value::Path("app".into()))])
        .with_payload(module.to_vec())
        .with_caps(vec![CapDescriptor {
            id: active_rpc::CapId([7u8; 16]),
            methods: ["evaluate".to_string()].into_iter().collect(),
            budget: Budget::default(),
            read_only: false,
            redact: false,
            path_scope: None,
        }])
}

fn benches(criterion: &mut Criterion) {
    let module = module_bytes();
    let sample = envelope(&module);
    let bytes = sample.encode().expect("encode");

    let mut group = criterion.benchmark_group("wire");
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_function(
        BenchmarkId::new("envelope-encode", bytes.len()),
        |bencher| {
            bencher.iter(|| black_box(sample.encode().expect("encode")));
        },
    );
    group.bench_function(
        BenchmarkId::new("envelope-decode", bytes.len()),
        |bencher| {
            bencher.iter(|| black_box(Envelope::decode(black_box(&bytes)).expect("decode")));
        },
    );
    group.finish();

    let mut group = criterion.benchmark_group("transport");
    group.throughput(Throughput::Bytes(module.len() as u64));
    group.bench_function("in-process", |bencher| {
        let mut transport = InProcessTransport::queue();
        bencher.iter(|| {
            transport.send(&sample).expect("send");
            black_box(transport.recv().expect("recv"));
        });
    });
    group.bench_function("shared-memory", |bencher| {
        let segment = SharedSegment::new(4 << 20);
        let mut transport = SharedMemoryTransport::new(segment);
        bencher.iter(|| {
            transport.send(&sample).expect("send");
            black_box(transport.recv().expect("recv"));
        });
    });
    group.finish();

    let mut group = criterion.benchmark_group("kernel");
    group.bench_function("call-and-run", |bencher| {
        let mut provider = ModuleProvider::new();
        let object = provider
            .install(active_rpc::domain::module_from_source(SOURCE, "bench").unwrap())
            .expect("install");
        let agent = Agent::new();
        let provider_id = agent.register(Box::new(provider));
        // A benchmark spends millions of calls; give the capability and the lane
        // room so the measurement is of dispatch, not of budget exhaustion.
        let wide = Budget {
            max_calls: u64::MAX,
            ..Budget::default()
        };
        let cap = agent
            .mint(
                provider_id,
                object,
                CapAttrs::new(&["stats"]).with_budget(wide),
            )
            .unwrap();
        let lane = agent.create_lane("bench", wide).unwrap();
        bencher.iter(|| {
            let promise = agent.call(lane, &cap, "stats", vec![]).expect("call");
            black_box(promise.value().expect("value"));
        });
    });
    group.finish();

    // The same eight calls, issued one-at-a-time versus queued together. The
    // difference is provider round-trips, not call cost, so this pair is the
    // checked-in evidence for the pipelining claim.
    let mut group = criterion.benchmark_group("kernel/pipelining");
    group.bench_function("sequential-8", |bencher| {
        let (agent, cap, lane) = kernel_fixture();
        bencher.iter(|| {
            for _ in 0..8 {
                let promise = agent.call(lane, &cap, "stats", vec![]).expect("call");
                black_box(promise.value().expect("value"));
            }
        });
    });
    group.bench_function("batched-8", |bencher| {
        let (agent, cap, lane) = kernel_fixture();
        bencher.iter(|| {
            let promises: Vec<_> = (0..8)
                .map(|_| agent.call(lane, &cap, "stats", vec![]).expect("call"))
                .collect();
            for promise in promises {
                black_box(promise.value().expect("value"));
            }
        });
    });
    group.finish();
}

fn kernel_fixture() -> (Agent, active_rpc::CapHandle, active_rpc::LaneId) {
    let mut provider = ModuleProvider::new();
    let object = provider
        .install(active_rpc::domain::module_from_source(SOURCE, "bench").unwrap())
        .expect("install");
    let agent = Agent::new();
    let provider_id = agent.register(Box::new(provider));
    let wide = Budget {
        max_calls: u64::MAX,
        ..Budget::default()
    };
    let cap = agent
        .mint(
            provider_id,
            object,
            CapAttrs::new(&["stats"]).with_budget(wide),
        )
        .unwrap();
    let lane = agent.create_lane("bench", wide).unwrap();
    (agent, cap, lane)
}

/// The native HTTP/2 transport over loopback: one call, then eight calls
/// multiplexed on one connection. The server runs on its own thread for the
/// lifetime of the group, so the numbers exclude handshakes.
#[cfg(feature = "http2")]
fn bench_http2(criterion: &mut Criterion) {
    use active_rpc::transport::http2::{Http2Client, Http2Server};

    let server = Http2Server::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let handle = std::thread::spawn(move || {
        server
            .serve(1, |envelope: Envelope| {
                Envelope::response(envelope.request_id, Value::text("pong"))
            })
            .expect("serve");
    });
    let mut client = Http2Client::connect(&address).expect("connect");
    let request = Envelope::request(1, "ping", vec![]);

    let mut group = criterion.benchmark_group("transport/http2");
    group.bench_function("call", |bencher| {
        bencher.iter(|| black_box(client.call(&request).expect("call")));
    });
    group.bench_function("call-many-8", |bencher| {
        bencher.iter(|| {
            let batch: Vec<Envelope> = (0..8u64)
                .map(|id| Envelope::request(id, "ping", vec![]))
                .collect();
            black_box(client.call_many(&batch).expect("calls"))
        });
    });
    group.finish();
    drop(client);
    handle.join().expect("server thread");
}

#[cfg(feature = "http2")]
criterion_group!(transport_benches, benches, bench_http2);
#[cfg(not(feature = "http2"))]
criterion_group!(transport_benches, benches);
criterion_main!(transport_benches);
