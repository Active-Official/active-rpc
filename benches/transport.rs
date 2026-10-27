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
        let object =
            provider.install(active_rpc::domain::module_from_source(SOURCE, "bench").unwrap());
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
}

criterion_group!(transport_benches, benches);
criterion_main!(transport_benches);
