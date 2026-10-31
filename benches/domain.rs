//! Domain-provider hot path.
//!
//! Two costs used to be paid on every call to a module capability: a full deep
//! clone of the module arena, and a canonical re-encode for `content_hash`.
//! Both are gone; this bench measures the shipped path next to the work that was
//! removed, so the numbers in `docs/spec/performance.md` describe real work
//! rather than a synthetic microbenchmark.
//!
//! Every arm drives the shipped `Provider::invoke` except the two `removed_*`
//! arms, which perform exactly the work the old implementation did (clone the
//! module; encode plus hash) on the same fixture.

use active_rpc::domain::ModuleProvider;
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Value};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

/// A module with a real shape: nested tables, an array, a quantity expression,
/// an environment default, string interpolation and one secret so the redaction
/// paths stay exercised.
const SOURCE: &str = r#"
# @intent: "domain benchmark fixture"
# @ai_immutable: true
[app]
name        = "domain-bench"
environment = env.APP_ENV ?: "test"
debug       = true

let base = "https://api.example.com"
let timeout = 1500ms
let retries = 3

[server]
host         = "127.0.0.1"
port         = 8080
read_timeout = timeout * 2
ratio        = 25%

[services]
auth_url  = "${base}/auth"
users_url = "${base}/users"
weights   = [1, 2, 3, 5, 8, 13]

[database]
host     = "localhost"
password = secret("bench-canary")
pool     = 16
"#;

fn fixture() -> (ModuleProvider, u64, active_infinity::InfinityModule) {
    let module =
        active_rpc::domain::module_from_source(SOURCE, "bench.active").expect("fixture module");
    let mut provider = ModuleProvider::new();
    let object = provider.install(module.clone());
    (provider, object, module)
}

fn call(method: &str, args: Vec<Arg>) -> Call {
    Call::new(method, args)
}

/// Drive one call through the shipped provider and return the response.
fn invoke(provider: &mut ModuleProvider, object: u64, call: &Call) -> active_rpc::Response {
    provider.invoke(object, call).expect("call")
}

fn bench_stats(c: &mut Criterion) {
    let mut group = c.benchmark_group("domain_stats");
    let (mut provider, object, module) = fixture();
    let stats = call("stats", vec![]);

    group.bench_function("shipped", |b| {
        b.iter(|| black_box(invoke(&mut provider, object, &stats)))
    });

    // What the old implementation did before answering: copy the whole arena.
    group.bench_function("removed_clone", |b| {
        b.iter(|| {
            let copy = module.clone();
            black_box(copy.node_count())
        })
    });
    group.finish();
}

fn bench_content_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("domain_content_hash");
    let (mut provider, object, module) = fixture();
    let hash = call("content_hash", vec![]);

    group.bench_function("shipped_cached", |b| {
        b.iter(|| black_box(invoke(&mut provider, object, &hash)))
    });

    // The encode + hash the old implementation repeated on every call.
    group.bench_function("removed_encode_hash", |b| {
        b.iter(|| {
            let bytes = active_infinity::encode(&module).expect("encode");
            black_box(active_infinity::content_hash(&bytes).expect("hash"))
        })
    });
    group.finish();
}

fn bench_path_calls(c: &mut Criterion) {
    let mut group = c.benchmark_group("domain_path");
    let (mut provider, object, module) = fixture();
    // `auth_url` interpolates `base`, so `why` has a real dependency edge.
    let why = call(
        "why",
        vec![Arg::Value(Value::Path("services.auth_url".to_string()))],
    );
    let subgraph = call(
        "subgraph",
        vec![Arg::Value(Value::Path("services".to_string()))],
    );

    for (name, request) in [("why", &why), ("subgraph", &subgraph)] {
        group.bench_with_input(BenchmarkId::new("shipped", name), request, |b, request| {
            b.iter(|| black_box(invoke(&mut provider, object, request)))
        });
    }
    // Resolving the path is part of the shipped cost; this isolates the
    // resolution alone so a regression in it is visible.
    group.bench_function("removed_clone", |b| {
        b.iter(|| {
            let copy = module.clone();
            black_box(copy.node_count())
        })
    });
    group.finish();
}

fn bench_evaluate(c: &mut Criterion) {
    let mut group = c.benchmark_group("domain_evaluate");
    let (mut provider, object, _module) = fixture();
    let root = call("evaluate", vec![]);
    group.bench_function("root", |b| {
        b.iter(|| black_box(invoke(&mut provider, object, &root)))
    });
    let scoped = call(
        "evaluate",
        vec![Arg::Value(Value::Path("services".to_string()))],
    );
    group.bench_function("scoped", |b| {
        b.iter(|| black_box(invoke(&mut provider, object, &scoped)))
    });
    group.finish();
}

/// The per-call floor of the provider interface, so the module work above can
/// be read as a delta rather than as an absolute.
struct Noop;

impl Provider for Noop {
    fn name(&self) -> &'static str {
        "noop"
    }
    fn methods(&self) -> Vec<String> {
        vec!["ping".to_string()]
    }
    fn mutating(&self, _method: &str) -> bool {
        false
    }
    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<active_rpc::Response> {
        Ok(active_rpc::Response::Value(Value::Null))
    }
}

fn bench_floor(c: &mut Criterion) {
    let mut group = c.benchmark_group("domain_floor");
    let mut noop = Noop;
    let ping = call("ping", vec![]);
    group.bench_function("noop_invoke", |b| {
        b.iter(|| black_box(noop.invoke(0, &ping).expect("call")))
    });
    let (mut provider, object, _module) = fixture();
    let stats = call("stats", vec![]);
    group.bench_function("stats_shipped", |b| {
        b.iter(|| black_box(invoke(&mut provider, object, &stats)))
    });
    group.finish();
}

/// The pieces the provider pays per call, measured alone so a regression can be
/// attributed instead of guessed at.
fn bench_components(c: &mut Criterion) {
    let mut group = c.benchmark_group("domain_components");
    let module = active_rpc::domain::module_from_source(SOURCE, "bench.active").expect("module");
    let bytes = active_infinity::encode(&module).expect("encode");
    let hash = active_infinity::content_hash(&bytes).expect("hash");

    group.bench_function("hash_hex", |b| {
        b.iter(|| black_box(active_infinity::ir::hash_hex(&hash)))
    });
    group.bench_function("format_text", |b| {
        b.iter(|| black_box(format!("blake3:{}", active_infinity::ir::hash_hex(&hash))))
    });
    group.bench_function("edges", |b| b.iter(|| black_box(module.edges().len())));
    group.bench_function("node_count", |b| b.iter(|| black_box(module.node_count())));
    group.bench_function("encode", |b| {
        b.iter(|| black_box(active_infinity::encode(&module).expect("encode")))
    });
    group.bench_function("encode_and_hash", |b| {
        b.iter(|| {
            let bytes = active_infinity::encode(&module).expect("encode");
            black_box(active_infinity::content_hash(&bytes).expect("hash"))
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_stats,
    bench_content_hash,
    bench_path_calls,
    bench_evaluate,
    bench_floor,
    bench_components
);
criterion_main!(benches);
