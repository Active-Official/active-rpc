//! Public RPC bakeoff skeleton.
//!
//! Measures the shipped in-process kernel: sequential calls versus a dependent
//! promise chain, with the round-trip count asserted by the harness. gRPC
//! adapter lands in C-7.3.

use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, Budget};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

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

fn setup() -> (Agent, active_rpc::CapHandle, active_rpc::LaneId) {
    let agent = Agent::with_secret([0x42; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let lane = agent
        .create_lane("bakeoff", Budget::default())
        .expect("lane");
    (agent, cap, lane)
}

fn bench_rpc(c: &mut Criterion) {
    let mut group = c.benchmark_group("rpc_bakeoff");
    for calls in [10usize, 100] {
        group.bench_with_input(BenchmarkId::new("sequential", calls), &calls, |b, calls| {
            b.iter(|| {
                let (agent, cap, lane) = setup();
                for _ in 0..*calls {
                    let promise = agent
                        .call(lane, &cap, "echo", vec![Arg::text("bench")])
                        .expect("call");
                    black_box(promise.value().expect("value"));
                }
                black_box(agent.round_trips())
            });
        });
        group.bench_with_input(BenchmarkId::new("pipelined", calls), &calls, |b, calls| {
            b.iter(|| {
                let (agent, cap, lane) = setup();
                let mut promise = agent
                    .call(lane, &cap, "echo", vec![Arg::text("seed")])
                    .expect("head");
                for _ in 1..*calls {
                    promise = agent
                        .call(lane, &cap, "echo", vec![Arg::Promise(promise.id())])
                        .expect("link");
                }
                black_box(promise.value().expect("value"));
                black_box(agent.round_trips())
            });
        });
    }
    group.finish();
}

#[allow(dead_code)]
mod competitors {
    //! TODO(CHECKLIST C-7.3): gRPC/Connect sequential and pipelined adapter.

    pub fn grpc_round_trip() -> Option<u64> {
        None
    }
}

criterion_group!(benches, bench_rpc);
criterion_main!(benches);
