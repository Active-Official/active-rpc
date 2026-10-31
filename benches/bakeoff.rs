//! Public RPC bakeoff skeleton.
//!
//! Measures the shipped in-process kernel: sequential calls versus a dependent
//! promise chain, with the round-trip count asserted by the harness. gRPC
//! adapter lands in C-7.3.

use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, Budget, Envelope};
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

mod competitors {
    //! A gRPC-shaped message with the same logical call: method, an integer
    //! argument and a payload, framed with the gRPC five-byte prefix.
    //!
    //! Scope: the message path only. A real gRPC exchange also pays HTTP/2
    //! framing and HPACK headers, which the transport benchmarks measure
    //! separately (`benches/transport.rs`); this adapter isolates the cost of
    //! the call encoding.
    use prost::Message;

    #[derive(Clone, PartialEq, Message)]
    pub struct GrpcCall {
        #[prost(string, tag = "1")]
        pub method: String,
        #[prost(int64, tag = "2")]
        pub argument: i64,
        #[prost(bytes = "vec", tag = "3")]
        pub payload: Vec<u8>,
    }

    pub fn grpc_encode(call: &GrpcCall) -> Vec<u8> {
        let body = call.encode_to_vec();
        let mut framed = Vec::with_capacity(5 + body.len());
        framed.push(0);
        framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
        framed.extend_from_slice(&body);
        framed
    }

    /// Decode with the same prefix and length validation a receiver performs.
    pub fn grpc_decode(bytes: &[u8]) -> Option<GrpcCall> {
        if bytes.len() < 5 || bytes[0] != 0 {
            return None;
        }
        let len = u32::from_be_bytes(bytes[1..5].try_into().ok()?) as usize;
        if bytes.len() != 5 + len {
            return None;
        }
        GrpcCall::decode(&bytes[5..]).ok()
    }
}

fn bench_protocol(c: &mut Criterion) {
    let payload = vec![0x41u8; 4096];
    let arp1 = Envelope::request(
        1,
        "echo",
        vec![Arg::Value(active_rpc::value::Value::Int(7))],
    );
    let arp1 = Envelope {
        payload: payload.clone(),
        ..arp1
    };
    let arp1_bytes = arp1.encode().expect("encode");
    let grpc_call = competitors::GrpcCall {
        method: "echo".to_string(),
        argument: 7,
        payload: payload.clone(),
    };
    let grpc_bytes = competitors::grpc_encode(&grpc_call);

    let mut group = c.benchmark_group("rpc_protocol");
    group.bench_function("arp1_encode", |b| {
        b.iter(|| black_box(arp1.encode().expect("encode")))
    });
    group.bench_function("grpc_encode", |b| {
        b.iter(|| black_box(competitors::grpc_encode(&grpc_call)))
    });
    group.bench_function("arp1_decode", |b| {
        b.iter(|| black_box(Envelope::decode(&arp1_bytes).expect("decode")))
    });
    group.bench_function("grpc_decode", |b| {
        b.iter(|| black_box(competitors::grpc_decode(&grpc_bytes).expect("decode")))
    });
    group.finish();
}

criterion_group!(benches, bench_rpc, bench_protocol);
criterion_main!(benches);
