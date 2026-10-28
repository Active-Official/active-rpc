//! Table-driven red-team battery for Active RPC.
//!
//! Every case names the checklist item it implements and the invariant it
//! defends. The harness catches a panic per case, runs the whole table, and
//! reports every failure instead of stopping at the first one.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use active_rpc::cap::CapAttrs;
use active_rpc::domain::ModuleProvider;
use active_rpc::error::Result;
use active_rpc::tool::{HttpTool, LocalProcess};
use active_rpc::transport::connect::{grpc_frame, grpc_unframe};
use active_rpc::transport::shm::SharedSegment;
use active_rpc::value::Call;
use active_rpc::wire::{decode_capability_table, Envelope, WireLimits};
use active_rpc::{Agent, Budget, CapId, Error, Provider, ProviderId, Response, ToolPolicy, Value};

struct Case {
    id: &'static str,
    invariant: &'static str,
    threat: &'static str,
    check: fn() -> std::result::Result<(), String>,
}

const CASES: &[Case] = &[
    Case {
        id: "H2.8",
        invariant: "I-4",
        threat: "forged, transplanted or bit-flipped capability id",
        check: h2_08_forge,
    },
    Case {
        id: "H2.9",
        invariant: "I-5",
        threat: "attenuate then widen a method, budget, path or policy",
        check: h2_09_widen,
    },
    Case {
        id: "H2.10",
        invariant: "I-6",
        threat: "revoke after queue, drop the last handle",
        check: h2_10_revoke,
    },
    Case {
        id: "H2.11",
        invariant: "I-11",
        threat: "confused deputy across two providers",
        check: h2_11_deputy,
    },
    Case {
        id: "H2.12",
        invariant: "I-11",
        threat: "tool adapter escape from the allow-list",
        check: h2_12_tool,
    },
    Case {
        id: "H2.13",
        invariant: "I-6",
        threat: "revocation racing with dispatch",
        check: h2_13_race,
    },
    Case {
        id: "H2.18",
        invariant: "I-3",
        threat: "secret material in telemetry events",
        check: h2_18_events,
    },
    Case {
        id: "H2.19",
        invariant: "I-8",
        threat: "queue storm under a low call budget",
        check: h2_19_queue,
    },
    Case {
        id: "H2.20",
        invariant: "I-8",
        threat: "nested value byte bomb",
        check: h2_20_byte_bomb,
    },
    Case {
        id: "H2.23",
        invariant: "I-8",
        threat: "zero ceiling accepted",
        check: h2_23_zero,
    },
    Case {
        id: "H2.26",
        invariant: "I-12",
        threat: "pipelining changes the authorization side effects",
        check: h2_26_pipeline,
    },
    Case {
        id: "H2.29",
        invariant: "I-12",
        threat: "read-only capability mutates",
        check: h2_29_read_only,
    },
    Case {
        id: "H2.32",
        invariant: "I-10",
        threat: "errors leak payload or use unstable codes",
        check: h2_32_errors,
    },
    Case {
        id: "H2.34",
        invariant: "I-10",
        threat: "the committed fuzz corpus as hostile input",
        check: h2_34_corpus,
    },
    Case {
        id: "H2.42",
        invariant: "I-4",
        threat: "cross-kernel capability transplant",
        check: h2_42_transplant,
    },
    Case {
        id: "H2.43",
        invariant: "I-3",
        threat: "secret in events after a module call",
        check: h2_43_events,
    },
    Case {
        id: "H2.45",
        invariant: "I-8",
        threat: "concurrent shared-memory frame churn",
        check: h2_45_shm,
    },
    Case {
        id: "H2.46",
        invariant: "I-11",
        threat: "absolute, dot-segment or encoded path escape",
        check: h2_46_path,
    },
];

struct Counting {
    calls: Arc<AtomicUsize>,
    drops: Arc<Mutex<Vec<(u64, CapId)>>>,
    methods: &'static [&'static str],
}

impl Provider for Counting {
    fn name(&self) -> &'static str {
        "counting"
    }
    fn methods(&self) -> Vec<String> {
        self.methods.iter().map(|name| name.to_string()).collect()
    }
    fn mutating(&self, method: &str) -> bool {
        method == "mutate"
    }
    fn invoke(&mut self, _object: u64, call: &Call) -> Result<Response> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if call.method == "fail" {
            return Err(Error::Provider {
                code: "fuzz/fail".into(),
            });
        }
        Ok(Response::Value(Value::text("pong")))
    }
    fn on_drop(&mut self, object: u64, cap: CapId) {
        if let Ok(mut drops) = self.drops.lock() {
            drops.push((object, cap));
        }
    }
    fn take_drop_notifications(&mut self) -> Vec<(u64, CapId)> {
        self.drops
            .lock()
            .map(|mut drops| std::mem::take(&mut *drops))
            .unwrap_or_default()
    }
}

fn agent(seed: u8) -> Agent {
    Agent::with_secret([seed; 32])
}

fn provider(
    agent: &Agent,
    calls: &Arc<AtomicUsize>,
    drops: &Arc<Mutex<Vec<(u64, CapId)>>>,
) -> ProviderId {
    agent.register(Box::new(Counting {
        calls: Arc::clone(calls),
        drops: Arc::clone(drops),
        methods: &["ping", "echo", "fail", "mutate"],
    }))
}

fn mint(agent: &Agent, provider: ProviderId, methods: &[&str]) -> active_rpc::CapHandle {
    agent
        .mint(provider, 0, CapAttrs::new(methods))
        .expect("mint")
}

fn expect_code(error: Error, expected: &str) -> std::result::Result<(), String> {
    if error.code() == expected {
        Ok(())
    } else {
        Err(format!("expected {expected}, got {}", error.code()))
    }
}

fn h2_08_forge() -> std::result::Result<(), String> {
    let agent = agent(8);
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(Mutex::new(Vec::new()));
    let provider = provider(&agent, &calls, &drops);
    let lane = agent
        .create_lane("main", Budget::default())
        .map_err(|e| e.to_string())?;
    let cap = mint(&agent, provider, &["ping"]);

    for id in [CapId([0u8; 16]), CapId([0xff; 16])] {
        let forged = agent.import(id);
        let error = agent
            .call(lane, &forged, "ping", vec![])
            .expect_err("forged id");
        expect_code(error, "rpc/unknown-capability")?;
    }
    let mut flipped = cap.id().0;
    flipped[0] ^= 1;
    let forged = agent.import(CapId(flipped));
    expect_code(
        agent
            .call(lane, &forged, "ping", vec![])
            .expect_err("flipped id"),
        "rpc/unknown-capability",
    )?;
    if calls.load(Ordering::SeqCst) != 0 {
        return Err("a forged id reached the provider".into());
    }
    Ok(())
}

fn h2_09_widen() -> std::result::Result<(), String> {
    let agent = agent(9);
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(Mutex::new(Vec::new()));
    let provider = provider(&agent, &calls, &drops);
    let parent = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["ping"])
                .with_path("app")
                .with_tool_policy(ToolPolicy::allow(&["get"])),
        )
        .map_err(|e| e.to_string())?;

    expect_code(
        agent
            .attenuate(&parent, CapAttrs::new(&["ping", "echo"]))
            .expect_err("method widening"),
        "rpc/attenuation-escalation",
    )?;
    expect_code(
        agent
            .attenuate(
                &parent,
                CapAttrs::new(&["ping"]).with_budget(Budget::calls(99)),
            )
            .expect_err("budget widening"),
        "rpc/attenuation-escalation",
    )?;
    expect_code(
        agent
            .attenuate(&parent, CapAttrs::new(&["ping"]).with_path("other"))
            .expect_err("path widening"),
        "rpc/attenuation-escalation",
    )?;
    expect_code(
        agent
            .attenuate(
                &parent,
                CapAttrs::new(&["ping"]).with_tool_policy(ToolPolicy::allow(&["get", "post"])),
            )
            .expect_err("tool policy widening"),
        "rpc/attenuation-escalation",
    )?;
    // Narrowing is accepted.
    let child = agent
        .attenuate(
            &parent,
            CapAttrs::new(&["ping"])
                .with_path("app.sub")
                .with_tool_policy(ToolPolicy::allow(&["get"])),
        )
        .map_err(|e| e.to_string())?;
    let attrs = agent.cap_attrs(&child).map_err(|e| e.to_string())?;
    if attrs.methods.len() != 1 {
        return Err("narrowed method set is wrong".into());
    }
    Ok(())
}

fn h2_10_revoke() -> std::result::Result<(), String> {
    let agent = agent(10);
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(Mutex::new(Vec::new()));
    let provider = provider(&agent, &calls, &drops);
    let lane = agent
        .create_lane("main", Budget::default())
        .map_err(|e| e.to_string())?;
    let cap = mint(&agent, provider, &["ping"]);

    let promise = agent
        .call(lane, &cap, "ping", vec![])
        .map_err(|e| e.to_string())?;
    agent.revoke(&cap);
    let _ = promise.value();
    if calls.load(Ordering::SeqCst) != 0 {
        return Err("a revoked queued call reached the provider".into());
    }

    let second = mint(&agent, provider, &["ping"]);
    drop(second);
    let notifications = agent.take_drops(provider);
    if notifications.is_empty() {
        return Err("the last handle drop did not notify the provider".into());
    }
    Ok(())
}

fn h2_11_deputy() -> std::result::Result<(), String> {
    let agent = agent(11);
    let calls_a = Arc::new(AtomicUsize::new(0));
    let calls_b = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(Mutex::new(Vec::new()));
    let a = provider(&agent, &calls_a, &drops);
    let b = provider(&agent, &calls_b, &drops);
    let lane = agent
        .create_lane("main", Budget::default())
        .map_err(|e| e.to_string())?;
    let cap_a = mint(&agent, a, &["ping"]);
    // Provider B has no "ping" method; the capability for A must not reach B.
    let error = agent.call(lane, &cap_a, "ping", vec![]);
    // The call is queued against A; run it and prove B never saw it.
    if let Ok(promise) = error {
        let _ = promise.value();
    }
    if calls_b.load(Ordering::SeqCst) != 0 {
        return Err("provider B served a call addressed to A".into());
    }
    let _ = b;
    Ok(())
}

fn h2_12_tool() -> std::result::Result<(), String> {
    let agent = agent(12);
    let lane = agent
        .create_lane("tools", Budget::default())
        .map_err(|e| e.to_string())?;

    let http = agent.register(Box::new(HttpTool::new(
        "http://127.0.0.1:1",
        &[("GET", "/safe")],
    )));
    let http_cap = agent
        .mint(
            http,
            0,
            CapAttrs::new(&["get"]).with_tool_policy(ToolPolicy::allow(&["get"])),
        )
        .map_err(|e| e.to_string())?;
    let promise = agent
        .call(
            lane,
            &http_cap,
            "get",
            vec![active_rpc::Arg::text("/safe/../admin")],
        )
        .map_err(|e| e.to_string())?;
    let error = promise.value().expect_err("path escape");
    if !matches!(error.code(), "rpc/tool-policy" | "rpc/invalid-argument") {
        return Err(format!("unexpected HTTP escape code {}", error.code()));
    }

    let process = agent.register(Box::new(LocalProcess::new(
        "/nonexistent-active-fuzz-binary",
        &["ok"],
    )));
    let process_cap = agent
        .mint(
            process,
            0,
            CapAttrs::new(&["run"]).with_tool_policy(ToolPolicy {
                allowed: ["run"].iter().map(|name| name.to_string()).collect(),
                max_arg_bytes: 64,
                allow_process: true,
            }),
        )
        .map_err(|e| e.to_string())?;
    let promise = agent
        .call(
            lane,
            &process_cap,
            "run",
            vec![active_rpc::Arg::text("ok;rm -rf /")],
        )
        .map_err(|e| e.to_string())?;
    let error = promise.value().expect_err("argv escape");
    expect_code(error, "rpc/tool-policy")?;
    Ok(())
}

fn h2_13_race() -> std::result::Result<(), String> {
    let agent = agent(13);
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(Mutex::new(Vec::new()));
    let provider = provider(&agent, &calls, &drops);
    let lane = agent
        .create_lane("main", Budget::default())
        .map_err(|e| e.to_string())?;
    let cap = mint(&agent, provider, &["ping"]);
    let promise = agent
        .call(lane, &cap, "ping", vec![])
        .map_err(|e| e.to_string())?;
    agent.revoke(&cap);
    agent.run();
    let _ = promise.value();
    if calls.load(Ordering::SeqCst) != 0 {
        return Err("revocation did not win the dispatch race".into());
    }
    Ok(())
}

fn secret_module(literal: &str) -> active_infinity::InfinityModule {
    let mut module = active_infinity::InfinityModule::new();
    let secret = module.push(active_infinity::Inode::Secret(
        active_infinity::SecretBytes::from(literal),
    ));
    let app = module.push(active_infinity::Inode::Table {
        fields: vec![("token".into(), secret)],
    });
    let root = module.push(active_infinity::Inode::Table {
        fields: vec![("app".into(), app)],
    });
    module.set_root(Some(root));
    module
}

fn module_provider(agent: &Agent, literal: &str) -> (ProviderId, u64) {
    let mut provider = ModuleProvider::new();
    let object = provider.install(secret_module(literal));
    (agent.register(Box::new(provider)), object)
}

fn h2_18_events() -> std::result::Result<(), String> {
    let literal = "redteam-events-canary";
    let agent = agent(18);
    let (provider, object) = module_provider(&agent, literal);
    let lane = agent
        .create_lane("main", Budget::default())
        .map_err(|e| e.to_string())?;
    let cap = agent
        .mint(provider, object, CapAttrs::new(&["subgraph", "evaluate"]))
        .map_err(|e| e.to_string())?;
    let promise = agent
        .call(
            lane,
            &cap,
            "subgraph",
            vec![active_rpc::Arg::value(Value::Path("app".into()))],
        )
        .map_err(|e| e.to_string())?;
    let _ = promise.value();
    let events = format!("{:?}", agent.events());
    if events.contains(literal) {
        return Err(format!("an event carried the secret: {events}"));
    }
    let raw = cap.id().hex();
    if events.contains(&raw) {
        return Err("an event carried raw capability authority bits".into());
    }
    Ok(())
}

fn h2_19_queue() -> std::result::Result<(), String> {
    let agent = agent(19);
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(Mutex::new(Vec::new()));
    let provider = provider(&agent, &calls, &drops);
    let lane = agent
        .create_lane("tight", Budget::calls(1))
        .map_err(|e| e.to_string())?;
    let cap = mint(&agent, provider, &["ping"]);
    let first = agent
        .call(lane, &cap, "ping", vec![])
        .map_err(|e| e.to_string())?;
    let _ = first.value();
    let error = agent
        .call(lane, &cap, "ping", vec![])
        .expect_err("queue storm");
    if error.code() != "rpc/budget-exceeded" {
        return Err(format!("unexpected queue-storm code {}", error.code()));
    }
    Ok(())
}

fn h2_20_byte_bomb() -> std::result::Result<(), String> {
    let agent = agent(20);
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(Mutex::new(Vec::new()));
    let provider = provider(&agent, &calls, &drops);
    let tight = Budget {
        max_bytes: 128,
        max_value_size: 128,
        max_depth: 8,
        ..Budget::default()
    };
    let lane = agent
        .create_lane("tight", tight)
        .map_err(|e| e.to_string())?;
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["ping"]).with_budget(tight))
        .map_err(|e| e.to_string())?;
    let mut value = Value::Int(1);
    for _ in 0..64 {
        value = Value::List(vec![value]);
    }
    let error = agent
        .call(lane, &cap, "ping", vec![active_rpc::Arg::Value(value)])
        .expect_err("byte bomb");
    if !matches!(error.code(), "rpc/budget-exceeded" | "rpc/invalid-argument") {
        return Err(format!("unexpected byte-bomb code {}", error.code()));
    }
    if calls.load(Ordering::SeqCst) != 0 {
        return Err("an over-budget value reached the provider".into());
    }
    Ok(())
}

fn h2_23_zero() -> std::result::Result<(), String> {
    let agent = agent(23);
    let provider = agent.register(Box::new(Counting {
        calls: Arc::new(AtomicUsize::new(0)),
        drops: Arc::new(Mutex::new(Vec::new())),
        methods: &["ping"],
    }));
    let zeros = [
        Budget {
            max_calls: 0,
            ..Budget::default()
        },
        Budget {
            max_bytes: 0,
            ..Budget::default()
        },
        Budget {
            max_wall_ms: 0,
            ..Budget::default()
        },
        Budget {
            max_nodes: 0,
            ..Budget::default()
        },
        Budget {
            max_depth: 0,
            ..Budget::default()
        },
        Budget {
            max_array_len: 0,
            ..Budget::default()
        },
        Budget {
            max_value_size: 0,
            ..Budget::default()
        },
    ];
    for zero in zeros {
        expect_code(
            agent
                .create_lane("zero", zero)
                .expect_err("zero lane ceiling"),
            "rpc/invalid-argument",
        )?;
        expect_code(
            agent
                .mint(provider, 0, CapAttrs::new(&["ping"]).with_budget(zero))
                .expect_err("zero cap ceiling"),
            "rpc/invalid-argument",
        )?;
    }
    Ok(())
}

fn h2_26_pipeline() -> std::result::Result<(), String> {
    let agent = agent(26);
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(Mutex::new(Vec::new()));
    let provider = provider(&agent, &calls, &drops);
    let lane = agent
        .create_lane("main", Budget::default())
        .map_err(|e| e.to_string())?;
    let cap = mint(&agent, provider, &["ping", "echo"]);
    let first = agent
        .call(lane, &cap, "ping", vec![])
        .map_err(|e| e.to_string())?;
    let second = agent
        .call(
            lane,
            &cap,
            "echo",
            vec![active_rpc::Arg::Promise(first.id())],
        )
        .map_err(|e| e.to_string())?;
    let _ = second.value();
    if calls.load(Ordering::SeqCst) != 2 {
        return Err(format!(
            "pipelined chain ran {} provider calls, expected 2",
            calls.load(Ordering::SeqCst)
        ));
    }
    Ok(())
}

fn h2_29_read_only() -> std::result::Result<(), String> {
    let agent = agent(29);
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(Mutex::new(Vec::new()));
    let provider = provider(&agent, &calls, &drops);
    let lane = agent
        .create_lane("main", Budget::default())
        .map_err(|e| e.to_string())?;
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["mutate"]).read_only())
        .map_err(|e| e.to_string())?;
    // A read-only refusal can happen at enqueue (the kernel knows the cap) or
    // at dispatch (the provider declares the method mutating); both are valid.
    match agent.call(lane, &cap, "mutate", vec![]) {
        Err(error) => expect_code(error, "rpc/read-only")?,
        Ok(promise) => {
            let error = promise.value().expect_err("read-only mutation");
            expect_code(error, "rpc/read-only")?;
        }
    }
    Ok(())
}

fn h2_32_errors() -> std::result::Result<(), String> {
    let agent = agent(32);
    let provider = agent.register(Box::new(Counting {
        calls: Arc::new(AtomicUsize::new(0)),
        drops: Arc::new(Mutex::new(Vec::new())),
        methods: &["fail"],
    }));
    let lane = agent
        .create_lane("main", Budget::default())
        .map_err(|e| e.to_string())?;
    let cap = mint(&agent, provider, &["fail"]);
    let promise = agent
        .call(lane, &cap, "fail", vec![])
        .map_err(|e| e.to_string())?;
    let error = promise.value().expect_err("provider failure");
    if error.code() != "rpc/provider" {
        return Err(format!("unexpected provider code {}", error.code()));
    }
    if !error.to_string().contains("fuzz/fail") {
        return Err("the provider code was lost".into());
    }
    Ok(())
}

fn corpus_files(directory: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            corpus_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn h2_34_corpus() -> std::result::Result<(), String> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    corpus_files(&root.join("fuzz").join("corpus"), &mut files);
    if files.is_empty() {
        return Err("no corpus files".into());
    }
    for file in files {
        let bytes = std::fs::read(&file).map_err(|e| e.to_string())?;
        let _ = Envelope::decode(&bytes);
        let _ = Envelope::decode_with(&bytes, WireLimits::strict());
        let _ = decode_capability_table(&bytes);
        if let Ok((message, _)) = grpc_unframe(&bytes) {
            let framed = grpc_frame(message);
            let _ = grpc_unframe(&framed);
        }
    }
    Ok(())
}

fn h2_42_transplant() -> std::result::Result<(), String> {
    let first = agent(42);
    let second = agent(43);
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(Mutex::new(Vec::new()));
    let provider = provider(&first, &calls, &drops);
    let cap = mint(&first, provider, &["ping"]);
    let lane = second
        .create_lane("main", Budget::default())
        .map_err(|e| e.to_string())?;
    let imported = second.import(cap.id());
    expect_code(
        second
            .call(lane, &imported, "ping", vec![])
            .expect_err("transplant"),
        "rpc/unknown-capability",
    )?;
    if calls.load(Ordering::SeqCst) != 0 {
        return Err("a transplanted capability reached the provider".into());
    }
    Ok(())
}

fn h2_43_events() -> std::result::Result<(), String> {
    let literal = "redteam-events-43-canary";
    let agent = agent(43);
    let (provider, object) = module_provider(&agent, literal);
    let lane = agent
        .create_lane("main", Budget::default())
        .map_err(|e| e.to_string())?;
    let cap = agent
        .mint(provider, object, CapAttrs::new(&["evaluate"]))
        .map_err(|e| e.to_string())?;
    let promise = agent
        .call(lane, &cap, "evaluate", vec![])
        .map_err(|e| e.to_string())?;
    let _ = promise.value();
    let events = format!("{:?}", agent.events());
    if events.contains(literal) {
        return Err("an event carried the secret literal".into());
    }
    Ok(())
}

fn h2_45_shm() -> std::result::Result<(), String> {
    let segment = SharedSegment::new(4096);
    let producer = Arc::clone(&segment);
    let consumer = Arc::clone(&segment);
    let writer = std::thread::spawn(move || {
        let frame = vec![0x42u8; 128];
        for _ in 0..2000 {
            if producer.write(&frame).is_err() {
                break;
            }
        }
    });
    let reader = std::thread::spawn(move || {
        for _ in 0..2000 {
            if consumer.read().is_err() {
                break;
            }
        }
    });
    writer.join().map_err(|_| "producer panicked".to_string())?;
    reader.join().map_err(|_| "consumer panicked".to_string())?;
    if segment.available() > segment.capacity() {
        return Err("the ring reported more than its capacity".into());
    }
    Ok(())
}

fn h2_46_path() -> std::result::Result<(), String> {
    let agent = agent(46);
    let lane = agent
        .create_lane("http", Budget::default())
        .map_err(|e| e.to_string())?;
    let http = agent.register(Box::new(HttpTool::new(
        "http://127.0.0.1:1",
        &[("GET", "/safe")],
    )));
    let cap = agent
        .mint(
            http,
            0,
            CapAttrs::new(&["get"])
                .with_tool_policy(ToolPolicy::allow(&["get"]))
                .with_budget(Budget::default()),
        )
        .map_err(|e| e.to_string())?;
    for path in [
        "http://127.0.0.1:1/admin",
        "/safe/../admin",
        "/safe%2f..%2fadmin",
        "//admin",
    ] {
        let promise = agent
            .call(lane, &cap, "get", vec![active_rpc::Arg::text(path)])
            .map_err(|e| e.to_string())?;
        let error = promise.value().expect_err("path escape");
        if !matches!(error.code(), "rpc/tool-policy" | "rpc/invalid-argument") {
            return Err(format!("path {path} returned {}", error.code()));
        }
    }
    Ok(())
}

#[test]
fn redteam_battery_is_green() {
    let mut failures = Vec::new();
    for case in CASES {
        match catch_unwind(AssertUnwindSafe(case.check)) {
            Ok(Ok(())) => println!("PASS {} ({}) {}", case.id, case.invariant, case.threat),
            Ok(Err(message)) => failures.push(format!(
                "{} ({}) {}: {message}",
                case.id, case.invariant, case.threat
            )),
            Err(payload) => {
                let message = payload
                    .downcast_ref::<&str>()
                    .map(|text| text.to_string())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "non-string panic".into());
                failures.push(format!(
                    "{} ({}) {}: panicked: {message}",
                    case.id, case.invariant, case.threat
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} red-team cases failed:\n{}",
        failures.len(),
        CASES.len(),
        failures.join("\n")
    );
}
