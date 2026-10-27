//! Integration tests: domain operations, transports and the cross-process peer.
//!
//! Each transport named in the proposal is exercised with a real payload: a
//! validated Infinity module plus a capability table. Malformed frames must come
//! back as errors, never panics.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

use active_rpc::cap::CapAttrs;
use active_rpc::domain::ModuleProvider;
use active_rpc::transport::connect::{BridgeServer, ConnectClient};
use active_rpc::transport::shm::{SharedMemoryTransport, SharedSegment};
use active_rpc::transport::{InProcessTransport, TcpTransport, Transport};
use active_rpc::value::{Arg, Value};
use active_rpc::wire::{CapDescriptor, Envelope, Kind};
use active_rpc::{Agent, Budget};

const SOURCE: &str = r#"
# @intent: "integration fixture"
[app]
name    = "integration"
port    = 8080
ratio   = 25%
routes  = ["/a", "/b"]

let timeout = 1500ms

[limits]
read_timeout = timeout * 2
token        = secret("integration-canary")
"#;

fn module() -> active_infinity::InfinityModule {
    active_rpc::domain::module_from_source(SOURCE, "integration.active").expect("module")
}

fn setup() -> (
    Agent,
    active_rpc::ProviderId,
    active_rpc::CapHandle,
    active_rpc::LaneId,
) {
    let mut provider = ModuleProvider::new();
    let object = provider.install(module());
    let agent = Agent::with_secret([21u8; 32]);
    let provider_id = agent.register(Box::new(provider));
    let cap = agent
        .mint(
            provider_id,
            object,
            CapAttrs::new(active_rpc::MODULE_METHODS),
        )
        .expect("mint");
    let lane = agent.create_lane("main", Budget::default()).expect("lane");
    (agent, provider_id, cap, lane)
}

#[test]
fn evaluate_runs_the_active_engine_over_the_binary_module() {
    let (agent, _provider, cap, lane) = setup();
    let promise = agent
        .call(
            lane,
            &cap,
            "evaluate",
            vec![Arg::Value(Value::Path("app".into()))],
        )
        .expect("call");
    let value = promise.value().expect("evaluate");
    let map = match value {
        Value::Map(map) => map,
        other => panic!("expected a map, got {other:?}"),
    };
    assert_eq!(map.get("name"), Some(&Value::text("integration")));
    assert_eq!(map.get("port"), Some(&Value::Int(8080)));
    let routes = match map.get("routes") {
        Some(Value::List(items)) => items.clone(),
        other => panic!("expected a list, got {other:?}"),
    };
    assert_eq!(routes.len(), 2);
}

#[test]
fn stats_hash_and_metadata_are_served_through_capabilities() {
    let (agent, _provider, cap, lane) = setup();
    let stats = agent
        .call(lane, &cap, "stats", vec![])
        .expect("call")
        .value()
        .expect("stats");
    let map = match stats {
        Value::Map(map) => map,
        other => panic!("expected map, got {other:?}"),
    };
    let nodes = match map.get("nodes") {
        Some(Value::Int(nodes)) => *nodes,
        other => panic!("expected nodes, got {other:?}"),
    };
    assert!(nodes > 10);
    assert_eq!(map.get("secrets"), Some(&Value::Int(1)));

    let hash = agent
        .call(lane, &cap, "content_hash", vec![])
        .expect("call")
        .value()
        .expect("hash");
    let hash = hash.as_text().expect("text").to_string();
    assert!(hash.starts_with("blake3:"), "{hash}");
    let again = agent
        .call(lane, &cap, "content_hash", vec![])
        .expect("call")
        .value()
        .expect("hash");
    assert_eq!(again.as_text().unwrap(), hash, "content address is stable");

    let provenance = agent
        .call(lane, &cap, "provenance", vec![])
        .expect("call")
        .value()
        .expect("provenance");
    assert_eq!(provenance, Value::Null);
}

#[test]
fn why_and_impact_answer_with_paths() {
    let (agent, _provider, cap, lane) = setup();
    let why = agent
        .call(
            lane,
            &cap,
            "why",
            vec![Arg::Value(Value::Path("limits.read_timeout".into()))],
        )
        .expect("call")
        .value()
        .expect("why");
    let labels = label_list(&why);
    assert!(
        labels.iter().any(|label| label == "timeout"),
        "why must include the binding: {labels:?}"
    );

    let impact = agent
        .call(
            lane,
            &cap,
            "impact",
            vec![Arg::Value(Value::Path("app.port".into()))],
        )
        .expect("call")
        .value()
        .expect("impact");
    let labels = label_list(&impact);
    assert!(
        labels.iter().any(|label| label == "app"),
        "impact must include the table: {labels:?}"
    );
}

fn label_list(value: &Value) -> Vec<String> {
    match value {
        Value::List(items) => items
            .iter()
            .filter_map(|item| item.as_text().map(|text| text.to_string()))
            .collect(),
        other => panic!("expected labels, got {other:?}"),
    }
}

#[test]
fn redaction_hides_the_secret_cone() {
    let (agent, _provider, cap, lane) = setup();
    let redacted = agent
        .attenuate(&cap, CapAttrs::new(&["why", "impact"]).redacted())
        .expect("attenuate");
    let value = agent
        .call(
            lane,
            &redacted,
            "why",
            vec![Arg::Value(Value::Path("limits.token".into()))],
        )
        .expect("call")
        .value()
        .expect("why");
    let labels = label_list(&value);
    assert_eq!(labels, vec!["***SECRET***".to_string()]);

    // Without redaction the paths are visible — values never are.
    let value = agent
        .call(
            lane,
            &cap,
            "why",
            vec![Arg::Value(Value::Path("limits.token".into()))],
        )
        .expect("call")
        .value()
        .expect("why");
    let labels = label_list(&value);
    assert!(!labels.is_empty(), "why must answer with dependencies");
    assert!(
        !labels.iter().any(|label| label.contains("canary")),
        "no label may carry secret material: {labels:?}"
    );
}

#[test]
fn subgraph_returns_a_valid_module() {
    let (agent, _provider, cap, lane) = setup();
    let value = agent
        .call(
            lane,
            &cap,
            "subgraph",
            vec![Arg::Value(Value::Path("app".into()))],
        )
        .expect("call")
        .value()
        .expect("subgraph");
    let bytes = match value {
        Value::Module(bytes) => bytes,
        other => panic!("expected module bytes, got {other:?}"),
    };
    let meta = active_infinity::validate(&bytes).expect("subgraph is a valid image");
    assert!(meta.nodes > 0);
    let decoded = active_infinity::decode(&bytes).expect("decode");
    assert!(decoded.root().is_some());
}

#[test]
fn patch_creates_a_new_module_version() {
    let (agent, _provider, cap, lane) = setup();
    let before = agent
        .call(lane, &cap, "content_hash", vec![])
        .unwrap()
        .value()
        .unwrap();
    let value = agent
        .call(
            lane,
            &cap,
            "patch",
            vec![
                Arg::Value(Value::Path("app.port".into())),
                Arg::value(Value::Int(9090)),
            ],
        )
        .expect("call")
        .value()
        .expect("patch");
    let bytes = match value {
        Value::Module(bytes) => bytes,
        other => panic!("expected module bytes, got {other:?}"),
    };
    let patched = active_infinity::decode(&bytes).expect("decode");
    assert!(patched
        .nodes()
        .iter()
        .any(|node| matches!(node, active_infinity::Inode::Int(9090))));
    let after = agent
        .call(lane, &cap, "content_hash", vec![])
        .unwrap()
        .value()
        .unwrap();
    assert_ne!(before, after, "the module capability advanced");
}

#[test]
fn evaluate_honors_the_capability_budget() {
    let (agent, _provider, cap, lane) = setup();
    let tight = agent
        .attenuate(
            &cap,
            CapAttrs::new(&["evaluate"]).with_budget(Budget {
                max_nodes: 1,
                ..Budget::default()
            }),
        )
        .expect("attenuate");
    let error = agent
        .call(lane, &tight, "evaluate", vec![])
        .expect("call")
        .value()
        .expect_err("evaluation must trip the node budget");
    assert_eq!(error.code(), "rpc/domain");
    assert!(error.to_string().contains("X001"), "{error}");
}

#[test]
fn in_process_transport_moves_envelopes_without_bytes() {
    let (mut left, mut right) = InProcessTransport::pair();
    let envelope = sample_envelope();
    left.send(&envelope).expect("send");
    let received = right.recv().expect("recv").expect("envelope");
    assert_eq!(received, envelope);
    assert_eq!(left.bytes_written(), 0, "no serialization in-process");
}

#[test]
fn shared_memory_transport_is_zero_copy_and_rejects_malformed_frames() {
    let segment = SharedSegment::new(1 << 20);
    let mut transport = SharedMemoryTransport::new(segment.clone());
    let envelope = sample_envelope();
    transport.send(&envelope).expect("send");

    // Zero copy: the borrowed frame points inside the segment's buffer.
    let inside = segment
        .with_frame(|frame| {
            let first = frame.as_ptr() as usize;
            first > 0 && !frame.is_empty()
        })
        .expect("frame")
        .expect("borrowed");
    assert!(inside);

    let received = transport.recv_zero_copy().expect("recv").expect("envelope");
    assert_eq!(received, envelope);
    assert_eq!(segment.available(), 0);

    // A frame that is not an envelope is refused.
    segment.write(b"not an envelope").expect("write");
    let error = transport.recv().unwrap_err();
    assert_eq!(error.code(), "rpc/wire");
}

#[test]
fn connect_bridge_moves_a_module_and_rejects_bad_frames() {
    let server = BridgeServer::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let handle = std::thread::spawn(move || {
        server
            .serve(3, |envelope| match envelope.method.as_str() {
                "evaluate" => Envelope::response(envelope.request_id, Value::text("bridged")),
                _ => Envelope::error(
                    envelope.request_id,
                    &active_rpc::Error::MethodNotGranted {
                        method: envelope.method,
                    },
                ),
            })
            .expect("serve")
    });

    let mut client = ConnectClient::connect(&address).expect("connect");
    let envelope = sample_envelope();
    let response = client.call(&envelope).expect("call");
    assert_eq!(response.kind, Kind::Response);
    assert_eq!(response.first_value(), Some(&Value::text("bridged")));

    // Malformed gRPC frame.
    let (status, body) = client.post_raw(b"\x00\x00\x00").expect("post");
    assert_eq!(status, 400);
    assert!(String::from_utf8_lossy(&body).starts_with("rpc/"));

    // Wrong content type.
    let (status, _body) = client.post_typed(&[0u8; 8], "text/plain").expect("post");
    assert_eq!(status, 415);

    let _served = handle.join().expect("join");
    // The well-formed call and the malformed frame are both "served" (the\n    // malformed one with an error); the bad content type is rejected before\n    // dispatch and does not count.\n    assert_eq!(served, 2, "served calls");
}

#[cfg(feature = "quic")]
#[test]
fn quic_transport_moves_a_module_and_rejects_malformed_frames() {
    let server = active_rpc::transport::quic::QuicServer::start(2, |envelope| {
        Envelope::response(envelope.request_id, Value::text("quic"))
    })
    .expect("start quic server");
    let address = server.address().to_string();
    let certificate = server.certificate().clone();

    let client =
        active_rpc::transport::quic::QuicClient::connect(&address, &certificate).expect("connect");
    let envelope = sample_envelope();
    let response = client.call(&envelope).expect("call");
    assert_eq!(response.kind, Kind::Response);
    assert_eq!(response.first_value(), Some(&Value::text("quic")));

    // A raw, unframed payload is rejected with an error envelope.
    let raw = client.exchange(&[0xff; 8]).expect("raw exchange");
    let mut cursor = std::io::Cursor::new(raw.as_slice());
    let body = active_rpc::transport::read_frame(&mut cursor, &active_rpc::WireLimits::default())
        .expect("frame ok")
        .expect("frame");
    let decoded = Envelope::decode(&body).expect("decode");
    assert_eq!(decoded.kind, Kind::Error);
    assert!(decoded.method.starts_with("rpc/"));
}

fn sample_envelope() -> Envelope {
    let module = active_infinity::encode(&module()).expect("encode");
    Envelope::request(9, "evaluate", vec![Arg::Value(Value::Path("app".into()))])
        .with_payload(module)
        .with_caps(vec![CapDescriptor {
            id: active_rpc::CapId([5u8; 16]),
            methods: ["evaluate".to_string()].into_iter().collect(),
            budget: Budget::default(),
            read_only: false,
            redact: false,
            path_scope: None,
        }])
}

#[test]
fn cross_process_peer_pipelines_in_one_round_trip() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_active-rpc-peer"))
        .args(["--listen", "127.0.0.1:0", "--calls", "16"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn peer");
    let stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read listen line");
    let address = line
        .trim()
        .strip_prefix("listening ")
        .expect("peer announces its address")
        .to_string();

    let mut transport = TcpTransport::connect(&address).expect("connect");

    let hello = Envelope::request(1, "hello", vec![]);
    transport.send(&hello).expect("send hello");
    let response = transport.recv().expect("recv").expect("response");
    assert_eq!(response.kind, Kind::Response);
    let capabilities = match response.first_value() {
        Some(Value::Map(map)) => map.clone(),
        other => panic!("expected hello map, got {other:?}"),
    };
    assert_eq!(
        capabilities.get("peer"),
        Some(&Value::text("active-rpc-peer"))
    );

    let ping = Envelope::request(2, "ping", vec![]);
    transport.send(&ping).expect("send ping");
    let response = transport.recv().expect("recv").expect("response");
    assert_eq!(response.first_value(), Some(&Value::text("pong")));

    let pipeline = Envelope::request(3, "pipeline", vec![]);
    transport.send(&pipeline).expect("send pipeline");
    let response = transport.recv().expect("recv").expect("response");
    let pipelined_trips = round_trips(&response);

    let sequential = Envelope::request(4, "sequential", vec![]);
    transport.send(&sequential).expect("send sequential");
    let response = transport.recv().expect("recv").expect("response");
    let sequential_trips = round_trips(&response);

    println!(
        "cross-process round trips: pipelined={pipelined_trips} sequential={sequential_trips}"
    );
    assert_eq!(pipelined_trips, 1);
    assert_eq!(sequential_trips, 2);
    assert!(pipelined_trips < sequential_trips);

    // A domain call over the same cross-process connection.
    let stats = Envelope::request(5, "stats", vec![]);
    transport.send(&stats).expect("send stats");
    let response = transport.recv().expect("recv").expect("response");
    let map = match response.first_value() {
        Some(Value::Map(map)) => map.clone(),
        other => panic!("expected stats, got {other:?}"),
    };
    assert!(matches!(map.get("nodes"), Some(Value::Int(nodes)) if *nodes > 5));

    drop(transport);
    let _ = child.kill();
    let _ = child.wait();
}

fn round_trips(response: &Envelope) -> i64 {
    match response.first_value() {
        Some(Value::Map(map)) => match map.get("round_trips") {
            Some(Value::Int(trips)) => *trips,
            other => panic!("expected round_trips, got {other:?}"),
        },
        other => panic!("expected a map, got {other:?}"),
    }
}

#[test]
fn peer_reports_an_error_envelope_for_unknown_methods() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_active-rpc-peer"))
        .args(["--listen", "127.0.0.1:0", "--calls", "4"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn peer");
    let stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read listen line");
    let address = line
        .trim()
        .strip_prefix("listening ")
        .expect("address")
        .to_string();
    let mut transport = TcpTransport::connect(&address).expect("connect");
    transport
        .send(&Envelope::request(1, "not_a_method", vec![]))
        .expect("send");
    let response = transport.recv().expect("recv").expect("response");
    assert_eq!(response.kind, Kind::Error);
    assert_eq!(response.method, "rpc/method-not-granted");
    drop(transport);
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn connect_bridge_survives_a_request_without_content_length() {
    use std::io::Write;
    let server = BridgeServer::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let handle = std::thread::spawn(move || {
        server
            .serve(2, |envelope| {
                Envelope::response(envelope.request_id, Value::text("ok"))
            })
            .expect("serve")
    });

    // A request with no content-length is a 400; the server keeps accepting.
    let mut raw = std::net::TcpStream::connect(&address).expect("connect");
    raw.write_all(b"POST /active.rpc.v1.Agent/Call HTTP/1.1\r\nhost: x\r\ncontent-type: application/connect+active-infinity\r\n\r\n")
        .expect("write");
    let mut reply = Vec::new();
    use std::io::Read;
    raw.read_to_end(&mut reply).expect("read");
    let text = String::from_utf8_lossy(&reply);
    assert!(text.starts_with("HTTP/1.1 400"), "{text}");

    let mut client = ConnectClient::connect(&address).expect("client");
    let response = client
        .call(&Envelope::request(1, "ping", vec![]))
        .expect("call after the malformed request");
    assert_eq!(response.first_value(), Some(&Value::text("ok")));
    let served = handle.join().expect("join");
    assert_eq!(served, 2);
}

#[test]
fn tcp_transport_rejects_a_malformed_envelope() {
    let (listener, address) = active_rpc::transport::bind_loopback().expect("bind");
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let mut transport = TcpTransport::new(stream).expect("wrap");
        transport.recv()
    });
    // A valid frame header with a body that is not an envelope.
    let mut stream = std::net::TcpStream::connect(&address).expect("connect");
    active_rpc::transport::write_frame(&mut stream, b"garbage").expect("write frame");
    let outcome = handle.join().expect("join");
    let error = outcome.expect_err("malformed envelope must be refused");
    assert_eq!(error.code(), "rpc/wire");
    let _ = BTreeMap::<u8, u8>::new();
}
