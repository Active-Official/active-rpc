//! RPC-57 regression tests: the round-1 Low rollup in the W3-R1-RPC-WIRE-TEST
//! area (11 sub-items: R01-4, R01-5, R01-6, R09-2, R09-3, R09-4, R09-5,
//! R09-6, R11-3, R11-4, R11-5).
//!
//! Each test pins the fixed behaviour. Tests that assert a behaviour the fix
//! changed fail at the pre-fix head `a4b6b42` (proven by the fail-before run
//! of the W3 probes); doc-contract tests pass before and after and are marked
//! as such. Feature gates: `http2` for the HTTP/2 half of R09-4,
//! `test-utils` for the verified-identity expiry tests (R11-5), `quic` for
//! the QUIC tests (a default feature).

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use active_rpc::cap::{CapAttrs, CapId};
use active_rpc::identity::{IdentityPolicy, PeerIdentity};
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::wire::{CapDescriptor, CapTableDelta, Envelope, Kind, WireLimits};
use active_rpc::{Agent, Budget, Error};

struct Echo(Arc<AtomicUsize>);
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
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Response::Value(Value::text(call.method.clone())))
    }
}

fn provider_error(id: u64) -> Envelope {
    Envelope::error(
        id,
        &Error::Provider {
            code: "rpc/provider".to_string(),
        },
    )
}

/// R01-4: a delta that removes the same capability twice is refused at
/// encode and at decode. Before the fix it encoded and decoded fine and only
/// `apply_to` refused it.
#[test]
fn delta_duplicate_removal_is_refused_at_encode_and_decode() {
    let base: Vec<CapDescriptor> = Vec::new();
    let removed = CapId([5u8; 16]);
    let delta = CapTableDelta {
        base: active_rpc::wire::cap_table_hash(&base).expect("hash"),
        removed: vec![removed, removed],
        added: Vec::new(),
    };
    let env = Envelope::request(1, "echo", vec![]).with_cap_delta(delta);
    let error = env
        .encode()
        .expect_err("encode refuses a duplicate removal");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");
    // The decode half needs bytes the encoder will no longer produce, so
    // they are built by hand: a valid frame with the duplicate removal
    // spliced in after the capability slot.
    let good = Envelope::request(1, "echo", vec![])
        .with_cap_delta(CapTableDelta {
            base: active_rpc::wire::cap_table_hash(&base).expect("hash"),
            removed: vec![removed],
            added: Vec::new(),
        })
        .encode()
        .expect("encode a well-formed delta");
    // Layout after the 16-byte header: method len + "echo" (8), arg count
    // (4), payload len (4), cap count (4), then the delta: base (32),
    // removed count (4), removed ids (16 each), added count (4).
    let mut bad = good.clone();
    let removed_count_at = 16 + 8 + 4 + 4 + 4 + 32;
    bad[removed_count_at..removed_count_at + 4].copy_from_slice(&2u32.to_le_bytes());
    bad.splice(
        removed_count_at + 4 + 16..removed_count_at + 4 + 16,
        removed.0,
    );
    let error = Envelope::decode(&bad).expect_err("decode refuses a duplicate removal");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");
}

/// R01-4: a delta that removes and adds the same capability is refused at
/// encode and at decode. Before the fix it encoded and decoded fine and only
/// `apply_to` refused it.
#[test]
fn delta_removed_and_added_overlap_is_refused_at_encode_and_decode() {
    let base: Vec<CapDescriptor> = Vec::new();
    let id = CapId([6u8; 16]);
    let added = CapDescriptor {
        id,
        methods: BTreeSet::from(["echo".to_string()]),
        budget: Budget::default(),
        read_only: false,
        redact: false,
        path_scope: None,
    };
    let delta = CapTableDelta {
        base: active_rpc::wire::cap_table_hash(&base).expect("hash"),
        removed: vec![id],
        added: vec![added],
    };
    let env = Envelope::request(1, "echo", vec![]).with_cap_delta(delta);
    let error = env
        .encode()
        .expect_err("encode refuses a removed-and-added overlap");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");
    // Decode half: the same overlap built by hand, since the encoder refuses
    // it. The added descriptor is re-encoded on its own and spliced in after
    // the removed id.
    let good = Envelope::request(1, "echo", vec![])
        .with_cap_delta(CapTableDelta {
            base: active_rpc::wire::cap_table_hash(&base).expect("hash"),
            removed: vec![id],
            added: Vec::new(),
        })
        .encode()
        .expect("encode a well-formed delta");
    let added_bytes = Envelope::request(1, "echo", vec![])
        .with_caps(vec![CapDescriptor {
            id,
            methods: BTreeSet::from(["echo".to_string()]),
            budget: Budget::default(),
            read_only: false,
            redact: false,
            path_scope: None,
        }])
        .encode()
        .expect("encode the added descriptor");
    // The added descriptor is the cap slot of that frame: after the 16-byte
    // header, method (8), arg count (4), payload len (4), cap count (4) —
    // 36 bytes in — and runs to the end of the frame.
    let descriptor = &added_bytes[36..];
    let mut bad = good.clone();
    let removed_count_at = 16 + 8 + 4 + 4 + 4 + 32;
    let added_count_at = removed_count_at + 4 + 16;
    bad[added_count_at..added_count_at + 4].copy_from_slice(&1u32.to_le_bytes());
    bad.splice(
        added_count_at + 4..added_count_at + 4,
        descriptor.iter().copied(),
    );
    let error = Envelope::decode(&bad).expect_err("decode refuses the overlap");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");
}

/// R01-4 control: a well-formed delta still round-trips.
#[test]
fn a_well_formed_delta_still_round_trips() {
    // The base must hold the removed capability: `apply_to` refuses a delta
    // that removes more than the base holds.
    let base = vec![CapDescriptor {
        id: CapId([5u8; 16]),
        methods: BTreeSet::from(["echo".to_string()]),
        budget: Budget::default(),
        read_only: false,
        redact: false,
        path_scope: None,
    }];
    let removed = CapId([5u8; 16]);
    let added = CapDescriptor {
        id: CapId([6u8; 16]),
        methods: BTreeSet::from(["echo".to_string()]),
        budget: Budget::default(),
        read_only: false,
        redact: false,
        path_scope: None,
    };
    let delta = CapTableDelta {
        base: active_rpc::wire::cap_table_hash(&base).expect("hash"),
        removed: vec![removed],
        added: vec![added],
    };
    let env = Envelope::request(1, "echo", vec![]).with_cap_delta(delta);
    let bytes = env.encode().expect("encode a well-formed delta");
    let back = Envelope::decode(&bytes).expect("decode a well-formed delta");
    let delta = back.cap_delta.expect("delta present");
    assert_eq!(delta.removed.len(), 1);
    assert_eq!(delta.added.len(), 1);
    let applied = delta.apply_to(&base).expect("a well-formed delta applies");
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].id, CapId([6u8; 16]));
    assert_eq!(applied[0].methods, BTreeSet::from(["echo".to_string()]));
    assert_eq!(applied[0].budget, Budget::default());
    assert!(!applied[0].read_only);
    assert!(!applied[0].redact);
    assert_eq!(applied[0].path_scope, None);
}

/// R01-5: one `Text` value past the per-value ceiling is refused at decode.
/// Before the fix an 11 MB `Text` decoded and materialised and was only
/// refused later, at dispatch.
#[test]
fn a_text_value_past_the_ceiling_is_refused_at_decode() {
    let big = "x".repeat(11_000_000);
    let env = Envelope::request(1, "echo", vec![Arg::text(big)]);
    // The encoder under a lifted ceiling produces the frame the decoder must
    // refuse; the default encoder refuses it first (encode symmetry).
    let loose = WireLimits {
        max_value: u32::MAX,
        ..WireLimits::default()
    };
    let bytes = env
        .encode_with_limits(loose)
        .expect("encode under a lifted ceiling");
    assert!(bytes.len() > 11_000_000, "frame is {} bytes", bytes.len());
    let error = Envelope::decode(&bytes).expect_err("decode refuses the 11 MB text");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    let error = env.encode().expect_err("encode refuses it too");
    assert_eq!(error.code(), "rpc/wire", "{error}");
}

/// R01-5: one `Module` value past the ceiling is refused at decode.
#[test]
fn a_module_value_past_the_ceiling_is_refused_at_decode() {
    let big = vec![0u8; 11_000_000];
    let env = Envelope::request(1, "echo", vec![Arg::Value(Value::Module(big))]);
    let loose = WireLimits {
        max_value: u32::MAX,
        ..WireLimits::default()
    };
    let bytes = env
        .encode_with_limits(loose)
        .expect("encode under a lifted ceiling");
    let error = Envelope::decode(&bytes).expect_err("decode refuses the 11 MB module");
    assert_eq!(error.code(), "rpc/wire", "{error}");
}

/// R01-5: one `Path` value past the ceiling is refused at decode.
#[test]
fn a_path_value_past_the_ceiling_is_refused_at_decode() {
    let big = "x".repeat(11_000_000);
    let env = Envelope::request(1, "echo", vec![Arg::Value(Value::path(big))]);
    let loose = WireLimits {
        max_value: u32::MAX,
        ..WireLimits::default()
    };
    let bytes = env
        .encode_with_limits(loose)
        .expect("encode under a lifted ceiling");
    let error = Envelope::decode(&bytes).expect_err("decode refuses the 11 MB path");
    assert_eq!(error.code(), "rpc/wire", "{error}");
}

/// R01-5: one map key past the ceiling is refused at decode.
#[test]
fn a_map_key_past_the_ceiling_is_refused_at_decode() {
    let big = "x".repeat(11_000_000);
    let map = Value::map([(big, Value::Null)]);
    let env = Envelope::request(1, "echo", vec![Arg::Value(map)]);
    let loose = WireLimits {
        max_value: u32::MAX,
        ..WireLimits::default()
    };
    let bytes = env
        .encode_with_limits(loose)
        .expect("encode under a lifted ceiling");
    let error = Envelope::decode(&bytes).expect_err("decode refuses the 11 MB map key");
    assert_eq!(error.code(), "rpc/wire", "{error}");
}

/// R01-5 control: a value exactly at the ceiling still decodes.
#[test]
fn a_value_at_the_ceiling_still_decodes() {
    let at_ceiling = "x".repeat(10_000_000);
    let env = Envelope::request(1, "echo", vec![Arg::text(at_ceiling)]);
    let bytes = env.encode().expect("encode a 10,000,000-byte text");
    let back = Envelope::decode(&bytes).expect("decode a value at the ceiling");
    match &back.args[0] {
        Arg::Value(Value::Text(text)) => assert_eq!(text.len(), 10_000_000),
        other => panic!("expected a Text arg, got {other:?}"),
    }
}

/// R01-5: the strict profile caps one value at 1 MiB.
#[test]
fn strict_profile_caps_one_value_at_one_mib() {
    let loose = WireLimits {
        max_value: u32::MAX,
        ..WireLimits::default()
    };
    let over = Envelope::request(1, "echo", vec![Arg::text("x".repeat((1 << 20) + 1))]);
    let bytes = over
        .encode_with_limits(loose)
        .expect("encode under a lifted ceiling");
    let error = Envelope::decode_with(&bytes, WireLimits::strict())
        .expect_err("strict refuses a value past 1 MiB");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    // A value of exactly 1 MiB still cannot ride a strict frame: strict's
    // `max_bytes` is 1 MiB too, and the frame overhead pushes it over, so the
    // frame ceiling binds first there. A value with headroom for the frame
    // decodes, proving the per-value ceiling itself admits up to 1 MiB.
    let at = Envelope::request(1, "echo", vec![Arg::text("x".repeat((1 << 20) - 8192))]);
    let bytes = at
        .encode_with_limits(loose)
        .expect("encode under a lifted ceiling");
    Envelope::decode_with(&bytes, WireLimits::strict())
        .expect("strict accepts a value just under 1 MiB");
}

/// R01-5: the wire ceiling is the kernel budget's ceiling, not a second
/// number that can drift.
#[test]
fn wire_limits_max_value_matches_the_kernel_budget() {
    assert_eq!(
        WireLimits::default().max_value as u64,
        Budget::default().max_value_size,
        "default max_value is the kernel default"
    );
    assert_eq!(
        WireLimits::strict().max_value as u64,
        Budget::strict().max_value_size,
        "strict max_value is the kernel strict ceiling"
    );
}

/// R01-6: a decode that preallocates from an untrusted count aborts the
/// process pre-fix, so it cannot be observed in-process. The parent tests
/// spawn this test binary as a child with `RPC57_ABORT_MODE` set; the child
/// decodes a frame whose count field is `u32::MAX` under a lifted profile
/// and must return `Err` instead of aborting.
#[test]
fn rpc57_r01_6_abort_probe_child() {
    let mode = match std::env::var("RPC57_ABORT_MODE") {
        Ok(mode) => mode,
        Err(_) => return, // Only the parent tests drive this worker.
    };
    // A normal 1-arg-free envelope, then patch the count field. Layout:
    // [16..20] method length, [20..24] "echo", [24..28] arg count,
    // [28..32] payload length, [32..36] capability count.
    let mut bytes = Envelope::request(1, "echo", vec![])
        .encode()
        .expect("encode");
    let limits = WireLimits {
        max_args: u32::MAX,
        max_caps: u32::MAX,
        max_bytes: usize::MAX,
        ..WireLimits::default()
    };
    match mode.as_str() {
        "args" => {
            bytes[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        }
        "caps" => {
            bytes[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
        }
        "removed" | "added" => {
            // A delta needs the flag bit and the 32-byte base first.
            bytes[6] |= 1 << 2;
            bytes.extend_from_slice(&[0u8; 32]);
            if mode == "removed" {
                bytes.extend_from_slice(&u32::MAX.to_le_bytes());
                bytes.extend_from_slice(&0u32.to_le_bytes());
            } else {
                bytes.extend_from_slice(&0u32.to_le_bytes());
                bytes.extend_from_slice(&u32::MAX.to_le_bytes());
            }
        }
        other => panic!("unknown RPC57_ABORT_MODE {other}"),
    }
    let result = Envelope::decode_with(&bytes, limits);
    assert!(
        result.is_err(),
        "a u32::MAX count is refused, not allocated: {result:?}"
    );
}

fn run_abort_probe_child(mode: &str) {
    let exe = std::env::current_exe().expect("current test binary");
    let output = std::process::Command::new(exe)
        .args(["rpc57_r01_6_abort_probe_child", "--exact"])
        .env("RPC57_ABORT_MODE", mode)
        .output()
        .expect("spawn the child probe");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "child probe for {mode} must exit 0 (pre-fix it aborts): status {:?}\n{stdout}",
        output.status
    );
    assert!(
        stdout.contains("1 passed"),
        "the child must actually run the worker test for {mode}:\n{stdout}"
    );
}

/// R01-6: an `arg_count` of `u32::MAX` under a lifted profile does not abort
/// the process.
#[test]
fn r01_6_args_count_does_not_abort_the_process() {
    run_abort_probe_child("args");
}

/// R01-6: a `cap_count` of `u32::MAX` under a lifted profile does not abort
/// the process.
#[test]
fn r01_6_caps_count_does_not_abort_the_process() {
    run_abort_probe_child("caps");
}

/// R01-6: a delta `removed_count` of `u32::MAX` under a lifted profile does
/// not abort the process.
#[test]
fn r01_6_delta_removed_count_does_not_abort_the_process() {
    run_abort_probe_child("removed");
}

/// R01-6: a delta `added_count` of `u32::MAX` under a lifted profile does not
/// abort the process.
#[test]
fn r01_6_delta_added_count_does_not_abort_the_process() {
    run_abort_probe_child("added");
}

/// R09-2: a stock gRPC content type is refused with 415. The bridge accepts
/// only the custom `+active-infinity` media types; see the doc test below
/// for why that is the honest contract rather than an interop bug.
#[test]
fn stock_grpc_content_type_is_refused_with_415() {
    use active_rpc::transport::connect::{grpc_frame, BridgeServer, ConnectClient};
    let server = BridgeServer::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let framed = grpc_frame(
        &Envelope::request(1, "echo", vec![])
            .encode()
            .expect("encode"),
    )
    .expect("frame");
    std::thread::scope(|scope| {
        let served = scope.spawn(|| {
            server.serve(1, |env| {
                Envelope::response(env.request_id, Value::text("ok"))
            })
        });
        let mut client = ConnectClient::connect(&address).expect("client");
        let (status, _) = client
            .post_typed(&framed, "application/grpc")
            .expect("post");
        assert_eq!(status, 415, "stock application/grpc is refused");
        assert_eq!(served.join().expect("serve").expect("serve ok"), 0);
    });
}

/// R09-2 (doc contract): the interop doc states plainly that the bridge does
/// not interoperate with stock gRPC or Connect clients.
#[test]
fn interop_doc_states_stock_clients_are_not_supported() {
    let doc = std::fs::read_to_string("docs/spec/interop.md").expect("interop.md");
    assert!(
        doc.contains("does NOT interoperate with stock gRPC"),
        "interop.md must state the stock-client limit"
    );
    assert!(
        doc.contains("refused with 415"),
        "interop.md must state the 415 for stock application/grpc"
    );
}

/// R09-3 (doc contract): serial servers answer the second request only after
/// the first handler finishes. There is no handler deadline by design — the
/// handler closure borrows the `Agent`, which is `!Send` — so the test pins
/// the documented serial contract instead of a deadline that cannot exist.
#[test]
fn serial_server_answers_the_second_request_only_after_the_first_handler_finishes() {
    use active_rpc::transport::{bind_loopback, serve_connection, TcpTransport, Transport};
    let (listener, address) = bind_loopback().expect("bind");
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let transport =
            TcpTransport::with_timeout(stream, Duration::from_secs(10)).expect("transport");
        serve_connection(transport, |env| {
            if env.request_id == 1 {
                std::thread::sleep(Duration::from_secs(1));
            }
            Envelope::response(env.request_id, Value::text("ok"))
        })
        .expect("serve")
    });
    let started = Instant::now();
    let mut client = TcpTransport::connect(&address).expect("connect");
    client
        .send(&Envelope::request(1, "echo", vec![]))
        .expect("send 1");
    client
        .send(&Envelope::request(2, "echo", vec![]))
        .expect("send 2");
    let first = client.recv().expect("recv 1").expect("answer 1");
    assert_eq!(first.request_id, 1);
    let second = client.recv().expect("recv 2").expect("answer 2");
    assert_eq!(second.request_id, 2);
    let elapsed = started.elapsed();
    drop(client);
    let _ = server.join();
    assert!(
        elapsed >= Duration::from_millis(700),
        "request 2 was stalled behind request 1's 1 s handler: {elapsed:?}"
    );
}

/// R09-4 (TCP): a frame-level refusal — the server refusing a non-Request
/// envelope as a call — surfaces as `Err` on TCP, like on HTTP/2 and the
/// bridge. Before the fix TCP answered it as `Ok(Error envelope)`.
#[test]
fn tcp_frame_refusal_is_an_error() {
    use active_rpc::transport::{bind_loopback, serve_connection, TcpTransport};
    let (listener, address) = bind_loopback().expect("bind");
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let transport =
            TcpTransport::with_timeout(stream, Duration::from_secs(5)).expect("transport");
        serve_connection(transport, |env| {
            Envelope::response(env.request_id, Value::text("ok"))
        })
        .expect("serve")
    });
    let mut client = TcpTransport::connect(&address).expect("connect");
    let error = client
        .call(&Envelope::response(7, Value::text("not a call")))
        .expect_err("a frame refusal is Err on TCP");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    drop(client);
    let _ = server.join();
}

/// R09-4 (TCP control): a handler's error envelope stays `Ok(Error
/// envelope)` on TCP — only frame-level refusals become `Err`.
#[test]
fn tcp_handler_error_stays_an_ok_error_envelope() {
    use active_rpc::transport::{bind_loopback, serve_connection, TcpTransport};
    let (listener, address) = bind_loopback().expect("bind");
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let transport =
            TcpTransport::with_timeout(stream, Duration::from_secs(5)).expect("transport");
        serve_connection(transport, |env| provider_error(env.request_id)).expect("serve")
    });
    let mut client = TcpTransport::connect(&address).expect("connect");
    let answer = client
        .call(&Envelope::request(7, "echo", vec![]))
        .expect("handler error envelope arrives as Ok on TCP");
    assert_eq!(
        answer.kind,
        Kind::Error,
        "the Ok value is an error envelope"
    );
    assert_eq!(answer.request_id, 7);
    drop(client);
    let _ = server.join();
}

/// R09-4 (bridge): an HTTP-layer refusal is `Err` on the bridge, and a
/// handler error envelope stays `Ok` — the same split as HTTP/2.
#[test]
fn connect_bridge_frame_refusal_is_an_error() {
    use active_rpc::transport::connect::{BridgeServer, ConnectClient};
    let server = BridgeServer::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let served = std::thread::spawn(move || {
        server.serve(1, |env| {
            Envelope::response(env.request_id, Value::text("ok"))
        })
    });
    let mut client = ConnectClient::connect(&address).expect("connect");
    let error = client
        .call(&Envelope::response(7, Value::text("not a call")))
        .expect_err("a 400 HTTP-layer refusal surfaces as Err on the bridge");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    drop(client);
    let _ = served.join();
}

/// R09-4 (bridge control): a handler's error envelope arrives as `Ok(Error
/// envelope)` over the Connect bridge too.
#[test]
fn connect_bridge_handler_error_stays_an_ok_error_envelope() {
    use active_rpc::transport::connect::{BridgeServer, ConnectClient};
    let server = BridgeServer::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let served = std::thread::spawn(move || server.serve(1, |env| provider_error(env.request_id)));
    let mut client = ConnectClient::connect(&address).expect("connect");
    let answer = client
        .call(&Envelope::request(7, "echo", vec![]))
        .expect("handler error envelope arrives as Ok on the bridge");
    assert_eq!(
        answer.kind,
        Kind::Error,
        "the Ok value is an error envelope"
    );
    assert_eq!(answer.request_id, 7);
    drop(client);
    let _ = served.join();
}

/// R09-5: `TcpTransport::connect` delegates to the deadline-bounded connect,
/// so a refused loopback port still errors promptly.
#[test]
fn connect_to_a_refused_loopback_port_errors_promptly() {
    use active_rpc::transport::TcpTransport;
    let started = Instant::now();
    let error = TcpTransport::connect("127.0.0.1:1").expect_err("port 1 refuses");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "a refused connect must not park the caller: {:?}",
        started.elapsed()
    );
    assert!(matches!(error, Error::Transport(_)), "{error}");
}

/// R09-5: a shared segment is capped at the largest frame any transport
/// accepts. Before the fix `new(usize::MAX)` panicked with a capacity
/// overflow and `new(4 GiB)` allocated 4 GiB.
#[test]
fn shared_segment_capacity_is_capped_at_the_frame_ceiling() {
    use active_rpc::transport::shm::SharedSegment;
    use active_rpc::transport::MAX_FRAME_BYTES;
    assert_eq!(
        SharedSegment::new(1 << 32).capacity(),
        MAX_FRAME_BYTES,
        "4 GiB is capped"
    );
    assert_eq!(
        SharedSegment::new(usize::MAX).capacity(),
        MAX_FRAME_BYTES,
        "usize::MAX is capped, not a capacity-overflow panic"
    );
}

/// R09-5 control: the segment floor and ordinary sizes are unchanged.
#[test]
fn shared_segment_floor_and_mid_sizes_are_unchanged() {
    use active_rpc::transport::shm::SharedSegment;
    assert_eq!(SharedSegment::new(0).capacity(), 1024);
    assert_eq!(SharedSegment::new(1024).capacity(), 1024);
    assert_eq!(SharedSegment::new(1 << 20).capacity(), 1 << 20);
}

/// R09-4 (HTTP/2): an HTTP-layer refusal is `Err` on HTTP/2.
#[cfg(feature = "http2")]
#[test]
fn http2_frame_refusal_is_an_error() {
    use active_rpc::transport::http2::{Http2Client, Http2Server};
    let server = Http2Server::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let served = std::thread::spawn(move || {
        server.serve(1, |env| {
            Envelope::response(env.request_id, Value::text("ok"))
        })
    });
    let mut client = Http2Client::connect(&address).expect("connect");
    let error = client
        .call(&Envelope::response(7, Value::text("not a call")))
        .expect_err("a 400 HTTP-layer refusal surfaces as Err on H2");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    drop(client);
    let _ = served.join();
}

/// R09-4 (HTTP/2 control): a handler's error envelope arrives as `Ok(Error
/// envelope)` over HTTP/2 too.
#[cfg(feature = "http2")]
#[test]
fn http2_handler_error_stays_an_ok_error_envelope() {
    use active_rpc::transport::http2::{Http2Client, Http2Server};
    let server = Http2Server::bind_loopback().expect("bind");
    let address = server.address().to_string();
    let served = std::thread::spawn(move || server.serve(1, |env| provider_error(env.request_id)));
    let mut client = Http2Client::connect(&address).expect("connect");
    let answer = client
        .call(&Envelope::request(7, "echo", vec![]))
        .expect("handler error envelope arrives as Ok on H2");
    assert_eq!(
        answer.kind,
        Kind::Error,
        "the Ok value is an error envelope"
    );
    assert_eq!(answer.request_id, 7);
    drop(client);
    let _ = served.join();
}

/// R09-4 (QUIC): a frame-level refusal — the server refusing a non-Request
/// envelope as a call — surfaces as `Err` on QUIC, like on HTTP/2 and the
/// bridge. Before the fix QUIC answered it as `Ok(Error envelope)`.
#[cfg(feature = "quic")]
#[test]
fn quic_frame_refusal_is_an_error() {
    use active_rpc::transport::quic::{QuicClient, QuicServer};
    let server = QuicServer::start(1, |env| {
        Envelope::response(env.request_id, Value::text("ok"))
    })
    .expect("server");
    let client = QuicClient::connect(server.address(), server.certificate()).expect("client");
    let error = client
        .call(&Envelope::response(7, Value::text("not a call")))
        .expect_err("a frame refusal is Err on QUIC");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    server.shutdown();
}

/// R09-4 (QUIC control): a handler's error envelope stays `Ok(Error
/// envelope)` on QUIC.
#[cfg(feature = "quic")]
#[test]
fn quic_handler_error_stays_an_ok_error_envelope() {
    use active_rpc::transport::quic::{QuicClient, QuicServer};
    let server = QuicServer::start(1, |env| provider_error(env.request_id)).expect("server");
    let client = QuicClient::connect(server.address(), server.certificate()).expect("client");
    let answer = client
        .call(&Envelope::request(7, "echo", vec![]))
        .expect("handler error envelope arrives as Ok on QUIC");
    assert_eq!(
        answer.kind,
        Kind::Error,
        "the Ok value is an error envelope"
    );
    assert_eq!(answer.request_id, 7);
    server.shutdown();
}

/// R09-6: an early error reply is still delivered when the server's profile
/// cannot carry it. The server runs `max_method: 1`, so the request method
/// "echo" is refused at decode — and the refusal method "rpc/wire" (8 bytes)
/// cannot be encoded under that profile either. The reply must fall back to
/// the default profile and reach the client instead of going silent: without
/// the fallback the client would wait out its exchange deadline and fail
/// with a transport timeout. This passes before and after the fix in shape
/// (the refusal arrives either way); it guards the fallback path the fix
/// added, and the `Err` shape is the R09-4 rule.
#[cfg(feature = "quic")]
#[test]
fn quic_error_reply_is_still_delivered_when_the_profile_cannot_carry_it() {
    use active_rpc::transport::quic::{QuicClient, QuicServer};
    let server = QuicServer::start(1, |env| {
        Envelope::response(env.request_id, Value::text("ok"))
    })
    .expect("server")
    .with_limits(WireLimits {
        max_method: 1,
        ..WireLimits::strict()
    });
    let client = QuicClient::connect(server.address(), server.certificate()).expect("client");
    let error = client
        .call(&Envelope::request(1, "echo", vec![]))
        .expect_err("the refusal arrives as Err");
    assert_eq!(error.code(), "rpc/wire", "{error}");
    server.shutdown();
}

/// R11-3: `local()` refuses an anonymous peer off loopback. Before the fix
/// `local().admit(None, false)` admitted as `Unauthenticated`.
#[test]
fn local_policy_refuses_anonymous_off_loopback() {
    let error = IdentityPolicy::local()
        .admit(None, false)
        .expect_err("local policy refuses anonymous off loopback");
    assert_eq!(error.code(), "rpc/identity", "{error}");
}

/// R11-3: an explicitly anonymous identity is refused off loopback under
/// `local()` too — `admit` normalises it to `None` first.
#[test]
fn local_policy_refuses_an_explicit_anonymous_identity_off_loopback() {
    let anonymous = PeerIdentity::anonymous();
    let error = IdentityPolicy::local()
        .admit(Some(&anonymous), false)
        .expect_err("local policy refuses an explicit anonymous identity off loopback");
    assert_eq!(error.code(), "rpc/identity", "{error}");
}

/// R11-3 control: `local()` still admits on loopback, as `LoopbackRelaxed`.
#[test]
fn local_policy_still_admits_on_loopback() {
    let admitted = IdentityPolicy::local()
        .admit(None, true)
        .expect("local policy admits on loopback");
    assert_eq!(
        admitted.trust(),
        active_rpc::identity::TrustLevel::LoopbackRelaxed
    );
    let anonymous = PeerIdentity::anonymous();
    let admitted = IdentityPolicy::local()
        .admit(Some(&anonymous), true)
        .expect("local policy admits an explicit anonymous identity on loopback");
    assert_eq!(
        admitted.trust(),
        active_rpc::identity::TrustLevel::LoopbackRelaxed
    );
}

/// R11-4 (doc contract): `dispatch_envelope` enforces admission — the one
/// admit-enforcing entry point — while the raw entry points stay usable for
/// in-process dispatch after `admit`, as `src/bin/peer.rs` does. The fix is
/// docs, so this passes before and after; it pins the contract the docs now
/// state.
#[test]
fn dispatch_envelope_enforces_admission_and_admitted_call_works() {
    let peer = PeerIdentity::from_certificate(b"fabricated certificate bytes, never verified");
    let calls = Arc::new(AtomicUsize::new(0));
    let agent = Agent::with_secret([0x7b; 32]);
    let provider = agent
        .register(Box::new(Echo(Arc::clone(&calls))))
        .expect("register");
    let lane = agent.create_lane("audit", Budget::default()).expect("lane");
    let attrs = CapAttrs::new(&["echo"]).bound_to(peer.fingerprint());
    let cap_bound = agent.mint(provider, 0, attrs).expect("mint a bound cap");
    let cap_open = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint an open cap");
    let env = Envelope::request(1, "echo", vec![]);

    // The raw entry point runs a bound call for a fabricated peer with no
    // admit() anywhere on the path — the documented local-only behaviour.
    let promise = agent
        .call_from_envelope(Some(&peer), lane, &cap_bound, &env)
        .expect("call_from_envelope runs a bound call for a fabricated peer");
    agent.run();
    assert_eq!(
        promise.value().expect("provider ran").as_text(),
        Some("echo")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // The binding check itself works — a different fabricated peer is refused.
    let other = PeerIdentity::from_certificate(b"a different fabricated certificate");
    let error = agent
        .call_from_envelope(Some(&other), lane, &cap_bound, &env)
        .expect_err("another peer must not exercise this binding");
    assert_eq!(error.code(), "rpc/identity", "{error}");

    // The blessed pattern: admit first, then call with the admitted identity.
    let admitted = IdentityPolicy::default()
        .admit(None, true)
        .expect("loopback admitted");
    let promise = agent
        .call_from_envelope(Some(admitted.identity()), lane, &cap_open, &env)
        .expect("admitted-then-call runs");
    agent.run();
    assert_eq!(
        promise.value().expect("provider ran").as_text(),
        Some("echo")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    // Contrast: the admit-enforcing entry point refuses an anonymous caller
    // under strict(), and admits a loopback caller under default().
    let error = agent
        .dispatch_envelope(&IdentityPolicy::strict(), None, true, lane, &cap_open, &env)
        .expect_err("dispatch_envelope admits first and refuses anonymous under strict()");
    assert_eq!(error.code(), "rpc/identity", "{error}");
    let promise = agent
        .dispatch_envelope(
            &IdentityPolicy::default(),
            None,
            true,
            lane,
            &cap_open,
            &env,
        )
        .expect("dispatch_envelope admits a loopback caller");
    agent.run();
    assert_eq!(
        promise.value().expect("provider ran").as_text(),
        Some("echo")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

/// R11-5: a verified identity built from a real certificate carries the
/// leaf's `notAfter`.
#[cfg(feature = "test-utils")]
#[test]
fn verified_identity_from_a_real_certificate_carries_its_expiry() {
    // Explicit validity: rcgen's `generate_simple_self_signed` helper mints
    // 1975 -> 4096 validity, so a real cert with controlled dates is built
    // with `CertificateParams` instead.
    let now = time::OffsetDateTime::now_utc();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    params.not_before = now - time::Duration::seconds(60);
    params.not_after = now + time::Duration::seconds(365 * 86_400);
    let key = rcgen::KeyPair::generate().expect("key");
    let cert = params.self_signed(&key).expect("cert");
    let der = cert.der().to_vec();
    let identity = PeerIdentity::from_certificate_for_test(&der);
    assert!(
        identity.is_verified(),
        "the test constructor builds a verified identity"
    );
    let not_after = identity
        .not_after()
        .expect("verified identity records not_after");
    let now_unix = now.unix_timestamp() as u64;
    assert_eq!(
        not_after,
        now_unix + 365 * 86_400,
        "not_after is the certificate's notAfter to the second"
    );
    assert!(!identity.is_expired_at(now_unix));
    assert!(identity.is_expired_at(not_after));
}

/// R11-5: a short-lived certificate's expiry predicates match its `notAfter`
/// to the second.
#[cfg(feature = "test-utils")]
#[test]
fn short_lived_certificate_expiry_predicates() {
    let now = time::OffsetDateTime::now_utc();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    params.not_before = now - time::Duration::seconds(60);
    params.not_after = now + time::Duration::seconds(5);
    let key = rcgen::KeyPair::generate().expect("key");
    let cert = params.self_signed(&key).expect("cert");
    let der = cert.der().to_vec();
    let identity = PeerIdentity::from_certificate_for_test(&der);
    let now_unix = now.unix_timestamp() as u64;
    assert_eq!(
        identity.not_after(),
        Some(now_unix + 5),
        "not_after is the certificate's notAfter to the second"
    );
    assert!(!identity.is_expired_at(now_unix));
    assert!(identity.is_expired_at(now_unix + 10));
}

/// R11-5: an unverified claim records no expiry, whatever the bytes say.
#[test]
fn unverified_claim_carries_no_expiry() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let der = cert.cert.der().to_vec();
    let claim = PeerIdentity::from_certificate(&der);
    assert_eq!(claim.not_after(), None);
    assert!(!claim.is_expired_at(u64::MAX));
}

/// R11-5 (QUIC): a CA, a server identity and a client certificate whose
/// `notAfter` is `valid_secs` out, built with rcgen in the test.
#[cfg(feature = "quic")]
fn quic_material_with_client_validity(
    valid_secs: i64,
) -> (
    rustls::pki_types::CertificateDer<'static>,
    active_rpc::transport::quic::ServerIdentity,
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "rpc57 test ca");
    let ca_key = KeyPair::generate().expect("ca key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
    let ca_der = CertificateDer::from(ca_cert.der().to_vec());

    let mut server_params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
    server_params
        .distinguished_name
        .push(DnType::CommonName, "rpc57 server");
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate().expect("server key");
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("server cert");
    let identity = active_rpc::transport::quic::ServerIdentity {
        chain: vec![CertificateDer::from(server_cert.der().to_vec())],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
    };

    let now = time::OffsetDateTime::now_utc();
    let mut client_params = CertificateParams::new(Vec::new()).expect("client params");
    client_params
        .distinguished_name
        .push(DnType::CommonName, "rpc57 client");
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_params.not_before = now - time::Duration::seconds(60);
    client_params.not_after = now + time::Duration::seconds(valid_secs);
    let client_key = KeyPair::generate().expect("client key");
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .expect("client cert");
    (
        ca_der,
        identity,
        CertificateDer::from(client_cert.der().to_vec()),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialize_der())),
    )
}

/// R11-5 (QUIC): one raw-quinn exchange on a connection the caller holds
/// open — `QuicClient` reconnects per call, so only a held connection can
/// cross an expiry boundary.
#[cfg(feature = "quic")]
fn quinn_exchange(
    runtime: &tokio::runtime::Runtime,
    connection: &quinn::Connection,
    envelope: &Envelope,
) -> Envelope {
    use active_rpc::transport::{frame, read_frame, MAX_FRAME_BYTES};
    runtime.block_on(async {
        let (mut send, mut recv) = connection.open_bi().await.expect("open stream");
        let bytes = envelope.encode().expect("encode");
        let mut payload = Vec::new();
        payload.extend_from_slice(&frame(bytes.len()).expect("frame"));
        payload.extend_from_slice(&bytes);
        send.write_all(&payload).await.expect("write");
        send.finish().expect("finish");
        let reply =
            tokio::time::timeout(Duration::from_secs(10), recv.read_to_end(MAX_FRAME_BYTES))
                .await
                .expect("reply arrives")
                .expect("read");
        let mut cursor = std::io::Cursor::new(&reply);
        let body = read_frame(&mut cursor, &WireLimits::default())
            .expect("frame")
            .expect("body");
        Envelope::decode_with(&body, WireLimits::default()).expect("decode")
    })
}

/// R11-5 (QUIC live): a busy connection outlives the client certificate that
/// created it, and the server re-checks expiry per stream. The client
/// connects while its certificate is valid, calls once successfully, sleeps
/// past `notAfter`, and its next call on the SAME connection is refused with
/// `rpc/identity`. Before the fix the second call succeeded: expiry was
/// verified once, at the handshake, and never again.
///
/// The handshake must complete before expiry, so the test connects
/// immediately after minting a 5-second certificate and sleeps 6 seconds.
/// The 30 s idle timeout leaves ample margin.
#[cfg(feature = "quic")]
#[test]
fn quic_refuses_a_call_after_the_peer_certificate_expires() {
    use active_rpc::transport::quic::QuicServer;
    let (ca_der, identity, client_cert, client_key) = quic_material_with_client_validity(5);
    let server = QuicServer::start_with_identity(
        10,
        |env, _peer| Envelope::response(env.request_id, Value::text("ok")),
        "127.0.0.1:0".parse().expect("loopback"),
        identity,
        Some(ca_der.clone()),
    )
    .expect("server");
    let address: std::net::SocketAddr = server.address().parse().expect("address");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let connection = runtime.block_on(async {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca_der).expect("trust");
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![client_cert], client_key)
            .expect("client auth");
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("quic config");
        let client_config = quinn::ClientConfig::new(Arc::new(crypto));
        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().expect("loopback")).expect("endpoint");
        endpoint.set_default_client_config(client_config);
        endpoint
            .connect(address, "localhost")
            .expect("connect")
            .await
            .expect("handshake")
    });

    let first = quinn_exchange(&runtime, &connection, &Envelope::request(1, "echo", vec![]));
    assert_eq!(first.kind, Kind::Response, "first call succeeds: {first:?}");

    std::thread::sleep(Duration::from_secs(6));
    let second = quinn_exchange(&runtime, &connection, &Envelope::request(2, "echo", vec![]));
    assert_eq!(
        second.kind,
        Kind::Error,
        "second call is refused after expiry: {second:?}"
    );
    assert_eq!(second.method, "rpc/identity", "{second:?}");
    connection.close(0u32.into(), b"done");
    server.shutdown();
}

/// R11-5 (QUIC live control): the same flow with a long-lived client
/// certificate keeps serving after the same sleep — the sleep and the second
/// stream are not what refuse the call in the test above.
#[cfg(feature = "quic")]
#[test]
fn quic_keeps_serving_a_call_while_the_peer_certificate_is_valid() {
    use active_rpc::transport::quic::QuicServer;
    let (ca_der, identity, client_cert, client_key) = quic_material_with_client_validity(3600);
    let server = QuicServer::start_with_identity(
        10,
        |env, _peer| Envelope::response(env.request_id, Value::text("ok")),
        "127.0.0.1:0".parse().expect("loopback"),
        identity,
        Some(ca_der.clone()),
    )
    .expect("server");
    let address: std::net::SocketAddr = server.address().parse().expect("address");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let connection = runtime.block_on(async {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca_der).expect("trust");
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![client_cert], client_key)
            .expect("client auth");
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("quic config");
        let client_config = quinn::ClientConfig::new(Arc::new(crypto));
        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().expect("loopback")).expect("endpoint");
        endpoint.set_default_client_config(client_config);
        endpoint
            .connect(address, "localhost")
            .expect("connect")
            .await
            .expect("handshake")
    });

    let first = quinn_exchange(&runtime, &connection, &Envelope::request(1, "echo", vec![]));
    assert_eq!(first.kind, Kind::Response, "first call succeeds: {first:?}");

    std::thread::sleep(Duration::from_secs(6));
    let second = quinn_exchange(&runtime, &connection, &Envelope::request(2, "echo", vec![]));
    assert_eq!(
        second.kind,
        Kind::Response,
        "second call still succeeds while the certificate is valid: {second:?}"
    );
    connection.close(0u32.into(), b"done");
    server.shutdown();
}
