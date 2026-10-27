//! Wire-format conformance and error-code contract.
//!
//! The envelope is the interoperability surface: a peer written in another
//! language must be able to produce these bytes. The golden vectors below are
//! therefore literal, hand-checked hex, not "whatever the encoder produced".

use std::collections::BTreeSet;

use active_rpc::budget::Budget;
use active_rpc::cap::CapId;
use active_rpc::error::Error;
use active_rpc::value::{Arg, Value};
use active_rpc::wire::{CapDescriptor, Envelope, Kind, WireLimits};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn minimal_request_is_a_stable_golden_vector() {
    let envelope = Envelope::request(1, "ping", vec![]);
    let bytes = envelope.encode().expect("encode");
    // 16 header + 4 method length + 4 method + 4 args + 4 payload + 4 caps.
    let expected = "41525031\
                    01\
                    01\
                    0000\
                    0100000000000000\
                    04000000\
                    70696e67\
                    00000000\
                    00000000\
                    00000000";
    assert_eq!(hex(&bytes), expected, "wire layout changed");
    assert_eq!(bytes.len(), 36);
    assert_eq!(Envelope::decode(&bytes).unwrap(), envelope);
}

#[test]
fn golden_bytes_decode_to_the_expected_request() {
    let bytes = unhex(
        "41525031\
         01\
         01\
         0000\
         0100000000000000\
         04000000\
         70696e67\
         00000000\
         00000000\
         00000000",
    );
    let envelope = Envelope::decode(&bytes).expect("decode");
    assert_eq!(envelope.kind, Kind::Request);
    assert_eq!(envelope.request_id, 1);
    assert_eq!(envelope.method, "ping");
    assert!(envelope.args.is_empty());
    assert!(envelope.caps.is_empty());
}

#[test]
fn every_encoding_is_stable_under_re_encoding() {
    let samples = vec![
        Envelope::request(0, "stats", vec![]),
        Envelope::request(
            9,
            "evaluate",
            vec![
                Arg::Value(Value::Path("app.port".into())),
                Arg::Value(Value::Int(-7)),
                Arg::Value(Value::Float(1.5)),
                Arg::Value(Value::Bool(true)),
                Arg::Value(Value::Null),
                Arg::Value(Value::list(vec![Value::text("a"), Value::Secret])),
                Arg::Value(Value::Module(vec![0x41, 0x49, 0x4e, 0x46])),
            ],
        ),
        Envelope::response(4, Value::map([("ok", Value::Bool(true))])),
        Envelope::error(5, &Error::ReadOnly),
        Envelope::request(6, "hello", vec![Arg::Promise(active_rpc::PromiseId(3))]),
    ];
    for envelope in samples {
        let first = envelope.encode().expect("encode");
        let decoded = Envelope::decode(&first).expect("decode");
        let second = decoded.encode().expect("re-encode");
        assert_eq!(first, second, "re-encoding must be stable");
        assert_eq!(decoded, envelope);
    }
}

#[test]
fn capability_table_golden_shape() {
    let descriptor = CapDescriptor {
        id: CapId([0x11; 16]),
        methods: ["stats".to_string()].into_iter().collect(),
        budget: Budget {
            max_calls: 5,
            max_bytes: 1024,
            max_wall_ms: 100,
            max_nodes: 16,
            max_depth: 4,
            max_array_len: 8,
            max_value_size: 64,
        },
        read_only: true,
        redact: true,
        path_scope: Some("app".to_string()),
    };
    let envelope = Envelope::request(2, "stats", vec![]).with_caps(vec![descriptor.clone()]);
    let bytes = envelope.encode().expect("encode");
    let decoded = Envelope::decode(&bytes).expect("decode");
    assert_eq!(decoded.caps.len(), 1);
    let cap = &decoded.caps[0];
    assert_eq!(cap.id, descriptor.id);
    assert_eq!(cap.methods, descriptor.methods);
    assert_eq!(cap.budget, descriptor.budget);
    assert!(cap.read_only && cap.redact);
    assert_eq!(cap.path_scope.as_deref(), Some("app"));

    // The standalone table codec agrees with the envelope.
    let table =
        active_rpc::wire::encode_capability_table(std::slice::from_ref(&descriptor)).unwrap();
    let decoded_table = active_rpc::wire::decode_capability_table(&table).unwrap();
    assert_eq!(decoded_table, vec![descriptor]);
}

#[test]
fn truncated_prefixes_are_always_rejected() {
    let bytes = Envelope::request(1, "stats", vec![Arg::Value(Value::Int(1))])
        .encode()
        .unwrap();
    for length in 0..bytes.len() {
        let outcome = std::panic::catch_unwind(|| Envelope::decode(&bytes[..length]));
        assert!(outcome.is_ok(), "decode panicked at length {length}");
        assert!(
            outcome.unwrap().is_err(),
            "truncated envelope at {length} accepted"
        );
    }
}

#[test]
fn header_field_attacks_are_rejected() {
    let bytes = Envelope::request(1, "stats", vec![]).encode().unwrap();

    let mut bad_version = bytes.clone();
    bad_version[4] = 2;
    assert_eq!(
        Envelope::decode(&bad_version).unwrap_err().code(),
        "rpc/wire"
    );

    let mut bad_kind = bytes.clone();
    bad_kind[5] = 9;
    assert_eq!(Envelope::decode(&bad_kind).unwrap_err().code(), "rpc/wire");

    let mut bad_flags = bytes.clone();
    bad_flags[6] = 0xff;
    assert_eq!(Envelope::decode(&bad_flags).unwrap_err().code(), "rpc/wire");

    let mut huge_method = bytes.clone();
    huge_method[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        Envelope::decode(&huge_method).unwrap_err().code(),
        "rpc/wire"
    );

    let mut huge_args = bytes.clone();
    huge_args[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        Envelope::decode_with(&huge_args, WireLimits::strict())
            .unwrap_err()
            .code(),
        "rpc/wire"
    );
}

#[test]
fn every_error_code_is_unique_and_documented() {
    let errors = [
        Error::UnknownCapability(1),
        Error::MethodNotGranted { method: "x".into() },
        Error::Escalation("budget"),
        Error::ReadOnly,
        Error::PathNotGranted("a".into()),
        Error::ToolPolicy("x"),
        Error::Revoked(1),
        Error::BudgetExceeded("calls"),
        Error::UnknownLane(1),
        Error::UnknownChannel(1),
        Error::UnknownPromise(1),
        Error::PromiseCancelled(1),
        Error::PromiseAlreadyResolved(1),
        Error::UnresolvablePromise(1),
        Error::Provider { code: "x".into() },
        Error::Domain("X001"),
        Error::Payload("x".into()),
        Error::Wire("x"),
        Error::CapabilityTable("x"),
        Error::Transport("x".into()),
        Error::TransportUnavailable("quic"),
        Error::Timeout,
        Error::PipelinedCycle,
        Error::InvalidArgument("x"),
    ];

    let mut codes = BTreeSet::new();
    for error in &errors {
        let code = error.code();
        assert!(code.starts_with("rpc/"), "code {code} is not namespaced");
        assert!(codes.insert(code), "duplicate code {code}");
        assert!(!error.to_string().is_empty());
    }

    let spec = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/spec/wire.md"),
    )
    .expect("wire spec");
    for code in codes {
        assert!(spec.contains(code), "wire spec must document {code}");
    }
}

#[test]
fn wire_limits_are_enforced() {
    let limits = WireLimits::strict();
    let envelope = Envelope::request(1, "x".repeat(128), vec![Arg::Value(Value::Int(1)); 8]);
    let bytes = envelope.encode().unwrap();
    let error = Envelope::decode_with(&bytes, limits).unwrap_err();
    assert_eq!(error.code(), "rpc/wire");
}
