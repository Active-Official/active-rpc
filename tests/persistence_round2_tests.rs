//! R-16 round 2: the durable record, the redactor and the egress gate.
//!
//! Each test names the finding it pins. The records are real sealed records and
//! the modules are real canonical images.

use active_rpc::cap::{CapAttrs, CapPersistence};
use active_rpc::identity::{AdmittedIdentity, IdentityPolicy, PeerIdentity};
use active_rpc::kernel::Provider;
use active_rpc::persistence::CapabilityRecord;
use active_rpc::security::{
    assert_no_structural_secrets, is_invisible_or_reordering, redact_module, redact_value,
    valid_text,
};
use active_rpc::value::{Call, Response, Value};
use active_rpc::{Agent, ProviderId};

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
    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::text("ok")))
    }
}

const SEAL: [u8; 32] = [0x6d; 32];

fn admitted(certificate: &[u8]) -> AdmittedIdentity {
    IdentityPolicy::strict()
        .admit(Some(&PeerIdentity::from_certificate(certificate)), false)
        .expect("admitted")
}

fn durable_agent() -> (Agent, ProviderId) {
    let agent = Agent::with_secret([0x77; 32]);
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key(SEAL);
    let provider = agent.register(Box::new(Echo));
    (agent, provider)
}

fn durable_cap(agent: &Agent, provider: ProviderId) -> active_rpc::CapHandle {
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    agent
        .mint_bound(&admitted(b"owner"), provider, 0, attrs)
        .expect("cap")
}

/// F1: a record that cannot be read back costs nothing.
#[test]
fn an_unexportable_record_costs_no_authority() {
    let (agent, provider) = durable_agent();
    // A scope the parser refuses (over 1 KiB), which mint does not validate.
    let mut attrs = CapAttrs::new(&["echo"]).with_path("p".repeat(2_000));
    attrs.persistence = CapPersistence::Durable;
    let cap = agent
        .mint_bound(&admitted(b"owner"), provider, 0, attrs)
        .expect("cap");
    let first = agent
        .export_capability(&cap)
        .expect_err("the record is unreadable");
    assert_eq!(first.code(), "rpc/persistence");
    // Nothing was burned: the same error again, from the build, not "already
    // consumed", and the grant is still usable.
    let second = agent.export_capability(&cap).expect_err("still unreadable");
    assert_eq!(
        second.to_string(),
        first.to_string(),
        "the second attempt reports the build error, not a consumed record"
    );
    // The grant is intact: the capability is still in the registry and the
    // revocation path still reaches it.
    agent.revoke(&cap).expect("the capability is still live");
}

/// F4: a lease without a deadline would restore as unbounded.
#[test]
fn a_lease_without_a_deadline_is_refused() {
    let (agent, provider) = durable_agent();
    let cap = durable_cap(&agent, provider);
    let record = agent.export_capability(&cap).expect("export");
    let mut text: serde_json::Value = serde_json::from_str(&record.to_json()).expect("json");
    text["expires_at"] = serde_json::Value::Null;
    text["lease_ms"] = serde_json::json!(1);
    let error =
        CapabilityRecord::from_json(&text.to_string()).expect_err("a lease needs a deadline");
    assert_eq!(error.code(), "rpc/persistence");
}

/// F7: every text field the parser accepts is validated there.
#[test]
fn a_record_with_a_malformed_method_or_topic_is_a_persistence_refusal() {
    let (agent, provider) = durable_agent();
    let cap = durable_cap(&agent, provider);
    let record = agent.export_capability(&cap).expect("export");

    let mut text: serde_json::Value = serde_json::from_str(&record.to_json()).expect("json");
    text["methods"] = serde_json::json!([""]);
    assert_eq!(
        CapabilityRecord::from_json(&text.to_string())
            .expect_err("an empty method is malformed")
            .code(),
        "rpc/persistence"
    );

    let mut text: serde_json::Value = serde_json::from_str(&record.to_json()).expect("json");
    text["methods"] = serde_json::json!(["echo\u{202E}x"]);
    assert_eq!(
        CapabilityRecord::from_json(&text.to_string())
            .expect_err("a reordering method is malformed")
            .code(),
        "rpc/persistence"
    );

    let mut text: serde_json::Value = serde_json::from_str(&record.to_json()).expect("json");
    text["topics"] = serde_json::json!(["a\u{2028}b"]);
    assert_eq!(
        CapabilityRecord::from_json(&text.to_string())
            .expect_err("a line separator is not a topic")
            .code(),
        "rpc/persistence"
    );
}

/// F9: the record text has one meaning.
#[test]
fn a_duplicate_key_or_unknown_field_is_refused() {
    let (agent, provider) = durable_agent();
    let cap = durable_cap(&agent, provider);
    let record = agent.export_capability(&cap).expect("export");
    let text = record.to_json();

    // A repeated key: serde keeps the last, a first-wins reader keeps the first.
    let duplicated = text.replacen(
        "\"provider\":\"echo\"",
        "\"provider\":\"evil\",\"provider\":\"echo\"",
        1,
    );
    assert_ne!(duplicated, text, "the fixture has the provider field");
    assert_eq!(
        CapabilityRecord::from_json(&duplicated)
            .expect_err("a repeated key has two meanings")
            .code(),
        "rpc/persistence"
    );

    // An unknown field is outside the seal.
    let mut value: serde_json::Value = serde_json::from_str(&text).expect("json");
    value["admin"] = serde_json::json!(true);
    assert_eq!(
        CapabilityRecord::from_json(&value.to_string())
            .expect_err("an unknown field is not sealed")
            .code(),
        "rpc/persistence"
    );
}

/// F10: the seal is purpose-separated.
#[test]
fn the_seal_is_not_a_bare_keyed_hash() {
    let (agent, provider) = durable_agent();
    let cap = durable_cap(&agent, provider);
    let mut record = agent.export_capability(&cap).expect("export");
    assert!(record.seal_is_valid(&SEAL));
    // A MAC computed the old way (no purpose prefix) does not verify.
    let bare = blake3::keyed_hash(
        &SEAL,
        serde_json::from_str::<serde_json::Value>(&record.to_json())
            .map(|value| {
                let mut object = value;
                object.as_object_mut().expect("object").remove("seal");
                object.to_string().into_bytes()
            })
            .expect("json")
            .as_slice(),
    );
    record.seal = Some(bare.to_hex().to_string());
    assert!(!record.seal_is_valid(&SEAL));
}

/// F2: a module whose free text carries a secret literal cannot be redacted,
/// and a canonical one loses its secret node.
#[test]
fn a_module_with_a_secret_literal_outside_the_node_is_refused() {
    // Canonical: `Secret("hunter2")` plus a copy of the same literal in a string.
    let module =
        active_rpc::domain::module_from_source("[app]\ntoken = secret(\"hunter2\")\n", "x")
            .expect("module");
    let image = active_infinity::encode(&module).expect("encode");
    // The image itself is accepted by the codec...
    active_infinity::validate(&image).expect("valid image");
    // ...but redaction either removes the secret material or refuses the module.
    match redact_module(&image) {
        Ok(redacted) => {
            assert!(
                !contains(&redacted, b"hunter2"),
                "the redacted image still carries the literal"
            );
        }
        Err(error) => assert_eq!(error.code(), "rpc/payload"),
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// F11: a map key is text too.
#[test]
fn a_secret_marker_in_a_map_key_collapses_the_map() {
    let mut entries = std::collections::BTreeMap::new();
    entries.insert("***SECRET***".to_string(), Value::Int(1));
    assert_eq!(redact_value(Value::Map(entries)), Value::Secret);
}

/// F8: the invisible set covers the format characters the review listed.
#[test]
fn the_invisible_set_covers_the_remaining_format_characters() {
    for character in [
        '\u{0600}',
        '\u{06DD}',
        '\u{070F}',
        '\u{08E2}',
        '\u{110BD}',
        '\u{13430}',
        '\u{1BCA0}',
        '\u{1D173}',
        '\u{206A}',
        '\u{FFF9}',
        '\u{E0100}',
        '\u{115F}',
        '\u{3164}',
        '\u{FFA0}',
        '\u{2800}',
    ] {
        assert!(
            is_invisible_or_reordering(character),
            "U+{:04X} is not refused",
            character as u32
        );
        assert!(!valid_text(&format!("a{character}b"), 128));
    }
    // Ordinary text still passes.
    assert!(valid_text("rpc/budget-exceeded", 128));
}

/// F5: egress applies the policy, so a provider bug cannot leak structure.
#[test]
fn a_non_redacting_call_refuses_a_secret_bearing_module() {
    let module = active_rpc::domain::module_from_source("[app]\ntoken = secret(\"canary\")\n", "x")
        .expect("module");
    let image = active_infinity::encode(&module).expect("encode");
    // A structural secret (the original bytes) is refused...
    assert!(assert_no_structural_secrets(&Value::Module(image.clone())).is_err());
    // ...while the content-free marker is the sanctioned answer.
    assert!(assert_no_structural_secrets(&Value::Secret).is_ok());
    // Opaque provider bytes (a WASM tool's binary output) are not an image.
    assert!(assert_no_structural_secrets(&Value::Module(b"\0asm\x01\0\0\0".to_vec())).is_ok());
}
