//! Hardening of the durable-capability record and the security helpers (R-16):
//! a record is single-use across kernels, an unparsable record is never exported,
//! the security helpers inspect module bytes, and the parser speaks the durable
//! error vocabulary.

use active_rpc::cap::{CapAttrs, CapPersistence};
use active_rpc::persistence::{CapabilityRecord, MemoryRecordStore, RecordStore};
use active_rpc::security::{assert_no_secret_material, redact_module, redact_value, SECRET_MARKER};
use active_rpc::value::Value;
use active_rpc::{Agent, Error, PeerIdentity};

fn admitted(name: &[u8]) -> active_rpc::AdmittedIdentity {
    active_rpc::IdentityPolicy::default()
        .admit(Some(&PeerIdentity::from_certificate(name)), false)
        .expect("admitted")
}

fn durable_agent() -> (Agent, active_rpc::ProviderId) {
    let agent = Agent::with_secret([0x61; 32]);
    agent.set_record_seal_key([0x62; 32]);
    agent.set_durable_capabilities(true);
    let provider = agent.register(Box::new(active_rpc::domain::ModuleProvider::new()));
    (agent, provider)
}

fn durable_cap(agent: &Agent, provider: active_rpc::ProviderId) -> active_rpc::CapHandle {
    let mut attrs = CapAttrs::new(&["metadata"]);
    attrs.persistence = CapPersistence::Durable;
    attrs.budget.max_calls = 4;
    agent
        .mint_bound(&admitted(b"owner"), provider, 0, attrs)
        .expect("durable cap")
}

// ---------------------------------------------------------------------------
// A2: one record, one restore, even across kernels
// ---------------------------------------------------------------------------

#[test]
fn a_record_restores_once_across_kernels_sharing_a_store() {
    let (first, provider) = durable_agent();
    let cap = durable_cap(&first, provider);
    let record = first.export_capability(&cap).expect("export");
    drop(cap);

    let mut store = MemoryRecordStore::new();
    let restored = first
        .restore_capability_with(&record, &admitted(b"owner"), Some(&mut store))
        .expect("the first restore");
    assert_eq!(store.len(), 1);
    drop(restored);

    // A second kernel with the same seal key would otherwise mint a second full
    // grant from the same record. The store is what stops it.
    let (second, _provider) = durable_agent();
    let error = second
        .restore_capability_with(&record, &admitted(b"owner"), Some(&mut store))
        .expect_err("a record is single-use across kernels");
    assert_eq!(error.code(), "rpc/persistence");
    assert_eq!(store.len(), 1);
}

#[test]
fn a_store_that_cannot_remember_refuses_and_revokes_the_grant() {
    struct Broken;
    impl RecordStore for Broken {
        fn is_restored(&self, _id: &[u8; 32]) -> bool {
            false
        }
        fn mark_restored(&mut self, _id: &[u8; 32]) -> active_rpc::Result<()> {
            Err(Error::persistence("the store is read-only"))
        }
    }

    let (agent, provider) = durable_agent();
    let cap = durable_cap(&agent, provider);
    let record = agent.export_capability(&cap).expect("export");
    drop(cap);
    let error = agent
        .restore_capability_with(&record, &admitted(b"owner"), Some(&mut Broken))
        .expect_err("a store that cannot remember refuses the restore");
    assert_eq!(error.code(), "rpc/persistence");
    // Nothing usable was left behind: the record cannot be restored again, and
    // the in-memory set remembers the id.
    // The revoke that failed the restore also tombstones the record id, so a
    // second attempt is refused either way: what matters is that no grant lives.
    assert!(
        agent
            .restore_capability(&record, &admitted(b"owner"))
            .is_err(),
        "a restore that could not be remembered must not leave a usable grant"
    );
}

// ---------------------------------------------------------------------------
// A1: the parser does not authenticate, and restore is the only bridge
// ---------------------------------------------------------------------------

#[test]
fn an_unsealed_record_parses_but_never_restores() {
    let (agent, provider) = durable_agent();
    let cap = durable_cap(&agent, provider);
    let mut record = agent.export_capability(&cap).expect("export");
    drop(cap);
    record.seal = None;
    // The parser is a parser: it accepts the shape.
    let parsed = CapabilityRecord::from_json(&record.to_json()).expect("parse");
    assert!(parsed.seal.is_none());
    // The authority comes only from the audited path, which checks the seal.
    let error = agent
        .restore_capability(&parsed, &admitted(b"owner"))
        .expect_err("an unsealed record is not authority");
    assert_eq!(error.code(), "rpc/persistence");
}

// ---------------------------------------------------------------------------
// A4: an unparsable record is never exported
// ---------------------------------------------------------------------------

#[test]
fn an_export_that_would_be_unreadable_is_refused_before_it_costs_anything() {
    let (agent, provider) = durable_agent();
    // The parser refuses a path scope over 1024 bytes; a capability minted with
    // one must not export, and the refusal must not burn the grant.
    let mut attrs = CapAttrs::new(&["metadata"]);
    attrs.persistence = CapPersistence::Durable;
    attrs.path_scope = Some("p".repeat(2_000));
    let cap = agent
        .mint_bound(&admitted(b"owner"), provider, 0, attrs)
        .expect("mint");
    let error = agent
        .export_capability(&cap)
        .expect_err("an unreadable record is refused");
    assert_eq!(error.code(), "rpc/persistence");
    // The grant is intact: a second export is refused for the same reason, not
    // because the first reserved the meter.
    let again = agent.export_capability(&cap).expect_err("still unreadable");
    assert_eq!(again.code(), "rpc/persistence");
    assert!(
        !format!("{again}").contains("committed"),
        "the first attempt must not have reserved the grant: {again}"
    );
}

// ---------------------------------------------------------------------------
// H6: the parser speaks the durable vocabulary
// ---------------------------------------------------------------------------

#[test]
fn a_record_with_a_zero_ceiling_is_a_persistence_refusal() {
    let text = r#"{"format":"active-rpc/capability-record/1","provider":"echo","object":0,
      "methods":["echo"],
      "budget":{"calls":0,"bytes":1,"wall_ms":1,"nodes":1,"depth":1,"array_len":1,"value_size":1},
      "read_only":false,"redact":false,"path_scope":null,"topics":null,"tool_policy":null,
      "bound_to":null,"expires_at":null}"#;
    let error = CapabilityRecord::from_json(text).expect_err("a zero ceiling is refused");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
}

// ---------------------------------------------------------------------------
// A3: the security helpers inspect module bytes
// ---------------------------------------------------------------------------

/// A module with a secret node, encoded.
fn module_with_a_secret() -> Vec<u8> {
    use active_infinity::{encode, InfinityModule, Inode};
    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(active_infinity::SecretBytes::new(b"canary")));
    let key = module.push(Inode::Str("password".to_string()));
    // A module needs a root: without one the encoder emits an empty arena.
    let root = module.push(Inode::Table {
        fields: vec![("k".to_string(), key), ("v".to_string(), secret)],
    });
    module.set_root(Some(root));
    encode(&module).expect("encode")
}

#[test]
fn a_module_that_carries_a_secret_is_refused_and_redacts() {
    let bytes = module_with_a_secret();
    // The value model has no secret variant for module bytes, so the helper has
    // to decode them: this is the case it used to pass through.
    let error = assert_no_secret_material(&Value::Module(bytes.clone()))
        .expect_err("a module with a secret node is secret material");
    assert_eq!(error.code(), "rpc/provider", "{error}");

    // Redaction rewrites the node rather than handing back the bytes.
    match redact_value(Value::Module(bytes.clone())) {
        Value::Module(redacted) => {
            assert_ne!(redacted, bytes, "the redacted module must differ");
            assert!(assert_no_secret_material(&Value::Module(redacted)).is_ok());
        }
        other => panic!("a decodable module stays a module: {other:?}"),
    }
    // And the shared redactor agrees with the value-level one.
    let redacted = redact_module(&bytes).expect("redact");
    assert!(assert_no_secret_material(&Value::Module(redacted)).is_ok());
}

#[test]
fn a_module_without_secrets_passes_and_is_untouched() {
    use active_infinity::{encode, InfinityModule, Inode};
    let mut module = InfinityModule::new();
    let root = module.push(Inode::Str("plain".to_string()));
    module.set_root(Some(root));
    let bytes = encode(&module).expect("encode");
    assert_no_secret_material(&Value::Module(bytes.clone())).expect("no secret");
    match redact_value(Value::Module(bytes.clone())) {
        Value::Module(same) => assert_eq!(same, bytes),
        other => panic!("expected a module, got {other:?}"),
    }
    assert!(SECRET_MARKER.contains("SECRET"));
}
