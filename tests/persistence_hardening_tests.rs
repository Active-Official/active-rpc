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
    // A record names a real object: restore refuses one whose object the
    // provider no longer holds (round 32, #3). The module is installed first,
    // so it takes object id 0.
    let mut provider = active_rpc::domain::ModuleProvider::new();
    let mut module = active_infinity::InfinityModule::new();
    let root = module.push(active_infinity::Inode::Str("app".to_string()));
    module.set_root(Some(root));
    provider.install(module).expect("install");
    let provider = agent.register(Box::new(provider));
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
        fn claim(&mut self, id: &[u8; 32]) -> active_rpc::Result<()> {
            self.mark_restored(id)
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
    // The claim happens *before* the mint, so a store that cannot claim leaves
    // no grant behind at all (the old order minted one and then revoked it).
    assert_eq!(
        agent.metrics().promises_pending,
        0,
        "a refused claim leaves nothing to run"
    );
    // The record was not consumed: a working deployment can still restore it.
    let mut store = MemoryRecordStore::new();
    let restored = agent
        .restore_capability_with(&record, &admitted(b"owner"), Some(&mut store))
        .expect("the record is intact after a failed claim");
    drop(restored);
    assert_eq!(store.len(), 1);
}

/// A store that detects the conflict (rather than a write error) also leaves
/// exactly one grant.
#[test]
fn a_store_that_detects_a_conflict_leaves_one_grant() {
    struct Conflict(bool);
    impl RecordStore for Conflict {
        fn is_restored(&self, _id: &[u8; 32]) -> bool {
            false
        }
        fn mark_restored(&mut self, _id: &[u8; 32]) -> active_rpc::Result<()> {
            if self.0 {
                return Err(Error::persistence("duplicate"));
            }
            self.0 = true;
            Ok(())
        }
        fn claim(&mut self, _id: &[u8; 32]) -> active_rpc::Result<()> {
            self.mark_restored(_id)
        }
    }

    let (first, provider) = durable_agent();
    let cap = durable_cap(&first, provider);
    let record = first.export_capability(&cap).expect("export");
    drop(cap);
    let mut store = Conflict(false);
    let restored = first
        .restore_capability_with(&record, &admitted(b"owner"), Some(&mut store))
        .expect("the first restore claims the record");
    drop(restored);

    let (second, _provider) = durable_agent();
    let error = second
        .restore_capability_with(&record, &admitted(b"owner"), Some(&mut store))
        .expect_err("the second restore is a conflict");
    assert_eq!(error.code(), "rpc/persistence");
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
        .restore_capability_in_process_only(&parsed, &admitted(b"owner"))
        .expect_err("an unsealed record is not authority");
    assert_eq!(error.code(), "rpc/persistence");
}

// ---------------------------------------------------------------------------
// A4: an unparsable record is never exported
// ---------------------------------------------------------------------------

#[test]
fn an_unreadable_path_scope_is_refused_at_mint() {
    let (agent, provider) = durable_agent();
    // The parser refuses a path scope over 1024 bytes. Since R-03 round 4 the
    // mint applies the same rule, so a capability that could never be exported
    // or restored is never created. (Before that round the mint accepted it and
    // the export refused, leaving an unusable capability behind.)
    let mut attrs = CapAttrs::new(&["metadata"]);
    attrs.persistence = CapPersistence::Durable;
    attrs.path_scope = Some("p".repeat(2_000));
    let error = agent
        .mint_bound(&admitted(b"owner"), provider, 0, attrs)
        .expect_err("an unreadable path scope is refused at the mint");
    assert_eq!(error.code(), "rpc/invalid-argument");

    // A control character in the scope is refused the same way.
    let mut attrs = CapAttrs::new(&["metadata"]);
    attrs.path_scope = Some("a\u{2028}b".to_string());
    let error = agent
        .mint(provider, 0, attrs)
        .expect_err("a scope with a reordering character is refused");
    assert_eq!(error.code(), "rpc/invalid-argument");
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
