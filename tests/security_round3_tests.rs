//! R-16 round 3: the secret gates inspect a module that claims to be an image,
//! the record store defaults fail closed, the seal parser mirrors the verifier,
//! and `Debug` never prints module bytes.

use active_rpc::cap::CapAttrs;
use active_rpc::identity::{IdentityPolicy, PeerIdentity};
use active_rpc::kernel::Provider;
use active_rpc::persistence::{CapabilityRecord, MemoryRecordStore, RecordStore};
use active_rpc::value::{Call, Response, Value};
use active_rpc::{Agent, Budget, CapPersistence, Error};

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
        Ok(Response::Value(
            call.args
                .first()
                .map(|arg| match arg {
                    active_rpc::value::Arg::Value(value) => value.clone(),
                    _ => Value::Null,
                })
                .unwrap_or(Value::Null),
        ))
    }
}

fn admitted(certificate: &[u8]) -> active_rpc::AdmittedIdentity {
    let peer = PeerIdentity::from_certificate(certificate);
    IdentityPolicy::default()
        .admit(Some(&peer), true)
        .expect("admit")
}

fn durable_agent() -> (Agent, active_rpc::CapHandle) {
    let agent = Agent::with_secret([0x31; 32]);
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key([0x41; 32]);
    let provider = agent.register(Box::new(Echo));
    let mut attrs = CapAttrs::new(&["echo"]).with_budget(Budget::calls(10_000));
    attrs.persistence = CapPersistence::Durable;
    let owner = admitted(b"durable-owner");
    let cap = agent.mint_bound(&owner, provider, 0, attrs).expect("mint");
    (agent, cap)
}

/// A store that implements `claim` by delegating to `mark_restored` and forgets
/// to override it: the default must refuse rather than accept silently, or one
/// record becomes two grants (round 3, F-3).
struct ForgetsMarkRestored {
    ids: std::collections::BTreeSet<[u8; 32]>,
}

impl RecordStore for ForgetsMarkRestored {
    fn is_restored(&self, record_id: &[u8; 32]) -> bool {
        self.ids.contains(record_id)
    }

    fn claim(&mut self, record_id: &[u8; 32]) -> Result<(), Error> {
        // The `MemoryRecordStore` shape, minus the override.
        self.mark_restored(record_id)
    }
}

#[test]
fn a_store_that_forgets_mark_restored_fails_closed() {
    let (agent, cap) = durable_agent();
    let owner = admitted(b"durable-owner");
    let record = agent.export_capability(&cap).expect("export");
    // A restore while the exporter is live is refused for a different reason.
    drop(cap);
    agent.run();
    let mut store = ForgetsMarkRestored {
        ids: std::collections::BTreeSet::new(),
    };
    let error = agent
        .restore_capability_with(&record, &owner, Some(&mut store))
        .expect_err("an unreachable store cannot claim the record");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
    assert!(
        store.ids.is_empty(),
        "a failed claim must not have been recorded"
    );

    // The control: an honest store accepts the record once.
    let mut honest = MemoryRecordStore::new();
    agent
        .restore_capability_with(&record, &owner, Some(&mut honest))
        .expect("the honest store claims the record");
}

/// The seal parser must accept exactly what the verifier accepts: lowercase hex
/// of the right length. An uppercase or non-hex seal parses today and every
/// restore then fails (round 3, F-4).
#[test]
fn a_record_with_a_seal_the_verifier_can_never_accept_is_refused() {
    let (agent, cap) = durable_agent();
    let record = agent.export_capability(&cap).expect("export");
    let text = record.to_json();

    for bad in [
        text.replace(
            &record.seal.clone().expect("sealed"),
            &record.seal.clone().expect("sealed").to_uppercase(),
        ),
        text.replace(&record.seal.clone().expect("sealed"), &"Z".repeat(64)),
    ] {
        let error = CapabilityRecord::from_json(&bad).expect_err("the seal is not verifier-shaped");
        assert_eq!(error.code(), "rpc/persistence", "{error}");
    }
}

/// `Debug` prints a module's length, never its bytes: a provider that logs its
/// own response must not print the payload the egress gate is about to inspect
/// (round 3, F-5).
#[test]
fn a_value_debug_does_not_print_module_bytes() {
    let secret = b"hunter2-and-then-some".to_vec();
    let rendered = format!("{:?}", Value::Module(secret.clone()));
    assert!(rendered.contains("Module"), "{rendered}");
    assert!(
        !rendered.contains("hunter2") && !rendered.contains("104"),
        "the bytes leaked: {rendered}"
    );
    assert_eq!(format!("{:?}", Value::Secret), "Secret");
}

/// The seal's input bytes are a golden vector: the top-level key order is
/// pinned elsewhere, and this pins the whole material (nested `budget` and
/// `tool_policy` order included), so a reorder that would invalidate every
/// record at rest fails here instead of silently in the field (round 3, F-6).
#[test]
fn the_seal_material_is_pinned_to_a_golden_vector() {
    let (agent, cap) = durable_agent();
    let record = agent.export_capability(&cap).expect("export");
    assert_eq!(
        record.seal.as_deref(),
        Some("fcb4a2b989f168236559fd994213f41df097c8c6bc8e28dad19e9f59620c54a9"),
        "the seal material changed; every record at rest would now fail its canonical check"
    );
}
