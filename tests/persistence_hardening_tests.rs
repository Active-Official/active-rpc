//! Hardening of the durable-capability record and the security helpers (R-16):
//! a record is single-use across kernels, an unparsable record is never exported,
//! the security helpers inspect module bytes, and the parser speaks the durable
//! error vocabulary.

#[cfg(feature = "test-utils")]
use active_rpc::cap::{CapAttrs, CapPersistence};
#[cfg(feature = "test-utils")]
use active_rpc::identity::IdentityPolicy;
#[cfg(feature = "test-utils")]
use active_rpc::kernel::Provider;
use active_rpc::persistence::CapabilityRecord;
#[cfg(feature = "test-utils")]
use active_rpc::persistence::{MemoryRecordStore, RecordStore};
use active_rpc::security::{assert_no_secret_material, redact_module, redact_value, SECRET_MARKER};
use active_rpc::value::Value;
#[cfg(feature = "test-utils")]
use active_rpc::value::{Call, Response};
#[cfg(feature = "test-utils")]
use active_rpc::{Agent, Error, PeerIdentity};
#[cfg(feature = "test-utils")]
use active_rpc::{Budget, CapHandle, ProviderId};
#[cfg(feature = "test-utils")]
use std::collections::BTreeSet;
#[cfg(feature = "test-utils")]
use std::fs::File;
#[cfg(feature = "test-utils")]
use std::io::{BufWriter, Write};
#[cfg(feature = "test-utils")]
use std::path::{Path, PathBuf};
#[cfg(feature = "test-utils")]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "test-utils")]
fn admitted(name: &[u8]) -> active_rpc::AdmittedIdentity {
    active_rpc::IdentityPolicy::default()
        .admit(Some(&PeerIdentity::from_certificate_for_test(name)), false)
        .expect("admitted")
}

#[cfg(feature = "test-utils")]
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
    let provider = agent
        .register(Box::new(provider))
        .expect("register provider");
    (agent, provider)
}

#[cfg(feature = "test-utils")]
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

#[cfg(feature = "test-utils")]
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

#[cfg(feature = "test-utils")]
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
#[cfg(feature = "test-utils")]
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

#[cfg(feature = "test-utils")]
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

#[cfg(feature = "test-utils")]
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
            assert_eq!(assert_no_secret_material(&Value::Module(redacted)), Ok(()));
        }
        other => panic!("a decodable module stays a module: {other:?}"),
    }
    // And the shared redactor agrees with the value-level one.
    let redacted = redact_module(&bytes).expect("redact");
    assert_eq!(assert_no_secret_material(&Value::Module(redacted)), Ok(()));
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

// ---------------------------------------------------------------------------
// R2-PERSIST-04: a `RecordStore::claim` is single-use only if it is durable
// ---------------------------------------------------------------------------
//
// The audit probe (`probe_persistence_r2.rs`,
// `r2_persist_04_buffered_claim_lost_on_crash_double_restores`) shows a
// natural file-backed store — append the id through a `BufWriter`, return
// `Ok` as soon as the bytes are buffered — losing every recent claim to a
// crash, so the next kernel restores the same record again. The trait
// never asked for durability; now it does (`RecordStore::claim`, and the
// `sync` hook the kernel calls after `claim` and before the mint).
//
// The port below keeps the probe's shape (same secrets, same seal, same
// Echo provider, same crash model: `mem::forget` the store with the claim
// still buffered) and adapts only what HEAD forces:
// - `register` returns `Result` now (RPC-51): `.expect("register provider")`.
// - `admit` refuses an unverified certificate identity (RPC-55): the test
//   peer is built with `from_certificate_for_test` (same bytes, same
//   fingerprint). `call_as` skips `admit`, so `persist04_peer` keeps the
//   audited constructor.
// - File names carry a per-test counter as well as the pid: the probe ran
//   one test per process, but this suite runs its tests in parallel threads
//   of one process, so a pid alone no longer disambiguates.
// - A `Persist04ClaimFileGuard` removes the claim file on drop, so a test
//   that panics mid-way (an `expect` before the cleanup) cannot leak a Temp
//   file.

#[cfg(feature = "test-utils")]
struct Persist04Echo;

#[cfg(feature = "test-utils")]
impl Provider for Persist04Echo {
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
                .iter()
                .find_map(|arg| match arg {
                    active_rpc::value::Arg::Value(value) => Some(value.clone()),
                    _ => None,
                })
                .unwrap_or(Value::Text("ok".into())),
        ))
    }
}

#[cfg(feature = "test-utils")]
fn persist04_admitted(certificate: &[u8]) -> active_rpc::AdmittedIdentity {
    // RPC-55: admit refuses an unverified certificate identity, so the test
    // peer is built with the verified test constructor (same bytes, same
    // fingerprint). The loopback flag is irrelevant for a verified identity.
    let peer = PeerIdentity::from_certificate_for_test(certificate);
    IdentityPolicy::default()
        .admit(Some(&peer), true)
        .expect("admit")
}

#[cfg(feature = "test-utils")]
fn persist04_peer(certificate: &[u8]) -> PeerIdentity {
    PeerIdentity::from_certificate(certificate)
}

#[cfg(feature = "test-utils")]
static PERSIST04_LANE_SEQ: AtomicUsize = AtomicUsize::new(0);

/// True when `cap` answers one `echo` call on `agent` as `peer_cert`.
#[cfg(feature = "test-utils")]
fn persist04_call_ok(agent: &Agent, cap: &CapHandle, peer_cert: &[u8]) -> bool {
    let n = PERSIST04_LANE_SEQ.fetch_add(1, Ordering::SeqCst);
    let lane = agent
        .create_lane(format!("probe-{n}"), Budget::default())
        .expect("lane");
    let promise = match agent.call_as(
        Some(&persist04_peer(peer_cert)),
        lane,
        cap,
        "echo",
        Vec::new(),
    ) {
        Ok(promise) => promise,
        Err(error) => {
            println!("call refused: {} ({})", error, error.code());
            return false;
        }
    };
    agent.run();
    match promise.value() {
        Ok(value) => {
            println!("call answered: {value:?}");
            true
        }
        Err(error) => {
            println!("call failed: {} ({})", error, error.code());
            false
        }
    }
}

#[cfg(feature = "test-utils")]
fn persist04_durable_attrs() -> CapAttrs {
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    attrs
}

/// Agent pair sharing one kernel secret and one seal key (one deployment,
/// two kernels), each with its own Echo provider.
#[cfg(feature = "test-utils")]
fn persist04_two_kernels(
    secret: [u8; 32],
    seal: [u8; 32],
) -> (Agent, ProviderId, Agent, ProviderId) {
    let a = Agent::with_secret(secret);
    a.set_durable_capabilities(true);
    a.set_record_seal_key(seal);
    let pa = a
        .register(Box::new(Persist04Echo))
        .expect("register provider");
    let b = Agent::with_secret(secret);
    b.set_durable_capabilities(true);
    b.set_record_seal_key(seal);
    let pb = b
        .register(Box::new(Persist04Echo))
        .expect("register provider");
    (a, pa, b, pb)
}

/// One claim file per test: the pid plus a per-test counter, so tests in
/// parallel threads of one process never share a path.
#[cfg(feature = "test-utils")]
static PERSIST04_FILE_SEQ: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "test-utils")]
fn persist04_claim_file_path(tag: &str) -> PathBuf {
    let n = PERSIST04_FILE_SEQ.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!("r2-persist-04-{}-{n}-{tag}", std::process::id()))
}

/// Removes the claim file when dropped, so a test that panics before its
/// cleanup still leaves no Temp file behind.
#[cfg(feature = "test-utils")]
struct Persist04ClaimFileGuard {
    path: PathBuf,
}

#[cfg(feature = "test-utils")]
impl Drop for Persist04ClaimFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A natural file-backed [`RecordStore`], ported from the audit probe, now
/// written against the durable contract: claims are appended through a
/// `BufWriter` and `claim` returns `Ok` as soon as the bytes are buffered —
/// but `sync` flushes + fsyncs, and the kernel calls it after `claim` and
/// before the mint, so a claim is durable before the grant exists.
/// `is_restored` answers from the synced set only: a buffered-but-unsynced
/// claim is not durable state, and a crash could still lose it.
#[cfg(feature = "test-utils")]
struct Persist04BufferedFileStore {
    writer: BufWriter<File>,
    seen: BTreeSet<[u8; 32]>,
    durable: BTreeSet<[u8; 32]>,
}

#[cfg(feature = "test-utils")]
impl Persist04BufferedFileStore {
    fn create(path: &Path) -> Self {
        Self {
            writer: BufWriter::new(File::create(path).expect("create claim file")),
            seen: BTreeSet::new(),
            durable: BTreeSet::new(),
        }
    }

    fn open(path: &Path) -> Self {
        let mut seen = BTreeSet::new();
        if let Ok(text) = std::fs::read_to_string(path) {
            for line in text.lines() {
                if line.len() == 64 {
                    let mut id = [0u8; 32];
                    for (i, slot) in id.iter_mut().enumerate() {
                        *slot = u8::from_str_radix(&line[i * 2..i * 2 + 2], 16).expect("hex");
                    }
                    seen.insert(id);
                }
            }
        }
        // Everything the file holds survived a crash by construction: the
        // reopened store's durable set is the file's set.
        let durable = seen.clone();
        Self {
            writer: BufWriter::new(
                File::options()
                    .append(true)
                    .open(path)
                    .expect("open claim file"),
            ),
            seen,
            durable,
        }
    }
}

#[cfg(feature = "test-utils")]
fn persist04_hex_id(id: &[u8; 32]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(feature = "test-utils")]
impl RecordStore for Persist04BufferedFileStore {
    fn is_restored(&self, record_id: &[u8; 32]) -> bool {
        // Durable state only: `seen` holds claims the buffer may still owe
        // the disk, and answering from it would call a losable claim restored.
        self.durable.contains(record_id)
    }

    fn mark_restored(&mut self, record_id: &[u8; 32]) -> active_rpc::Result<()> {
        // The advisory path commits like the kernel path: claim, then sync.
        self.claim(record_id)?;
        self.sync()
    }

    fn claim(&mut self, record_id: &[u8; 32]) -> active_rpc::Result<()> {
        if !self.seen.insert(*record_id) {
            return Err(Error::persistence("the record was already restored"));
        }
        writeln!(self.writer, "{}", persist04_hex_id(record_id))
            .map_err(|_| Error::persistence("claim write failed"))?;
        // Deliberately no flush() / sync_all() here: the kernel's `sync`
        // is what makes the claim durable, before the mint.
        Ok(())
    }

    fn sync(&mut self) -> active_rpc::Result<()> {
        self.writer
            .flush()
            .and_then(|()| self.writer.get_ref().sync_all())
            .map_err(|_| Error::persistence("claim sync failed"))?;
        // Every claim accepted so far is now durable.
        self.durable = self.seen.clone();
        Ok(())
    }
}

/// R2-PERSIST-04: a buffered file-backed claim survives a crash, so the
/// record restores once. Ported from the audit probe
/// (`r2_persist_04_buffered_claim_lost_on_crash_double_restores`): the
/// probe's store never flushed, and the trait never asked it to. The
/// store here is the same shape, written against the new contract —
/// `claim` buffers, `sync` flushes + fsyncs — and the kernel calls `sync`
/// after `claim` and before the mint, so the claim is on disk before the
/// grant exists and `mem::forget` (the crash analogue) loses nothing.
#[cfg(feature = "test-utils")]
#[test]
fn a_buffered_claim_survives_a_crash_once_the_kernel_syncs_it() {
    let secret = [0x77; 32];
    let seal = [0x97; 32];
    let (a, pa, b, _pb) = persist04_two_kernels(secret, seal);
    let owner = persist04_admitted(b"durable-owner");
    let cap = a
        .mint_bound(&owner, pa, 0, persist04_durable_attrs())
        .expect("durable cap");
    let record = a.export_capability(&cap).expect("export");
    drop(cap);

    let path = persist04_claim_file_path("main");
    let _guard = Persist04ClaimFileGuard { path: path.clone() };
    let _ = std::fs::remove_file(&path);
    let mut store1 = Persist04BufferedFileStore::create(&path);
    let restored_b = b
        .restore_capability_with(&record, &owner, Some(&mut store1))
        .expect("first restore");
    assert!(
        persist04_call_ok(&b, &restored_b, b"durable-owner"),
        "first restored grant calls"
    );
    // Simulated crash: the process dies with the claim still in the
    // BufWriter. `mem::forget` models exactly that -- but the kernel's
    // `sync` already flushed + fsynced the claim before the mint, so
    // there is nothing left in the buffer to lose.
    std::mem::forget(store1);
    drop(restored_b);
    drop(b);
    let persisted = std::fs::read_to_string(&path).expect("read claim file");

    let mut store2 = Persist04BufferedFileStore::open(&path);
    assert!(
        store2.is_restored(&record.record_id),
        "the reopened store answers from durable state: the claim survived the crash"
    );
    let c = Agent::with_secret(secret);
    c.set_durable_capabilities(true);
    c.set_record_seal_key(seal);
    c.register(Box::new(Persist04Echo))
        .expect("register provider");
    match c.restore_capability_with(&record, &owner, Some(&mut store2)) {
        Ok(restored_c) => {
            let callable = persist04_call_ok(&c, &restored_c, b"durable-owner");
            panic!(
                "REPRODUCED R2-PERSIST-04: after a crash lost the buffered \
                 claim, a second kernel restored the same record and its \
                 grant calls: callable={callable} -- one credential, two live \
                 grants, budgets doubled (claim file after the crash: {persisted:?})"
            );
        }
        Err(error) => {
            assert_eq!(error.code(), "rpc/persistence");
            assert!(
                !persisted.is_empty(),
                "the claim reached disk before the crash: the file holds it"
            );
            println!("OK: second restore refused: {}", error.code());
        }
    }
}

/// The audit probe's store verbatim: `claim` buffers, `sync` is the
/// default no-op, `is_restored` answers from the in-memory set. It
/// violates the durable contract on purpose — the control.
#[cfg(feature = "test-utils")]
struct Persist04NeverSyncStore {
    writer: BufWriter<File>,
    seen: BTreeSet<[u8; 32]>,
}

#[cfg(feature = "test-utils")]
impl Persist04NeverSyncStore {
    fn create(path: &Path) -> Self {
        Self {
            writer: BufWriter::new(File::create(path).expect("create claim file")),
            seen: BTreeSet::new(),
        }
    }

    fn open(path: &Path) -> Self {
        let mut seen = BTreeSet::new();
        if let Ok(text) = std::fs::read_to_string(path) {
            for line in text.lines() {
                if line.len() == 64 {
                    let mut id = [0u8; 32];
                    for (i, slot) in id.iter_mut().enumerate() {
                        *slot = u8::from_str_radix(&line[i * 2..i * 2 + 2], 16).expect("hex");
                    }
                    seen.insert(id);
                }
            }
        }
        Self {
            writer: BufWriter::new(
                File::options()
                    .append(true)
                    .open(path)
                    .expect("open claim file"),
            ),
            seen,
        }
    }
}

#[cfg(feature = "test-utils")]
impl RecordStore for Persist04NeverSyncStore {
    fn is_restored(&self, record_id: &[u8; 32]) -> bool {
        self.seen.contains(record_id)
    }

    fn mark_restored(&mut self, record_id: &[u8; 32]) -> active_rpc::Result<()> {
        self.claim(record_id)
    }

    fn claim(&mut self, record_id: &[u8; 32]) -> active_rpc::Result<()> {
        if !self.seen.insert(*record_id) {
            return Err(Error::persistence("the record was already restored"));
        }
        writeln!(self.writer, "{}", persist04_hex_id(record_id))
            .map_err(|_| Error::persistence("claim write failed"))?;
        // Deliberately no flush() / sync_all(): the trait never asked for
        // it — this is the store the finding is about. No `sync` override,
        // so the kernel's `sync` call is the default no-op.
        Ok(())
    }
}

/// R2-PERSIST-04 (control): a store that buffers in `claim` and never
/// makes the claim durable still loses it on crash — the kernel cannot
/// conjure durability for a store that violates the `RecordStore`
/// contract. The second restore succeeds and its grant calls, which is
/// the harm, and which also proves the main test above is non-vacuous:
/// it fails exactly when durability is absent.
#[cfg(feature = "test-utils")]
#[test]
fn a_store_that_never_makes_its_claim_durable_still_double_restores() {
    let secret = [0x77; 32];
    let seal = [0x97; 32];
    let (a, pa, b, _pb) = persist04_two_kernels(secret, seal);
    let owner = persist04_admitted(b"durable-owner");
    let cap = a
        .mint_bound(&owner, pa, 0, persist04_durable_attrs())
        .expect("durable cap");
    let record = a.export_capability(&cap).expect("export");
    drop(cap);

    let path = persist04_claim_file_path("control");
    let _guard = Persist04ClaimFileGuard { path: path.clone() };
    let _ = std::fs::remove_file(&path);
    let mut store1 = Persist04NeverSyncStore::create(&path);
    let restored_b = b
        .restore_capability_with(&record, &owner, Some(&mut store1))
        .expect("first restore");
    assert!(
        persist04_call_ok(&b, &restored_b, b"durable-owner"),
        "first restored grant calls"
    );
    // Simulated crash, as in the main test — but nothing ever flushed the
    // claim, so the buffer dies with the store.
    std::mem::forget(store1);
    drop(restored_b);
    drop(b);
    let persisted = std::fs::read_to_string(&path).expect("read claim file");
    assert!(
        persisted.is_empty(),
        "control setup: the buffered claim must not have reached disk, got {persisted:?}"
    );

    let mut store2 = Persist04NeverSyncStore::open(&path);
    assert!(
        !store2.is_restored(&record.record_id),
        "control setup: the reopened store sees the record as fresh"
    );
    let c = Agent::with_secret(secret);
    c.set_durable_capabilities(true);
    c.set_record_seal_key(seal);
    c.register(Box::new(Persist04Echo))
        .expect("register provider");
    let restored_c = c
        .restore_capability_with(&record, &owner, Some(&mut store2))
        .expect("the non-conforming store restores twice: the kernel cannot save it");
    assert!(
        persist04_call_ok(&c, &restored_c, b"durable-owner"),
        "the second grant calls: one credential, two live grants"
    );
}

/// R2-PERSIST-04: a `sync` failure refuses the restore with no grant
/// minted. The `sync` error is propagated with `?`, never swallowed: a
/// store whose disk is gone must not mint a grant its claim cannot outlive.
#[cfg(feature = "test-utils")]
#[test]
fn a_failed_sync_refuses_the_restore_and_spends_the_record_in_that_store() {
    /// A store that records the claim in memory but can never make it
    /// durable: `sync` always fails. Deliberately non-durable in every
    /// method — it exists to pin the kernel's behaviour when `sync`
    /// fails, not as a contract example.
    struct FailingSyncStore {
        seen: BTreeSet<[u8; 32]>,
    }

    impl RecordStore for FailingSyncStore {
        fn is_restored(&self, record_id: &[u8; 32]) -> bool {
            self.seen.contains(record_id)
        }

        fn mark_restored(&mut self, record_id: &[u8; 32]) -> active_rpc::Result<()> {
            self.claim(record_id)
        }

        fn claim(&mut self, record_id: &[u8; 32]) -> active_rpc::Result<()> {
            if self.seen.insert(*record_id) {
                Ok(())
            } else {
                Err(Error::persistence("the record was already restored"))
            }
        }

        fn sync(&mut self) -> active_rpc::Result<()> {
            Err(Error::persistence("the claim could not be made durable"))
        }
    }

    let secret = [0x77; 32];
    let seal = [0x97; 32];
    let (a, pa, b, _pb) = persist04_two_kernels(secret, seal);
    let owner = persist04_admitted(b"durable-owner");
    let cap = a
        .mint_bound(&owner, pa, 0, persist04_durable_attrs())
        .expect("durable cap");
    let record = a.export_capability(&cap).expect("export");
    drop(cap);

    let mut store = FailingSyncStore {
        seen: BTreeSet::new(),
    };
    let error = b
        .restore_capability_with(&record, &owner, Some(&mut store))
        .expect_err("a sync failure refuses the restore");
    assert_eq!(error.code(), "rpc/persistence");
    // The claim happens *before* the mint, and the sync happens before the
    // mint too, so a failed sync leaves no grant behind at all.
    assert_eq!(
        b.metrics().promises_pending,
        0,
        "a refused sync leaves nothing to run"
    );
    // The claim itself landed in this store: a retry against the same store
    // is a conflict, fail-closed — the record is spent here, and the
    // operator reconciles (ADR-0010).
    let error = b
        .restore_capability_with(&record, &owner, Some(&mut store))
        .expect_err("the failed sync spent the record in this store");
    assert_eq!(error.code(), "rpc/persistence");
    // The failed attempt minted nothing and burned nothing outside the
    // failing store: a working store still restores the record once.
    let mut working = MemoryRecordStore::new();
    let restored = b
        .restore_capability_with(&record, &owner, Some(&mut working))
        .expect("the record is intact after a failed sync");
    drop(restored);
    assert_eq!(working.len(), 1);
}
