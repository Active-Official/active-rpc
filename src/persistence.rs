//! The durable capability profile (ADR-0010).
//!
//! A `CapabilityRecord` is the *authority metadata* of a durable capability:
//! provider name, object, methods, budget, flags, scope, topics, tool policy,
//! identity binding and absolute deadline. It carries no secret and no kernel
//! id: ids are derived from the kernel secret and are meaningless elsewhere.
//!
//! Restoring is a re-mint, not a resurrection: the kernel creates a fresh id
//! with the recorded authority, shortens the deadline to the original one, and
//! binds it to the peer the deployment admitted. A record alone is therefore
//! not authority: the deployment must enable durable capabilities *and* admit
//! the peer the record is restored for.

use std::collections::BTreeSet;

use serde_json::{Map, Value as Json};

use crate::budget::Budget;
use crate::cap::{CapAttrs, CapPersistence, ToolPolicy};
use crate::{Error, Result};

/// A durable home for the "already restored" set.
///
/// [`crate::Agent::restore_capability`] remembers restored record ids only in
/// the process that restored them. A record is a bearer credential whose seal is
/// deployment-wide, so without a durable set a restart (or a second kernel)
/// restores the same record again and mints a second grant for the full recorded
/// budget. A deployment with persistent storage implements this over it and
/// calls [`crate::Agent::restore_capability_with`].
///
/// Both methods are fallible in spirit: `is_restored` answers from the store, and
/// `mark_restored` must fail closed — a store that cannot write must return an
/// error, because the restore is then refused and the minted grant revoked.
pub trait RecordStore {
    /// True when this record id was restored by any kernel sharing the store.
    ///
    /// A read error must answer `true`: the caller treats `false` as "not yet
    /// restored" and would mint a second grant.
    fn is_restored(&self, record_id: &[u8; 32]) -> bool;

    /// Remember a restore, or refuse when the store cannot.
    ///
    /// A store whose backend accepts duplicates (an upsert) must detect the
    /// conflict and return an error: two restores of one record are two copies
    /// of its budget, and a revocation reaches only the one it knows.
    fn mark_restored(&mut self, record_id: &[u8; 32]) -> Result<()>;

    /// Atomically take ownership of a record id.
    ///
    /// Required, with no default: a check-then-mark implementation races
    /// between two processes, and both would mint a grant for one record
    /// (audit ARPC-010). An implementation over shared storage must do an
    /// insert-if-absent (a unique key, a conditional write, a compare-and-swap)
    /// in one step, in the same transactional domain as its tombstones.
    /// [`MemoryRecordStore`] is atomic in one process only.
    ///
    /// The kernel calls this after the seal and the binding are verified and
    /// before the grant is minted.
    fn claim(&mut self, record_id: &[u8; 32]) -> Result<()>;
}

/// An in-memory [`RecordStore`], for tests and single-process deployments.
///
/// It buys nothing over the kernel's own set; it exists so an embedder can share
/// one set between several agents in one process.
#[derive(Debug, Default)]
pub struct MemoryRecordStore {
    ids: BTreeSet<[u8; 32]>,
}

impl MemoryRecordStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of record ids remembered.
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// True when the store remembers nothing.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
}

impl RecordStore for MemoryRecordStore {
    fn is_restored(&self, record_id: &[u8; 32]) -> bool {
        self.ids.contains(record_id)
    }

    fn mark_restored(&mut self, record_id: &[u8; 32]) -> Result<()> {
        // The set is the store: a second insert of the same id is a conflict,
        // and accepting it would hand out a second copy of the budget.
        if self.ids.insert(*record_id) {
            Ok(())
        } else {
            Err(Error::persistence(
                "the record was already restored by this deployment",
            ))
        }
    }

    fn claim(&mut self, record_id: &[u8; 32]) -> Result<()> {
        // `insert` is the check and the write in one step. The store is
        // single-process by construction; a multi-process deployment must
        // implement `claim` over its own storage.
        self.mark_restored(record_id)
    }
}

/// Format tag of a capability record.
pub const RECORD_FORMAT: &str = "active-rpc/capability-record/1";

/// Largest record accepted, in bytes.
///
/// A record is a fixed set of scalar fields and short lists; anything beyond
/// this is hostile input.
pub const MAX_RECORD_BYTES: usize = 64 << 10;

/// The fields a record may carry. Anything else is refused.
const RECORD_KEYS: &[&str] = &[
    "format",
    "provider",
    "object",
    "methods",
    "budget",
    "read_only",
    "redact",
    "path_scope",
    "topics",
    "publish",
    "tool_policy",
    "bound_to",
    "expires_at",
    "wall_clock",
    "lease_ms",
    "record_id",
    "seal",
];

/// The fields a record's `budget` object may carry.
const BUDGET_KEYS: &[&str] = &[
    "calls",
    "bytes",
    "wall_ms",
    "nodes",
    "depth",
    "array_len",
    "value_size",
];

/// The fields a record's `tool_policy` object may carry.
const TOOL_POLICY_KEYS: &[&str] = &["allowed", "max_arg_bytes", "allow_process"];

/// Refuse a nested object key the format does not define.
///
/// The outer record map is checked; a nested extra key used to parse and seal,
/// so the text had a meaning the writer never produces (round 42, F1).
fn refuse_unknown_keys(
    object: &serde_json::Map<String, Json>,
    allowed: &[&str],
    what: &'static str,
) -> Result<()> {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(Error::persistence(match what {
                "budget" => "the record's budget has an unknown field",
                _ => "the record's tool policy has an unknown field",
            }));
        }
    }
    Ok(())
}

/// Refuse a record whose text is not the canonical rendering of its value.
///
/// The seal is computed over the parsed value, so the *text* must have exactly
/// one meaning. `serde_json` keeps the last of two equal keys, so
/// `{"provider":"evil",…,"provider":"echo"}` parsed to `echo` and sealed while a
/// first-wins consumer of the same text read `evil`. Re-rendering the parsed
/// value gives the one form this crate produces (`to_json`), and any other text —
/// a repeated key, different whitespace, a different key order — is refused.
fn refuse_non_canonical(text: &str, value: &Json) -> Result<()> {
    let Some(object) = value.as_object() else {
        return Err(Error::persistence("record is not an object"));
    };
    let rendered = Json::Object(object.clone()).to_string();
    if rendered != text {
        return Err(Error::persistence(
            "record text is not the canonical rendering of its value",
        ));
    }
    Ok(())
}

/// A durable capability's authority, without its id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRecord {
    /// Name of the provider that owns the object.
    pub provider: String,
    /// Object within the provider.
    pub object: u64,
    /// Granted methods; never empty.
    pub methods: BTreeSet<String>,
    /// Resource budget.
    pub budget: Budget,
    /// May not mutate.
    pub read_only: bool,
    /// Redacts trace output.
    pub redact: bool,
    /// Dotted path scope.
    pub path_scope: Option<String>,
    /// Topic set, when restricted.
    pub topics: Option<BTreeSet<String>>,
    /// Whether the record carries the publish grant.
    pub publish: bool,
    /// Tool policy, when present.
    pub tool_policy: Option<ToolPolicy>,
    /// Peer this capability was bound to, if it was.
    pub bound_to: Option<[u8; 32]>,
    /// Absolute deadline in kernel milliseconds, if bounded.
    pub expires_at: Option<u64>,
    /// Clock mode the deadline was taken in: `true` for wall clock, `false`
    /// for the virtual round-trip clock. A bounded record is only meaningful in
    /// its own domain.
    pub wall_clock: bool,
    /// Remaining lifetime at export time, in milliseconds.
    ///
    /// An absolute deadline only means something inside the kernel that minted
    /// it: two virtual clocks have unrelated epochs, so `expires_at` alone would
    /// stretch a lease across a restart. The lease is the ground truth, sealed
    /// with the rest of the record, and restore takes the smaller of the two.
    pub lease_ms: Option<u64>,
    /// Stable identity of the exported capability.
    ///
    /// A record is accepted only if its id was never tombstoned by a
    /// revocation, so the id is authority-bearing metadata: it is derived from
    /// the kernel secret and is not a capability by itself.
    pub record_id: [u8; 32],
    /// Keyed MAC over every other field, when the record was sealed.
    ///
    /// A record is a credential: whoever writes one can mint the authority it
    /// describes. The seal binds the fields to a deployment key so a record
    /// that was edited, truncated or fabricated is refused before it is
    /// re-minted.
    pub seal: Option<String>,
}

impl CapabilityRecord {
    /// The record's fields as a JSON map, without the seal.
    fn fields(&self) -> Map<String, Json> {
        let mut map = Map::new();
        map.insert("format".into(), RECORD_FORMAT.into());
        map.insert("provider".into(), self.provider.clone().into());
        map.insert("object".into(), self.object.into());
        let methods: Vec<Json> = self.methods.iter().cloned().map(Json::String).collect();
        map.insert("methods".into(), Json::Array(methods));
        map.insert(
            "budget".into(),
            serde_json::json!({
                "calls": self.budget.max_calls,
                "bytes": self.budget.max_bytes,
                "wall_ms": self.budget.max_wall_ms,
                "nodes": self.budget.max_nodes,
                "depth": self.budget.max_depth,
                "array_len": self.budget.max_array_len,
                "value_size": self.budget.max_value_size,
            }),
        );
        map.insert("read_only".into(), self.read_only.into());
        map.insert("redact".into(), self.redact.into());
        map.insert(
            "path_scope".into(),
            match &self.path_scope {
                Some(scope) => scope.clone().into(),
                None => Json::Null,
            },
        );
        map.insert(
            "topics".into(),
            match &self.topics {
                Some(topics) => Json::Array(topics.iter().cloned().map(Json::String).collect()),
                None => Json::Null,
            },
        );
        map.insert("publish".into(), self.publish.into());
        map.insert(
            "tool_policy".into(),
            match &self.tool_policy {
                Some(policy) => serde_json::json!({
                    "allowed": policy.allowed.iter().cloned().collect::<Vec<String>>(),
                    "max_arg_bytes": policy.max_arg_bytes,
                    "allow_process": policy.allow_process,
                }),
                None => Json::Null,
            },
        );
        map.insert(
            "bound_to".into(),
            match &self.bound_to {
                Some(fingerprint) => hex(fingerprint).into(),
                None => Json::Null,
            },
        );
        map.insert(
            "expires_at".into(),
            match self.expires_at {
                Some(at) => at.into(),
                None => Json::Null,
            },
        );
        map.insert("wall_clock".into(), self.wall_clock.into());
        map.insert(
            "lease_ms".into(),
            match self.lease_ms {
                Some(lease) => lease.into(),
                None => Json::Null,
            },
        );
        map.insert("record_id".into(), hex(&self.record_id).into());
        map
    }

    /// The bytes a seal covers: every field, canonically ordered, no seal.
    ///
    /// A purpose prefix separates this MAC from any other keyed hash a
    /// deployment might compute with the same 32-byte key: without it, a MAC
    /// from another protocol could be presented as a seal.
    pub fn seal_material(&self) -> Vec<u8> {
        let mut material = Vec::with_capacity(64);
        material.extend_from_slice(b"active-rpc/capability-record-seal/v1\0");
        material.extend_from_slice(Json::Object(self.fields()).to_string().as_bytes());
        material
    }

    /// Seal the record with a deployment key.
    pub fn seal_with(&mut self, key: &[u8; 32]) {
        let digest = blake3::keyed_hash(key, &self.seal_material());
        self.seal = Some(digest.to_hex().to_string());
    }

    /// True when the record carries a seal this key produced.
    ///
    /// The comparison is constant-time: an attacker who can submit records must
    /// not learn the seal byte by byte from timing.
    pub fn seal_is_valid(&self, key: &[u8; 32]) -> bool {
        let Some(seal) = self.seal.as_deref() else {
            return false;
        };
        if seal.len() != 64 {
            return false;
        }
        let digest = blake3::keyed_hash(key, &self.seal_material());
        let expected = digest.to_hex();
        let mut difference = 0u8;
        for (left, right) in seal.as_bytes().iter().zip(expected.as_bytes()) {
            difference |= left ^ right;
        }
        difference == 0
    }

    /// Render the record as JSON.
    pub fn to_json(&self) -> String {
        let mut map = self.fields();
        map.insert(
            "seal".into(),
            match &self.seal {
                Some(seal) => seal.clone().into(),
                None => Json::Null,
            },
        );
        Json::Object(map).to_string()
    }

    /// Parse a record, refusing anything malformed or out of range.
    pub fn from_json(text: &str) -> Result<Self> {
        if text.len() > MAX_RECORD_BYTES {
            return Err(Error::persistence("record exceeds its size ceiling"));
        }
        let value: Json =
            serde_json::from_str(text).map_err(|_| Error::persistence("record is not JSON"))?;
        if value.get("format").and_then(Json::as_str) != Some(RECORD_FORMAT) {
            return Err(Error::persistence("unknown record format"));
        }
        // The seal covers the parsed value, so the text must have one meaning:
        // a duplicate key, different whitespace or an unknown field would let two
        // consumers of the same stored text disagree.
        refuse_non_canonical(text, &value)?;
        let Some(object) = value.as_object() else {
            return Err(Error::persistence("record is not an object"));
        };
        for key in object.keys() {
            if !RECORD_KEYS.contains(&key.as_str()) {
                return Err(Error::persistence("record has an unknown field"));
            }
        }
        let provider = value
            .get("provider")
            .and_then(Json::as_str)
            .filter(|name| crate::security::valid_text(name, 128))
            .ok_or_else(|| Error::persistence("provider name is missing or out of range"))?;
        let object = value
            .get("object")
            .and_then(Json::as_u64)
            .ok_or_else(|| Error::persistence("missing object"))?;
        let methods =
            string_set(&value, "methods")?.ok_or_else(|| Error::persistence("missing methods"))?;
        if methods.is_empty() {
            return Err(Error::persistence("a record grants no methods"));
        }
        // The parser validates every text field it accepts: a record with an
        // empty or control-character method used to parse here and then fail in
        // the mint as `rpc/invalid-argument`, so the durable surface reported two
        // classes for one fault.
        for method in &methods {
            if !crate::receipts::valid_method(method) {
                return Err(Error::persistence("a record grants a malformed method"));
            }
        }
        let budget = value
            .get("budget")
            .and_then(Json::as_object)
            .ok_or_else(|| Error::persistence("missing budget"))?;
        // A nested key this format does not define is a text no writer
        // produces: the outer map is checked against `RECORD_KEYS`, and a
        // nested extra used to ride along under a valid seal (round 42, F1).
        refuse_unknown_keys(budget, BUDGET_KEYS, "budget")?;
        let number = |key: &str| -> Result<u64> {
            budget
                .get(key)
                .and_then(Json::as_u64)
                .ok_or_else(|| Error::persistence("a budget field is missing"))
        };
        let budget = Budget {
            max_calls: number("calls")?,
            max_bytes: number("bytes")?,
            max_wall_ms: number("wall_ms")?,
            max_nodes: number("nodes")?,
            max_depth: number("depth")?,
            max_array_len: number("array_len")?,
            max_value_size: number("value_size")?,
        };
        // A budget the parser refuses is a malformed record, not a bad argument:
        // the whole durable surface speaks `rpc/persistence`, and `restore` maps
        // the same check the same way.
        budget
            .check()
            .map_err(|_| Error::persistence("the record's budget is invalid"))?;
        let read_only = value
            .get("read_only")
            .and_then(Json::as_bool)
            .ok_or_else(|| Error::persistence("missing read_only"))?;
        let redact = value
            .get("redact")
            .and_then(Json::as_bool)
            .ok_or_else(|| Error::persistence("missing redact"))?;
        let path_scope = match value.get("path_scope") {
            None | Some(Json::Null) => None,
            Some(Json::String(scope))
                if crate::security::valid_text(scope, crate::kernel::MAX_PATH_SCOPE_BYTES) =>
            {
                Some(scope.clone())
            }
            // The mint refuses a scope that cannot be logged; refusing it here
            // makes the fault `rpc/persistence` before the store is claimed
            // (round 38, F6).
            Some(_) => return Err(Error::persistence("path scope is malformed")),
        };
        let topics = string_set(&value, "topics")?;
        if let Some(topics) = &topics {
            for topic in topics {
                if !crate::kernel::valid_topic(topic) {
                    return Err(Error::persistence("a record names a malformed topic"));
                }
            }
        }
        // A record written before the grant existed carries no field. The
        // default narrows authority (no publishing) rather than widening it, and
        // a record that names topics implies the grant.
        // A present field must have the type the record defines: `"publish":
        // "false"` used to parse as `true` (a non-empty string is not a bool, so
        // the default "topics imply publishing" applied), and a JSON-reading
        // policy tool disagreed with the kernel about the grant (round 41, F4).
        let publish = match value.get("publish") {
            None | Some(Json::Null) => topics.is_some(),
            Some(Json::Bool(flag)) => *flag,
            Some(_) => return Err(Error::persistence("publish is not a boolean")),
        };
        let tool_policy = match value.get("tool_policy") {
            None | Some(Json::Null) => None,
            Some(Json::Object(policy)) => {
                refuse_unknown_keys(policy, TOOL_POLICY_KEYS, "tool policy")?;
                // The same canonical list rule as `methods` and `topics`: a
                // reordered or duplicated allow-list used to parse into the
                // same set, so a sealed text did not have one meaning
                // (round 42, F1).
                let policy_value = Json::Object(policy.clone());
                let names = string_set(&policy_value, "allowed")?
                    .ok_or_else(|| Error::persistence("tool allow-list is missing"))?;
                for name in &names {
                    if !crate::receipts::valid_method(name) {
                        // The mint refuses such a name with `rpc/invalid-argument`
                        // after the store claim is spent; a record is checked
                        // against the same rule here (round 38, F6).
                        return Err(Error::persistence("a record names a malformed tool"));
                    }
                }
                Some(ToolPolicy {
                    allowed: names,
                    max_arg_bytes: policy
                        .get("max_arg_bytes")
                        .and_then(Json::as_u64)
                        .ok_or_else(|| Error::persistence("missing tool argument ceiling"))?,
                    allow_process: policy
                        .get("allow_process")
                        .and_then(Json::as_bool)
                        .ok_or_else(|| Error::persistence("missing allow_process"))?,
                })
            }
            Some(_) => return Err(Error::persistence("tool policy is malformed")),
        };
        let bound_to = match value.get("bound_to") {
            None | Some(Json::Null) => None,
            Some(Json::String(text)) => {
                let fingerprint = parse_hex32(text)?;
                // The all-zero fingerprint is the anonymous constant: a record
                // naming it would restore for a peer that proved nothing.
                if !crate::identity::bindable(fingerprint) {
                    return Err(Error::persistence(
                        "binding names an anonymous or loopback identity",
                    ));
                }
                Some(fingerprint)
            }
            Some(_) => return Err(Error::persistence("binding is malformed")),
        };
        let expires_at = match value.get("expires_at") {
            None | Some(Json::Null) => None,
            Some(number) => Some(
                number
                    .as_u64()
                    .ok_or_else(|| Error::persistence("deadline is malformed"))?,
            ),
        };
        // Same rule as `publish`: the clock mode decides how an absolute
        // deadline is read, so a text that is not a boolean must not silently
        // default it (round 41, F4).
        let wall_clock = match value.get("wall_clock") {
            None | Some(Json::Null) => false,
            Some(Json::Bool(flag)) => *flag,
            Some(_) => return Err(Error::persistence("wall_clock is not a boolean")),
        };
        let lease_ms = match value.get("lease_ms") {
            None | Some(Json::Null) => None,
            Some(number) => Some(
                number
                    .as_u64()
                    .ok_or_else(|| Error::persistence("lease is malformed"))?,
            ),
        };
        // A lease with no deadline would restore with no deadline at all: the
        // restorer takes its TTL from `expires_at`, so the lease would be
        // silently widened to "forever".
        if lease_ms.is_some() && expires_at.is_none() {
            return Err(Error::persistence(
                "a record carries a lease without a deadline",
            ));
        }
        // The mirror shape: restore always refuses a bounded record with no
        // lease (`a bounded record carries no lease`), so the parser must not
        // advertise it (round 39, L-5).
        if expires_at.is_some() && lease_ms.is_none() {
            return Err(Error::persistence("a bounded record carries no lease"));
        }
        let record_id = match value.get("record_id") {
            Some(Json::String(text)) => parse_hex32(text)?,
            _ => return Err(Error::persistence("missing record id")),
        };
        if record_id == [0u8; 32] {
            return Err(Error::persistence("the record id is not a record id"));
        }
        let seal = match value.get("seal") {
            None | Some(Json::Null) => None,
            Some(Json::String(text)) if text.len() == 64 && text.is_ascii() => Some(text.clone()),
            Some(_) => return Err(Error::persistence("the seal is malformed")),
        };
        let record = Self {
            provider: provider.to_string(),
            object,
            methods,
            budget,
            read_only,
            redact,
            path_scope,
            topics,
            publish,
            tool_policy,
            bound_to,
            expires_at,
            wall_clock,
            lease_ms,
            record_id,
            seal,
        };
        // The text must be the one this crate writes, key order included.
        // `refuse_non_canonical` re-renders the *parsed* map, and `serde_json`
        // carries `preserve_order` here, so it echoed the input order: a
        // reordered text parsed and kept a valid seal (round 43, F2).
        if record.to_json() != text {
            return Err(Error::persistence(
                "record text is not the canonical rendering of its value",
            ));
        }
        Ok(record)
    }

    /// The attributes a *restore* mints with.
    ///
    /// Crate-internal on purpose: this converts a parsed record into authority
    /// attributes without looking at the seal, so exposing it would publish a
    /// bridge that skips authentication (a record with `seal: null` would mint).
    /// The audited path is [`crate::Agent::restore_capability`], which verifies
    /// the seal, the tombstone and the binding first; an embedder that needs the
    /// attributes should go through it.
    ///
    /// `ttl_ms` is the remaining lifetime, so the restored capability keeps the
    /// original absolute deadline. Persistence is `Durable`: this is a durable
    /// record by construction.
    pub(crate) fn attrs(&self, ttl_ms: Option<u64>) -> CapAttrs {
        let refs: Vec<&str> = self.methods.iter().map(String::as_str).collect();
        let mut attrs = CapAttrs::new(&refs).with_budget(self.budget);
        attrs.read_only = self.read_only;
        attrs.redact = self.redact;
        attrs.path_scope = self.path_scope.clone();
        attrs.topics = self.topics.clone();
        attrs.publish = self.publish;
        attrs.tool_policy = self.tool_policy.clone();
        attrs.bound_to = self.bound_to;
        attrs.persistence = CapPersistence::Durable;
        attrs.ttl_ms = ttl_ms;
        attrs
    }
}

fn string_set(value: &Json, key: &str) -> Result<Option<BTreeSet<String>>> {
    match value.get(key) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::Array(items)) => {
            let mut set = BTreeSet::new();
            let mut previous: Option<&str> = None;
            for item in items {
                let text = item
                    .as_str()
                    .ok_or_else(|| Error::persistence("a record list holds a non-string"))?;
                // The writer renders a sorted set, and the canonicality check
                // compares the parsed value with the text: an unsorted or
                // duplicated array parsed to the same set and passed, so two
                // texts shared one record and one seal (round 41, F4).
                if let Some(previous) = previous {
                    if text <= previous {
                        return Err(Error::persistence(
                            "a record list is not in canonical order",
                        ));
                    }
                }
                previous = Some(text);
                set.insert(text.to_string());
            }
            Ok(Some(set))
        }
        Some(_) => Err(Error::persistence("a record list is malformed")),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Parse 64 hex characters into 32 bytes.
///
/// ASCII is required before slicing: a 64-byte string of multi-byte characters
/// would otherwise be cut inside a code point and panic. A record that arrives
/// from a store or a peer must never turn a parse fault into a process fault.
fn parse_hex32(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64 || !text.is_ascii() {
        return Err(Error::persistence("fingerprint must be 64 hex characters"));
    }
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| Error::persistence("fingerprint is not hex"))?;
    }
    Ok(out)
}
