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

/// Format tag of a capability record.
pub const RECORD_FORMAT: &str = "active-rpc/capability-record/1";

/// Largest record accepted, in bytes.
///
/// A record is a fixed set of scalar fields and short lists; anything beyond
/// this is hostile input.
pub const MAX_RECORD_BYTES: usize = 64 << 10;

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
    /// Tool policy, when present.
    pub tool_policy: Option<ToolPolicy>,
    /// Peer this capability was bound to, if it was.
    pub bound_to: Option<[u8; 32]>,
    /// Absolute deadline in kernel milliseconds, if bounded.
    pub expires_at: Option<u64>,
}

impl CapabilityRecord {
    /// Render the record as JSON.
    pub fn to_json(&self) -> String {
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
        let provider = value
            .get("provider")
            .and_then(Json::as_str)
            .filter(|name| !name.is_empty() && name.len() <= 128)
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
        let budget = value
            .get("budget")
            .and_then(Json::as_object)
            .ok_or_else(|| Error::persistence("missing budget"))?;
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
        budget.check()?;
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
            Some(Json::String(scope)) if !scope.is_empty() && scope.len() <= 1024 => {
                Some(scope.clone())
            }
            Some(_) => return Err(Error::persistence("path scope is malformed")),
        };
        let topics = string_set(&value, "topics")?;
        let tool_policy = match value.get("tool_policy") {
            None | Some(Json::Null) => None,
            Some(Json::Object(policy)) => {
                let allowed = policy
                    .get("allowed")
                    .and_then(Json::as_array)
                    .ok_or_else(|| Error::persistence("tool allow-list is missing"))?;
                let mut names = BTreeSet::new();
                for item in allowed {
                    let name = item
                        .as_str()
                        .ok_or_else(|| Error::persistence("tool name is not a string"))?;
                    names.insert(name.to_string());
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
            Some(Json::String(text)) => Some(parse_hex32(text)?),
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
        Ok(Self {
            provider: provider.to_string(),
            object,
            methods,
            budget,
            read_only,
            redact,
            path_scope,
            topics,
            tool_policy,
            bound_to,
            expires_at,
        })
    }

    /// The attributes a restore mints with.
    ///
    /// `ttl_ms` is the remaining lifetime, so the restored capability keeps the
    /// original absolute deadline. Persistence is `Durable`: this is a durable
    /// record by construction.
    pub fn attrs(&self, ttl_ms: Option<u64>) -> CapAttrs {
        let refs: Vec<&str> = self.methods.iter().map(String::as_str).collect();
        let mut attrs = CapAttrs::new(&refs).with_budget(self.budget);
        attrs.read_only = self.read_only;
        attrs.redact = self.redact;
        attrs.path_scope = self.path_scope.clone();
        attrs.topics = self.topics.clone();
        attrs.tool_policy = self.tool_policy.clone();
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
            for item in items {
                let text = item
                    .as_str()
                    .ok_or_else(|| Error::persistence("a record list holds a non-string"))?;
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

fn parse_hex32(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64 {
        return Err(Error::persistence("fingerprint must be 64 hex characters"));
    }
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| Error::persistence("fingerprint is not hex"))?;
    }
    Ok(out)
}
