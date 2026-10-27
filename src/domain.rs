//! Domain operations over Active Infinity modules.
//!
//! A [`ModuleProvider`] is the provider behind a *module capability*. Every
//! method maps to a real Active/Infinity operation:
//!
//! | Method | Behaviour |
//! |--------|-----------|
//! | `evaluate` | evaluate the module (or the subgraph at a path) with the Active engine under the capability budget |
//! | `why` | transitive dependencies of a path, as labels |
//! | `impact` | transitive dependents of a path, as labels |
//! | `subgraph` | the dependency cone, encoded as a new canonical module |
//! | `patch` | replace one node's content (refused on a read-only capability) |
//! | `dependents` / `dependencies` | direct edges |
//! | `content_hash` | the Blake3 content address |
//! | `stats` | node/edge/secret counts |
//! | `annotations` / `provenance` | metadata |
//!
//! Redaction: `why`/`impact` collapse the secret cone to one marker when the
//! capability is redacting. Evaluation results never carry secret material in
//! either mode — a secret is [`Value::Secret`].

use std::collections::{BTreeMap, BTreeSet};

use active_infinity::interop::{
    dependencies, dependents, impact, secret_tainted_paths, subgraph, why,
};
use active_infinity::{decode, encode, AnnotationKind, InfinityModule, Inode, NodeId, Provenance};

use crate::cap::CapId;
use crate::error::{Error, Result};
use crate::kernel::Provider;
use crate::security;
use crate::value::Response;
use crate::value::{Arg, Call, Value};

/// Methods a module capability can grant.
pub const METHODS: &[&str] = &[
    "evaluate",
    "why",
    "impact",
    "subgraph",
    "patch",
    "dependents",
    "dependencies",
    "content_hash",
    "stats",
    "annotations",
    "provenance",
];

/// A provider that serves domain operations on Infinity modules.
pub struct ModuleProvider {
    modules: BTreeMap<u64, InfinityModule>,
    next_object: u64,
    /// Drop notifications received (object id, capability).
    pub drops: Vec<(u64, CapId)>,
    /// Calls served, for tests and diagnostics.
    pub calls: u64,
}

impl Default for ModuleProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleProvider {
    pub fn new() -> Self {
        Self {
            modules: BTreeMap::new(),
            next_object: 0,
            drops: Vec::new(),
            calls: 0,
        }
    }

    /// Install a module and return the object id to mint capabilities for.
    pub fn install(&mut self, module: InfinityModule) -> u64 {
        let id = self.next_object;
        self.next_object += 1;
        self.modules.insert(id, module);
        id
    }

    /// Read a module back (tests and local callers).
    pub fn module(&self, object: u64) -> Option<&InfinityModule> {
        self.modules.get(&object)
    }

    /// Number of modules installed (including patch results).
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    fn require(&self, object: u64) -> Result<&InfinityModule> {
        self.modules
            .get(&object)
            .ok_or(Error::InvalidArgument("unknown module"))
    }

    fn path_arg(call: &Call) -> Option<String> {
        call.args.iter().find_map(|arg| match arg {
            Arg::Value(Value::Path(path)) => Some(path.clone()),
            _ => None,
        })
    }

    fn resolve(&self, module: &InfinityModule, call: &Call) -> Result<(String, NodeId)> {
        let path =
            Self::path_arg(call).ok_or(Error::InvalidArgument("a path argument is required"))?;
        let node = active_infinity::interop::resolve_path(module, &path)
            .ok_or(Error::InvalidArgument("path does not resolve"))?;
        Ok((path, node))
    }
}

impl Provider for ModuleProvider {
    fn name(&self) -> &'static str {
        "module"
    }

    fn methods(&self) -> Vec<String> {
        METHODS.iter().map(|method| method.to_string()).collect()
    }

    fn mutating(&self, method: &str) -> bool {
        method == "patch"
    }

    fn invoke(&mut self, object: u64, call: &Call) -> Result<Response> {
        self.calls += 1;
        let module = self.require(object)?.clone();
        let response = match call.method.as_str() {
            "evaluate" => {
                let module = match Self::path_arg(call) {
                    Some(path) => {
                        let node = active_infinity::interop::resolve_path(&module, &path)
                            .ok_or(Error::InvalidArgument("path does not resolve"))?;
                        restrict(&module, node)?
                    }
                    None => module,
                };
                let budget = call.budget.to_active_budget();
                let (value, _diagnostics) = active_infinity::interop::evaluate(&module, budget)
                    .map_err(|error| match &error {
                        active_infinity::Error::Evaluation(code) => Error::Domain(code),
                        other => Error::Payload(other.code().to_string()),
                    })?;
                Response::Value(security::from_active_value(&value))
            }
            "why" => {
                let (_path, node) = self.resolve(&module, call)?;
                let labels = why(&module, node);
                Response::Labels(apply_redaction(&module, labels, call.redact))
            }
            "impact" => {
                let (_path, node) = self.resolve(&module, call)?;
                let labels = impact(&module, node);
                Response::Labels(apply_redaction(&module, labels, call.redact))
            }
            "subgraph" => {
                let (_path, node) = self.resolve(&module, call)?;
                let sub = restrict(&module, node)?;
                let bytes =
                    encode(&sub).map_err(|error| Error::Payload(error.code().to_string()))?;
                Response::Module(bytes)
            }
            "patch" => {
                let (_path, node) = self.resolve(&module, call)?;
                if call.read_only {
                    return Err(Error::ReadOnly);
                }
                let replacement = call
                    .args
                    .iter()
                    .find_map(|arg| match arg {
                        // The first argument names the target path; the
                        // replacement is the next literal.
                        Arg::Value(Value::Path(_)) => None,
                        Arg::Value(value) => literal_node(value),
                        _ => None,
                    })
                    .ok_or(Error::InvalidArgument("patch needs a literal value"))?;
                let mut patched = module.clone();
                *patched.node_mut(node)? = replacement;
                patched.set_provenance(Some(Provenance {
                    producer: Some("active-rpc/patch".to_string()),
                    timestamp_ms: 0,
                    model: None,
                    tool: Some("patch".to_string()),
                    parent: None,
                    entries: Vec::new(),
                }));
                let bytes =
                    encode(&patched).map_err(|error| Error::Payload(error.code().to_string()))?;
                // A patch advances the object in place: every holder of a
                // capability for it observes the new version, which is what
                // "patch returns the new module capability" means without a
                // provider-side mint hook. Mint a fresh capability when
                // isolation is required.
                self.modules.insert(object, patched);
                Response::Module(bytes)
            }
            "dependents" => {
                let (_path, node) = self.resolve(&module, call)?;
                let labels: Vec<String> = dependents(&module, node)
                    .into_iter()
                    .map(|id| active_infinity::interop::node_label(&module, id))
                    .collect();
                Response::Labels(apply_redaction(&module, labels, call.redact))
            }
            "dependencies" => {
                let (_path, node) = self.resolve(&module, call)?;
                let labels: Vec<String> = dependencies(&module, node)
                    .into_iter()
                    .map(|id| active_infinity::interop::node_label(&module, id))
                    .collect();
                Response::Labels(apply_redaction(&module, labels, call.redact))
            }
            "content_hash" => {
                let bytes =
                    encode(&module).map_err(|error| Error::Payload(error.code().to_string()))?;
                let hash = active_infinity::content_hash(&bytes)
                    .map_err(|error| Error::Payload(error.code().to_string()))?;
                Response::Value(Value::Text(format!(
                    "blake3:{}",
                    active_infinity::ir::hash_hex(&hash)
                )))
            }
            "stats" => {
                let mut map = BTreeMap::new();
                map.insert("nodes".to_string(), Value::Int(module.node_count() as i64));
                map.insert("edges".to_string(), Value::Int(module.edges().len() as i64));
                map.insert(
                    "secrets".to_string(),
                    Value::Int(
                        module
                            .nodes()
                            .iter()
                            .filter(|node| node.is_secret())
                            .count() as i64,
                    ),
                );
                map.insert(
                    "has_provenance".to_string(),
                    Value::Bool(module.provenance().is_some()),
                );
                Response::Value(Value::Map(map))
            }
            "annotations" => {
                let mut out = Vec::new();
                for annotation in module.annotations() {
                    let (kind, text) = match &annotation.kind {
                        AnnotationKind::Intent(text) => ("intent", text.clone()),
                        AnnotationKind::Constraint { source, .. } => ("constraint", source.clone()),
                        AnnotationKind::AiImmutable(flag) => ("ai_immutable", flag.to_string()),
                    };
                    let text = if call.redact && text.contains("***") {
                        Value::Secret
                    } else {
                        Value::Text(text)
                    };
                    out.push(Value::Map(
                        [
                            ("node".to_string(), Value::Int(annotation.node.0 as i64)),
                            ("kind".to_string(), Value::Text(kind.to_string())),
                            ("text".to_string(), text),
                        ]
                        .into_iter()
                        .collect(),
                    ));
                }
                Response::Value(Value::List(out))
            }
            "provenance" => match module.provenance() {
                None => Response::Value(Value::Null),
                Some(prov) => {
                    let mut map = BTreeMap::new();
                    if let Some(producer) = &prov.producer {
                        map.insert("producer".to_string(), Value::Text(producer.clone()));
                    }
                    if let Some(model) = &prov.model {
                        map.insert("model".to_string(), Value::Text(model.clone()));
                    }
                    if let Some(tool) = &prov.tool {
                        map.insert("tool".to_string(), Value::Text(tool.clone()));
                    }
                    map.insert(
                        "timestamp_ms".to_string(),
                        Value::Int(prov.timestamp_ms as i64),
                    );
                    Response::Value(Value::Map(map))
                }
            },
            other => {
                return Err(Error::MethodNotGranted {
                    method: other.to_string(),
                })
            }
        };
        Ok(response)
    }

    fn on_drop(&mut self, object: u64, cap: CapId) {
        self.drops.push((object, cap));
    }

    fn take_drop_notifications(&mut self) -> Vec<(u64, CapId)> {
        std::mem::take(&mut self.drops)
    }
}

fn apply_redaction(module: &InfinityModule, labels: Vec<String>, redact: bool) -> Vec<String> {
    if !redact {
        return labels;
    }
    let tainted = tainted_labels(module);
    security::redact_cone_labels(labels, &tainted)
}

/// Labels of every node that is a secret or contains one, transitively.
///
/// `secret_tainted_paths` only names nodes that have a value path; a secret
/// literal nested under a reference has none, so the cone is computed over node
/// ids and then mapped to labels.
fn tainted_labels(module: &InfinityModule) -> BTreeSet<String> {
    let count = module.node_count();
    if count == 0 {
        return BTreeSet::new();
    }
    let mut tainted = vec![false; count];
    // A secret kind and everything it references (the locator expression) is
    // secret material.
    let mut stack: Vec<usize> = Vec::new();
    for (index, node) in module.nodes().iter().enumerate() {
        if node.is_secret() {
            tainted[index] = true;
            stack.push(index);
        }
    }
    while let Some(index) = stack.pop() {
        if let Some(node) = module.nodes().get(index) {
            for child in node.children() {
                if !tainted[child.index()] {
                    tainted[child.index()] = true;
                    stack.push(child.index());
                }
            }
        }
    }
    let mut changed = true;
    while changed {
        changed = false;
        for (index, node) in module.nodes().iter().enumerate() {
            if tainted[index] {
                continue;
            }
            if node
                .children()
                .iter()
                .any(|child| tainted.get(child.index()).copied().unwrap_or(false))
            {
                tainted[index] = true;
                changed = true;
            }
        }
    }
    let mut labels = BTreeSet::new();
    for (index, is_tainted) in tainted.iter().enumerate() {
        if *is_tainted {
            labels.insert(active_infinity::interop::node_label(
                module,
                NodeId(index as u32),
            ));
        }
    }
    // Keep the path-based answer too: it covers nodes with value paths whose
    // label differs from the id-derived one.
    labels.extend(secret_tainted_paths(module));
    labels
}

/// Extract the subgraph rooted at `node` as a standalone module.
///
/// The cone is closed under dependencies by construction, so every child
/// reference stays inside the new arena.
fn restrict(module: &InfinityModule, node: NodeId) -> Result<InfinityModule> {
    let cone = subgraph(module, &[node]);
    let mut sub = InfinityModule::new();
    let mut map = BTreeMap::new();
    for id in &cone {
        let cloned = module
            .get(*id)
            .cloned()
            .ok_or(Error::InvalidArgument("subgraph node disappeared"))?;
        map.insert(*id, sub.push(cloned));
    }
    for (old, new) in &map {
        if let Some(node) = module.get(*old).cloned() {
            let rewritten = remap_children(&node, &map)?;
            *sub.node_mut(*new)? = rewritten;
        }
    }
    sub.set_root(map.get(&node).copied());
    Ok(sub)
}

/// Rewrite a node's child references through `map`.
fn remap_children(node: &Inode, map: &BTreeMap<NodeId, NodeId>) -> Result<Inode> {
    let resolve = |id: NodeId| -> Result<NodeId> {
        map.get(&id)
            .copied()
            .ok_or(Error::InvalidArgument("subgraph is not closed"))
    };
    let rewritten = match node {
        Inode::Array { elements } => Inode::Array {
            elements: elements
                .iter()
                .map(|id| resolve(*id))
                .collect::<Result<_>>()?,
        },
        Inode::Table { fields } => Inode::Table {
            fields: fields
                .iter()
                .map(|(name, id)| Ok((name.clone(), resolve(*id)?)))
                .collect::<Result<_>>()?,
        },
        Inode::Quantity { value, unit } => Inode::Quantity {
            value: resolve(*value)?,
            unit: unit.clone(),
        },
        Inode::Ref(id) => Inode::Ref(resolve(*id)?),
        Inode::SecretRef { locator } => Inode::SecretRef {
            locator: resolve(*locator)?,
        },
        other => other.clone(),
    };
    Ok(rewritten)
}

fn literal_node(value: &Value) -> Option<Inode> {
    match value {
        Value::Null => Some(Inode::Null),
        Value::Bool(flag) => Some(Inode::Bool(*flag)),
        Value::Int(number) => Some(Inode::Int(*number)),
        Value::Float(number) => Some(Inode::Float(*number)),
        Value::Text(text) => Some(Inode::Str(text.clone())),
        Value::Path(path) => Some(Inode::Str(path.clone())),
        // Composite values need a full node tree; `patch` accepts literals and
        // callers that need structure send a module instead.
        Value::List(_) | Value::Map(_) | Value::Secret | Value::Module(_) => None,
    }
}

/// Decode a module returned by `subgraph`/`patch`.
pub fn decode_module(bytes: &[u8]) -> Result<InfinityModule> {
    decode(bytes).map_err(|error| Error::Payload(error.code().to_string()))
}

/// Build a module from a text document (test and example helper).
pub fn module_from_source(source: &str, name: &str) -> Result<InfinityModule> {
    active_infinity::interop::from_active_source(source, name)
        .map_err(|error| Error::Payload(error.code().to_string()))
}

/// Resolve a dotted path in a module (test and example helper).
pub fn resolve_path(module: &InfinityModule, path: &str) -> Option<NodeId> {
    active_infinity::interop::resolve_path(module, path)
}

/// Node ids in a module's dependency cone, for tests.
pub fn cone_ids(module: &InfinityModule, path: &str) -> Result<Vec<NodeId>> {
    let node = active_infinity::interop::resolve_path(module, path)
        .ok_or(Error::InvalidArgument("path does not resolve"))?;
    Ok(subgraph(module, &[node]))
}
