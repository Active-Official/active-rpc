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

use active_infinity::interop::subgraph;
use active_infinity::{
    decode, encode, AnnotationKind, InfinityModule, Inode, InterpPart, NodeId, PatchOp, Provenance,
    SchemaFieldSpec,
};

use crate::cap::CapId;
use crate::error::{Error, Result};
use crate::kernel::Provider;
use crate::security;
use crate::value::Response;
use crate::value::{Arg, Call, Value};

/// Largest drop log the provider keeps for diagnostics.
pub const MAX_DROP_LOG: usize = 4_096;

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

/// A stored module plus its cached canonical hash.
///
/// The hash is what `content_hash` returns. Caching it removes a full encode
/// per call for a monitoring loop, and installing canonical bytes can seed it
/// without encoding at all. Any replacement (a patch) clears it.
struct ModuleSlot {
    module: InfinityModule,
    hash: Option<[u8; 32]>,
}

/// A provider that serves domain operations on Infinity modules.
pub struct ModuleProvider {
    modules: BTreeMap<u64, ModuleSlot>,
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
    /// Create an empty provider with no modules installed.
    pub fn new() -> Self {
        Self {
            modules: BTreeMap::new(),
            next_object: 0,
            drops: Vec::new(),
            calls: 0,
        }
    }

    /// Install a module and return the object id to mint capabilities for.
    ///
    /// The canonical hash is computed lazily on the first `content_hash` call.
    /// The module is validated as canonical first: a hand-built arena can carry
    /// a dangling reference, a secret copy in provenance text, or a node graph
    /// that no encoder would produce, and every query below assumes the codec's
    /// invariants hold.
    pub fn install(&mut self, module: InfinityModule) -> Result<u64> {
        let bytes = encode(&module).map_err(|error| Error::Payload(error.code().to_string()))?;
        active_infinity::validate_canonical(&bytes, active_infinity::Limits::default())
            .map_err(|error| Error::Payload(error.code().to_string()))?;
        let hash = active_infinity::content_hash(&bytes)
            .map_err(|error| Error::Payload(error.code().to_string()))?;
        Ok(self.install_slot(ModuleSlot {
            module,
            hash: Some(hash),
        }))
    }

    /// Install a module from a canonical image and seed its cached hash.
    ///
    /// The bytes are validated as canonical first, so the cached hash is the
    /// hash of exactly those bytes and no re-encode is needed until the module
    /// is patched. This is the path a transport or a store should use: the
    /// payload it already has is the canonical form.
    pub fn install_canonical_image(&mut self, bytes: &[u8]) -> Result<u64> {
        active_infinity::validate_canonical(bytes, active_infinity::Limits::default())
            .map_err(|error| Error::Payload(error.code().to_string()))?;
        let module = active_infinity::decode(bytes)
            .map_err(|error| Error::Payload(error.code().to_string()))?;
        let hash = active_infinity::content_hash(bytes)
            .map_err(|error| Error::Payload(error.code().to_string()))?;
        Ok(self.install_slot(ModuleSlot {
            module,
            hash: Some(hash),
        }))
    }

    fn install_slot(&mut self, slot: ModuleSlot) -> u64 {
        let id = self.next_object;
        self.next_object += 1;
        self.modules.insert(id, slot);
        id
    }

    /// Read a module back (tests and local callers).
    pub fn module(&self, object: u64) -> Option<&InfinityModule> {
        self.modules.get(&object).map(|slot| &slot.module)
    }

    /// The cached canonical hash of a module, when it has been computed.
    ///
    /// `None` means "not computed yet"; it does not mean the module has no
    /// hash. `content_hash` fills it.
    pub fn cached_hash(&self, object: u64) -> Option<[u8; 32]> {
        self.modules.get(&object).and_then(|slot| slot.hash)
    }

    /// Number of modules installed (including patch results).
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Remove a module for the duration of one call and put it back afterwards.
    ///
    /// Taking the slot by value avoids a full deep clone for every read-only
    /// method (`stats`, `why`, `subgraph`, …). The module is re-inserted on
    /// every path, including errors, so a failed call never drops the object.
    fn take(&mut self, object: u64) -> Result<ModuleSlot> {
        self.modules
            .remove(&object)
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

    /// Serve one call against a slot that has been taken out of the map.
    ///
    /// Read-only methods borrow the module, so a call copies nothing; the two
    /// methods that change or hash the canonical bytes handle the slot
    /// themselves. `content_hash` reuses the cached hash, and `patch` clones
    /// only on the mutating path.
    fn serve(&self, slot: &mut ModuleSlot, call: &Call) -> Result<Response> {
        // A scoped capability is confined to its subtree. A pathless form would
        // return (or rewrite) the whole module, and a path outside the scope is
        // not this capability's data: both are refused here, because the kernel
        // can only check the arguments it can see and these methods address the
        // module by name.
        if let Some(scope) = &call.path_scope {
            match Self::path_arg(call) {
                Some(path) if crate::cap::is_path_prefix(scope, &path) => {}
                Some(path) => return Err(Error::PathNotGranted(path)),
                None => return Err(Error::PathNotGranted(scope.clone())),
            }
        }
        // The metadata queries do no evaluator work, so the wall ceiling has
        // to be measured here.
        let started = std::time::Instant::now();
        match call.method.as_str() {
            "evaluate" => {
                let budget = call.budget.to_active_budget();
                let (value, _diagnostics) = match Self::path_arg(call) {
                    Some(path) => {
                        let node = active_infinity::interop::resolve_path(&slot.module, &path)
                            .ok_or(Error::InvalidArgument("path does not resolve"))?;
                        let sub = restrict(&slot.module, node)?;
                        active_infinity::interop::evaluate(&sub, budget)
                    }
                    // No path means the module root: evaluate in place rather
                    // than cloning the whole arena.
                    None => active_infinity::interop::evaluate(&slot.module, budget),
                }
                .map_err(|error| match &error {
                    active_infinity::Error::Evaluation(code) => Error::Domain(code),
                    other => Error::Payload(other.code().to_string()),
                })?;
                Ok(Response::Value(security::from_active_value(&value)))
            }
            "why" => {
                check_node_budget(&slot.module, call)?;
                let (_path, node) = self.resolve(&slot.module, call)?;
                let labels = labels_for(&slot.module, transitive(&slot.module, node, true));
                check_wall_budget(started, call)?;
                Ok(Response::Labels(redact_answer(
                    &slot.module,
                    node,
                    labels,
                    call.redact,
                )))
            }
            "impact" => {
                check_node_budget(&slot.module, call)?;
                let (_path, node) = self.resolve(&slot.module, call)?;
                let labels = labels_for(&slot.module, transitive(&slot.module, node, false));
                check_wall_budget(started, call)?;
                Ok(Response::Labels(redact_answer(
                    &slot.module,
                    node,
                    labels,
                    call.redact,
                )))
            }
            "subgraph" => {
                let (_path, node) = self.resolve(&slot.module, call)?;
                let sub = restrict(&slot.module, node)?;
                Ok(Response::Module(redacted_module_bytes(&sub)?))
            }
            "patch" => {
                if call.read_only {
                    return Err(Error::ReadOnly);
                }
                check_node_budget(&slot.module, call)?;
                // The parent hash is the pre-patch content address: it is what
                // the new provenance records as its parent, so the lineage of an
                // audited module survives a write.
                let parent_hash = match slot.hash {
                    Some(hash) => Some(hash),
                    None => {
                        let bytes =
                            encode(&slot.module).map_err(|_| Error::Domain("active/lower"))?;
                        Some(
                            active_infinity::content_hash(&bytes)
                                .map_err(|_| Error::Domain("active/lower"))?,
                        )
                    }
                };
                let (patched, bytes) = {
                    let module = &slot.module;
                    let (path, node) = self.resolve(module, call)?;
                    if immutable_target(module, &path) {
                        // `@ai_immutable: true` is the format's marker for a
                        // node no agent may rewrite.
                        return Err(Error::ReadOnly);
                    }
                    if let Some(scope) = &call.path_scope {
                        if !effects_within_scope(module, node, scope) {
                            // The write would change a value the scope does not
                            // name: a shared DAG is not confinement.
                            return Err(Error::PathNotGranted(path.clone()));
                        }
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
                    // The producer chain survives: the new module records the
                    // old content address as its parent and keeps the entries
                    // (and the identities) the module already carried.
                    let previous = patched.provenance().cloned();
                    patched.set_provenance(Some(Provenance {
                        producer: previous
                            .as_ref()
                            .and_then(|prov| prov.producer.clone())
                            .or_else(|| Some("active-rpc/patch".to_string())),
                        timestamp_ms: previous.as_ref().map_or(0, |prov| prov.timestamp_ms),
                        model: previous.as_ref().and_then(|prov| prov.model.clone()),
                        tool: Some("patch".to_string()),
                        parent: parent_hash,
                        entries: previous.map(|prov| prov.entries).unwrap_or_default(),
                    }));
                    // The reply is the cone at the target, not the whole arena:
                    // a scoped writer must not receive the rest of the module
                    // back, and the bytes stay bounded by the write.
                    let cone = restrict(&patched, node)?;
                    let bytes = redacted_module_bytes(&cone)?;
                    (patched, bytes)
                };
                // A patch advances the object in place: every holder of a
                // capability for it observes the new version, which is what
                // "patch returns the new module capability" means without a
                // provider-side mint hook. Mint a fresh capability when
                // isolation is required. The cached hash no longer describes
                // the module, so it is cleared.
                slot.module = patched;
                slot.hash = None;
                Ok(Response::Module(bytes))
            }
            "dependents" => {
                check_node_budget(&slot.module, call)?;
                let (_path, node) = self.resolve(&slot.module, call)?;
                let (_, dependents) = adjacency(&slot.module);
                let ids = dependents.get(node.index()).cloned().unwrap_or_default();
                let labels = labels_for(&slot.module, ids);
                check_wall_budget(started, call)?;
                Ok(Response::Labels(redact_answer(
                    &slot.module,
                    node,
                    labels,
                    call.redact,
                )))
            }
            "dependencies" => {
                check_node_budget(&slot.module, call)?;
                let (_path, node) = self.resolve(&slot.module, call)?;
                let (dependencies, _) = adjacency(&slot.module);
                let ids = dependencies.get(node.index()).cloned().unwrap_or_default();
                let labels = labels_for(&slot.module, ids);
                check_wall_budget(started, call)?;
                Ok(Response::Labels(redact_answer(
                    &slot.module,
                    node,
                    labels,
                    call.redact,
                )))
            }
            "content_hash" => {
                let hash = match slot.hash {
                    Some(hash) => hash,
                    None => {
                        let bytes = encode(&slot.module)
                            .map_err(|error| Error::Payload(error.code().to_string()))?;
                        let hash = active_infinity::content_hash(&bytes)
                            .map_err(|error| Error::Payload(error.code().to_string()))?;
                        slot.hash = Some(hash);
                        hash
                    }
                };
                Ok(Response::Value(Value::Text(format!(
                    "blake3:{}",
                    hex32(&hash)
                ))))
            }
            "stats" => {
                check_node_budget(&slot.module, call)?;
                let module = &slot.module;
                let mut map = BTreeMap::new();
                map.insert("nodes".to_string(), Value::Int(module.node_count() as i64));
                map.insert("edges".to_string(), Value::Int(module.edges().len() as i64));
                // `security.md` promises a redacting capability learns that a
                // cone is tainted, never how many secrets it holds.
                if !call.redact {
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
                }
                map.insert(
                    "has_provenance".to_string(),
                    Value::Bool(module.provenance().is_some()),
                );
                Ok(Response::Value(Value::Map(map)))
            }
            "annotations" => {
                check_node_budget(&slot.module, call)?;
                let module = &slot.module;
                // The taint walk is only needed when the capability redacts.
                let tainted_ids = if call.redact {
                    tainted_nodes(module)
                } else {
                    BTreeSet::new()
                };
                let mut out = Vec::new();
                for annotation in module.annotations() {
                    let (kind, text) = match &annotation.kind {
                        AnnotationKind::Intent(text) => ("intent", text.clone()),
                        AnnotationKind::Constraint { source, .. } => ("constraint", source.clone()),
                        AnnotationKind::AiImmutable(flag) => ("ai_immutable", flag.to_string()),
                    };
                    // A redacting capability hides anything attached to the
                    // secret cone; a non-redacting one still only sees text that
                    // canonicalization already redacted.
                    let hidden = (call.redact && tainted_ids.contains(&annotation.node))
                        || text.contains(security::SECRET_MARKER);
                    let text = if hidden {
                        Value::Secret
                    } else {
                        Value::Text(text)
                    };
                    let mut entry: BTreeMap<String, Value> = BTreeMap::new();
                    // A hidden annotation does not name its node: the id would
                    // be a map of where the secret cone is.
                    if !hidden {
                        entry.insert("node".to_string(), Value::Int(annotation.node.0 as i64));
                    }
                    entry.insert("kind".to_string(), Value::Text(kind.to_string()));
                    entry.insert("text".to_string(), text);
                    out.push(Value::Map(entry));
                }
                Ok(Response::Value(Value::List(out)))
            }
            "provenance" => {
                check_node_budget(&slot.module, call)?;
                Ok(match slot.module.provenance() {
                    None => Response::Value(Value::Null),
                    Some(prov) => {
                        // Text fields come from `provenance_lines`, which owns
                        // the redaction: a copy of a secret literal in a producer
                        // string is replaced by the marker instead of leaving as
                        // ordinary text.
                        let mut map = provenance_map(&slot.module);
                        let timestamp = i64::try_from(prov.timestamp_ms).unwrap_or(i64::MAX);
                        map.insert("timestamp_ms".to_string(), Value::Int(timestamp));
                        Response::Value(Value::Map(map))
                    }
                })
            }
            other => Err(Error::MethodNotGranted {
                method: other.to_string(),
            }),
        }
    }
}

impl Provider for ModuleProvider {
    fn name(&self) -> &'static str {
        "module"
    }

    fn methods(&self) -> Vec<String> {
        METHODS.iter().map(|method| method.to_string()).collect()
    }

    /// Answer the membership question without building the method table: the
    /// default clones every name on every admitted call.
    fn has_method(&self, method: &str) -> bool {
        METHODS.contains(&method)
    }

    fn mutating(&self, method: &str) -> bool {
        method == "patch"
    }

    fn invoke(&mut self, object: u64, call: &Call) -> Result<Response> {
        let mut slot = self.take(object)?;
        // A refused call is not a served call.
        self.calls = self.calls.saturating_add(1);
        // Re-insert on every path, including a panic: the slot was taken out of
        // the map, so an unwind that skipped this line would destroy the module.
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.serve(&mut slot, call)));
        self.modules.insert(object, slot);
        match outcome {
            Ok(result) => result,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    fn on_drop(&mut self, object: u64, cap: CapId) {
        // A diagnostic log, drained by `Agent::take_drops`; bound it so a long
        // mint/drop loop cannot grow memory without a caller asking for it.
        if self.drops.len() < MAX_DROP_LOG {
            self.drops.push((object, cap));
        }
    }

    fn take_drop_notifications(&mut self) -> Vec<(u64, CapId)> {
        std::mem::take(&mut self.drops)
    }
}

/// Refuse a metadata query whose walk would exceed the capability's node
/// ceiling.
///
/// These methods do no evaluator work, so nothing else bounds them: without
/// this check a `why` on a large installed module burns unbounded CPU for one
/// charged call.
fn check_node_budget(module: &InfinityModule, call: &Call) -> Result<()> {
    if module.node_count() as u64 > call.budget.max_nodes {
        return Err(Error::BudgetExceeded("nodes"));
    }
    Ok(())
}

/// Refuse a metadata query that has run past the capability's wall ceiling.
fn check_wall_budget(started: std::time::Instant, call: &Call) -> Result<()> {
    let limit = std::time::Duration::from_millis(call.budget.max_wall_ms.max(1));
    if started.elapsed() > limit {
        return Err(Error::BudgetExceeded("wall"));
    }
    Ok(())
}

/// Direct dependency and dependent adjacency, built in one pass over the edges.
///
/// The interop helpers rebuild this per call, which makes a walk over `n` nodes
/// quadratic; a metadata query gets it once and then walks it.
fn adjacency(module: &InfinityModule) -> (Vec<Vec<NodeId>>, Vec<Vec<NodeId>>) {
    let count = module.node_count();
    let mut dependencies = vec![Vec::new(); count];
    let mut dependents = vec![Vec::new(); count];
    // `edges()` yields (dependency, dependent): a child comes before the node
    // that holds it.
    for (dependency, dependent) in module.edges() {
        if dependency.index() < count && dependent.index() < count {
            dependencies[dependent.index()].push(dependency);
            dependents[dependency.index()].push(dependent);
        }
    }
    (dependencies, dependents)
}

/// Transitive closure from `node` over one direction of the graph.
///
/// The node itself is never part of the answer: `why` is what a node is built
/// from and `impact` is what is built from it.
fn transitive(module: &InfinityModule, node: NodeId, walk_dependencies: bool) -> BTreeSet<NodeId> {
    let (dependencies, dependents) = adjacency(module);
    let graph = if walk_dependencies {
        dependencies
    } else {
        dependents
    };
    let mut seen = BTreeSet::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if let Some(next) = graph.get(current.index()) {
            for id in next {
                if seen.insert(*id) {
                    stack.push(*id);
                }
            }
        }
    }
    seen.remove(&node);
    seen
}

/// Labels for a set of node ids, from one `value_paths` pass.
///
/// `node_label` rebuilds the whole path map per node, which is what made these
/// queries quadratic; one map turns the whole answer into a lookup.
fn labels_for(module: &InfinityModule, ids: impl IntoIterator<Item = NodeId>) -> Vec<String> {
    let paths = active_infinity::interop::value_paths(module);
    let mut labels: Vec<String> = ids
        .into_iter()
        .map(|id| match paths.get(&id) {
            Some(path) => path.clone(),
            None => match module.get(id) {
                Some(node) => format!("{}[{}]", node.kind().name(), id.0),
                None => format!("node[{}]", id.0),
            },
        })
        .collect();
    labels.sort();
    labels.dedup();
    labels
}

/// The provenance map, with every text field redacted exactly as the library
/// redacts it.
///
/// The secret literals of a module are not readable from this crate by design,
/// so the redaction has to go through `provenance_lines`, which owns that
/// access. A text field that contains a copy of a secret comes back as the
/// marker instead of the raw string.
fn provenance_map(module: &InfinityModule) -> BTreeMap<String, Value> {
    let mut map = BTreeMap::new();
    for line in active_infinity::interop::provenance_lines(module) {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let rendered = if value == security::SECRET_MARKER {
            Value::Secret
        } else {
            Value::Text(value.to_string())
        };
        map.insert(key.to_string(), rendered);
    }
    map
}

/// True when `path` or one of its ancestors carries `@ai_immutable: true`.
///
/// The format marks a node as agent-immutable; the only write path in the
/// provider has to honour it, including when the marker sits on a table above
/// the named node.
fn immutable_target(module: &InfinityModule, path: &str) -> bool {
    let immutable: BTreeSet<NodeId> = active_infinity::interop::immutable_nodes(module)
        .into_iter()
        .collect();
    if immutable.is_empty() {
        return false;
    }
    let mut prefix = String::new();
    for segment in path.split('.') {
        if !prefix.is_empty() {
            prefix.push('.');
        }
        prefix.push_str(segment);
        if let Some(id) = active_infinity::interop::resolve_path(module, &prefix) {
            if immutable.contains(&id) {
                return true;
            }
        }
    }
    false
}

/// True when every named value that depends on `node` is inside `scope`.
///
/// A module is a shared DAG: constraining the *target* node is not confinement
/// if the write changes a value another path can read. A dependent with no
/// value path of its own is a structural node, not a value the scope names.
fn effects_within_scope(module: &InfinityModule, node: NodeId, scope: &str) -> bool {
    let dependents = transitive(module, node, false);
    if dependents.is_empty() {
        return true;
    }
    let paths = active_infinity::interop::value_paths(module);
    dependents.iter().all(|id| match paths.get(id) {
        Some(path) => crate::cap::is_path_prefix(scope, path),
        None => true,
    })
}

/// Answer a metadata query under a redacting capability.
///
/// A query about a node inside the secret cone learns one marker, not which
/// dependencies it has; a query outside it is redacted only when one of its
/// answers is inside the cone.
fn redact_answer(
    module: &InfinityModule,
    node: NodeId,
    labels: Vec<String>,
    redact: bool,
) -> Vec<String> {
    if !redact {
        return labels;
    }
    let tainted = tainted_nodes(module);
    if tainted.contains(&node) {
        return vec![security::SECRET_MARKER.to_string()];
    }
    security::redact_cone_labels(labels, &tainted_labels(module))
}

/// Labels of every node that is a secret or contains one, transitively.
///
/// `secret_tainted_paths` only names nodes that have a value path; a secret
/// literal nested under a reference has none, so the cone is computed over node
/// ids and then mapped to labels.
fn tainted_labels(module: &InfinityModule) -> BTreeSet<String> {
    // One taint pass over ids (linear), then one path map for the labels. The
    // earlier shape indexed a byte vector with a node id (a panic on a
    // hand-built locator) and rebuilt the path map per tainted node, and it
    // called the library's path-based taint walk as well, which repeats the
    // same fixpoint.
    labels_for(module, tainted_nodes(module))
        .into_iter()
        .collect()
}

/// Encode a module for an RPC payload with every secret replaced by the marker.
///
/// The RPC wire has no tag that carries secret bytes (`docs/spec/wire.md` §2.2),
/// so a module returned by `subgraph` or `patch` is a redacted projection: the
/// structure survives, the material does not. A caller that needs the raw module
/// moves it through a transport payload, not through a capability result.
fn redacted_module_bytes(module: &InfinityModule) -> Result<Vec<u8>> {
    // One implementation, shared with the security helpers: a second copy of
    // the redactor would drift, and the one that drifted would be the leak.
    let bytes = encode(module).map_err(|error| Error::Payload(error.code().to_string()))?;
    security::redact_module(&bytes)
}

/// Node ids that are secrets or contain one, transitively.
fn tainted_nodes(module: &InfinityModule) -> BTreeSet<NodeId> {
    let count = module.node_count();
    let (_, dependents) = adjacency(module);
    // Kahn order: a node is processed only after every child, so one pass
    // propagates the whole cone. The earlier fixpoint rescanned the arena once
    // per level, which is quadratic on a deep chain.
    let mut remaining: Vec<usize> = (0..count)
        .map(|index| {
            module
                .nodes()
                .get(index)
                .map(|node| node.children().len())
                .unwrap_or(0)
        })
        .collect();
    let mut tainted = vec![false; count];
    let mut queue: std::collections::VecDeque<usize> =
        (0..count).filter(|index| remaining[*index] == 0).collect();
    for (index, node) in module.nodes().iter().enumerate() {
        if node.is_secret() {
            tainted[index] = true;
        }
    }
    while let Some(index) = queue.pop_front() {
        for dependent in dependents.get(index).into_iter().flatten() {
            let target = dependent.index();
            if target >= count {
                continue;
            }
            if tainted[index] {
                tainted[target] = true;
            }
            if let Some(left) = remaining.get_mut(target) {
                *left = left.saturating_sub(1);
                if *left == 0 {
                    queue.push_back(target);
                }
            }
        }
    }
    tainted
        .iter()
        .enumerate()
        .filter(|(_, is_tainted)| **is_tainted)
        .map(|(index, _)| NodeId(index as u32))
        .collect()
}

/// Extract the subgraph rooted at `node` as a standalone module.
///
/// The cone is closed under dependencies by construction, so every child
/// reference stays inside the new arena.
fn restrict(module: &InfinityModule, node: NodeId) -> Result<InfinityModule> {
    // A constraint is part of the rule, not decoration: its expression node
    // travels with the annotated node, or a projected module would state a
    // constraint whose expression is missing. The roots grow until no
    // in-cone constraint points outside the cone.
    let mut roots = vec![node];
    let cone = loop {
        let cone: BTreeSet<NodeId> = subgraph(module, &roots).into_iter().collect();
        let mut extended = false;
        for annotation in module.annotations() {
            if let AnnotationKind::Constraint { expr, .. } = &annotation.kind {
                if cone.contains(&annotation.node) && !cone.contains(expr) {
                    roots.push(*expr);
                    extended = true;
                }
            }
        }
        if !extended {
            break cone;
        }
    };
    let cone: Vec<NodeId> = cone.into_iter().collect();
    let mut sub = InfinityModule::new();
    // Allocate the destination ids first, then copy each reachable node once
    // with its references already rewritten. The older shape cloned every node
    // twice (once into the module and once to remap its children).
    let mut map = BTreeMap::new();
    for id in &cone {
        map.entry(*id).or_insert_with(|| sub.push(Inode::Null));
    }
    for id in &cone {
        let source = module
            .get(*id)
            .ok_or(Error::InvalidArgument("subgraph node disappeared"))?;
        let target = *map
            .get(id)
            .ok_or(Error::InvalidArgument("subgraph node missing from the map"))?;
        let rewritten = remap_node(source, &map)?;
        *sub.node_mut(target)? = rewritten;
    }
    // Annotations follow the cone. A constraint or an `@ai_immutable` flag whos
    // node moved must move with it: without this a scoped evaluation silently
    // skips the rule the module states, and a subgraph handed to another agent
    // loses the guard that protected it.
    for annotation in module.annotations() {
        let Some(target) = map.get(&annotation.node).copied() else {
            continue;
        };
        let kind = match &annotation.kind {
            AnnotationKind::Intent(text) => AnnotationKind::Intent(text.clone()),
            AnnotationKind::Constraint { source, expr } => {
                let Some(expr) = map.get(expr).copied() else {
                    continue;
                };
                AnnotationKind::Constraint {
                    source: source.clone(),
                    expr,
                }
            }
            AnnotationKind::AiImmutable(flag) => AnnotationKind::AiImmutable(*flag),
        };
        sub.annotate(target, kind);
    }
    // A binding whose node is in the cone keeps its name; the rest would dangle.
    for (name, id) in module.bindings() {
        if let Some(target) = map.get(id).copied() {
            sub.bind(name.clone(), target);
        }
    }
    sub.set_provenance(module.provenance().cloned());
    sub.set_root(map.get(&node).copied());
    Ok(sub)
}

/// Rewrite every node reference through `map`.
///
/// The match is exhaustive over [`Inode`]: a new child-bearing variant in the
/// codec makes this fail to compile, which is what stops a projection from
/// carrying a dangling reference. (The earlier version handled five variants
/// and cloned the rest, so a cone containing an interpolation encoded to an
/// invalid module.)
fn remap_node(node: &Inode, map: &BTreeMap<NodeId, NodeId>) -> Result<Inode> {
    let map_id = |id: NodeId| -> Result<NodeId> {
        map.get(&id)
            .copied()
            .ok_or(Error::InvalidArgument("subgraph is not closed"))
    };
    let map_opt = |id: Option<NodeId>| -> Result<Option<NodeId>> {
        match id {
            Some(id) => Ok(Some(map_id(id)?)),
            None => Ok(None),
        }
    };
    let out = match node {
        Inode::Quantity { value, unit } => Inode::Quantity {
            value: map_id(*value)?,
            unit: unit.clone(),
        },
        Inode::Array { elements } => Inode::Array {
            elements: elements
                .iter()
                .map(|child| map_id(*child))
                .collect::<Result<_>>()?,
        },
        Inode::Table { fields } => Inode::Table {
            fields: fields
                .iter()
                .map(|(name, child)| Ok((name.clone(), map_id(*child)?)))
                .collect::<Result<_>>()?,
        },
        Inode::SecretRef { locator } => Inode::SecretRef {
            locator: map_id(*locator)?,
        },
        Inode::Ref(child) => Inode::Ref(map_id(*child)?),
        Inode::Env { name, default } => Inode::Env {
            name: name.clone(),
            default: map_opt(*default)?,
        },
        Inode::Interpolate { parts } => Inode::Interpolate {
            parts: parts
                .iter()
                .map(|part| match part {
                    InterpPart::Literal(text) => Ok(InterpPart::Literal(text.clone())),
                    InterpPart::Expr(child) => Ok(InterpPart::Expr(map_id(*child)?)),
                })
                .collect::<Result<_>>()?,
        },
        Inode::Binary { op, lhs, rhs } => Inode::Binary {
            op: *op,
            lhs: map_id(*lhs)?,
            rhs: map_id(*rhs)?,
        },
        Inode::Unary { op, expr } => Inode::Unary {
            op: *op,
            expr: map_id(*expr)?,
        },
        Inode::Constrained { target, constraint } => Inode::Constrained {
            target: map_id(*target)?,
            constraint: constraint.clone(),
        },
        Inode::Patch(op) => Inode::Patch(match op {
            PatchOp::Set { path, value } => PatchOp::Set {
                path: path.clone(),
                value: map_id(*value)?,
            },
            PatchOp::Remove { path } => PatchOp::Remove { path: path.clone() },
            PatchOp::Rename { from, to } => PatchOp::Rename {
                from: from.clone(),
                to: to.clone(),
            },
        }),
        Inode::SchemaField(spec) => Inode::SchemaField(SchemaFieldSpec {
            typ: spec.typ.clone(),
            min: map_opt(spec.min)?,
            max: map_opt(spec.max)?,
            min_len: map_opt(spec.min_len)?,
            max_len: map_opt(spec.max_len)?,
            pattern: map_opt(spec.pattern)?,
            default: map_opt(spec.default)?,
            deprecated: spec.deprecated.clone(),
        }),
        Inode::SchemaTable { fields, closed } => Inode::SchemaTable {
            fields: fields
                .iter()
                .map(|(name, child)| Ok((name.clone(), map_id(*child)?)))
                .collect::<Result<_>>()?,
            closed: *closed,
        },
        Inode::SchemaArray { element } => Inode::SchemaArray {
            element: map_id(*element)?,
        },
        Inode::Semantic { tag, inner } => Inode::Semantic {
            tag: *tag,
            inner: map_id(*inner)?,
        },
        Inode::ContentAddressed { media_type, data } => Inode::ContentAddressed {
            media_type: map_id(*media_type)?,
            data: map_id(*data)?,
        },
        // Leaves carry no node references.
        Inode::Null
        | Inode::Bool(_)
        | Inode::Int(_)
        | Inode::Float(_)
        | Inode::Str(_)
        | Inode::DurationMs(_)
        | Inode::Secret(_)
        | Inode::Ident(_)
        | Inode::Blob { .. } => node.clone(),
    };
    Ok(out)
}

/// Lowercase hex for a content address, one allocation.
///
/// `active_infinity::ir::hash_hex` formats each byte with `format!` (32
/// allocations per hash, about 4 µs on the benchmark host). The codec's own
/// formatter is fixed in the Active-Infinity tree; this local copy keeps the hot
/// path fast on the published 2.3.0 dependency and goes away with the next
/// dependency bump.
fn hex32(hash: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in hash {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
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
