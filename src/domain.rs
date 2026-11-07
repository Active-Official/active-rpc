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
    /// Work a metadata walk may do: nodes, excess references, annotations and
    /// bindings (see [`walk_weight`]).
    walk_weight: u64,
    /// Cached hash of the redacted projection.
    ///
    /// A secret-bearing module is hashed in redacted form on every
    /// `content_hash` call; the projection clones, re-encodes and re-hashes the
    /// whole arena, so the answer is cached and invalidated by a patch
    /// (round 32, #8).
    redacted_hash: Option<[u8; 32]>,
    /// The secret literals the module held when it was installed.
    ///
    /// A patch can remove the last secret node, and the redactor rebuilt from
    /// the post-write module would then find nothing to hide while plaintext
    /// copies of the old literal remain in the cone. The install-time set is an
    /// upper bound (a patch can only remove secrets), so every later redaction
    /// and every "does this module hold a secret" decision uses it
    /// (round 27, critical).
    redactor: active_infinity::interop::Redactor,
    /// Whether the module holds secret material of any kind: a `Secret` node
    /// (the redactor's literal set) or a tainted blob, whose address is
    /// secret-derived (R-16 round 10, Finding 1).
    ///
    /// Sticky: a patch that removes the last secret keeps the flag, exactly as
    /// the install-time redactor stays, so a module cannot declassify itself by
    /// removing the node that made it secret.
    held_secret: bool,
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
    /// The install seeds the cached hash from the bytes it produced, so a
    /// `content_hash` call answers without re-encoding; a `patch` clears the
    /// cache and the next call recomputes it. The module is validated as
    /// canonical first: a hand-built arena can carry
    /// a dangling reference, a secret copy in provenance text, or a node graph
    /// that no encoder would produce, and every query below assumes the codec's
    /// invariants hold.
    pub fn install(&mut self, module: InfinityModule) -> Result<u64> {
        let bytes = encode(&module).map_err(|error| Error::Payload(error.code().to_string()))?;
        active_infinity::validate_canonical(&bytes, active_infinity::Limits::default())
            .map_err(|error| Error::Payload(error.code().to_string()))?;
        let hash = active_infinity::content_hash(&bytes)
            .map_err(|error| Error::Payload(error.code().to_string()))?;
        // Store the canonical image, not the caller's arena: the encoder
        // canonicalizes metadata prose (a secret copy in an intent or a
        // constraint source becomes the marker), drops unreachable nodes and
        // renumbers, so the arena the caller handed in is not what the hash
        // describes. Serving it let `annotations` return raw secret copies
        // (R-07 round 10, critical).
        let module = active_infinity::decode(&bytes)
            .map_err(|error| Error::Payload(error.code().to_string()))?;
        check_names(&module)?;
        let redactor = security::redactor_for(&module);
        let held_secret = !redactor.is_empty() || security::module_holds_secret(&module);
        let walk_weight = walk_weight(&module);
        Ok(self.install_slot(ModuleSlot {
            module,
            hash: Some(hash),
            walk_weight,
            redacted_hash: None,
            redactor,
            held_secret,
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
        check_names(&module)?;
        let hash = active_infinity::content_hash(bytes)
            .map_err(|error| Error::Payload(error.code().to_string()))?;
        let redactor = security::redactor_for(&module);
        let held_secret = !redactor.is_empty() || security::module_holds_secret(&module);
        let walk_weight = walk_weight(&module);
        Ok(self.install_slot(ModuleSlot {
            module,
            hash: Some(hash),
            walk_weight,
            redacted_hash: None,
            redactor,
            held_secret,
        }))
    }

    fn install_slot(&mut self, slot: ModuleSlot) -> u64 {
        let id = self.next_object;
        self.next_object += 1;
        self.modules.insert(id, slot);
        id
    }

    /// Read a module back (tests and local callers).
    ///
    /// This is the **owner's** view: the provider is the host's object, so an
    /// in-process caller that already holds the `Agent` sees the arena, secret
    /// nodes included. Nothing on the wire path returns it; a capability's
    /// methods go through the redaction and content-address rules instead
    /// (R-16 round 5, #4).
    pub fn module(&self, object: u64) -> Option<&InfinityModule> {
        self.modules.get(&object).map(|slot| &slot.module)
    }

    /// The cached **raw** canonical digest of a module, when it has been computed.
    ///
    /// This is the in-process owner's cache probe (the M-4.1 invariant is "one
    /// encode per version"), and it is deliberately the *raw* value: for a
    /// secret-bearing module it is the offline equality oracle, so a capability
    /// never serves it — `content_hash` is the address a caller sees, and it is
    /// the redacted projection. `None` means "not computed yet".
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
    /// A later call or re-mint on a stale object is `provider/object`.
    fn take(&mut self, object: u64) -> Result<ModuleSlot> {
        self.modules.remove(&object).ok_or(Error::Provider {
            // The object is provider state, not a caller argument: a record
            // restored onto a rebuilt provider or a hand-minted object number
            // is a provider-side fault, and `rpc/invalid-argument` told the
            // peer to fix its own input (round 34, L-7).
            code: "provider/object".to_string(),
        })
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
            // A dotted path into an array (`app.0`) or through a semantic
            // wrapper is a legitimate name the library resolver does not walk
            // (round 19, #2).
            .or_else(|| structural_resolve(module, &path))
            // A scoped caller gets one answer for "not yours": the two codes
            // enumerated which fields exist (round 21, #5).
            .ok_or_else(|| {
                if call.path_scope.is_some() {
                    Error::PathNotGranted(path.clone())
                } else {
                    Error::InvalidArgument("path does not resolve")
                }
            })?;
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
                check_node_budget(slot, call)?;
                let budget = call.budget.to_active_budget();
                let (value, _diagnostics) = match Self::path_arg(call) {
                    Some(path) => {
                        let node = active_infinity::interop::resolve_path(&slot.module, &path)
                            .or_else(|| structural_resolve(&slot.module, &path))
                            // A scoped caller gets one answer for "not yours"
                            // (round 22, #1): the two codes distinguished a
                            // missing field from a confined one.
                            .ok_or_else(|| {
                                if call.path_scope.is_some() {
                                    Error::PathNotGranted(path.clone())
                                } else {
                                    Error::InvalidArgument("path does not resolve")
                                }
                            })?;
                        // Evaluation follows references: a scoped capability
                        // must not read a value that is built from data outside
                        // its subtree.
                        if let Some(scope) = &call.path_scope {
                            let (outside, environment) =
                                scope_closure(&slot.module, node, scope, started, call)?;
                            if outside || environment {
                                return Err(Error::PathNotGranted(path));
                            }
                        }
                        let sub = restrict(&slot.module, node)?;
                        evaluate_for_caller(&slot.module, &sub, budget, &slot.redactor)
                    }
                    // No path means the module root: evaluate in place rather
                    // than cloning the whole arena.
                    None => evaluate_for_caller(&slot.module, &slot.module, budget, &slot.redactor),
                }
                .map_err(|error| evaluator_fault(&error))?;
                // The conversion recurses; a result deeper than the wire can
                // carry can never be returned, so it is refused before the walk
                // (round 7, #4).
                if security::active_value_too_deep(&value, crate::wire::MAX_VALUE_DEPTH) {
                    return Err(Error::BudgetExceeded("depth"));
                }
                let converted = security::from_active_value(&value);
                // The conversion is work too: the ceiling covers it
                // (round 8, #7).
                check_wall_budget(started, call)?;
                Ok(Response::Value(converted))
            }
            "why" => {
                check_node_budget(slot, call)?;
                let (path, node) = self.resolve(&slot.module, call)?;
                let dependencies = transitive(&slot.module, node, true);
                // A scoped answer describes the scope. Following a reference to
                // out-of-scope data would return it under the labels of a walk
                // the capability was never granted.
                if let Some(scope) = &call.path_scope {
                    let (outside, environment) =
                        scope_closure(&slot.module, node, scope, started, call)?;
                    if outside || environment {
                        return Err(Error::PathNotGranted(path));
                    }
                }
                let labels = scoped_labels(
                    &slot.module,
                    dependencies,
                    call.path_scope.as_deref(),
                    call.redact,
                    started,
                    call,
                )?;
                let answer = redact_answer(&slot.module, node, labels, call.redact);
                // The redaction walk is the caller's work too: the ceiling is
                // checked after the answer is built (round 32, #7).
                check_wall_budget(started, call)?;
                Ok(Response::Labels(answer))
            }
            "impact" => {
                check_node_budget(slot, call)?;
                let (path, node) = self.resolve(&slot.module, call)?;
                let dependents = transitive(&slot.module, node, false);
                if let Some(scope) = &call.path_scope {
                    // The answer is the dependent closure: that is what has to
                    // be inside the scope (the dependency closure says nothing
                    // about who can see the value).
                    let mut affected = dependents.clone();
                    affected.insert(node);
                    if !nodes_within_scope(&slot.module, &affected, scope, started, call)? {
                        return Err(Error::PathNotGranted(path));
                    }
                }
                let labels = scoped_labels(
                    &slot.module,
                    dependents,
                    call.path_scope.as_deref(),
                    call.redact,
                    started,
                    call,
                )?;
                let answer = redact_answer(&slot.module, node, labels, call.redact);
                // As in `dependencies`: after the redaction walk
                // (round 32, #7).
                check_wall_budget(started, call)?;
                Ok(Response::Labels(answer))
            }
            "subgraph" => {
                check_node_budget(slot, call)?;
                let (path, node) = self.resolve(&slot.module, call)?;
                if let Some(scope) = &call.path_scope {
                    let (outside, environment) =
                        scope_closure(&slot.module, node, scope, started, call)?;
                    if outside || environment {
                        return Err(Error::PathNotGranted(path));
                    }
                }
                let mut sub = restrict(&slot.module, node)?;
                // The wire has no tag for secret bytes, so the cone is redacted
                // from the source module's literal set: the cone itself no
                // longer holds the secret node, and a plain copy used to travel
                // verbatim (round 9, #2).
                // The taint set is computed before the redaction: replacing the
                // secret node with the marker leaves nothing to taint, and the
                // metadata filter below needs the original cone.
                let tainted = call.redact.then(|| tainted_nodes(&sub));
                security::redact_derived(&mut sub, &slot.redactor).map_err(redaction_fault)?;
                // A secret-bearing module carries a raw content address in its
                // provenance; that is an offline oracle, so the cone drops it
                // for every capability (round 13, H2).
                let holds_secret = slot.held_secret;
                if call.redact || holds_secret {
                    // A redacting cone is data only: provenance (producer,
                    // entries and the parent content address) describes the
                    // whole module, annotation text and a binding that names a
                    // tainted node describe it, and the `annotations` method
                    // already hides them (round 8, #3). The parent hash is an
                    // equality oracle over the secret heap, exactly as on the
                    // patch path (round 9, #1).
                    sub.set_provenance(None);
                }
                if call.redact {
                    redact_cone_metadata(&mut sub, &tainted.unwrap_or_default());
                }
                if let Some(scope) = &call.path_scope {
                    // A cone reply is the subtree's data. Provenance (producer,
                    // entries and the parent content address) describes the whole
                    // module, and an annotation's intent or constraint source is
                    // free text that may name outside paths; neither is part of
                    // the subtree.
                    sub.set_provenance(None);
                    keep_immutable_annotations(&mut sub);
                    keep_scoped_bindings(&mut sub, scope);
                }
                let bytes = redacted_module_bytes(&sub)?;
                check_wall_budget(started, call)?;
                Ok(Response::Module(bytes))
            }
            "patch" => {
                if call.read_only {
                    return Err(Error::ReadOnly);
                }
                check_node_budget(slot, call)?;
                // The parent hash is the pre-patch content address: it is what
                // the new provenance records as its parent, so the lineage of an
                // audited module survives a write.
                let parent_hash = match slot.hash {
                    Some(hash) => Some(hash),
                    None => {
                        let bytes = encode(&slot.module)
                            .map_err(|error| Error::Payload(error.code().to_string()))?;
                        Some(
                            active_infinity::content_hash(&bytes)
                                .map_err(|error| Error::Payload(error.code().to_string()))?,
                        )
                    }
                };
                let (patched, bytes) = {
                    let module = &slot.module;
                    let (path, node) = self.resolve(module, call)?;
                    if call.path_scope.is_some() && Some(node) == module.root() {
                        // A binding can name the root, and a label resolves
                        // back to it, so the scope checks would pass: replacing
                        // the root deletes every outside subtree through a
                        // write that never named one (R-07 round 10, #3).
                        return Err(Error::PathNotGranted(path.clone()));
                    }
                    if immutable_target(module, &path) || immutable_node(module, node) {
                        // `@ai_immutable: true` is the format's marker for a
                        // node no agent may rewrite. A shared DAG means the same
                        // node can be named by an alias outside the marked
                        // subtree, so the check is on the node too.
                        return Err(Error::ReadOnly);
                    }
                    if let Some(scope) = &call.path_scope {
                        if !effects_within_scope(module, node, scope, started, call)? {
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
                    if slot.held_secret && matches!(replacement, Inode::Str(_)) {
                        // The reply is the caller's own literal through the
                        // install-time redactor, and that redaction is
                        // unconditional: a candidate containing the secret
                        // comes back as the marker and one that does not comes
                        // back verbatim, for every capability (round 32, #1;
                        // round 33, F1 showed the `redact` flag does not
                        // narrow it). Refuse every text replacement on a
                        // secret-bearing module; a non-text literal cannot
                        // carry the secret, so declassification uses one of
                        // those.
                        return Err(Error::InvalidArgument(
                            "a text replacement is refused on a secret-bearing module",
                        ));
                    }
                    let mut patched = module.clone();
                    *patched
                        .node_mut(node)
                        .map_err(|error| Error::Payload(error.code().to_string()))? = replacement;
                    // The producer chain survives: the new module records the
                    // old content address as its parent and keeps the entries
                    // (and the identities) the module already carried.
                    let held_secret = slot.held_secret;
                    let previous = patched.provenance().cloned();
                    patched.set_provenance(Some(Provenance {
                        producer: previous
                            .as_ref()
                            .and_then(|prov| prov.producer.clone())
                            .or_else(|| Some("active-rpc/patch".to_string())),
                        timestamp_ms: previous.as_ref().map_or(0, |prov| prov.timestamp_ms),
                        model: previous.as_ref().and_then(|prov| prov.model.clone()),
                        tool: Some("patch".to_string()),
                        // A raw pre-patch address over a secret image is an
                        // offline oracle, so a secret-bearing history records no
                        // parent (round 14, H1).
                        parent: if held_secret { None } else { parent_hash },
                        // A `Hash` entry renders as a content address: the
                        // pre-patch image's, when the history held a secret
                        // (round 15, #2).
                        // `held_secret` is computed once: the filter used to
                        // rescan every node per entry, which is O(entries x
                        // nodes) after the last wall check (round 27, medium).
                        entries: previous
                            .map(|prov| prov.entries)
                            .unwrap_or_default()
                            .into_iter()
                            .filter(|entry| {
                                !held_secret
                                    || !matches!(entry.value, active_infinity::ProvValue::Hash(_))
                            })
                            .collect(),
                    }));
                    // The reply is the cone at the target, not the whole arena:
                    // a scoped writer must not receive the rest of the module
                    // back, and the bytes stay bounded by the write.
                    let mut cone = restrict(&patched, node)?;
                    // As in `subgraph`: the reply is a projection, and a copy of
                    // a secret literal in the cone is still the secret.
                    let tainted = call.redact.then(|| tainted_nodes(&cone));
                    security::redact_derived(&mut cone, &slot.redactor).map_err(redaction_fault)?;
                    // The provenance names the pre-patch image, so the
                    // pre-patch secret set decides too (round 14, H1).
                    let holds_secret = slot.held_secret || security::module_holds_secret(&patched);
                    if call.redact {
                        // The provenance records the parent's content address,
                        // and a redacting caller may not receive a hash of an
                        // image it cannot read: comparing it with a guessed hash
                        // is an equality oracle over secrets (round 7, #2).
                        // Annotation text and bindings on a tainted node describe
                        // it, so they go with it (round 8, #3).
                        cone.set_provenance(None);
                        redact_cone_metadata(&mut cone, &tainted.unwrap_or_default());
                    } else if holds_secret && call.path_scope.is_none() {
                        // The new provenance records the pre-patch content
                        // address, which covers the secret heap (round 13, H2).
                        cone.set_provenance(None);
                    }
                    if let Some(scope) = &call.path_scope {
                        // The same rule as `subgraph`: a scoped cone reply is the
                        // subtree's data, not the module's history.
                        cone.set_provenance(None);
                        keep_immutable_annotations(&mut cone);
                        keep_scoped_bindings(&mut cone, scope);
                    }
                    let bytes = redacted_module_bytes(&cone)?;
                    (patched, bytes)
                };
                // A patch advances the object in place: every holder of a
                // capability for it observes the new version, which is what
                // "patch returns the new module capability" means without a
                // provider-side mint hook. Mint a fresh capability when
                // isolation is required. The cached hash no longer describes
                // the module, so it is cleared.
                check_wall_budget(started, call)?;
                // Store the canonical form, as `install` does: a patch that
                // replaces an ancestor orphans the old subtree, and an orphaned
                // secret node made the module look secret forever while the
                // canonical image was public (round 21, #3).
                let canonical =
                    encode(&patched).map_err(|error| Error::Payload(error.code().to_string()))?;
                active_infinity::validate_canonical(&canonical, active_infinity::Limits::default())
                    .map_err(|error| Error::Payload(error.code().to_string()))?;
                // Both fields change together: a failure between the two
                // assignments left a cached hash naming the previous image,
                // so the module identity and the next patch's parent were
                // wrong (round 24, F10).
                let decoded = active_infinity::decode(&canonical)
                    .map_err(|error| Error::Payload(error.code().to_string()))?;
                let hash = active_infinity::content_hash(&canonical)
                    .map_err(|error| Error::Payload(error.code().to_string()))?;
                let weight = walk_weight(&decoded);
                // Sticky: the pre-patch module may have held secret material the
                // patch removed, and its addresses are still what the new
                // provenance names (R-16 round 10, Finding 1).
                slot.held_secret |= security::module_holds_secret(&decoded);
                slot.module = decoded;
                slot.hash = Some(hash);
                slot.walk_weight = weight;
                // The reply changed, and the redacted projection is derived
                // from it (round 32, #8).
                slot.redacted_hash = None;
                Ok(Response::Module(bytes))
            }
            "dependents" => {
                check_node_budget(slot, call)?;
                let (path, node) = self.resolve(&slot.module, call)?;
                // The entry node is part of the answer's meaning: an alias can
                // name an outside node, and checking only the result set let a
                // scoped query start outside the scope (round 13, H1).
                if let Some(scope) = &call.path_scope {
                    if !in_scope_path(&slot.module, node, &path, scope) {
                        return Err(Error::PathNotGranted(path));
                    }
                }
                let (_, dependents) = adjacency(&slot.module);
                let ids: BTreeSet<NodeId> = dependents
                    .get(node.index())
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                if let Some(scope) = &call.path_scope {
                    if !nodes_within_scope(&slot.module, &ids, scope, started, call)? {
                        return Err(Error::PathNotGranted(path));
                    }
                }
                let labels = scoped_labels(
                    &slot.module,
                    ids,
                    call.path_scope.as_deref(),
                    call.redact,
                    started,
                    call,
                )?;
                let answer = redact_answer(&slot.module, node, labels, call.redact);
                // After the redaction walk (round 32, #7).
                check_wall_budget(started, call)?;
                Ok(Response::Labels(answer))
            }
            "dependencies" => {
                check_node_budget(slot, call)?;
                let (path, node) = self.resolve(&slot.module, call)?;
                // As in `dependents`: the entry node must be named by the scope.
                if let Some(scope) = &call.path_scope {
                    if !in_scope_path(&slot.module, node, &path, scope) {
                        return Err(Error::PathNotGranted(path));
                    }
                }
                let (dependencies, _) = adjacency(&slot.module);
                let ids: BTreeSet<NodeId> = dependencies
                    .get(node.index())
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                if let Some(scope) = &call.path_scope {
                    if !nodes_within_scope(&slot.module, &ids, scope, started, call)? {
                        return Err(Error::PathNotGranted(path));
                    }
                }
                let labels = scoped_labels(
                    &slot.module,
                    ids,
                    call.path_scope.as_deref(),
                    call.redact,
                    started,
                    call,
                )?;
                let answer = redact_answer(&slot.module, node, labels, call.redact);
                // After the redaction walk (round 32, #7).
                check_wall_budget(started, call)?;
                Ok(Response::Labels(answer))
            }
            "content_hash" => {
                check_node_budget(slot, call)?;
                // A hash names the whole module: under a scope it would answer a
                // question about data the capability was never granted, and it
                // is an equality oracle for the parts outside the scope.
                if let Some(scope) = &call.path_scope {
                    return Err(Error::PathNotGranted(scope.clone()));
                }
                // A redacting capability gets the hash of the *redacted* image:
                // the canonical hash covers the secret heap, so handing it to a
                // caller that may not read the module is an equality oracle over
                // secret material (compare one guess, or brute-force a short
                // value). The redacted hash still proves structural identity.
                // A module that holds a secret is hashed in redacted form for
                // every capability: the canonical hash covers the secret heap,
                // so the raw value is an offline equality oracle over a
                // low-entropy secret even for a caller that cannot read the
                // bytes. The redacted hash still proves structural identity
                // (round 12, F4).
                let holds_secret = slot.held_secret;
                // Fill the slot cache first: it holds the raw canonical hash,
                // which is the module's identity and the parent of a later
                // patch. The answer below may be the redacted one.
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
                if !holds_secret {
                    // Nothing to redact: the redacted projection is the module
                    // itself, so the answer is the stored hash -- including a
                    // streamed image, which a re-encode would not reproduce
                    // (R-16 round 10, Finding 3).
                    check_wall_budget(started, call)?;
                    return Ok(Response::Value(Value::Text(format!(
                        "blake3:{}",
                        hex32(&hash)
                    ))));
                }
                if call.redact || holds_secret {
                    // A module that holds a secret is hashed in redacted form
                    // for every capability: the raw hash covers the secret heap
                    // and is an offline equality oracle over a low-entropy
                    // secret, even for a caller that cannot read the bytes. The
                    // redacted hash still proves structural identity
                    // (round 12, F4).
                    // Redact in memory with the install-time handle: deriving
                    // the literal set from the stored image made the "redacted"
                    // hash equal the raw one once a patch removed the last
                    // secret node (round 28, critical). The result is cached: a
                    // patch invalidates it (round 32, #8).
                    let redacted_hash = match slot.redacted_hash {
                        Some(hash) => hash,
                        None => {
                            let mut redacted = slot.module.clone();
                            crate::security::redact_derived(&mut redacted, &slot.redactor)
                                .map_err(redaction_fault)?;
                            // Only a secret-bearing module has something to
                            // hide: its provenance names the pre-redaction
                            // image, and those addresses are an offline oracle.
                            // A secret-free module's redacted projection *is*
                            // the module, so its digest must stay the true
                            // content address a `fetch by address` flow uses
                            // (R-16 round 8, #1; round 9, F-1).
                            if holds_secret {
                                redacted.set_provenance(None);
                            }
                            // A tainted blob's hash is secret-derived whatever
                            // the module's provenance says (round 9, F-2).
                            crate::security::sanitize_tainted_blobs(&mut redacted);
                            let redacted_bytes = encode(&redacted).map_err(|error| {
                                redaction_fault(Error::Payload(error.code().to_string()))
                            })?;
                            let hash = active_infinity::content_hash(&redacted_bytes)
                                .map_err(|error| Error::Payload(error.code().to_string()))?;
                            slot.redacted_hash = Some(hash);
                            hash
                        }
                    };
                    check_wall_budget(started, call)?;
                    return Ok(Response::Value(Value::Text(format!(
                        "blake3:{}",
                        hex32(&redacted_hash)
                    ))));
                }
                check_wall_budget(started, call)?;
                Ok(Response::Value(Value::Text(format!(
                    "blake3:{}",
                    hex32(&hash)
                ))))
            }
            "stats" | "annotations" | "provenance" if call.path_scope.is_some() => {
                // These describe the whole module. A scoped capability asking
                // with an in-scope path still learns global counts, node ids and
                // provenance, so the answer is refused rather than filtered.
                Err(Error::PathNotGranted(
                    call.path_scope.clone().unwrap_or_default(),
                ))
            }
            "stats" => {
                check_node_budget(slot, call)?;
                let module = &slot.module;
                let mut map = BTreeMap::new();
                // A size is an oracle over the secret cone: a redacting caller
                // learns whether a module holds one secret or many by counting
                // nodes. A caller that may read the module already knows
                // (round 21, #1).
                let hides_size = call.redact;
                if !hides_size {
                    map.insert("nodes".to_string(), Value::Int(module.node_count() as i64));
                    map.insert("edges".to_string(), Value::Int(module.edges().len() as i64));
                }
                // `security.md` promises a redacting capability learns that a
                // cone is tainted, never how many secrets `stats` holds. The
                // redacted projections (`evaluate`, `subgraph`) still preserve
                // structure, so they reveal the count and positions of secret
                // nodes; the security spec states that trade-off explicitly
                // (round 36, L-5).
                if !call.redact {
                    let live = module
                        .nodes()
                        .iter()
                        .filter(|node| node.is_secret() || security::is_tainted_blob(node))
                        .count() as i64;
                    // The install-time redactor still hides literals after a
                    // patch removed the last secret node, so `0` would
                    // contradict every other method (round 30, L-6). A
                    // non-redacting caller may know the count; it may not learn
                    // "zero" when the module is treated as secret-bearing.
                    let reported = if live == 0 && slot.held_secret {
                        1
                    } else {
                        live
                    };
                    map.insert("secrets".to_string(), Value::Int(reported));
                }
                // Whether provenance exists is a size signal a redacting caller
                // must not read, and `provenance` already answers the question
                // for a caller that holds that grant (round 27, low; round 31,
                // F2 removed the field that leaked the same bit through
                // `stats`).
                check_wall_budget(started, call)?;
                Ok(Response::Value(Value::Map(map)))
            }
            "annotations" => {
                check_node_budget(slot, call)?;
                let module = &slot.module;
                // The taint walk is only needed when the capability redacts.
                // A tainted blob's content address is secret material, so an
                // annotation that names it -- as its subject, or with the hex
                // address in its text -- is hidden from every capability, not
                // only a redacting one (R-16 round 11, Findings 1 and 4).
                let mut tainted_ids: BTreeSet<NodeId> = BTreeSet::new();
                let mut hidden_addresses: BTreeSet<[u8; 64]> = BTreeSet::new();
                if slot.held_secret {
                    for index in 0..module.node_count() {
                        let id = NodeId(index as u32);
                        if module.get(id).is_some_and(security::is_tainted_blob) {
                            tainted_ids.insert(id);
                            if let Some(active_infinity::Inode::Blob { hash, .. }) = module.get(id)
                            {
                                if let Ok(key) = <[u8; 64]>::try_from(
                                    active_infinity::ir::hash_hex(hash).as_bytes(),
                                ) {
                                    hidden_addresses.insert(key);
                                }
                            }
                        }
                    }
                }
                if call.redact {
                    tainted_ids.extend(tainted_nodes(module));
                }
                let mut out = Vec::new();
                let mut hidden_seen = false;
                for annotation in module.annotations() {
                    let (kind, text) = match &annotation.kind {
                        AnnotationKind::Intent(text) => ("intent", text.clone()),
                        AnnotationKind::Constraint { source, .. } => ("constraint", source.clone()),
                        AnnotationKind::AiImmutable(flag) => ("ai_immutable", flag.to_string()),
                    };
                    // A redacting capability hides anything attached to the
                    // secret cone; a non-redacting one still only sees text that
                    // canonicalization already redacted.
                    let carries_text = security::annotation_text(&annotation.kind).is_some();
                    let hidden = (carries_text && tainted_ids.contains(&annotation.node))
                        || security::text_names_an_address(&text, &hidden_addresses)
                        || text.contains(security::SECRET_MARKER);
                    if hidden {
                        // One marker for the whole hidden set: a marker per
                        // annotation would count the rules on the secret cone
                        // and name their kinds (R-07 round 10, #6).
                        hidden_seen = true;
                        continue;
                    }
                    let mut entry: BTreeMap<String, Value> = BTreeMap::new();
                    // A node id is an arena position: `stats` hides the size
                    // from a redacting caller, and naming an index handed the
                    // count back (round 25, #4).
                    if !call.redact {
                        entry.insert("node".to_string(), Value::Int(annotation.node.0 as i64));
                    }
                    entry.insert("kind".to_string(), Value::Text(kind.to_string()));
                    entry.insert("text".to_string(), Value::Text(text));
                    out.push(Value::Map(entry));
                }
                if hidden_seen {
                    let mut entry: BTreeMap<String, Value> = BTreeMap::new();
                    entry.insert("text".to_string(), Value::Secret);
                    out.push(Value::Map(entry));
                }
                check_wall_budget(started, call)?;
                Ok(Response::Value(Value::List(out)))
            }
            "provenance" => {
                check_node_budget(slot, call)?;
                // A raw content address over the secret heap is an offline
                // oracle, so a secret-bearing module hides it from every
                // capability, exactly like `content_hash` (round 13, H2).
                let holds_secret = slot.held_secret;
                Ok(match slot.module.provenance() {
                    None => {
                        // Every arm charges the ceiling; this one returned
                        // first (round 15, #4).
                        check_wall_budget(started, call)?;
                        Response::Value(Value::Null)
                    }
                    Some(prov) => {
                        // Text fields come from `provenance_lines`, which owns
                        // the redaction: a copy of a secret literal in a producer
                        // string is replaced by the marker instead of leaving as
                        // ordinary text.
                        let mut map = provenance_map(&slot.module);
                        if call.redact || holds_secret {
                            // Every content address is an oracle over an image
                            // the caller may not read: the parent, and the
                            // `Input` lineage entries a patch carries forward
                            // (round 7 #2, round 8 #2).
                            map.retain(|_, value| {
                                !matches!(value, Value::Text(text) if text.contains("blake3:"))
                            });
                        }
                        let timestamp = i64::try_from(prov.timestamp_ms).unwrap_or(i64::MAX);
                        map.insert("timestamp_ms".to_string(), Value::Int(timestamp));
                        check_wall_budget(started, call)?;
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
        // Re-insert on every path, including a panic: the slot was taken out of
        // the map, so an unwind that skipped this line would destroy the module.
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.serve(&mut slot, call)));
        self.modules.insert(object, slot);
        // Only an answered call counts: a refusal decided after the slot was
        // taken is not a served call.
        if outcome.as_ref().is_ok_and(|result| result.is_ok()) {
            self.calls = self.calls.saturating_add(1);
        }
        match outcome {
            Ok(result) => result,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    fn on_drop(&mut self, object: u64, cap: CapId) {
        // The last capability on this object is gone: the module is no longer
        // reachable through the provider, so retaining it retained every
        // installed module for the life of the agent (R-07 round 10, #8). A
        // later call or re-mint on the stale object is `unknown module`.
        self.modules.remove(&object);
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
fn check_node_budget(slot: &ModuleSlot, call: &Call) -> Result<()> {
    // The weight is computed once, at install and after each patch: a node
    // ceiling bounds nodes, not references, and a two-node module whose root is
    // a table with a million fields passed a `max_nodes = 4` check and spent
    // 261 ms under a 5 ms grant (round 36, M-1). Counting it here would do the
    // work the ceiling exists to refuse. Annotations and bindings are part of
    // the same weight: each is a record the metadata walks scan (round 23, #5;
    // round 35, L-3). The dimension is `nodes` for all of them: a distinct
    // label would let a redacting or scoped caller binary-search a size `stats`
    // deliberately hides (round 24, F6).
    if slot.walk_weight > call.budget.max_nodes {
        return Err(Error::BudgetExceeded("nodes"));
    }
    Ok(())
}

/// The work a metadata walk may do on `module`: its nodes, the references past
/// one per node, its annotations and its bindings.
fn walk_weight(module: &InfinityModule) -> u64 {
    let nodes = module.node_count() as u64;
    let mut references = 0u64;
    for node in module.nodes() {
        references = references.saturating_add(node.children().len() as u64);
    }
    nodes
        .saturating_add(references.saturating_sub(nodes))
        .saturating_add(module.annotations().len() as u64)
        .saturating_add(module.bindings().len() as u64)
        // Provenance text is redacted against every secret literal, so its
        // entry count belongs to the same walk weight (round 39, L-6).
        .saturating_add(
            module
                .provenance()
                .map_or(0, |provenance| provenance.entries.len() as u64),
        )
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
    transitive_with(&dependencies, &dependents, node, walk_dependencies)
}

/// Transitive closure over an adjacency that the caller built once.
///
/// A scope check walks once per matching constraint annotation; rebuilding the
/// adjacency for each made one round cost `O(annotations x edges)` before any
/// ceiling could be observed (round 24, F1).
fn transitive_with(
    dependencies: &[Vec<NodeId>],
    dependents: &[Vec<NodeId>],
    node: NodeId,
    walk_dependencies: bool,
) -> BTreeSet<NodeId> {
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

/// The value path a node is *named* by.
///
/// `value_paths` labels the module root with the empty string and leaves a node
/// no walk reaches out of the map. Neither is a name a scope can grant: the root
/// is the module itself, and a floating node is out of scope by construction.
fn named_path(paths: &std::collections::HashMap<NodeId, String>, id: NodeId) -> Option<&str> {
    paths
        .get(&id)
        .map(String::as_str)
        .filter(|path| !path.is_empty())
}

/// Labels for a set of node ids, from one `value_paths` pass.
///
/// `node_label` rebuilds the whole path map per node, which is what made these
/// queries quadratic; one map turns the whole answer into a lookup.
fn labels_for(module: &InfinityModule, ids: impl IntoIterator<Item = NodeId>) -> Vec<String> {
    let paths = active_infinity::interop::value_paths(module);
    labels_from(module, &paths, ids)
}

/// Labels from a path map the caller already built.
///
/// The scoped path needs the map for its own resolution check, so rebuilding it
/// here walked the module twice per charged query (round 26, #6).
fn labels_from(
    module: &InfinityModule,
    paths: &std::collections::HashMap<NodeId, String>,
    ids: impl IntoIterator<Item = NodeId>,
) -> Vec<String> {
    let mut labels: Vec<String> = ids
        .into_iter()
        .map(|id| match named_path(paths, id) {
            Some(path) => path.to_string(),
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
        if let Some(id) = active_infinity::interop::resolve_path(module, &prefix)
            .or_else(|| structural_resolve(module, &prefix))
        {
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
fn effects_within_scope(
    module: &InfinityModule,
    node: NodeId,
    scope: &str,
    started: std::time::Instant,
    call: &Call,
) -> Result<bool> {
    let (dependencies, dependents) = adjacency(module);
    let mut affected = transitive_with(&dependencies, &dependents, node, false);
    affected.insert(node);
    // A constraint's expression is part of the validation of its subject: a
    // scoped write may not change the meaning of a rule that watches data
    // outside the scope. A constraint on a constraint is the same rule again, so
    // this runs to a fixpoint: one pass left the tail order-dependent, and a
    // reversed annotation order let a write through that the forward order
    // refused (round 7, #1).
    loop {
        check_wall_budget(started, call)?;
        let before = affected.len();
        let subjects = affected.clone();
        for (index, annotation) in module.annotations().iter().enumerate() {
            // A round over a hostile annotation count is itself unbounded work;
            // the ceiling is checked inside it, not only between rounds
            // (round 24, F1).
            if index % 64 == 63 {
                check_wall_budget(started, call)?;
            }
            if let AnnotationKind::Constraint { expr, .. } = &annotation.kind {
                // The relation is undirected: changing a rule's subject changes
                // what is validated, and changing its expression changes the
                // same rule from the other side. Following only subject ->
                // expression let a scoped write rewrite an outside subtree's
                // rule expression (round 9, #3).
                if subjects.contains(&annotation.node) || subjects.contains(expr) {
                    // The expression's own dependencies too: `scope_closure`
                    // follows them on the read side, and a write that changes
                    // the rule's meaning is the same access (round 8, #4).
                    affected.extend(transitive_with(&dependencies, &dependents, *expr, true));
                    affected.insert(*expr);
                    affected.insert(annotation.node);
                }
            }
        }
        if affected.len() == before {
            break;
        }
    }
    // An environment node is host state: a scoped write whose rule reads it is
    // not confined, exactly as on the read side.
    if affected
        .iter()
        .any(|id| matches!(module.get(*id), Some(Inode::Env { .. })))
    {
        return Ok(false);
    }
    let paths = active_infinity::interop::value_paths(module);
    let root = module.root();
    for (index, id) in affected.iter().enumerate() {
        let inside = match named_path(&paths, *id) {
            Some(path) => in_scope_path(module, *id, path, scope),
            // The module root is pathless by construction. A pathless node
            // inside the scope's subtree is part of the scope; any other is a
            // floating value or an expression, and an affected one makes the
            // write unconfined (round 15, #1).
            None => Some(*id) == root || in_scope_node(module, *id, scope),
        };
        if !inside {
            return Ok(false);
        }
        // `in_scope_node` walks the scope subtree for a pathless id, so a large
        // array is O(n^2) without an interim ceiling (round 35, M-2).
        if index % 64 == 63 {
            check_wall_budget(started, call)?;
        }
    }
    // A binding is a name for a node: if a dependent is bound outside the
    // scope, changing the node changes what that name resolves to.
    Ok(module
        .bindings()
        .iter()
        .all(|(name, id)| !affected.contains(id) || crate::cap::is_path_prefix(scope, name)))
}

/// True when `node` is immutable, is inside a marked subtree, or protects one.
///
/// `@ai_immutable` protects a subtree. A shared DAG lets the same node be named
/// by an alias outside the marked path, and replacing an ancestor deletes its
/// children, so both directions count: the node's dependencies (it is inside a
/// marked subtree) and the marked nodes below it (it would delete one).
fn immutable_node(module: &InfinityModule, node: NodeId) -> bool {
    let immutable: BTreeSet<NodeId> = active_infinity::interop::immutable_nodes(module)
        .into_iter()
        .collect();
    if immutable.is_empty() {
        return false;
    }
    if immutable.contains(&node) {
        return true;
    }
    let (dependencies, dependents) = adjacency(module);
    // One reachability pass each way: a marked node above (an ancestor replace
    // deletes) or below (an alias of a marked value) protects the target.
    let reachable = |graph: &[Vec<NodeId>]| {
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
        seen
    };
    reachable(&dependencies)
        .iter()
        .any(|id| immutable.contains(id))
        || reachable(&dependents)
            .iter()
            .any(|id| immutable.contains(id))
}

/// Reduce a cone's annotations to the immutability guards.
///
/// An annotation's intent or constraint source is free text that may name outside
/// paths, so it leaves with the scope. `@ai_immutable` is different: it is the
/// guard that stops the next agent from rewriting the subtree, and dropping it
/// would hand the recipient a cone it may change.
fn keep_immutable_annotations(module: &mut InfinityModule) {
    let guards: Vec<(NodeId, AnnotationKind)> = module
        .annotations()
        .iter()
        .filter(|annotation| matches!(annotation.kind, AnnotationKind::AiImmutable(_)))
        .map(|annotation| (annotation.node, annotation.kind.clone()))
        .collect();
    module.clear_annotations();
    for (node, kind) in guards {
        module.annotate(node, kind);
    }
}

/// Drop bindings whose name is outside the scope.
///
/// A binding is a second name for a node. A cone that carries one lets the
/// receiver address data by a name the scope never granted, and `value_paths`
/// would then report that name for the node.
fn keep_scoped_bindings(module: &mut InfinityModule, scope: &str) {
    // `restrict` only copies bindings whose node it kept, so the ids are already
    // the cone's: the name is what can still be outside the scope.
    let bindings: Vec<(String, NodeId)> = module
        .bindings()
        .iter()
        .filter(|(name, _)| crate::cap::is_path_prefix(scope, name))
        .cloned()
        .collect();
    module.clear_bindings();
    for (name, id) in bindings {
        module.bind(name, id);
    }
}

/// True when every node in `ids` is named by a path inside `scope`.
fn nodes_within_scope(
    module: &InfinityModule,
    ids: &BTreeSet<NodeId>,
    scope: &str,
    started: std::time::Instant,
    call: &Call,
) -> Result<bool> {
    if ids.is_empty() {
        return Ok(true);
    }
    let paths = active_infinity::interop::value_paths(module);
    let root = module.root();
    let mut inside = true;
    for (index, id) in ids.iter().enumerate() {
        // A pathless id costs a subtree walk; a hostile module makes that
        // quadratic, so the grant is checked inside the scan
        // (round 28, low).
        if index % 64 == 63 {
            check_wall_budget(started, call)?;
        }
        let within = match named_path(&paths, *id) {
            Some(path) => in_scope_path(module, *id, path, scope),
            // The module root is pathless by construction; a pathless node
            // inside the scope's subtree is part of it; any other is a floating
            // value or an expression, and a scoped answer that dropped it
            // presented itself as complete (round 8, #6).
            None => Some(*id) == root || in_scope_node(module, *id, scope),
        };
        if !within {
            inside = false;
            break;
        }
    }
    Ok(inside)
}

/// True when `path` is inside `scope` *and* still resolves to `id`.
///
/// `value_paths` reports a binding name for a node that has one, so a binding can
/// present an outside node under an in-scope-looking name. A name that does not
/// resolve back is not confinement.
fn in_scope_path(module: &InfinityModule, id: NodeId, path: &str, scope: &str) -> bool {
    if !crate::cap::is_path_prefix(scope, path) {
        return false;
    }
    if path.starts_with('@') {
        // A synthetic label (`@node[id]`, a redaction collision) is not a name,
        // so it is no evidence either way: decide by walking the scope's
        // subtree. This is the semantic-wrapper collision case, where the
        // wrapper and its inner node share one dotted name (round 15, #1).
        return in_scope_node(module, id, scope);
    }
    structural_resolve(module, path).is_some_and(|resolved| same_place(module, resolved, id))
}

/// Whether `id` is a node of the subtree the scope names.
fn in_scope_node(module: &InfinityModule, id: NodeId, scope: &str) -> bool {
    let Some(root) = structural_resolve(module, scope) else {
        return false;
    };
    let mut seen = vec![false; module.node_count()];
    let mut stack = vec![root];
    while let Some(current) = stack.pop() {
        if current.index() >= seen.len() || seen[current.index()] {
            continue;
        }
        seen[current.index()] = true;
        if current == id || same_place(module, current, id) {
            return true;
        }
        match module.get(current) {
            Some(Inode::Table { fields }) => {
                stack.extend(fields.iter().map(|(_, child)| *child));
            }
            Some(Inode::SchemaTable { fields, .. }) => {
                stack.extend(fields.iter().map(|(_, child)| *child));
            }
            Some(Inode::Array { elements }) => stack.extend(elements.iter().copied()),
            Some(Inode::SchemaArray { element }) => stack.push(*element),
            Some(Inode::Semantic { inner, .. }) => stack.push(*inner),
            _ => {}
        }
    }
    false
}

/// Whether two ids name the same value through semantic wrappers.
///
/// A semantic wrapper is transparent to the path walk, so a name can resolve to
/// the wrapper while the walk reports the inner node (or the other way round).
fn same_place(module: &InfinityModule, left: NodeId, right: NodeId) -> bool {
    let through = |start: NodeId, target: NodeId| {
        let mut current = start;
        for _ in 0..64 {
            if current == target {
                return true;
            }
            match module.get(current) {
                Some(Inode::Semantic { inner, .. }) => current = *inner,
                _ => return false,
            }
        }
        false
    };
    through(left, right) || through(right, left)
}

/// Resolve a dotted path through table fields from the module root.
///
/// No bindings and no annotations: exactly the tree a scoped capability was
/// granted. `bind("app", outside)` used to present an outside node as in-scope,
/// because `value_paths` labels the binding and `resolve_path` follows it
/// (R-07 round 11, #1; round 12, F1).
fn structural_resolve(module: &InfinityModule, path: &str) -> Option<NodeId> {
    let mut current = module.root()?;
    if path.is_empty() {
        return Some(current);
    }
    for segment in path.split('.') {
        if segment.is_empty() || segment == ".." {
            return None;
        }
        // A semantic wrapper above a container is transparent: unwrap it
        // without consuming the segment. An earlier version sliced the path by
        // the segment's length and skipped the segment itself, which panicked on
        // a single-segment path and refused a legal nested name
        // (round 14 H2/M1, round 15 #1).
        let mut node = current;
        // Bounded: a hand-built `Semantic { inner: self }` would otherwise hang
        // the scope check (round 16, #2).
        for _ in 0..module.node_count().max(1) {
            match module.get(node) {
                Some(Inode::Semantic { inner, .. }) => node = *inner,
                _ => break,
            }
            if node == current {
                return None;
            }
        }
        current = match module.get(node)? {
            Inode::Table { fields } | Inode::SchemaTable { fields, .. } => fields
                .iter()
                .find(|(name, _)| name == segment)
                .map(|(_, id)| *id)?,
            // A number selects an array element; `value_paths` spells it the
            // same way, so a scoped array access is a legitimate name.
            Inode::Array { elements } => {
                let index: usize = segment.parse().ok()?;
                *elements.get(index)?
            }
            Inode::SchemaArray { element } => {
                // The only name a schema array element has is index 0.
                if segment != "0" {
                    return None;
                }
                *element
            }
            _ => return None,
        };
    }
    Some(current)
}

/// Whether a scoped read closure reaches a node named outside `scope`, and
/// whether it reads the host environment.
///
/// `transitive` walks value edges only; a constraint's expression is stored text
/// the cone carries, so it joins the closure here. `Env` resolves against the
/// process environment at evaluation time and has no path at all, so a scope
/// always refuses it.
fn scope_closure(
    module: &InfinityModule,
    node: NodeId,
    scope: &str,
    started: std::time::Instant,
    call: &Call,
) -> Result<(bool, bool)> {
    let (dependencies, dependents) = adjacency(module);
    let mut closure = transitive_with(&dependencies, &dependents, node, true);
    closure.insert(node);
    // A constraint chain can be arbitrarily deep, so iterate until nothing new
    // arrives; the closure is bounded by the node count, and every round is
    // charged against the wall ceiling because each one scans every annotation
    // (round 23, #5).
    loop {
        check_wall_budget(started, call)?;
        let before = closure.len();
        let subjects = closure.clone();
        for (index, annotation) in module.annotations().iter().enumerate() {
            if index % 64 == 63 {
                check_wall_budget(started, call)?;
            }
            if let AnnotationKind::Constraint { expr, .. } = &annotation.kind {
                if subjects.contains(&annotation.node) {
                    closure.extend(transitive_with(&dependencies, &dependents, *expr, true));
                    closure.insert(*expr);
                }
            }
        }
        if closure.len() == before {
            break;
        }
    }
    let environment = closure
        .iter()
        .any(|id| matches!(module.get(*id), Some(Inode::Env { .. })));
    let paths = active_infinity::interop::value_paths(module);
    let root = module.root();
    let mut outside = false;
    for (index, id) in closure.iter().enumerate() {
        let confined = match named_path(&paths, *id) {
            Some(path) => in_scope_path(module, *id, path, scope),
            // The module root is the module itself. A pathless node is inside
            // only when the scope's own subtree reaches it (a node behind a
            // semantic wrapper or an array has no dotted name of its own)
            // (round 15, #1).
            None => Some(*id) == root || in_scope_node(module, *id, scope),
        };
        if !confined {
            outside = true;
            break;
        }
        // `in_scope_node` walks the scope subtree for a pathless id, so a large
        // array is O(n^2) without an interim ceiling (round 35, M-2).
        if index % 64 == 63 {
            check_wall_budget(started, call)?;
        }
    }
    Ok((outside, environment))
}

/// Labels for a set of node ids under an optional scope.
///
/// The caller has already checked that the ids are confined; this function
/// filters what cannot be named, it does not enforce the scope
/// (round 27, low).
///
/// A node with no value path is labelled `Kind[index]`, which names a node id
/// the scope never granted; under a scope those labels are dropped rather than
/// refused, because the root of every walk is pathless and refusing would make
/// the dependent queries unusable.
fn scoped_labels(
    module: &InfinityModule,
    ids: impl IntoIterator<Item = NodeId>,
    scope: Option<&str>,
    redact: bool,
    started: std::time::Instant,
    call: &Call,
) -> Result<Vec<String>> {
    let ids: Vec<NodeId> = ids.into_iter().collect();
    // Nothing to name: an empty answer must not walk the module (round 36,
    // L-2).
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    // A pathless node has no name a caller could use: under a scope the label
    // would name a node the scope never granted, and under a redacting
    // capability it names an arena position of a module the caller cannot read
    // (round 9, #6). Round 4 fixed only the scoped half.
    if scope.is_none() && !redact {
        // The unfiltered path builds the whole path map too; keep it under the
        // ceiling like the filtered one (round 36, L-2).
        check_wall_budget(started, call)?;
        return Ok(labels_for(module, ids));
    }
    let paths = active_infinity::interop::value_paths(module);
    // Only a label that resolves back to the node is a name the caller may
    // receive: `@node[7]`, `@annotation[0]` and a stale dotted binding label
    // are arena positions (round 10, #4).
    let mut kept = Vec::new();
    for (index, id) in ids.into_iter().enumerate() {
        let named = match named_path(&paths, id) {
            Some(path) => structural_resolve(module, path)
                .is_some_and(|resolved| same_place(module, resolved, id)),
            None => false,
        };
        if named {
            kept.push(id);
        }
        // Resolving one label walks the arena: a wide table of aliases made
        // this O(ids x nodes) with no interim ceiling, on the dispatch thread
        // (round 34, M-1). Count every id walked, not every label kept: the
        // hostile case is a run of ids whose labels do not resolve
        // (round 35, M-1).
        if index % 64 == 63 {
            check_wall_budget(started, call)?;
        }
    }
    Ok(labels_from(module, &paths, kept))
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

/// A provider-side redaction fault, not a fault in the caller's payload.
///
/// Redacting a stored module can make two field names collide after the
/// replacement, which the encoder refuses. The stored module came from this
/// provider, so blaming the caller's payload with `rpc/payload` misreports it
/// (round 33, F5).
fn redaction_fault(error: Error) -> Error {
    match error {
        Error::Payload(_) => Error::Provider {
            code: "provider/redaction".to_string(),
        },
        other => other,
    }
}

/// Encode a module for an RPC payload with every secret replaced by the marker.
///
/// The RPC wire has no tag that carries secret bytes (`docs/spec/wire.md` §2.2),
/// so a module returned by `subgraph` or `patch` is a redacted projection: the
/// structure survives, the material does not. A caller that needs the raw module
/// moves it through a transport payload, not through a capability result.
/// Refuse a module whose field or binding name cannot be logged safely.
///
/// A field or binding name reaches a caller as a dotted label, and every other
/// caller-controlled name in the crate is bounded and de-formatted; one that
/// carries a newline could forge a log line at the receiver. Scrubbing the
/// label is not an option (it must stay resolvable), so the module is refused
/// at install (round 37, C).
fn check_names(module: &InfinityModule) -> Result<()> {
    let unprintable = |text: &str| {
        text.is_empty()
            || text.chars().any(|character| {
                character.is_control() || security::is_invisible_or_reordering(character)
            })
    };
    // The label format joins field names with `.`, so a dotted field name makes
    // a label name a different node than the one it describes (round 38, F4).
    // A binding name is a dotted path by design, so only the printability rule
    // applies to it.
    let bad_field = |text: &str| unprintable(text) || text.contains('.');
    for node in module.nodes() {
        match node {
            Inode::Table { fields } | Inode::SchemaTable { fields, .. }
                if fields.iter().any(|(name, _)| bad_field(name)) =>
            {
                return Err(Error::Payload(
                    "a module field name is not printable text".to_string(),
                ));
            }
            _ => {}
        }
    }
    if module.bindings().iter().any(|(name, _)| unprintable(name)) {
        return Err(Error::Payload(
            "a module binding name is not printable text".to_string(),
        ));
    }
    Ok(())
}

fn redacted_module_bytes(module: &InfinityModule) -> Result<Vec<u8>> {
    // One implementation, shared with the security helpers: a second copy of
    // the redactor would drift, and the one that drifted would be the leak.
    // An encode fault here is the provider's own reply, not the caller's
    // payload: blaming `rpc/payload` misreported a redaction collision as bad
    // input (round 32, #9; round 34, M-2 also maps the library redactor).
    let bytes = encode(module)
        .map_err(|error| redaction_fault(Error::Payload(error.code().to_string())))?;
    security::redact_module(&bytes).map_err(redaction_fault)
}

/// Strip the metadata a redacting cone must not carry.
///
/// An annotation's intent or constraint source is free text, and a binding is a
/// name that resolves to a node: both describe the cone, and the `annotations`
/// method already hides them for a tainted node. Keeping them in the bytes while
/// hiding them in the query made the two answers disagree (R-07 round 8, #3).
fn redact_cone_metadata(module: &mut InfinityModule, tainted: &BTreeSet<NodeId>) {
    // Only a rule on a tainted node describes secret material. Dropping every
    // rule made the cone disagree with the `annotations` method about a module
    // the caller was granted, and silently removed the constraints a receiver
    // should keep (round 9, #4). Annotation text that copies a secret literal is
    // redacted by the encoder before the marker pass.
    keep_annotations_outside(module, tainted);
    if tainted.is_empty() {
        return;
    }
    let kept: Vec<(String, NodeId)> = module
        .bindings()
        .iter()
        .filter(|(_, id)| !tainted.contains(id))
        .map(|(name, id)| (name.clone(), *id))
        .collect();
    module.clear_bindings();
    for (name, id) in kept {
        module.bind(name, id);
    }
}

/// Keep every annotation whose subject is not in the secret cone.
fn keep_annotations_outside(module: &mut InfinityModule, tainted: &BTreeSet<NodeId>) {
    let kept: Vec<(NodeId, AnnotationKind)> = module
        .annotations()
        .iter()
        .filter(|annotation| {
            // `@ai_immutable` is a boolean guard, not content: a redacted cone
            // must keep it, or the recipient may rewrite a node the module
            // marked immutable (round 37, B).
            matches!(annotation.kind, AnnotationKind::AiImmutable(_))
                || !tainted.contains(&annotation.node)
        })
        .map(|annotation| (annotation.node, annotation.kind.clone()))
        .collect();
    if kept.len() == module.annotations().len() {
        return;
    }
    module.clear_annotations();
    for (node, kind) in kept {
        module.annotate(node, kind);
    }
}

/// Node ids that are secrets or contain one, transitively.
fn tainted_nodes(module: &InfinityModule) -> BTreeSet<NodeId> {
    let count = module.node_count();
    let (_, dependents) = adjacency(module);
    // A monotone worklist: a node is tainted once, and taint only spreads to
    // its dependents. The earlier Kahn pass counted `children()` but walked
    // `edges()`, which also carries constraint edges, so a self-referential
    // constraint never reached zero and re-enqueued forever; a butterfly DAG
    // re-enqueued exponentially (R-07 round 10, high).
    let mut tainted = vec![false; count];
    let mut queue: std::collections::VecDeque<usize> = std::collections::VecDeque::new();
    for (index, node) in module.nodes().iter().enumerate() {
        if node.is_secret() || security::is_tainted_blob(node) {
            tainted[index] = true;
            queue.push_back(index);
        }
    }
    while let Some(index) = queue.pop_front() {
        for dependent in dependents.get(index).into_iter().flatten() {
            let target = dependent.index();
            if target < count && !tainted[target] {
                tainted[target] = true;
                queue.push_back(target);
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

/// Map an evaluator fault to the code a caller branches on.
///
/// Kept as one function so the classes cannot drift: a resource ceiling is this
/// provider's budget refusal, an evaluator encode failure is the Active bridge,
/// and anything else is a payload fault (round 39, L-2; round 40, R-07-5).
fn evaluator_fault(error: &active_infinity::Error) -> Error {
    match error {
        active_infinity::Error::Evaluation(code) if code.starts_with("active/X00") => {
            // The engine reports its ceilings as evaluation codes (X001 nodes
            // .. X006 value size); a caller branches on them and must not be
            // told this is a domain fault (round 19, #1).
            let kind = if code.contains("node") {
                "nodes"
            } else if code.contains("wall") {
                "wall"
            } else if code.contains("depth") {
                "depth"
            } else if code.contains("array") {
                "array_len"
            } else if code.contains("keys") {
                "keys"
            } else {
                "value"
            };
            Error::BudgetExceeded(kind)
        }
        active_infinity::Error::Evaluation(code) => Error::Domain(code),
        // A resource ceiling the evaluator hit is this provider's budget
        // refusal, not a payload fault: a caller branches on the two
        // differently (round 16, #1).
        active_infinity::Error::Limit { kind, .. } => {
            // Keep the caller's branch: the provider's own gates use `nodes`,
            // `depth` and `wall`, and an evaluator ceiling names the same
            // conditions (round 17, F4).
            let kind = if kind.contains("node") {
                "nodes"
            } else if kind.contains("depth") {
                "depth"
            } else if kind.contains("wall") {
                "wall"
            } else if kind.contains("array") {
                "array_len"
            } else if kind.contains("key") {
                // `annotation key bytes` is a key ceiling even though the word
                // does not start the label (round 31, F3).
                "keys"
            } else {
                // The provider's own vocabulary is closed; an unknown dimension
                // is the value budget.
                "value"
            };
            Error::BudgetExceeded(kind)
        }
        // The evaluator's own encode failure is a bridge fault (a schema type
        // the Active core cannot represent, secret material it refuses), not a
        // redaction collision; the redaction sites raise `provider/redaction`
        // themselves (round 39, L-2).
        active_infinity::Error::Encode(_) => Error::Domain("active/encode"),
        other => Error::Payload(other.code().to_string()),
    }
}

/// Evaluate a module for a caller, redacting first when the capability asks.
///
/// The engine has no notion of a secret literal: a plain `Str` that copies one
/// is an ordinary value, and evaluating it handed the text to a redacting
/// caller (R-07 round 9, high). The redacted copy is what a redacting caller
/// may see, and it is the same rule the cone bytes and the projections apply.
fn evaluate_for_caller(
    source: &InfinityModule,
    module: &InfinityModule,
    budget: active_core::Budget,
    redactor: &active_infinity::interop::Redactor,
) -> std::result::Result<(active_core::Value, Vec<active_core::Diagnostic>), active_infinity::Error>
{
    // The `active-core` bridge refuses a module that holds secret material: it
    // would have to hand the plaintext to every consumer (ADR-0010). So the
    // engine always runs on the redacted copy, and a secret becomes a marker.
    // A redacting capability and a plain one therefore see the same structure;
    // the marker is content-free for both, and `VALUE_MARKER` maps it back to
    // `Value::Secret` so the caller can tell it from data.
    if redactor.is_empty() && !security::module_holds_secret(module) {
        return active_infinity::interop::evaluate(module, budget);
    }
    // The placeholder is not always `***SECRET***`: when a secret is a
    // substring of the marker the redactor substitutes the empty string, and
    // mapping only the marker left `Text("")` (round 10, #5). Read what the
    // redactor actually wrote for a secret node.
    let mut redacted = module.clone();
    security::redact_derived(&mut redacted, redactor)
        .map_err(|error| active_infinity::Error::Encode(error.code()))?;
    // Every text the redactor wrote for a secret node: the marker for a normal
    // secret, the empty string when a secret is a substring of the marker. One
    // placeholder from the first secret missed the second case when a module
    // held both (round 12, F2).
    // A restricted cone no longer holds the secret node, so the placeholders are
    // read from a redacted copy of the source (round 15, #6).
    let mut redacted_source = source.clone();
    security::redact_derived(&mut redacted_source, redactor)
        .map_err(|error| active_infinity::Error::Encode(error.code()))?;
    let placeholders: BTreeSet<String> = (0..source.node_count())
        .map(|index| NodeId(index as u32))
        .filter(|id| source.get(*id).is_some_and(|node| node.is_secret()))
        .filter_map(|id| match redacted_source.get(id) {
            Some(Inode::Str(text)) => Some(text.clone()),
            _ => None,
        })
        .collect();
    let placeholders = if placeholders.is_empty() {
        // A patch can remove the last secret node, so the source may name none
        // while the install-time redactor still hides literals. Both strings
        // the redactor can write for a secret map back to `Value::Secret`;
        // marking an empty public string as hidden is the documented
        // fail-closed direction (round 15, #6; round 27, critical).
        [
            active_infinity::interop::SECRET_MARKER.to_string(),
            String::new(),
        ]
        .into_iter()
        .collect()
    } else {
        placeholders
    };
    let (value, diagnostics) = active_infinity::interop::evaluate(&redacted, budget)?;
    // The marking walk is recursive; the depth gate is iterative and must run
    // first, or a deep value aborts instead of being refused (round 12, F5).
    // The value goes back unmarked in that case: the caller's own gate answers
    // `rpc/budget-exceeded`, which is the code every other depth refusal uses
    // (round 14, L3).
    if security::active_value_too_deep(&value, crate::wire::MAX_VALUE_DEPTH) {
        return Ok((value, diagnostics));
    }
    Ok((mark_secret_texts(value, &placeholders), diagnostics))
}

/// Replace a text equal to the redaction marker with the structural marker.
///
/// The engine has no secret value, so the marker comes back as text; a caller
/// that reads a `Value::Secret` knows the field was secret, and a caller that
/// reads `"***SECRET***"` might treat it as data.
fn mark_secret_texts(
    value: active_core::Value,
    placeholders: &BTreeSet<String>,
) -> active_core::Value {
    use active_core::Value as CoreValue;
    match value {
        // Any placeholder stands for a secret. A key that matches means the
        // table's shape itself was secret-derived, so the whole table collapses
        // like a value that carries one (round 12, F6).
        CoreValue::Table(entries)
            if entries
                .iter()
                .any(|(key, _)| placeholders.contains(key.as_str())) =>
        {
            CoreValue::Secret(active_infinity::interop::SECRET_MARKER.to_string())
        }
        CoreValue::Table(entries) => CoreValue::Table(
            entries
                .into_iter()
                .map(|(key, value)| (key, mark_secret_texts(value, placeholders)))
                .collect(),
        ),
        CoreValue::String(text) if placeholders.contains(text.as_str()) => {
            CoreValue::Secret(active_infinity::interop::SECRET_MARKER.to_string())
        }
        // A unit is text too: one that matches a placeholder means the value's
        // shape came from a secret, as with a table key (round 13, L1).
        CoreValue::Quantity(_, unit) if placeholders.iter().any(|text| *text == unit.suffix()) => {
            CoreValue::Secret(active_infinity::interop::SECRET_MARKER.to_string())
        }
        CoreValue::Array(items) => CoreValue::Array(
            items
                .into_iter()
                .map(|item| mark_secret_texts(item, placeholders))
                .collect(),
        ),
        other => other,
    }
}

fn restrict(module: &InfinityModule, node: NodeId) -> Result<InfinityModule> {
    // A constraint is part of the rule, not decoration: its expression node
    // travels with the annotated node, or a projected module would state a
    // constraint whose expression is missing. `InfinityModule::edges` lists
    // each expression as a dependency of its subject, and `adjacency` reads
    // those edges, so one BFS covers the whole chain. `interop::subgraph` is
    // deliberately not used: its adjacency reads only value children, so it
    // dropped every expression and the old code compensated with a fixpoint
    // that rebuilt that adjacency per newly discovered root with no ceiling
    // (round 25, #1).
    let (dependencies, _) = adjacency(module);
    let mut cone: BTreeSet<NodeId> = BTreeSet::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if !cone.insert(current) {
            continue;
        }
        if let Some(next) = dependencies.get(current.index()) {
            stack.extend(next.iter().copied());
        }
    }
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
        *sub.node_mut(target)
            .map_err(|error| Error::Payload(error.code().to_string()))? = rewritten;
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
                // The annotated node is in the cone but its expression is not:
                // shipping the subject without its rule is a fail-open
                // projection. `adjacency` follows the constraint edge, so this
                // only happens for an arena whose mirror edge is missing
                // (round 42, F6).
                let Some(expr) = map.get(expr).copied() else {
                    return Err(Error::Payload("annotation escaped the cone".to_string()));
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
        // `patch` skips a `Value::Path` replacement (the first path names the
        // target), so a path never becomes text: a future refactor that removed
        // that filter should decide the behaviour here explicitly
        // (round 36, L-4).
        Value::Path(_) => None,
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
        .or_else(|| structural_resolve(module, path))
}

/// Node ids in a module's dependency cone, for tests.
pub fn cone_ids(module: &InfinityModule, path: &str) -> Result<Vec<NodeId>> {
    let node = active_infinity::interop::resolve_path(module, path)
        .ok_or(Error::InvalidArgument("path does not resolve"))?;
    Ok(subgraph(module, &[node]))
}

#[cfg(test)]
mod evaluator_fault_tests {
    use super::{evaluator_fault, redaction_fault};
    use crate::error::Error;

    #[test]
    fn the_evaluator_ceiling_classes_keep_their_caller_branch() {
        let nodes = evaluator_fault(&active_infinity::Error::Evaluation("active/X001 nodes"));
        assert_eq!(nodes.code(), "rpc/budget-exceeded");
        assert!(nodes.to_string().contains("nodes"), "{nodes}");

        let array = evaluator_fault(&active_infinity::Error::Evaluation(
            "active/X004 array length",
        ));
        assert!(array.to_string().contains("array_len"), "{array}");

        let keys = evaluator_fault(&active_infinity::Error::Limit {
            kind: "annotation key bytes",
            limit: 1,
        });
        assert!(keys.to_string().contains("keys"), "{keys}");

        let unknown = evaluator_fault(&active_infinity::Error::Limit {
            kind: "unheard-of",
            limit: 1,
        });
        assert!(unknown.to_string().contains("value"), "{unknown}");
    }

    #[test]
    fn an_evaluator_encode_failure_is_a_domain_fault() {
        // The round-39 split: a bridge encode failure is this provider's
        // domain, not a redaction collision (round 40, R-07-5).
        let error = evaluator_fault(&active_infinity::Error::Encode("duplicate key"));
        assert_eq!(error.code(), "rpc/domain", "{error}");
        assert!(error.to_string().contains("active/encode"), "{error}");
    }

    #[test]
    fn an_evaluator_diagnostic_and_a_framing_fault_stay_distinct() {
        let diagnostic = evaluator_fault(&active_infinity::Error::Evaluation("active/T001"));
        assert_eq!(diagnostic.code(), "rpc/domain", "{diagnostic}");
        let framing = evaluator_fault(&active_infinity::Error::Magic);
        assert_eq!(framing.code(), "rpc/payload", "{framing}");
    }

    #[test]
    fn a_redaction_collision_is_the_providers_fault() {
        let error = redaction_fault(Error::Payload("two fields collide".to_string()));
        assert_eq!(error.code(), "rpc/provider", "{error}");
        assert!(error.to_string().contains("provider/redaction"), "{error}");
        let other = redaction_fault(Error::BudgetExceeded("byte"));
        assert_eq!(other.code(), "rpc/budget-exceeded");
    }
}
