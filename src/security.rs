//! Security helpers shared by providers and transports.
//!
//! Three rules, enforced here so no provider has to remember them:
//!
//! 1. **Secrets never cross the boundary as content.** An evaluated secret
//!    becomes [`Value::Secret`], a marker; there is no variant that carries the
//!    bytes.
//! 2. **Redaction is monotone.** A redacting capability sees paths but not
//!    secret-cone labels; a non-redacting one still never sees values.
//! 3. **Diagnostics are value-free.** Provider errors carry stable codes.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{Error, Result};
use crate::value::Value;

/// Marker used wherever a secret would otherwise appear.
///
/// The library's constant, not a copy: a copy that drifted would make the
/// map-key gates miss the marker the library itself writes
/// (R-16 round 8, #2).
pub const SECRET_MARKER: &str = active_infinity::interop::SECRET_MARKER;

/// True when an evaluator value is deeper than `limit`.
///
/// [`from_active_value`] recurses, so a result the wire could never carry is
/// refused before the conversion: the evaluator's own ceiling can be larger than
/// the wire's, and converting first would walk (and possibly overflow on) a value
/// that can never leave the kernel (R-07 round 7, #4).
pub fn active_value_too_deep(value: &active_core::Value, limit: usize) -> bool {
    use active_core::Value as ActiveValue;
    // The root sits at depth 0, the depth the conversion gives it: rooting at
    // 1 refused a wire-legal 64-container value (R-16 round 7, L-3).
    let mut work = vec![(value, 0usize)];
    while let Some((value, depth)) = work.pop() {
        match value {
            // The conversion replaces a container at the cap with `Null`, so a
            // value that would reach that point is refused here instead of
            // being silently truncated.
            ActiveValue::Array(items) => {
                if depth >= limit {
                    return true;
                }
                work.extend(items.iter().map(|item| (item, depth.saturating_add(1))));
            }
            ActiveValue::Table(entries) => {
                if depth >= limit {
                    return true;
                }
                work.extend(
                    entries
                        .iter()
                        .map(|(_, item)| (item, depth.saturating_add(1))),
                );
            }
            // These two convert into a synthetic map at the Active node's own
            // depth, and the map's entries are one level below it (round 17,
            // F5): a duration at the cap would need a child past the wire's.
            ActiveValue::DurationMs(_) | ActiveValue::Quantity(..)
                if depth.saturating_add(1) > limit =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

/// Convert an evaluated Active value into an RPC value.
///
/// Secrets and tainted blobs collapse to [`Value::Secret`]: the RPC layer never
/// carries secret material, only the fact that something is secret.
pub fn from_active_value(value: &active_core::Value) -> Value {
    use active_core::Value as ActiveValue;

    /// One unit of work: convert a value at a depth, or assemble the children
    /// already on the output stack.
    enum Frame<'a> {
        Value(&'a ActiveValue, usize),
        Array(usize),
        Table(Vec<String>, usize),
    }

    /// The same ceiling the wire applies: a deeper value cannot be represented,
    /// and a value deeper than this would also overflow the stack when it is
    /// dropped (R-16 round 5, #6).
    const LIMIT: usize = crate::wire::MAX_VALUE_DEPTH;

    // An explicit stack: this used to recurse, and a value deeper than the wire
    // cap overflowed the Rust stack, which aborts the process where no
    // `catch_unwind` reaches (R-16 round 5, #6).
    let mut work = vec![Frame::Value(value, 0)];
    let mut out: Vec<Value> = Vec::new();
    while let Some(frame) = work.pop() {
        match frame {
            Frame::Value(ActiveValue::Array(items), depth) if depth >= LIMIT => {
                // Past the ceiling the shape is truncated to the cap rather
                // than carried deeper: the wire cannot express it either.
                out.push(Value::Null);
                let _ = items;
            }
            Frame::Value(ActiveValue::Table(entries), depth) if depth >= LIMIT => {
                out.push(Value::Null);
                let _ = entries;
            }
            Frame::Value(ActiveValue::Array(items), depth) => {
                work.push(Frame::Array(items.len()));
                for item in items.iter().rev() {
                    work.push(Frame::Value(item, depth + 1));
                }
            }
            Frame::Value(ActiveValue::Table(entries), depth) => {
                let keys: Vec<String> = entries.iter().map(|(key, _)| key.clone()).collect();
                work.push(Frame::Table(keys, entries.len()));
                for (_key, item) in entries.iter().rev() {
                    work.push(Frame::Value(item, depth + 1));
                }
            }
            Frame::Value(scalar, _) => out.push(scalar_value(scalar)),
            Frame::Array(count) => {
                let items = out.split_off(out.len() - count);
                out.push(Value::List(items));
            }
            Frame::Table(keys, count) => {
                let values = out.split_off(out.len() - count);
                out.push(Value::Map(keys.into_iter().zip(values).collect()));
            }
        }
    }
    out.pop().unwrap_or(Value::Null)
}

/// One non-container Active value as an RPC value.
///
/// Secrets and tainted blobs collapse to [`Value::Secret`]: the RPC layer never
/// carries secret material, only the fact that something is secret.
fn scalar_value(value: &active_core::Value) -> Value {
    use active_core::Value as ActiveValue;
    match value {
        ActiveValue::Null => Value::Null,
        ActiveValue::Bool(flag) => Value::Bool(*flag),
        ActiveValue::Int(number) => Value::Int(*number),
        ActiveValue::Float(number) => Value::Float(*number),
        ActiveValue::String(text) => Value::Text(text.clone()),
        ActiveValue::DurationMs(ms) => Value::Map(
            // A duration past `i64::MAX` saturates: a cast wraps negative and a
            // consumer that reads `ms` as a deadline misbehaves.
            [(
                "ms".to_string(),
                Value::Int(i64::try_from(*ms).unwrap_or(i64::MAX)),
            )]
            .into_iter()
            .collect(),
        ),
        ActiveValue::Quantity(amount, unit) => Value::Map(
            [
                ("value".to_string(), Value::Float(*amount)),
                ("unit".to_string(), Value::Text(unit.suffix())),
            ]
            .into_iter()
            .collect(),
        ),
        // Containers never reach here: `from_active_value` handles them with the
        // explicit stack. A nested container in this position would be a bug in
        // that walk, and `Null` is the safe answer for it.
        ActiveValue::Array(_) | ActiveValue::Table(_) => Value::Null,
        ActiveValue::Secret(_) => Value::Secret,
    }
}

/// Redact labels that name nodes in the secret cone.
///
/// A redacting capability still learns that a path is tainted, but not which
/// path or how many: the answer collapses to a single marker.
pub fn redact_cone_labels(labels: Vec<String>, tainted: &BTreeSet<String>) -> Vec<String> {
    if labels.iter().any(|label| tainted.contains(label)) {
        vec![SECRET_MARKER.to_string()]
    } else {
        labels
    }
}

/// Redact a value tree that may contain secret markers because a path is
/// tainted (used when a capability is redacting but a provider already built
/// labels).
pub fn redact_value(value: Value) -> Value {
    // An explicit stack, like `Value::shape`: a provider-built value can be
    // deeper than the Rust stack, and the walk that exists to contain a hostile
    // provider must not be the thing that aborts the process (F-04).
    enum Task {
        Visit(Value),
        AssembleList(usize),
        AssembleMap(Vec<String>, usize),
    }
    let mut tasks = vec![Task::Visit(value)];
    let mut done: Vec<Value> = Vec::new();
    while let Some(task) = tasks.pop() {
        match task {
            Task::Visit(value) => match value {
                Value::Secret => done.push(Value::Secret),
                Value::List(items) => {
                    let count = items.len();
                    tasks.push(Task::AssembleList(count));
                    // Children are visited in order: push them reversed so the
                    // first one is on top of the stack.
                    for item in items.into_iter().rev() {
                        tasks.push(Task::Visit(item));
                    }
                }
                // A key is text too: a provider that puts a secret copy or the
                // marker in a `Value::Map` key would otherwise pass through
                // untouched. The whole map collapses to the marker, because
                // renaming a key could collide with another entry.
                Value::Map(entries) => {
                    if entries.keys().any(|key| key.contains(SECRET_MARKER)) {
                        done.push(Value::Secret);
                        continue;
                    }
                    let count = entries.len();
                    let keys: Vec<String> = entries.keys().cloned().collect();
                    tasks.push(Task::AssembleMap(keys, count));
                    for value in entries.into_values().rev() {
                        tasks.push(Task::Visit(value));
                    }
                }
                // A text that *is* the marker (or that embeds it) stays text:
                // the marker is content-free, and a provider that already
                // redacted its answer returns it as a label. Collapsing it here
                // turned `["***SECRET***"]` into `[Secret]` and made redaction
                // destroy its own output. Secret *bytes* in plain text are the
                // provider's fault and are what the codec's fragment checks
                // refuse on encode.
                Value::Text(text) => done.push(Value::Text(text)),
                // A module is the only variant that carries arbitrary bytes, so
                // it is the only one that can smuggle a secret node. Rewriting
                // beats passing it through: a redacting caller must not receive
                // the original bytes. A module is either an Infinity image or
                // opaque bytes a provider produced (a WASM tool's binary
                // output). Only an image has secret structure; refusing an
                // opaque blob here turned every binary tool result into a
                // marker.
                Value::Module(bytes) => done.push(match redact_module(&bytes) {
                    Ok(redacted) => Value::Module(redacted),
                    Err(_) if !claims_infinity_image(&bytes) => Value::Module(bytes),
                    // An image that cannot be redacted is not safe to hand back.
                    // This arm is reachable now: before the predicate was
                    // shared, a magic-prefixed payload that failed to decode was
                    // returned verbatim to a redacting caller (R-16 round 6, #1).
                    Err(_) => Value::Secret,
                }),
                other => done.push(other),
            },
            Task::AssembleList(count) => {
                let start = done.len().saturating_sub(count);
                let items = done.split_off(start);
                done.push(Value::List(items));
            }
            Task::AssembleMap(keys, count) => {
                let start = done.len().saturating_sub(count);
                let values = done.split_off(start);
                let entries: BTreeMap<String, Value> = keys.into_iter().zip(values).collect();
                done.push(Value::Map(entries));
            }
        }
    }
    done.pop().unwrap_or(Value::Null)
}

/// Rewrite every secret node of an Active Infinity module to the marker.
///
/// One implementation for [`redact_value`] and the domain provider: two would
/// drift, and the one that drifted would be the leak.
///
/// Field, binding and unit *names* are not re-validated here: the domain
/// provider is the name authority and refuses an unrepresentable name at
/// install, and this helper's callers hand it a module the provider accepted
/// (R-16 round 17, F14). A mid-redaction failure is reported as a payload error;
/// the domain provider maps it to `provider/redaction` (F15).
pub fn redact_module(bytes: &[u8]) -> Result<Vec<u8>> {
    let module =
        active_infinity::decode(bytes).map_err(|error| Error::Payload(error.code().to_string()))?;
    // The raw image's own content address: a provider can copy it into a text,
    // and it is an equality oracle over the secret heap just like a blob's
    // (R-16 round 13, F2).
    let own = active_infinity::content_hash(bytes).ok();
    if !module_holds_secret(&module) {
        // Nothing to rewrite. The bytes go back untouched, so a non-secret
        // streamed module keeps its flag and its identity (R-16 round 7, L-4),
        // after the canonical proof the egress owes the caller (L-2).
        check_module_payload(bytes)?;
        return Ok(bytes.to_vec());
    }
    // One implementation, in the library that holds the secret heap: it
    // canonicalizes first (so the codec can refuse free text or a binary copy
    // that carries a secret literal, and can redact the metadata while the
    // literals are still named), then rewrites the value plane, where a mere
    // `Str`, `Ident`, `Env` name, field name or binding name can hold a copy.
    // Active RPC cannot see an `Inode::Secret`'s bytes, so a local pass would
    // miss every copy the library itself redacts in its projections.
    let redacted = active_infinity::interop::redact_image(bytes)
        .map_err(|error| Error::Payload(error.code().to_string()))?;
    // Provenance names the pre-redaction image: `parent` is its content
    // address and a `Hash` entry is another one. The library drops an entry
    // that *is* a secret literal, not the address of the secret-bearing
    // image, and either address is an offline equality oracle over the secret
    // heap. The whole provenance goes, exactly as the domain provider does on
    // every secret-bearing reply (R-16 round 7, M-1; R-07 round 13, H2).
    let mut module = active_infinity::decode(&redacted)
        .map_err(|error| Error::Payload(error.code().to_string()))?;
    // The decoded provenance names its parent and Hash entries; both are
    // sticky oracles even though the provenance is about to be dropped
    // (R-16 round 17, F1).
    let mut extra_vec: Vec<[u8; 32]> = own.into_iter().collect();
    extra_vec.extend(provenance_addresses(&module));
    module.set_provenance(None);
    let addresses = sanitize_tainted_blobs(&mut module, &extra_vec)?;

    let redacted = active_infinity::encode(&module)
        .map_err(|error| Error::Payload(error.code().to_string()))?;
    check_module_payload(&redacted)?;
    assert_no_address_bytes(&redacted, &addresses)?;
    Ok(redacted)
}

/// Refuse a redacted image that still carries one of its own addresses.
///
/// The field pass — the library's, then this module's — is a list, and a list
/// drifts: a new carrier, a payload, an extension or a future `Inode` variant
/// can hold the address while every arm says it cannot. The encoded bytes are
/// the one thing the caller receives, so the last check reads them: an address
/// in raw or hex form means the projection failed closed (R-16 round 14, F1-F4).
fn assert_no_address_bytes(bytes: &[u8], addresses: &BTreeSet<[u8; 32]>) -> Result<()> {
    if addresses.is_empty() {
        return Ok(());
    }
    // One pass, not one scan per address: O(bytes) per form instead of
    // O(addresses x bytes), which was minutes on a crafted image and ran
    // before any wall check (R-16 round 17, F2). The all-zero hash is the
    // redaction sentinel and cannot be a real credential address
    // (R-16 round 17, F10).
    let raw: BTreeSet<[u8; 32]> = addresses
        .iter()
        .copied()
        .filter(|address| *address != [0u8; 32])
        .collect();
    if raw.is_empty() {
        return Ok(());
    }
    let hex = address_keys_from_raw(&raw);
    if bytes_carry_an_address(bytes, &hex, &raw) {
        return Err(Error::Provider {
            code: "provider/redaction".to_string(),
        });
    }
    Ok(())
}

/// Refuse encoded projection bytes that carry one of `extra`'s addresses.
///
/// The field passes and `redact_module`'s own assertion know the blobs they
/// sanitized; a domain projection also has to answer for the caller's set (the
/// sticky secret addresses and the parent hash) and for payloads and extensions,
/// which the field walk does not read (R-16 round 16, F3).
pub(crate) fn assert_module_bytes(bytes: &[u8], extra: &[[u8; 32]]) -> Result<()> {
    if extra.is_empty() {
        return Ok(());
    }
    let addresses: BTreeSet<[u8; 32]> = extra.iter().copied().collect();
    assert_no_address_bytes(bytes, &addresses)
}

/// The hex keys of a raw address set.
fn address_keys_from_raw(raw: &BTreeSet<[u8; 32]>) -> BTreeSet<[u8; 64]> {
    raw.iter().map(hex_key).collect()
}

/// A redactor for the literals `module` names.
///
/// A cone, a restricted subtree or a scoped evaluation no longer holds the
/// secret node, so the redactor has to come from the module the capability was
/// installed from. The handle carries the text; nothing here reads it back.
pub fn redactor_for(
    module: &active_infinity::InfinityModule,
) -> active_infinity::interop::Redactor {
    active_infinity::interop::Redactor::for_module(module)
}

/// Apply a redactor to a derived module (a cone, a restricted subtree).
///
/// The wire has no tag that carries secret bytes, so every cone is redacted: a
/// plain `Str` that copies a secret literal is an ordinary node to the codec and
/// used to travel verbatim (R-07 round 9, high).
pub fn redact_derived(
    module: &mut active_infinity::InfinityModule,
    redactor: &active_infinity::interop::Redactor,
) -> Result<()> {
    redact_derived_with(module, redactor, &[])
}

/// [`redact_derived`] with extra addresses to scrub.
///
/// The domain passes the pre-patch content address: a text that quotes it is a
/// lineage oracle even though it names no blob (R-16 round 13, F3).
///
/// This function does not touch `Provenance`: a caller that returns the module
/// must drop or scrub it first (the domain provider does on every secret-bearing
/// reply) (R-16 round 17, F16).
pub fn redact_derived_with(
    module: &mut active_infinity::InfinityModule,
    redactor: &active_infinity::interop::Redactor,
    extra: &[[u8; 32]],
) -> Result<()> {
    redactor
        .redact(module)
        .map_err(|error| Error::Payload(error.code().to_string()))?;
    // The library redacts a tainted blob's media type, not its content
    // address; a cone or a patched reply is still a projection that leaves the
    // kernel (R-16 round 9, F-2).
    sanitize_tainted_blobs(module, extra)?;
    Ok(())
}

/// True when a payload claims to be an Infinity image.
///
/// A payload that decodes is one. A payload that starts with the image magic but
/// does not decode also claims to be one, and it cannot be proven secret-free:
/// a corrupted secret-bearing image would otherwise be classified opaque and
/// pass every gate. The two gates (secret detection and redaction) must use the
/// same predicate, or the mode that promises confidentiality treats the shape
/// the other mode refuses (R-16 rounds 5-6).
pub(crate) fn claims_infinity_image(bytes: &[u8]) -> bool {
    is_infinity_image(bytes) || bytes.starts_with(&active_infinity::MAGIC)
}

/// What a `Value::Module` payload is, decided by one decode.
///
/// The egress gates ask this once instead of walking the same bytes three
/// times: every pass is O(bytes) over provider- or guest-controlled output
/// (R-16 round 8, #4).
enum ModuleKind {
    /// Not an image, and does not claim to be one: a provider's opaque blob.
    Opaque,
    /// A decodable image, with whether it holds a secret node.
    Image { secret: bool },
    /// Starts with the image magic but does not decode. It cannot be proven
    /// secret-free, so every gate fails closed on it (R-16 round 5).
    Corrupt,
}

fn inspect_module(bytes: &[u8]) -> ModuleKind {
    match active_infinity::decode(bytes) {
        Ok(module) => ModuleKind::Image {
            secret: module_holds_secret(&module),
        },
        Err(_) if bytes.starts_with(&active_infinity::MAGIC) => ModuleKind::Corrupt,
        Err(_) => ModuleKind::Opaque,
    }
}

/// True when a decoded module holds secret material.
///
/// A `Secret`/`SecretRef` node is the obvious case. A **tainted blob** is the
/// other: its bytes are secret-derived and its `hash` is a content address over
/// them, which the codec keeps through redaction (R-16 round 9, F-2).
pub(crate) fn module_holds_secret(module: &active_infinity::InfinityModule) -> bool {
    (0..module.node_count()).any(|index| {
        module
            .get(active_infinity::NodeId(index as u32))
            // A node the decoder counts but cannot materialise cannot be
            // proven secret-free, so it fails closed (round 3, F-1).
            .is_none_or(|node| node.is_secret() || is_tainted_blob(node))
    })
}

/// Every tainted blob's address in `module`.
///
/// The domain keeps this set for the life of a slot: a patch can remove the
/// blob, and a projection that recomputes the set from the post-write module
/// then finds nothing to scrub while the address is still in a binding, a
/// constraint or the provenance (R-16 round 14, F2).
pub(crate) fn tainted_blob_addresses(
    module: &active_infinity::InfinityModule,
) -> BTreeSet<[u8; 32]> {
    let mut addresses = BTreeSet::new();
    for index in 0..module.node_count() {
        let id = active_infinity::NodeId(index as u32);
        if let Some(active_infinity::Inode::Blob { hash, .. }) = module.get(id) {
            if is_tainted_blob(module.get(id).expect("the node was just read")) {
                addresses.insert(*hash);
            }
        }
    }
    addresses
}

/// The content addresses a module's provenance names.
///
/// A parent image and a `Hash` entry are offline equality oracles over the
/// pre-redaction heap, exactly like a tainted blob's hash: a secret-bearing
/// module must treat them as sticky secret addresses (R-16 round 17, F1).
pub(crate) fn provenance_addresses(module: &active_infinity::InfinityModule) -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    if let Some(provenance) = module.provenance() {
        if let Some(parent) = provenance.parent {
            out.push(parent);
        }
        for entry in &provenance.entries {
            if let active_infinity::ProvValue::Hash(hash) = entry.value {
                out.push(hash);
            }
        }
    }
    out
}

pub(crate) fn is_tainted_blob(node: &active_infinity::Inode) -> bool {
    matches!(node, active_infinity::Inode::Blob { tainted: true, .. })
}

/// Strip every secret-derived field from a tainted blob in a projection.
///
/// A tainted blob's hash is `blake3(secret bytes)` and its size is a length
/// signal; the library's *image* redactor leaves all of the fields alone (only
/// its JSON projection writes the marker), so this pass drops the address, the
/// size, any payload and the media type, replaces every annotation or text that
/// names those addresses, and clears the taint flag: what remains carries no
/// secret-derived material, so a non-redacting caller can receive it
/// (R-16 rounds 9-13).
pub(crate) fn sanitize_tainted_blobs(
    module: &mut active_infinity::InfinityModule,
    extra: &[[u8; 32]],
) -> Result<BTreeSet<[u8; 32]>> {
    let mut doomed: BTreeSet<active_infinity::NodeId> = BTreeSet::new();
    let mut raw: BTreeSet<[u8; 32]> = extra.iter().copied().collect();
    let mut addresses = address_keys(extra);
    for index in 0..module.node_count() {
        let id = active_infinity::NodeId(index as u32);
        if module.get(id).is_some_and(is_tainted_blob) {
            doomed.insert(id);
            if let Some(active_infinity::Inode::Blob { hash, .. }) = module.get(id) {
                addresses.insert(hex_key(hash));
                raw.insert(*hash);
            }
        }
    }
    // A second untainted blob with the same hash is the same address, and one
    // whose payload or media type carries it is the same oracle. Both are
    // doomed too (R-16 round 14, F4). With no address to look for there is
    // nothing this pass can find, and skipping it keeps a public module with a
    // huge payload from being scanned on every projection
    // (R-16 round 17, F8).
    if addresses.is_empty() && raw.is_empty() {
        return Ok(raw);
    }
    for index in 0..module.node_count() {
        let id = active_infinity::NodeId(index as u32);
        let Some(active_infinity::Inode::Blob {
            hash,
            media_type,
            payload,
            ..
        }) = module.get(id)
        else {
            continue;
        };
        let duplicate = addresses.contains(&hex_key(hash));
        let media = text_names_an_address(media_type, &addresses);
        let binary = payload
            .as_deref()
            .is_some_and(|bytes| bytes_carry_an_address(bytes, &addresses, &raw));
        if duplicate || media || binary {
            addresses.insert(hex_key(hash));
            raw.insert(*hash);
            doomed.insert(id);
        }
    }
    if doomed.is_empty() && addresses.is_empty() {
        return Ok(raw);
    }
    // A text copy of an address carries what the blob fields no longer do. The
    // library's redactor rewrites secret literals, not an address the provider
    // copied into a string, an identifier, an env name, a field key or a
    // literal interpolation (R-16 round 13, F1).
    scrub_text_copies(module, &addresses, &raw)?;
    // An annotation is free text about its subject: one attached to the blob,
    // or one whose text quotes the address, carries what the fields no longer
    // do. An `AiImmutable` flag carries no text, so it stays (R-16 rounds 10-13).
    let kept: Vec<active_infinity::Annotation> = module
        .annotations()
        .iter()
        .filter(|annotation| {
            if doomed.contains(&annotation.node) {
                return annotation_text(&annotation.kind).is_none();
            }
            match annotation_text(&annotation.kind) {
                Some(text) => !text_names_an_address(text, &addresses),
                None => true,
            }
        })
        .cloned()
        .collect();
    module.clear_annotations();
    for annotation in kept {
        module.annotate(annotation.node, annotation.kind);
    }
    for id in doomed {
        let Ok(node) = module.node_mut(id) else {
            continue;
        };
        if let active_infinity::Inode::Blob {
            hash,
            size,
            tainted,
            media_type,
            payload,
            ..
        } = node
        {
            *hash = [0u8; 32];
            *size = 0;
            *payload = None;
            *tainted = false;
            // The codec's own JSON projection writes the marker for a tainted
            // blob's media type; use the same placeholder (R-16 round 13, F6).
            *media_type = SECRET_MARKER.to_string();
        }
    }
    // An extension payload is opaque to the module's own redactor: a copy there
    // survives every field pass, so the extension is dropped rather than edited
    // (its bytes are the value) (R-16 round 14, F4).
    let extensions = module.extensions().to_vec();
    if extensions
        .iter()
        .any(|(_, bytes)| bytes_carry_an_address(bytes, &addresses, &raw))
    {
        let kept: Vec<(u64, Vec<u8>)> = extensions
            .into_iter()
            .filter(|(_, bytes)| !bytes_carry_an_address(bytes, &addresses, &raw))
            .collect();
        module.set_extensions(kept);
    }
    Ok(raw)
}

/// The 64-byte lowercase hex key of a hash.
fn hex_key(hash: &[u8; 32]) -> [u8; 64] {
    let hex = active_infinity::ir::hash_hex(hash);
    let mut key = [0u8; 64];
    // The formatter produces 64 lowercase hex characters. A shorter one leaves
    // a zero tail rather than panicking the way `copy_from_slice` on a
    // mismatched length would; a zero key matches no text, so the only effect
    // is a missed scrub, not an over-scrub (R-16 round 14, F9).
    let bytes = hex.as_bytes();
    let len = bytes.len().min(64);
    key[..len].copy_from_slice(&bytes[..len]);
    key
}

/// The addresses to scrub: the caller's extra hashes, lowercased by
/// [`hex_key`].
fn address_keys(extra: &[[u8; 32]]) -> BTreeSet<[u8; 64]> {
    extra.iter().map(hex_key).collect()
}

/// Replace the address in every text carrier, in place.
///
/// The round-13 pass covered `Str`, `Ident`, `Env`, table keys, interpolated
/// literals and `SchemaField.deprecated`; a binding name, a constraint, an enum
/// member, a unit name, a patch path, a schema type list or a blob media type
/// carried the same address untouched (R-16 round 14, F1). The text is rewritten
/// rather than the node replaced, so a `SchemaField` keeps its constraints and a
/// table keeps its shape (F6).
fn scrub_text_copies(
    module: &mut active_infinity::InfinityModule,
    addresses: &BTreeSet<[u8; 64]>,
    raw: &BTreeSet<[u8; 32]>,
) -> Result<()> {
    if addresses.is_empty() {
        return Ok(());
    }
    let bindings: Vec<(String, active_infinity::NodeId)> = module.bindings().to_vec();
    let mut renamed: Vec<(String, active_infinity::NodeId)> = Vec::with_capacity(bindings.len());
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (name, id) in bindings {
        let name = scrub_addresses(&name, addresses);
        if !seen.insert(name.clone()) {
            // Two names that scrub to one would silently drop a binding: the
            // projection's shape changed. Fail closed instead
            // (R-16 round 16, F8).
            return Err(redaction_failure());
        }
        renamed.push((name, id));
    }
    module.clear_bindings();
    for (name, id) in renamed {
        module.bind(name, id);
    }
    for index in 0..module.node_count() {
        let id = active_infinity::NodeId(index as u32);
        let Ok(node) = module.node_mut(id) else {
            continue;
        };
        match node {
            active_infinity::Inode::Str(text) | active_infinity::Inode::Ident(text) => {
                *text = scrub_addresses(text, addresses);
            }
            active_infinity::Inode::Env { name, .. } => {
                *name = scrub_addresses(name, addresses);
            }
            active_infinity::Inode::Table { fields }
            | active_infinity::Inode::SchemaTable { fields, .. } => {
                scrub_field_keys(fields, addresses)?;
            }
            active_infinity::Inode::Interpolate { parts } => {
                for part in parts.iter_mut() {
                    if let active_infinity::InterpPart::Literal(text) = part {
                        *text = scrub_addresses(text, addresses);
                    }
                }
            }
            active_infinity::Inode::Constrained { constraint, .. } => match constraint {
                active_infinity::Constraint::Enum(members) => {
                    let mut seen = BTreeSet::new();
                    for member in members.iter_mut() {
                        *member = scrub_addresses(member, addresses);
                        if !seen.insert(member.clone()) {
                            // Two members that scrub to one change the
                            // projection's meaning (R-16 round 17, F11).
                            return Err(redaction_failure());
                        }
                    }
                }
                active_infinity::Constraint::Pattern(text)
                | active_infinity::Constraint::Custom(text) => {
                    *text = scrub_addresses(text, addresses);
                }
                active_infinity::Constraint::MinMax { .. } | active_infinity::Constraint::Odd => {}
            },
            active_infinity::Inode::Patch(operation) => match operation {
                active_infinity::PatchOp::Set { path, .. }
                | active_infinity::PatchOp::Remove { path } => {
                    *path = scrub_addresses(path, addresses);
                }
                active_infinity::PatchOp::Rename { from, to } => {
                    *from = scrub_addresses(from, addresses);
                    *to = scrub_addresses(to, addresses);
                }
            },
            active_infinity::Inode::SchemaField(spec) => {
                if let active_infinity::TypeSpec::Enum(members) = &mut spec.typ {
                    let mut seen = BTreeSet::new();
                    for member in members.iter_mut() {
                        *member = scrub_addresses(member, addresses);
                        if !seen.insert(member.clone()) {
                            return Err(redaction_failure());
                        }
                    }
                }
                if let Some(text) = spec.deprecated.as_mut() {
                    *text = scrub_addresses(text, addresses);
                }
            }
            active_infinity::Inode::Quantity {
                unit: active_infinity::UnitTag::Named(name),
                ..
            } => {
                *name = scrub_addresses(name, addresses);
            }
            active_infinity::Inode::Quantity { .. } => {}
            active_infinity::Inode::Blob {
                media_type,
                payload,
                ..
            } => {
                *media_type = scrub_addresses(media_type, addresses);
                if let Some(bytes) = payload.as_mut() {
                    // A payload that carries the address is a binary copy of it;
                    // the payload is dropped rather than edited, because its
                    // length defines the blob identity (R-16 round 14, F4).
                    if bytes_carry_an_address(bytes, addresses, raw) {
                        *payload = None;
                    }
                }
            }
            // Exhaustive on purpose: a new `Inode` variant that carries text
            // must fail the build here rather than be silently un-scrubbed
            // (R-16 round 16, F9; contrast `remap_node`).
            active_infinity::Inode::Null
            | active_infinity::Inode::Bool(_)
            | active_infinity::Inode::Int(_)
            | active_infinity::Inode::Float(_)
            | active_infinity::Inode::DurationMs(_)
            | active_infinity::Inode::Array { .. }
            | active_infinity::Inode::Secret(_)
            | active_infinity::Inode::SecretRef { .. }
            | active_infinity::Inode::Ref(_)
            | active_infinity::Inode::Binary { .. }
            | active_infinity::Inode::Unary { .. }
            | active_infinity::Inode::SchemaArray { .. }
            | active_infinity::Inode::Semantic { .. }
            | active_infinity::Inode::ContentAddressed { .. } => {}
        }
    }
    Ok(())
}

/// Rewrite table keys that name an address, refusing a collision the rewrite
/// introduces.
fn scrub_field_keys(
    fields: &mut [(String, active_infinity::NodeId)],
    addresses: &BTreeSet<[u8; 64]>,
) -> Result<()> {
    for (name, _) in fields.iter_mut() {
        *name = scrub_addresses(name, addresses);
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (name, _) in fields.iter() {
        if !seen.insert(name.as_str()) {
            // Silently dropping one field changed the projection's shape;
            // a scrubbed name must stay unique or the reply is refused
            // (R-16 round 16, F8).
            return Err(redaction_failure());
        }
    }
    Ok(())
}

/// The projection refused to keep its shape.
fn redaction_failure() -> Error {
    Error::Provider {
        code: "provider/redaction".to_string(),
    }
}

/// Replace every occurrence of an address in `text` with the marker.
///
/// A contiguous occurrence is rewritten in place, so prose that quotes an
/// address keeps its sentence. A separated copy cannot be cut without
/// reconstructing the separators, so the whole text becomes the marker
/// (R-16 round 14, F5).
pub(crate) fn scrub_addresses(text: &str, addresses: &BTreeSet<[u8; 64]>) -> String {
    if !text_names_an_address(text, addresses) {
        return text.to_string();
    }
    let scrubbed = scrub_contiguous(text, addresses);
    if text_names_an_address(&scrubbed, addresses) {
        return SECRET_MARKER.to_string();
    }
    scrubbed
}

/// Rewrite the contiguous occurrences, leaving separated ones to the caller.
fn scrub_contiguous(text: &str, addresses: &BTreeSet<[u8; 64]>) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes.len() - index >= 64 {
            let mut key = [0u8; 64];
            for (slot, byte) in key.iter_mut().zip(&bytes[index..index + 64]) {
                *slot = byte.to_ascii_lowercase();
            }
            if addresses.contains(&key) {
                out.push_str(SECRET_MARKER);
                index += 64;
                continue;
            }
        }
        // Copy one UTF-8 character, not one byte.
        let step = text[index..].chars().next().map_or(1, char::len_utf8);
        out.push_str(&text[index..index + step]);
        index += step;
    }
    out
}

/// Whether `bytes` contains an address, raw or in hex.
///
/// `raw` is the same set as `addresses` in binary form, maintained by the
/// caller: rebuilding it per blob made a many-blob image quadratic
/// (R-16 round 16, F6). The hex scan is one pass over the bytes against a set,
/// not a window scan per address, and a UTF-8 payload is also checked for
/// compatibility-form copies (fullwidth or mathematical hex)
/// (R-16 round 16, F5).
fn bytes_carry_an_address(
    bytes: &[u8],
    addresses: &BTreeSet<[u8; 64]>,
    raw: &BTreeSet<[u8; 32]>,
) -> bool {
    if bytes.len() < 32 {
        return false;
    }
    let raw_hit = bytes.windows(32).any(|window| {
        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(window);
        raw.contains(&candidate)
    });
    let hex_hit = !addresses.is_empty() && bytes.len() >= 64 && {
        let mut key = [0u8; 64];
        bytes.windows(64).any(|window| {
            for (slot, byte) in key.iter_mut().zip(window) {
                *slot = byte.to_ascii_lowercase();
            }
            addresses.contains(&key)
        })
    };
    let compat_hit = !hex_hit && text_names_an_address(&String::from_utf8_lossy(bytes), addresses);
    raw_hit || hex_hit || compat_hit
}

/// Whether `text` contains one of the addresses, contiguous or separated.
///
/// Contiguous matching alone let a hyphenated, colon-separated or
/// zero-width-split copy through; each decodes to the same address and is the
/// same equality oracle (R-16 round 14, F5). A run of hex digits with those
/// separators between them is compared as one token; the separators do not
/// include whitespace, so ordinary prose cannot form a token by accident.
pub(crate) fn text_names_an_address(text: &str, addresses: &BTreeSet<[u8; 64]>) -> bool {
    if addresses.is_empty() || text.len() < 64 {
        return false;
    }
    let bytes: Vec<u8> = text.bytes().map(|byte| byte.to_ascii_lowercase()).collect();
    let mut key = [0u8; 64];
    for window in bytes.windows(64) {
        key.copy_from_slice(window);
        if addresses.contains(&key) {
            return true;
        }
    }
    // Separated and compatibility-form copies: collect hex digits across the
    // separators, folding fullwidth and mathematical alphanumerics to ASCII
    // first (NFKC-equivalent copies of a hex string are the same oracle,
    // R-16 round 16, F5), and check every 64-digit window of the collected run.
    let mut run: Vec<u8> = Vec::with_capacity(64);
    for character in text.chars() {
        let character = fold_compat_hex(character);
        if character.is_ascii_hexdigit() {
            run.push(character.to_ascii_lowercase() as u8);
            if run.len() > 64 {
                run.remove(0);
            }
            if run.len() == 64 {
                key.copy_from_slice(&run);
                if addresses.contains(&key) {
                    return true;
                }
            }
        } else if !is_address_separator(character) {
            run.clear();
        }
    }
    false
}

/// Fold a compatibility-form hex character to ASCII.
///
/// Fullwidth digits and A-F/a-f, the mathematical alphanumeric letters and
/// digits, and the compatibility punctuation NFKC folds to `-`, `:` or `_`.
///
/// Only these compatibility forms are folded; circled, superscript and
/// parenthesized forms are not, and the security docs name the covered set
/// (R-16 round 16, F5; round 17, F6).
fn fold_compat_hex(character: char) -> char {
    let code = character as u32;
    let from = |start: u32, ascii: u8| char::from(ascii + (code - start) as u8);
    match code {
        0xFF10..=0xFF19 => from(0xFF10, b'0'),
        0xFF21..=0xFF26 => from(0xFF21, b'A'),
        0xFF41..=0xFF46 => from(0xFF41, b'a'),
        // Compatibility punctuation that NFKC folds to a separator: a copy
        // split by a fullwidth colon, hyphen or underscore is a split copy
        // (R-16 round 17, F3).
        0xFF1A | 0xFE55 => ':',
        0xFF0D | 0xFE63 => '-',
        0xFF3F | 0xFE33 => '_',
        // The mathematical alphanumeric symbols: thirteen alphabets of 52
        // letters (A-Z then a-z), then five digit sets of ten.
        0x1D400..=0x1D6A3 => {
            let offset = (code - 0x1D400) % 52;
            if offset < 26 {
                char::from(b'A' + offset as u8)
            } else {
                char::from(b'a' + (offset - 26) as u8)
            }
        }
        0x1D7CE..=0x1D7FF => char::from(b'0' + (code - 0x1D7CE) as u8 % 10),
        _ => character,
    }
}

/// Characters a decoder ignores inside a hex address.
///
/// A reader that strips them can compare a split copy, so the scrub must too.
/// The set covers the zero-width family, the soft hyphen, the bidi controls,
/// the invisible operators and the variation selectors and tag characters a
/// renderer hides (R-16 rounds 14-15).
fn is_address_separator(character: char) -> bool {
    // One source for the invisible set: the same predicate the metadata
    // sanitizer uses, so a character the renderer hides cannot be a separator
    // for one pass and opaque for the other (R-16 round 16, F4). Only ASCII
    // whitespace is excluded: U+2028/U+2029 are in the invisible set and a
    // consumer may join across them (R-16 round 17, F4).
    matches!(character, '-' | ':' | '_')
        || (is_invisible_or_reordering(character) && !character.is_ascii_whitespace())
}

/// The hex keys of a raw address set, computed once by a caller that scans
/// many texts (R-16 round 17, F7).
pub(crate) fn hex_addresses(addresses: &[[u8; 32]]) -> BTreeSet<[u8; 64]> {
    addresses.iter().map(hex_key).collect()
}

/// Whether a text carries one of the raw 32-byte addresses.
pub(crate) fn text_carries_raw_address(text: &str, addresses: &[[u8; 32]]) -> bool {
    addresses
        .iter()
        .any(|address| text.as_bytes().windows(32).any(|window| window == address))
}

/// The free text an annotation carries, if it carries any.
pub(crate) fn annotation_text(kind: &active_infinity::AnnotationKind) -> Option<&str> {
    match kind {
        active_infinity::AnnotationKind::Intent(text) => Some(text),
        active_infinity::AnnotationKind::Constraint { source, .. } => Some(source),
        active_infinity::AnnotationKind::AiImmutable(_) => None,
    }
}

/// True when a module image carries a structural secret.
///
/// `false` only for bytes that neither decode nor claim to be an image: opaque
/// data has no secret structure this walk can see. A payload that starts with
/// the image magic and does not decode is `true`, because it cannot be proven
/// secret-free (R-16 round 5). An adapter that must not hand secrets to
/// third-party code
/// asks this first — the wasm sandbox writes its input into guest memory, and a
/// guest can return it mangled into an opaque blob the egress check passes
/// through by design (R-14 round 3, L-3).
pub fn module_carries_a_secret(bytes: &[u8]) -> bool {
    match inspect_module(bytes) {
        ModuleKind::Opaque => false,
        ModuleKind::Image { secret } => secret,
        // A magic-prefixed payload that does not decode cannot be proven
        // secret-free (R-16 round 5).
        ModuleKind::Corrupt => true,
    }
}

/// True when the bytes decode as an Active Infinity image.
///
/// This is the **validating** form, not a shape test: `decode` checks the
/// header and rejects a trailing tail, so a payload that merely starts with the
/// magic is `false` here and `true` in `claims_infinity_image`, which is the
/// predicate the gates use (R-16 round 9, F-4). `Value::Module` also carries
/// opaque provider output (a WASM tool's binary result), which has no secret
/// structure to redact.
pub fn is_infinity_image(bytes: &[u8]) -> bool {
    active_infinity::decode(bytes).is_ok()
}

/// Prove an outgoing module payload is a canonical image before it is handed
/// to a transport or a tool.
///
/// `validate` alone proves structure and the stored hash, not the canonical
/// form: the decoder drops an unreferenced string, blob or type entry, so two
/// byte strings can name one module, and a receiver's install gate
/// (`ModuleProvider::install_canonical_image`) refuses what the weaker check
/// passed. The proof here is the one the receiver applies (R-16 round 7, L-2).
pub fn check_module_payload(bytes: &[u8]) -> Result<()> {
    active_infinity::validate_canonical(bytes, active_infinity::Limits::default())
        .map(|_| ())
        .map_err(|error| Error::Payload(error.code().to_string()))
}

/// Refuse a value that carries *structural* secrets.
///
/// The egress gate for a non-redacting capability: a [`Value::Secret`] marker is
/// content-free and is the whole point of the value model, but a module with
/// secret nodes is the original bytes and must not cross. The distinction is why
/// this is not [`assert_no_secret_material`], which refuses the marker too.
pub fn assert_no_structural_secrets(value: &Value) -> Result<()> {
    // An explicit stack: a provider-built value can be deeper than the Rust
    // stack, and this walk runs after the provider returns (F-04).
    let mut stack: Vec<&Value> = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            Value::Secret => {}
            Value::List(items) => stack.extend(items.iter()),
            // A key is text the peer reads: `redact_value` collapses a map whose
            // key carries the marker, so the door out must inspect keys too
            // (round 22, #5).
            Value::Map(entries) => {
                if entries.keys().any(|key| key.contains(SECRET_MARKER)) {
                    return Err(Error::Provider {
                        code: "provider/secret-material".to_string(),
                    });
                }
                stack.extend(entries.values());
            }
            Value::Module(bytes) => match inspect_module(bytes) {
                ModuleKind::Opaque => {}
                ModuleKind::Corrupt => {
                    // An image that cannot be read cannot be proven
                    // secret-free.
                    return Err(Error::Provider {
                        code: "provider/secret-material".to_string(),
                    });
                }
                ModuleKind::Image { secret: true } => {
                    return Err(Error::Provider {
                        code: "provider/secret-material".to_string(),
                    });
                }
                // A decodable image must also be canonical: a receiver's
                // install gate refuses what `decode` alone would pass
                // (R-16 round 6, #2; round 7, L-2).
                ModuleKind::Image { secret: false } => check_module_payload(bytes)?,
            },
            Value::Null
            | Value::Bool(_)
            | Value::Int(_)
            | Value::Float(_)
            | Value::Text(_)
            | Value::Path(_) => {}
        }
    }
    Ok(())
}

/// Ensure a response carries no secret material.
pub fn assert_no_secret_material(value: &Value) -> Result<()> {
    // An explicit stack, like its sibling: the check runs on values a provider
    // built, so its own depth must not be the process's depth limit (F-04).
    let mut stack: Vec<&Value> = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            Value::Secret => {
                return Err(Error::Provider {
                    code: "provider/secret-material".to_string(),
                })
            }
            Value::List(items) => stack.extend(items.iter()),
            Value::Map(entries) => {
                if entries.keys().any(|key| key.contains(SECRET_MARKER)) {
                    return Err(Error::Provider {
                        code: "provider/secret-material".to_string(),
                    });
                }
                stack.extend(entries.values());
            }
            // A module is bytes: it is the one variant that can carry a secret
            // without the value model noticing, so it is decoded and inspected.
            Value::Module(bytes) => match inspect_module(bytes) {
                ModuleKind::Opaque => {}
                ModuleKind::Corrupt => {
                    // An image that cannot be read cannot be proven
                    // secret-free.
                    return Err(Error::Provider {
                        code: "provider/secret-material".to_string(),
                    });
                }
                ModuleKind::Image { secret: true } => {
                    return Err(Error::Provider {
                        code: "provider/secret-material".to_string(),
                    });
                }
                // A decodable image must also be canonical, the proof a peer's
                // install gate applies (round 3, F-2; R-16 round 7, L-2).
                ModuleKind::Image { secret: false } => check_module_payload(bytes)?,
            },
            // Every other variant is a scalar or a label with no room for
            // secret bytes, and a new variant has to be considered here rather
            // than inheriting this arm silently.
            Value::Null
            | Value::Bool(_)
            | Value::Int(_)
            | Value::Float(_)
            | Value::Text(_)
            | Value::Path(_) => {}
        }
    }
    Ok(())
}

/// Characters that reorder rendered text or render as nothing.
///
/// A log line splits on `\n` and `\r`, never on U+2028/U+2029, so an unscrubbed
/// line separator makes one value render as two log records. The format
/// characters have no width, so they can hide text or join two words into one.
///
/// One predicate for every name, topic and tool description the crate accepts:
/// `tool.rs` used to carry its own copy, and `intro.rs`, `kernel.rs` and
/// `receipts.rs` carried none, so a bidi override in a *topic* passed.
pub fn is_invisible_or_reordering(character: char) -> bool {
    matches!(
        character,
        // Bidi embeddings, overrides, isolates, LRM/RLM, and the Arabic letter
        // mark.
        '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{061C}'
            // Zero-width space, non-joiner, joiner, and word joiner.
            | '\u{200B}'..='\u{200D}'
            | '\u{2060}'
            // Byte order mark / zero-width no-break space, and soft hyphen.
            | '\u{FEFF}'
            | '\u{00AD}'
            // Line and paragraph separators.
            | '\u{2028}'
            | '\u{2029}'
            // Unicode tag characters: the standard invisible-ASCII smuggling
            // channel, and invisible by design.
            | '\u{E0000}'..='\u{E007F}'
            // Invisible operators, the Mongolian vowel separator, and variation
            // selectors, which change rendering without adding width.
            | '\u{2061}'..='\u{2064}'
            | '\u{180B}'..='\u{180F}'
            | '\u{034F}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{FE00}'..='\u{FE0F}'
            // Deprecated format characters and the interlinear annotation set.
            | '\u{206A}'..='\u{206F}'
            | '\u{FFF9}'..='\u{FFFB}'
            // Prepend characters that render as nothing in most fonts.
            | '\u{0600}'..='\u{0605}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{110BD}'
            | '\u{110CD}'
            // Egyptian hieroglyph format controls, Shorthand Format Controls and
            // musical symbol controls.
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            // The variation selectors supplement.
            | '\u{E0100}'..='\u{E01EF}'
            // Invisible fillers: Hangul fillers, the Hangul filler letter, the
            // halfwidth Hangul filler, and the braille blank.
            | '\u{115F}'..='\u{1160}'
            | '\u{3164}'
            | '\u{FFA0}'
            | '\u{2800}'
    )
}

/// True when `text` is a name, topic or label the crate can carry safely.
///
/// Non-empty, at most `max` bytes, and free of control characters and of the
/// characters that reorder or hide rendered text. This is the one rule for
/// method names, topics, provider names and channel names.
pub fn valid_text(text: &str, max: usize) -> bool {
    !text.is_empty()
        && text.len() <= max
        && !text
            .chars()
            .any(|character| character.is_control() || is_invisible_or_reordering(character))
}
