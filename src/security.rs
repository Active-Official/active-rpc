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
pub const SECRET_MARKER: &str = "***SECRET***";

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
pub fn redact_module(bytes: &[u8]) -> Result<Vec<u8>> {
    let module =
        active_infinity::decode(bytes).map_err(|error| Error::Payload(error.code().to_string()))?;
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
    module.set_provenance(None);
    let redacted = active_infinity::encode(&module)
        .map_err(|error| Error::Payload(error.code().to_string()))?;
    check_module_payload(&redacted)?;
    Ok(redacted)
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
    redactor
        .redact(module)
        .map_err(|error| Error::Payload(error.code().to_string()))
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

/// True when a module holds a node marked secret.
fn module_has_secret(bytes: &[u8]) -> Result<bool> {
    // Opaque bytes are not an Infinity image and carry no secret structure.
    let Ok(module) = active_infinity::decode(bytes) else {
        // A payload that claims to be an image and cannot be decoded fails
        // closed (R-16 round 5, #1).
        return Ok(claims_infinity_image(bytes));
    };
    Ok(module_holds_secret(&module))
}

/// True when a decoded module holds a node marked secret.
fn module_holds_secret(module: &active_infinity::InfinityModule) -> bool {
    (0..module.node_count()).any(|index| {
        module
            .get(active_infinity::NodeId(index as u32))
            // A node the decoder counts but cannot materialise cannot be
            // proven secret-free, so it fails closed (round 3, F-1).
            .is_none_or(|node| node.is_secret())
    })
}

/// True when a module image carries a structural secret.
///
/// `false` for bytes that are not an image: opaque data has no secret structure
/// this walk can see. An adapter that must not hand secrets to third-party code
/// asks this first — the wasm sandbox writes its input into guest memory, and a
/// guest can return it mangled into an opaque blob the egress check passes
/// through by design (R-14 round 3, L-3).
pub fn module_carries_a_secret(bytes: &[u8]) -> bool {
    module_has_secret(bytes).unwrap_or(true)
}

/// True when the bytes are an Active Infinity image.
///
/// `Value::Module` also carries opaque provider output (a WASM tool's binary
/// result), which has no secret structure to redact.
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
            Value::Module(bytes) => {
                if module_has_secret(bytes)? {
                    return Err(Error::Provider {
                        code: "provider/secret-material".to_string(),
                    });
                }
                // A decodable image must also be *valid*: `decode` tolerates a
                // trailing tail, and a receiver's install gate refuses what this
                // gate would otherwise pass (R-16 round 6, #2).
                if is_infinity_image(bytes) {
                    check_module_payload(bytes)?;
                }
            }
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
            Value::Module(bytes) => {
                if module_has_secret(bytes)? {
                    return Err(Error::Provider {
                        code: "provider/secret-material".to_string(),
                    });
                }
                // A decodable image must also pass the codec's `validate`: a
                // decoder that tolerates a trailing byte would otherwise emit
                // an image a peer's install gate refuses, so two byte strings
                // would name one module for a peer that hashes the payload
                // (round 3, F-2). Opaque non-image bytes stay untouched.
                if is_infinity_image(bytes) {
                    check_module_payload(bytes)?;
                }
            }
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
