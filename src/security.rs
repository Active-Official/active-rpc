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

use std::collections::BTreeSet;

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
    let mut work = vec![(value, 1usize)];
    while let Some((value, depth)) = work.pop() {
        if depth > limit {
            return true;
        }
        match value {
            ActiveValue::Array(items) => {
                work.extend(items.iter().map(|item| (item, depth.saturating_add(1))));
            }
            ActiveValue::Table(entries) => {
                work.extend(
                    entries
                        .iter()
                        .map(|(_, item)| (item, depth.saturating_add(1))),
                );
            }
            // These two convert into a synthetic map, one level deeper than
            // the Active node itself (round 17, F5).
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
    match value {
        ActiveValue::Null => Value::Null,
        ActiveValue::Bool(flag) => Value::Bool(*flag),
        ActiveValue::Int(number) => Value::Int(*number),
        ActiveValue::Float(number) => Value::Float(*number),
        ActiveValue::String(text) => Value::Text(text.clone()),
        ActiveValue::DurationMs(ms) => Value::Map(
            // A duration past `i64::MAX` saturates: a cast wraps negative
            // and a consumer that reads `ms` as a deadline misbehaves.
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
        ActiveValue::Array(items) => Value::List(items.iter().map(from_active_value).collect()),
        ActiveValue::Table(entries) => Value::Map(
            entries
                .iter()
                .map(|(key, value)| (key.clone(), from_active_value(value)))
                .collect(),
        ),
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
    match value {
        Value::Secret => Value::Secret,
        Value::List(items) => Value::List(items.into_iter().map(redact_value).collect()),
        // A key is text too: a provider that puts a secret copy or the marker
        // in a `Value::Map` key would otherwise pass through untouched. The
        // whole map collapses to the marker, because renaming a key could
        // collide with another entry.
        Value::Map(entries) if entries.keys().any(|key| key.contains(SECRET_MARKER)) => {
            Value::Secret
        }
        Value::Map(entries) => Value::Map(
            entries
                .into_iter()
                .map(|(key, value)| (key, redact_value(value)))
                .collect(),
        ),
        // A text that *is* the marker (or that embeds it) stays text: the marker
        // is content-free, and a provider that already redacted its answer
        // returns it as a label. Collapsing it here turned `["***SECRET***"]`
        // into `[Secret]` and made redaction destroy its own output. Secret
        // *bytes* in plain text are the provider's fault and are what the
        // codec's fragment checks refuse on encode.
        Value::Text(_) => value,
        // A module is the only variant that carries arbitrary bytes, so it is
        // the only one that can smuggle a secret node. Rewriting beats passing
        // it through: a redacting caller must not receive the original bytes.
        // A module is either an Infinity image or opaque bytes a provider
        // produced (a WASM tool's binary output). Only an image has secret
        // structure; refusing an opaque blob here turned every binary tool
        // result into a marker.
        Value::Module(bytes) => match redact_module(&bytes) {
            Ok(redacted) => Value::Module(redacted),
            Err(_) if !is_infinity_image(&bytes) => Value::Module(bytes),
            // An image that cannot be redacted is not safe to hand back.
            Err(_) => Value::Secret,
        },
        other => other,
    }
}

/// Rewrite every secret node of an Active Infinity module to the marker.
///
/// One implementation for [`redact_value`] and the domain provider: two would
/// drift, and the one that drifted would be the leak.
pub fn redact_module(bytes: &[u8]) -> Result<Vec<u8>> {
    // One implementation, in the library that holds the secret heap: it
    // canonicalizes first (so the codec can refuse free text or a binary copy
    // that carries a secret literal, and can redact the metadata while the
    // literals are still named), then rewrites the value plane, where a mere
    // `Str`, `Ident`, `Env` name, field name or binding name can hold a copy.
    // Active RPC cannot see an `Inode::Secret`'s bytes, so a local pass would
    // miss every copy the library itself redacts in its projections.
    let redacted = active_infinity::interop::redact_image(bytes)
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

/// True when a module holds a node marked secret.
fn module_has_secret(bytes: &[u8]) -> Result<bool> {
    // Opaque bytes are not an Infinity image and carry no secret structure.
    let Ok(module) = active_infinity::decode(bytes) else {
        return Ok(false);
    };
    Ok((0..module.node_count()).any(|index| {
        module
            .get(active_infinity::NodeId(index as u32))
            .map(|node| node.is_secret())
            .unwrap_or(false)
    }))
}

/// True when the bytes are an Active Infinity image.
///
/// `Value::Module` also carries opaque provider output (a WASM tool's binary
/// result), which has no secret structure to redact.
pub fn is_infinity_image(bytes: &[u8]) -> bool {
    active_infinity::decode(bytes).is_ok()
}

/// Validate an outgoing module payload before it is handed to a transport or a
/// tool.
pub fn check_module_payload(bytes: &[u8]) -> Result<()> {
    active_infinity::validate(bytes)
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
    match value {
        Value::Secret => Ok(()),
        Value::List(items) => items.iter().try_for_each(assert_no_structural_secrets),
        Value::Map(entries) => entries.values().try_for_each(assert_no_structural_secrets),
        Value::Module(bytes) => {
            if module_has_secret(bytes)? {
                return Err(Error::Provider {
                    code: "rpc/secret-material".to_string(),
                });
            }
            Ok(())
        }
        Value::Null
        | Value::Bool(_)
        | Value::Int(_)
        | Value::Float(_)
        | Value::Text(_)
        | Value::Path(_) => Ok(()),
    }
}

/// Ensure a response carries no secret material.
pub fn assert_no_secret_material(value: &Value) -> Result<()> {
    match value {
        Value::Secret => Err(Error::Provider {
            code: "rpc/secret-material".to_string(),
        }),
        Value::List(items) => items.iter().try_for_each(assert_no_secret_material),
        Value::Map(entries) => entries.values().try_for_each(assert_no_secret_material),
        // A module is bytes: it is the one variant that can carry a secret
        // without the value model noticing, so it is decoded and inspected.
        Value::Module(bytes) => {
            if module_has_secret(bytes)? {
                return Err(Error::Provider {
                    code: "rpc/secret-material".to_string(),
                });
            }
            Ok(())
        }
        // Every other variant is a scalar or a label with no room for secret
        // bytes, and a new variant has to be considered here rather than
        // inheriting this arm silently.
        Value::Null
        | Value::Bool(_)
        | Value::Int(_)
        | Value::Float(_)
        | Value::Text(_)
        | Value::Path(_) => Ok(()),
    }
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
            | '\u{180E}'
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
