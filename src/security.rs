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
            [("ms".to_string(), Value::Int(*ms as i64))]
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
        Value::Map(entries) => Value::Map(
            entries
                .into_iter()
                .map(|(key, value)| (key, redact_value(value)))
                .collect(),
        ),
        Value::Text(text) if text.contains(SECRET_MARKER) => Value::Secret,
        // A module is the only variant that carries arbitrary bytes, so it is
        // the only one that can smuggle a secret node. Rewriting beats passing
        // it through: a redacting caller must not receive the original bytes.
        Value::Module(bytes) => match redact_module(&bytes) {
            Ok(redacted) => Value::Module(redacted),
            // A module that cannot be decoded has no structure to redact, and
            // handing the bytes back would be the leak this function exists to
            // prevent.
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
    let mut module =
        active_infinity::decode(bytes).map_err(|error| Error::Payload(error.code().to_string()))?;
    for index in 0..module.node_count() {
        let id = active_infinity::NodeId(index as u32);
        let is_secret = module.get(id).map(|node| node.is_secret()).unwrap_or(false);
        if is_secret {
            *module
                .node_mut(id)
                .map_err(|error| Error::Payload(error.code().to_string()))? =
                active_infinity::Inode::Str(SECRET_MARKER.to_string());
        }
    }
    let redacted = active_infinity::encode(&module)
        .map_err(|error| Error::Payload(error.code().to_string()))?;
    check_module_payload(&redacted)?;
    Ok(redacted)
}

/// True when a module holds a node marked secret.
fn module_has_secret(bytes: &[u8]) -> Result<bool> {
    let module =
        active_infinity::decode(bytes).map_err(|error| Error::Payload(error.code().to_string()))?;
    Ok((0..module.node_count()).any(|index| {
        module
            .get(active_infinity::NodeId(index as u32))
            .map(|node| node.is_secret())
            .unwrap_or(false)
    }))
}

/// Validate an outgoing module payload before it is handed to a transport or a
/// tool.
pub fn check_module_payload(bytes: &[u8]) -> Result<()> {
    active_infinity::validate(bytes)
        .map(|_| ())
        .map_err(|error| Error::Payload(error.code().to_string()))
}

/// Ensure a response carries no secret material.
///
/// The RPC value model cannot represent secret bytes, but a provider might hand
/// back text that contains a marker or a module that a caller does not expect to
/// be secret-bearing. Modules are checked for structural secrets before they go
/// out; a module with secrets is allowed only inside a redacting capability,
/// which the provider already enforces.
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
