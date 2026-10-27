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
        other => other,
    }
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
        _ => Ok(()),
    }
}
