//! Values, arguments and results crossing an Active RPC boundary.
//!
//! The value model is small on purpose: it carries what domain operations and
//! tools need, and it never carries secret material. A secret is represented as
//! [`Value::Secret`] — a marker — so no code path in this crate can put secret
//! bytes on the wire.

use std::collections::BTreeMap;

use crate::cap::CapId;
use crate::promise::PromiseId;

/// A value crossing the RPC boundary.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Absent value.
    Null,
    /// Boolean.
    Bool(bool),
    /// Integer.
    Int(i64),
    /// Floating-point number.
    Float(f64),
    /// UTF-8 text.
    Text(String),
    /// Ordered list.
    List(Vec<Value>),
    /// Key-sorted map (deterministic wire order).
    Map(BTreeMap<String, Value>),
    /// Redaction marker: a secret existed here. Never carries content.
    Secret,
    /// A serialized Active Infinity module.
    Module(Vec<u8>),
    /// A dotted path inside a module.
    Path(String),
}

impl Value {
    /// Convenience constructor for a text value.
    pub fn text(value: impl Into<String>) -> Value {
        Value::Text(value.into())
    }

    /// Convenience constructor for a path value.
    pub fn path(value: impl Into<String>) -> Value {
        Value::Path(value.into())
    }

    /// Convenience constructor for a list.
    pub fn list(items: impl IntoIterator<Item = Value>) -> Value {
        Value::List(items.into_iter().collect())
    }

    /// Convenience constructor for a map (keys sorted on construction).
    pub fn map<K: Into<String>, I: IntoIterator<Item = (K, Value)>>(entries: I) -> Value {
        Value::Map(
            entries
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect(),
        )
    }

    /// Read as text, if it is text.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(text) => Some(text),
            _ => None,
        }
    }

    /// Read as a path, if it is a path.
    pub fn as_path(&self) -> Option<&str> {
        match self {
            Value::Path(path) => Some(path),
            _ => None,
        }
    }

    /// Bytes this value occupies on the wire (upper bound; used for budgets).
    pub fn wire_size(&self) -> u64 {
        match self {
            Value::Null => 1,
            Value::Bool(_) => 2,
            Value::Int(_) | Value::Float(_) => 9,
            Value::Text(text) | Value::Path(text) => 5 + text.len() as u64,
            Value::Secret => 1,
            Value::Module(bytes) => 5 + bytes.len() as u64,
            Value::List(items) => 5 + items.iter().map(Value::wire_size).sum::<u64>(),
            Value::Map(entries) => {
                5 + entries
                    .iter()
                    .map(|(key, value)| 5 + key.len() as u64 + value.wire_size())
                    .sum::<u64>()
            }
        }
    }

    /// True when this value or any descendant is a secret marker.
    pub fn is_tainted(&self) -> bool {
        match self {
            Value::Secret => true,
            Value::List(items) => items.iter().any(Value::is_tainted),
            Value::Map(entries) => entries.values().any(Value::is_tainted),
            _ => false,
        }
    }
}

/// One call argument.
#[derive(Debug, Clone, PartialEq)]
pub enum Arg {
    /// A concrete value.
    Value(Value),
    /// A promise: the call is pipelined and starts as soon as it resolves.
    Promise(PromiseId),
    /// A capability handle (capability passing).
    Cap(CapId),
}

impl Arg {
    /// Build a value argument.
    pub fn value(value: Value) -> Arg {
        Arg::Value(value)
    }

    /// Build a text argument.
    pub fn text(value: impl Into<String>) -> Arg {
        Arg::Value(Value::Text(value.into()))
    }

    /// The promise this argument waits for, if any.
    pub fn promise(&self) -> Option<PromiseId> {
        match self {
            Arg::Promise(id) => Some(*id),
            _ => None,
        }
    }

    /// Bytes this argument occupies on the wire (used for budget accounting).
    pub fn wire_size(&self) -> u64 {
        match self {
            Arg::Value(value) => value.wire_size(),
            Arg::Promise(_) => 8,
            Arg::Cap(_) => 16,
        }
    }
}

/// A request as a provider sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct Call {
    /// Method name.
    pub method: String,
    /// Arguments in order.
    pub args: Vec<Arg>,
    /// Path restriction inherited from the capability, when present.
    pub path_scope: Option<String>,
    /// Whether the caller asked for redacted output.
    pub redact: bool,
    /// Whether the capability is read-only.
    pub read_only: bool,
    /// Whether the capability's tool policy grants process execution.
    pub tool_allows_process: bool,
    /// Effective budget (capability ∩ lane) for this call.
    pub budget: crate::budget::Budget,
}

impl Call {
    /// Build a call.
    pub fn new(method: impl Into<String>, args: Vec<Arg>) -> Call {
        Call {
            method: method.into(),
            args,
            path_scope: None,
            redact: false,
            read_only: false,
            tool_allows_process: false,
            budget: crate::budget::Budget::default(),
        }
    }

    /// The first argument, when present.
    pub fn first(&self) -> Option<&Arg> {
        self.args.first()
    }
}

/// What a provider returns.
#[derive(Debug, Clone, PartialEq)]
pub enum Response {
    /// A plain value.
    Value(Value),
    /// A serialized module (already canonical and validated).
    Module(Vec<u8>),
    /// An ordered list of labels (why/impact answers).
    Labels(Vec<String>),
}

impl Response {
    /// Convert into a value for uniform handling by the kernel.
    pub fn into_value(self) -> Value {
        match self {
            Response::Value(value) => value,
            Response::Module(bytes) => Value::Module(bytes),
            Response::Labels(labels) => Value::List(labels.into_iter().map(Value::Text).collect()),
        }
    }
}
