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
    ///
    /// Computed by [`Value::shape`], so the walk is iterative: a value nested
    /// deeper than the stack can hold is measured (and then refused by the
    /// depth ceiling), never an abort. It used to recurse, which meant the
    /// ceiling that exists to stop such a value was applied after the walk that
    /// fell over on it.
    pub fn wire_size(&self) -> u64 {
        self.shape().size
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

    /// Measure the shape of this value in one iterative pass.
    ///
    /// A budget's `max_depth`, `max_array_len` and `max_value_size` are checked
    /// against this, so a caller cannot hand a provider a value deeper, wider or
    /// larger than its grant names. The walk uses an explicit stack: a caller can
    /// build a value deeper than the Rust stack, and the check that is supposed
    /// to bound it must not be the thing that overflows.
    pub fn shape(&self) -> Shape {
        enum Work<'a> {
            Visit(&'a Value, u64),
            /// A container finished: fold its size into its parent.
            Fold(u64),
        }

        let mut shape = Shape::default();
        let mut work = vec![Work::Visit(self, 0)];
        // Accumulators, one per open container. A scalar at the top level (no
        // open container) lands in `total` directly.
        let mut open: Vec<u64> = Vec::new();
        let mut total = 0u64;
        while let Some(item) = work.pop() {
            match item {
                Work::Visit(value, depth) => {
                    let scalar = match value {
                        Value::Null | Value::Secret => Some(1u64),
                        Value::Bool(_) => Some(2),
                        Value::Int(_) | Value::Float(_) => Some(9),
                        Value::Text(text) | Value::Path(text) => {
                            Some(5u64.saturating_add(text.len() as u64))
                        }
                        Value::Module(bytes) => Some(5u64.saturating_add(bytes.len() as u64)),
                        Value::List(_) | Value::Map(_) => None,
                    };
                    if let Some(size) = scalar {
                        match open.last_mut() {
                            Some(top) => *top = top.saturating_add(size),
                            None => total = total.saturating_add(size),
                        }
                        continue;
                    }
                    shape.depth = shape.depth.max(depth + 1);
                    open.push(0);
                    work.push(Work::Fold(5));
                    match value {
                        Value::List(items) => {
                            shape.widest = shape.widest.max(items.len() as u64);
                            for item in items {
                                work.push(Work::Visit(item, depth + 1));
                            }
                        }
                        Value::Map(entries) => {
                            shape.widest = shape.widest.max(entries.len() as u64);
                            for (key, item) in entries {
                                // A key is payload too: a grant that bounds the
                                // size of a value must bound the name it arrives
                                // under.
                                let key_size = 5u64.saturating_add(key.len() as u64);
                                match open.last_mut() {
                                    Some(top) => *top = top.saturating_add(key_size),
                                    None => total = total.saturating_add(key_size),
                                }
                                work.push(Work::Visit(item, depth + 1));
                            }
                        }
                        _ => unreachable!("only containers open an accumulator"),
                    }
                }
                Work::Fold(constant) => {
                    let inner = open.pop().unwrap_or(0).saturating_add(constant);
                    match open.last_mut() {
                        Some(top) => *top = top.saturating_add(inner),
                        None => total = total.saturating_add(inner),
                    }
                }
            }
        }
        shape.size = total;
        shape
    }
}

/// The structure a budget bounds: nesting, width and materialised size.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Shape {
    /// Nesting depth: a scalar is 0, a list holding a scalar is 1.
    pub depth: u64,
    /// Length of the longest list or map anywhere in the value.
    pub widest: u64,
    /// Bytes the value occupies on the wire, matching [`Value::wire_size`].
    pub size: u64,
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
    /// The envelope payload this call carried, if any.
    ///
    /// A provider that moves large bodies (bulk transfer, blob upload) reads it
    /// here. The bytes were charged against the caller's grant on ingress, so a
    /// provider must not charge them again.
    pub payload: Vec<u8>,
    /// The kernel's clock at dispatch.
    ///
    /// A provider that needs a time (a sandboxed guest reading a clock, a
    /// timestamp in a log) reads it here instead of asking the operating system,
    /// so the call follows the kernel's clock policy: deterministic in the
    /// default virtual mode and real when the kernel was switched to the wall
    /// clock.
    pub now_ms: u64,
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
            payload: Vec::new(),
            now_ms: 0,
        }
    }

    /// The first argument, when present.
    pub fn first(&self) -> Option<&Arg> {
        self.args.first()
    }

    /// Attach the envelope payload this call carries.
    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
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
