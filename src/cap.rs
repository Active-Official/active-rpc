//! Capabilities: unforgeable, attenuable references.
//!
//! A capability is an opaque 128-bit id minted by a kernel from a per-kernel
//! secret, a monotonic serial and the parent id. Holding the id is the *only*
//! authority needed to call the object it names, and the kernel is the only
//! component that can mint one: an id that is not in the registry is refused
//! with `rpc/unknown-capability`, so a peer cannot forge, guess or transplant a
//! capability from another connection.
//!
//! Attenuation is monotone by construction: [`CapAttrs::attenuate`] refuses any
//! attempt to widen methods, budget, path scope or tool policy.

use std::collections::BTreeSet;
use std::fmt;
use std::rc::Rc;

use crate::budget::Budget;
use crate::error::{Error, Result};

/// An unforgeable capability identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapId(pub [u8; 16]);

impl CapId {
    /// Derive an id from the kernel secret, serial and parent.
    ///
    /// Deterministic for a given kernel (which makes tests and replays stable),
    /// unpredictable to a peer without the secret.
    pub fn derive(secret: &[u8; 32], serial: u64, parent: Option<&CapId>) -> CapId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"active-rpc/cap");
        hasher.update(secret);
        hasher.update(&serial.to_le_bytes());
        hasher.update(&parent.map(|id| id.0).unwrap_or([0u8; 16]));
        let digest = hasher.finalize();
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest.as_bytes()[..16]);
        CapId(id)
    }

    /// Hex form for logs and errors.
    ///
    /// This is the raw capability id and **is** authority: possession of it is
    /// enough to call the object while the kernel lives. Prefer
    /// [`CapId::correlation_id`] in telemetry; `hex` is for an explicit,
    /// deliberate transfer (the peer CLI prints it so a caller can use it).
    pub fn hex(self) -> String {
        let mut out = String::with_capacity(32);
        for byte in self.0 {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    /// A non-reversible correlation id for logs and events.
    ///
    /// Logs can correlate two events that mention the same capability without
    /// carrying the authority itself.
    pub fn correlation_id(self) -> String {
        correlation(&self.0)
    }
}

/// Domain-separated, truncated hash used for capability correlation.
fn correlation(bytes: &[u8; 16]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"active-rpc/capid-correlation");
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(16);
    for byte in &digest.as_bytes()[..8] {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// A capability id carried by an error or diagnostic.
///
/// The raw 128 bits stay in memory so the kernel can look the id up, but every
/// formatting path prints a correlation id. An error log therefore cannot be
/// replayed as authority (I-3, I-4, H2.18).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CapToken(pub u128);

impl CapToken {
    /// Correlation id matching [`CapId::correlation_id`] for the same id.
    pub fn correlation_id(self) -> String {
        correlation(&self.0.to_be_bytes())
    }
}

impl fmt::Debug for CapToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CapToken({})", self.correlation_id())
    }
}

impl fmt::Display for CapToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.correlation_id())
    }
}

impl fmt::Debug for CapId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Default telemetry must not carry raw authority bits. Use `hex` only
        // for a deliberate transfer.
        write!(f, "CapId({})", self.correlation_id())
    }
}

impl fmt::Display for CapId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display is a diagnostic surface, like Debug. Raw authority is only
        // available through the explicitly documented `hex()`.
        f.write_str(&self.correlation_id())
    }
}

/// Identity of a provider object: which adapter, which object within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProviderId(pub u64);

/// Tool-level policy attached to a capability.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ToolPolicy {
    /// Tool names this capability may invoke. Empty means "none".
    pub allowed: BTreeSet<String>,
    /// Maximum bytes one tool call may pass.
    pub max_arg_bytes: u64,
    /// Whether the tool may run a local process.
    pub allow_process: bool,
}

impl ToolPolicy {
    /// Build a policy from tool names.
    pub fn allow(names: &[&str]) -> Self {
        Self {
            allowed: names.iter().map(|name| name.to_string()).collect(),
            max_arg_bytes: 1 << 20,
            allow_process: false,
        }
    }

    /// True when `self` grants nothing beyond `parent`.
    pub fn is_attenuation_of(&self, parent: &ToolPolicy) -> bool {
        self.allowed.is_subset(&parent.allowed)
            && self.max_arg_bytes <= parent.max_arg_bytes
            && (!self.allow_process || parent.allow_process)
    }
}

/// Whether a capability may outlive the process under an explicit policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CapPersistence {
    /// The default: the capability dies with the process.
    #[default]
    Ephemeral,
    /// May be stored by a deployment-provided secure restore path.
    Durable,
}

/// The authority a capability carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapAttrs {
    /// Granted method names. Must be non-empty after attenuation.
    pub methods: BTreeSet<String>,
    /// Resource budget.
    pub budget: Budget,
    /// May not mutate module state.
    pub read_only: bool,
    /// Redacts trace output.
    pub redact: bool,
    /// Dotted path prefix the capability is confined to (inclusive).
    pub path_scope: Option<String>,
    /// Tool policy, when the capability targets a tool.
    pub tool_policy: Option<ToolPolicy>,
    /// Whether the capability is ephemeral or eligible for durable restore.
    pub persistence: CapPersistence,
}

impl CapAttrs {
    /// Full authority over `methods` with the default budget.
    pub fn new(methods: &[&str]) -> Self {
        Self {
            methods: methods.iter().map(|method| method.to_string()).collect(),
            budget: Budget::default(),
            read_only: false,
            redact: false,
            path_scope: None,
            tool_policy: None,
            persistence: CapPersistence::Ephemeral,
        }
    }

    /// Restrict methods.
    pub fn with_methods(mut self, methods: &[&str]) -> Self {
        self.methods = methods.iter().map(|method| method.to_string()).collect();
        self
    }

    /// Restrict the budget.
    pub fn with_budget(mut self, budget: Budget) -> Self {
        self.budget = budget;
        self
    }

    /// Confine the capability to a path prefix.
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path_scope = Some(path.into());
        self
    }

    /// Mark the capability read-only.
    pub fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }

    /// Mark the capability eligible for durable restore under policy.
    pub fn durable(mut self) -> Self {
        self.persistence = CapPersistence::Durable;
        self
    }

    /// Mark the capability redacting.
    pub fn redacted(mut self) -> Self {
        self.redact = true;
        self
    }

    /// Attach a tool policy.
    pub fn with_tool_policy(mut self, policy: ToolPolicy) -> Self {
        self.tool_policy = Some(policy);
        self
    }

    /// True when `self` is a valid attenuation of `parent`.
    pub fn is_attenuation_of(&self, parent: &CapAttrs) -> bool {
        let methods_ok = self.methods.is_subset(&parent.methods) && !self.methods.is_empty();
        let persistence_ok = self.persistence != CapPersistence::Durable
            || parent.persistence == CapPersistence::Durable;
        let budget_ok = self.budget.is_attenuation_of(&parent.budget);
        let read_only_ok = !parent.read_only || self.read_only;
        let redact_ok = !parent.redact || self.redact;
        let path_ok = match (&self.path_scope, &parent.path_scope) {
            (None, None) => true,
            (Some(_), None) => true,
            (Some(child), Some(parent)) => is_path_prefix(parent, child),
            (None, Some(_)) => false,
        };
        let tool_ok = match (&self.tool_policy, &parent.tool_policy) {
            // A parent without a policy leaves the tool surface open; adding one
            // on the child narrows it, which `attenuate` also accepts.
            (_, None) => true,
            // Dropping the parent's policy widens authority.
            (None, Some(_)) => false,
            (Some(policy), Some(parent)) => policy.is_attenuation_of(parent),
        };
        methods_ok && budget_ok && read_only_ok && redact_ok && path_ok && tool_ok && persistence_ok
    }

    /// Attenuate, refusing anything that would widen authority.
    pub fn attenuate(&self, child: CapAttrs) -> Result<CapAttrs> {
        if child.methods.is_empty() {
            return Err(Error::InvalidArgument("attenuation grants no methods"));
        }
        if !child.methods.is_subset(&self.methods) {
            return Err(Error::Escalation("method set grows"));
        }
        if !child.budget.is_attenuation_of(&self.budget) {
            return Err(Error::Escalation("budget grows"));
        }
        if self.read_only && !child.read_only {
            return Err(Error::Escalation("read-only cannot be lifted"));
        }
        if self.redact && !child.redact {
            return Err(Error::Escalation("redaction cannot be lifted"));
        }
        match (&child.path_scope, &self.path_scope) {
            (_, None) => {}
            (Some(child_path), Some(parent)) if is_path_prefix(parent, child_path) => {}
            (Some(_), Some(_)) => return Err(Error::Escalation("path scope widens")),
            (None, Some(_)) => return Err(Error::Escalation("path scope removed")),
        }
        match (&child.tool_policy, &self.tool_policy) {
            (_, None) => {}
            (Some(policy), Some(parent)) if policy.is_attenuation_of(parent) => {}
            _ => return Err(Error::Escalation("tool policy widens")),
        }
        let mut attrs = child;
        attrs.budget = attrs.budget.intersect(&self.budget);
        attrs.persistence = self.persistence;
        Ok(attrs)
    }

    /// Whether `method` is granted.
    pub fn grants(&self, method: &str) -> bool {
        self.methods.contains(method)
    }

    /// Whether `path` is inside the capability's scope.
    pub fn covers_path(&self, path: &str) -> bool {
        match &self.path_scope {
            None => true,
            Some(scope) => is_path_prefix(scope, path),
        }
    }
}

/// True when `parent` is a dotted-path prefix of `child` (or equal).
pub fn is_path_prefix(parent: &str, child: &str) -> bool {
    if parent == child {
        return true;
    }
    child
        .strip_prefix(parent)
        .map(|rest| rest.starts_with('.'))
        .unwrap_or(false)
}

/// Provider-side record of a live capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapRecord {
    /// Capability id.
    pub id: CapId,
    /// Provider that owns the object.
    pub provider: ProviderId,
    /// Object within the provider (module id, tool id, lane id).
    pub object: u64,
    /// Authority.
    pub attrs: CapAttrs,
    /// Parent capability, when this one was derived by attenuation.
    pub parent: Option<CapId>,
    /// Outstanding references (client handles plus transfers).
    pub refs: u32,
    /// Revoked capabilities are refused even if the id is known.
    pub revoked: bool,
}

impl CapRecord {
    /// A first-generation capability.
    pub fn new(id: CapId, provider: ProviderId, object: u64, attrs: CapAttrs) -> Self {
        Self {
            id,
            provider,
            object,
            attrs,
            parent: None,
            refs: 1,
            revoked: false,
        }
    }
}

/// Control surface a capability handle uses to release its reference.
///
/// The kernel implements this; `cap.rs` stays independent of the kernel so the
/// two can be reasoned about separately.
pub trait CapControl {
    /// Add one reference to a capability.
    fn retain(&self, id: CapId);
    /// Drop one reference; the provider is notified when the last one goes.
    fn release(&self, id: CapId);
}

/// A client-side capability handle.
///
/// Cloning a handle adds a reference; dropping the last handle notifies the
/// provider (automatic lifetime, `RPROPOSAL` §3).
pub struct CapHandle {
    control: Rc<dyn CapControl>,
    id: CapId,
    /// False only for handles that do not own a reference (imported views).
    owning: bool,
}

impl CapHandle {
    /// Wrap a minted capability.
    pub fn new(control: Rc<dyn CapControl>, id: CapId) -> Self {
        Self {
            control,
            id,
            owning: true,
        }
    }

    /// A non-owning handle (used when reconstructing a handle from a transfer).
    pub fn borrowed(control: Rc<dyn CapControl>, id: CapId) -> Self {
        Self {
            control,
            id,
            owning: false,
        }
    }

    /// The capability id this handle refers to.
    pub fn id(&self) -> CapId {
        self.id
    }

    /// Surrender this handle without releasing its reference.
    ///
    /// Used when a reference moves (channel transfer): the receiver becomes
    /// responsible for the reference the sender held.
    pub fn into_id(mut self) -> CapId {
        self.owning = false;
        self.id
    }
}

impl Clone for CapHandle {
    /// Cloning an *owning* handle retains the capability: the kernel increments
    /// the reference count and both handles must drop before the provider is
    /// notified. Cloning a borrowed handle stays borrowed — it never retained a
    /// reference, so it must not create one.
    fn clone(&self) -> Self {
        if self.owning {
            self.control.retain(self.id);
        }
        Self {
            control: Rc::clone(&self.control),
            id: self.id,
            owning: self.owning,
        }
    }
}

impl Drop for CapHandle {
    fn drop(&mut self) {
        if self.owning {
            self.control.release(self.id);
        }
    }
}

impl fmt::Debug for CapHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapHandle").field("id", &self.id).finish()
    }
}
