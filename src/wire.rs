//! The wire envelope: one frame of Active RPC traffic.
//!
//! Every transport carries the same envelope, so a capability table, a method
//! call and an Infinity payload look identical whether they travel in-process,
//! through a shared-memory segment, over QUIC or through the Connect bridge.
//!
//! Decoding is fail-closed: the magic, version, every length, every count and
//! the total size are checked before a single value is materialised, and an
//! envelope carrying a capability descriptor that violates the attenuation
//! rules is refused with `rpc/capability-table`.
//!
//! ```text
//! 0  4  magic "ARP1"
//! 4  1  version (1)
//! 5  1  kind (1 request, 2 response, 3 error, 4 hello)
//! 6  2  flags (bit 0 redact, bit 1 read-only)
//! 8  8  request id
//! 16 4  method length + bytes
//! ..    argument count + arguments
//! ..    payload length + bytes
//! ..    capability count + capability descriptors
//! ```

use std::collections::BTreeSet;

use crate::budget::Budget;
use crate::cap::{CapAttrs, CapId};
use crate::error::{Error, Result};
use crate::promise::PromiseId;
use crate::value::{Arg, Value};

/// Refuse a value whose node count or width the decoder would refuse.
///
/// `write_value_at` bounds depth only; the decoder also decrements a cumulative
/// `max_values` per value (and per map key) and refuses a container past
/// `max_array_len`. Without this walk the encoder emitted frames its own reader
/// rejected, after the call had been charged (round 40, R-07-3).
fn check_value_limits(value: &Value, limits: &WireLimits, remaining: &mut u64) -> Result<()> {
    let widest = u64::from(limits.max_array_len);
    let mut stack: Vec<&Value> = vec![value];
    while let Some(value) = stack.pop() {
        *remaining = remaining
            .checked_sub(1)
            .ok_or(Error::Wire("value count exceeds the ceiling"))?;
        match value {
            Value::List(items) => {
                if items.len() as u64 > widest {
                    return Err(Error::Wire("list is wider than the ceiling"));
                }
                stack.extend(items.iter());
            }
            Value::Map(entries) => {
                if entries.len() as u64 > widest {
                    return Err(Error::Wire("map is wider than the ceiling"));
                }
                for item in entries.values() {
                    // A key is a value on the wire; the reader charges it.
                    *remaining = remaining
                        .checked_sub(1)
                        .ok_or(Error::Wire("value count exceeds the ceiling"))?;
                    stack.push(item);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Refuse a descriptor the decoder would refuse.
///
/// Shared by the envelope writer and the standalone table encoder so the two
/// cannot drift: a descriptor method longer than the table's ceiling used to
/// encode here and be refused by every reader (round 41, F3).
fn check_descriptor(cap: &CapDescriptor, limits: &WireLimits) -> Result<()> {
    if cap.id.0 == [0u8; 16] {
        return Err(Error::CapabilityTable("zero capability id"));
    }
    if cap.methods.is_empty() {
        return Err(Error::CapabilityTable("capability grants no methods"));
    }
    cap.budget
        .check()
        .map_err(|_| Error::CapabilityTable("budget disables a ceiling"))?;
    if cap.methods.len() > limits.max_methods as usize {
        return Err(Error::CapabilityTable("too many methods"));
    }
    if cap
        .methods
        .iter()
        .any(|method| method.len() > limits.max_method as usize)
    {
        return Err(Error::CapabilityTable("method name exceeds the ceiling"));
    }
    if cap
        .path_scope
        .as_deref()
        .is_some_and(|path| path.len() > limits.max_path as usize)
    {
        return Err(Error::CapabilityTable("path scope exceeds the ceiling"));
    }
    Ok(())
}

/// Envelope magic.
pub const MAGIC: [u8; 4] = *b"ARP1";
/// Envelope version.
pub const VERSION: u8 = 1;
/// Flag: the caller asks for redacted output.
pub const FLAG_REDACT: u16 = 1 << 0;
/// Flag: the capability is read-only.
pub const FLAG_READ_ONLY: u16 = 1 << 1;
/// Flag: the envelope carries a capability-table delta after the full-table slot.
pub const FLAG_CAP_DELTA: u16 = 1 << 2;
/// All understood flags.
pub const FLAG_KNOWN: u16 = FLAG_REDACT | FLAG_READ_ONLY | FLAG_CAP_DELTA;

/// Envelope kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A method call.
    Request,
    /// A result.
    Response,
    /// An error with a stable code.
    Error,
    /// A capability handshake (hello/announce).
    Hello,
}

impl Kind {
    /// The wire byte for this kind. Codes are permanent.
    pub const fn code(self) -> u8 {
        match self {
            Kind::Request => 1,
            Kind::Response => 2,
            Kind::Error => 3,
            Kind::Hello => 4,
        }
    }

    /// Parse a wire byte; an unknown kind is `None`, never a guess.
    pub const fn from_code(code: u8) -> Option<Kind> {
        match code {
            1 => Some(Kind::Request),
            2 => Some(Kind::Response),
            3 => Some(Kind::Error),
            4 => Some(Kind::Hello),
            _ => None,
        }
    }
}

/// A capability descriptor travelling with an envelope.
#[derive(Debug, Clone, PartialEq)]
pub struct CapDescriptor {
    /// Capability id.
    pub id: CapId,
    /// Methods the capability grants.
    pub methods: BTreeSet<String>,
    /// Budget ceilings.
    pub budget: Budget,
    /// Read-only flag.
    pub read_only: bool,
    /// Redaction flag.
    pub redact: bool,
    /// Optional path scope.
    pub path_scope: Option<String>,
}

impl CapDescriptor {
    /// Build the wire view of a capability.
    ///
    /// A descriptor carries the subset a peer can use to *plan* a call: id,
    /// methods, budget, read-only, redaction and path scope. Persistence, the tool
    /// policy and the identity binding stay local to the minting kernel and are
    /// never widened by a descriptor; a descriptor grants nothing on the receiving
    /// side either (the registry is the authority).
    pub fn from_attrs(id: CapId, attrs: &CapAttrs) -> Self {
        Self {
            id,
            methods: attrs.methods.clone(),
            budget: attrs.budget,
            read_only: attrs.read_only,
            redact: attrs.redact,
            path_scope: attrs.path_scope.clone(),
        }
    }
}

/// A capability-table delta negotiated against a known base table.
#[derive(Debug, Clone, PartialEq)]
pub struct CapTableDelta {
    /// Blake3 hash of the base capability table.
    pub base: [u8; 32],
    /// Capability ids removed from the base.
    pub removed: Vec<CapId>,
    /// Descriptors added to the base.
    pub added: Vec<CapDescriptor>,
}

impl CapTableDelta {
    /// Build a delta against a base table.
    pub fn new(
        base: &[CapDescriptor],
        removed: Vec<CapId>,
        added: Vec<CapDescriptor>,
    ) -> Result<Self> {
        Ok(Self {
            base: cap_table_hash(base)?,
            removed,
            added,
        })
    }

    /// Apply to a base table after checking the base hash. Fail closed on an
    /// unknown base or a removal of an id that is not present.
    ///
    /// The per-delta ceilings are the default profile's (`max_caps`), the same
    /// numbers the envelope writer and reader use: a delta this method applies
    /// is one the wire can carry. An embedder that tightened its profile must
    /// enforce that profile itself; the negotiated table's absolute ceiling is
    /// [`MAX_CAP_TABLE`] (round 37, L2).
    pub fn apply_to(&self, base: &[CapDescriptor]) -> Result<Vec<CapDescriptor>> {
        if cap_table_hash(base)? != self.base {
            return Err(Error::CapabilityTable("cap-table delta base mismatch"));
        }
        if base.len() < self.removed.len() {
            return Err(Error::CapabilityTable("delta removes more than the base"));
        }
        let limits = WireLimits::default();
        // One delta is bounded like one envelope: a programmatic delta with 300
        // additions applied locally but could never be encoded or decoded
        // (round 36, #2).
        if self.added.len() > limits.max_caps as usize
            || self.removed.len() > limits.max_caps as usize
        {
            return Err(Error::CapabilityTable("delta exceeds the ceiling"));
        }
        let resulting = base.len() - self.removed.len() + self.added.len();
        if resulting > MAX_CAP_TABLE {
            return Err(Error::CapabilityTable(
                "cap-table delta exceeds the table ceiling",
            ));
        }
        {
            // The programmatic path must not admit something the wire path would
            // refuse: the same descriptor rule, ceilings included, applies
            // whichever way a descriptor arrived (round 35, N2).
            for cap in &self.added {
                check_descriptor(cap, &limits)?;
            }
        }
        // An added id that already exists in the *base* table is a replacement.
        // Removing and re-adding an id would let a wider descriptor bypass the
        // attenuation/import rules that adding a new id must satisfy.
        for descriptor in &self.added {
            if base.iter().any(|cap| cap.id == descriptor.id) {
                return Err(Error::CapabilityTable(
                    "delta replaces an existing capability",
                ));
            }
        }
        let mut table = base.to_vec();
        for id in &self.removed {
            let Some(index) = table.iter().position(|cap| &cap.id == id) else {
                return Err(Error::CapabilityTable(
                    "delta removes an unknown capability",
                ));
            };
            table.remove(index);
        }
        for descriptor in &self.added {
            if table.iter().any(|cap| cap.id == descriptor.id) {
                return Err(Error::CapabilityTable("delta adds an existing capability"));
            }
            table.push(descriptor.clone());
        }
        table.sort_by_key(|cap| cap.id.hex());
        Ok(table)
    }
}

/// Largest capability table a delta may build.
///
/// The decoder bounds one envelope's additions and removals, but a connection
/// keeps one table and applies every delta it receives: without a ceiling a
/// peer could grow the negotiated table until memory runs out.
pub const MAX_CAP_TABLE: usize = 4_096;

/// Blake3 hash of the canonical capability table encoding.
///
/// Fails closed: a table that cannot be encoded has no hash, so it can never
/// collide with a real base and be accepted as a delta base by accident.
pub fn cap_table_hash(caps: &[CapDescriptor]) -> Result<[u8; 32]> {
    let encoded = encode_capability_table(caps)?;
    Ok(*blake3::hash(&encoded).as_bytes())
}

/// One Active RPC envelope.
///
/// `Debug` is written by hand: the payload is opaque bytes (an in-process
/// provider may hand back a large blob) and a derived formatter would dump it
/// into every log line. Formatting shows sizes and a bounded method label
/// (F-02).
#[derive(Clone, PartialEq)]
pub struct Envelope {
    /// Envelope kind.
    pub kind: Kind,
    /// Request id, echoed by the response.
    pub request_id: u64,
    /// Method name (requests) or error code (errors).
    pub method: String,
    /// Arguments, in order.
    pub args: Vec<Arg>,
    /// Optional Infinity payload (module bytes).
    pub payload: Vec<u8>,
    /// Capability descriptors travelling with this envelope.
    pub caps: Vec<CapDescriptor>,
    /// Redaction hint.
    pub redact: bool,
    /// Read-only hint.
    pub read_only: bool,
    /// Optional capability-table delta relative to a negotiated base.
    pub cap_delta: Option<CapTableDelta>,
}

impl std::fmt::Debug for Envelope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Envelope {{ kind: {:?}, request_id: {}, method: {:?}, args: {}, payload: {} bytes, \
             caps: {}, redact: {}, read_only: {}, cap_delta: {} }}",
            self.kind,
            self.request_id,
            debug_label(&self.method),
            self.args.len(),
            self.payload.len(),
            self.caps.len(),
            self.redact,
            self.read_only,
            self.cap_delta.is_some(),
        )
    }
}

/// A bounded, escaped label for a debug line.
///
/// A hand-built envelope may carry a method far past the wire ceiling; a log
/// line must stay a log line (F-02).
fn debug_label(text: &str) -> String {
    let mut label = String::new();
    for (index, character) in text.chars().enumerate() {
        if index == 64 {
            label.push('…');
            break;
        }
        label.push(character);
    }
    label
}

/// Envelope size and count ceilings for untrusted input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireLimits {
    /// Maximum total envelope bytes.
    pub max_bytes: usize,
    /// Maximum arguments.
    pub max_args: u32,
    /// Maximum method-name bytes.
    pub max_method: u32,
    /// Maximum payload bytes.
    pub max_payload: u32,
    /// Maximum capability descriptors.
    pub max_caps: u32,
    /// Maximum methods per descriptor.
    pub max_methods: u32,
    /// Maximum values one envelope may decode to, cumulatively.
    ///
    /// A frame is bounded by bytes, but a byte can be a whole value (`Null`),
    /// so a 64 MiB frame of nulls is 64 million `Value`s. This ceiling bounds
    /// the decoded arena, not the frame.
    pub max_values: u32,
    /// Maximum elements in one list or map.
    pub max_array_len: u32,
    /// Maximum path-scope bytes in a capability descriptor.
    pub max_path: u32,
}

impl Default for WireLimits {
    fn default() -> Self {
        Self {
            max_bytes: 64 << 20,
            max_args: 1 << 12,
            // The same bound the kernel mints against
            // (`kernel::MAX_GRANTED_METHOD_BYTES`) and the receipts accept:
            // three numbers disagreed, so a capability could be granted a name
            // no transport in this crate could encode (round 40, R-07-4).
            max_method: 1_024,
            max_payload: 32 << 20,
            max_caps: 1 << 8,
            max_methods: 64,
            max_values: 1 << 20,
            max_array_len: 1 << 20,
            max_path: 1_024,
        }
    }
}

impl WireLimits {
    /// Tight profile for adversarial surfaces.
    pub fn strict() -> Self {
        Self {
            max_bytes: 1 << 20,
            max_args: 64,
            max_method: 64,
            max_payload: 1 << 20,
            max_caps: 16,
            max_methods: 16,
            max_values: 1 << 16,
            max_array_len: 1 << 12,
            max_path: 128,
        }
    }
}

/// Write a length prefix, refusing a value the wire cannot carry.
///
/// Every length in this format is a `u32`; a cast wrapped past 4 GiB instead
/// of refusing, which breaks the re-encode-stability rule (round 28, #5).
fn put_len(out: &mut Vec<u8>, len: usize) -> Result<()> {
    let len = u32::try_from(len).map_err(|_| Error::Wire("length exceeds the wire"))?;
    out.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

impl Envelope {
    /// A request envelope.
    pub fn request(request_id: u64, method: impl Into<String>, args: Vec<Arg>) -> Self {
        Self {
            kind: Kind::Request,
            request_id,
            method: method.into(),
            args,
            payload: Vec::new(),
            caps: Vec::new(),
            redact: false,
            read_only: false,
            cap_delta: None,
        }
    }

    /// A response envelope.
    pub fn response(request_id: u64, value: Value) -> Self {
        Self {
            kind: Kind::Response,
            request_id,
            method: String::new(),
            args: vec![Arg::Value(value)],
            payload: Vec::new(),
            caps: Vec::new(),
            redact: false,
            read_only: false,
            cap_delta: None,
        }
    }

    /// Longest provider code an error envelope carries, in bytes.
    ///
    /// The destination field is bounded on decode (`WireLimits::max_method`: 1024
    /// by default, 64 in the strict profile), and a provider code may embed OS
    /// text, so
    /// a longer code falls back to `rpc/provider`. The trace keeps the full code
    /// (round 34, M-3).
    pub const MAX_ENVELOPE_PROVIDER_CODE: usize = 64;

    fn bounded_provider_code(code: &str) -> &str {
        // ASCII, bounded, and free of control or reordering characters: a
        // provider code may embed OS text, and a newline would forge a line in
        // the peer's error log (round 37, D).
        let clean = code.chars().all(|character| {
            !character.is_control() && !crate::security::is_invisible_or_reordering(character)
        });
        if code.len() <= Self::MAX_ENVELOPE_PROVIDER_CODE && code.is_ascii() && clean {
            code
        } else {
            "rpc/provider"
        }
    }

    /// An error envelope.
    pub fn error(request_id: u64, error: &Error) -> Self {
        Self {
            kind: Kind::Error,
            request_id,
            // The inner provider code is the bit a peer needs: `rpc/provider`
            // alone cannot say whether a mutating call landed, and a caller
            // that retries a withheld reply writes twice (round 33, F3). The
            // field is bounded on decode, so an over-long code (a provider
            // code may embed OS text) falls back to the class instead of
            // making the refusal undecodable (round 34, M-3).
            method: error
                .provider_code()
                .map(Self::bounded_provider_code)
                .unwrap_or_else(|| error.code())
                .to_string(),
            args: Vec::new(),
            payload: Vec::new(),
            caps: Vec::new(),
            redact: false,
            read_only: false,
            cap_delta: None,
        }
    }

    /// Whether this envelope is the answer to `request_id`.
    ///
    /// A response must echo the id. An error may carry id `0`, the id a peer
    /// writes when the frame was refused before it could be decoded far enough
    /// to learn the caller's id. A request, or another call's answer, is never
    /// this call's answer (round 13, R-09 #3).
    pub fn answers(&self, request_id: u64) -> bool {
        match self.kind {
            Kind::Response => self.request_id == request_id,
            Kind::Error => self.request_id == request_id || self.request_id == 0,
            _ => false,
        }
    }

    /// Attach a capability-table delta and set the negotiation flag.
    pub fn with_cap_delta(mut self, delta: CapTableDelta) -> Self {
        self.cap_delta = Some(delta);
        self
    }

    /// Attach an Infinity payload.
    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    /// Attach capability descriptors.
    pub fn with_caps(mut self, caps: Vec<CapDescriptor>) -> Self {
        self.caps = caps;
        self
    }

    /// Serialize under the default profile.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.encode_with_limits(WireLimits::default())
    }

    /// Serialize under a caller's profile.
    ///
    /// A peer that decodes with `WireLimits::strict()` should encode with the
    /// same limits, so a frame is refused by the sender rather than by the
    /// receiver (F-09). `encode()` stays the default-profile form.
    pub fn encode_with_limits(&self, limits: WireLimits) -> Result<Vec<u8>> {
        // Encoding is documented as the inverse of decoding: a frame this
        // crate would refuse must be refused locally, not by the peer
        // (round 39, L-7).
        self.check_limits(&limits)?;
        let mut out = Vec::with_capacity(32 + self.payload.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(self.kind.code());
        let mut flags = 0u16;
        if self.redact {
            flags |= FLAG_REDACT;
        }
        if self.read_only {
            flags |= FLAG_READ_ONLY;
        }
        if self.cap_delta.is_some() {
            flags |= FLAG_CAP_DELTA;
        }
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&self.request_id.to_le_bytes());
        write_str(&mut out, &self.method)?;
        if self.args.len() > u32::MAX as usize {
            return Err(Error::Wire("too many arguments"));
        }
        put_len(&mut out, self.args.len())?;
        for arg in &self.args {
            write_arg(&mut out, arg)?;
        }
        if self.payload.len() > u32::MAX as usize {
            return Err(Error::Wire("payload too large"));
        }
        put_len(&mut out, self.payload.len())?;
        out.extend_from_slice(&self.payload);
        put_len(&mut out, self.caps.len())?;
        for cap in &self.caps {
            write_cap(&mut out, cap)?;
        }
        if let Some(delta) = &self.cap_delta {
            out.extend_from_slice(&delta.base);
            put_len(&mut out, delta.removed.len())?;
            for id in &delta.removed {
                out.extend_from_slice(&id.0);
            }
            put_len(&mut out, delta.added.len())?;
            for cap in &delta.added {
                write_cap(&mut out, cap)?;
            }
        }
        if out.len() > limits.max_bytes {
            return Err(Error::Wire("envelope exceeds the size ceiling"));
        }
        Ok(out)
    }

    /// Refuse an envelope this crate's own decoder would refuse.
    fn check_limits(&self, limits: &WireLimits) -> Result<()> {
        if self.method.len() > limits.max_method as usize {
            return Err(Error::Wire("method name exceeds the ceiling"));
        }
        if self.args.len() > limits.max_args as usize {
            return Err(Error::Wire("argument count exceeds the ceiling"));
        }
        // One counter for the whole frame: the decoder's ceiling is cumulative,
        // so two arguments that each fit are still over it together
        // (round 34, #4).
        let mut remaining_values = u64::from(limits.max_values);
        for arg in &self.args {
            if let Arg::Value(value) = arg {
                check_value_limits(value, limits, &mut remaining_values)?;
            }
        }
        if self.payload.len() > limits.max_payload as usize {
            // A ceiling is `rpc/wire`, like every other limit: `rpc/payload`
            // means "this is not an image", which would send a caller to fix a
            // payload that is merely too large (round 33, H2).
            return Err(Error::Wire("payload exceeds the ceiling"));
        }
        if self.caps.len() > limits.max_caps as usize {
            return Err(Error::CapabilityTable("too many descriptors"));
        }
        for cap in self
            .caps
            .iter()
            .chain(self.cap_delta.iter().flat_map(|delta| delta.added.iter()))
        {
            check_descriptor(cap, limits)?;
        }
        let mut ids = std::collections::BTreeSet::new();
        for cap in self
            .caps
            .iter()
            .chain(self.cap_delta.iter().flat_map(|delta| delta.added.iter()))
        {
            if !ids.insert(cap.id) {
                // The decoder refuses a repeated id: a table order would decide
                // which descriptor wins (round 33, M4).
                return Err(Error::CapabilityTable("duplicate capability id"));
            }
        }
        if let Some(delta) = &self.cap_delta {
            if delta.removed.len() > limits.max_caps as usize
                || delta.added.len() > limits.max_caps as usize
            {
                return Err(Error::CapabilityTable("delta exceeds the ceiling"));
            }
        }
        Ok(())
    }

    /// Parse with default limits.
    pub fn decode(bytes: &[u8]) -> Result<Envelope> {
        Self::decode_with(bytes, WireLimits::default())
    }

    /// Parse with explicit limits.
    pub fn decode_with(bytes: &[u8], limits: WireLimits) -> Result<Envelope> {
        if bytes.len() > limits.max_bytes {
            return Err(Error::Wire("envelope exceeds the size ceiling"));
        }
        if bytes.len() < 16 || bytes[0..4] != MAGIC {
            return Err(Error::Wire("bad magic"));
        }
        if bytes[4] != VERSION {
            return Err(Error::Wire("unsupported envelope version"));
        }
        let kind = Kind::from_code(bytes[5]).ok_or(Error::Wire("unknown envelope kind"))?;
        let flags = u16::from_le_bytes([bytes[6], bytes[7]]);
        if flags & !FLAG_KNOWN != 0 {
            return Err(Error::Wire("unknown envelope flags"));
        }
        let request_id = u64::from_le_bytes(bytes[8..16].try_into().expect("8 bytes"));
        let mut cursor = 16usize;
        let method = read_str(bytes, &mut cursor, limits.max_method)?;
        let arg_count = read_u32(bytes, &mut cursor)?;
        if arg_count > limits.max_args {
            return Err(Error::Wire("argument count exceeds the ceiling"));
        }
        let mut args = Vec::with_capacity(arg_count as usize);
        let mut remaining_values = limits.max_values;
        for _ in 0..arg_count {
            args.push(read_arg(
                bytes,
                &mut cursor,
                &mut remaining_values,
                limits.max_array_len,
            )?);
        }
        let payload_len = read_u32(bytes, &mut cursor)?;
        if payload_len > limits.max_payload {
            return Err(Error::Wire("payload exceeds the ceiling"));
        }
        let payload_end = cursor
            .checked_add(payload_len as usize)
            .ok_or(Error::Wire("payload length overflow"))?;
        if payload_end > bytes.len() {
            return Err(Error::Wire("truncated payload"));
        }
        let payload = bytes[cursor..payload_end].to_vec();
        cursor = payload_end;
        let cap_count = read_u32(bytes, &mut cursor)
            .map_err(|_| Error::CapabilityTable("truncated capability table"))?;
        if cap_count > limits.max_caps {
            return Err(Error::CapabilityTable("too many descriptors"));
        }
        let mut caps = Vec::with_capacity(cap_count as usize);
        let mut seen: BTreeSet<[u8; 16]> = BTreeSet::new();
        for _ in 0..cap_count {
            let descriptor = read_cap(bytes, &mut cursor, &limits)?;
            if !seen.insert(descriptor.id.0) {
                // The same id twice with different descriptors would make the
                // table's meaning depend on import order (the delta path already
                // refuses this).
                return Err(Error::CapabilityTable("duplicate capability id"));
            }
            caps.push(descriptor);
        }
        let cap_delta = if flags & FLAG_CAP_DELTA != 0 {
            if cursor + 32 > bytes.len() {
                return Err(Error::CapabilityTable("truncated cap-table delta"));
            }
            let mut base = [0u8; 32];
            base.copy_from_slice(&bytes[cursor..cursor + 32]);
            cursor += 32;
            let removed_count = read_u32(bytes, &mut cursor)
                .map_err(|_| Error::CapabilityTable("truncated cap-table delta"))?;
            if removed_count > limits.max_caps {
                return Err(Error::CapabilityTable("too many delta removals"));
            }
            let mut removed = Vec::with_capacity(removed_count as usize);
            for _ in 0..removed_count {
                if cursor + 16 > bytes.len() {
                    return Err(Error::CapabilityTable("truncated delta id"));
                }
                let mut id = [0u8; 16];
                id.copy_from_slice(&bytes[cursor..cursor + 16]);
                cursor += 16;
                removed.push(CapId(id));
            }
            let added_count = read_u32(bytes, &mut cursor)
                .map_err(|_| Error::CapabilityTable("truncated cap-table delta"))?;
            if added_count > limits.max_caps {
                return Err(Error::CapabilityTable("too many delta additions"));
            }
            let mut added = Vec::with_capacity(added_count as usize);
            for _ in 0..added_count {
                added.push(read_cap(bytes, &mut cursor, &limits)?);
            }
            for descriptor in &added {
                // A delta addition that repeats an id the table already names
                // (or another addition) makes the table order-dependent. The
                // writer refuses that union, so the reader must too
                // (round 40, residual R-6).
                if !seen.insert(descriptor.id.0) {
                    return Err(Error::CapabilityTable("duplicate capability id"));
                }
            }
            Some(CapTableDelta {
                base,
                removed,
                added,
            })
        } else {
            None
        };
        if cursor != bytes.len() {
            return Err(Error::Wire("trailing bytes"));
        }
        Ok(Envelope {
            kind,
            request_id,
            method,
            args,
            payload,
            caps,
            redact: flags & FLAG_REDACT != 0,
            read_only: flags & FLAG_READ_ONLY != 0,
            cap_delta,
        })
    }

    /// The first value argument, when present.
    pub fn first_value(&self) -> Option<&Value> {
        self.args.iter().find_map(|arg| match arg {
            Arg::Value(value) => Some(value),
            _ => None,
        })
    }
}

fn write_str(out: &mut Vec<u8>, text: &str) -> Result<()> {
    if text.len() > u32::MAX as usize {
        return Err(Error::Wire("string too large"));
    }
    put_len(out, text.len())?;
    out.extend_from_slice(text.as_bytes());
    Ok(())
}

fn write_opt_str(out: &mut Vec<u8>, text: &Option<String>) -> Result<()> {
    match text {
        None => {
            out.push(0);
            Ok(())
        }
        Some(text) => {
            out.push(1);
            write_str(out, text)
        }
    }
}

fn write_arg(out: &mut Vec<u8>, arg: &Arg) -> Result<()> {
    match arg {
        Arg::Value(value) => {
            out.push(0);
            write_value(out, value)
        }
        Arg::Promise(id) => {
            out.push(1);
            out.extend_from_slice(&id.0.to_le_bytes());
            Ok(())
        }
        Arg::Cap(id) => {
            out.push(2);
            out.extend_from_slice(&id.0);
            Ok(())
        }
    }
}

fn write_value(out: &mut Vec<u8>, value: &Value) -> Result<()> {
    write_value_at(out, value, 0)
}

fn write_value_at(out: &mut Vec<u8>, value: &Value, depth: usize) -> Result<()> {
    // The decoder refuses a value deeper than the ceiling, so the encoder must
    // too: recursing first would overflow the stack on a value the kernel would
    // never accept (round 2, #2).
    if depth > MAX_VALUE_DEPTH {
        return Err(Error::Wire("value nesting exceeds the ceiling"));
    }
    match value {
        Value::Null => out.push(0),
        Value::Bool(flag) => {
            out.push(1);
            out.push(u8::from(*flag));
        }
        Value::Int(number) => {
            out.push(2);
            out.extend_from_slice(&number.to_le_bytes());
        }
        Value::Float(number) => {
            out.push(3);
            out.extend_from_slice(&number.to_bits().to_le_bytes());
        }
        Value::Text(text) => {
            out.push(4);
            write_str(out, text)?;
        }
        Value::List(items) => {
            out.push(5);
            // A length past `u32` cannot be carried by the wire; refuse it
            // rather than write a truncated count (round 27, #5).
            let count = u32::try_from(items.len()).map_err(|_| Error::Wire("list too long"))?;
            out.extend_from_slice(&count.to_le_bytes());
            for item in items {
                write_value_at(out, item, depth + 1)?;
            }
        }
        Value::Map(entries) => {
            out.push(6);
            let count = u32::try_from(entries.len()).map_err(|_| Error::Wire("map too large"))?;
            out.extend_from_slice(&count.to_le_bytes());
            for (key, value) in entries {
                write_str(out, key)?;
                write_value_at(out, value, depth + 1)?;
            }
        }
        Value::Secret => out.push(7),
        Value::Module(bytes) => {
            out.push(8);
            put_len(out, bytes.len())?;
            out.extend_from_slice(bytes);
        }
        Value::Path(path) => {
            out.push(9);
            write_str(out, path)?;
        }
    }
    Ok(())
}

fn write_cap(out: &mut Vec<u8>, cap: &CapDescriptor) -> Result<()> {
    out.extend_from_slice(&cap.id.0);
    put_len(out, cap.methods.len())?;
    for method in &cap.methods {
        write_str(out, method)?;
    }
    write_budget(out, &cap.budget);
    out.push(u8::from(cap.read_only));
    out.push(u8::from(cap.redact));
    write_opt_str(out, &cap.path_scope)
}

fn write_budget(out: &mut Vec<u8>, budget: &Budget) {
    for value in [
        budget.max_calls,
        budget.max_bytes,
        budget.max_wall_ms,
        budget.max_nodes,
        budget.max_depth,
        budget.max_array_len,
        budget.max_value_size,
    ] {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8> {
    if *cursor >= bytes.len() {
        return Err(Error::Wire("truncated"));
    }
    let value = bytes[*cursor];
    *cursor += 1;
    Ok(value)
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32> {
    if *cursor + 4 > bytes.len() {
        return Err(Error::Wire("truncated"));
    }
    let value = u32::from_le_bytes(bytes[*cursor..*cursor + 4].try_into().expect("4 bytes"));
    *cursor += 4;
    Ok(value)
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    if *cursor + 8 > bytes.len() {
        return Err(Error::Wire("truncated"));
    }
    let value = u64::from_le_bytes(bytes[*cursor..*cursor + 8].try_into().expect("8 bytes"));
    *cursor += 8;
    Ok(value)
}

fn read_str(bytes: &[u8], cursor: &mut usize, max: u32) -> Result<String> {
    let len = read_u32(bytes, cursor)?;
    if len > max {
        return Err(Error::Wire("string exceeds the ceiling"));
    }
    let end = cursor
        .checked_add(len as usize)
        .ok_or(Error::Wire("length overflow"))?;
    if end > bytes.len() {
        return Err(Error::Wire("truncated string"));
    }
    let text = std::str::from_utf8(&bytes[*cursor..end])
        .map_err(|_| Error::Wire("string is not UTF-8"))?
        .to_string();
    *cursor = end;
    Ok(text)
}

fn read_opt_str(bytes: &[u8], cursor: &mut usize, max: u32) -> Result<Option<String>> {
    match read_u8(bytes, cursor)? {
        0 => Ok(None),
        1 => Ok(Some(read_str(bytes, cursor, max)?)),
        _ => Err(Error::CapabilityTable("invalid optional string tag")),
    }
}

fn read_arg(
    bytes: &[u8],
    cursor: &mut usize,
    remaining_values: &mut u32,
    max_array_len: u32,
) -> Result<Arg> {
    let tag = read_u8(bytes, cursor)?;
    match tag {
        0 => Ok(Arg::Value(read_value(
            bytes,
            cursor,
            remaining_values,
            max_array_len,
        )?)),
        1 => {
            let id = read_u64(bytes, cursor)?;
            Ok(Arg::Promise(PromiseId(id)))
        }
        2 => {
            let mut id = [0u8; 16];
            if *cursor + 16 > bytes.len() {
                return Err(Error::Wire("truncated capability id"));
            }
            id.copy_from_slice(&bytes[*cursor..*cursor + 16]);
            *cursor += 16;
            Ok(Arg::Cap(CapId(id)))
        }
        _ => Err(Error::Wire("unknown argument tag")),
    }
}

/// Deepest value nesting an envelope may carry.
pub const MAX_VALUE_DEPTH: usize = 64;

fn read_value(
    bytes: &[u8],
    cursor: &mut usize,
    remaining_values: &mut u32,
    max_array_len: u32,
) -> Result<Value> {
    read_value_at(
        bytes,
        cursor,
        0,
        bytes.len(),
        remaining_values,
        max_array_len,
    )
}

fn read_value_at(
    bytes: &[u8],
    cursor: &mut usize,
    depth: usize,
    budget: usize,
    remaining_values: &mut u32,
    max_array_len: u32,
) -> Result<Value> {
    if depth > MAX_VALUE_DEPTH {
        return Err(Error::Wire("value nesting exceeds the ceiling"));
    }
    // One byte can decode to one value, so the byte ceiling alone does not bound
    // the arena: a 64 MiB frame of nulls is 64 million `Value`s.
    *remaining_values = remaining_values
        .checked_sub(1)
        .ok_or(Error::Wire("value count exceeds the ceiling"))?;
    let tag = read_u8(bytes, cursor)?;
    let value = match tag {
        0 => Value::Null,
        1 => match read_u8(bytes, cursor)? {
            // A boolean that decodes but re-encodes to a different byte breaks
            // re-encode stability (§8.5), so only 0 and 1 are admissible.
            0 => Value::Bool(false),
            1 => Value::Bool(true),
            _ => return Err(Error::Wire("boolean is not 0 or 1")),
        },
        2 => Value::Int(read_u64(bytes, cursor)? as i64),
        3 => Value::Float(f64::from_bits(read_u64(bytes, cursor)?)),
        4 => Value::Text(read_str(
            bytes,
            cursor,
            budget.min(u32::MAX as usize) as u32,
        )?),
        5 => {
            let count = read_u32(bytes, cursor)?;
            // A list cannot hold more elements than there are bytes left.
            if count as usize > budget {
                return Err(Error::Wire("list too long"));
            }
            if count > max_array_len {
                return Err(Error::Wire("list is wider than the ceiling"));
            }
            // Never preallocate from an untrusted count: the loop grows the
            // vector and stops when the input runs out.
            let mut items = Vec::with_capacity((count as usize).min(1024));
            for _ in 0..count {
                items.push(read_value_at(
                    bytes,
                    cursor,
                    depth + 1,
                    budget,
                    remaining_values,
                    max_array_len,
                )?);
            }
            Value::List(items)
        }
        6 => {
            let count = read_u32(bytes, cursor)?;
            if count as usize > budget {
                return Err(Error::Wire("map too large"));
            }
            if count > max_array_len {
                return Err(Error::Wire("map is wider than the ceiling"));
            }
            let mut entries = std::collections::BTreeMap::new();
            for _ in 0..count {
                // A key is a value: a 1 MiB map of keys cost one insert each
                // without ever charging `max_values` (round 24, #7).
                *remaining_values = remaining_values
                    .checked_sub(1)
                    .ok_or(Error::Wire("value count exceeds the ceiling"))?;
                let key = read_str(bytes, cursor, budget.min(u32::MAX as usize) as u32)?;
                let value = read_value_at(
                    bytes,
                    cursor,
                    depth + 1,
                    budget,
                    remaining_values,
                    max_array_len,
                )?;
                // Keys are strictly increasing. A duplicate decodes to one
                // entry, and an out-of-order map re-encodes sorted: either way
                // two byte images would name one value and the raw-hash
                // agreement a replay package relies on would break (§8.5).
                if let Some(last) = entries.keys().next_back() {
                    if key == *last {
                        return Err(Error::Wire("duplicate map key"));
                    }
                    if key < *last {
                        return Err(Error::Wire("map keys are not in canonical order"));
                    }
                }
                entries.insert(key, value);
            }
            Value::Map(entries)
        }
        7 => Value::Secret,
        8 => {
            let len = read_u32(bytes, cursor)?;
            if len as usize > budget {
                return Err(Error::Wire("module payload exceeds the ceiling"));
            }
            let end = cursor
                .checked_add(len as usize)
                .ok_or(Error::Wire("length overflow"))?;
            if end > bytes.len() {
                return Err(Error::Wire("truncated module"));
            }
            let module = bytes[*cursor..end].to_vec();
            *cursor = end;
            Value::Module(module)
        }
        9 => Value::Path(read_str(
            bytes,
            cursor,
            budget.min(u32::MAX as usize) as u32,
        )?),
        _ => return Err(Error::Wire("unknown value tag")),
    };
    Ok(value)
}

fn read_budget(bytes: &[u8], cursor: &mut usize) -> Result<Budget> {
    Ok(Budget {
        max_calls: read_u64(bytes, cursor)?,
        max_bytes: read_u64(bytes, cursor)?,
        max_wall_ms: read_u64(bytes, cursor)?,
        max_nodes: read_u64(bytes, cursor)?,
        max_depth: read_u64(bytes, cursor)?,
        max_array_len: read_u64(bytes, cursor)?,
        max_value_size: read_u64(bytes, cursor)?,
    })
}

fn read_cap(bytes: &[u8], cursor: &mut usize, limits: &WireLimits) -> Result<CapDescriptor> {
    // Every fault inside a descriptor is a capability-table fault (§3.1), so the
    // scalar readers are mapped here instead of leaking `rpc/wire`.
    let table = |error: Error| match error {
        // A descriptor-level refusal keeps its reason; only the scalar readers
        // (which speak `rpc/wire`) are translated.
        Error::CapabilityTable(_) => error,
        Error::Wire(message) => Error::CapabilityTable(message),
        _ => Error::CapabilityTable("malformed capability descriptor"),
    };
    read_cap_inner(bytes, cursor, limits).map_err(table)
}

fn read_cap_inner(bytes: &[u8], cursor: &mut usize, limits: &WireLimits) -> Result<CapDescriptor> {
    let mut id = [0u8; 16];
    if *cursor + 16 > bytes.len() {
        return Err(Error::CapabilityTable("truncated capability id"));
    }
    id.copy_from_slice(&bytes[*cursor..*cursor + 16]);
    *cursor += 16;
    if id == [0u8; 16] {
        return Err(Error::CapabilityTable("zero capability id"));
    }
    let count = read_u32(bytes, cursor)?;
    if count > limits.max_methods {
        return Err(Error::CapabilityTable("too many methods"));
    }
    if count == 0 {
        // A descriptor that grants no method is not a capability; `mint` and
        // `attenuate` refuse it, so the wire path must not admit one either.
        return Err(Error::CapabilityTable("capability grants no methods"));
    }
    let mut methods = BTreeSet::new();
    for _ in 0..count {
        // The method bound is the caller's profile, not a constant: a strict
        // peer refused 100-byte methods at the envelope but accepted them in a
        // descriptor (round 2, #6).
        let method = read_str(bytes, cursor, limits.max_method)?;
        // Strictly increasing, like a map's keys: a duplicate or a reordered set
        // would decode to a smaller or sorted set and re-encode differently,
        // diverging from a delta base negotiated on raw bytes.
        if let Some(last) = methods.last() {
            if method == *last {
                return Err(Error::CapabilityTable("duplicate method name"));
            }
            if method < *last {
                return Err(Error::CapabilityTable(
                    "method names are not in canonical order",
                ));
            }
        }
        methods.insert(method);
    }
    let budget = read_budget(bytes, cursor)?;
    budget
        .check()
        .map_err(|_| Error::CapabilityTable("budget disables a ceiling"))?;
    let read_only = match read_u8(bytes, cursor)? {
        0 => false,
        1 => true,
        _ => return Err(Error::CapabilityTable("read_only is not 0 or 1")),
    };
    let redact = match read_u8(bytes, cursor)? {
        0 => false,
        1 => true,
        _ => return Err(Error::CapabilityTable("redact is not 0 or 1")),
    };
    let path_scope = read_opt_str(bytes, cursor, limits.max_path)?;
    Ok(CapDescriptor {
        id: CapId(id),
        methods,
        budget,
        read_only,
        redact,
        path_scope,
    })
}

/// Decode a capability table on its own (side-channel use).
///
/// A table is bounded by [`MAX_CAP_TABLE`], not by one envelope's descriptor
/// ceiling: it is the negotiated object `apply_to` grows.
pub fn decode_capability_table(bytes: &[u8]) -> Result<Vec<CapDescriptor>> {
    let limits = WireLimits {
        max_caps: MAX_CAP_TABLE as u32,
        ..WireLimits::default()
    };
    decode_capability_table_with(bytes, &limits)
}

/// Decode a capability table under caller-supplied limits.
///
/// A strict peer can tighten `max_caps` and `max_methods` for a context that
/// accepts only a few, narrowly-scoped capabilities. `max_caps` is honoured
/// here, and `MAX_CAP_TABLE` is the absolute ceiling whatever the caller asks
/// for (round 43, F3).
pub fn decode_capability_table_with(
    bytes: &[u8],
    limits: &WireLimits,
) -> Result<Vec<CapDescriptor>> {
    // The caller's byte ceiling applies here too, and its breach is the table
    // class every other table limit uses (round 21, finding 6; round 22, N6).
    if bytes.len() > limits.max_bytes {
        return Err(Error::CapabilityTable("table exceeds the byte ceiling"));
    }
    let mut cursor = 0usize;
    let count = read_u32(bytes, &mut cursor)?;
    if count as usize > MAX_CAP_TABLE {
        return Err(Error::CapabilityTable("too many descriptors"));
    }
    if count > limits.max_caps {
        return Err(Error::CapabilityTable("too many descriptors"));
    }
    let mut caps = Vec::with_capacity((count as usize).min(64));
    let mut seen: BTreeSet<[u8; 16]> = BTreeSet::new();
    for _ in 0..count {
        let descriptor = read_cap(bytes, &mut cursor, limits)?;
        if !seen.insert(descriptor.id.0) {
            return Err(Error::CapabilityTable("duplicate capability id"));
        }
        caps.push(descriptor);
    }
    if cursor != bytes.len() {
        return Err(Error::CapabilityTable("trailing bytes"));
    }
    Ok(caps)
}

/// Encode a capability table on its own.
pub fn encode_capability_table(caps: &[CapDescriptor]) -> Result<Vec<u8>> {
    let limits = WireLimits::default();
    // The reader refuses a table past its descriptor ceiling or with a
    // repeated id, and a table this crate produced for a delta base or a
    // side channel must be one a peer can read. The ceiling is the table's own
    // (`MAX_CAP_TABLE`), the same one `apply_to` grows against; the
    // per-envelope `max_caps` is checked by `check_limits` (round 42, F2).
    if caps.len() > MAX_CAP_TABLE {
        return Err(Error::CapabilityTable("too many descriptors"));
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    put_len(&mut out, caps.len())?;
    // ADR-0009 makes table identity the hash, not the descriptor order, and
    // `apply_to` returns a table sorted by id. Writing the caller's order made
    // `cap_table_hash` order-dependent: the same set held in two orders hashed
    // differently, so a delta base built from one was refused by the other
    // (round 47, F4).
    let mut ordered: Vec<&CapDescriptor> = caps.iter().collect();
    ordered.sort_by_key(|cap| cap.id.0);
    for cap in ordered {
        if !seen.insert(cap.id.0) {
            return Err(Error::CapabilityTable("duplicate capability id"));
        }
        check_descriptor(cap, &limits)?;
        write_cap(&mut out, cap)?;
    }
    Ok(out)
}
