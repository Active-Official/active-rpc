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

/// Envelope magic.
pub const MAGIC: [u8; 4] = *b"ARP1";
/// Envelope version.
pub const VERSION: u8 = 1;
/// Flag: the caller asks for redacted output.
pub const FLAG_REDACT: u16 = 1 << 0;
/// Flag: the capability is read-only.
pub const FLAG_READ_ONLY: u16 = 1 << 1;
/// All understood flags.
pub const FLAG_KNOWN: u16 = FLAG_REDACT | FLAG_READ_ONLY;

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
    pub const fn code(self) -> u8 {
        match self {
            Kind::Request => 1,
            Kind::Response => 2,
            Kind::Error => 3,
            Kind::Hello => 4,
        }
    }

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
    /// Build a descriptor from attributes.
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

/// One Active RPC envelope.
#[derive(Debug, Clone, PartialEq)]
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
}

impl Default for WireLimits {
    fn default() -> Self {
        Self {
            max_bytes: 64 << 20,
            max_args: 1 << 12,
            max_method: 256,
            max_payload: 32 << 20,
            max_caps: 1 << 8,
            max_methods: 64,
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
        }
    }
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
        }
    }

    /// An error envelope.
    pub fn error(request_id: u64, error: &Error) -> Self {
        Self {
            kind: Kind::Error,
            request_id,
            method: error.code().to_string(),
            args: Vec::new(),
            payload: Vec::new(),
            caps: Vec::new(),
            redact: false,
            read_only: false,
        }
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

    /// Serialize.
    pub fn encode(&self) -> Result<Vec<u8>> {
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
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&self.request_id.to_le_bytes());
        write_str(&mut out, &self.method)?;
        if self.args.len() > u32::MAX as usize {
            return Err(Error::Wire("too many arguments"));
        }
        out.extend_from_slice(&(self.args.len() as u32).to_le_bytes());
        for arg in &self.args {
            write_arg(&mut out, arg)?;
        }
        if self.payload.len() > u32::MAX as usize {
            return Err(Error::Wire("payload too large"));
        }
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&(self.caps.len() as u32).to_le_bytes());
        for cap in &self.caps {
            write_cap(&mut out, cap)?;
        }
        Ok(out)
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
        for _ in 0..arg_count {
            args.push(read_arg(bytes, &mut cursor)?);
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
        let cap_count = read_u32(bytes, &mut cursor)?;
        if cap_count > limits.max_caps {
            return Err(Error::CapabilityTable("too many descriptors"));
        }
        let mut caps = Vec::with_capacity(cap_count as usize);
        for _ in 0..cap_count {
            caps.push(read_cap(bytes, &mut cursor, limits.max_methods)?);
        }
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
    out.extend_from_slice(&(text.len() as u32).to_le_bytes());
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
            out.extend_from_slice(&(items.len() as u32).to_le_bytes());
            for item in items {
                write_value(out, item)?;
            }
        }
        Value::Map(entries) => {
            out.push(6);
            out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
            for (key, value) in entries {
                write_str(out, key)?;
                write_value(out, value)?;
            }
        }
        Value::Secret => out.push(7),
        Value::Module(bytes) => {
            out.push(8);
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
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
    out.extend_from_slice(&(cap.methods.len() as u32).to_le_bytes());
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

fn read_arg(bytes: &[u8], cursor: &mut usize) -> Result<Arg> {
    let tag = read_u8(bytes, cursor)?;
    match tag {
        0 => Ok(Arg::Value(read_value(bytes, cursor)?)),
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

fn read_value(bytes: &[u8], cursor: &mut usize) -> Result<Value> {
    read_value_at(bytes, cursor, 0, bytes.len())
}

fn read_value_at(bytes: &[u8], cursor: &mut usize, depth: usize, budget: usize) -> Result<Value> {
    if depth > MAX_VALUE_DEPTH {
        return Err(Error::Wire("value nesting exceeds the ceiling"));
    }
    let tag = read_u8(bytes, cursor)?;
    let value = match tag {
        0 => Value::Null,
        1 => Value::Bool(read_u8(bytes, cursor)? != 0),
        2 => Value::Int(read_u64(bytes, cursor)? as i64),
        3 => Value::Float(f64::from_bits(read_u64(bytes, cursor)?)),
        4 => Value::Text(read_str(bytes, cursor, budget as u32)?),
        5 => {
            let count = read_u32(bytes, cursor)?;
            // A list cannot hold more elements than there are bytes left.
            if count as usize > budget {
                return Err(Error::Wire("list too long"));
            }
            // Never preallocate from an untrusted count: the loop grows the
            // vector and stops when the input runs out.
            let mut items = Vec::with_capacity((count as usize).min(1024));
            for _ in 0..count {
                items.push(read_value_at(bytes, cursor, depth + 1, budget)?);
            }
            Value::List(items)
        }
        6 => {
            let count = read_u32(bytes, cursor)?;
            if count as usize > budget {
                return Err(Error::Wire("map too large"));
            }
            let mut entries = std::collections::BTreeMap::new();
            for _ in 0..count {
                let key = read_str(bytes, cursor, budget as u32)?;
                entries.insert(key, read_value_at(bytes, cursor, depth + 1, budget)?);
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
        9 => Value::Path(read_str(bytes, cursor, budget as u32)?),
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

fn read_cap(bytes: &[u8], cursor: &mut usize, max_methods: u32) -> Result<CapDescriptor> {
    let mut id = [0u8; 16];
    if *cursor + 16 > bytes.len() {
        return Err(Error::CapabilityTable("truncated capability id"));
    }
    id.copy_from_slice(&bytes[*cursor..*cursor + 16]);
    *cursor += 16;
    let count = read_u32(bytes, cursor)?;
    if count > max_methods {
        return Err(Error::CapabilityTable("too many methods"));
    }
    let mut methods = BTreeSet::new();
    for _ in 0..count {
        methods.insert(read_str(bytes, cursor, 256)?);
    }
    let budget = read_budget(bytes, cursor)?;
    budget
        .check()
        .map_err(|_| Error::CapabilityTable("budget disables a ceiling"))?;
    let read_only = read_u8(bytes, cursor)? != 0;
    let redact = read_u8(bytes, cursor)? != 0;
    let path_scope = read_opt_str(bytes, cursor, 1024)?;
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
pub fn decode_capability_table(bytes: &[u8]) -> Result<Vec<CapDescriptor>> {
    let mut cursor = 0usize;
    let count = read_u32(bytes, &mut cursor)?;
    if count > WireLimits::default().max_caps {
        return Err(Error::CapabilityTable("too many descriptors"));
    }
    let mut caps = Vec::with_capacity((count as usize).min(64));
    for _ in 0..count {
        caps.push(read_cap(bytes, &mut cursor, 256)?);
    }
    if cursor != bytes.len() {
        return Err(Error::CapabilityTable("trailing bytes"));
    }
    Ok(caps)
}

/// Encode a capability table on its own.
pub fn encode_capability_table(caps: &[CapDescriptor]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&(caps.len() as u32).to_le_bytes());
    for cap in caps {
        write_cap(&mut out, cap)?;
    }
    Ok(out)
}
