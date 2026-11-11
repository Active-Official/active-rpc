//! Authenticated transport identity and capability introduction policy.
//!
//! A capability id is unforgeable, but an id that is copied off a connection can
//! be replayed by whoever observed it. Identity binding closes that gap. A
//! capability introduced to a peer records the authenticated identity it was
//! given to, and the kernel refuses it when another peer — or an anonymous one —
//! presents it (`rpc/identity`).
//!
//! [`IdentityPolicy`] states the one relaxation deployments need: loopback
//! traffic may proceed without a certificate when
//! [`IdentityPolicy::trust_loopback`] is set. Off-host traffic never takes that
//! path, so a missing certificate is a refusal, never a silent downgrade.
//!
//! The fingerprint is a domain-separated Blake3 digest of the peer certificate,
//! not the X.509 SHA-256 thumbprint. It is a public label: it identifies a peer,
//! it never authorises one. Authority stays in the capability registry.
//!
//! Provenance is part of the identity (RPC-55): a `MutualTls` identity is only
//! *verified* when a transport built it from a certificate chain the TLS stack
//! verified for this connection (`PeerIdentity::is_verified`). The public
//! `PeerIdentity::from_certificate` builds an unverified claim from raw bytes
//! (a fingerprint label, never authority), and [`IdentityPolicy::admit`]
//! refuses it. The only other verified producer is the `test-utils` feature's
//! `PeerIdentity::from_certificate_for_test`, test scaffolding that must never
//! be enabled in a shipped build.

use crate::error::{Error, Result};

/// Length of a peer fingerprint in bytes.
pub const FINGERPRINT_LEN: usize = 32;

/// Length of the caller prefix recorded for a call (RPC-56): the first 128
/// bits of a peer's fingerprint. A 128-bit prefix is the same representation
/// the replay trace keeps for an introduced peer, and a targeted second
/// preimage on 128 bits is 2^128 work, so the prefix identifies the caller
/// for forensics without carrying the full fingerprint into telemetry.
pub const FINGERPRINT_PREFIX_LEN: usize = 16;

/// Longest subject label an identity keeps, in bytes.
///
/// The subject reaches logs, JSON and the control plane; an unbounded principal
/// name amplifies every record it appears in, and a control or bidi character in
/// it can forge a log line. Longer names are cut at a character boundary and
/// unrepresentable characters are escaped.
pub const MAX_SUBJECT_BYTES: usize = 512;

const FINGERPRINT_DOMAIN: &[u8] = b"active-rpc/peer-identity/v1\0";

/// How a peer proved who it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IdentityKind {
    /// Mutual TLS (QUIC or TLS) with a client certificate. The kind names the
    /// mechanism, not the proof: whether the chain was verified is
    /// [`PeerIdentity::is_verified`], and [`IdentityPolicy::admit`] only accepts
    /// a verified certificate identity (RPC-55).
    MutualTls,
    /// Loopback peer admitted by policy rather than by a certificate.
    Loopback,
    /// A peer that presented no identity at all.
    Anonymous,
}

impl IdentityKind {
    /// Stable name for logs and the observability schema.
    pub const fn as_str(self) -> &'static str {
        match self {
            IdentityKind::MutualTls => "mutual-tls",
            IdentityKind::Loopback => "loopback",
            IdentityKind::Anonymous => "anonymous",
        }
    }
}

/// The verified identity of the peer at the other end of a transport.
///
/// Build one only from evidence the transport actually verified: a certificate
/// chain, a TLS exporter, or an explicit loopback decision. A caller-supplied
/// string is not an identity.
///
/// Provenance is part of the value (RPC-55): a verified identity and an
/// unverified claim for the same certificate are distinct values (equality
/// includes `verified` and `not_after`), though they share a fingerprint,
/// which is exactly the binding key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerIdentity {
    kind: IdentityKind,
    subject: String,
    fingerprint: [u8; FINGERPRINT_LEN],
    /// True only when a transport built this identity from a certificate chain
    /// the TLS stack verified for this connection - or when the `test-utils`
    /// test constructor built it. The field is private, so no caller outside
    /// this module can set it (RPC-55).
    verified: bool,
    /// Unix seconds after which the verified certificate that created this
    /// identity is no longer valid, or `None` when the identity carries no
    /// certificate expiry (RPC-57, R11-5). Set only for verified identities,
    /// parsed from the leaf certificate's `notAfter` at construction; an
    /// unverified claim must not assert an expiry, and a loopback or
    /// anonymous identity has no certificate to expire. A transport re-checks
    /// it against wall time for the life of the connection
    /// (`PeerIdentity::is_expired_at`); the kernel never sees it, because the
    /// kernel clock is logical and expiry is a wall-clock fact.
    not_after: Option<u64>,
}

impl PeerIdentity {
    /// Identity from a certificate's bytes - an unverified CLAIM, not proof.
    ///
    /// `certificate` is the DER encoding the caller *claims* is a certificate;
    /// only its digest is retained, so the identity is safe to log and compare.
    /// The default subject is a short certificate label; use
    /// [`PeerIdentity::with_subject`] to attach the principal a deployment
    /// extracted from the certificate's SAN.
    ///
    /// This performs no verification of any kind (RPC-55): it does not parse
    /// X.509, check a chain, an expiry, a revocation, or a SAN, and it cannot
    /// tell whether the caller holds the certificate's key - a certificate is
    /// public, so the same bytes from any caller name the same principal.
    /// [`IdentityPolicy::admit`] therefore refuses a `MutualTls` identity built
    /// here: authority needs a transport that verified the chain, which builds
    /// the identity through `PeerIdentity::from_verified_certificate` (in-crate;
    /// see `transport::quic::peer_identity`). Use this constructor only for a
    /// fingerprint label - comparing against a binding, or presenting a peer to
    /// a raw entry point in a test - and use
    /// `PeerIdentity::from_certificate_for_test` (feature `test-utils`) when a
    /// test needs an admitted peer. Pass the authenticated certificate's DER,
    /// never a placeholder, a proxy header or a configuration string: every
    /// caller that passes the same bytes is the same principal and can exercise
    /// the others' bound capabilities through the raw entry points. An empty
    /// buffer is treated as no identity at all.
    pub fn from_certificate(certificate: &[u8]) -> Self {
        Self::from_cert_bytes(certificate, false)
    }

    /// Identity from a certificate the transport verified (in-crate only).
    ///
    /// Only a transport may call this, and only with the leaf of a chain the
    /// TLS stack verified for this connection (`transport::quic::peer_identity`).
    /// The returned identity is [`PeerIdentity::is_verified`] and
    /// [`IdentityPolicy::admit`] accepts it as [`TrustLevel::Authenticated`]
    /// (RPC-55). The leaf's `notAfter` is recorded on the identity
    /// ([`PeerIdentity::not_after`]) so a transport can re-check it against
    /// wall time for the life of the connection (RPC-57, R11-5). An empty
    /// buffer is treated as no identity at all, exactly as in
    /// [`PeerIdentity::from_certificate`].
    ///
    /// No production caller exists in a build without the `quic` transport
    /// (the only in-crate caller is `transport::quic::peer_identity`); the
    /// kernel's unit tests still call it in every build, so the lint is
    /// silenced only where no production caller can exist.
    #[cfg_attr(not(feature = "quic"), allow(dead_code))]
    pub(crate) fn from_verified_certificate(certificate: &[u8]) -> Self {
        Self::from_cert_bytes(certificate, true)
    }

    /// Identity from a certificate for tests only (feature `test-utils`).
    ///
    /// Test scaffolding, not a transport: it builds a *verified* identity from
    /// raw bytes so the kernel's binding tests can build admitted peers without
    /// a live transport. NEVER enable `test-utils` in a shipped build - it
    /// re-opens RPC-55 exactly as `from_certificate` used to, by letting any
    /// caller mint a bindable identity for any fingerprint. An empty buffer is
    /// treated as no identity at all, exactly as in
    /// [`PeerIdentity::from_certificate`].
    #[cfg(feature = "test-utils")]
    pub fn from_certificate_for_test(certificate: &[u8]) -> Self {
        Self::from_cert_bytes(certificate, true)
    }

    /// Shared construction for the three certificate constructors: the
    /// fingerprint is the digest of the bytes, the subject is a short label,
    /// and only `verified` differs. An empty buffer is not evidence of
    /// anything - returning a `MutualTls` identity for it would give every
    /// caller that passed an empty exporter, proxy header or config string
    /// *one shared* bindable fingerprint, the same wildcard class as the
    /// all-zero binding, wearing a cert label - so it is an anonymous
    /// identity, which is never verified whatever the caller asked for.
    fn from_cert_bytes(certificate: &[u8], verified: bool) -> Self {
        if certificate.is_empty() {
            return Self::anonymous();
        }
        let fingerprint = fingerprint_for("", certificate);
        let subject = format!("cert:{}", hex_prefix(&fingerprint, 16));
        // Expiry is a verified fact, not a claim: only a transport-verified
        // identity (or the test constructor) records a `notAfter`, parsed
        // from the leaf certificate. An unverified claim must not assert an
        // expiry it never proved (RPC-57, R11-5). A certificate whose validity
        // cannot be parsed records no expiry.
        let not_after = if verified {
            certificate_not_after(certificate)
        } else {
            None
        };
        Self {
            kind: IdentityKind::MutualTls,
            subject,
            fingerprint,
            verified,
            not_after,
        }
    }

    /// Attach the verified principal name for this certificate.
    ///
    /// The subject is a **label**; the fingerprint stays the digest of the
    /// certificate bytes, because that is what a transport presents at dispatch.
    /// Recomputing it here would break every binding made before the name was
    /// attached. Two identities for the same certificate with different subjects
    /// are distinct values (equality includes the subject) but share a
    /// fingerprint, which is exactly the binding key. Provenance is preserved:
    /// renaming a verified identity keeps it verified, and renaming a claim
    /// keeps it a claim.
    ///
    /// The label is bounded to [`MAX_SUBJECT_BYTES`] and any control, line
    /// separator or bidi character is escaped, because the same string is
    /// rendered into logs and JSON.
    pub fn with_subject(self, subject: impl Into<String>) -> Self {
        Self {
            subject: sanitized_subject(&subject.into()),
            ..self
        }
    }

    /// The loopback identity admitted by [`IdentityPolicy::trust_loopback`].
    ///
    /// It is a **relaxed** identity, not a peer: every local process shares it,
    /// so [`AdmittedIdentity::can_bind`] refuses to bind a capability to it.
    pub fn loopback() -> Self {
        Self {
            kind: IdentityKind::Loopback,
            subject: "loopback".to_string(),
            fingerprint: loopback_fingerprint(),
            verified: false,
            not_after: None,
        }
    }

    /// A peer with no identity. Binding a capability to it is refused.
    pub fn anonymous() -> Self {
        Self {
            kind: IdentityKind::Anonymous,
            subject: "anonymous".to_string(),
            fingerprint: [0u8; FINGERPRINT_LEN],
            verified: false,
            not_after: None,
        }
    }

    /// How the identity was established.
    pub fn kind(&self) -> IdentityKind {
        self.kind
    }

    /// True only when a transport built this identity from a certificate chain
    /// the TLS stack verified for this connection - or when the `test-utils`
    /// test constructor built it (RPC-55). [`IdentityPolicy::admit`] accepts a
    /// `MutualTls` identity only when this is true; a loopback or anonymous
    /// identity is never verified.
    pub fn is_verified(&self) -> bool {
        self.verified
    }

    /// Unix seconds after which the verified certificate that created this
    /// identity is no longer valid, or `None` when the identity carries no
    /// certificate expiry (RPC-57, R11-5). `None` means "unknown", not
    /// "never expires": a transport that enforces expiry must treat an
    /// unknown expiry as a reason to refuse, not as a licence to keep
    /// serving.
    pub fn not_after(&self) -> Option<u64> {
        self.not_after
    }

    /// True when the certificate that created this identity is expired at
    /// `now_unix` (unix seconds, wall time). An identity with no recorded
    /// expiry is never expired by this predicate: the caller decides what an
    /// unknown expiry means. Expiry is inclusive at `notAfter`: a certificate
    /// MUST NOT be used on or after that second (RFC 5280), so `now_unix`
    /// equal to `notAfter` is already expired.
    pub fn is_expired_at(&self, now_unix: u64) -> bool {
        self.not_after
            .is_some_and(|not_after| now_unix >= not_after)
    }

    /// Verified principal name.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Stable fingerprint (a public label, never authority).
    pub fn fingerprint(&self) -> [u8; FINGERPRINT_LEN] {
        self.fingerprint
    }

    /// Hex fingerprint for logs and operator tooling.
    pub fn fingerprint_hex(&self) -> String {
        let mut out = String::with_capacity(FINGERPRINT_LEN * 2);
        for byte in self.fingerprint {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    /// True when the peer presented no identity.
    pub fn is_anonymous(&self) -> bool {
        self.kind == IdentityKind::Anonymous
    }
}

/// Unix seconds of the `notAfter` in a DER certificate, or `None` when the
/// validity period cannot be read (RPC-57, R11-5).
///
/// A minimal strict DER reader for the certificate's validity period only: it
/// walks Certificate -> tbsCertificate -> optional `[0]` version -> serial ->
/// signature -> issuer -> validity, and reads `notAfter` as UTCTime or
/// GeneralizedTime. No new dependency, no unsafe code. Anything malformed,
/// truncated, non-UTC or pre-epoch yields `None`: an identity whose expiry
/// cannot be read carries no expiry, and a transport that enforces expiry
/// must refuse a `None` for a verified identity rather than assume it lives
/// forever. The reader stops at the validity period, so the rest of the
/// certificate is never parsed.
fn certificate_not_after(der: &[u8]) -> Option<u64> {
    let mut reader = DerReader { bytes: der, pos: 0 };
    let certificate = reader.read_tlv(0x30)?;
    // The outer content is the tbsCertificate TLV itself, not its fields:
    // read the inner SEQUENCE before walking the fields.
    let mut cert_reader = DerReader {
        bytes: certificate,
        pos: 0,
    };
    let tbs = cert_reader.read_tlv(0x30)?;
    let mut tbs = DerReader { bytes: tbs, pos: 0 };
    // Optional `[0]` EXPLICIT version.
    if tbs.peek_tag() == Some(0xA0) {
        let _version = tbs.read_tlv(0xA0)?;
    }
    let _serial = tbs.read_tlv(0x02)?;
    let _signature = tbs.read_tlv(0x30)?;
    let _issuer = tbs.read_tlv(0x30)?;
    let validity = tbs.read_tlv(0x30)?;
    let mut validity_reader = DerReader {
        bytes: validity,
        pos: 0,
    };
    let _not_before = validity_reader.read_tlv_any()?;
    let not_after = validity_reader.read_tlv_any()?;
    parse_x509_time(not_after)
}

/// One TLV at a time over a byte slice. Definite lengths only: the indefinite
/// form is refused, and a length that runs past the slice is truncated.
struct DerReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    fn peek_tag(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Read one TLV with the expected tag; return its content bytes.
    fn read_tlv(&mut self, expected: u8) -> Option<&'a [u8]> {
        let (tag, content) = self.read_tlv_any()?;
        if tag != expected {
            return None;
        }
        Some(content)
    }

    /// Read one TLV of any tag; return the tag and its content bytes.
    fn read_tlv_any(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = *self.bytes.get(self.pos)?;
        let mut pos = self.pos + 1;
        let first_len = *self.bytes.get(pos)?;
        pos += 1;
        let len = if first_len < 0x80 {
            first_len as usize
        } else {
            // Long form: 1-4 length bytes. The indefinite form (0x80) and a
            // length longer than 4 bytes are refused.
            let count = (first_len & 0x7F) as usize;
            if count == 0 || count > 4 {
                return None;
            }
            let mut len = 0usize;
            for _ in 0..count {
                len = len
                    .checked_mul(256)?
                    .checked_add(*self.bytes.get(pos)? as usize)?;
                pos += 1;
            }
            len
        };
        let end = pos.checked_add(len)?;
        let content = self.bytes.get(pos..end)?;
        self.pos = end;
        Some((tag, content))
    }
}

/// Unix seconds for an X.509 time value: UTCTime `YYMMDDHHMMSSZ` or
/// GeneralizedTime `YYYYMMDDHHMMSSZ`, Zulu only. A two-digit year below 50 is
/// 20xx, 50 and above is 19xx (RFC 5280). Anything else yields `None`.
fn parse_x509_time((tag, content): (u8, &[u8])) -> Option<u64> {
    let (year, month, day, hour, minute, second) = match tag {
        0x17 => {
            if content.len() != 13 || content[12] != b'Z' {
                return None;
            }
            let year = two_digits(content, 0)?;
            let year = if year < 50 { 2000 + year } else { 1900 + year };
            (
                year,
                two_digits(content, 2)?,
                two_digits(content, 4)?,
                two_digits(content, 6)?,
                two_digits(content, 8)?,
                two_digits(content, 10)?,
            )
        }
        0x18 => {
            if content.len() != 15 || content[14] != b'Z' {
                return None;
            }
            let year = four_digits(content, 0)?;
            (
                year,
                two_digits(content, 4)?,
                two_digits(content, 6)?,
                two_digits(content, 8)?,
                two_digits(content, 10)?,
                two_digits(content, 12)?,
            )
        }
        _ => return None,
    };
    if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => return None,
    };
    if day == 0 || day > max_day {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    days.checked_mul(86_400)?
        .checked_add(hour.checked_mul(3_600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)
}

/// Two decimal digits at `at`, or `None` when they are not digits.
fn two_digits(bytes: &[u8], at: usize) -> Option<u64> {
    let hi = *bytes.get(at)?;
    let lo = *bytes.get(at + 1)?;
    if !hi.is_ascii_digit() || !lo.is_ascii_digit() {
        return None;
    }
    Some(u64::from(hi - b'0') * 10 + u64::from(lo - b'0'))
}

/// Four decimal digits at `at`, or `None` when they are not digits.
fn four_digits(bytes: &[u8], at: usize) -> Option<u64> {
    let hi = two_digits(bytes, at)?;
    let lo = two_digits(bytes, at + 2)?;
    Some(hi * 100 + lo)
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
/// `None` for a pre-epoch date, which unix seconds cannot represent.
fn days_from_civil(year: u64, month: u64, day: u64) -> Option<u64> {
    let year = year as i64;
    let month = month as i64;
    let day = day as i64;
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days).ok()
}

/// Bounded, log-safe form of a principal label.
///
/// Cut at a character boundary at [`MAX_SUBJECT_BYTES`], then any character that
/// a log line or a JSON cell cannot carry literally is rendered by
/// `escape_debug`. A plain ASCII name is unchanged.
fn sanitized_subject(subject: &str) -> String {
    let mut end = 0;
    for (index, character) in subject.char_indices() {
        let next = index + character.len_utf8();
        if next > MAX_SUBJECT_BYTES {
            break;
        }
        end = next;
    }
    let bounded = &subject[..end];
    if crate::security::valid_text(bounded, MAX_SUBJECT_BYTES) {
        return bounded.to_string();
    }
    // Escaping can multiply the length (`\u{1b}` is six bytes for one
    // character), so the escaped form is bounded again at a character boundary.
    // Emit one character's escape at a time and stop before the budget: cutting
    // the escaped text at a byte boundary could end it mid-escape
    // (`\u{1b}` minus its last digit is a dangling backslash).
    let mut out = String::new();
    for character in bounded.chars() {
        let mut token = String::new();
        token.extend(character.escape_debug());
        if out.len() + token.len() > MAX_SUBJECT_BYTES {
            break;
        }
        out.push_str(&token);
    }
    out
}

fn fingerprint_for(subject: &str, evidence: &[u8]) -> [u8; FINGERPRINT_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FINGERPRINT_DOMAIN);
    // The word separates the loopback constant from a certificate digest; a
    // principal label never reaches this function, because the label must not
    // change the binding key.
    let length = u32::try_from(subject.len()).unwrap_or(u32::MAX);
    hasher.update(&length.to_le_bytes());
    hasher.update(subject.as_bytes());
    hasher.update(evidence);
    *hasher.finalize().as_bytes()
}

fn loopback_fingerprint() -> [u8; FINGERPRINT_LEN] {
    fingerprint_for("loopback", b"loopback")
}

fn empty_certificate_fingerprint() -> [u8; FINGERPRINT_LEN] {
    fingerprint_for("", b"")
}

/// Whether a fingerprint names a peer that can hold a binding.
///
/// The all-zero fingerprint is the anonymous constant and the loopback
/// fingerprint is shared by every local process: binding to either would make
/// the capability usable by a peer that never proved anything.
pub fn bindable(fingerprint: [u8; FINGERPRINT_LEN]) -> bool {
    fingerprint != [0u8; FINGERPRINT_LEN]
        && fingerprint != loopback_fingerprint()
        // The digest `from_certificate` would have produced for empty evidence,
        // refused as a second layer against a hand-built identity.
        && fingerprint != empty_certificate_fingerprint()
}

/// The fingerprint a peer presents, or `None` when it presented no identity.
///
/// An anonymous peer has no fingerprint. Comparing its zero constant as a value
/// would let a capability bound to `[0; 32]` match it, so the absence has to be
/// modelled as absence.
pub fn presented_fingerprint(peer: Option<&PeerIdentity>) -> Option<[u8; FINGERPRINT_LEN]> {
    peer.filter(|identity| !identity.is_anonymous())
        .map(PeerIdentity::fingerprint)
}

/// The first 128 bits of a fingerprint: the caller label events, receipts
/// and traces record (RPC-56). The full fingerprint stays in the kernel's
/// binding checks; only the prefix leaves the kernel.
pub fn fingerprint_prefix(fingerprint: [u8; FINGERPRINT_LEN]) -> [u8; FINGERPRINT_PREFIX_LEN] {
    let mut prefix = [0u8; FINGERPRINT_PREFIX_LEN];
    prefix.copy_from_slice(&fingerprint[..FINGERPRINT_PREFIX_LEN]);
    prefix
}

/// Hex form of a caller prefix: 32 lowercase hex characters.
pub fn fingerprint_prefix_hex(prefix: &[u8; FINGERPRINT_PREFIX_LEN]) -> String {
    let mut out = String::with_capacity(FINGERPRINT_PREFIX_LEN * 2);
    for byte in prefix {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Compare a presented fingerprint with a bound one without a short circuit.
///
/// The value is a public label, so this is defence in depth: a caller learns
/// nothing usable from the comparison's timing either way.
pub fn matches(presented: Option<[u8; FINGERPRINT_LEN]>, bound: [u8; FINGERPRINT_LEN]) -> bool {
    let Some(presented) = presented else {
        return false;
    };
    let mut difference = 0u8;
    for (left, right) in presented.iter().zip(bound.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

fn hex_prefix(bytes: &[u8; FINGERPRINT_LEN], len: usize) -> String {
    let mut out = String::with_capacity(len * 2);
    for byte in &bytes[..len.min(FINGERPRINT_LEN)] {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// How far a peer's identity was trusted for this connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TrustLevel {
    /// A certificate chain was verified.
    Authenticated,
    /// Loopback, admitted under policy without a certificate.
    LoopbackRelaxed,
    /// No identity; only usable where the policy does not require one.
    Unauthenticated,
}

impl TrustLevel {
    /// Stable name for logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            TrustLevel::Authenticated => "authenticated",
            TrustLevel::LoopbackRelaxed => "loopback-relaxed",
            TrustLevel::Unauthenticated => "unauthenticated",
        }
    }
}

/// An identity the policy admitted, with the level it was admitted at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedIdentity {
    identity: PeerIdentity,
    trust: TrustLevel,
}

impl AdmittedIdentity {
    /// The admitted peer.
    pub fn identity(&self) -> &PeerIdentity {
        &self.identity
    }

    /// Trust level the policy assigned.
    pub fn trust(&self) -> TrustLevel {
        self.trust
    }

    /// Fingerprint of the admitted peer.
    pub fn fingerprint(&self) -> [u8; FINGERPRINT_LEN] {
        self.identity.fingerprint()
    }

    /// True when a capability may be bound to this peer.
    ///
    /// Only a **verified certificate** peer can hold a binding: `admit` refuses
    /// an unverified certificate identity (RPC-55). A loopback peer is shared
    /// by every local process and an unauthenticated peer is nobody in
    /// particular, so a capability bound to either would be usable by a peer
    /// that never proved anything. An unbound capability works for both.
    pub fn can_bind(&self) -> bool {
        self.trust == TrustLevel::Authenticated
    }
}

/// Admission rules for capability introduction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityPolicy {
    /// Refuse a peer that presents no identity.
    pub require_identity: bool,
    /// Allow loopback peers to proceed without a certificate.
    pub trust_loopback: bool,
}

impl Default for IdentityPolicy {
    /// Production default: identity required, loopback relaxed.
    fn default() -> Self {
        Self {
            require_identity: true,
            trust_loopback: true,
        }
    }
}

impl IdentityPolicy {
    /// Require a certificate even on loopback.
    pub const fn strict() -> Self {
        Self {
            require_identity: true,
            trust_loopback: false,
        }
    }

    /// Development policy: no certificate required on loopback. Never use it
    /// for a listener that is reachable off-host.
    ///
    /// The relaxation is loopback-scoped in code, not only in this comment:
    /// `admit` refuses an anonymous peer off loopback under this policy too
    /// (RPC-57, R11-3). The policy exists so a local development listener does
    /// not need certificates; it is not a licence to serve unauthenticated
    /// traffic off-host.
    pub const fn local() -> Self {
        Self {
            require_identity: false,
            trust_loopback: true,
        }
    }

    /// Admit a peer, or refuse with `rpc/identity`.
    ///
    /// `loopback` must be computed from the connection's local and remote
    /// addresses, never from a header or a caller-supplied flag. Admission
    /// does not re-check certificate expiry: a binding outlives the
    /// certificate that created it unless the transport re-checks
    /// `PeerIdentity::is_expired_at` against wall time (RPC-57, R11-5; the
    /// QUIC transport does so per stream).
    pub fn admit(&self, peer: Option<&PeerIdentity>, loopback: bool) -> Result<AdmittedIdentity> {
        // An explicitly anonymous identity says exactly what presenting none
        // says. Normalising first keeps one label per connection: otherwise
        // `local()` called a local caller `Loopback` when the transport passed
        // `None` and `Unauthenticated` when it passed `anonymous()`.
        let peer = peer.filter(|identity| !identity.is_anonymous());
        match peer {
            Some(identity) if identity.kind() == IdentityKind::MutualTls => {
                // RPC-55: the kind names the mechanism, not the proof. A
                // certificate is public, so any caller can present the bytes of
                // a certificate it does not hold; only an identity a transport
                // built from a chain the TLS stack verified (or the test-utils
                // test constructor built) may be authenticated.
                if identity.is_verified() {
                    Ok(AdmittedIdentity {
                        identity: identity.clone(),
                        trust: TrustLevel::Authenticated,
                    })
                } else {
                    Err(Error::Identity(
                        "certificate identity was not verified by a transport",
                    ))
                }
            }
            Some(identity) if identity.kind() == IdentityKind::Loopback => {
                if loopback && self.trust_loopback {
                    Ok(AdmittedIdentity {
                        identity: identity.clone(),
                        trust: TrustLevel::LoopbackRelaxed,
                    })
                } else {
                    Err(Error::Identity(
                        "loopback identity presented off loopback or refused by policy",
                    ))
                }
            }
            // Unreachable after the filter (every remaining kind is matched
            // above); kept so a future kind cannot fall through silently.
            Some(_) => Err(Error::Identity("unrecognised peer identity")),
            None => {
                // The label follows the connection, not the identity
                // requirement: an embedder that branches on `kind()` for
                // local-only operations must see `Loopback` for a local caller
                // under `local()` as well as under the default policy.
                if loopback && self.trust_loopback {
                    Ok(AdmittedIdentity {
                        identity: PeerIdentity::loopback(),
                        trust: TrustLevel::LoopbackRelaxed,
                    })
                } else if !self.require_identity && loopback {
                    // `local()` relaxes the identity requirement, but only on
                    // loopback: an anonymous peer off loopback is refused
                    // under every policy, because "never for a reachable
                    // listener" is a property of the connection, not of the
                    // policy object (RPC-57, R11-3).
                    Ok(AdmittedIdentity {
                        identity: PeerIdentity::anonymous(),
                        trust: TrustLevel::Unauthenticated,
                    })
                } else {
                    Err(Error::Identity("peer identity required"))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DER length encoding: short form below 128, long form above.
    fn der_len(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else if len < 0x100 {
            vec![0x81, len as u8]
        } else {
            vec![0x82, (len >> 8) as u8, len as u8]
        }
    }

    fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend_from_slice(&der_len(content.len()));
        out.extend_from_slice(content);
        out
    }

    /// A minimal certificate that ends after the validity period: the parser
    /// stops there, so the rest of the certificate is not needed. `version`
    /// selects the optional `[0]` EXPLICIT version wrapper.
    fn cert_with_validity(not_before: &[u8], not_after: &[u8], version: bool) -> Vec<u8> {
        let validity = der_tlv(
            0x30,
            &[der_tlv(0x17, not_before), der_tlv(0x17, not_after)].concat(),
        );
        let mut tbs = Vec::new();
        if version {
            tbs.extend_from_slice(&der_tlv(0xA0, &der_tlv(0x02, &[2])));
        }
        tbs.extend_from_slice(&der_tlv(0x02, &[1])); // serial
        tbs.extend_from_slice(&der_tlv(0x30, &[])); // signature
        tbs.extend_from_slice(&der_tlv(0x30, &[])); // issuer
        tbs.extend_from_slice(&validity);
        der_tlv(0x30, &der_tlv(0x30, &tbs))
    }

    #[test]
    fn utctime_future_parses_to_unix_seconds() {
        // 2049-01-01T00:00:00Z. (UTCTime year 50 would be 1950, not 2050 —
        // see the boundary test.)
        let der = cert_with_validity(b"200101000000Z", b"490101000000Z", true);
        assert_eq!(certificate_not_after(&der), Some(2_493_072_000));
    }

    #[test]
    fn utctime_past_parses_to_unix_seconds() {
        // 2020-01-01T00:00:00Z.
        let der = cert_with_validity(b"190101000000Z", b"200101000000Z", true);
        assert_eq!(certificate_not_after(&der), Some(1_577_836_800));
    }

    #[test]
    fn generalized_time_parses_to_unix_seconds() {
        let validity = der_tlv(
            0x30,
            &[
                der_tlv(0x18, b"20200101000000Z"),
                der_tlv(0x18, b"20500101000000Z"),
            ]
            .concat(),
        );
        let mut tbs = Vec::new();
        tbs.extend_from_slice(&der_tlv(0x02, &[1]));
        tbs.extend_from_slice(&der_tlv(0x30, &[]));
        tbs.extend_from_slice(&der_tlv(0x30, &[]));
        tbs.extend_from_slice(&validity);
        let der = der_tlv(0x30, &der_tlv(0x30, &tbs));
        assert_eq!(certificate_not_after(&der), Some(2_524_608_000));
    }

    #[test]
    fn utctime_year_boundary_49_is_2049_and_50_is_pre_epoch() {
        // Year 49 is 2049; year 50 is 1950, which unix seconds cannot
        // represent, so the parser yields no expiry for it.
        let der = cert_with_validity(b"480101000000Z", b"490101000000Z", true);
        assert_eq!(certificate_not_after(&der), Some(2_493_072_000));
        let der = cert_with_validity(b"490101000000Z", b"500101000000Z", true);
        assert_eq!(certificate_not_after(&der), None);
    }

    #[test]
    fn version_absent_still_parses() {
        let der = cert_with_validity(b"200101000000Z", b"490101000000Z", false);
        assert_eq!(certificate_not_after(&der), Some(2_493_072_000));
    }

    #[test]
    fn garbage_and_truncated_certificates_yield_no_expiry() {
        assert_eq!(certificate_not_after(&[]), None);
        assert_eq!(certificate_not_after(&[0u8; 64]), None);
        // A real-shaped certificate cut off inside the validity period.
        let der = cert_with_validity(b"200101000000Z", b"500101000000Z", true);
        assert_eq!(certificate_not_after(&der[..der.len() - 4]), None);
        // Indefinite length is refused.
        let mut indefinite = der.clone();
        indefinite[1] = 0x80;
        assert_eq!(certificate_not_after(&indefinite), None);
        // A non-UTC time tag is refused.
        let validity = der_tlv(
            0x30,
            &[
                der_tlv(0x17, b"200101000000Z"),
                der_tlv(0x16, b"500101000000Z"),
            ]
            .concat(),
        );
        let mut tbs = Vec::new();
        tbs.extend_from_slice(&der_tlv(0x02, &[1]));
        tbs.extend_from_slice(&der_tlv(0x30, &[]));
        tbs.extend_from_slice(&der_tlv(0x30, &[]));
        tbs.extend_from_slice(&validity);
        let der = der_tlv(0x30, &der_tlv(0x30, &tbs));
        assert_eq!(certificate_not_after(&der), None);
    }

    #[test]
    fn unverified_and_non_certificate_identities_have_no_expiry() {
        // An unverified claim records no expiry, whatever the bytes say.
        let der = cert_with_validity(b"200101000000Z", b"500101000000Z", true);
        let claim = PeerIdentity::from_certificate(&der);
        assert_eq!(claim.not_after(), None);
        assert!(!claim.is_expired_at(u64::MAX));
        // Loopback and anonymous identities have no expiry.
        assert_eq!(PeerIdentity::loopback().not_after(), None);
        assert_eq!(PeerIdentity::anonymous().not_after(), None);
    }

    #[test]
    #[cfg(feature = "test-utils")]
    fn verified_identity_records_expiry_and_predicate_matches() {
        let der = cert_with_validity(b"200101000000Z", b"490101000000Z", true);
        let identity = PeerIdentity::from_certificate_for_test(&der);
        assert_eq!(identity.not_after(), Some(2_493_072_000)); // 2049-01-01T00:00:00Z
        assert!(!identity.is_expired_at(2_493_071_999));
        assert!(identity.is_expired_at(2_493_072_000));
    }
}
