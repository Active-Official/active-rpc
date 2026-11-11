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
/// includes `verified`), though they share a fingerprint, which is exactly the
/// binding key.
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
    /// (RPC-55). An empty buffer is treated as no identity at all, exactly as
    /// in [`PeerIdentity::from_certificate`].
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
        Self {
            kind: IdentityKind::MutualTls,
            subject,
            fingerprint,
            verified,
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
        }
    }

    /// A peer with no identity. Binding a capability to it is refused.
    pub fn anonymous() -> Self {
        Self {
            kind: IdentityKind::Anonymous,
            subject: "anonymous".to_string(),
            fingerprint: [0u8; FINGERPRINT_LEN],
            verified: false,
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

    /// Development policy: no certificate required anywhere. Never use it for a
    /// listener that is reachable off-host.
    pub const fn local() -> Self {
        Self {
            require_identity: false,
            trust_loopback: true,
        }
    }

    /// Admit a peer, or refuse with `rpc/identity`.
    ///
    /// `loopback` must be computed from the connection's local and remote
    /// addresses, never from a header or a caller-supplied flag.
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
                } else if !self.require_identity {
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
