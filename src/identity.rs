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

use crate::error::{Error, Result};

/// Length of a peer fingerprint in bytes.
pub const FINGERPRINT_LEN: usize = 32;

const FINGERPRINT_DOMAIN: &[u8] = b"active-rpc/peer-identity/v1\0";

/// How a peer proved who it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IdentityKind {
    /// Mutual TLS (QUIC or TLS) with a verified client certificate.
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerIdentity {
    kind: IdentityKind,
    subject: String,
    fingerprint: [u8; FINGERPRINT_LEN],
}

impl PeerIdentity {
    /// Identity from a verified certificate.
    ///
    /// `certificate` is the DER encoding the transport authenticated; only its
    /// digest is retained, so the identity is safe to log and compare. The
    /// default subject is a short certificate label; use
    /// [`PeerIdentity::with_subject`] to attach the principal a deployment
    /// extracted from the certificate's SAN.
    pub fn from_certificate(certificate: &[u8]) -> Self {
        let fingerprint = fingerprint_for("", certificate);
        let subject = format!("cert:{}", hex_prefix(&fingerprint, 8));
        Self {
            kind: IdentityKind::MutualTls,
            subject,
            fingerprint,
        }
    }

    /// Attach the verified principal name for this certificate.
    ///
    /// The fingerprint is recomputed over the subject, so two identities that
    /// differ only in name never compare equal.
    pub fn with_subject(self, subject: impl Into<String>) -> Self {
        let subject = subject.into();
        Self {
            fingerprint: fingerprint_for(&subject, &self.fingerprint),
            subject,
            kind: self.kind,
        }
    }

    /// The loopback identity admitted by [`IdentityPolicy::trust_loopback`].
    pub fn loopback() -> Self {
        Self {
            kind: IdentityKind::Loopback,
            subject: "loopback".to_string(),
            fingerprint: fingerprint_for("loopback", b"loopback"),
        }
    }

    /// A peer with no identity. Binding a capability to it is refused.
    pub fn anonymous() -> Self {
        Self {
            kind: IdentityKind::Anonymous,
            subject: "anonymous".to_string(),
            fingerprint: [0u8; FINGERPRINT_LEN],
        }
    }

    /// Reconstruct an identity the transport already verified (for example the
    /// server side of a QUIC connection reconstructed from the peer's chain).
    pub fn from_parts(
        kind: IdentityKind,
        subject: impl Into<String>,
        fingerprint: [u8; FINGERPRINT_LEN],
    ) -> Self {
        Self {
            kind,
            subject: subject.into(),
            fingerprint,
        }
    }

    /// How the identity was established.
    pub fn kind(&self) -> IdentityKind {
        self.kind
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

fn fingerprint_for(subject: &str, evidence: &[u8]) -> [u8; FINGERPRINT_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FINGERPRINT_DOMAIN);
    hasher.update(&(subject.len() as u32).to_le_bytes());
    hasher.update(subject.as_bytes());
    hasher.update(evidence);
    *hasher.finalize().as_bytes()
}

fn hex_prefix(bytes: &[u8; FINGERPRINT_LEN], len: usize) -> String {
    let mut out = String::with_capacity(len * 2);
    for byte in &bytes[..len] {
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
    /// Only an authenticated or explicitly loopback peer can be bound: an
    /// unauthenticated peer has no stable identity to bind to, so introduction
    /// to it is refused rather than recorded as a wildcard.
    pub fn can_bind(&self) -> bool {
        self.trust != TrustLevel::Unauthenticated
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
        match peer {
            Some(identity) if identity.kind() == IdentityKind::MutualTls => Ok(AdmittedIdentity {
                identity: identity.clone(),
                trust: TrustLevel::Authenticated,
            }),
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
            Some(_) => {
                if self.require_identity {
                    Err(Error::Identity("anonymous peer refused"))
                } else {
                    Ok(AdmittedIdentity {
                        identity: PeerIdentity::anonymous(),
                        trust: TrustLevel::Unauthenticated,
                    })
                }
            }
            None => {
                if loopback && self.trust_loopback && self.require_identity {
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
