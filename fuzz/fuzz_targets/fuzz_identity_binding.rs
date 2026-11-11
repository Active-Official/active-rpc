#![no_main]

//! Identity and fingerprint binding: a peer is only the identity it proved.
//!
//! Invariants:
//!
//! 1. A certificate claim is a label, never proof: `from_certificate` never
//!    verifies, never expires, and never admits as authenticated under any
//!    policy (RPC-55).
//! 2. Admission is a pure function of (policy, peer, loopback): loopback
//!    admits only on loopback under a loopback-trusting policy, an anonymous
//!    peer admits only where the policy does not require identity, and no
//!    admission this target can construct can hold a binding — only a verified
//!    certificate can, and no input here can construct one.
//! 3. Fingerprints are deterministic labels: the same bytes always give the
//!    same fingerprint, different bytes give different bindings, and the
//!    comparison never confuses two peers.
//! 4. An introduction is canonical: the same surface always builds the same
//!    bytes regardless of input order, and it decodes and re-encodes to itself.
//!
//! Run with `cargo +nightly fuzz run fuzz_identity_binding -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_rpc::identity::{
    bindable, fingerprint_prefix, fingerprint_prefix_hex, matches, presented_fingerprint,
    IdentityPolicy, PeerIdentity, TrustLevel,
};
use active_rpc::Budget;

#[path = "common.rs"]
mod common;

/// Policies in the admit matrix: strict, local, default, and the fourth
/// combination (identity not required, loopback not trusted) the named
/// constructors do not spell.
fn policies() -> [IdentityPolicy; 4] {
    [
        IdentityPolicy::strict(),
        IdentityPolicy::local(),
        IdentityPolicy::default(),
        IdentityPolicy {
            require_identity: false,
            trust_loopback: false,
        },
    ]
}

/// The expected outcome of `admit` for one matrix cell, read off
/// `IdentityPolicy::admit`: an unverified certificate claim is refused under
/// every policy; a loopback peer admits only on loopback under a
/// loopback-trusting policy; an anonymous peer admits as loopback where the
/// policy trusts loopback, as unauthenticated where it requires no identity
/// but only on loopback, and is refused everywhere else.
fn expected(policy: &IdentityPolicy, peer_kind: u8, loopback: bool) -> Option<TrustLevel> {
    match peer_kind {
        // 0 = an unverified certificate claim (MutualTls, not verified).
        0 => None,
        // 1 = the loopback identity.
        1 => {
            if loopback && policy.trust_loopback {
                Some(TrustLevel::LoopbackRelaxed)
            } else {
                None
            }
        }
        // 2 = no peer, or the anonymous identity (admit normalises them).
        _ => {
            if loopback && policy.trust_loopback {
                Some(TrustLevel::LoopbackRelaxed)
            } else if !policy.require_identity && loopback {
                Some(TrustLevel::Unauthenticated)
            } else {
                None
            }
        }
    }
}

/// A name the introduction can carry: ASCII letters, digits and safe
/// punctuation only, so validity is decided here, not by re-implementing
/// `security::valid_text` (which also refuses bidi and invisible characters
/// the fuzzer would otherwise have to model exactly).
fn safe_name(data: &[u8], take: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-_.";
    if data.is_empty() {
        // A name must be 1..=1024 bytes: an empty slice still names a
        // provider, it just names it "a".
        return "a".to_string();
    }
    let mut out = String::new();
    for byte in data.iter().take(take) {
        out.push(ALPHABET[(byte % ALPHABET.len() as u8) as usize] as char);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    // Fixed positive control: a certificate claim is never verified, the
    // loopback admission under local() is loopback-relaxed and cannot hold a
    // binding, and the fingerprint is stable. Without it a policy that
    // refused every peer would satisfy every refusal assertion below.
    {
        let claim = PeerIdentity::from_certificate(b"fixed-cert-bytes");
        assert!(
            !claim.is_verified(),
            "a certificate claim is never verified"
        );
        assert_eq!(
            claim.fingerprint(),
            claim.fingerprint(),
            "the fingerprint is stable"
        );
        assert_eq!(
            claim.fingerprint_hex().len(),
            64,
            "the fingerprint hex is 32 bytes"
        );
        let admitted = IdentityPolicy::local()
            .admit(None, true)
            .expect("loopback admits under local()");
        assert_eq!(admitted.trust(), TrustLevel::LoopbackRelaxed);
        assert!(
            !admitted.can_bind(),
            "a loopback admission cannot hold a binding"
        );
    }
    if data.is_empty() {
        return;
    }

    // 1. A certificate claim: totality, determinism, and no proof.
    let claim = PeerIdentity::from_certificate(data);
    assert!(!claim.is_verified(), "a fuzzed claim must never verify");
    assert_eq!(
        claim.not_after(),
        None,
        "an unverified claim asserts no expiry"
    );
    assert!(
        !claim.is_expired_at(u64::MAX),
        "an unverified claim never expires"
    );
    assert!(
        !claim.is_expired_at(0),
        "an unverified claim never expires at zero"
    );
    let fingerprint = claim.fingerprint();
    assert_eq!(
        fingerprint,
        PeerIdentity::from_certificate(data).fingerprint(),
        "the fingerprint is deterministic"
    );
    let hex = claim.fingerprint_hex();
    assert_eq!(hex.len(), 64, "the fingerprint hex is 32 bytes");
    assert!(
        hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "the fingerprint hex is lowercase hex: {hex}"
    );
    assert!(
        hex.starts_with(&fingerprint_prefix_hex(&fingerprint_prefix(fingerprint))),
        "the fingerprint hex starts with its prefix hex"
    );
    assert!(
        fingerprint_prefix(fingerprint) == fingerprint[..16],
        "the fingerprint prefix is the first 16 bytes"
    );
    // A fingerprint is bindable unless it is one of the three refused
    // constants. The third (the empty-evidence digest) is a Blake3 digest, so
    // reaching it from fuzzed bytes would need a preimage, not a mutation;
    // if it ever fires, it is a real collision, not a harness artefact.
    let loopback_fp = PeerIdentity::loopback().fingerprint();
    if fingerprint != [0u8; 32] && fingerprint != loopback_fp {
        assert!(
            bindable(fingerprint),
            "a real certificate digest is bindable"
        );
    }
    assert!(
        !bindable([0u8; 32]),
        "the all-zero fingerprint is not bindable"
    );
    assert!(
        !bindable(loopback_fp),
        "the loopback fingerprint is not bindable"
    );
    // Renaming a peer keeps its fingerprint and its verified status, and the
    // subject stays bounded and free of control characters.
    let renamed = claim.clone().with_subject(safe_name(data, 600));
    assert_eq!(
        renamed.fingerprint(),
        fingerprint,
        "renaming keeps the fingerprint"
    );
    assert_eq!(
        renamed.is_verified(),
        claim.is_verified(),
        "renaming keeps verified status"
    );
    assert!(
        renamed.subject().len() <= 512,
        "the subject is bounded to 512 bytes"
    );
    assert!(
        renamed.subject().chars().all(|ch| !ch.is_control()),
        "the subject carries no control characters"
    );

    // 2. The admit matrix, exhaustively: every policy, every peer kind, both
    // loopback values. A peer is only admitted at the trust the policy
    // assigns, and no admission here can hold a binding.
    let anonymous = PeerIdentity::anonymous();
    let loopback = PeerIdentity::loopback();
    for policy in policies() {
        for (peer_kind, peer) in [
            (0u8, Some(&claim)),
            (1u8, Some(&loopback)),
            (2u8, Some(&anonymous)),
            (2u8, None),
        ] {
            for loopback_flag in [true, false] {
                match policy.admit(peer, loopback_flag) {
                    Ok(admitted) => {
                        assert_eq!(
                            Some(admitted.trust()),
                            expected(&policy, peer_kind, loopback_flag),
                            "admission at an unexpected trust level"
                        );
                        assert_eq!(
                            admitted.identity().fingerprint(),
                            match admitted.trust() {
                                TrustLevel::LoopbackRelaxed => loopback_fp,
                                TrustLevel::Unauthenticated => anonymous.fingerprint(),
                                TrustLevel::Authenticated => fingerprint,
                            },
                            "the admitted identity is not the one the trust level names"
                        );
                        assert!(
                            !admitted.can_bind(),
                            "no admission in this matrix can hold a binding"
                        );
                        assert_eq!(
                            admitted.fingerprint(),
                            admitted.identity().fingerprint(),
                            "the admitted fingerprint is the identity's"
                        );
                    }
                    Err(error) => {
                        assert_eq!(error.code(), "rpc/identity");
                        assert_eq!(
                            expected(&policy, peer_kind, loopback_flag),
                            None,
                            "a peer the matrix admits was refused: {error}"
                        );
                    }
                }
            }
        }
    }

    // 3. Two peers are never confused: different certificate bytes give
    // different fingerprints, and the comparison distinguishes them both ways.
    let half = data.len() / 2;
    let first = &data[..half.max(1)];
    let mut second = data[half.max(1)..].to_vec();
    if second.is_empty() {
        second.push(0x01);
    }
    if second.as_slice() == first {
        second[0] ^= 0xff;
    }
    let first_peer = PeerIdentity::from_certificate(first);
    let second_peer = PeerIdentity::from_certificate(&second);
    let first_fp = first_peer.fingerprint();
    let second_fp = second_peer.fingerprint();
    assert_ne!(
        first_fp, second_fp,
        "two different certificates share a fingerprint"
    );
    assert!(matches(Some(first_fp), first_fp));
    assert!(matches(Some(second_fp), second_fp));
    assert!(
        !matches(Some(first_fp), second_fp),
        "the first peer matches the second binding"
    );
    assert!(
        !matches(Some(second_fp), first_fp),
        "the second peer matches the first binding"
    );
    assert!(!matches(None, first_fp), "no peer matches a binding");
    assert_eq!(presented_fingerprint(Some(&first_peer)), Some(first_fp));
    assert_eq!(presented_fingerprint(Some(&second_peer)), Some(second_fp));
    assert_eq!(presented_fingerprint(Some(&anonymous)), None);
    assert_eq!(presented_fingerprint(None), None);

    // 4. The introduction: a valid surface builds, canonically, and an
    // invalid one is refused with the code that names the fault.
    let provider_count = data.first().copied().unwrap_or(0) as usize % 4;
    let mut providers: Vec<(String, Vec<String>)> = Vec::new();
    for index in 0..provider_count {
        let start = 1 + index * 8;
        let name = safe_name(&data[start.min(data.len())..], 1 + (data.len() % 20));
        let method_count = data.get(start + 1).copied().unwrap_or(0) as usize % 4;
        let mut methods = Vec::new();
        for method in 0..method_count {
            let at = start + 2 + method;
            methods.push(safe_name(
                &data[at.min(data.len())..],
                1 + (data.len() % 12),
            ));
        }
        providers.push((name, methods));
    }
    let peer_name = safe_name(data, 1 + (data.len() % 24));
    let budget = if data.len() > 2 && data[2].is_multiple_of(8) {
        Budget {
            max_calls: u64::MAX,
            ..Budget::default()
        }
    } else {
        common::budget_from(data)
    };
    let built = active_rpc::intro::build(&peer_name, &providers, &budget);
    match built {
        Ok(bytes) => {
            assert!(!bytes.is_empty(), "an introduction is never empty");
            let again = active_rpc::intro::build(&peer_name, &providers, &budget)
                .expect("the same surface builds twice");
            assert_eq!(bytes, again, "the same surface must build the same bytes");
            let mut reversed = providers.clone();
            reversed.reverse();
            let shuffled = active_rpc::intro::build(&peer_name, &reversed, &budget)
                .expect("the reversed surface builds");
            assert_eq!(bytes, shuffled, "provider order must not change the bytes");
            let decoded = active_infinity::decode(&bytes).expect("the introduction decodes");
            let reencoded = active_infinity::encode(&decoded).expect("the introduction encodes");
            assert_eq!(
                bytes, reencoded,
                "the introduction must round-trip canonically"
            );
        }
        Err(error) => {
            // The only fault this leg can construct on a valid surface is a
            // ceiling that does not fit the module integer (the u64::MAX
            // budget above). Every name here is a safe-alphabet name of
            // 1..=1024 bytes, so a refusal for any other reason is a
            // misclassification, not a fault in the input.
            assert_eq!(
                error.code(),
                "rpc/invalid-argument",
                "unexpected refusal: {error}"
            );
            assert_eq!(
                budget.max_calls,
                u64::MAX,
                "a valid surface was refused: {error}"
            );
        }
    }

    // 4b. The invalid half, deterministically: an overlong name and a name
    // with a control character are both refused, whatever the rest of the
    // input is.
    let long = "p".repeat(1025);
    let error = active_rpc::intro::build(&long, &providers, &Budget::default())
        .expect_err("a peer name over 1024 bytes is refused");
    assert_eq!(error.code(), "rpc/invalid-argument");
    let error = active_rpc::intro::build("bad\nname", &providers, &Budget::default())
        .expect_err("a peer name with a control character is refused");
    assert_eq!(error.code(), "rpc/invalid-argument");
});
