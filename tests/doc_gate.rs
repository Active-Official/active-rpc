//! Documentation gate for Active RPC.
//!
//! The wire spec and the error catalog are part of the public contract. These
//! tests fail when the prose and the implementation disagree about a code, an
//! invariant, or a hardening rule.

use std::fs;
use std::path::Path;

fn repo_path(relative: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

const ERROR_CODES: &[&str] = &[
    "rpc/unknown-capability",
    "rpc/method-not-granted",
    "rpc/attenuation-escalation",
    "rpc/read-only",
    "rpc/path-not-granted",
    "rpc/tool-policy",
    "rpc/revoked",
    "rpc/budget-exceeded",
    "rpc/unknown-lane",
    "rpc/unknown-channel",
    "rpc/unknown-promise",
    "rpc/promise-cancelled",
    "rpc/promise-resolved",
    "rpc/unresolvable-promise",
    "rpc/provider",
    "rpc/domain",
    "rpc/payload",
    "rpc/wire",
    "rpc/capability-table",
    "rpc/transport",
    "rpc/transport-unavailable",
    "rpc/timeout",
    "rpc/pipelined-cycle",
    "rpc/invalid-argument",
];

#[test]
fn every_error_code_is_documented() {
    let spec = fs::read_to_string(repo_path("docs/spec/wire.md")).expect("wire spec");
    for code in ERROR_CODES {
        assert!(spec.contains(code), "wire spec must document {code}");
    }
}

#[test]
fn wire_spec_documents_the_envelope_and_capability_table() {
    let spec = fs::read_to_string(repo_path("docs/spec/wire.md")).expect("wire spec");
    for needle in ["ARP1", "capability table", "request", "response", "error"] {
        assert!(
            spec.to_lowercase().contains(&needle.to_lowercase()),
            "wire spec must document {needle}"
        );
    }
}

#[test]
fn security_spec_lists_every_invariant() {
    let spec = fs::read_to_string(repo_path("docs/spec/security.md")).expect("security spec");
    for number in 1..=12 {
        let needle = format!("| I-{number} |");
        assert!(
            spec.contains(&needle),
            "security spec must list invariant I-{number}"
        );
    }
}

#[test]
fn readme_states_the_guarantees() {
    let readme = fs::read_to_string(repo_path("README.md")).expect("readme");
    assert!(readme.contains("No ambient authority"));
    assert!(readme.contains("capability"));
    assert!(readme.contains("promise"));
}

#[test]
fn hardening_documents_exist_and_state_their_rules() {
    for doc in [
        "REVIEW-SCOPE.md",
        "RELEASE.md",
        "COMPATIBILITY.md",
        "MIGRATION.md",
        "COMPARISON.md",
        "LOGGING.md",
        "CORPUS.md",
        "RESEARCH-LOG.md",
        "STATUS.md",
        "invariant-map.toml",
    ] {
        let path = repo_path(&format!("docs/hardening/{doc}"));
        assert!(path.exists(), "missing hardening document {doc}");
    }

    let logging = fs::read_to_string(repo_path("docs/hardening/LOGGING.md")).expect("logging");
    assert!(logging.contains("raw 16-byte capability id"));
    assert!(logging.contains("***SECRET***"));
    assert!(logging.contains("correlation"));

    let release = fs::read_to_string(repo_path("docs/hardening/RELEASE.md")).expect("release");
    assert!(release.contains("Active-Official"));
    assert!(release.contains("RatioArtificiosa"));
    assert!(release.contains("cargo yank"));

    let compatibility =
        fs::read_to_string(repo_path("docs/hardening/COMPATIBILITY.md")).expect("compatibility");
    assert!(compatibility.contains("Unknown flags"));
    assert!(compatibility.contains("Deprecation window"));
}

#[test]
fn review_program_is_documented_and_has_a_record() {
    let scope = fs::read_to_string(repo_path("docs/hardening/REVIEW-SCOPE.md")).expect("scope");
    for phrase in [
        "## Scope",
        "## Method",
        "## Severity",
        "## Mandatory review triggers",
        "## Cadence",
        "delta review",
        "release candidate",
    ] {
        assert!(scope.contains(phrase), "review scope must contain {phrase}");
    }
    let record = fs::read_to_string(repo_path("REVIEWS.md")).expect("review record");
    assert!(
        record.contains("## Round"),
        "review record must list rounds"
    );
    assert!(
        record.to_lowercase().contains("no new findings"),
        "review record must state convergence"
    );
    assert!(record.contains("| Finding |"), "review record must triage");
}

#[test]
fn performance_baselines_are_checked_in() {
    let perf = fs::read_to_string(repo_path("docs/spec/performance.md")).expect("performance");
    for phrase in [
        "envelope encode",
        "envelope decode",
        "in-process transport",
        "shared-memory transport",
        "kernel call",
        "sequential",
        "batched",
    ] {
        assert!(
            perf.contains(phrase),
            "performance matrix must include {phrase}"
        );
    }
    assert!(perf.contains("Regression policy"));
    assert!(perf.contains("Sustained-load and hostile-input budgets"));
    let bench = fs::read_to_string(repo_path("benches/transport.rs")).expect("benchmark");
    assert!(
        bench.contains("pipelining"),
        "benchmark must cover pipelining"
    );
}

#[test]
fn release_and_supply_chain_process_is_operational() {
    let release = fs::read_to_string(repo_path("docs/hardening/RELEASE.md")).expect("release");
    for phrase in [
        "SBOM",
        "signed",
        "reproducib",
        "cargo yank",
        "crates.io",
        "Active-Official",
        "RatioArtificiosa",
        "allowed_signers",
    ] {
        assert!(
            release.contains(phrase),
            "release guide must contain {phrase}"
        );
    }
}

#[test]
fn migration_comparison_and_compatibility_are_documented() {
    let migration =
        fs::read_to_string(repo_path("docs/hardening/MIGRATION.md")).expect("migration");
    assert!(migration.contains("JSON") && migration.contains("YAML"));
    let comparison =
        fs::read_to_string(repo_path("docs/hardening/COMPARISON.md")).expect("comparison");
    assert!(comparison.contains("Cap'n Proto"));
    assert!(comparison.contains("gRPC"));
    let compatibility =
        fs::read_to_string(repo_path("docs/hardening/COMPATIBILITY.md")).expect("compatibility");
    for phrase in ["Unknown flags", "Deprecation window", "ARP1"] {
        assert!(
            compatibility.contains(phrase),
            "compatibility must contain {phrase}"
        );
    }
}

#[test]
fn security_policy_states_the_evidence_levels() {
    let security = fs::read_to_string(repo_path("SECURITY.md")).expect("security policy");
    for level in ["**Tested**", "**Fuzzed**", "**Reviewed**", "**Proven**"] {
        assert!(security.contains(level), "SECURITY.md must state {level}");
    }
    assert!(security.contains("not") && security.contains("formally"));
}

#[test]
fn status_publishes_residual_risks_and_the_sign_off_block() {
    let status = fs::read_to_string(repo_path("docs/hardening/STATUS.md")).expect("status");
    for phrase in [
        "Residual risks",
        "Maturity sign-off",
        "H0 inventory complete",
        "H9 continuous assurance active",
        "Sign-off",
    ] {
        assert!(status.contains(phrase), "STATUS must contain {phrase}");
    }
}
