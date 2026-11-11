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
    "rpc/bulk",
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
    // R2-CI-02: the enforcement must live in the workflow, not only in the
    // prose — a phrase-presence test over the runbook is the same class of
    // hole as the one being fixed. Assert the release workflow itself
    // verifies the tag, checks the tag out, checks the version, gates on
    // green CI, and never silently replaces an asset — and that the two
    // proofs run BEFORE the SBOM step (ordering, not mere presence).
    let workflow =
        fs::read_to_string(repo_path(".github/workflows/release.yml")).expect("release.yml");
    let verify = workflow
        .find("run: scripts/verify_tag.sh")
        .expect("release.yml must invoke scripts/verify_tag.sh");
    let version_check = workflow
        .find("Assert the tag matches Cargo.toml")
        .expect("release.yml must assert the tag matches Cargo.toml");
    let sbom = workflow
        .find("name: SBOM")
        .expect("release.yml must have an SBOM step");
    assert!(
        verify < sbom,
        "the tag-signature verification step must run before the SBOM step"
    );
    assert!(
        version_check < sbom,
        "the tag-version check must run before the SBOM step"
    );
    assert!(
        workflow.contains("ref: ${{ inputs.tag || github.ref_name }}"),
        "release.yml must check out the tag itself, not the dispatch branch"
    );
    assert!(
        workflow.contains("Require green CI for this commit"),
        "release.yml must require green CI before publishing"
    );
    for line in workflow.lines() {
        assert!(
            !(line.contains("gh release upload") && line.contains("--clobber")),
            "release.yml must never silently replace a release asset (--clobber)"
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

/// The security policy lists the minor this crate ships.
///
/// A shipped version outside the supported table tells a reporter the release is
/// out of scope while it is the one in production (F-44).
#[test]
fn the_security_policy_lists_the_shipped_minor() {
    let cargo = fs::read_to_string(repo_path("Cargo.toml")).expect("Cargo.toml");
    let version = cargo
        .lines()
        .find_map(|line| line.strip_prefix("version = "))
        .expect("a package version");
    let version = version.trim().trim_matches('"');
    let mut parts = version.split('.');
    let minor = format!(
        "{}.{}.x",
        parts.next().expect("major"),
        parts.next().expect("minor")
    );
    let policy = fs::read_to_string(repo_path("SECURITY.md")).expect("SECURITY.md");
    assert!(
        policy.contains(&minor),
        "SECURITY.md must list {minor} (the shipped minor)"
    );
    assert!(
        policy.contains("| yes") || policy.contains("| yes (current)"),
        "SECURITY.md must say which version is supported"
    );
}

/// Every version the changelog names as yanked must have its ADR.
///
/// TEST-03: ADR-0006 required an ADR for any yank, and
/// active-infinity 2.0.0 was yanked (CHANGELOG.md, 1.1.9) with no ADR at
/// all. The gate reads every `yank` line in CHANGELOG.md, extracts the
/// version(s) it names, and requires one numbered ADR to mention the
/// version *in a yank context* — the version string and the word "yank"
/// in the same file. The same-file requirement is load-bearing: ADR-0019
/// mentions "2.0.0" only as wasmi's version, so a plain "some ADR
/// mentions the version" check would have passed vacuously before this
/// fix. The index (docs/adr/README.md) is not an ADR, so it is excluded
/// from the scan: only files named `NNNN-*.md` count. A yank line that
/// names no version fails outright, so a future yank cannot dodge the
/// gate by omitting the version.
#[test]
fn every_yanked_version_has_an_adr() {
    let changelog = fs::read_to_string(repo_path("CHANGELOG.md")).expect("CHANGELOG.md");
    let adr_dir = repo_path("docs/adr");
    let mut adrs: Vec<String> = Vec::new();
    for entry in fs::read_dir(&adr_dir).expect("docs/adr").flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let numbered = name.len() > 5
            && name[..4].chars().all(|c| c.is_ascii_digit())
            && name.as_bytes()[4] == b'-';
        if numbered && path.extension().is_some_and(|extension| extension == "md") {
            adrs.push(
                fs::read_to_string(&path).unwrap_or_else(|_| panic!("read {}", path.display())),
            );
        }
    }
    assert!(!adrs.is_empty(), "docs/adr must contain numbered ADR files");
    let mut yanked: Vec<String> = Vec::new();
    for line in changelog.lines() {
        if !line.to_lowercase().contains("yank") {
            continue;
        }
        let mut found = false;
        for token in line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.')) {
            let parts: Vec<&str> = token.split('.').collect();
            if parts.len() == 3
                && parts
                    .iter()
                    .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
            {
                yanked.push(token.to_string());
                found = true;
            }
        }
        assert!(
            found,
            "CHANGELOG yank line names no version, so no ADR can cover it: {line}"
        );
    }
    assert!(
        !yanked.is_empty(),
        "expected CHANGELOG.md to record at least one yank (active-infinity 2.0.0)"
    );
    for version in yanked {
        assert!(
            adrs.iter().any(|adr| adr.contains(&version)
                && adr.to_lowercase().contains("yank")),
            "no ADR records the yank of version {version}; see ADR-0006 point 5 as amended by ADR-0040"
        );
    }
}
