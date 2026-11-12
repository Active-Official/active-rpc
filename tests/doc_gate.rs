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

/// TEST-11: the checked-in perf baseline was measured on Windows while CI
/// runs on Ubuntu-only, and the gate script never reads the baseline's host
/// field — so the host record lives here, in `docs/spec/performance.md`,
/// next to the gate description. If the baseline is re-measured on another
/// host, this test forces the record to move with it.
#[test]
fn perf_baseline_host_is_recorded() {
    let perf = fs::read_to_string(repo_path("docs/spec/performance.md")).expect("performance");
    assert!(
        perf.contains(r#""host": {"arch": "x86_64", "os": "windows"}"#),
        "performance.md must record the perf-baseline host exactly as the JSON states it"
    );
    assert!(
        perf.contains("ubuntu-latest"),
        "performance.md must say CI's perf-gate job runs on ubuntu-latest"
    );
    assert!(
        perf.contains("does not pass `--baseline`"),
        "performance.md must say CI does not run the absolute comparison"
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

fn parse_version_opt(token: &str) -> Option<(u64, u64, u64)> {
    let token = token.strip_prefix('v').unwrap_or(token);
    let mut parts = token.split('.');
    let major: u64 = parts.next()?.parse().ok()?;
    let minor: u64 = parts.next()?.parse().ok()?;
    let patch: u64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

fn format_version(version: (u64, u64, u64)) -> String {
    format!("{}.{}.{}", version.0, version.1, version.2)
}

/// `STATUS.md` and `REGISTRY.md` must track the library version.
///
/// TEST-04: both files named `active-rpc` 2.2.0 while `Cargo.toml` said
/// 2.3.0, so an operator verifying a deployment against them checked the
/// wrong tag/SBOM. The release runbook (precondition 2) requires
/// `REGISTRY.md` to list the versions when the version is bumped, and
/// precondition 4 requires `STATUS.md` to reflect the candidate state, so
/// both files track the in-tree version — the version the next release
/// will carry — not the last release.
///
/// Two precision points, both load-bearing:
/// * The `Library` row and the registry row are asserted row-scoped, not
///   file-wide: a stray "2.3.0" anywhere else in either file must not
///   satisfy the gate (the TEST-03 lesson — a plain `contains` check
///   passes vacuously).
/// * The `Tag` / GitHub Release / SBOM rows describe the *latest
///   release*, not the candidate: 2.3.0 is unreleased (CHANGELOG
///   `Unreleased - 2.3.0`, no `v2.3.0` tag), so bumping those rows to
///   `v2.3.0` would fabricate a release. They must instead agree with
///   each other on one version, name the SBOM for it, never run ahead of
///   the library version (equal at release time, older before it), and
///   name a tag that exists in this repo.
#[test]
fn status_and_registry_track_the_library_version() {
    let version = env!("CARGO_PKG_VERSION");
    let library_version =
        parse_version_opt(version).expect("CARGO_PKG_VERSION must be three numeric parts");

    let status = fs::read_to_string(repo_path("STATUS.md")).expect("STATUS.md");
    let library_rows: Vec<&str> = status
        .lines()
        .filter(|line| line.starts_with("| Library |"))
        .collect();
    assert_eq!(
        library_rows.len(),
        1,
        "STATUS.md must have exactly one Library row"
    );
    assert!(
        library_rows[0].contains(&format!("`active-rpc` {version}")),
        "STATUS.md Library row must name the library version {version}: {}",
        library_rows[0]
    );

    let registry = fs::read_to_string(repo_path("REGISTRY.md")).expect("REGISTRY.md");
    let crate_rows: Vec<&str> = registry
        .lines()
        .filter(|line| {
            line.split('|').nth(1).is_some_and(|cell| {
                cell.trim() == "[`active-rpc`](https://crates.io/crates/active-rpc)"
            })
        })
        .collect();
    assert_eq!(
        crate_rows.len(),
        1,
        "REGISTRY.md must have exactly one active-rpc row"
    );
    let registry_version = crate_rows[0]
        .split('|')
        .nth(2)
        .expect("registry row version cell")
        .trim();
    assert_eq!(
        registry_version, version,
        "REGISTRY.md active-rpc row must list the library version {version}"
    );

    // The release rows describe the latest release, not the candidate.
    let tag_row = status
        .lines()
        .find(|line| {
            line.split('|')
                .nth(1)
                .is_some_and(|cell| cell.trim().starts_with("Tag"))
        })
        .expect("STATUS.md must have a Tag row");
    assert!(
        tag_row.contains("(latest release)"),
        "STATUS.md Tag row must say it names the latest release, so it is never mistaken for the candidate version: {tag_row}"
    );
    let release_row = status
        .lines()
        .find(|line| {
            line.split('|')
                .nth(1)
                .is_some_and(|cell| cell.trim() == "GitHub Release")
        })
        .expect("STATUS.md must have a GitHub Release row");
    let mut named: Vec<(u64, u64, u64)> = Vec::new();
    for row in [tag_row, release_row] {
        for token in row.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.')) {
            if let Some(triple) = parse_version_opt(token) {
                named.push(triple);
            }
        }
    }
    assert!(
        !named.is_empty(),
        "STATUS.md Tag and GitHub Release rows must name a version"
    );
    let tag_version = named[0];
    assert!(
        named.iter().all(|triple| *triple == tag_version),
        "STATUS.md Tag and GitHub Release rows must agree on one version: {named:?}"
    );
    let tag_version_text = format_version(tag_version);
    assert!(
        release_row.contains(&format!("active-rpc-{tag_version_text}.cdx.json")),
        "STATUS.md GitHub Release row must name the SBOM for the tagged version {tag_version_text}: {release_row}"
    );
    assert!(
        tag_version <= library_version,
        "STATUS.md Tag row names {tag_version_text}, ahead of the library version {version}: the tag names a release that does not exist yet"
    );

    // The tag the file names must exist in this repo. A checkout without
    // git (a published crate tarball) skips this assertion rather than
    // failing spuriously; CI and the release workflow always run in a
    // checkout, where the check is load-bearing.
    let tag = format!("v{tag_version_text}");
    match std::process::Command::new("git")
        .args(["tag", "--list", &tag])
        .current_dir(repo_path(""))
        .output()
    {
        Ok(output) if output.status.success() => {
            let listed = String::from_utf8_lossy(&output.stdout);
            assert!(
                listed.lines().any(|line| line.trim() == tag),
                "STATUS.md names tag {tag} but no such tag exists in this repo"
            );
        }
        _ => {
            eprintln!("note: git unavailable or not a checkout, skipping tag-existence check");
        }
    }
}

/// `CHANGELOG.md` must have exactly one `## Unreleased` section, at the top.
///
/// TEST-05: Infinity's changelog carried two `## Unreleased` sections; the
/// second one — after `## 2.4.2` — hid hash-affecting canonical-form changes
/// ("enum members … are sorted before interning", "node numbering orders
/// bindings by name", "re-encode them to migrate"), so a changelog parser
/// (or a human) reading top-down stopped at the first `Unreleased` and
/// missed them. The Infinity half was already fixed by the INF-03 fix
/// (aa2ba55), which merged the second block into the top one and marked its
/// entries `### Changed (hash-affecting — re-encode required)`; this repo
/// never grew a second block (its single heading is
/// `## Unreleased - 2.3.0`), so there is no content to merge here — the
/// gate is the fix on this side, so the same drift can never land
/// unnoticed in this repo.
///
/// Two precision points, both load-bearing:
/// * The count is over `## ` headings whose text starts with
///   "Unreleased", not a file-wide `contains` — a stray "Unreleased"
///   mention in prose must not satisfy the gate, and a second heading
///   must fail it (the TEST-03 lesson — a plain `contains` check passes
///   vacuously).
/// * The single heading must be the FIRST `## ` heading in the file: a
///   second block is exactly an `Unreleased` heading that is not first,
///   so position is asserted, not just count.
#[test]
fn changelog_has_exactly_one_unreleased_section() {
    let changelog = fs::read_to_string(repo_path("CHANGELOG.md")).expect("CHANGELOG.md");
    let headings: Vec<&str> = changelog
        .lines()
        .filter_map(|line| line.strip_prefix("## "))
        .collect();
    assert!(
        !headings.is_empty(),
        "CHANGELOG.md must have at least one `## ` section heading"
    );
    let unreleased: Vec<&&str> = headings
        .iter()
        .filter(|heading| heading.starts_with("Unreleased"))
        .collect();
    assert_eq!(
        unreleased.len(),
        1,
        "CHANGELOG.md must have exactly one `## Unreleased` section, found {}: {unreleased:?}",
        unreleased.len()
    );
    assert!(
        headings[0].starts_with("Unreleased"),
        "the `## Unreleased` section must be the first section in CHANGELOG.md, found first heading: {}",
        headings[0]
    );
}

/// Every facade's `active-rpc` floor must equal the parent version.
///
/// TEST-09: all five facades pinned `active-rpc = "2.0.0"` while the
/// parent shipped 2.3.0, so a consumer pinning the floor got a facade
/// over a three-minor-old kernel with known-fixed secret/redaction
/// bugs. The floor is the parent version, exactly — not a range, not
/// "at least": a floor below the parent re-admits the old kernel, and
/// a floor above the parent cannot resolve.
///
/// The dependency also carries `path = "../.."`, the same shape as
/// the CLI (`cli/active-rpc-cli/Cargo.toml`) and the control plane
/// (`control-plane/Cargo.toml`): the facades are part of this repo,
/// so they resolve the tree under test. Without the path, the bumped
/// floor could not resolve at all until 2.3.0 is published on
/// crates.io (latest published is 2.2.0), and the CI facades job —
/// `cargo test --manifest-path facades/<crate>/Cargo.toml` — would
/// go red on main. With the path, `cargo publish` still strips it
/// and keeps the version requirement, so the published facade
/// requires the published kernel (release order: kernel first, as
/// the runbook already requires for the CLI).
///
/// Three precision points, all load-bearing:
/// * The floor is read from the `active-rpc = { ... }` line inside
///   the facade's `[dependencies]` section, not file-wide: the
///   transport facade also mentions `active-rpc/quic` in `[features]`,
///   and a plain `contains` check would pass vacuously (the TEST-03
///   lesson).
/// * A facade with no `active-rpc` dependency line fails outright:
///   a missing floor must not read as a matching floor.
/// * The five known facades must all be present, and no other
///   directory may appear: a deleted facade must fail the gate, not
///   silently drop out of it, and a new facade must be added to the
///   list deliberately.
#[test]
fn facade_floors_equal_the_parent_version() {
    const EXPECTED: &[&str] = &[
        "active-rpc-kernel",
        "active-rpc-core",
        "active-rpc-client",
        "active-rpc-tools",
        "active-rpc-transport",
    ];
    let parent = env!("CARGO_PKG_VERSION");
    let facades = repo_path("facades");
    let mut checked: Vec<String> = Vec::new();
    for entry in fs::read_dir(&facades).expect("facades/ must exist") {
        let entry = entry.expect("facade dir entry");
        let manifest = entry.path().join("Cargo.toml");
        if !manifest.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let text =
            fs::read_to_string(&manifest).unwrap_or_else(|_| panic!("read {}", manifest.display()));
        let line = facade_active_rpc_dep_line(&text).unwrap_or_else(|| {
            panic!("{name}/Cargo.toml has no active-rpc line in [dependencies]")
        });
        let floor = facade_active_rpc_floor(&line).unwrap_or_else(|| {
            panic!("{name}/Cargo.toml active-rpc line names no version: {line}")
        });
        assert_eq!(
            floor.as_str(),
            parent,
            "{name}/Cargo.toml pins active-rpc {floor}, parent is {parent}"
        );
        assert!(
            line.contains("path = \"../..\""),
            "{name}/Cargo.toml must resolve active-rpc from the tree (path = \"../..\") so the floor resolves before the parent is published"
        );
        checked.push(name);
    }
    for expected in EXPECTED {
        assert!(
            checked.iter().any(|name| name == expected),
            "facade {expected} is missing from facades/"
        );
    }
    assert_eq!(
        checked.len(),
        EXPECTED.len(),
        "unexpected facade directories in facades/: {checked:?}"
    );
}

/// The `active-rpc = ...` line inside a manifest's `[dependencies]`
/// section, or `None` when the section has no such line. Section
/// scoped: a mention in `[features]` (the transport facade's
/// `active-rpc/quic`) is not a dependency line.
fn facade_active_rpc_dep_line(manifest: &str) -> Option<String> {
    let mut in_dependencies = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_dependencies = line == "[dependencies]";
            continue;
        }
        if in_dependencies && line.starts_with("active-rpc = ") {
            return Some(line.to_string());
        }
    }
    None
}

/// The version requirement on an `active-rpc = ...` dependency line.
/// Handles the bare form (`active-rpc = "2.3.0"`) and the table form
/// (`active-rpc = { path = "../..", version = "2.3.0", ... }`),
/// in either key order.
fn facade_active_rpc_floor(dep_line: &str) -> Option<String> {
    if let Some(version) = dep_line.strip_prefix("active-rpc = \"") {
        return version.split('"').next().map(str::to_string);
    }
    let marker = "version = \"";
    let start = dep_line.find(marker)? + marker.len();
    dep_line[start..].split('"').next().map(str::to_string)
}
