//! The fuzz manifest is the single source of truth for the target list.
//!
//! Every lane names its targets in a different file (three workflows, the
//! corpus inventory, the fuzz README), and a hand-copied list drifts: the local
//! `scripts/fuzz_docker.py` list ended at `fuzz_topic_policy` and printed "all
//! 12 targets completed" while four targets never ran. This test compares each
//! document against `fuzz/Cargo.toml`, so adding or renaming a target fails here
//! until every lane is updated.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn repo(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// Target names declared by `[[bin]]` in the fuzz manifest.
fn manifest_targets() -> BTreeSet<String> {
    let mut targets = BTreeSet::new();
    for line in repo("fuzz/Cargo.toml").lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("name = \"") else {
            continue;
        };
        let Some(name) = rest.strip_suffix('"') else {
            continue;
        };
        if name.starts_with("fuzz_") {
            targets.insert(name.to_string());
        }
    }
    targets
}

fn fuzz_targets() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/fuzz_targets")
}

#[test]
fn every_target_has_a_source_file_and_a_committed_corpus_directory() {
    let targets = manifest_targets();
    assert!(
        targets.len() >= 16,
        "the manifest declares {} targets: {targets:?}",
        targets.len()
    );
    for target in &targets {
        let source = fuzz_targets().join(format!("{target}.rs"));
        assert!(source.is_file(), "{target} is declared but has no source");
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fuzz/corpus")
            .join(target);
        assert!(
            corpus.is_dir(),
            "{target} has no corpus directory (an empty one is fine)"
        );
    }
}

#[test]
fn every_lane_covers_every_target() {
    // The CI lanes derive their list from the manifest, so one entry point
    // drives all of them; a lane that went back to a hand-copied list must name
    // every target or fail here (R-20 round 3, L6/L7). The derivation is a
    // heredoc reading `fuzz/Cargo.toml`, not any mention of it: a comment was
    // enough to satisfy the earlier form (round 4, #6).
    for lane in [
        ".github/workflows/ci.yml",
        ".github/workflows/nightly.yml",
        ".github/workflows/fuzz-nightly.yml",
    ] {
        let text = repo(lane);
        let derives = text.contains("fuzz/Cargo.toml") && text.contains("<<'PY'");
        assert!(
            derives,
            "{lane} neither derives its targets from fuzz/Cargo.toml nor carries a list"
        );
        if derives {
            continue;
        }
        for target in manifest_targets() {
            assert!(text.contains(&target), "{lane} does not name {target}");
        }
    }
    // The prose documents name every target.
    for lane in ["fuzz/README.md", "docs/hardening/CORPUS.md"] {
        let text = repo(lane);
        for target in manifest_targets() {
            assert!(text.contains(&target), "{lane} does not name {target}");
        }
    }
}

#[test]
fn the_local_lane_reads_the_manifest() {
    // A second hand-copied list in the runner script is the drift this test
    // exists to prevent.
    let script = repo("scripts/fuzz_docker.py");
    assert!(script.contains("fuzz/Cargo.toml") || script.contains("Cargo.toml"));
    assert!(
        !script.contains("\"fuzz_arp1_frame\""),
        "scripts/fuzz_docker.py hard-codes a target list"
    );
}

/// Every lane that installs a fuzz or coverage tool pins its version and runs
/// with a read-only token (R-20 round 4, #4 and #6).
#[test]
fn every_fuzz_lane_pins_its_tools_and_its_token() {
    for lane in [
        ".github/workflows/ci.yml",
        ".github/workflows/nightly.yml",
        ".github/workflows/fuzz-nightly.yml",
    ] {
        let text = repo(lane);
        if text.contains("cargo-fuzz") {
            assert!(
                text.contains("cargo install cargo-fuzz --version 0.13.2 --locked"),
                "{lane} installs cargo-fuzz without a pinned version"
            );
        }
        if text.contains("cargo-llvm-cov") {
            assert!(
                text.contains("cargo install cargo-llvm-cov --version")
                    && text.contains("--locked"),
                "{lane} installs cargo-llvm-cov without a pinned version"
            );
        }
        assert!(
            text.contains("permissions:") && text.contains("contents: read"),
            "{lane} does not pin the job token to read-only"
        );
    }
}

/// The primary decoders assert a fixed positive control before any early
/// return, so a decoder that refuses every input fails the lane instead of
/// passing it (R-20 rounds 3-4, H1 and #5).
#[test]
fn every_decoder_target_asserts_its_control_first() {
    for target in [
        "fuzz_arp1_frame",
        "fuzz_bulk_plan",
        "fuzz_domain_module",
        "fuzz_persistence_record",
        "fuzz_replay_package",
        "fuzz_tool_mcp",
        "fuzz_wasm_module",
    ] {
        let source = fs::read_to_string(fuzz_targets().join(format!("{target}.rs")))
            .unwrap_or_else(|error| panic!("{target}: {error}"));
        let control = source
            .to_lowercase()
            .find("positive control")
            .unwrap_or_else(|| panic!("{target} has no fixed positive control"));
        let guard = source.find("if data.is_empty()");
        assert!(
            guard.is_none_or(|guard| control < guard),
            "{target} runs its positive control after the empty-input guard"
        );
    }
}
