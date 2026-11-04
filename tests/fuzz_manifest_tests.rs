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
fn every_lane_names_every_target() {
    for lane in [
        ".github/workflows/ci.yml",
        ".github/workflows/nightly.yml",
        ".github/workflows/fuzz-nightly.yml",
        "fuzz/README.md",
        "docs/hardening/CORPUS.md",
    ] {
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
