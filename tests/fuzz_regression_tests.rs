//! Corpus seeds that pin the rules the fuzz targets enforce.
//!
//! A seed named for a rule must be refused by that rule alone, and no target
//! should carry two byte-identical seeds (R-20 round 4, #10).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use active_rpc::replay::ReplayPackage;

fn repo(relative: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// The seed is a well-formed package with a valid checksum whose only fault is
/// a missing leading `SetLatency`, so it pins the rule `encode`/`replay_trace`
/// enforce (the parser that used to accept it).
#[test]
fn the_header_latency_seed_is_refused_by_that_rule_alone() {
    let bytes = repo("fuzz/corpus/fuzz_replay_package/header-latency-missing.arrp");
    let (body, checksum) = bytes.split_at(bytes.len() - 32);
    assert_eq!(
        blake3::hash(body).as_bytes(),
        checksum,
        "the seed's checksum must be valid"
    );
    let error = ReplayPackage::decode(&bytes).expect_err("refused");
    assert_eq!(error.code(), "rpc/replay");
    assert!(error.to_string().contains("header latency"), "{error}");
}

/// Two seeds that are byte-identical burn campaign time and hide a missing
/// case behind a name that suggests it exists.
#[test]
fn no_target_carries_two_identical_seeds() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus");
    let targets = std::fs::read_dir(&root).expect("corpus");
    for target in targets.flatten().filter(|entry| entry.path().is_dir()) {
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        for seed in std::fs::read_dir(target.path()).expect("seeds").flatten() {
            if !seed.path().is_file() {
                continue;
            }
            let bytes = std::fs::read(seed.path()).expect("read seed");
            assert!(
                seen.insert(bytes),
                "{} holds a duplicate seed: {}",
                target.path().display(),
                seed.path().display()
            );
        }
    }
}
