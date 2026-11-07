//! The fuzz manifest is the single source of truth for the target list.
//!
//! Every lane names its targets in a different file (three workflows, the
//! corpus inventory, the fuzz README), and a hand-copied list drifts: the local
//! `scripts/fuzz_docker.py` list ended at `fuzz_topic_policy` and printed "all
//! 12 targets completed" while four targets never ran. This test *executes*
//! each lane's derivation and compares the result against `fuzz/Cargo.toml`,
//! so a lane that regresses to a hand-copied list is caught even when it still
//! carries the here-doc token (R-20 round 5, F5/F6).

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
        // The same pattern every lane derives with: a mixed-case name passed
        // the old check and was then run by no lane (R-20 round 5, F6).
        if name.strip_prefix("fuzz_").is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
        }) {
            targets.insert(name.to_string());
        }
    }
    targets
}

fn fuzz_targets() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/fuzz_targets")
}

/// The interpreter the lanes invoke. `python3` is the name in CI; Windows
/// developers usually have it as `python`.
fn python() -> &'static str {
    for candidate in ["python3", "python"] {
        let ok = Command::new(candidate)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        if ok {
            return candidate;
        }
    }
    panic!("neither python3 nor python is on PATH; every fuzz lane derives its list with one");
}

/// Run a Python script with `script` on stdin and return its stdout.
fn run_python(script: &str) -> String {
    let mut child = Command::new(python())
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn python");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(script.as_bytes())
        .expect("write the script");
    let output = child.wait_with_output().expect("wait for python");
    assert!(
        output.status.success(),
        "python failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf-8")
}

/// Split a lane's stdout (a JSON array or one target per line) into names.
fn parse_names(output: &str) -> BTreeSet<String> {
    output
        .replace(['[', ']', '"', ','], " ")
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

/// The body of the `python3 - <<'PY' ... PY` block a lane runs, dedented the
/// way the YAML block scalar dedents it.
fn lane_derivation(lane: &str) -> String {
    let text = repo(lane);
    let start = text
        .find("<<'PY'")
        .unwrap_or_else(|| panic!("{lane} no longer derives its targets with a here-doc"));
    let rest = &text[start + "<<'PY'".len()..];
    let mut lines: Vec<&str> = Vec::new();
    for line in rest.lines().skip(1) {
        if line.trim() == "PY" {
            break;
        }
        lines.push(line);
    }
    let indent = lines
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.len() - line.trim_start().len())
        .min()
        .unwrap_or(0);
    let body: Vec<String> = lines
        .iter()
        .map(|line| line.get(indent.min(line.len())..).unwrap_or("").to_string())
        .collect();
    let body = body.join("\n");
    assert!(
        !body.trim().is_empty(),
        "{lane}'s here-doc has no body after dedenting"
    );
    body
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
fn every_lane_derives_exactly_the_manifest_targets() {
    // The derivation is executed, not pattern-matched: a lane that went back to
    // a hand-copied list yields a different set even if it keeps the here-doc
    // token (R-20 round 5, F5). The set equality also fails a lane whose
    // regex differs from the canonical charset, so a target can no longer be
    // declared and silently run by nobody (F6).
    let expected = manifest_targets();
    for lane in [
        ".github/workflows/ci.yml",
        ".github/workflows/nightly.yml",
        ".github/workflows/fuzz-nightly.yml",
    ] {
        let derived = parse_names(&run_python(&lane_derivation(lane)));
        assert_eq!(
            derived, expected,
            "{lane}'s derivation does not match fuzz/Cargo.toml"
        );
    }
    // The prose documents name every target.
    for lane in ["fuzz/README.md", "docs/hardening/CORPUS.md"] {
        let text = repo(lane);
        for target in &expected {
            assert!(text.contains(target), "{lane} does not name {target}");
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

#[test]
fn the_local_lane_helper_runs_and_lists_the_manifest_targets() {
    // `--list` starts the module: a helper that uses a name it never imported
    // dies here with `NameError` before any container starts, which the text
    // checks above cannot see (R-20 round 5, F1).
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new(python())
        .arg("scripts/fuzz_docker.py")
        .arg("--list")
        .current_dir(root)
        .output()
        .expect("run scripts/fuzz_docker.py --list");
    assert!(
        output.status.success(),
        "scripts/fuzz_docker.py --list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let listed = parse_names(&String::from_utf8_lossy(&output.stdout));
    assert_eq!(listed, manifest_targets());
}

/// Drive the shipped `main()` down the container path with `subprocess.run`
/// replaced, so the branch that builds the `docker run` command is executed
/// without Docker. An unimported name or a dropped flag fails here (R-20
/// round 5, F1/F2).
#[test]
fn the_local_lane_builds_a_container_command_for_a_target() {
    let script = r#"
import importlib.util
import pathlib
import sys

path = pathlib.Path("scripts/fuzz_docker.py")
spec = importlib.util.spec_from_file_location("fuzz_docker", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

seen = []


class Result:
    returncode = 0
    stdout = "stat::number_of_executed_units: 1"
    stderr = ""


def fake(cmd, cwd=None, timeout=None, **kwargs):
    seen.append(list(cmd))
    return Result()


module.subprocess.run = fake
sys.argv = ["scripts/fuzz_docker.py", "--target", "fuzz_arp1_frame", "--runs", "1"]
code = module.main()
assert code == 0, code
runs = [cmd for cmd in seen if cmd[:2] == ["docker", "run"]]
assert len(runs) == 1, seen
cmd = runs[0]
joined = " ".join(cmd)
assert module.IMAGE in cmd, cmd
assert "fuzz_arp1_frame" in joined, cmd
assert "-v" in cmd and "/work/fuzz" in cmd, cmd
if module.os.name == "nt":
    assert "--user" not in cmd, cmd
else:
    assert "--user" in cmd, cmd
    assert "CARGO_HOME=/work/fuzz/target/cargo-home" in joined, cmd
    assert "RUSTUP_HOME=/usr/local/rustup" in joined, cmd
print("OK")
"#;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut child = Command::new(python())
        .arg("-")
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn python");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(script.as_bytes())
        .expect("write the harness");
    let output = child.wait_with_output().expect("wait for python");
    assert!(
        output.status.success(),
        "the local lane harness failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Every lane that installs a fuzz or coverage tool pins its version, runs
/// with a read-only token and installs nothing unpinned (R-20 round 4 #4/#6,
/// round 5 F8/F11).
#[test]
fn every_fuzz_lane_pins_its_tools_and_its_token() {
    for lane in [
        ".github/workflows/ci.yml",
        ".github/workflows/nightly.yml",
        ".github/workflows/fuzz-nightly.yml",
    ] {
        let text = repo(lane);
        assert!(
            text.contains("permissions:") && text.contains("contents: read"),
            "{lane} does not pin the job token to read-only"
        );
        assert!(
            !text.contains("contents: write") && !text.contains("write-all"),
            "{lane} grants a write scope"
        );
        // A pinned string in a comment while a second, unpinned `cargo install`
        // does the work passed the earlier `contains` check (F8).
        let installs: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|line| line.contains("cargo install"))
            .collect();
        assert!(!installs.is_empty(), "{lane} installs no tool");
        for line in installs {
            assert!(
                line.contains("--version"),
                "{lane} installs a tool without a pinned version: {line}"
            );
            assert!(
                line.contains("--locked"),
                "{lane} installs a tool without --locked: {line}"
            );
        }
        for action in text
            .lines()
            .filter(|line| line.contains("dtolnay/rust-toolchain@"))
        {
            let reference = action
                .split("dtolnay/rust-toolchain@")
                .nth(1)
                .expect("reference")
                .split_whitespace()
                .next()
                .expect("reference");
            assert!(
                reference.len() == 40 && reference.chars().all(|ch| ch.is_ascii_hexdigit()),
                "{lane} uses a moving toolchain ref: {reference}"
            );
        }
    }
}

/// Every target asserts a fixed positive control before it touches the fuzzed
/// input, and the control asserts an outcome rather than merely naming itself:
/// a comment over dead code satisfied the earlier form (R-20 round 5, F7).
#[test]
fn every_target_asserts_a_fixed_control_before_its_input() {
    for target in manifest_targets() {
        let source = fs::read_to_string(fuzz_targets().join(format!("{target}.rs")))
            .unwrap_or_else(|error| panic!("{target}: {error}"));
        let marker = source
            .to_lowercase()
            .find("positive control")
            .unwrap_or_else(|| panic!("{target} has no fixed positive control"));
        let guard = source.find("if data.is_empty()").unwrap_or(source.len());
        assert!(
            marker < guard,
            "{target} runs its positive control after the empty-input guard"
        );
        let region = &source[marker..guard];
        assert!(
            region.contains("assert") || region.contains("expect("),
            "{target}'s control does not assert an outcome"
        );
    }
}
