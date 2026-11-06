//! R-12 replay, confirmation round 2: the CLI gates on the library's package
//! ceiling, refuses to replace an existing artifact by accident, and validates
//! every flag it accepts.

use std::io::Write;
use std::process::{Command, Output};

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_active-rpc-cli"))
}

fn run(args: &[&str]) -> Output {
    cli().args(args).output().expect("spawn cli")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A fresh temporary directory per test.
fn sandbox(name: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("active-rpc-cli-r12-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("sandbox");
    dir
}

/// `replay dump` writes an evidence artifact; the default path makes an
/// accidental replacement likely, so replacing takes `--force`.
#[test]
fn replay_dump_refuses_to_overwrite_without_force() {
    let dir = sandbox("overwrite");
    let path = dir.join("session.arrp");
    let path = path.to_str().expect("utf8");

    let first = run(&["replay", "dump", "--output", path]);
    assert_eq!(first.status.code(), Some(0), "{}", stderr(&first));

    let second = run(&["replay", "dump", "--output", path]);
    assert_eq!(second.status.code(), Some(1), "{}", stderr(&second));
    assert!(
        stderr(&second).contains("--force"),
        "the refusal names the way through: {}",
        stderr(&second)
    );

    let forced = run(&["replay", "dump", "--output", path, "--force"]);
    assert_eq!(forced.status.code(), Some(0), "{}", stderr(&forced));
    assert!(stdout(&forced).contains("ops="));

    // A flag that takes a boolean is validated, not ignored.
    let garbage = run(&["replay", "dump", "--output", path, "--force=garbage"]);
    assert_eq!(garbage.status.code(), Some(2), "{}", stderr(&garbage));

    let _ = std::fs::remove_dir_all(&dir);
}

/// `--emit-cap-hex` belongs to the commands that print a capability; `replay
/// dump` never read it, so accepting it meant accepting a typo.
#[test]
fn replay_dump_rejects_the_capability_flag() {
    let dir = sandbox("cap-flag");
    let path = dir.join("session.arrp");
    let output = run(&[
        "replay",
        "dump",
        "--output",
        path.to_str().expect("utf8"),
        "--emit-cap-hex",
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("unknown option"),
        "{}",
        stderr(&output)
    );
    assert!(!path.exists(), "a rejected invocation wrote an artifact");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A package over the ceiling is refused (exit 1), like a damaged one. The
/// ceiling is the library's constant, so the CLI and the format cannot drift.
#[test]
fn an_oversize_package_is_refused_not_usage() {
    let dir = sandbox("oversize");
    let path = dir.join("huge.arrp");
    {
        let file = std::fs::File::create(&path).expect("create");
        file.set_len(active_rpc::replay::MAX_PACKAGE_BYTES as u64 + 1)
            .expect("extend");
        // One real byte, so the sparse file is not all that the length says.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open");
        file.write_all(b"ARRP").expect("write");
    }
    let output = run(&["replay", "run", path.to_str().expect("utf8")]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("ceiling"),
        "the message names the ceiling: {}",
        stderr(&output)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A missing package is still a usage error: the command line named a file that
/// is not there.
#[test]
fn a_missing_package_is_usage() {
    let output = run(&["replay", "run", "no-such-package.arrp"]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
}

/// The dump writes beside the destination and renames, so an interrupted write
/// cannot leave a truncated artifact and a successful one leaves nothing
/// behind.
#[test]
fn replay_dump_leaves_no_temporary_files() {
    let dir = sandbox("temporaries");
    let path = dir.join("session.arrp");
    let output = run(&["replay", "dump", "--output", path.to_str().expect("utf8")]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let leftovers: Vec<String> = std::fs::read_dir(&dir)
        .expect("dir")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".tmp-"))
        .collect();
    assert!(leftovers.is_empty(), "temporary files left: {leftovers:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--force` replaces the *destination*, not what a symlink there points at: the
/// rename is atomic and does not open the link.
#[cfg(unix)]
#[test]
fn replay_dump_replaces_a_destination_symlink_not_its_target() {
    let dir = sandbox("symlink");
    let victim = dir.join("victim.txt");
    std::fs::write(&victim, b"do not touch").expect("victim");
    let path = dir.join("session.arrp");
    std::os::unix::fs::symlink(&victim, &path).expect("symlink");
    let output = run(&[
        "replay",
        "dump",
        "--output",
        path.to_str().expect("utf8"),
        "--force",
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        std::fs::read(&victim).expect("victim"),
        b"do not touch",
        "the symlink target was overwritten"
    );
    let bytes = std::fs::read(&path).expect("package");
    assert_eq!(&bytes[..4], b"ARRP");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A destination that exists but is empty is still evidence the operator made:
/// it is refused without `--force` (R-12 round 5, L-5).
#[test]
fn replay_dump_refuses_an_empty_destination_without_force() {
    let dir = sandbox("empty-destination");
    let path = dir.join("session.arrp");
    std::fs::write(&path, b"").expect("plant an empty file");

    let refused = run(&["replay", "dump", "--output", path.to_str().expect("utf8")]);
    assert_eq!(refused.status.code(), Some(1), "{}", stderr(&refused));
    assert!(stderr(&refused).contains("--force"), "{}", stderr(&refused));
    assert_eq!(
        std::fs::metadata(&path).expect("the file stays").len(),
        0,
        "the refusal wrote over it"
    );

    let forced = run(&[
        "replay",
        "dump",
        "--output",
        path.to_str().expect("utf8"),
        "--force",
    ]);
    assert_eq!(forced.status.code(), Some(0), "{}", stderr(&forced));
    assert!(std::fs::metadata(&path).expect("written").len() > 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A dumped package always runs: the CLI replays before writing
/// (R-12 round 5, L-6).
#[test]
fn a_dumped_package_always_replays() {
    let dir = sandbox("dump-replays");
    let path = dir.join("session.arrp");
    let path = path.to_str().expect("utf8");
    let dump = run(&["replay", "dump", "--output", path]);
    assert_eq!(dump.status.code(), Some(0), "{}", stderr(&dump));
    let replay = run(&["replay", "run", path]);
    assert_eq!(replay.status.code(), Some(0), "{}", stderr(&replay));
    let _ = std::fs::remove_dir_all(&dir);
}
