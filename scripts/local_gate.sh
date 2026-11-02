#!/usr/bin/env bash
# The local pre-push gate for Active-RPC.
#
# Runs the CI jobs in one command so a red run is found before the push, not
# after it. Every step is the same command `.github/workflows/ci.yml` runs.
#
# Usage:
#   bash scripts/local_gate.sh            # every gate
#   bash scripts/local_gate.sh --no-msrv  # skip the 1.88 checks (toolchain absent)
#
# The MSRV steps are skipped, with a message, when the 1.88.0 toolchain is not
# installed: they are the ones that catch a newer-than-floor API, so a release
# must run them.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

skip_msrv=0
for argument in "$@"; do
    case "$argument" in
        --no-msrv) skip_msrv=1 ;;
        *) echo "unknown argument: $argument" >&2 && exit 2 ;;
    esac
done

fail=0
summary=()

run() {
    local name="$1"
    shift
    local started=$SECONDS
    if "$@" > /tmp/active-rpc-gate.log 2>&1; then
        summary+=("PASS $name ($((SECONDS - started))s)")
    else
        summary+=("FAIL $name ($((SECONDS - started))s)")
        fail=1
        echo "--- $name ---" >&2
        tail -40 /tmp/active-rpc-gate.log >&2
    fi
}

run "fmt" cargo fmt --all -- --check
run "clippy-all-features" cargo clippy --locked --all-targets --all-features -- -D warnings
run "clippy-no-default" cargo clippy --locked --all-targets --no-default-features -- -D warnings
run "test-all-features" cargo test --locked --all-features
run "test-no-default" cargo test --locked --no-default-features
run "doc" env RUSTDOCFLAGS=-Dwarnings cargo doc --locked --no-deps --all-features
run "bench-compile" cargo bench --locked --benches --no-run
run "fuzz-check" cargo check --locked --manifest-path fuzz/Cargo.toml --bins
run "fuzz-clippy" cargo clippy --locked --manifest-path fuzz/Cargo.toml --bins -- -D warnings
run "control-plane-test" cargo test --locked --manifest-path control-plane/Cargo.toml
run "control-plane-clippy" cargo clippy --locked --manifest-path control-plane/Cargo.toml --all-targets -- -D warnings
run "cli-test" cargo test --locked --manifest-path cli/active-rpc-cli/Cargo.toml
run "cli-clippy" cargo clippy --locked --manifest-path cli/active-rpc-cli/Cargo.toml --all-targets -- -D warnings
run "hardening-status" python scripts/hardening_status.py --check
run "negative-controls" python scripts/negative_controls.py --check

if [ "$skip_msrv" -eq 0 ]; then
    if rustup toolchain list 2>/dev/null | grep -q '^1\.88\.0'; then
        run "msrv-check" cargo +1.88.0 check --locked --all-targets --all-features
        run "msrv-check-no-default" cargo +1.88.0 check --locked --all-targets --no-default-features
    else
        summary+=("SKIP msrv (1.88.0 toolchain not installed; run it on a release)")
    fi
else
    summary+=("SKIP msrv (--no-msrv)")
fi

printf '%s\n' "${summary[@]}"
if [ "$fail" -ne 0 ]; then
    echo "gate: FAILED"
    exit 1
fi
echo "gate: green"
