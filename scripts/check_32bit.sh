#!/usr/bin/env bash
# Run the test suite on i686 in Docker. See docker/32bit.Dockerfile.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
# Git Bash reports /f/... ; Docker Desktop needs a Windows path.
if command -v cygpath >/dev/null 2>&1; then
    docker_root="$(cygpath -w "$root")"
else
    docker_root="$root"
fi
image="${IMAGE:-active-32:1.88}"
features="${FEATURES:---no-default-features}"

MSYS_NO_PATHCONV=1 docker build -t "$image" -f "$docker_root/docker/32bit.Dockerfile" "$docker_root/docker"
MSYS_NO_PATHCONV=1 docker run --rm -v "$docker_root:/work" -w /work "$image" bash -c \
    "export PATH=/usr/local/cargo/bin:\$PATH; cargo test --locked $features --target i686-unknown-linux-gnu"
