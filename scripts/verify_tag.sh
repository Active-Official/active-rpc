#!/usr/bin/env bash
# Verify a release tag's SSH signature against the committed signers file.
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: scripts/verify_tag.sh <tag>" >&2
    exit 2
fi

tag="$1"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if [ ! -f release-signing.allowed_signers ]; then
    echo "missing release-signing.allowed_signers" >&2
    exit 1
fi

git -c gpg.ssh.allowedSignersFile=release-signing.allowed_signers tag -v "$tag"
echo "verified $tag"
