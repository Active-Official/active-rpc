# 32-bit lane: parser and wire arithmetic must be correct on i686 too.
# A 64-bit-only test suite misses sign-extension and width bugs (CVE-2026-116734
# and CVE-2021-32629 are the motivating classes).
FROM rust:1.88.0-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc-multilib libc6-dev-i386 \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add i686-unknown-linux-gnu

ENV PATH="/usr/local/cargo/bin:${PATH}"
WORKDIR /work

