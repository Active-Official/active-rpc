FROM rust:1.88-bookworm

# libFuzzer runtime comes from clang. The image is deliberately separate from
# the crate build so a fuzz campaign does not depend on the host toolchain.
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang \
    && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly --profile minimal
RUN cargo +nightly install cargo-fuzz --locked

ENV PATH="/usr/local/cargo/bin:${PATH}"
WORKDIR /work
