# Fuzzing

One target exercises the untrusted framing surface:

- `framing` — envelope decoding (fixed-point re-encode), the standalone
  capability-table codec and the gRPC/Connect frame splitter.

## Running

```bash
cargo install cargo-fuzz --locked
cargo +nightly fuzz run framing -- -runs=200000
```

On Windows MSVC the current cargo-fuzz/libFuzzer combination fails to *launch*
with `STATUS_DLL_NOT_FOUND`; that is an environment limitation, not a target
defect. Use a Linux container:

```bash
docker run --rm -v "$PWD:/work" -w /work rust:1.88-bookworm bash -c \
  "apt-get update -qq && apt-get install -y -qq clang && \
   rustup toolchain install nightly --profile minimal && \
   cargo +nightly install cargo-fuzz --locked && \
   cargo +nightly fuzz run framing -- -runs=20000"
```

## Corpus

Seed with one well-formed envelope so mutations start from a valid frame:

```bash
mkdir -p fuzz/corpus/framing
printf '415250310101000001000000000000000400000070696e67000000000000000000000000' \
  | xxd -r -p > fuzz/corpus/framing/ping.arp1
```

## Invariants asserted by the target

1. `Envelope::decode` is total; a successful decode re-encodes to a fixed point.
2. Decoded envelopes respect `WireLimits`.
3. `decode_capability_table` is total and never accepts a zero ceiling.
4. `grpc_unframe`/`grpc_frame` are self-delimiting and never panic.

A crash or assertion failure is a release blocker.
