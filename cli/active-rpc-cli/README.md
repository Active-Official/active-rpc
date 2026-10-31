# active-rpc-cli

Production command-line surface for Active RPC. Every command drives the real
capability kernel and the real transport stack: peers mint capabilities, calls
travel as native ARP1 envelopes, and refusals surface their stable `rpc/...`
codes.

## Synopsis

```text
active-rpc-cli <command> [options]

  doctor
  peer [--transport tcp|http2|connect|quic] [--limit N] [--methods echo,sum]
       [--cert-out PATH]
  call --addr HOST:PORT [--transport ...] [--cap HEX] [--method M]
       [--payload FILE | --text TEXT] [--cert FILE]
  pipeline --addr HOST:PORT --cap HEX [--calls N] [--method M] [--payload FILE]
  loadgen --addr HOST:PORT --cap HEX [--requests N] [--concurrency C]
          [--method M] [--payload FILE]
  bridge [--limit N]
  events [--plane URL] [--after ID] [--follow] [--interval-ms N]
  replay dump [--output PATH]
  replay run <package>
  help
```

`peer` prints three lines on stdout, then serves:

```text
transport=tcp
addr=127.0.0.1:54321
cap=92fbe408998a14afb774f7455a6911f9
```

For `quic` it adds a `cert=PATH` line: the self-signed certificate the client
must trust with `--cert`.

## Commands

| Command | Behavior |
|---------|----------|
| `doctor` | Version, transports, compiled features, budget defaults and exit codes. |
| `peer` | Real kernel peer with one minted capability. `--limit` is connections for tcp/http2, requests for connect, calls for quic. |
| `call` | One call. Prints `kind`, `id`, `payload` length and the decoded value; an error envelope exits `1`. |
| `pipeline` | Sends N calls on one connection before reading any response, then reports `round_trips=1`. |
| `loadgen` | C connections, N requests, real latency percentiles and throughput. Respects the capability budget. |
| `bridge` | Serves the Connect/gRPC interop adapter against the demo kernel. |
| `events` | Tails the control-plane event stream; events carry correlation ids, never raw authority. |
| `replay dump` | Records a deterministic demo session (mint, calls, a refusal, a TTL expiry, a revocation) as an `ARRP` package. |
| `replay run` | Re-executes a package against a fresh kernel and compares every decision; a tampered or divergent package exits `1`. |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success. |
| `1` | Refusal or a failed request (`rpc/method-not-granted`, `rpc/unknown-capability`, ...). |
| `2` | Usage error. |
| `3` | Transport or codec failure (connect, handshake, frame). |

## Examples

```bash
# Start a peer and capture its address and capability
active-rpc-cli peer --limit 4 > peer.txt
ADDR=$(awk -F= '/^addr=/{print $2}' peer.txt)
CAP=$(awk -F= '/^cap=/{print $2}' peer.txt)

# One call, then a deliberate refusal
active-rpc-cli call --addr "$ADDR" --cap "$CAP" --method echo --text hello
active-rpc-cli call --addr "$ADDR" --cap "$CAP" --method refuse

# Pipelining and load
active-rpc-cli pipeline --addr "$ADDR" --cap "$CAP" --calls 16
active-rpc-cli loadgen --addr "$ADDR" --cap "$CAP" --requests 200 --concurrency 8

# Interop bridge and event tail
active-rpc-cli bridge --limit 2
active-rpc-cli events --plane http://127.0.0.1:8787 --follow

# Record a session and verify it replays identically
active-rpc-cli replay dump --output session.arrp
active-rpc-cli replay run session.arrp
```

## Notes

- Interop transports (`connect`, `http2`) are adapters. Native ARP1 over TCP is
  the baseline; QUIC and HTTP/2 exist for environments that need them.
- The QUIC peer exits after `--limit` calls and drains the last response before
  closing. The library's own QUIC tests cover mutual TLS and identity binding;
  the CLI uses the self-signed demo mode.
- Capabilities print as opaque ids. The CLI never prints authority bits or
  secret material.
