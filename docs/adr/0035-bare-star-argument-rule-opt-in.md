# ADR 0035 — A bare `*` argument rule needs an explicit opt-in

**Status:** Accepted 2026-11-10 (RPC-40).

## Context

Round 1, R-08 H7 (AUDIT-REPORT.md:502), verified CONFIRMED by W2: a
`*` prefix rule admits any metachar-free argv. `LocalProcess::permitted`
treats a rule ending in `*` as a prefix, so a bare `"*"` is a prefix of
`""`, and `arg.starts_with("")` is true for every argument. Two proofs:

- The audit's P2-PROC-3: `/bin/echo /etc/passwd` succeeds — for a
  path-taking program (`cat`, `curl`) the wildcard is a grant to read
  arbitrary files.
- W2's Windows equivalent: `LocalProcess::new(cmd.exe, &["*"])` with
  args `["/c", "echo w2-star-marker-42"]` returns `Ok` with the marker
  on stdout — arbitrary command execution through the wildcard plus a
  shell program.

The metacharacter guard (`permitted_by_prefix_only` plus
`SHELL_METACHARACTERS`) does not help: neither `/c` nor
`echo w2-star-marker-42` contains a shell metacharacter, and `cmd /C`
treats the rest of the line as code. The guard can only see syntax;
the attack carries none.

The fix is intentionally breaking: any deployment that today relies on
`"*"` with a path-taking or shell program loses that grant. A silent
change to a refusal would read as a regression to operators, so the
break must be loud — a startup warning plus a migration note — and the
old grant must remain reachable only through an explicit statement.

## Decision

- **A bare `"*"` rule is inert unless the operator opts in.**
  `LocalProcess` gains a public `allow_any_arg: bool` field (default
  `false`) and a `with_allow_any_arg()` builder. `permitted()` skips a
  rule that is exactly `"*"` unless the flag is set, so the rule
  admits no argument on its own. Non-empty prefix rules (`"echo*"`)
  are unaffected by the opt-in.
- **The check runs at invoke time, not only at construction.**
  `allow_args` is a public field, so a rule assigned after
  construction must be bound by the same opt-in. `permitted()` and
  `permitted_by_prefix_only()` both apply it, so the two predicates
  cannot disagree.
- **Construction warns to stderr when a bare `"*"` rule is present.**
  The crate has no logging facade, so the warning goes to stderr at
  construction, where the operator configures the tool. It names the
  program and states the rule's semantics — it admits any argument
  only when `allow_any_arg` is explicitly enabled, and admits nothing
  without it — so a deployment that relied on the wildcard notices the
  change at startup instead of at the first refused call.
- **The metacharacter guard still applies under the opt-in.** An
  argument admitted only through the `"*"` rule that carries shell
  syntax is still refused with `rpc/tool-policy`; the opt-in restores
  the argument grant, not a licence to smuggle a command line.
- **The opt-in is visible in `Debug`.** `LocalProcess`'s hand-written
  `Debug` gains an `allow_any_arg` field, so a deployment log shows
  whether the grant is on.
- **Documented as a breaking change.** `docs/spec/security.md` (the
  "prefix allowlist rule is a command line" row), `docs/spec/wire.md`,
  and `docs/hardening/MIGRATION.md` all state the new rule and the
  migration paths: list the arguments exactly, use a non-empty prefix,
  or opt in explicitly.

Alternatives considered and rejected:

- **Refusing `"*"` at construction.** Breaks compilation of every
  existing `"*"` caller, and does not cover a rule assigned to the
  public `allow_args` field after construction — the invoke-time
  check would still be needed, so this adds a compile break on top
  of the same runtime rule.
- **Requiring exact-match rules for programs that take paths.** The
  adapter cannot know which programs take paths; any classification
  would be a maintained list of program names, wrong the moment a new
  path-taking program appears. The opt-in puts the decision where the
  knowledge is: with the operator who chose the program.
- **A logging-facade warning instead of `eprintln!`.** No facade
  exists in the crate; adding one (a new dependency, a logger
  contract for embedders) for a single startup warning is
  disproportionate. The warning is a deliberate, documented
  exception, confined to construction of a tool configured with the
  dangerous rule.
- **Extending the metacharacter guard instead.** The admitted
  arguments are metachar-free by construction of the attack — that
  is the finding — so no guard extension can see them. The guard
  stays as the second line of defence, not the fix.

## Consequences

- A deployment that relied on `"*"` now gets `rpc/tool-policy`
  refusals instead of a grant, plus a stderr warning at startup.
  The migration is exact rules, a non-empty prefix, or the explicit
  opt-in.
- A shell program with a prefix rule remains a command-line grant —
  for a non-empty prefix, and for an opted-in `"*"`. The opt-in is
  an explicit acceptance of that grant for that program, and the
  metacharacter guard still refuses syntax-bearing arguments
  admitted only through it.
- The warning fires at construction, before a builder call can set
  the opt-in, so it also fires for a deployment that does opt in.
  That is a known wart: the text states the rule's semantics rather
  than claiming the configuration is broken, so it stays true in
  both cases.
- The in-repo tests that used `"*"` as a convenience allowlist now
  opt in explicitly where their purpose is elsewhere, and five new
  tests pin the behaviour: the W2 shape refused without the opt-in,
  the `cat /etc/passwd` shape refused without it (Unix), the W2
  shape admitted with it, shell syntax still refused with it, and a
  non-empty prefix still admitting without it.
- Per `docs/hardening/COMPATIBILITY.md`, a security removal is
  recorded in an ADR (this one) and the release notes; the
  release-notes line is owed at the next release.
