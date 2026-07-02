# commit0-analyzer — Product Overview & PDR

## Problem

Software Composition Analysis (SCA) tools report every known CVE in a dependency
closure regardless of whether the vulnerable code path is ever executed. Teams
drown in advisory noise: a lockfile-only match on a transitive dependency that is
installed but never imported carries the same visual weight as a genuinely
exploitable vulnerability. The result is alert fatigue — real risk gets lost in a
sea of theoretical matches, and security teams either over-triage manually or
tune out the scanner entirely.

`commit0-analyzer` addresses this by tracing a real call path from application
entry points into the vulnerable symbol. A CVE in a package that is present in
the lockfile but never reached is *proven* harmless (VEX `not_affected`) instead
of cluttering the findings list — but only when that proof is sound. An unproven
result is never mistaken for a safe one.

## Persona

- **CI/CD and platform engineers** wiring a security gate into a build pipeline
  who need a single command, deterministic exit codes, and machine-readable
  output (SARIF for GitHub code scanning, VEX for downstream tooling).
- **Application security engineers** triaging findings across a polyglot
  monorepo who need call-path evidence to justify a suppression, not a
  spreadsheet of CVE IDs to research by hand.
- **Open-source maintainers** who want a scanner that respects licensing
  boundaries around advisory data redistribution (see Non-Goals) and can run
  fully offline in air-gapped CI.

## Cardinal Invariant

**`unknown ≠ safe`.** Any advisory whose reachability the analyzer cannot prove
— a build failure, a timeout, a plugin crash, a stale advisory fetch, an
undecidable version comparison — degrades to `CONFIDENCE_UNKNOWN` and counts
toward the policy gate by default. It is never silently dropped and never
mapped to a "safe" verdict. The cardinal failure mode this product must never
produce is a false `NOT_REACHABLE` or a false-clean exit `0`.

## Product Requirements

### Functional

- **Reachability with proof.** Every finding resolves to one of four confidence
  tiers — `SYMBOL_REACHABLE`, `PACKAGE_REACHABLE`, `NOT_REACHABLE`, `UNKNOWN`
  — and a `SYMBOL_REACHABLE` finding carries a SARIF `codeFlows` call path that
  can be audited, not just asserted. See
  [`docs/system-architecture.md`](./system-architecture.md) for the full tier
  semantics.
- **Eleven-ecosystem coverage from one binary.** Go, JavaScript/TypeScript,
  Rust, Python, JVM (Java/Kotlin/Scala), .NET, PHP, Ruby, Elixir/Erlang, Dart,
  and Swift, auto-detected in a single `scan` invocation, including polyglot
  monorepos. Four ecosystems (Go, JS/TS, Rust, Python) get plugin-backed call
  graph or dependency-graph reachability; the remaining seven get
  lockfile-static package-level reachability. See the ecosystem table in
  [`README.md`](../README.md#supported-ecosystems).
- **Multi-source advisory intelligence.** Advisories are merged and
  deduplicated across the Go vulnerability database, OSV.dev, GHSA, and
  GitLab's gemnasium-db, then enriched with CVSS, CISA KEV, EPSS, and CWE into
  one deterministic, explainable risk score (0-100).
- **VEX and SARIF output.** `--format sarif|json|table` for findings;
  `--vex openvex|cyclonedx|csaf|all` for exploitability exchange documents. VEX
  status mapping is a cardinal soundness contract (`NOT_REACHABLE` + complete
  → `not_affected`; anything unproven → `under_investigation`; never a false
  `not_affected`).
- **A CI-native exit-code contract.** `0` clean, `1` policy gate violation, `3`
  incomplete/operational error — code `2` is intentionally reserved to avoid
  collision with `govulncheck`/Go-runtime-panic exit codes. Exit `0` always
  means "scan completed and policy-clean," never "scan incomplete, assumed
  safe."
- **A configurable policy gate.** Severity floor (`--fail-on`), confidence
  floor (`--gate-on reachable|reachable+unknown|all`), additive risk
  predicates (`kev`, `epss>=X`, `risk>=Y`), and an ignore-rules file with
  mandatory reason + expiry (no wildcard suppression). Full flag reference:
  [`docs/usage.md`](./usage.md).
- **Offline and air-gapped operation.** `--offline` and `--db-snapshot` support
  reproducible, network-free scans with byte-identical output across runs
  against the same pinned snapshot.

### Non-Functional

- **Determinism.** Renderers (SARIF/JSON/table) and VEX emitters are pure
  functions of their input — no `time.Now()`, no random UUIDs in output — so
  two scans of the same input produce byte-identical documents.
- **Performance budget.** Target ≤ 1.5× `govulncheck` wall-clock on a ~50k-LOC
  Go module (warm cache, same machine); see the Performance section of
  [`docs/usage.md`](./usage.md#performance).
- **Fail-closed data boundary.** A crashed plugin process, a timed-out
  analysis, or a failed advisory fetch is caught and converted into a
  synthetic `CONFIDENCE_UNKNOWN` finding or an incomplete-scan exit — coverage
  is never silently dropped.
- **Trust boundary for plugins.** Reachability plugins are loaded only from an
  explicit allowlist with SHA-256 artifact pinning (no PATH/conventional-path
  discovery). See [`docs/system-architecture.md`](./system-architecture.md).
- **ACE safety.** Neither the host nor any lockfile-static ecosystem adapter ever
  executes a project's manifest, build script, or install hook to determine
  reachability; where dependency installation runs, lifecycle scripts are
  always disabled.

## Non-Goals

- **No advisory data redistribution.** `commit0-analyzer` fetches and caches a
  user's own copy of advisory data (Go vuln DB, OSV, GHSA, GitLab); it never
  bundles or redistributes that data as part of the product, for licensing
  reasons. GitLab's advisory source defaults to the MIT-licensed community
  mirror rather than the primary gemnasium-db for the same reason.
  `internal/advisory/parity/` — the comparator harness — likewise does not
  redistribute comparator output.
- **Not a runtime agent.** The tool performs static analysis only. It never
  instruments, hooks, or observes a running process; reachability is always a
  static call-graph or dependency-graph proof, never a runtime trace.
- **No general vulnerability database.** commit0-analyzer does not maintain
  its own advisory corpus; it is a fetch-merge-enrich-and-reason layer over
  existing public sources.
- **Out of scope ecosystems.** C/C++ (no manifest-based dependency model to
  anchor on) is explicitly out of scope; see
  [`docs/project-roadmap.md`](./project-roadmap.md) for other deferred
  ecosystem work (Java/JVM call-graph reachability, Rust symbol-level analysis,
  Swift advisory-source decision).

## Success Criteria

- **Precision/recall against a labeled corpus.** The `internal/corpus/`
  harness runs real fixtures through the full host → plugin pipeline and
  classifies outcomes as TP/FP/FN/TN plus `UnknownViolation` (a definitive
  verdict where `UNKNOWN` was the correct answer — the most dangerous class of
  miss). A JSON baseline pins the analyzer's own numbers
  (`--regen-baseline`); comparator tools (`govulncheck`, etc.) are recorded as
  provenance context, not as a pass/fail oracle.
- **Determinism and fail-closed behavior are measured, not assumed.** The
  parity/quality harness in `internal/advisory/parity/` records, per corpus
  entry: false-positive/false-negative deltas against comparator scanners,
  determinism (byte-identical re-runs), and fail-closed behavior under an
  injected source-fetch failure. See
  [`docs/soundness-limits.md`](./soundness-limits.md) for the currently
  recorded numbers — coverage claims in these docs are sourced only from that
  harness's reports, never asserted.
- **Every scan resolves to an honest exit code.** No test, corpus entry, or
  real-world scan may reach exit `0` while a finding is unproven and
  gate-eligible; this is enforced by the policy gate ordering (gate failure
  `1` outranks incomplete `3` outranks clean `0`).

## Current Status

- **Plugin contract:** `v0-PROVISIONAL` (`pkg/contract/version.go`,
  `ProtocolMajor=0`). The wire contract between host and reachability plugins
  is not yet frozen at v1; see
  [`docs/project-roadmap.md`](./project-roadmap.md) for the contract-freeze
  item.
- **Distribution:** `go install
  github.com/commit0-dev/commit0-analyzer/cmd/commit0-analyzer@latest`; no
  binary release workflow exists yet.
- **License:** GNU AGPL-3.0 — the copyleft keeps the engine and its platform
  surface open and precludes embedding the core as a library in closed-source
  products.
