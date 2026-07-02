# Codebase Summary

Directory-by-directory map of `commit0-analyzer`. Module path:
`github.com/commit0-dev/commit0-analyzer` (Go 1.26.4).

**Scale:** `internal/` ~47.2K LOC · JS plugin ~17.5K · Rust plugin ~2.9K · Go
plugin ~2.4K · Python plugin ~1.7K · `pkg/` ~2.1K · `proto/` ~357 lines.

For architecture and data flow, see
[`docs/system-architecture.md`](./system-architecture.md). For coding
conventions, see [`docs/code-standards.md`](./code-standards.md).

## Top level

| Path | Purpose |
|---|---|
| `cmd/commit0-analyzer/` | CLI entry point — flag parsing and wiring only; all scan logic lives in `internal/`. |
| `internal/` | Private application code: CLI orchestration, advisory intelligence, plugin host, rendering, VEX, policy, corpus, telemetry. |
| `pkg/` | Public-surface packages: the versioned plugin contract and shared plugin handshake. |
| `proto/commit0/v1/` | `plugin.proto` — source of truth for the host↔plugin wire contract. |
| `plugins/` | In-tree reachability plugin implementations (go, rust, python, js). |
| `docs/` | Product, architecture, and usage documentation (this directory). |
| `plans/` | Per-feature planning history (see `docs/project-roadmap.md` for a distilled timeline). |
| `Makefile` | `generate`, `build`, `test`, `lint`, `vet`, `tidy`, `clean`, `hooks`, `build-js-plugin`, `test-js`. |
| `lefthook.yml` | Git hooks: `commit-msg` (Conventional Commits), `pre-push` (`golangci-lint run`, `go build ./...`). |
| `.github/workflows/ci.yml` | The only CI workflow — see [`docs/system-architecture.md`](./system-architecture.md#ci-pipeline). |

## `cmd/commit0-analyzer/`

Single Cobra binary, one subcommand: `scan [path]` (default `.`). `main.go`
runs `os.Exit(policy.RunWithRecovery(cli.Run))` so a panic during a scan exits
`3` rather than crashing uncaught.

## `internal/cli/` — CLI & scan orchestration

- `scan.go` — the scan orchestrator (large file); defines the `scan` command,
  every flag, and `runScan`'s end-to-end pipeline: ecosystem detection →
  dependency install → advisory resolution → plugin dispatch → severity/risk
  stamping → render → VEX → policy gate.
- `ecosystem_registry.go` — the single `EcosystemAdapter` registry (populated at
  init via `RegisterEcosystemAdapter`). One entry per supported ecosystem carries
  its detection files, `--language` value, `MaxConfidence` ceiling, and (for
  lockfile-static ecosystems) a `ParseLockfile` resolver. It is the one taxonomy
  for detection, `--language` validation, and advisory resolution — adding a
  lockfile-static ecosystem is one entry plus a version comparator, with no
  per-language `switch` to touch.
- `ecosystem_maven.go`, `ecosystem_nuget.go`, `ecosystem_packagist.go`,
  `ecosystem_rubygems.go`, `ecosystem_hex.go`, `ecosystem_pub.go`,
  `ecosystem_swift.go` — one lockfile-static adapter per ecosystem (Maven/JVM,
  NuGet/.NET, Packagist/PHP, RubyGems/Ruby, Hex/Elixir, Pub/Dart, SwiftPM/Swift).
  Each sets `ParseLockfile` and parses only the lockfile — manifests (`pom.xml`,
  `*.csproj`, `Gemfile`, `mix.exs`, `Package.swift`) are read for
  direct-dependency hints only and are never executed. `MaxConfidence` is the
  package-level ceiling.
- Plugin-backed ecosystems — Go, JS/TS, Rust, Python — appear in the same
  registry with `ParseLockfile` nil and a `SYMBOL_REACHABLE` ceiling; the
  `scan.go` orchestrator dispatches them to `internal/host` for call-graph
  reachability instead of parsing a lockfile.

## `internal/advisory/` — advisory intelligence (85 files)

- `source.go` + `govulndb.go`/`fetcher.go`, `osv.go`, `ghsa_source.go`,
  `gitlab_source.go`, `nvd.go` — the five advisory sources, composed through
  `MultiSource`/`NamedSource{Name,S,Trust}`.
- `merge.go`, `conflict.go` — alias-equivalence dedup and fail-safe conflict
  resolution across sources (see
  [`docs/system-architecture.md`](./system-architecture.md) for the merge
  rules).
- `enrichment.go`, `cvss.go` — the enrichment chain: CVSS scoring, NVD
  CVSS/CWE join, CISA KEV, FIRST EPSS, CWE normalization.
- `risk.go` — pure, deterministic 0-100 risk fusion
  (`CVSS×10×reachMult + EPSS×10`, KEV boost, `NOT_REACHABLE`→0).
- `comparator_registry.go` + one comparator file per ecosystem (`semver.go`,
  `npm_semver.go`, `cargo_semver.go`, `pep440.go`, `maven_version.go`,
  `nuget_version.go`, `composer_version.go`, `rubygems_version.go`,
  `hex_version.go`, `pub_version.go`, `swift_version.go`) — tri-state
  `ComparatorFunc` returning `VersionAffected | VersionNotAffected |
  VersionUndecidable`; a parse error or unregistered ecosystem always
  resolves to `Undecidable`, never `NotAffected`. Duplicate registration
  panics.
- `cache.go` — singleflight-guarded, atomic-write (temp→fsync→rename),
  cross-process-locked disk cache with SHA-256 manifest verification, zip/tar
  guards (10MiB/file, 1GiB total, path-traversal rejection), snapshot pinning,
  offline mode, and staleness warnings.
- `doc.go` — package-level doc comment. **Known documentation gap:** this
  comment still describes the package as "MVP Scope: Go Vulnerability
  Database Only" with multi-source resolution framed as a future roadmap
  item. The package is in fact the full multi-source, multi-ecosystem
  advisory layer described above; the comment was not updated as sources were
  added. Flagged here for a future code change, not corrected in this pass.
- `ghfetch/` — fetches fix-commit diffs from GitHub for symbol extraction;
  degrades gracefully for non-GitHub forges.
- `symbolextract/` — extracts vulnerable symbols from advisory fix patches via
  a plugin's `--extract-symbols` subcommand.
- `symbolindex/` — persisted, offline-safe symbol `Resolver` (index → ghfetch →
  extract).
- `parity/` — the precision/recall and coverage-gain harness against
  `osv-scanner`/`grype`/`trivy`/`govulncheck`; suppression counts only ever
  credit a `NOT_REACHABLE` proof, never an unmatched advisory. Reports under
  `internal/advisory/parity/reports/`.

Key public types: `Advisory`, `Package`, `Severity`, `VersionRange`,
`CVSSMetric`, `EPSSScore`, `KEVEntry`, `RiskScore`, `SourceContribution`,
`VersionVerdict`.

## `internal/host/` — plugin host

- `registry.go` — the explicit plugin allowlist (no PATH or conventional-path
  discovery); rejects relative paths, non-regular files, and world-writable
  path components (TOCTOU guard, sticky-bit exempt).
- `client.go` — go-plugin handshake (magic cookie + protocol-version check),
  SHA-256 artifact pinning via `SecureConfig`, and a metadata self-test
  (rejects a plugin whose `Metadata.Name` is empty).
- `run.go` — `Analyze` fan-out: concurrent dispatch bounded by a semaphore,
  per-plugin `context.WithTimeout`, `defer Kill()` (no zombie processes).
  Launch/RPC/receive errors keep any partial findings already streamed and
  append a synthetic `CONFIDENCE_UNKNOWN` finding
  (`properties{synthetic:true,cause,plugin}`) rather than dropping coverage.
  Results are sorted by plugin name for determinism.
- `manifest.go` — plugin manifest structure (main binary hash + additional
  artifact hashes, e.g. the JS plugin's oxc `.node` sidecar).

## `pkg/contract/` — versioned plugin contract

- `version.go` — `ProtocolMajor`/`ProtocolMinor` and the compatibility rule
  (`plugin.Major == host.Major && plugin.Minor <= host.Minor`).
- `finding.go` — `FindingWrapper.IsSuppressible()`, the single point in the
  codebase that decides a finding may be suppressed (true only for
  `NOT_REACHABLE`).
- `doc.go` — contract package documentation.
- `commit0v1/` — **generated** gRPC/protobuf stubs from `proto/commit0/v1/`
  (via `make generate` / `buf generate`). Excluded from lint; never
  hand-edited.

## `pkg/plugin/` — shared plugin handshake

Magic cookie (`commit0-analyzer-v0-plugin`) and protocol-version constants
shared by the host and every plugin binary — a UX guard against accidentally
launching an unrelated executable, not the integrity mechanism (SHA-256
pinning in `internal/host/manifest.go` is).

## `proto/commit0/v1/plugin.proto`

Source of truth for the wire contract. Defines the `Analyzer` gRPC service
(`Metadata` unary RPC, `Analyze` server-streaming RPC), `AnalyzeRequest`
(`module_root`, `entrypoints`, `build_config`, `advisories`,
`ecosystem_build_config`), `Advisory`, and `Finding` (designed to lower
directly into SARIF 2.1, with `codeFlows` omitted when no call path exists).

## `plugins/` — reachability plugin implementations

| Plugin | Language | Technique | Notes |
|---|---|---|---|
| `go-reachability/` | Go | `x/tools` SSA + VTA on a CHA/RTA base graph, BFS from entry points to the vulnerable symbol | Reflection/address-taken calls degrade to `UNKNOWN`; SSA generics panics are recovered and degrade to sound import-level analysis. Includes a `cmd/standalone` debug binary with an `--algorithm rta` fallback. |
| `rust-reachability/` | Go (shells to `cargo metadata`) | Dependency-closure membership only, no call graph | `NOT_REACHABLE` only when a crate is wholly absent from the resolved closure; proc-macros, `dyn` dispatch, and `build.rs` involvement degrade to `UNKNOWN`; dev-only crates are tagged `dev_only`. |
| `python-reachability/` | Go host + embedded Python sidecar | Demand-driven AST call graph, stdlib-only sidecar | `NOT_REACHABLE` requires the distribution to be absent, a complete call graph, and import provenance from static analysis; `eval`/`getattr`-style dynamism degrades to `UNKNOWN`; parse failures are isolated in a worker pool. |
| `js-reachability/` | TypeScript, compiled with Bun; oxc parser sidecar | Demand-driven, flow-insensitive call graph into third-party source, fidelity-gated | Minified code, types-only packages, and dynamic imports widen the analysis frontier to `UNKNOWN`; size/line guards run before invoking oxc; parsing is isolated in a worker process. Subcommands: `serve`, `--list-deps`, `--analyze`, `--project-model`, `--extract-symbols`, `--parse-worker`. |

All four plugins implement an identical `commit0v1.Analyzer` gRPC surface and
mirror the same confidence-decision logic independently per language: Go
`confidence.go`, JS `confidence.ts`, Python `cg/confidence.py`, Rust
`engine/analyze.go`.

## `internal/render/` — output renderers

Three deterministic renderers (byte-identical output for identical input;
golden-file tests use an `-update` flag to regenerate fixtures):

- `sarif.go` — SARIF 2.1.0. `codeFlows` is emitted only when at least one
  `CallStep` exists (an empty `threadFlow` is schema-invalid and GitHub
  rejects the upload). `NOT_REACHABLE` findings become SARIF *suppressed*
  results (kind `external`, `accepted`, with justification) rather than being
  omitted — auditable, not dropped. `risk_score` is promoted to SARIF `rank`.
  A vendored `schema/sarif-schema-2.1.0.json` validates output at test time.
- `json.go` — stable JSON schema; risk fields (`score`, `tier`, `rationale`,
  `cvss`, `epss`, `kev`, `cwe`) and provenance are typed fields, not free-form
  properties.
- `table.go` — human-readable TTY table
  (`ADVISORY|SEVERITY|CONFIDENCE|RISK|MODULE|ENTRY POINT`) plus a call-path
  tree for symbol-reachable findings.

## `internal/vex/` — VEX emitters

One internal status model, three formatters selected by `--vex
openvex|cyclonedx|csaf|all`:

- `openvex.go` (OpenVEX v0.2.0), `cyclonedx.go` (CycloneDX 1.5,
  `code_not_reachable`), `csaf.go` (CSAF 2.0 `csaf_vex`, product-status
  groups).
- `MapStatus` is the cardinal-sin guard: reachable → `affected`;
  `NOT_REACHABLE` **and complete** → `not_affected`
  (`vulnerable_code_not_in_execute_path`); incomplete `NOT_REACHABLE` or
  `UNKNOWN` → `under_investigation`.
- Deterministic by construction: document IDs are content-SHA-256, no
  `time.Now()`/random UUID generation inside the emitters (timestamps are
  injected by the caller).
- `PackageURL()` produces purls for all eleven ecosystems.

## `internal/policy/` — the gate

- `policy.go` — `EvaluateWithFlags`: skip non-gate-eligible findings → skip
  ignored findings → gate if the finding meets the confidence/severity
  threshold or matches an additive predicate. `NOT_REACHABLE` never gates.
  `dev`/`test`/`optional` dependency types don't gate by default (a missing
  `dep_type` conservatively defaults to `runtime`).
- `exit.go` — the exit-code contract and precedence: gate failure (`1`)
  outranks incomplete (`3`) outranks clean pass (`0`).
- Ignore rules: exact `(advisory, module[, symbol])` tuples only — no
  wildcards — with a mandatory `reason` and a bounded `expires-at` (an
  expired entry fails closed, i.e. the finding is **not** suppressed).
  Suppressing a `SYMBOL_REACHABLE CRITICAL` finding requires an explicit
  `elevated-ignore: true`. Ignored findings still render as suppressed in
  SARIF, never as absent.

## `internal/corpus/` — precision/recall harness

Runs labeled fixtures through the real host → plugin pipeline and classifies
outcomes as TP/FP/FN/TN plus `UnknownViolation` (a definitive verdict where
`UNKNOWN` was the correct/expected answer — treated as the most dangerous
class of miss, since it represents overconfidence). A baseline JSON pins the
analyzer's own numbers, regenerated via `--regen-baseline`; `govulncheck`
results are recorded as provenance context only, not as ground truth.

## `internal/telemetry/` — phase timing

Stderr phase-timing instrumentation, gated on `COMMIT0_DEBUG` or
`COMMIT0_TELEMETRY`; a no-op otherwise.

## Build, CI, and tooling

- **`Makefile`** — `generate` (buf-regenerate Go + TS protobuf stubs),
  `build` (JS plugin via Bun, warns-and-skips if Bun absent, then `go build
  ./...`), `build-js-plugin` (maps the oxc-parser npm binding filename to
  Go's `GOOS-GOARCH` naming so the host finds the sidecar deterministically),
  `test` (vitest, Node-gated, then `go test ./...`), `lint` (golangci-lint
  v2, falls back to `go vet` if not installed), `tidy`, `clean`, `hooks`
  (installs lefthook).
- **`.github/workflows/ci.yml`** (the only workflow) — a `changes` job
  path-filters which heavy jobs run; `proto` job checks for generated-stub
  drift (`buf generate` + `git diff`); `build-test` runs `go vet`, `go test`
  (`-race` on `main` only), and `golangci-lint`; `js-test` runs `tsc` +
  `vitest` + the corpus harness plus a non-blocking Jelly cross-check;
  `js-e2e` runs plugin + host integration tests; a `ci` aggregate job is the
  single required status check.
- **`lefthook.yml`** — `commit-msg` enforces Conventional Commits;
  `pre-push` runs `golangci-lint run --timeout=5m` and `go build ./...` in
  parallel.
- **`buf`** (v2) — `STANDARD` lint, `FILE` breaking-change detection;
  `buf.gen.yaml` generates the Go stubs (`pkg/contract/commit0v1`, lint-
  excluded, never hand-edited); `buf.gen.js.yaml` generates the TypeScript
  stubs (`plugins/js-reachability/src/gen`, same rule).
- **Distribution** — `go install
  github.com/commit0-dev/commit0-analyzer/cmd/commit0-analyzer@latest`; no
  binary release workflow exists yet (tracked in
  [`docs/project-roadmap.md`](./project-roadmap.md)).

## Existing docs (reference, not duplicated here)

- [`README.md`](../README.md) — product pitch, quick start, ecosystem table,
  comparison table, `unknown ≠ safe` promise.
- [`docs/usage.md`](./usage.md) — every CLI flag and environment variable,
  with examples.
- [`docs/soundness-limits.md`](./soundness-limits.md) — the full soundness
  model, per-ecosystem reachability ceilings, and measured coverage numbers.
