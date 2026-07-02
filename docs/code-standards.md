# Code Standards

Conventions derived from repo reality (linters, hooks, existing code) and
`CLAUDE.md`. Applies to all new and modified code in `commit0-analyzer`.

## Language & tooling baseline

- **Go 1.26+** (`go.mod` pins `go 1.26.4`). CGO is not required for this
  repo's own build (unlike the sibling `commit0` backend).
- **Lint:** `make lint` runs `golangci-lint run ./...` (v2, matches CI);
  falls back to `go vet ./...` if `golangci-lint` is not installed locally.
  Generated code (`pkg/contract/commit0v1/`) is excluded from lint.
- **Format:** standard `gofmt`/`goimports` conventions; no repo-specific
  formatter overrides observed.
- **Git hooks (`lefthook.yml`, install once via `make hooks`):**
  - `commit-msg` — enforces Conventional Commits
    (`build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test(scope)?:
    description`). Bypass only with `git commit --no-verify` in a genuine
    emergency.
  - `pre-push` — runs `golangci-lint run --timeout=5m` and `go build ./...`
    in parallel; both must pass before a push succeeds.

## Naming

- **Full English words in identifiers.** `vulnerability`, not `vuln`.
  `template`, not `tmpl`. `repository`, not `repo`, in code — CLI flags may
  stay short for ergonomics (e.g. `--db-snapshot`, not
  `--database-snapshot`).
- **Go files:** `snake_case.go`, matching the existing convention throughout
  `internal/` and `pkg/` (e.g. `ecosystem_maven.go`, `npm_semver.go`,
  `comparator_registry.go`).
- **Non-Go files** (Markdown, shell, YAML): kebab-case with a descriptive
  name, e.g. `docs/code-standards.md`, `docs/soundness-limits.md`.
- **TypeScript** (`plugins/js-reachability/src/`): standard TS/JS
  camelCase for identifiers, kebab-case or camelCase for filenames matching
  the existing plugin source layout.

## No stub code

Every change ships fully working logic plus tests. No `panic("not
implemented")`, no empty function bodies standing in for real behavior, no
`// TODO` placeholders for behavior that should exist now. This applies with
extra weight to reachability and soundness logic — a stubbed confidence
decision is a silent soundness regression, not a cosmetic gap.

## Generated code — never hand-edited

- `pkg/contract/commit0v1/` — generated Go protobuf/gRPC stubs from
  `proto/commit0/v1/plugin.proto`.
- `plugins/js-reachability/src/gen/` — generated TypeScript stubs from the
  same proto source.

Regenerate both via `make generate` (`buf generate` +
`buf generate --template buf.gen.js.yaml`), which requires `buf` and the
`protoc-gen-go`/`protoc-gen-go-grpc` plugins on `PATH`. If `proto/plugin.proto`
changes without regenerating, CI's dedicated `proto` job (path-filtered on
`proto/**`, `buf.yaml`, `buf.gen.yaml`, `pkg/contract/commit0v1/**`) fails on
stub drift (`buf generate` + `git diff`).

## Testing conventions

- **Golden files.** Renderer tests (`internal/render/*_test.go`, e.g.
  `sarif_test.go`) compare output against checked-in golden fixtures;
  regenerate with an `-update` flag on the test binary
  (`go test ./internal/render/... -run TestX -update`) when output
  intentionally changes. Golden output must stay byte-identical across runs
  with the same input — that determinism is itself part of what the tests
  verify.
- **Tri-state comparator tests.** Every version comparator in
  `internal/advisory/` (`semver.go`, `npm_semver.go`, `cargo_semver.go`,
  `pep440.go`, `maven_version.go`, `nuget_version.go`, `composer_version.go`,
  `rubygems_version.go`, `hex_version.go`, `pub_version.go`,
  `swift_version.go`) must have tests covering all three
  `VersionAffected | VersionNotAffected | VersionUndecidable` outcomes,
  including the parse-error/malformed-range path, which must resolve to
  `VersionUndecidable` — never `VersionNotAffected`.
- **Real-repo tests.** Ecosystem adapters and comparators are tested against
  real, representative lockfiles/manifests for that ecosystem, not only
  synthetic fixtures, to catch real-world format variance.
- **Corpus harness.** `internal/corpus/` runs labeled fixtures through the
  full host → plugin pipeline; a JSON baseline pins the analyzer's own
  numbers and is regenerated deliberately via `--regen-baseline`, never
  silently overwritten by a normal test run.
- **Parity harness.** `internal/advisory/parity/` is build-tagged
  (`-tags parity`) so it stays out of the default `go test ./...` run and
  requires comparator binaries (`osv-scanner`, `grype`, `trivy`,
  `govulncheck`) on `PATH` to produce non-skipped rows.

## Registry patterns — panic on misconfiguration, not silent skip

Registries in this codebase fail loudly rather than degrade quietly, because
a silently-missing entry would be a soundness regression discovered only in
production:

- `internal/cli/ecosystem_registry.go` — the `EcosystemAdapter` registry is
  the single source of ecosystem taxonomy: detection, `--language`
  validation, and the scan loop all derive from it, so an unregistered
  ecosystem can never be detected-but-unscanned. The one-adapter-per-language
  invariant is test-enforced. When adding a new lockfile-static ecosystem,
  register it in an `init()` alongside its adapter file.
- `internal/advisory/comparator_registry.go` — panics on duplicate
  comparator registration for the same ecosystem. When adding a new
  ecosystem's version comparator, register it here and add the
  `comparator_registry.go` wiring in the same change as the comparator file.

## Determinism requirements

Any code that produces user-facing or machine-readable output must be a pure
function of its inputs:

- **No `time.Now()` or random UUID generation** inside `internal/render/` or
  `internal/vex/` emitters. Timestamps, when needed, are injected by the
  caller; VEX document IDs are content-derived (SHA-256), not random.
- **Sorted output.** Merge, dedup, and plugin-fan-out results are
  deterministically ordered (advisory merge is stable-sorted by ID; plugin
  `Analyze` results are sorted by plugin name) so two runs over the same
  input produce byte-identical output — this is exercised directly by the
  offline-determinism examples in `docs/usage.md`.

## Soundness rules for new code

These are non-negotiable invariants specific to this project's threat model
(false-negative reachability is the cardinal sin). Any change touching
advisory matching, comparators, reachability plugins, VEX mapping, or the
policy gate must preserve all of the following:

- **`unknown ≠ safe`.** A result the code cannot prove must degrade to
  `CONFIDENCE_UNKNOWN`, never to a "safe" or "not applicable" verdict, and
  must still count toward the policy gate by default.
- **Only `NOT_REACHABLE` may suppress a finding.** `contract.FindingWrapper
  .IsSuppressible()` is the single enforcement point for this rule; do not
  add a second path that can mark a finding suppressible.
- **A version-comparator parse error resolves to `VersionUndecidable`,
  never `VersionNotAffected`.** An unregistered ecosystem in
  `comparator_registry.go` must behave the same way, not silently match
  or silently skip.
- **VEX status mapping never emits a false `not_affected`.** Only a
  `NOT_REACHABLE` verdict from a *complete* analysis may map to
  `not_affected`; an incomplete `NOT_REACHABLE` or any `UNKNOWN` maps to
  `under_investigation`. See `internal/vex/`'s `MapStatus`.
- **ACE-safety: never execute a project's manifest or build scripts to
  determine reachability or dependencies.** Lockfile-static adapters parse lockfiles
  only (`pom.xml`, `Gemfile`, `mix.exs`, `Package.swift`, and similar
  manifests are read for direct-dependency hints, never executed). Where
  the host installs dependencies for reachability (JS, Rust), install
  commands always run with lifecycle/build scripts disabled
  (`--ignore-scripts`, `cargo fetch`).
- **A plugin crash or timeout never drops coverage.** `internal/host/run.go`
  converts a launch/RPC/receive failure into a synthetic
  `CONFIDENCE_UNKNOWN` finding rather than omitting the plugin's advisories
  from the result set.
- **Trust boundary for plugins is explicit, not conventional.** New plugins
  are added to the allowlist in `internal/host/registry.go` with a pinned
  SHA-256 manifest hash — never discovered via `PATH` or a well-known
  directory.

## Commit and PR conventions

- **Conventional Commits**, enforced by the `commit-msg` hook:
  `<type>(<scope>): <description>`, types `build|chore|ci|docs|feat|fix|perf
  |refactor|revert|style|test`.
- Keep commits focused on the actual code change; no AI-authorship
  references in commit messages or PR descriptions (see the parent
  workspace `CLAUDE.md`).
