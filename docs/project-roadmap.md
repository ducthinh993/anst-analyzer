# Project Roadmap

Status is reported honestly: **done** (shipped and in the default pipeline),
**planned** (intended next work, not yet started), **deferred** (considered,
explicitly postponed), or **out-of-scope** (deliberately excluded from the
product). This roadmap is a distillation of `plans/` history plus known open
items surfaced during codebase review — it does not restate flag-level
detail, which lives in [`docs/usage.md`](./usage.md).

## Completed milestones

| Milestone | What shipped |
|---|---|
| OSS reachability security platform | Initial project scaffold: Go-only reachability engine, SARIF output, policy gate, exit-code contract. |
| Live advisory DB fetch | Replaced static/offline-only advisory data with live fetch-and-cache from `vuln.go.dev`, including atomic writes and snapshot pinning. |
| OSV multi-source advisories | Added OSV.dev as a second advisory source with alias-based merge/dedup against the Go vulnerability database. |
| JS/TS reachability SCA | Added the Bun-compiled JS/TS reachability plugin (import-graph reachability) and npm/Yarn/pnpm ecosystem support. |
| True reachability | Upgraded the Go plugin's call-graph algorithm to VTA on a CHA/RTA base for interface-dispatch precision; formalized the confidence-tier model. |
| Multi-language reachability | Added Rust (`cargo metadata` dependency-closure reachability) and Python (AST-driven call-graph reachability) plugins, bringing plugin-backed coverage to four ecosystems. |
| Additional language ecosystems | Added seven lockfile-static ecosystem adapters: Maven/JVM, NuGet/.NET, Packagist/PHP, RubyGems/Ruby, Hex/Elixir, Pub/Dart, SwiftPM/Swift — bringing total ecosystem coverage to eleven. |
| Advisory intelligence, multi-source | Added GHSA and GitLab (gemnasium-db) advisory sources, the CVSS/KEV/EPSS/CWE enrichment chain, the deterministic 0-100 risk score, and VEX emission (OpenVEX, CycloneDX, CSAF). |
| Org migration | Rebranded from the project's original working name (`anst-analyzer`) to `commit0-analyzer` under the `commit0-dev` organization. |

Recent merged work (see repository commit history for exact PRs): multi-language
reachability across 11 ecosystems, multi-source advisory intelligence
(GHSA/NVD/GitLab + enrichment/risk/VEX/reachability-by-default), and the
`commit0-analyzer` rebrand.

## Planned

- **Live `govulncheck` side-by-side comparison in the corpus harness.**
  `internal/corpus/` and `internal/advisory/parity/` currently record
  comparator results as provenance/context; a live, always-on side-by-side
  `govulncheck` comparison (rather than an opt-in, build-tagged parity run)
  is intended future work to keep coverage claims continuously verified.
- **Binary release workflow.** Distribution today is `go install
  github.com/commit0-dev/commit0-analyzer/cmd/commit0-analyzer@latest` only;
  a tagged binary release workflow (cross-platform artifacts, checksums) is
  not yet built.

## Deferred

- **Java/JVM call-graph reachability.** JVM is currently a
  lockfile-static, package-level-only adapter (`internal/cli
  /ecosystem_maven.go`). Bytecode-level call-graph reachability (a
  reachability plugin mirroring the Go/JS/Rust/Python plugins) has been
  considered and explicitly deferred — JVM stays at `PACKAGE_REACHABLE`
  ceiling for now.
- **Rust symbol-level reachability.** The Rust plugin currently reasons over
  the `cargo metadata` dependency-closure graph only; there is no call graph,
  so Rust reachability tops out at `PACKAGE_REACHABLE`. A MIR-level call
  graph (to reach `SYMBOL_REACHABLE`) has been discussed and deferred; see
  `docs/soundness-limits.md` for the current Rust ceiling.
- **Swift advisory-source decision.** GitLab's gemnasium-db archive does not
  serve Swift advisories (only OSV.dev's SwiftURL ecosystem does today,
  which is the sole current source). Whether to add or prioritize an
  additional Swift-specific advisory source is an open, deferred decision.
- **Plugin contract freeze at v1.** The host↔plugin wire contract
  (`pkg/contract/version.go`) is `v0-PROVISIONAL`
  (`ProtocolMajor = 0`); freezing a stable v1 contract (with the attendant
  backward-compatibility guarantees for third-party plugin authors) is
  deferred until the contract shape has proven stable across the existing
  four in-tree plugins.

## Out of scope

- **C/C++.** There is no ecosystem-standard manifest/lockfile format to
  anchor a dependency-resolution model on (unlike the eleven supported
  ecosystems, which all have a canonical lockfile or resolved-dependency
  format). C/C++ support is explicitly excluded from the product's scope.

## Known documentation gaps

- `internal/advisory/doc.go`'s package comment describes the package as
  "MVP Scope: Go Vulnerability Database Only," with multi-source resolution
  framed as a future roadmap item. This is stale — the package has shipped
  full multi-source (Go-DB, OSV, GHSA, GitLab, opt-in NVD), multi-ecosystem
  advisory resolution since the milestones above landed. Tracked as a
  documentation-only fix (code comment, not behavior); see
  [`docs/codebase-summary.md`](./codebase-summary.md) for the accurate
  package description in the meantime.
