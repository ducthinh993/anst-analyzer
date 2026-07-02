# commit0-analyzer Soundness Limits

This document honestly describes what `commit0-analyzer` can and cannot determine. Understanding these limits helps you interpret findings and set appropriate policy thresholds.

## The Core Invariant: `unknown ≠ safe`

A finding with confidence `UNKNOWN` means the analyzer **could not determine reachability** — not that the symbol is safe. `UNKNOWN` findings are always surfaced to the user and always count toward the policy gate (unless `reachable-only: true` is combined with a narrow `fail-on` threshold, but even then `UNKNOWN` is counted, not suppressed).

Only `CONFIDENCE_NOT_REACHABLE` findings may be excluded from gate counts.

## What Causes `CONFIDENCE_UNKNOWN`

### 1. Build configuration mismatch (GOOS / GOARCH / build tags)

`go/packages` loads packages for a specific `(GOOS, GOARCH, tags)` triple. If a vulnerable call site is gated behind a build constraint that does not match the scan configuration, the file is excluded from the build graph and the engine cannot trace a call path.

**Result:** `CONFIDENCE_UNKNOWN` — the engine cannot prove the path is absent on the target platform, only that it is absent on the scanned configuration.

**Implication:** Scanning with `--goos linux` on a codebase that runs on `linux` is necessary to find linux-specific reachable paths. Scanning with the wrong `GOOS` never produces `NOT_REACHABLE` for a genuinely gated path.

### 2. Reflection and dynamic dispatch

Go's `reflect` package and runtime-generated function values break the static call graph. The VTA call-graph algorithm has no edges for:
- `reflect.Value.Call` / `reflect.Value.CallSlice`
- `reflect.Method` invocations
- `plugin.Plugin.Lookup` (Go plugin system)
- Function values passed as `interface{}` and invoked via reflection

If the engine detects that a vulnerable symbol's address is taken **and** a reflect invocation is reachable, it conservatively emits `CONFIDENCE_UNKNOWN`.

**Result:** `CONFIDENCE_UNKNOWN` — the engine cannot confirm or deny the path exists at runtime.

### 3. cgo and external C symbols

`go/packages` with `TypecheckCgo: false` (the default) skips cgo elaboration. If a dependency requires cgo and the build environment lacks the C toolchain or CGO_ENABLED=0, the package may be `IllTyped` and the engine cannot build its SSA representation.

**Result:** `CONFIDENCE_UNKNOWN` — the advisory finding is kept (fail-closed), never silently dropped.

### 4. Non-compiling or broken modules

If the target module or a dependency fails to type-check (`IllTyped` in `go/packages`), the engine cannot reason about that package's call graph.

**Triggers:**
- A `replace` directive pointing to a non-existent path.
- Missing dependencies when running with `GOPROXY=off` and an incomplete module cache.
- Syntax or type errors in the module.

**Result:** `CONFIDENCE_UNKNOWN` for all advisories affecting the broken dependency. The error is surfaced in the finding's `properties.build_error` field and printed to stderr.

### 5. Unresolved advisory symbols

The Go vulnerability database sometimes records symbols that do not exist in the affected version (renamed, unexported, or generated). If the symbol cannot be located in the SSA program, the engine emits `CONFIDENCE_UNKNOWN` rather than claiming the path is absent.

## What the Engine **Can** Determine

| Confidence | Meaning | When produced |
|---|---|---|
| `SYMBOL_REACHABLE` | A concrete call-graph path from an entry point to the vulnerable symbol was found. | Static call graph has a path via VTA (with CHA/RTA base). |
| `PACKAGE_REACHABLE` | The vulnerable package is imported and reachable, but symbol-level confirmation is unavailable. | Advisory has no symbol-level data (`SymbolLevel=false`). |
| `NOT_REACHABLE` | No call path from any entry point to the vulnerable symbol was found in the static call graph. | BFS from all roots found no edge to the symbol, no reflection detected, no build mismatch. |
| `UNKNOWN` | Reachability could not be determined. See above. | Any of the cases above. |

## Advisory Data Scope

`commit0-analyzer` queries four advisory sources by default, plus two opt-in NVD modes (configurable via `--source`):

| Source | Default | Coverage | Symbol-level data |
|---|---|---|---|
| `go-vuln-db` (`vuln.go.dev`) | on | Go modules | Yes — the primary source for symbol-level precision. |
| `osv` (`osv.dev` offline bundle) | on | Go, npm/JS, Rust (crates.io), Python (PyPI), Maven (JVM), NuGet (.NET), Packagist (PHP), RubyGems (Ruby), Hex (Elixir), Pub (Dart), SwiftURL (Swift) | No — package-level only (all ecosystems). |
| `ghsa` (GitHub Security Advisory) | on | npm, PyPI, Maven, NuGet, RubyGems, Composer, and more (cross-ecosystem). Hybrid: OSV-format cached bundle (offline floor) + live GraphQL freshness when `GITHUB_TOKEN` is set. | No — package-level. |
| `gitlab` (GitLab Advisory DB / gemnasium-db) | on | npm, Maven, PyPI, Go, NuGet, Packagist, RubyGems, crates.io, Pub (Hex/Swift not served). One archive, refreshed once per scan. Defaults to the MIT-licensed community mirror `gitlab-org/advisories-community` (time-delayed ~30 days; the primary gemnasium-db has usage restrictions). An unparseable `affected_range` is forwarded as UNKNOWN, never dropped. | No — package-level. |
| `nvd` (NIST NVD API 2.0) | opt-in | CVE-keyed CVSS/CWE **enrichment** on already-matched advisories. Not a package matcher. | n/a (enricher). |
| `nvd-cpe` (NVD CPE breadth) | opt-in | CPE-keyed breadth matches, explicitly **lower-confidence** and non-gating. | No — CPE-based, never upgraded to reachability. |

**Measured, not asserted.** The multi-source merge, enrichment, risk fusion, and VEX are validated by the parity/quality harness in `internal/advisory/parity`, which scans a fixed, version-pinned corpus of real repositories — this repo (Go self-scan), `litellm` (Python), a Log4Shell-era app (JVM), and the `turbo` monorepo (npm) — and records, per entry: (a) the false-positive/false-negative deltas against `osv-scanner`, `grype`, `trivy`, and `govulncheck`; (b) the determinism and fail-closed invariants; and (c) the **coverage gain of the full source set (`go-vuln-db,osv,ghsa`) over the 2-source baseline (`go-vuln-db,osv`)**. The delta classifier counts a comparator finding commit0-analyzer did not report as a **false negative** unless commit0-analyzer proved the dependency `NOT_REACHABLE` *with a complete analysis* (a sound reachability suppression, mirroring the VEX `not_affected` guard); it never launders a miss — or an incomplete `NOT_REACHABLE` verdict — into a "suppression." The harness is build-tagged (`-tags parity`) so the default test suite stays hermetic; its machine-readable report is written under `internal/advisory/parity/reports/` and is the only source of any coverage number in these docs.

**Measured coverage gain (recorded corpus run, no `GITHUB_TOKEN`): zero new findings over the 2-source baseline.** On every corpus entry the 3-source scan surfaced exactly the same advisories as the 2-source baseline — Go `47→47`, Python `93→93`, npm `234→234`, and the JVM entry incomplete→incomplete (Gradle without a committed lockfile, correctly marked exit 3, never a false clean). The reason is structural, not a defect: the OSV.dev offline bundle already aggregates GHSA advisories (GHSA-keyed records are cached under the OSV tree), so GHSA's *offline* floor overlaps OSV almost completely. GHSA's incremental value is therefore **not** extra offline coverage but (1) the live GraphQL freshness layer, active only when `GITHUB_TOKEN` is set, and (2) per-source provenance attribution on merged advisories. The earlier "GHSA adds real cross-ecosystem coverage" framing was an unmeasured assertion; the measured offline gain over OSV is zero, and these docs now say so. Determinism (byte-identical re-runs) and fail-closed (injected source-fetch failure → exit 3) passed on all four entries. In the recorded environment the *pinned* comparator versions were unavailable (`osv-scanner` 2.x vs the pinned 1.7.4; `grype`/`trivy` absent), so comparator-vs-commit0-analyzer FP/FN deltas were recorded as **skipped — parity not claimed**, never asserted; re-run with the pinned binaries on PATH to populate those rows.

**Honest Go-coverage note:** OSV.dev's "Go" ecosystem dataset is the same underlying data as `vuln.go.dev` (OSV feeds the Go vuln DB). For Go modules specifically, OSV (and GHSA's Go entries) add **near-zero additional advisory coverage** — the merge layer collapses these back onto existing Go-DB symbol-level advisories. As the measured run above shows, this overlap is not Go-specific: because OSV already aggregates GHSA, the offline coverage gain of adding GHSA is ~zero across ecosystems (npm/PyPI included); GHSA's cross-ecosystem benefit is the freshness layer, which is `GITHUB_TOKEN`-gated.

**Only the Go vuln DB carries symbol-level data.** OSV Go entries are package-level (`SymbolLevel=false`). When the same advisory appears in both sources, the Go-DB (symbol-level) representative is kept and OSV is attributed in `Sources`. No precision is ever invented: merging never fabricates symbol data from a package-level entry.

**Multi-source dedup:** The same CVE appearing from multiple sources (Go-DB, OSV, GHSA, GitLab) collapses to one merged advisory via alias matching (`{ID} ∪ Aliases` set intersection). The merged advisory carries every contributing source (e.g. `Sources: ["go-vuln-db", "osv.dev", "ghsa", "gitlab"]`) for auditability. Output is deterministic (stable-sorted by advisory ID).

**Cross-source conflict resolution (fail-safe rules).** When sources disagree about an advisory (severity, version range, withdrawn status), the merge layer resolves by a documented, deterministic trust policy and records full provenance — a disagreement never silently drops coverage:
- **Representative selection** prefers, in order: a symbol-level entry over package-level, then a wider/more-conservative affected range, then a higher source trust tier (`go-vuln-db` > `ghsa` > `osv` = `gitlab` > `nvd-cpe`). The trust tier is only a final tie-break, never a reason to discard another source's match.
- **Severity** takes the highest reported across sources (conservative); each source's reported severity is retained in per-source provenance.
- **Withdrawn** is honored only by unanimous agreement: a merged advisory is treated as withdrawn ONLY when every contributing source withdrew it. A single still-live source keeps the advisory surfaced (a retraction in one DB never silently erases an active match in another).
- **NVD's CPE caveat:** NVD is CPE-keyed, not package-coordinate-keyed. `nvd` is therefore an enricher (CVSS/CWE by CVE) and `nvd-cpe` matches are tagged lower-confidence and **non-gating**. A CPE-breadth match is never promoted to package- or symbol-level reachability — no precision is invented.

**Enrichment freshness & honesty (EPSS / KEV / CVSS / CWE).** Enrichment is additive metadata; it never gates by default and a missing signal is never read as "safe":
- A KEV entry appears only when the CVE is in the CISA catalog **and** the catalog was successfully fetched. A KEV/EPSS fetch failure marks the scan **incomplete** (exit 3) — it is never treated as "not exploited."
- CVSS v3.1 vectors are scored exactly; v4.0 vectors are captured losslessly but their base-score math is deferred, so a 0 base score on a v4.0 metric means "not yet computed," never "no risk" (severity is not downgraded from it).
- Every advisory carries which sources contributed and each source's freshness (fetch time / snapshot age); stale-but-usable data warns and is used, never silently trusted.

**Risk fusion is deterministic and reachability-flooring.** The fused 0–100 risk score (SARIF `rank`) is a pure function of reachability × CVSS × KEV × EPSS: `NOT_REACHABLE` → 0, KEV dominates a reachable finding into the top band, and a reachability floor guarantees a reachable finding is never demoted to "ignore" by missing enrichment. The default gate is byte-identical to the pre-risk behavior; risk only gates when the user opts in via `--gate-on kev|epss>=X|risk>=Y`.

**VEX `under_investigation` guarantee (cardinal rule).** When emitting VEX (`--vex`), commit0-analyzer maps `NOT_REACHABLE` → `not_affected` (justification `vulnerable_code_not_in_execute_path`), reachable → `affected`, and **everything it could not prove safe** — `UNKNOWN` or any incomplete analysis — → `under_investigation`. It is structurally impossible for an unproven finding to emit `not_affected`; doing so would weaponize the tool into a false-clean generator, so only a proven `NOT_REACHABLE` verdict ever produces `not_affected`.

**Implication for Go:** `commit0-analyzer` and `govulncheck` use the same advisory symbol data. The differentiation is SARIF `codeFlows`, policy-as-code gating, and multi-ecosystem support — not symbol resolution precision.

**For JS/TS:** the OSV npm bundle is the only advisory source. No symbol-level data is available for npm (OSV npm entries are package-level only). The JS plugin narrows findings by building an import-reachability graph, so findings are NOT_REACHABLE for packages that are installed but never imported from a reachable entry point.

**For Rust:** OSV.dev includes crates.io advisories and RustSec data. Rust reachability is package-level (no static call graph available in the current implementation). Symbol hints may come from RustSec advisory metadata but are not propagated as SYMBOL_REACHABLE findings.

**For Python:** OSV.dev includes PyPI advisories. Python reachability uses a call-graph-driven analysis on the installed environment (lockfile-static; no code execution). For dynamic apps, UNKNOWN is correct and expected — the tool cannot prove reachability under `importlib.import_module()` and similar dynamic patterns. NOT_REACHABLE is never surfaced for gate purposes on Python (negative reachability is unsound on dynamic languages).

**For JVM (Java/Kotlin/Scala):** OSV.dev includes Maven Central advisories. Reachability is package-level only (lockfile-static, no bytecode analysis available). Version matching uses Apache Maven ComparableVersion ordering. Dependency types (dev vs runtime) come from Maven `<scope>` (test, provided → dev) and Gradle configurations.

**For .NET:** OSV.dev includes NuGet package advisories. Reachability is package-level only (lockfile-static, no static call graph available). Version matching uses NuGet SemVer-2 with 4-part versions and floating ranges. Dependency types come from `.csproj` `<PrivateAssets>All</PrivateAssets>` markup (if present); lockfile-only scans default all packages to runtime (documented trade-off, incomplete without `dotnet restore`).

**For PHP:** OSV.dev includes Packagist advisories. Reachability is package-level only (lockfile-static, no static call graph available). Version matching respects Composer stability flags (stable, RC, beta, alpha, dev). Dependency types come from `composer.lock` sections: `packages` (runtime) vs `packages-dev` (dev).

**For Ruby:** OSV.dev includes RubyGems advisories. Reachability is package-level only (lockfile-static, no static call graph available; `Gemfile` is executable Ruby and is **never** evaluated). Version matching uses `Gem::Version` canonical segments (supports pessimistic `~>` at the range level). Dependency types (dev vs runtime) come from `Gemfile.lock` groups (development, test → dev).

**For Elixir:** OSV.dev includes Hex advisories. Reachability is package-level only (lockfile-static, no static call graph available; `mix.exs` is executable Elixir and is **never** evaluated). Version matching uses SemVer 2.0. Dependency types (dev vs runtime) come from `mix.lock` grouping. An unparseable `mix.lock` (e.g., incomplete lockfile) is treated as an incomplete scan (exit 3), never a false clean pass.

**For Dart:** OSV.dev includes Pub advisories. Reachability is package-level only (lockfile-static, no static call graph available). Advisory volume is currently **thin** — Pub has fewer published vulnerabilities than more mature ecosystems. Version matching uses `pub_semver` (build metadata is significant, unlike SemVer 2.0). Dependency types (dev vs runtime) come from `pubspec.lock`.

**For Swift:** OSV.dev includes SwiftURL ecosystem advisories. Reachability is package-level only (lockfile-static; `Package.swift` is executable Swift and is **never** evaluated). Packages are identified by their git repository URL; commit0-analyzer normalizes resolved URLs to match advisory identifiers. Version matching uses SemVer 2.0. All dependencies in `Package.resolved` are tagged as runtime (dependency types are not distinguished in the lockfile).

**Partial closures (Maven pom.xml, .NET .csproj):** A plain `pom.xml` project without a lockfile can be scanned for declared direct dependencies only (incomplete closure); transitive dependencies require Maven to build. Such scans are marked incomplete (exit 3). Similarly, `.csproj` without a generated lockfile scans declared references (incomplete); `dotnet restore` generates the full closure.

### Live fetch and caching

`commit0-analyzer scan` fetches advisory data from all enabled sources on first run and caches them locally. Each source is refreshed independently before the per-dependency query loop. Use `--update` to force a re-fetch of all enabled sources.

**Failure handling at the fetch boundary:** A Go vuln DB fetch failure with no usable cache exits 3 (never a silent clean pass). An OSV bundle fetch failure (secondary source — for either Go or npm) emits a warning to stderr, marks the scan **incomplete** (exit 3), but does not abort — remaining-source findings still gate. If the staleness probe for Go-DB fails but a valid local cache exists, the scan uses the existing cache, prints a warning, and exits 3 (incomplete). See `docs/usage.md` for the advisory-data modes and `--source` details.

## Entry-Point Detection

### Go

| Module type | Detected entry points |
|---|---|
| `main` package | `main.main`, `init` functions, test functions (when `Tests=true` in load config) |
| Library (no `main`) | All exported functions and methods, `init` functions |

If no entry points are detected (e.g. an empty package), the engine emits `CONFIDENCE_UNKNOWN` for all advisories.

### JavaScript / TypeScript

The JS plugin builds a package-level import graph from the project's lockfile and source files. Entry points are:

- Files declared as `"main"` or `"exports"` in `package.json`
- Files in `src/`, `lib/`, or the package root that are not inside `node_modules/`

A dependency is `PACKAGE_REACHABLE` if there is a static import path from any entry-point file to the package's primary export. Dynamic `require()` calls, `eval`, and variable-module-name imports cannot be statically traced — these produce `CONFIDENCE_UNKNOWN` for any advisory affecting that package.

**Workspace (monorepo) attribution:** In an npm/Yarn/pnpm workspace, each workspace package is analyzed independently using only that workspace's entrypoints and declared deps. A dep that is declared in a workspace's `package.json` (including hoisted deps) but not imported from that workspace's entrypoints emits `NOT_REACHABLE` for that workspace. `NOT_REACHABLE` findings are included in JSON output (`--format json`) and in the audit trail; they are **suppressed** (but auditable) in SARIF output per the SARIF suppression spec — they do not appear as active results in SARIF. If a dep appears in the root `node_modules/` but is not declared in the workspace's own `package.json`, it is a **phantom dependency** and is tagged `phantom (undeclared)` in the finding.

**Ceiling:** The JS plugin currently operates at package-level reachability. Symbol-level (`SYMBOL_REACHABLE`) findings require Jelly enrichment, which is a fast-follow. Until Jelly enrichment is enabled, the maximum confidence for JS findings is `PACKAGE_REACHABLE`.

### Rust

The Rust plugin uses `cargo metadata` to enumerate declared dependencies (online by default; `--offline` honored). Entry points are all crates in the workspace. Reachability is determined via a static dependency graph — a vulnerable crate is `PACKAGE_REACHABLE` if it is declared as a direct or transitive dependency.

**Ceiling:** Rust reachability is package-level only. There is no static call-graph analysis. A vulnerable crate's reachability always terminates at `PACKAGE_REACHABLE` (never `SYMBOL_REACHABLE`). Symbol hints may come from RustSec advisory metadata but are not propagated as reachable/not-reachable confidence levels.

**Toolchain:** The Rust plugin pins the resolver to stable toolchain for safety; `cargo metadata` never runs build scripts. Scanning is deterministic and sandbox-safe.

### Python

The Python plugin performs AST-driven call-graph analysis on a lockfile-static resolved dependency set (uv.lock, poetry.lock, requirements.txt, or pyproject.toml). No code execution is required; the resolver works offline and sandboxed.

**Entry points:** The plugin analyzes all top-level modules in the project and installed dependencies, building an import-and-call graph. A vulnerable function is `SYMBOL_REACHABLE` when directly referenced from reachable first-party code (sound direct-reference lower bound). A vulnerable package is `PACKAGE_REACHABLE` if imported from reachable code.

**Dynamic languages and UNKNOWN:** Python allows dynamic imports via `importlib.import_module()`, `__import__()`, `exec`, and string-based configuration. When a package's import path cannot be statically determined, the finding confidence is `UNKNOWN`. **UNKNOWN on Python is correct, not a limitation** — it means the analysis completed but cannot prove the package is used under runtime dynamism.

**Dependency types:** Each finding includes `dep_type` (runtime, optional-extra, dev, test, docs) from the manifest. Non-runtime findings do not fail the gate by default; use `--gate-on` to customize. This segmentation helps prioritize findings: a dev-only vulnerable dependency is surfaced but typically lower risk than a runtime vulnerability.

**Negative reachability (NOT_REACHABLE):** On a dynamic app, `NOT_REACHABLE` is unsound — a package's absence from the static call graph does not prove it is unused (config-driven imports could load it at runtime). Accordingly, `NOT_REACHABLE` findings never gate, and `--gate-on reachable` suppresses `UNKNOWN` on non-runtime deps to focus on provable vulnerabilities.

**Ceiling:** Python reachability is call-graph-driven (positive model). The maximum confidence is `SYMBOL_REACHABLE` (with `--symbols`); `PACKAGE_REACHABLE` when symbol-level data is unavailable.

### JVM (Java / Kotlin / Scala)

The JVM analyzer resolves dependencies from Maven `pom.xml` or Gradle `gradle.lockfile` (and `build.gradle[.kts]` for detection). Entry points are all declared library and application dependencies. Reachability is determined via the lockfile's dependency graph — a vulnerable package is `PACKAGE_REACHABLE` if it is declared as a direct or transitive dependency.

**Ceiling:** JVM reachability is package-level only. There is no bytecode or call-graph analysis. A vulnerable package's reachability always terminates at `PACKAGE_REACHABLE` (never `SYMBOL_REACHABLE`). Confidence tier options are `PACKAGE_REACHABLE`, `UNKNOWN`, or `NOT_REACHABLE`.

**Limitations:** Manifest-only scans (`.pom` without lockfile) are incomplete. Gradle projects require `gradle.lockfile` or `--offline false` to auto-detect and resolve. Multi-module projects are detected and scanned from the root; subdirectory-only manifests may not be fully detected (shared root-detection limitation).

### .NET

The .NET analyzer resolves dependencies from NuGet lockfiles (`packages.lock.json`, `project.assets.json`) or declared dependencies in `.csproj` files. Entry points are all declared package references. Reachability is determined via the lockfile's dependency graph — a vulnerable package is `PACKAGE_REACHABLE` if it is declared as a direct or transitive dependency.

**Ceiling:** .NET reachability is package-level only. There is no static call-graph analysis. A vulnerable package's reachability always terminates at `PACKAGE_REACHABLE` (never `SYMBOL_REACHABLE`). Confidence tier options are `PACKAGE_REACHABLE`, `UNKNOWN`, or `NOT_REACHABLE`.

**Limitations:** `.csproj`-only scans (without a generated lockfile) report only declared dependencies and are marked **incomplete** (exit 3) — transitive dependencies cannot be resolved without running `dotnet restore`. Lockfile-only scans default all packages to runtime dep_type (a documented trade-off when `.csproj` with `<PrivateAssets>` tags is absent). Multi-project solutions are detected and scanned from the root; subdirectory-only projects may not be fully detected (shared root-detection limitation).

### PHP

The PHP analyzer resolves dependencies from the `composer.lock` lockfile. Entry points are all declared package dependencies. Reachability is determined via the lockfile's dependency graph — a vulnerable package is `PACKAGE_REACHABLE` if it is declared as a direct or transitive dependency.

**Ceiling:** PHP reachability is package-level only. There is no static call-graph analysis. A vulnerable package's reachability always terminates at `PACKAGE_REACHABLE` (never `SYMBOL_REACHABLE`). Confidence tier options are `PACKAGE_REACHABLE`, `UNKNOWN`, or `NOT_REACHABLE`.

**Limitations:** Requires `composer.lock` (generated by `composer install`). The analyzer never runs `composer` — it is lockfile-static and sandbox-safe. Multi-project composer setups are detected from the root only; subdirectory-only projects may not be fully detected (shared root-detection limitation).

### Ruby

The Ruby analyzer resolves dependencies from the `Gemfile.lock` lockfile. Entry points are all declared gem dependencies. Reachability is determined via the lockfile's dependency graph — a vulnerable package is `PACKAGE_REACHABLE` if it is declared as a direct or transitive dependency.

**Ceiling:** Ruby reachability is package-level only. There is no static call-graph analysis. A vulnerable package's reachability always terminates at `PACKAGE_REACHABLE` (never `SYMBOL_REACHABLE`). Confidence tier options are `PACKAGE_REACHABLE`, `UNKNOWN`, or `NOT_REACHABLE`.

**Limitations:** Requires `Gemfile.lock` (generated by `bundle install`). The analyzer never evaluates the `Gemfile` — it is lockfile-static and sandbox-safe. Multi-project setups are detected from the root only; subdirectory-only projects may not be fully detected (shared root-detection limitation).

### Elixir / Erlang

The Elixir analyzer resolves dependencies from `mix.lock` (for Elixir projects) or `rebar.lock` (for Erlang/rebar3 projects). Entry points are all declared application dependencies. Reachability is determined via the lockfile's dependency graph — a vulnerable package is `PACKAGE_REACHABLE` if it is declared as a direct or transitive dependency.

**Ceiling:** Elixir reachability is package-level only. There is no static call-graph analysis. A vulnerable package's reachability always terminates at `PACKAGE_REACHABLE` (never `SYMBOL_REACHABLE`). Confidence tier options are `PACKAGE_REACHABLE`, `UNKNOWN`, or `NOT_REACHABLE`.

**Limitations:** Requires `mix.lock` or `rebar.lock` (generated by `mix deps.get` or `rebar3 get-deps`). The analyzer never evaluates `mix.exs` — it is lockfile-static and sandbox-safe. An unparseable or incomplete lockfile is marked as an incomplete scan (exit 3). Multi-project setups are detected from the root only; subdirectory-only projects may not be fully detected (shared root-detection limitation).

### Dart / Flutter

The Dart analyzer resolves dependencies from the `pubspec.lock` lockfile. Entry points are all declared package dependencies. Reachability is determined via the lockfile's dependency graph — a vulnerable package is `PACKAGE_REACHABLE` if it is declared as a direct or transitive dependency.

**Ceiling:** Dart reachability is package-level only. There is no static call-graph analysis. A vulnerable package's reachability always terminates at `PACKAGE_REACHABLE` (never `SYMBOL_REACHABLE`). Confidence tier options are `PACKAGE_REACHABLE`, `UNKNOWN`, or `NOT_REACHABLE`.

**Limitations:** Requires `pubspec.lock` (generated by `pub get` or `flutter pub get`). The analyzer never runs pub — it is lockfile-static and sandbox-safe. Advisory volume in Pub is currently thin — vulnerabilities in the Pub ecosystem are less comprehensively documented than in more mature ecosystems. Multi-project flutter setups are detected from the root only; subdirectory-only projects may not be fully detected (shared root-detection limitation).

### Swift

The Swift analyzer resolves dependencies from the `Package.resolved` lockfile. Entry points are all declared package dependencies. Reachability is determined via the lockfile's dependency graph — a vulnerable package is `PACKAGE_REACHABLE` if it is declared as a direct or transitive dependency.

**Ceiling:** Swift reachability is package-level only. There is no static call-graph analysis. A vulnerable package's reachability always terminates at `PACKAGE_REACHABLE` (never `SYMBOL_REACHABLE`). Confidence tier options are `PACKAGE_REACHABLE`, `UNKNOWN`, or `NOT_REACHABLE`.

**Limitations:** Requires `Package.resolved` (generated by `swift package resolve`). The analyzer never evaluates `Package.swift` — it is lockfile-static and sandbox-safe. Packages are identified by their git repository URL; commit0-analyzer normalizes resolved URLs to match advisory identifiers. All dependencies are tagged as runtime (dependency types are not distinguished in the lockfile).

## Multi-Project Detection

**Plugin ecosystems (Go, JS/TS, Rust, Python)** detect projects at the **project root** only:
- Go: `go.mod` in subdirectories may not be detected.
- JS/TS: `package.json` in subdirectories may not be detected.
- Rust: `Cargo.toml` in subdirectories may not be detected.
- Python: `pyproject.toml` or `requirements.txt` in subdirectories may not be detected.

**Lockfile-static ecosystems (Maven, NuGet, Packagist, RubyGems, Hex, Pub, Swift)** now discover and scan manifests in subdirectories via bounded depth-limited walk:
- JVM: Multiple `pom.xml` or `gradle.lockfile` files in subdirectories are now detected.
- .NET: Multiple `.csproj` files in subdirectories of a shared solution are now detected.
- PHP: Multiple `composer.lock` files in subdirectories are now detected.
- Ruby: Multiple `Gemfile.lock` files in subdirectories are now detected.
- Elixir: Multiple `mix.lock` or `rebar.lock` files in subdirectories are now detected.
- Dart: Multiple `pubspec.lock` files in subdirectories are now detected.
- Swift: Multiple `Package.resolved` files in subdirectories are now detected.

The subdirectory walk is pruned by an ignore-list (`.git`, `node_modules`, `vendor`, `dist`, `build`, `target`, `obj`, dot-directories) so it never descends into dependency/build trees and stays fast. Hitting a project-directory cap marks the scan incomplete (exit 3).

**Workaround for plugin ecosystems:** Run `commit0-analyzer scan` from the lowest common root containing all manifests, or explicitly pass `--language <lang>` to narrow scope when scanning from the desired project root.

## Performance Budget

Target: **≤ 1.5× `govulncheck`** wall-clock on a ~50 k-LOC module (warm module cache, same machine).

VTA (Variable Type Analysis) is more expensive than CHA or RTA but provides better precision for interface dispatch. If VTA exceeds the budget, fall back to RTA via the `--algorithm rta` flag (available in the `standalone` binary) and document the precision trade-off. RTA may miss some interface-dispatch reachable paths and produce more `NOT_REACHABLE` results.

## License Note (AGPL-3.0)

`commit0-analyzer` is licensed under AGPL-3.0. This precludes embedding the core engine as a library in proprietary closed-source tools without releasing the embedding application's source. For CLI / CI use this is not a concern. Contact the project maintainers if library embedding in a proprietary context is a requirement.
