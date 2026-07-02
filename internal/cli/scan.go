package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
	"github.com/commit0-dev/commit0-analyzer/internal/advisory/ghfetch"
	"github.com/commit0-dev/commit0-analyzer/internal/advisory/symbolindex"
	"github.com/commit0-dev/commit0-analyzer/internal/host"
	"github.com/commit0-dev/commit0-analyzer/internal/policy"
	"github.com/commit0-dev/commit0-analyzer/internal/render"
	"github.com/commit0-dev/commit0-analyzer/internal/telemetry"
	"github.com/commit0-dev/commit0-analyzer/internal/vex"
	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// scanFlags holds all flag values for the scan sub-command.
type scanFlags struct {
	format          string
	policyFile      string
	dbSnapshot      string
	offline         bool
	update          bool
	failOn          string
	gateOn          string // confidence floor for gating: reachable|reachable+unknown|all
	goos            string
	goarch          string
	tags            string
	pluginBin       string
	jsPluginBin     string // path to pre-built js-reachability plugin binary (skip build)
	rustPluginBin   string // path to pre-built rust-reachability plugin binary (skip build)
	pythonPluginBin string // path to pre-built python-reachability plugin binary (skip build)
	source          string // comma-separated source names; default "go-vuln-db,osv,ghsa"
	sourceExplicit  bool   // true when --source was explicitly set by the user
	language        string // "auto"|"go"|"js"|"rust"|"python"; default "auto"
	symbols         bool   // resolve vulnerable-symbol data from advisory fix patches
	vexFormat       string // VEX output format(s): openvex|cyclonedx|csaf|all; "" = off
	vexOut          string // VEX output path; "" or "-" = stdout (single format only)

	// skipDepsInstall opts out of the default automatic dependency installation
	// (scripts-disabled) that runs before analysis.
	skipDepsInstall bool
	// skipReachabilityAnalysis reports package-level advisory matches only and
	// skips the call-graph reachability plugin step for plugin ecosystems
	// (Go/JS/Rust/Python). Findings are emitted at CONFIDENCE_UNKNOWN.
	skipReachabilityAnalysis bool
}

// detectEcosystems checks moduleRoot for the well-known manifest files of every
// registered ecosystem and returns the set of those present. It never errors; an
// absent file simply leaves the ecosystem out of the set (unknown ≠ safe: the
// caller decides what to do with an empty set).
//
// Detection is fully registry-driven: every EcosystemAdapter (plugin-backed and
// lockfile-static alike) contributes its DetectFiles. Adding an ecosystem only
// requires registering its adapter — no edits to this function.
//
// DetectFiles entries that start with "*." are treated as suffix-glob patterns
// (e.g., "*.csproj") and match any non-directory file in moduleRoot with that
// extension. This avoids hardcoding project-specific filenames for ecosystems
// where the manifest name varies per project (e.g., .NET SDK-style .csproj files).
func detectEcosystems(moduleRoot string) ecosystems {
	e := make(ecosystems)
	stat := func(name string) bool {
		_, err := os.Stat(filepath.Join(moduleRoot, name))
		return err == nil
	}
	// hasFileSuffix returns true when any non-directory file in moduleRoot ends
	// with suffix (case-insensitive). Used for "*.ext" glob DetectFiles entries.
	hasFileSuffix := func(suffix string) bool {
		entries, err := os.ReadDir(moduleRoot)
		if err != nil {
			return false
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), strings.ToLower(suffix)) {
				return true
			}
		}
		return false
	}
	for _, a := range ecosystemRegistry {
		for _, f := range a.DetectFiles {
			var matched bool
			if strings.HasPrefix(f, "*.") {
				matched = hasFileSuffix(f[1:]) // e.g., "*.csproj" → ".csproj"
			} else {
				matched = stat(f)
			}
			if matched {
				e.set(a.Language)
				break
			}
		}
	}
	return e
}

// resolveLanguage applies the --language override to the detected ecosystem set.
// "auto" defers to detection and passes every detected ecosystem through
// (zero-config: a polyglot repo runs every detected path). Any other recognised
// value is a narrowing filter — it restricts scanning to that ecosystem only but
// never activates an ecosystem that has no manifest file. An unrecognised value
// is an operational error.
func resolveLanguage(lang string, e ecosystems) (ecosystems, error) {
	if lang == "auto" {
		return e, nil
	}
	if isKnownLanguage(lang) {
		return ecosystems{lang: true}, nil
	}
	return nil, fmt.Errorf("unknown --language value %q: must be one of %s", lang, languageChoices())
}

// warnUnsupportedEcosystems writes a warning to w for every ecosystem in eco
// that is detected (or explicitly selected via --language) but has no scan path
// yet (rust, python, java, dotnet, php, ruby, elixir, dart, swift). It returns
// true when any such ecosystem is present, signalling that the caller must set
// incomplete=true.
//
// "unknown ≠ safe": a detected ecosystem with no scan path MUST surface as an
// incomplete scan (exit 3) rather than a false-clean pass (exit 0). This
// mirrors the npm-no-capable-source guard at the JS advisory block.
//
// Go and JS always have full scan paths and are never warned about. Rust and
// Python are warned about only when their plugin binaries are absent (callers
// reduce the eco set before calling this when a plugin is available).
// Lockfile-static ecosystems are cleared by the registry loop when their adapter
// ran; they remain here as a symmetric backstop so a detected-but-unscanned
// ecosystem still surfaces as incomplete rather than passing false-clean.
//
// Iteration order is orderedLanguages (never map iteration) so the warning
// sequence is deterministic.
func warnUnsupportedEcosystems(eco ecosystems, w io.Writer) bool {
	incomplete := false
	for _, lang := range orderedLanguages {
		if lang == "go" || lang == "js" {
			continue // Go and JS always have a full scan path
		}
		if !eco.active(lang) {
			continue
		}
		_, _ = fmt.Fprintf(w,
			"warning: %s ecosystem detected but no %s scan path is available yet; "+
				"%s deps were not checked for vulnerabilities; scan marked incomplete\n",
			lang, lang, lang)
		incomplete = true
	}
	return incomplete
}

// ceilingToConfidence maps an ecosystem's local capability tier to the wire-level
// commit0v1.Confidence. This is the single seam where the local confidenceCeiling
// enum meets the generated proto package, keeping proto imports out of the
// adapter files.
func ceilingToConfidence(c confidenceCeiling) commit0v1.Confidence {
	switch c {
	case ceilingSymbol:
		return commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE
	default:
		return commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE
	}
}

// sourceAliases maps user-facing --source flag tokens to canonical advisory
// source names (the SourceXxx constants in the advisory package).
// "go-vuln-db" is both the flag token and the canonical name (SourceGoVulnDB).
// "osv" is the short flag token; its canonical name is "osv.dev" (SourceOSV).
// The full canonical name "osv.dev" is also accepted for forward compatibility.
//
// "ghsa" is the GitHub Security Advisory source (real, in the default set).
// "nvd" enables the NVD CVE-keyed enricher (it is NOT a package→advisory source;
// it augments matched advisories with CVSS/CWE detail). "nvd-cpe" enables the
// opt-in, lower-confidence CPE-breadth source. "epss" enables the EPSS exploit-
// prediction enricher. KEV and CWE enrichment are always on (not --source tokens).
var sourceAliases = map[string]string{
	"go-vuln-db": advisory.SourceGoVulnDB, // SourceGoVulnDB = "go-vuln-db"
	"osv":        advisory.SourceOSV,      // short alias for "osv.dev"
	"osv.dev":    advisory.SourceOSV,      // SourceOSV = "osv.dev" (full canonical)
	"ghsa":       advisory.SourceGHSA,     // GitHub Security Advisory (default-on)
	"gitlab":     advisory.SourceGitLab,   // GitLab Advisory Database / gemnasium-db (default-on)
	"nvd":        advisory.SourceNVD,      // NVD CVE-keyed enricher (opt-in)
	"nvd-cpe":    advisory.SourceNVDCPE,   // NVD CPE-breadth source (opt-in, lower-confidence)
	"epss":       advisory.SourceEPSS,     // EPSS exploit-prediction enricher (opt-in)
}

// defaultSourceFlag is the default --source value. GHSA and GitLab join
// go-vuln-db and OSV as real sources; NVD enrichment (nvd) and CPE breadth
// (nvd-cpe) are opt-in. Migration note: a default scan also attaches GHSA and
// GitLab. With no cache or token present each is a no-op (returns no advisories
// without claiming clean), so the change is coverage-monotonic and gate-
// compatible. GitLab (gemnasium-db) aggregates package-level advisories OSV/GHSA
// can miss, so it adds real breadth.
const defaultSourceFlag = "go-vuln-db,osv,ghsa,gitlab"

// Source trust tiers feed advisory.NamedSource.Trust, the merge representative
// tie-break that engages only after the symbol-level and range-width rules.
// Higher wins; the symbol-curated Go vuln DB outranks GHSA, which outranks the
// vendor-neutral package-level aggregators (OSV and GitLab share the same tier);
// the opt-in NVD-CPE breadth source is lowest. 0 is reserved for "unset" so an
// unranked source never wins a tie by accident.
const (
	trustGoVulnDB = 4
	trustGHSA     = 3
	trustOSV      = 2
	trustGitLab   = 2
	trustNVDCPE   = 1
)

// nvdAPIDefaultURL is the NVD CVE API 2.0 endpoint used by the opt-in `nvd`
// enricher and `nvd-cpe` source when online and COMMIT0_NVD_API_URL is unset.
const nvdAPIDefaultURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// newScanCmd returns the cobra sub-command for `commit0-analyzer scan`.
func newScanCmd() *cobra.Command {
	var flags scanFlags

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a Go module, JS/TS package, Rust crate, Python project, or Java project for reachable dependency vulnerabilities",
		Long: `Run the full reachability SCA pipeline against a Go module:

  1. Resolve module dependencies from go.mod/go.sum.
  2. Query the advisory service for each dependency.
  3. Build an AnalyzeRequest with advisory data and build config.
  4. Drive the go-reachability plugin through the host subprocess transport.
  5. Render findings in the requested format (sarif|json|table).
  6. Evaluate the policy gate and exit with the appropriate code.

PATH is the module root to scan. Defaults to the current directory.

Exit codes:
  0  All findings within policy thresholds.
  1  One or more findings exceeded the configured threshold.
  3  Operational error (plugin crash, build failure, missing deps).`,
		Args: cobra.MaximumNArgs(1),
		// RunE returns an error only for operational failures (exit 3).
		// Policy gate failures (exit 1) are signalled via os.Exit from within runScan.
		RunE: func(cmd *cobra.Command, args []string) error {
			moduleRoot := "."
			if len(args) > 0 {
				moduleRoot = args[0]
			}
			abs, err := filepath.Abs(moduleRoot)
			if err != nil {
				return fmt.Errorf("resolve module root %q: %w", moduleRoot, err)
			}

			flags.sourceExplicit = cmd.Flags().Changed("source")
			code := runScan(cmd.Context(), abs, flags)
			if code != policy.ExitPass {
				os.Exit(code)
			}
			return nil
		},
	}

	fs := cmd.Flags()
	fs.StringVar(&flags.format, "format", "sarif", "output format: sarif|json|table")
	fs.StringVar(&flags.policyFile, "policy", "", "path to a YAML policy file (optional)")
	fs.StringVar(&flags.dbSnapshot, "db-snapshot", "", "path to a pinned advisory snapshot directory (read-only; never fetched)")
	fs.BoolVar(&flags.offline, "offline", false, "disable network access; use existing cache or --db-snapshot")
	fs.BoolVar(&flags.update, "update", false, "force re-fetch of advisory data even when cached version is current")
	fs.StringVar(&flags.failOn, "fail-on", "high", "minimum severity to fail: low|medium|high|critical")
	fs.StringVar(&flags.goos, "goos", "", "GOOS override for build config")
	fs.StringVar(&flags.goarch, "goarch", "", "GOARCH override for build config")
	fs.StringVar(&flags.tags, "tags", "", "comma-separated build tags")
	fs.StringVar(&flags.pluginBin, "plugin-binary", "", "path to pre-built go-reachability plugin binary (skip build)")
	fs.StringVar(&flags.jsPluginBin, "js-plugin-binary", "", "path to pre-built js-reachability plugin binary (skip build)")
	fs.StringVar(&flags.rustPluginBin, "rust-plugin-binary", "", "path to pre-built rust-reachability plugin binary (skip build)")
	fs.StringVar(&flags.pythonPluginBin, "python-plugin-binary", "", "path to pre-built python-reachability plugin binary (skip build)")
	fs.StringVar(&flags.source, "source", defaultSourceFlag,
		"comma-separated advisory sources: go-vuln-db, osv, ghsa, gitlab (default). KEV + CWE enrichment always on; opt-in: epss, nvd (CVE enrichers), nvd-cpe (CPE breadth)")
	fs.StringVar(&flags.language, "language", "auto",
		"ecosystem to scan: auto|go|js|rust|python|java (default: auto — detected from manifest files; auto runs ALL detected ecosystems)")
	fs.BoolVar(&flags.symbols, "symbols", false,
		"resolve vulnerable-symbol data from advisory fix patches (network, cached) to enable symbol-level reachability; degrades to package-level when unavailable")
	fs.StringVar(&flags.gateOn, "gate-on", "",
		"confidence floor for gate failures: reachable (SYMBOL+PACKAGE only), reachable+unknown (default, gates UNKNOWN on runtime deps too), all (gate all non-NOT_REACHABLE findings). "+
			"Append opt-in, additive risk predicates (comma-separated): kev, epss>=X, risk>=Y (e.g. reachable+unknown,kev,epss>=0.5)")
	fs.StringVar(&flags.vexFormat, "vex", "",
		"emit a VEX document in addition to the normal output: openvex|cyclonedx|csaf|all (off by default). "+
			"NOT_REACHABLE→not_affected, reachable→affected, UNKNOWN/incomplete→under_investigation (never not_affected)")
	fs.StringVar(&flags.vexOut, "vex-out", "",
		"VEX output path; '-' or empty writes to stdout (single format only). With --vex all, this must be a directory")
	fs.BoolVar(&flags.skipDepsInstall, "skip-deps-install", false,
		"skip automatic dependency installation before analysis")
	fs.BoolVar(&flags.skipReachabilityAnalysis, "skip-reachability-analysis", false,
		"report package-level advisory matches only; skip call-graph reachability")

	return cmd
}

// runScan executes the full scan pipeline and returns the exit code.
// It never panics; panics are caught by policy.RunWithRecovery in main.
func runScan(ctx context.Context, moduleRoot string, flags scanFlags) int {
	defer telemetry.Span("scan.total")()

	// ── 1. Detect ecosystems and validate module root ────────────────────────
	detected := detectEcosystems(moduleRoot)
	eco, langErr := resolveLanguage(flags.language, detected)
	if langErr != nil {
		fmt.Fprintf(os.Stderr, "commit0-analyzer scan: %v\n", langErr)
		return policy.ExitOperationalError
	}

	// Discover lockfile-static manifests in subdirectories early — before the
	// nothing-to-scan gate — so that a multi-project layout where NO manifest
	// lives at the repo root is still recognised and scanned rather than
	// silently skipped. The result (lockfileDiscovered, discoveryCapped) is
	// carried through to step 5e to avoid walking the tree a second time.
	lockfileDiscovered, discoveryCapped := discoverLockfileProjectDirs(moduleRoot, lockfileAdapters())

	// A lockfile-static subdir manifest counts as "something to scan" even when no root
	// manifest exists (multi-root project layouts).
	lockfileSubdirFound := false
	for _, dirs := range lockfileDiscovered {
		if len(dirs) > 0 {
			lockfileSubdirFound = true
			break
		}
	}

	if !eco.any() && !lockfileSubdirFound {
		fmt.Fprintf(os.Stderr,
			"commit0-analyzer scan: %s contains no recognised ecosystem manifest "+
				"(go.mod, package.json, Cargo.toml, pyproject.toml, requirements.txt, "+
				"pom.xml, build.gradle, build.gradle.kts, "+
				"packages.lock.json, packages.config, *.csproj, "+
				"composer.lock, composer.json, Gemfile.lock, Gemfile, "+
				"mix.lock, rebar.lock, pubspec.lock, pubspec.yaml, "+
				"Package.resolved); nothing to scan\n",
			moduleRoot)
		return policy.ExitOperationalError
	}

	// The Go advisory pipeline (steps 3–5) requires go.mod to resolve deps.
	// Skip it when only non-Go ecosystems were selected.
	if eco.active("go") {
		goModPath := filepath.Join(moduleRoot, "go.mod")
		if _, err := os.Stat(goModPath); err != nil {
			fmt.Fprintf(os.Stderr, "commit0-analyzer scan: --language go selected but %s does not contain a go.mod file: %v\n",
				moduleRoot, err)
			return policy.ExitOperationalError
		}
	}

	// ── 1b. Auto-install dependencies (deepest-security default) ──────────────
	// Materialize the scanned project's dependency closure before analysis so that
	// reachability sees the real installed graph. Every installer runs with
	// lifecycle/build scripts DISABLED (a security scanner must never execute
	// untrusted package code by default). Best-effort: failures warn and continue
	// (the downstream "unknown ≠ safe" handling marks the scan incomplete if deps
	// remain missing). Opt out with --skip-deps-install; --offline never installs.
	if !flags.skipDepsInstall && !flags.offline {
		installDependencies(ctx, eco, moduleRoot, flags.offline)
	}

	// ── 2. Validate --source flag ─────────────────────────────────────────────
	selectedSources, sourceErr := parseSourceFlag(flags.source)
	if sourceErr != nil {
		fmt.Fprintf(os.Stderr, "commit0-analyzer scan: --source: %v\n", sourceErr)
		return policy.ExitOperationalError
	}

	// ── 3. Resolve module dependencies (Go only) ─────────────────────────────
	var deps []modDep
	if eco.active("go") {
		var depsErr error
		deps, depsErr = listModDeps(ctx, moduleRoot)
		if depsErr != nil {
			fmt.Fprintf(os.Stderr, "commit0-analyzer scan: resolve deps: %v\n", depsErr)
			return policy.ExitOperationalError
		}
	}

	// ── 4. Build advisory sources and refresh (Go only) ──────────────────────
	//
	// Each enabled source is cache-backed (Go-DB via Cache; OSV via
	// OSVBundleSource). Both honour --offline (no Refresh) and --db-snapshot
	// (Go-DB snapshot pin; OSV falls back to its existing cache dir offline).
	//
	// Refresh is called once per enabled source before the per-dep query loop so
	// that Query calls are network-free. A secondary-source Refresh failure → warn
	// + incomplete (never abort); Go-DB Refresh failure → abort (primary source).
	//
	// Three advisory-data modes:
	//   a) --db-snapshot <dir>  → pin Go-DB to that dir (read-only, never fetched).
	//   b) --offline            → read existing caches; no network.
	//   c) default (online)     → refresh both caches from upstream.
	incomplete := false
	var namedSources []advisory.NamedSource
	var protoAdvs []*commit0v1.Advisory
	sourcesByID := map[string][]string{}
	// severityByID maps advisory ID → advisory.Severity (CVSS-derived).
	// Populated alongside sourcesByID; used in stampAdvisorySeverity after
	// findings are collected so that Finding.Severity is filled from the
	// advisory when the plugin left it UNSPECIFIED.
	severityByID := map[string]advisory.Severity{}
	// advByID maps advisory ID → the resolved+enriched advisory. Populated
	// alongside severityByID; used by stampRisk after findings are collected to
	// fuse reachability (the finding's confidence) with the advisory's CVSS/EPSS/
	// KEV/CWE enrichment into a deterministic risk score and stamp it onto
	// properties (risk_score, risk_tier, cvss, epss, kev, cwe).
	advByID := map[string]*advisory.Advisory{}
	// depTypeByAdvID maps advisory ID → dep_type (runtime | optional-extra | dev |
	// test | docs) for Python packages. Populated during the PyPI advisory loop;
	// used by stampDepType after findings are collected to tag each finding with
	// properties["dep_type"] so the policy gate can apply dep-type aware gating.
	// Non-Python ecosystems do not populate this map; their findings get no
	// dep_type property (treated as runtime by the gate — conservative default).
	depTypeByAdvID := map[string]string{}

	// pkgLevelFindings accumulates package-level advisory findings for the plugin
	// ecosystems (Go/JS/Rust/Python) when --skip-reachability-analysis is set. In
	// that mode the call-graph plugin step is skipped, so each matched advisory is
	// emitted directly as a CONFIDENCE_UNKNOWN finding (no reachability was
	// computed → we cannot narrow → unknown ≠ safe). These are unused when the
	// flag is off. lockfile-static ecosystems are unaffected: they never run a call-graph
	// plugin and already emit package-level findings in step 5e.
	var pkgLevelFindings []*commit0v1.Finding

	// ── 4d. GitLab advisory archive (one tarball for every ecosystem) ─────────
	// GitLab (gemnasium-db) serves many ecosystems from a single archive, so it is
	// refreshed exactly once per scan here — not per-ecosystem like the OSV bundles.
	// appendSecondarySources attaches the query-time source within each ecosystem
	// block (Go/npm/Rust/Python and the lockfile-static ecosystems); this step only ensures the shared cache is
	// populated. A refresh failure degrades to the existing cache and marks the scan
	// incomplete (unknown ≠ safe), never aborts; --offline skips the fetch.
	if selectedSources[advisory.SourceGitLab] {
		if cd, cacheErr := os.UserCacheDir(); cacheErr == nil {
			gitlabDir := filepath.Join(cd, "commit0-analyzer", "gitlab")
			if refreshGitLabArchive(ctx, gitlabDir, flags) {
				incomplete = true
			}
		}
	}

	if eco.active("go") {
		cacheDir, cacheErr := os.UserCacheDir()
		if cacheErr != nil {
			fmt.Fprintf(os.Stderr, "commit0-analyzer scan: cannot locate user cache dir: %v\n", cacheErr)
			return policy.ExitOperationalError
		}

		// ── 4a. Go vuln DB source ─────────────────────────────────────────────────
		if selectedSources[advisory.SourceGoVulnDB] {
			var cacheCfg advisory.CacheConfig
			cacheCfg.StalenessWarning = snapshotStalenessThreshold()

			if flags.dbSnapshot != "" {
				// Pinned snapshot: read-only, manifest-verified, never fetched.
				cacheCfg.SnapshotPin = flags.dbSnapshot
				cacheCfg.Offline = true
			} else {
				cacheCfg.Dir = filepath.Join(cacheDir, "commit0-analyzer", "vuln-db")
				cacheCfg.Offline = flags.offline
				if !flags.offline {
					// COMMIT0_VULN_DB_URL overrides the default vuln.go.dev base URL (test seam).
					f := advisory.NewFetcher()
					if override := os.Getenv("COMMIT0_VULN_DB_URL"); override != "" {
						f.BaseURL = override
					}
					cacheCfg.Fetcher = f
					cacheCfg.ForceUpdate = flags.update
				}
			}

			goCache := advisory.NewCache(cacheCfg)

			// Refresh Go-DB (no-op for pinned/offline/no-fetcher).
			// Failure handling ("unknown ≠ safe"):
			//   - RefreshFallbackWarning: probe failed but valid cache exists → warn + incomplete.
			//   - Other error (no cache + fetch failed) → abort (primary source).
			if refreshErr := goCache.Refresh(ctx, modPaths(deps)); refreshErr != nil {
				var fallback *advisory.RefreshFallbackWarning
				if errors.As(refreshErr, &fallback) {
					fmt.Fprintf(os.Stderr, "warning: %s\n", fallback.Warning)
					incomplete = true
				} else {
					fmt.Fprintf(os.Stderr, "commit0-analyzer scan: advisory refresh: %v\n", refreshErr)
					return policy.ExitOperationalError
				}
			}

			namedSources = append(namedSources, advisory.NamedSource{
				Name:  advisory.SourceGoVulnDB,
				S:     goCache,
				Trust: trustGoVulnDB,
			})
		}

		// ── 4b. OSV bundle source ─────────────────────────────────────────────────
		if selectedSources[advisory.SourceOSV] {
			osvCacheDir := filepath.Join(cacheDir, "commit0-analyzer", "osv")

			osvSrc := advisory.NewOSVBundleSource(osvCacheDir)
			// COMMIT0_OSV_DB_URL overrides the default OSV GCS base URL (test seam).
			// BaseURL is an exported field on OSVBundleSource for exactly this purpose.
			if override := os.Getenv("COMMIT0_OSV_DB_URL"); override != "" {
				osvSrc.BaseURL = override
			}
			osvSrc.ForceUpdate = flags.update

			// Refresh OSV (secondary source): failure → warn + incomplete, not abort.
			// --offline and --db-snapshot skip the Refresh; OSV falls back to its
			// existing cache dir if populated, or returns empty (nil,nil) if not.
			// A missing OSV cache in offline mode is recorded as incomplete (not silent).
			addOSV := true
			if !flags.offline && flags.dbSnapshot == "" {
				if refreshErr := osvSrc.Refresh(ctx, advisory.EcosystemGo); refreshErr != nil {
					fmt.Fprintf(os.Stderr, "warning: OSV source refresh failed (%s): %v; scan marked incomplete\n",
						advisory.SourceOSV, refreshErr)
					incomplete = true
					addOSV = false
				}
			} else if flags.offline || flags.dbSnapshot != "" {
				// Offline/snapshot mode: check whether the OSV cache exists.
				// If missing:
				//   - When --source was explicitly set to include osv → warn + incomplete
				//     ("unknown ≠ safe": the user specifically requested OSV coverage).
				//   - When --source was not explicitly set (OSV is the default) → silently
				//     skip. This preserves backward compat for callers using --db-snapshot
				//     (a Go-DB-only mode) who never populated an OSV cache.
				if !osvCacheDirExists(osvCacheDir, advisory.EcosystemGo) {
					if flags.sourceExplicit {
						fmt.Fprintf(os.Stderr,
							"warning: OSV cache not populated at %s (run without --offline to fetch); OSV source skipped, scan marked incomplete\n",
							filepath.Join(osvCacheDir, advisory.EcosystemGo))
						incomplete = true
					}
					addOSV = false
				}
			}

			if addOSV {
				namedSources = append(namedSources, advisory.NamedSource{
					Name:  advisory.SourceOSV,
					S:     osvSrc,
					Trust: trustOSV,
				})
			}
		}

		// ── 4c. GHSA + opt-in NVD-CPE secondary sources, and the NVD enricher ─────
		// GHSA is in the default set; NVD-CPE/NVD are opt-in. The secondary sources
		// self-guard (no-op for a missing bundle), so coverage is monotonic-up.
		namedSources = appendSecondarySources(namedSources, selectedSources, cacheDir, flags.offline)
		goEnrichChain := buildEnrichmentChain(cacheDir, flags.offline, selectedSources)

		// ── 5. Query advisory sources for each Go dep ─────────────────────────────
		multiSrc := advisory.NewMultiSource(namedSources...)

		// sourcesByID records the merged source attribution for each advisory so it
		// can be stamped onto findings (the Finding carries only an advisory ref, not
		// the advisory's Sources, so we propagate it here for visible attribution).
		goDeps := make([]advisoryDep, len(deps))
		for i, dep := range deps {
			desc := dep.Path + "@" + dep.Version
			goDeps[i] = advisoryDep{
				QueryName:       dep.Path,
				Version:         dep.Version,
				Module:          dep.Path,
				SourcesFailDesc: desc,
				Desc:            desc,
			}
		}
		resolveDepAdvisories(ctx, advisoryResolution{
			Ecosystem:    advisory.EcosystemGo,
			Source:       multiSrc,
			Enrich:       goEnrichChain,
			ProtoAdvs:    &protoAdvs,
			SourcesByID:  sourcesByID,
			AdvByID:      advByID,
			SeverityByID: severityByID,
			Incomplete:   &incomplete,
			// --skip-reachability-analysis: emit a package-level UNKNOWN finding
			// instead of running the call-graph plugin (see step 7).
			PerAdvisory: func(dep advisoryDep, adv *advisory.Advisory) {
				if flags.skipReachabilityAnalysis && adv.ID != "" {
					pkgLevelFindings = append(pkgLevelFindings, packageLevelFinding(adv, dep.Module, "go"))
				}
			},
		}, goDeps)
	}

	// ── 5b. npm advisory resolution (JS ecosystem) ───────────────────────────
	//
	// When JS is in scope, obtain the lockfile-resolved dep list from the JS
	// plugin via --list-deps (a fast local-only subprocess). Then query advisories
	// for each (workspace, pkg, version) through the same MultiSource / OSV bundle
	// plumbing as the Go path. Advisory resolution is centralized here in the CLI
	// so that --source, --offline, --db-snapshot, and --update all apply uniformly.
	//
	// go-vuln-db source returns (nil,nil) for npm (it covers only "Go") —
	// confirmed by goVulnDBClient.Query checking pkg.Ecosystem != EcosystemGo.
	// OSV source uses the "npm" bundle (npm/all.zip from the OSV GCS bucket).
	if eco.active("js") {
		// Resolve the JS plugin binary path (same as the manifest lookup used later
		// for registering the gRPC plugin, but needed now for --list-deps).
		jsPluginBin := flags.jsPluginBin
		if jsPluginBin == "" {
			if d := jsDistDir(); d != "" {
				jsPluginBin = filepath.Join(d, "commit0-js-reachability")
			}
		}
		if jsPluginBin == "" {
			fmt.Fprintf(os.Stderr, "commit0-analyzer scan: js plugin not available for --list-deps: cannot locate dist directory\n")
			return policy.ExitOperationalError
		}
		if _, statErr := os.Stat(jsPluginBin); statErr != nil {
			fmt.Fprintf(os.Stderr, "commit0-analyzer scan: js plugin binary not found at %s: %v\n", jsPluginBin, statErr)
			return policy.ExitOperationalError
		}

		// Get the dep list from the project model.
		npmDeps, modelIncomplete, listErr := listNPMDeps(ctx, jsPluginBin, moduleRoot)
		if listErr != nil {
			fmt.Fprintf(os.Stderr, "commit0-analyzer scan: list npm deps: %v\n", listErr)
			return policy.ExitOperationalError
		}
		if modelIncomplete {
			fmt.Fprintf(os.Stderr, "warning: npm project model is incomplete (some deps could not be resolved); scan marked incomplete\n")
			incomplete = true
		}

		// OSV is the only source with npm coverage. go-vuln-db covers only the Go
		// ecosystem and returns no advisories for npm. When JS deps are present but
		// no npm-capable source is selected, the scan has zero advisory coverage for
		// those deps — unknown ≠ safe, so warn and mark incomplete.
		npmCapableSourceSelected := selectedSources[advisory.SourceOSV]
		if len(npmDeps) > 0 && !npmCapableSourceSelected {
			fmt.Fprintf(os.Stderr,
				"warning: JS npm deps found but no npm-capable advisory source is selected "+
					"(osv.dev covers npm; go-vuln-db does not); "+
					"npm packages were not checked for vulnerabilities; scan marked incomplete\n")
			incomplete = true
		}

		if len(npmDeps) > 0 && npmCapableSourceSelected {
			// Build an OSV source for npm; reuse the same cacheDir as the Go OSV path.
			cacheDir, cacheErr := os.UserCacheDir()
			if cacheErr != nil {
				fmt.Fprintf(os.Stderr, "commit0-analyzer scan: cannot locate user cache dir: %v\n", cacheErr)
				return policy.ExitOperationalError
			}
			osvCacheDir := filepath.Join(cacheDir, "commit0-analyzer", "osv")

			osvSrc := advisory.NewOSVBundleSource(osvCacheDir)
			if override := os.Getenv("COMMIT0_OSV_DB_URL"); override != "" {
				osvSrc.BaseURL = override
			}
			osvSrc.ForceUpdate = flags.update

			// Refresh OSV npm bundle (secondary source → failure warns + marks incomplete).
			addNPMOSV := true
			if !flags.offline && flags.dbSnapshot == "" {
				if refreshErr := osvSrc.Refresh(ctx, advisory.EcosystemNPM); refreshErr != nil {
					fmt.Fprintf(os.Stderr, "warning: OSV npm source refresh failed (%s): %v; scan marked incomplete\n",
						advisory.SourceOSV, refreshErr)
					incomplete = true
					addNPMOSV = false
				}
			} else {
				// Offline/snapshot mode: check whether the npm OSV cache exists.
				if !osvCacheDirExists(osvCacheDir, advisory.EcosystemNPM) {
					if flags.sourceExplicit {
						fmt.Fprintf(os.Stderr,
							"warning: OSV npm cache not populated at %s (run without --offline to fetch); OSV npm source skipped, scan marked incomplete\n",
							filepath.Join(osvCacheDir, advisory.EcosystemNPM))
						incomplete = true
					}
					addNPMOSV = false
				}
			}

			if addNPMOSV {
				npmNamedSources := []advisory.NamedSource{
					{Name: advisory.SourceOSV, S: osvSrc, Trust: trustOSV},
				}
				// go-vuln-db source is intentionally excluded: it returns (nil,nil) for
				// npm automatically, but we avoid the lookup overhead for clarity.
				// GHSA (default) and opt-in NVD-CPE layer on top; both self-guard.
				npmNamedSources = appendSecondarySources(npmNamedSources, selectedSources, cacheDir, flags.offline)
				npmMultiSrc := advisory.NewMultiSource(npmNamedSources...)
				npmEnrichChain := buildEnrichmentChain(cacheDir, flags.offline, selectedSources)

				// Build the symbol resolver once for the entire npm dep loop when
				// --symbols is set and the JS plugin binary is known. A missing plugin
				// binary is handled below (resolver stays nil → symbols skipped silently).
				var symResolver *symbolindex.Resolver
				if flags.symbols && jsPluginBin != "" {
					ghCacheDir := filepath.Join(osvCacheDir, "gh-fix-cache")
					ghClient := ghfetch.NewClient(ghCacheDir)
					if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
						ghClient.Token = tok
					}
					symIndexDir := filepath.Join(osvCacheDir, "symbol-index")
					symResolver = symbolindex.NewResolver(symIndexDir, ghClient, jsPluginBin, flags.offline)
				}

				npmResolveDeps := make([]advisoryDep, len(npmDeps))
				for i, dep := range npmDeps {
					// Normalize the npm package name to lowercase to match OSV records.
					// OSV stores npm package names lowercase; lockfile names may differ.
					npmResolveDeps[i] = advisoryDep{
						QueryName:       strings.ToLower(dep.Name),
						Version:         dep.Version,
						Module:          dep.Name,
						SourcesFailDesc: dep.Name + "@" + dep.Version + " (workspace " + dep.Workspace + ")",
						Desc:            dep.Name + "@" + dep.Version,
					}
				}
				npmRes := advisoryResolution{
					Ecosystem:    advisory.EcosystemNPM,
					Source:       npmMultiSrc,
					Enrich:       npmEnrichChain,
					ProtoAdvs:    &protoAdvs,
					SourcesByID:  sourcesByID,
					AdvByID:      advByID,
					SeverityByID: severityByID,
					Incomplete:   &incomplete,
					// --skip-reachability-analysis: emit a package-level UNKNOWN finding
					// instead of running the call-graph plugin (see step 7).
					PerAdvisory: func(dep advisoryDep, adv *advisory.Advisory) {
						if flags.skipReachabilityAnalysis && adv.ID != "" {
							pkgLevelFindings = append(pkgLevelFindings, packageLevelFinding(adv, dep.Module, "js"))
						}
					},
				}
				// Resolve symbols before the fold (only when --symbols is set and the
				// resolver was successfully constructed). Any failure inside Resolve
				// degrades quietly: the advisory stays at SymbolLevel=false and the
				// finding remains PACKAGE_REACHABLE. Never marks the scan incomplete —
				// symbol data is precision-only.
				if symResolver != nil {
					npmRes.PostEnrich = func(advs []advisory.Advisory) {
						for i := range advs {
							if len(advs[i].FixRefs) == 0 {
								continue
							}
							syms := symResolver.Resolve(ctx, &advs[i])
							if len(syms) > 0 {
								advs[i].Symbols = syms
								advs[i].SymbolLevel = true
							}
						}
					}
				}
				resolveDepAdvisories(ctx, npmRes, npmResolveDeps)
			}
		}
	}

	// ── 5c. Rust ecosystem — pre-build manifest check and advisory query ────
	//
	// When Cargo.toml is detected (eco.active("rust")), attempt to build the Rust
	// plugin manifest now so we know whether the binary is available. The
	// manifest is registered in step 7 (after reg is initialized). If the
	// binary is absent, we fall through to warnUnsupportedEcosystems.
	//
	// When the plugin binary IS available, query the OSV crates.io bundle for
	// advisories covering the project's resolved Cargo deps — mirroring the JS
	// npm advisory resolution path (step 5b). Without this the plugin always
	// receives an empty advisory list and can never emit findings.
	//
	// "unknown ≠ safe": a Cargo.toml without a registered plugin means the
	// Rust deps were not checked; the scan MUST be marked incomplete.
	var rustManifest *host.Manifest
	if eco.active("rust") {
		rustManifest, _ = buildRustPluginManifest(ctx, flags.rustPluginBin)
	}

	// False-clean guard (Rust): OSV is the only advisory source with crates.io
	// coverage. If Rust is in scope but no OSV-capable source is selected, the
	// plugin would run against an empty advisory list and silently exit 0.
	// "unknown ≠ safe": warn and mark incomplete so the gate cannot pass clean.
	if eco.active("rust") && rustManifest != nil && !selectedSources[advisory.SourceOSV] {
		fmt.Fprintf(os.Stderr,
			"warning: Rust crates.io deps found but no crates.io-capable advisory source is selected "+
				"(osv.dev covers crates.io; go-vuln-db does not); "+
				"Rust packages were not checked for vulnerabilities; scan marked incomplete\n")
		incomplete = true
	}

	if rustManifest != nil && selectedSources[advisory.SourceOSV] {
		// List the resolved crate deps via cargo metadata (lockfile-static, no
		// build-script execution — safe on untrusted repos).
		cargoDeps, cargoIncomplete, cargoListErr := listCargoDeps(ctx, moduleRoot, flags.offline)
		if cargoListErr != nil {
			// cargo not on PATH or Cargo.lock missing: degrade to incomplete
			// (unknown ≠ safe). The plugin will emit UNKNOWN+Incomplete=true for
			// every advisory when ClosureUnknown=true, but it needs advisories to
			// iterate over. Mark incomplete here; the plugin's own degradation
			// handles the finding tier.
			fmt.Fprintf(os.Stderr,
				"warning: cargo metadata failed for crates.io advisory query: %v; scan marked incomplete\n",
				cargoListErr)
			incomplete = true
		}
		if cargoIncomplete {
			fmt.Fprintf(os.Stderr,
				"warning: cargo dep list is incomplete; scan marked incomplete\n")
			incomplete = true
		}

		if len(cargoDeps) > 0 {
			// Build a crates.io OSV source; reuse the same cache root as the Go/npm paths.
			cacheDir, cacheErr := os.UserCacheDir()
			if cacheErr != nil {
				fmt.Fprintf(os.Stderr, "commit0-analyzer scan: cannot locate user cache dir: %v\n", cacheErr)
				return policy.ExitOperationalError
			}
			osvCacheDir := filepath.Join(cacheDir, "commit0-analyzer", "osv")

			cratesOSV := advisory.NewOSVBundleSource(osvCacheDir)
			if override := os.Getenv("COMMIT0_OSV_DB_URL"); override != "" {
				cratesOSV.BaseURL = override
			}
			cratesOSV.ForceUpdate = flags.update

			// Refresh the crates.io OSV bundle (secondary source → failure warns + marks incomplete).
			addCratesOSV := true
			if !flags.offline && flags.dbSnapshot == "" {
				if refreshErr := cratesOSV.Refresh(ctx, advisory.EcosystemCratesIO); refreshErr != nil {
					fmt.Fprintf(os.Stderr,
						"warning: OSV crates.io source refresh failed (%s): %v; scan marked incomplete\n",
						advisory.SourceOSV, refreshErr)
					incomplete = true
					addCratesOSV = false
				}
			} else {
				// Offline/snapshot mode: check whether the crates.io OSV cache exists.
				if !osvCacheDirExists(osvCacheDir, advisory.EcosystemCratesIO) {
					if flags.sourceExplicit {
						fmt.Fprintf(os.Stderr,
							"warning: OSV crates.io cache not populated at %s (run without --offline to fetch); OSV crates.io source skipped, scan marked incomplete\n",
							filepath.Join(osvCacheDir, advisory.EcosystemCratesIO))
						incomplete = true
					}
					addCratesOSV = false
				}
			}

			if addCratesOSV {
				cratesNamedSources := []advisory.NamedSource{
					{Name: advisory.SourceOSV, S: cratesOSV, Trust: trustOSV},
				}
				cratesNamedSources = appendSecondarySources(cratesNamedSources, selectedSources, cacheDir, flags.offline)
				cratesMultiSrc := advisory.NewMultiSource(cratesNamedSources...)
				cratesEnrichChain := buildEnrichmentChain(cacheDir, flags.offline, selectedSources)

				cratesResolveDeps := make([]advisoryDep, len(cargoDeps))
				for i, dep := range cargoDeps {
					desc := "crate " + dep.Name + "@" + dep.Version
					cratesResolveDeps[i] = advisoryDep{
						QueryName:       dep.Name,
						Version:         dep.Version,
						Module:          dep.Name,
						SourcesFailDesc: desc,
						Desc:            desc,
					}
				}
				resolveDepAdvisories(ctx, advisoryResolution{
					Ecosystem:    advisory.EcosystemCratesIO,
					Source:       cratesMultiSrc,
					Enrich:       cratesEnrichChain,
					ProtoAdvs:    &protoAdvs,
					SourcesByID:  sourcesByID,
					AdvByID:      advByID,
					SeverityByID: severityByID,
					Incomplete:   &incomplete,
					// --skip-reachability-analysis: emit a package-level UNKNOWN finding
					// instead of running the call-graph plugin (see step 7).
					PerAdvisory: func(dep advisoryDep, adv *advisory.Advisory) {
						if flags.skipReachabilityAnalysis && adv.ID != "" {
							pkgLevelFindings = append(pkgLevelFindings, packageLevelFinding(adv, dep.Module, "rust"))
						}
					},
				}, cratesResolveDeps)
			}
		}
	}

	// ── 5d. Python ecosystem — pre-build manifest check and advisory query ──
	//
	// When pyproject.toml or requirements.txt is detected (eco.active("python")), attempt
	// to build the Python plugin manifest now so we know whether the binary is
	// available. The manifest is registered in step 7 (after reg is initialized).
	// If the binary is absent, we fall through to warnUnsupportedEcosystems.
	//
	// When the plugin binary IS available, query the PyPI OSV bundle for
	// advisories covering the project's resolved Python deps. Without this the
	// plugin always receives an empty advisory list and can never emit findings.
	//
	// "unknown ≠ safe": a pyproject.toml/requirements.txt without a registered
	// plugin means the Python deps were not checked; the scan MUST be marked
	// incomplete. Additionally, manifest-only / no-venv / offline+unpinned
	// scenarios where the plugin cannot perform reachability analysis are surfaced
	// as incomplete=true so the scan exits 3, never 0 (false-clean).
	var pythonManifest *host.Manifest
	if eco.active("python") {
		pythonManifest, _ = buildPythonPluginManifest(ctx, flags.pythonPluginBin)
	}

	// False-clean guard (Python): OSV is the only advisory source with PyPI
	// coverage. If Python is in scope but no OSV-capable source is selected,
	// the plugin would run against an empty advisory list and silently exit 0.
	// "unknown ≠ safe": warn and mark incomplete so the gate cannot pass clean.
	if eco.active("python") && pythonManifest != nil && !selectedSources[advisory.SourceOSV] {
		fmt.Fprintf(os.Stderr,
			"warning: Python PyPI deps found but no PyPI-capable advisory source is selected "+
				"(osv.dev covers PyPI; go-vuln-db does not); "+
				"Python packages were not checked for vulnerabilities; scan marked incomplete\n")
		incomplete = true
	}

	if pythonManifest != nil && selectedSources[advisory.SourceOSV] {
		// List the resolved Python package deps via the plugin's --list-deps
		// subcommand (lockfile-static, no pip/uv execution — safe on untrusted repos
		// when a lockfile is present; degrades to incomplete when no lockfile/venv).
		pythonDeps, pyIncomplete, pyListErr := listPythonDeps(ctx, pythonManifest.ExecPath, moduleRoot)
		if pyListErr != nil {
			// Plugin --list-deps failed: degrade to incomplete.
			// The plugin will emit UNKNOWN+Incomplete=true for every advisory.
			fmt.Fprintf(os.Stderr,
				"warning: python-reachability --list-deps failed: %v; scan marked incomplete\n",
				pyListErr)
			incomplete = true
		}
		if pyIncomplete {
			// Manifest-only / no-venv / offline+unpinned: the plugin signalled
			// that its dep resolution is partial. Force incomplete=true so the
			// scan exits 3 (not 0) and the user sees the degraded-mode message.
			fmt.Fprintf(os.Stderr,
				"warning: python project model is incomplete (manifest-only or no resolved venv); "+
					"reachability analysis will be degraded; scan marked incomplete\n")
			incomplete = true
		}

		if len(pythonDeps) > 0 {
			// Build a PyPI OSV source; reuse the same cache root as the Go/npm/Rust paths.
			cacheDir, cacheErr := os.UserCacheDir()
			if cacheErr != nil {
				fmt.Fprintf(os.Stderr, "commit0-analyzer scan: cannot locate user cache dir: %v\n", cacheErr)
				return policy.ExitOperationalError
			}
			osvCacheDir := filepath.Join(cacheDir, "commit0-analyzer", "osv")

			pypiOSV := advisory.NewOSVBundleSource(osvCacheDir)
			if override := os.Getenv("COMMIT0_OSV_DB_URL"); override != "" {
				pypiOSV.BaseURL = override
			}
			pypiOSV.ForceUpdate = flags.update

			// Refresh the PyPI OSV bundle (secondary source → failure warns + marks incomplete).
			addPyPIOSV := true
			if !flags.offline && flags.dbSnapshot == "" {
				if refreshErr := pypiOSV.Refresh(ctx, advisory.EcosystemPyPI); refreshErr != nil {
					fmt.Fprintf(os.Stderr,
						"warning: OSV PyPI source refresh failed (%s): %v; scan marked incomplete\n",
						advisory.SourceOSV, refreshErr)
					incomplete = true
					addPyPIOSV = false
				}
			} else {
				// Offline/snapshot mode: check whether the PyPI OSV cache exists.
				if !osvCacheDirExists(osvCacheDir, advisory.EcosystemPyPI) {
					if flags.sourceExplicit {
						fmt.Fprintf(os.Stderr,
							"warning: OSV PyPI cache not populated at %s (run without --offline to fetch); OSV PyPI source skipped, scan marked incomplete\n",
							filepath.Join(osvCacheDir, advisory.EcosystemPyPI))
						incomplete = true
					}
					addPyPIOSV = false
				}
			}

			if addPyPIOSV {
				pypiNamedSources := []advisory.NamedSource{
					{Name: advisory.SourceOSV, S: pypiOSV, Trust: trustOSV},
				}
				pypiNamedSources = appendSecondarySources(pypiNamedSources, selectedSources, cacheDir, flags.offline)
				pypiMultiSrc := advisory.NewMultiSource(pypiNamedSources...)
				pypiEnrichChain := buildEnrichmentChain(cacheDir, flags.offline, selectedSources)

				pypiResolveDeps := make([]advisoryDep, len(pythonDeps))
				for i, dep := range pythonDeps {
					// Normalize the PyPI package name to lowercase to match OSV records.
					desc := "python pkg " + dep.Name + "@" + dep.Version
					pypiResolveDeps[i] = advisoryDep{
						QueryName:       strings.ToLower(dep.Name),
						Version:         dep.Version,
						Module:          dep.Name,
						DepType:         dep.DepType,
						SourcesFailDesc: desc,
						Desc:            desc,
					}
				}
				resolveDepAdvisories(ctx, advisoryResolution{
					Ecosystem:    advisory.EcosystemPyPI,
					Source:       pypiMultiSrc,
					Enrich:       pypiEnrichChain,
					ProtoAdvs:    &protoAdvs,
					SourcesByID:  sourcesByID,
					AdvByID:      advByID,
					SeverityByID: severityByID,
					// Tag advisory with dep's classification for the gate.
					// Conservative: "runtime" wins; empty dep-type is runtime (unknown ≠ safe).
					DepTypeByAdv: depTypeByAdvID,
					Incomplete:   &incomplete,
					// --skip-reachability-analysis: emit a package-level UNKNOWN finding
					// instead of running the call-graph plugin (see step 7).
					PerAdvisory: func(dep advisoryDep, adv *advisory.Advisory) {
						if flags.skipReachabilityAnalysis && adv.ID != "" {
							pkgLevelFindings = append(pkgLevelFindings, packageLevelFinding(adv, dep.Module, "python"))
						}
					},
				}, pypiResolveDeps)
			}
		}
	}

	// ── 5e. Lockfile-static adapter loop — static resolve and OSV query ──
	//
	// Multi-project (subdirectory) detection: before the adapter loop, walk
	// moduleRoot to discover all directories that contain lockfile-static manifests. This
	// enables scanning multi-project layouts (e.g. a .NET solution with .csproj
	// in subdirs, a monorepo with per-package composer.lock) without any extra
	// flags. The walk is bounded by depth and an ignore-list so it stays fast.
	//
	// For each active adapter, ParseLockfile is called once per discovered
	// directory and the results are aggregated (deduped by name@version). If ANY
	// per-directory parse is incomplete, the aggregate is incomplete.
	//
	// "unknown ≠ safe" invariants:
	//   - ParseLockfile returning complete=false means the closure cannot be fully
	//     determined (missing lockfile, parse error, or requires running a build
	//     tool). The scan is marked incomplete; no OSV query is performed for that
	//     sub-result (a partial closure would produce false NOT_REACHABLE for the
	//     missing portion).
	//   - A capped discovery (> discoveryMaxDirs matching dirs) → incomplete=true;
	//     silently truncated discovery must never read as a clean scan.
	//   - OSV is the only source with coverage for these ecosystems; when OSV is
	//     not in the selected sources and deps were resolved, warn + mark incomplete.
	//   - After this block, clear the lockfile-static ecosystem flags from unsupportedEco so
	//     warnUnsupportedEcosystems does not emit a duplicate warning for them.
	//
	// lockfile-static findings are generated here (not by a plugin) because there is no
	// reachability plugin for these ecosystems. OSV advisory matches are converted
	// directly to PACKAGE_REACHABLE findings (max confidence for lockfile-static
	// analysis — no call-graph data). Undecidable advisory matches (version parse
	// error or unrecognised ecosystem) are converted to CONFIDENCE_UNKNOWN findings
	// with Incomplete=true so the policy gate exits 3 (not 0, which would be a
	// false-clean pass violating "unknown ≠ safe").

	// Handle capped discovery (lockfileDiscovered and discoveryCapped were computed
	// in step 1 and carried here to avoid a second walk).
	if discoveryCapped {
		fmt.Fprintf(os.Stderr,
			"warning: lockfile manifest discovery reached the %d-directory cap; "+
				"some subdirectories may not have been scanned; scan marked incomplete\n",
			discoveryMaxDirs)
		incomplete = true
	}

	var lockfileFindings []*commit0v1.Finding
	for _, lockfileAdapter := range lockfileAdapters() {
		// Determine which directories to scan for this adapter.
		//
		// Start from directories found by the bounded walk. If the adapter is also
		// active via root detection (detectEcosystems) or an explicit --language
		// flag, ensure moduleRoot appears first so single-root behaviour is fully
		// preserved.
		adapterDirs := lockfileDiscovered[lockfileAdapter.Language]
		if eco.active(lockfileAdapter.Language) {
			adapterDirs = ensureRootFirst(adapterDirs, moduleRoot)
		}
		if len(adapterDirs) == 0 {
			continue // adapter not active anywhere in this tree
		}

		// Aggregate the dependency closure across all discovered project directories.
		// Each directory is parsed independently; results are merged and deduped so
		// OSV is queried exactly once per unique normalised name@version.
		var aggDeps []ResolvedDep
		aggComplete := true
		for _, dir := range adapterDirs {
			dirDeps, complete, parseErr := lockfileAdapter.ParseLockfile(dir)
			if parseErr != nil {
				fmt.Fprintf(os.Stderr,
					"warning: %s lockfile parse failed (dir %s): %v; "+
						"%s deps in that directory were not checked; scan marked incomplete\n",
					lockfileAdapter.Language, dir, parseErr, lockfileAdapter.Language)
				incomplete = true
				aggComplete = false
				continue
			}
			if !complete {
				// An incomplete closure for this directory. Mark aggregate incomplete
				// (→ exit 3, never a false-clean exit 0) and split on whether the
				// adapter returned anything usable.
				aggComplete = false
				if len(dirDeps) == 0 {
					// No usable closure: no static parser, an unrecognised lockfile, or a
					// manifest with nothing statically resolvable. Nothing to query.
					fmt.Fprintf(os.Stderr,
						"warning: %s ecosystem detected in %s but its dependency closure could not be "+
							"resolved statically; %s deps there were not checked for vulnerabilities; "+
							"scan marked incomplete\n",
						lockfileAdapter.Language, dir, lockfileAdapter.Language)
					continue
				}
				// Partial closure: declared/direct deps resolved, but the full transitive
				// closure is unknown (e.g. Maven pom.xml or a .NET .csproj without running
				// the build tool). Fall through to query OSV for the KNOWN deps — a match
				// on a resolved dep is a sound PACKAGE_REACHABLE positive — while the scan
				// stays incomplete so the unresolved portion never reads as a false-clean.
				fmt.Fprintf(os.Stderr,
					"warning: %s dependency closure is partial in %s (declared/direct deps only; "+
						"transitives unresolved without running the build tool); the known deps "+
						"were checked but the scan is marked incomplete\n",
					lockfileAdapter.Language, dir)
			}
			aggDeps = append(aggDeps, dirDeps...)
		}

		if !aggComplete {
			incomplete = true
		}

		// Dedup aggregated deps by normalised name@version before querying OSV.
		// "runtime" wins when the same dep has different DepTypes across sub-projects.
		deps := dedupLockfileDeps(aggDeps, lockfileAdapter.NormalizeName)

		// Query OSV advisories for the resolved closure (full when complete=true,
		// declared/direct-only when this is a partial closure that fell through above).
		// OSV is the only source with coverage for lockfile-static ecosystems; go-vuln-db covers
		// only "Go" and returns (nil,nil) for all others.
		if len(deps) > 0 && !selectedSources[advisory.SourceOSV] {
			fmt.Fprintf(os.Stderr,
				"warning: %s deps found but no %s-capable advisory source is selected "+
					"(osv.dev covers %s; go-vuln-db does not); "+
					"%s packages were not checked for vulnerabilities; scan marked incomplete\n",
				lockfileAdapter.Language, lockfileAdapter.Language, lockfileAdapter.Ecosystem, lockfileAdapter.Language)
			incomplete = true
		}

		if len(deps) > 0 && selectedSources[advisory.SourceOSV] {
			cacheDir, cacheErr := os.UserCacheDir()
			if cacheErr != nil {
				fmt.Fprintf(os.Stderr, "commit0-analyzer scan: cannot locate user cache dir: %v\n", cacheErr)
				return policy.ExitOperationalError
			}
			osvCacheDir := filepath.Join(cacheDir, "commit0-analyzer", "osv")

			lockfileOSV := advisory.NewOSVBundleSource(osvCacheDir)
			if override := os.Getenv("COMMIT0_OSV_DB_URL"); override != "" {
				lockfileOSV.BaseURL = override
			}
			lockfileOSV.ForceUpdate = flags.update

			addLockfileOSV := true
			if !flags.offline && flags.dbSnapshot == "" {
				if refreshErr := lockfileOSV.Refresh(ctx, lockfileAdapter.Ecosystem); refreshErr != nil {
					fmt.Fprintf(os.Stderr,
						"warning: OSV %s source refresh failed (%s): %v; scan marked incomplete\n",
						lockfileAdapter.Language, advisory.SourceOSV, refreshErr)
					incomplete = true
					addLockfileOSV = false
				}
			} else {
				if !osvCacheDirExists(osvCacheDir, lockfileAdapter.Ecosystem) {
					if flags.sourceExplicit {
						fmt.Fprintf(os.Stderr,
							"warning: OSV %s cache not populated at %s (run without --offline to fetch); "+
								"OSV %s source skipped, scan marked incomplete\n",
							lockfileAdapter.Language,
							filepath.Join(osvCacheDir, lockfileAdapter.Ecosystem),
							lockfileAdapter.Language)
						incomplete = true
					}
					addLockfileOSV = false
				}
			}

			if addLockfileOSV {
				lockfileNamedSources := []advisory.NamedSource{
					{Name: advisory.SourceOSV, S: lockfileOSV, Trust: trustOSV},
				}
				lockfileNamedSources = appendSecondarySources(lockfileNamedSources, selectedSources, cacheDir, flags.offline)
				lockfileMultiSrc := advisory.NewMultiSource(lockfileNamedSources...)
				lockfileEnrichChain := buildEnrichmentChain(cacheDir, flags.offline, selectedSources)

				lockfileResolveDeps := make([]advisoryDep, len(deps))
				for i, dep := range deps {
					// Apply adapter-specific name normalization.
					// Default (NormalizeName==nil) is identity: Maven coordinates are
					// case-sensitive and OSV records preserve their case; do NOT lowercase.
					// A future PyPI adapter would set NormalizeName=strings.ToLower.
					normalizedName := dep.Name
					if lockfileAdapter.NormalizeName != nil {
						normalizedName = lockfileAdapter.NormalizeName(normalizedName)
					}
					desc := lockfileAdapter.Language + " pkg " + dep.Name + "@" + dep.Version
					lockfileResolveDeps[i] = advisoryDep{
						QueryName:       normalizedName,
						Version:         dep.Version,
						Module:          dep.Name,
						DepType:         dep.DepType,
						SourcesFailDesc: desc,
						Desc:            desc,
					}
				}
				resolveDepAdvisories(ctx, advisoryResolution{
					Ecosystem:    lockfileAdapter.Ecosystem,
					Source:       lockfileMultiSrc,
					Enrich:       lockfileEnrichChain,
					ProtoAdvs:    &protoAdvs,
					SourcesByID:  sourcesByID,
					AdvByID:      advByID,
					SeverityByID: severityByID,
					// Dep-type segmentation for the gate (same semantics as Python path):
					// "runtime" wins; empty dep-type is treated as runtime (unknown ≠ safe).
					DepTypeByAdv: depTypeByAdvID,
					Incomplete:   &incomplete,
					// Generate a lockfile-static finding directly from the advisory match.
					// No reachability plugin exists for these ecosystems; the host converts
					// OSV advisory matches into PACKAGE_REACHABLE findings.
					// Undecidable matches become CONFIDENCE_UNKNOWN + Incomplete=true so
					// the policy gate correctly exits 3 rather than silently passing clean.
					PerAdvisory: func(dep advisoryDep, adv *advisory.Advisory) {
						lockfileConf := ceilingToConfidence(lockfileAdapter.MaxConfidence)
						if adv.Incomplete {
							lockfileConf = commit0v1.Confidence_CONFIDENCE_UNKNOWN
						}
						lockfileFindings = append(lockfileFindings, &commit0v1.Finding{
							Advisory: &commit0v1.AdvisoryRef{
								Id:      adv.ID,
								Aliases: append([]string(nil), adv.Aliases...),
							},
							Module:     dep.Module,
							Confidence: lockfileConf,
							Incomplete: adv.Incomplete,
							Pillar:     "sca",
							Language:   lockfileAdapter.Language,
						})
					},
				}, lockfileResolveDeps)
			}
		}
	}

	// ── 5f. Unsupported ecosystems (python when plugin absent, and rust
	// when the rust plugin binary is absent) ──────────────────────────────────
	//
	// Warn and mark incomplete (→ exit 3) for every detected ecosystem that
	// has no scan path (no advisory query, no plugin), mirroring the
	// npm-no-capable-source guard above.
	//
	// Lockfile-static adapters that ran in step 5e (whether complete or
	// incomplete) are removed from unsupportedEco before the call so
	// warnUnsupportedEcosystems does not emit a duplicate warning for those
	// ecosystems. ecosystems is a map (reference type): clone before reducing so
	// the plugin-registration reads of eco below are not corrupted.
	unsupportedEco := eco.clone() // copy; reduce below as plugins are confirmed
	if rustManifest != nil {
		unsupportedEco.clear("rust") // Rust plugin binary is available
	}
	if pythonManifest != nil {
		unsupportedEco.clear("python") // Python plugin binary is available
	}
	// Clear lockfile-static ecosystems: they were handled by the registry loop
	// above. Also clear for adapters that ran solely via subdirectory discovery
	// (i.e. eco.active is false but manifests were found in subdirs); their eco
	// entry is already absent so clear is a no-op, but the explicit check ensures
	// we don't accidentally leave a root-detected flag set when discovery also
	// produced results.
	for _, lockfileAdapter := range lockfileAdapters() {
		if eco.active(lockfileAdapter.Language) || len(lockfileDiscovered[lockfileAdapter.Language]) > 0 {
			unsupportedEco.clear(lockfileAdapter.Language)
		}
	}
	if warnUnsupportedEcosystems(unsupportedEco, os.Stderr) {
		incomplete = true
	}

	// ── 6. Build AnalyzeRequest ───────────────────────────────────────────────
	req := &commit0v1.AnalyzeRequest{
		ModuleRoot: moduleRoot,
		Advisories: protoAdvs,
		BuildConfig: &commit0v1.BuildConfig{
			Goos:   flags.goos,
			Goarch: flags.goarch,
		},
	}
	if flags.tags != "" {
		req.BuildConfig.Tags = strings.Split(flags.tags, ",")
	}

	// ── 7. Locate / build plugins and register ────────────────────────────────
	//
	// --skip-reachability-analysis short-circuits the entire call-graph plugin
	// step for the plugin ecosystems (Go/JS/Rust/Python). The matched advisories
	// were already converted to package-level CONFIDENCE_UNKNOWN findings during
	// the per-ecosystem advisory loops (pkgLevelFindings). Because the plugin
	// never runs, no NOT_REACHABLE verdict is ever produced — skipping
	// reachability can only widen a finding to UNKNOWN, never narrow it to a
	// false-clean. lockfile-static findings (step 5e) are unaffected either way.
	var findings []*commit0v1.Finding
	if flags.skipReachabilityAnalysis {
		findings = append(findings, pkgLevelFindings...)
		// A real advisory match must never read as a clean pass when reachability
		// was not computed. Marking the scan incomplete guarantees a non-zero exit
		// for any match the severity gate does not already fail on (a high/critical
		// match still exits 1 — gate failure takes precedence over incompleteness).
		if len(pkgLevelFindings) > 0 {
			incomplete = true
		}
	} else {
		reg := host.NewRegistry()

		if eco.active("go") {
			pluginBin := flags.pluginBin
			if pluginBin == "" {
				var buildErr error
				pluginBin, buildErr = buildPlugin(ctx)
				if buildErr != nil {
					fmt.Fprintf(os.Stderr, "commit0-analyzer scan: build plugin: %v\n", buildErr)
					return policy.ExitOperationalError
				}
			}
			var absErr error
			pluginBin, absErr = filepath.Abs(pluginBin)
			if absErr != nil {
				fmt.Fprintf(os.Stderr, "commit0-analyzer scan: resolve plugin binary path: %v\n", absErr)
				return policy.ExitOperationalError
			}

			pluginHash, hashErr := host.SHA256OfFile(pluginBin)
			if hashErr != nil {
				fmt.Fprintf(os.Stderr, "commit0-analyzer scan: hash plugin binary: %v\n", hashErr)
				return policy.ExitOperationalError
			}

			if addErr := reg.Add(&host.Manifest{
				Name:      "go-reachability",
				ExecPath:  pluginBin,
				Pillar:    "sca",
				Languages: []string{"go"},
				SHA256:    pluginHash,
			}); addErr != nil {
				fmt.Fprintf(os.Stderr, "commit0-analyzer scan: register go plugin: %v\n", addErr)
				return policy.ExitOperationalError
			}
		}

		if eco.active("js") {
			m, buildErr := buildJSPluginManifest(flags.jsPluginBin)
			if buildErr != nil {
				fmt.Fprintf(os.Stderr, "commit0-analyzer scan: js plugin not available: %v\n", buildErr)
				return policy.ExitOperationalError
			}
			if addErr := reg.Add(m); addErr != nil {
				fmt.Fprintf(os.Stderr, "commit0-analyzer scan: register js plugin: %v\n", addErr)
				return policy.ExitOperationalError
			}
		}

		// Register the Rust plugin when its manifest was successfully built in step 5c.
		// rustManifest is non-nil only when eco.active("rust") && the binary is present.
		if rustManifest != nil {
			if addErr := reg.Add(rustManifest); addErr != nil {
				fmt.Fprintf(os.Stderr, "commit0-analyzer scan: register rust plugin: %v\n", addErr)
				return policy.ExitOperationalError
			}
		}

		// Register the Python plugin when its manifest was successfully built in step 5d.
		// pythonManifest is non-nil only when eco.active("python") && the binary is present.
		if pythonManifest != nil {
			if addErr := reg.Add(pythonManifest); addErr != nil {
				fmt.Fprintf(os.Stderr, "commit0-analyzer scan: register python plugin: %v\n", addErr)
				return policy.ExitOperationalError
			}
		}

		// Signal offline mode to child plugins via environment. The Rust plugin reads
		// COMMIT0_CARGO_OFFLINE to decide whether to pass --offline to cargo metadata.
		// Plugin subprocesses inherit the host process environment (go-plugin uses
		// exec.CommandContext with no explicit cmd.Env override), and the plugin's
		// sanitized cargo env allowlists COMMIT0_CARGO_OFFLINE so it flows through to
		// the cargo subprocess. We unset it when not in offline mode so a stale env
		// var from a parent process cannot accidentally trigger offline mode.
		if flags.offline {
			_ = os.Setenv("COMMIT0_CARGO_OFFLINE", "1")
		} else {
			_ = os.Unsetenv("COMMIT0_CARGO_OFFLINE")
		}

		stopPluginRun := telemetry.Span("scan.plugin.run")
		results, runErr := host.Run(ctx, reg, req, host.RunOptions{})
		stopPluginRun()
		if runErr != nil {
			fmt.Fprintf(os.Stderr, "commit0-analyzer scan: host.Run: %v\n", runErr)
			return policy.ExitOperationalError
		}

		// Collect all findings and detect plugin errors.
		//
		// Ecosystem-agnostic incomplete signal: a plugin may signal partial analysis by
		// emitting a synthetic UNKNOWN finding with Properties["synthetic"]="true".
		// This is the same marker that host.Run appends on crash (see run.go:syntheticUnknown);
		// a clean plugin that detects its own partiality (e.g. partial resolve, no-venv,
		// missing environment) MUST emit the same shape to propagate incomplete=true here.
		//
		// Wire contract (plugin author-facing):
		//   1. For each advisory the plugin cannot decide (partial resolve, killed analysis,
		//      dynamic dispatch, missing environment, unparseable version), emit:
		//        Finding{Confidence: CONFIDENCE_UNKNOWN, Properties: {"synthetic": "true"}}
		//   2. Return from the Analyze stream without error (normal EOF).
		//   The host reads Properties["synthetic"]=="true" on CONFIDENCE_UNKNOWN findings
		//   and sets incomplete=true at the policy gate, ensuring the scan exits 3 (not 0).
		//
		// This generalises the JS modelIncomplete→incomplete path (listNPMDeps returns a
		// bool that callers must forward) into a single, language-agnostic detection pass
		// that every ecosystem plugin can use without any per-language host-side wiring.
		for _, pr := range results {
			if pr.Err != nil {
				fmt.Fprintf(os.Stderr, "commit0-analyzer scan: plugin %s error: %v\n",
					pr.Manifest.Name, pr.Err)
				incomplete = true
			}
			findings = append(findings, pr.Findings...)
		}
	}
	// Merge lockfile-static findings generated in step 5e. These were produced directly
	// from OSV advisory matches without a plugin; stampAdvisorySeverity,
	// stampDepType, and stampSources apply equally to them because severityByID,
	// depTypeByAdvID, and sourcesByID were all populated during step 5e.
	findings = append(findings, lockfileFindings...)
	// Check whether any finding carries the synthetic partiality marker.
	// This covers plugins that ran to completion but detected their own analysis gap.
	if hasPartialityMarker(findings) {
		incomplete = true
	}

	// ── 7b. Stamp advisory severity ───────────────────────────────────────────
	// Join findings with the advisory's CVSS-derived severity (populated from
	// the OSV severity[] array during the advisory query loop above). Only fills
	// SEVERITY_UNSPECIFIED slots — never downgrades a severity a plugin already
	// set as more specific (e.g. a plugin may have a narrower CVSS override).
	stampAdvisorySeverity(findings, severityByID)

	// ── 7b2. Stamp default severity ───────────────────────────────────────────
	// After the advisory join, any finding still UNSPECIFIED and reachable gets
	// a conservative HIGH default so the policy gate can function without CVSS data.
	// This is the fallback; the advisory join above is the preferred source.
	stampDefaultSeverity(findings)

	// ── 7c. Stamp source attribution ──────────────────────────────────────────
	// Make the multi-source merge visible: record which source(s) reported each
	// finding's advisory into properties["sources"] (e.g. "go-vuln-db,osv.dev").
	stampSources(findings, sourcesByID)

	// ── 7d. Stamp dep_type ────────────────────────────────────────────────────
	// For Python findings, record the dependency classification (runtime |
	// optional-extra | dev | test | docs) into properties["dep_type"].
	// This makes the dep_type visible in all output formats and lets the policy
	// gate apply dep-type aware confidence-tiered gating.
	stampDepType(findings, depTypeByAdvID)

	// ── 7e. Stamp fused risk prioritization ───────────────────────────────────
	// Fuse each finding's reachability tier (its confidence) with the matched
	// advisory's CVSS/EPSS/KEV/CWE enrichment into a deterministic risk score and
	// stamp it onto properties (risk_score, risk_tier, risk_rationale, cvss, epss,
	// kev, cwe). SARIF rank, the table RISK column, and JSON risk field all read
	// these properties. Additive metadata only — the default gate is unaffected.
	stampRisk(findings, advByID)

	// ── 7f. Stamp cross-source provenance & conflict audit trail ──────────────
	// Surface the evidence behind the merge layer's fail-safe resolution: which
	// sources contributed (provenance, always when source metadata exists) and,
	// when present, where they disagreed on severity (severity_conflict) or were
	// stale (stale_source). This never recomputes the resolved facts — it renders
	// what mergeAdvisories already decided. Additive metadata; the gate is
	// unaffected and stale data never flips a result to "safe".
	stampProvenance(findings, advByID)

	// ── 8. Render output ──────────────────────────────────────────────────────
	if renderErr := renderFindings(flags.format, findings); renderErr != nil {
		fmt.Fprintf(os.Stderr, "commit0-analyzer scan: render: %v\n", renderErr)
		return policy.ExitOperationalError
	}

	// ── 8b. Emit VEX (opt-in) ─────────────────────────────────────────────────
	// VEX is an additional output, independent of the gate and exit code. A
	// requested-but-failed VEX emission is an operational error (exit 3) — never
	// a silent skip. The status mapping (NOT_REACHABLE→not_affected, reachable→
	// affected, UNKNOWN/incomplete→under_investigation) lives in internal/vex and
	// is the phase's cardinal-sin guard against false-clean output.
	if flags.vexFormat != "" {
		if vexErr := emitVEX(flags, findings, advByID, incomplete); vexErr != nil {
			fmt.Fprintf(os.Stderr, "commit0-analyzer scan: vex: %v\n", vexErr)
			return policy.ExitOperationalError
		}
	}

	// ── 9. Evaluate policy gate ───────────────────────────────────────────────
	pol, polErr := loadPolicyFromFlags(flags)
	if polErr != nil {
		fmt.Fprintf(os.Stderr, "commit0-analyzer scan: policy: %v\n", polErr)
		return policy.ExitOperationalError
	}

	return pol.EvaluateWithFlags(findings, policy.EvalFlags{Incomplete: incomplete})
}

// hasPartialityMarker reports whether any finding in the slice signals
// incomplete analysis. Two wire contracts are honored:
//
//  1. The ecosystem-agnostic synthetic-partiality marker: a CONFIDENCE_UNKNOWN
//     finding whose Properties map contains the key "synthetic" set to "true".
//     This is emitted by the host's syntheticUnknown (run.go) on plugin crash
//     and SHOULD be emitted by any plugin that detects its own partiality.
//
//  2. The Finding.Incomplete proto field (plugin.proto:10): any finding with
//     Incomplete=true signals that the analysis producing it was partial. The
//     Rust plugin sets this field (not Properties["synthetic"]) when cargo
//     metadata fails or returns a partial closure. Both signals are equivalent
//     — either one sets incomplete=true at the policy gate.
//
// Both are honored to support:
//   - Plugins (e.g. go-reachability, js-reachability) that use the Properties
//     path (legacy wire contract), and
//   - Plugins (e.g. rust-reachability) that use Finding.Incomplete (proto field).
func hasPartialityMarker(findings []*commit0v1.Finding) bool {
	for _, f := range findings {
		// Proto field: Incomplete=true (Rust plugin partiality signal).
		if f.GetIncomplete() {
			return true
		}
		// Properties marker: synthetic=true on CONFIDENCE_UNKNOWN (crash/host signal).
		if f.GetConfidence() == commit0v1.Confidence_CONFIDENCE_UNKNOWN &&
			f.GetProperties()["synthetic"] == "true" {
			return true
		}
	}
	return false
}

// packageLevelFinding builds a CONFIDENCE_UNKNOWN finding directly from a matched
// advisory for the --skip-reachability-analysis path. No call-graph reachability
// was computed, so the confidence is UNKNOWN (we cannot narrow to NOT_REACHABLE —
// unknown ≠ safe). The per-finding Incomplete flag mirrors the advisory's own
// undecidability (e.g. an unparseable version); the scan-level incomplete signal
// for "reachability was skipped" is set by the caller so a real advisory match
// can never read as a clean pass.
func packageLevelFinding(adv *advisory.Advisory, module, language string) *commit0v1.Finding {
	return &commit0v1.Finding{
		Advisory: &commit0v1.AdvisoryRef{
			Id:      adv.ID,
			Aliases: append([]string(nil), adv.Aliases...),
		},
		Module:     module,
		Confidence: commit0v1.Confidence_CONFIDENCE_UNKNOWN,
		Incomplete: adv.Incomplete,
		Pillar:     "sca",
		Language:   language,
	}
}

// advisorySeverityToProto maps the internal advisory.Severity to the wire
// commit0v1.Severity enum. The values are intentionally parallel (both ordered
// Unspecified < Low < Medium < High < Critical), so a direct cast works, but
// we keep an explicit mapping to make the coupling visible and catch drift.
func advisorySeverityToProto(s advisory.Severity) commit0v1.Severity {
	switch s {
	case advisory.SeverityLow:
		return commit0v1.Severity_SEVERITY_LOW
	case advisory.SeverityMedium:
		return commit0v1.Severity_SEVERITY_MEDIUM
	case advisory.SeverityHigh:
		return commit0v1.Severity_SEVERITY_HIGH
	case advisory.SeverityCritical:
		return commit0v1.Severity_SEVERITY_CRITICAL
	default:
		return commit0v1.Severity_SEVERITY_UNSPECIFIED
	}
}

// stampAdvisorySeverity joins each finding with the CVSS-derived severity from
// the matched advisory (keyed by advisory ID). It only fills SEVERITY_UNSPECIFIED
// slots — if a plugin already set a more specific severity it is preserved.
// Findings with no advisory (synthetic/crash markers) are skipped.
func stampAdvisorySeverity(findings []*commit0v1.Finding, severityByID map[string]advisory.Severity) {
	for _, f := range findings {
		// Only fill slots the plugin left as UNSPECIFIED.
		if f.GetSeverity() != commit0v1.Severity_SEVERITY_UNSPECIFIED {
			continue
		}
		if f.GetAdvisory() == nil {
			continue
		}
		advSev, ok := severityByID[f.GetAdvisory().GetId()]
		if !ok || advSev == advisory.SeverityUnspecified {
			continue
		}
		f.Severity = advisorySeverityToProto(advSev)
	}
}

// stampDefaultSeverity conservatively stamps SEVERITY_HIGH onto findings that
// are reachable (SYMBOL_REACHABLE or PACKAGE_REACHABLE) but carry no severity.
// This ensures the policy gate works when the advisory source does not provide
// a severity field (e.g. the corpus test snapshot and older Go vuln DB entries).
//
// Rationale: a reachable vulnerability with unknown severity is conservatively
// HIGH rather than UNSPECIFIED (which would never trip the gate). Callers that
// have advisory-level CVSS scores should populate Finding.Severity from those
// scores instead of relying on this default.
func stampDefaultSeverity(findings []*commit0v1.Finding) {
	for _, f := range findings {
		if f.GetSeverity() != commit0v1.Severity_SEVERITY_UNSPECIFIED {
			continue
		}
		switch f.GetConfidence() {
		case commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
			commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE:
			f.Severity = commit0v1.Severity_SEVERITY_HIGH
		}
		// UNKNOWN and NOT_REACHABLE keep SEVERITY_UNSPECIFIED.
	}
}

// stampSources records, for each finding, which advisory source(s) reported the
// underlying advisory, into properties["sources"] (e.g. "go-vuln-db,osv.dev").
// The Finding carries only an advisory reference, so without this the merged
// multi-source attribution would not be visible in JSON/SARIF/table output.
// Synthetic findings (e.g. a plugin crash, which have no advisory) are skipped.
func stampSources(findings []*commit0v1.Finding, sourcesByID map[string][]string) {
	for _, f := range findings {
		if f.GetAdvisory() == nil {
			continue
		}
		srcs := sourcesByID[f.GetAdvisory().GetId()]
		if len(srcs) == 0 {
			continue
		}
		if f.Properties == nil {
			f.Properties = map[string]string{}
		}
		f.Properties["sources"] = strings.Join(srcs, ",")
	}
}

// stampDepType records the dependency classification (dep_type) for Python
// findings into properties["dep_type"]. The depTypeByAdvID map is populated
// during the PyPI OSV advisory query loop. Only findings whose advisory ID is
// present in the map are tagged; other ecosystem findings are left untagged
// (the policy gate treats missing dep_type as runtime — conservative default).
//
// This makes the dep_type visible in all output formats (SARIF properties,
// JSON, table) and is the data that lets the policy gate apply dep-type aware
// confidence-tiered gating without any per-language wiring in the gate itself.
func stampDepType(findings []*commit0v1.Finding, depTypeByAdvID map[string]string) {
	for _, f := range findings {
		if f.GetAdvisory() == nil {
			continue
		}
		dt, ok := depTypeByAdvID[f.GetAdvisory().GetId()]
		if !ok || dt == "" {
			continue
		}
		if f.Properties == nil {
			f.Properties = map[string]string{}
		}
		f.Properties["dep_type"] = dt
	}
}

// reachabilityTierFromConfidence maps a wire Confidence enum to the advisory
// package's reachability-tier string used by advisory.Score. NOT_REACHABLE is
// the only proven-safe tier (scores 0); an unrecognised value is treated as
// UNKNOWN (conservative: unknown ≠ safe).
func reachabilityTierFromConfidence(c commit0v1.Confidence) string {
	switch c {
	case commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE:
		return advisory.ReachabilitySymbol
	case commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE:
		return advisory.ReachabilityPackage
	case commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE:
		return advisory.ReachabilityNotReachable
	default:
		return advisory.ReachabilityUnknown
	}
}

// stampRisk computes the fused risk score for each finding and stamps the result
// onto its properties. The reachability input is the finding's own confidence;
// the CVSS/EPSS/KEV/CWE inputs come from the matched advisory (advByID). Findings
// with no matched advisory (synthetic/crash markers) are skipped.
//
// Stamped keys: risk_score, risk_tier, risk_rationale, and the underlying signals
// cvss, epss, kev, cwe when present. These are additive metadata: the default
// policy gate ignores them unless the user opts in via --gate-on kev|epss>=X|risk>=Y.
func stampRisk(findings []*commit0v1.Finding, advByID map[string]*advisory.Advisory) {
	for _, f := range findings {
		if f.GetAdvisory() == nil {
			continue
		}
		adv, ok := advByID[f.GetAdvisory().GetId()]
		if !ok || adv == nil {
			continue
		}

		rs := advisory.Score(adv, reachabilityTierFromConfidence(f.GetConfidence()))

		if f.Properties == nil {
			f.Properties = map[string]string{}
		}
		f.Properties["risk_score"] = strconv.FormatFloat(rs.Score, 'f', 1, 64)
		f.Properties["risk_tier"] = rs.Tier
		if rs.Rationale != "" {
			f.Properties["risk_rationale"] = rs.Rationale
		}

		// Underlying signals, surfaced for visibility (never gate by default).
		if vec, score, has := advisory.BestCVSS(adv); has {
			if score > 0 {
				f.Properties["cvss"] = strconv.FormatFloat(score, 'f', 1, 64)
			} else if vec != "" {
				// Unscored (e.g. v4.0) vector: surface the vector losslessly.
				f.Properties["cvss"] = vec
			}
		}
		if adv.EPSS != nil {
			f.Properties["epss"] = strconv.FormatFloat(adv.EPSS.Probability, 'f', -1, 64)
		}
		if adv.KEV != nil {
			f.Properties["kev"] = strconv.FormatBool(adv.KEV.Listed)
		}
		if len(adv.CWEs) > 0 {
			f.Properties["cwe"] = strings.Join(adv.CWEs, ",")
		}
	}
}

// freshnessSLA is the source-freshness policy used to flag stale advisory
// sources. A source older than Soft is reported in properties["stale_source"]
// (warn-only). HardIncomplete is deliberately left false: stale advisory data is
// a warning, never a surprise exit-3 — staleness must not silently flip a result.
var freshnessSLA = advisory.FreshnessSLA{Soft: 72 * time.Hour, Hard: 720 * time.Hour}

// stampProvenance records the cross-source audit trail onto each finding's
// properties from its matched advisory's source metadata (populated by the merge
// layer's conflict resolution). provenance — the deterministic per-source
// severity/freshness summary — is stamped whenever source metadata exists;
// severity_conflict and stale_source are stamped only when a real disagreement
// or stale source exists. The strings come from the advisory package's
// resolution helpers, so the resolved facts are never recomputed here, only
// surfaced. Findings with no matched advisory or no source metadata are skipped.
func stampProvenance(findings []*commit0v1.Finding, advByID map[string]*advisory.Advisory) {
	now := time.Now()
	for _, f := range findings {
		if f.GetAdvisory() == nil {
			continue
		}
		adv, ok := advByID[f.GetAdvisory().GetId()]
		if !ok || adv == nil || len(adv.SourceMeta) == 0 {
			continue
		}
		prov := advisory.ProvenanceString(adv.SourceMeta)
		if prov == "" {
			continue
		}
		if f.Properties == nil {
			f.Properties = map[string]string{}
		}
		f.Properties["provenance"] = prov
		if conflict := advisory.SeverityConflictString(adv.SourceMeta); conflict != "" {
			f.Properties["severity_conflict"] = conflict
		}
		if stale, _ := freshnessSLA.Evaluate(adv.SourceMeta, now); len(stale) > 0 {
			f.Properties["stale_source"] = advisory.StaleSourceString(stale)
		}
	}
}

// renderFindings writes findings to stdout in the requested format.
func renderFindings(format string, findings []*commit0v1.Finding) error {
	switch strings.ToLower(format) {
	case "sarif":
		data, err := render.ToSARIF(findings)
		if err != nil {
			return fmt.Errorf("SARIF render: %w", err)
		}
		_, err = os.Stdout.Write(data)
		return err
	case "json":
		data, err := render.ToJSON(findings)
		if err != nil {
			return fmt.Errorf("JSON render: %w", err)
		}
		_, err = os.Stdout.Write(data)
		return err
	case "table":
		_, err := os.Stdout.Write(render.ToTable(findings))
		return err
	default:
		return fmt.Errorf("unknown format %q: must be sarif|json|table", format)
	}
}

// emitVEX builds a VEX document from the findings and their matched advisories
// and writes it in the requested format(s). Findings with no matched advisory
// (synthetic/crash markers) are skipped — they carry no vulnerability to attest
// to. The document timestamp is injected once here so the formatters stay pure
// and reproducible.
//
// scanIncomplete is the scan-level aggregate incompleteness signal. It is ORed
// into every statement's per-finding Incomplete flag: some ecosystems (e.g. the JS
// modelIncomplete path) mark only the scan incomplete without stamping each
// finding, so a NOT_REACHABLE verdict proven over that partial dependency
// closure must still degrade to under_investigation — never not_affected. This
// is the cardinal-sin guard (a false-clean VEX statement on an incomplete graph).
func emitVEX(flags scanFlags, findings []*commit0v1.Finding, advByID map[string]*advisory.Advisory, scanIncomplete bool) error {
	formatters, err := vex.Formatters(flags.vexFormat)
	if err != nil {
		return err
	}
	if len(formatters) == 0 {
		return nil
	}

	inputs := make([]vex.StatementInput, 0, len(findings))
	for _, f := range findings {
		ref := f.GetAdvisory()
		if ref == nil || ref.GetId() == "" {
			continue
		}
		in := vex.StatementInput{
			VulnID:       ref.GetId(),
			Aliases:      append([]string(nil), ref.GetAliases()...),
			PackageName:  f.GetModule(),
			Reachability: vexReachability(f.GetConfidence()),
			Incomplete:   f.GetIncomplete() || scanIncomplete,
		}
		if adv, ok := advByID[ref.GetId()]; ok && adv != nil {
			in.Ecosystem = adv.Ecosystem
			if adv.Module != "" {
				in.PackageName = adv.Module
			}
			in.FixedVersion = lowestFixedVersion(adv)
			if len(in.Aliases) == 0 {
				in.Aliases = append([]string(nil), adv.Aliases...)
			}
		}
		inputs = append(inputs, in)
	}

	doc := vex.BuildDocument(vexAssessmentTime(), inputs)
	return vex.Write(formatters, doc, flags.vexOut, os.Stdout)
}

// vexAssessmentTime returns the timestamp stamped on the VEX document. The
// timestamp feeds the openVEX id and CSAF tracking id hashes, so a wall-clock
// value makes output non-reproducible across runs. When SOURCE_DATE_EPOCH is set
// (the reproducible-builds convention, Unix seconds) it is honored verbatim,
// yielding byte-identical VEX for the same inputs; otherwise the assessment time
// is the current wall clock (the honest "when this was asserted" semantics).
func vexAssessmentTime() time.Time {
	if v := os.Getenv("SOURCE_DATE_EPOCH"); v != "" {
		if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
			return time.Unix(secs, 0).UTC()
		}
	}
	return time.Now().UTC()
}

// vexReachability maps a wire Confidence to the VEX package's reachability enum.
// CONFIDENCE_UNKNOWN (the zero value) maps to ReachabilityUnknown so an
// undetermined finding is never asserted not_affected.
func vexReachability(c commit0v1.Confidence) vex.Reachability {
	switch c {
	case commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE:
		return vex.ReachabilitySymbolReachable
	case commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE:
		return vex.ReachabilityPackageReachable
	case commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE:
		return vex.ReachabilityNotReachable
	default:
		return vex.ReachabilityUnknown
	}
}

// lowestFixedVersion returns the lexicographically smallest non-empty Fixed
// version across the advisory's ranges, for the VEX action statement. Returns ""
// when no fixed version is recorded (the action statement degrades to a generic
// mitigation message rather than inventing a version).
func lowestFixedVersion(adv *advisory.Advisory) string {
	lowest := ""
	for _, r := range adv.VersionRanges {
		if r.Fixed == "" {
			continue
		}
		if lowest == "" || r.Fixed < lowest {
			lowest = r.Fixed
		}
	}
	return lowest
}

// loadPolicyFromFlags loads a Policy from a file or synthesises one from flags.
func loadPolicyFromFlags(flags scanFlags) (*policy.Policy, error) {
	if flags.policyFile != "" {
		data, err := os.ReadFile(flags.policyFile)
		if err != nil {
			return nil, fmt.Errorf("read policy file %q: %w", flags.policyFile, err)
		}
		return policy.LoadPolicy(data)
	}

	// Synthesise a minimal policy from --fail-on and --gate-on flags.
	yamlSrc := fmt.Sprintf("fail-on: %s\n", flags.failOn)
	if flags.gateOn != "" {
		yamlSrc += fmt.Sprintf("gate-on: %s\n", flags.gateOn)
	}
	return policy.LoadPolicy([]byte(yamlSrc))
}

// npmDep is a resolved npm package dependency from the JS project model.
type npmDep struct {
	Ecosystem string `json:"ecosystem"` // always "npm"
	Name      string `json:"name"`
	Version   string `json:"version"`
	Workspace string `json:"workspace"`
	// Direct is true when the package is declared directly in the workspace's
	// dependencies or optionalDependencies (not only transitively reachable).
	// Omitted (false) when the field is absent in older plugin versions.
	Direct bool `json:"direct,omitempty"`
	// Dev is true when the package appears only in devDependencies for this
	// workspace (not in dependencies or optionalDependencies).
	// Omitted (false) when the field is absent in older plugin versions.
	Dev bool `json:"dev,omitempty"`
}

// listDepsOutput is the JSON shape emitted by the JS plugin's --list-deps mode.
type listDepsOutput struct {
	Deps       []npmDep          `json:"deps"`
	Incomplete []incompleteEntry `json:"incomplete"`
	// DeclaredDepCount is the total number of declared runtime deps across all
	// workspaces before resolution. The CLI uses this together with each entry's
	// Kind to determine whether to mark the scan incomplete.
	DeclaredDepCount int `json:"declaredDepCount"`
}

// incompleteEntry mirrors the IncompleteEntry shape from the JS plugin model.
type incompleteEntry struct {
	Scope  string `json:"scope"`
	Reason string `json:"reason"`
	// Kind categorizes the incomplete signal. "lockfile-corrupt" is error-level
	// and always marks the scan incomplete. Other kinds are suppressed when
	// DeclaredDepCount is 0 (no runtime deps to resolve, so no real coverage gap).
	Kind string `json:"kind"`
}

// listNPMDeps execs the JS plugin binary in --list-deps mode and returns the
// resolved npm dependency list for the project rooted at moduleRoot.
// It also returns whether the project model is incomplete.
//
// The incomplete signal is kind-aware:
//   - "lockfile-corrupt" entries always mark the model incomplete — a corrupt
//     lockfile is an error regardless of how many runtime deps are declared.
//     Suppressing it when declaredDepCount=0 would produce a false-negative for
//     projects with only devDependencies and a corrupt lockfile.
//   - All other incomplete kinds are suppressed when declaredDepCount=0, because
//     a missing lockfile on a project with no declared runtime deps is not a
//     concern (there is nothing that could be unresolvable).
//
// On any subprocess or parse failure it returns an error (never silently empty).
func listNPMDeps(ctx context.Context, pluginBin, moduleRoot string) ([]npmDep, bool, error) {
	cmd := exec.CommandContext(ctx, pluginBin, "--list-deps", moduleRoot)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, false, fmt.Errorf("js plugin --list-deps: %w\n%s", err, exitErr.Stderr)
		}
		return nil, false, fmt.Errorf("js plugin --list-deps: %w", err)
	}

	var result listDepsOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, false, fmt.Errorf("js plugin --list-deps: parse output: %w", err)
	}

	// Determine model-level incompleteness by kind:
	//   lockfile-corrupt → always incomplete (error-level signal).
	//   all other kinds  → incomplete only when there are declared deps to resolve.
	modelIncomplete := false
	for _, entry := range result.Incomplete {
		if entry.Kind == "lockfile-corrupt" {
			modelIncomplete = true
			break
		}
	}
	if !modelIncomplete && result.DeclaredDepCount > 0 && len(result.Incomplete) > 0 {
		modelIncomplete = true
	}

	return result.Deps, modelIncomplete, nil
}

// cargoDep is a resolved Rust crate dependency (name + version) extracted from
// `cargo metadata --format-version 1`. Used to query crates.io OSV advisories
// before the Rust reachability plugin runs. Only the fields needed for the
// advisory query are kept; full dependency graph data lives in the plugin.
type cargoDep struct {
	Name    string
	Version string
}

// sanitizedCargoEnv returns a filtered copy of the current process environment
// suitable for running `cargo` on untrusted repo sources. It:
//
//  1. Pins RUSTUP_TOOLCHAIN=stable so a repo-local rust-toolchain.toml cannot
//     hijack the toolchain (defense against supply-chain attacks).
//  2. Removes CARGO_HOME and RUSTUP_HOME overrides from the environment — only
//     the existing values (inherited from the parent shell) are preserved; a
//     repo cannot override them via the environment it injects.
//  3. Passes through an allowlist of safe variables (PATH, HOME, TMPDIR,
//     SSL_CERT_*, XDG_*, GITHUB_ACTIONS, CI, TERM) so the subprocess can find
//     the cargo binary and write to temp dirs, but cannot be influenced by
//     arbitrary env vars the parent process might have inherited.
//
// The result is intentionally conservative: unknown vars are excluded.
func sanitizedCargoEnv() []string {
	// Variables to always strip (override vectors for toolchain hijacking).
	strip := map[string]bool{
		"CARGO_HOME":       true,
		"RUSTUP_HOME":      true,
		"RUSTUP_TOOLCHAIN": true, // we pin it explicitly below
	}

	// Allowlist prefixes: variables whose names start with any of these are
	// forwarded. Exact matches and prefix matches are both checked.
	allowPrefixes := []string{
		"PATH",
		"HOME",
		"TMPDIR",
		"TEMP",
		"TMP",
		"SSL_CERT",
		"XDG_",
		"GITHUB_",
		"CI",
		"TERM",
		"USER",
		"LOGNAME",
		"LANG",
		"LC_",
		// Preserve existing CARGO_HOME and RUSTUP_HOME so they stay consistent
		// with the user's toolchain setup. We strip override attempts but keep
		// the inherited values (handled below via the strip map + re-add).
		// Proxy vars: required for online cargo metadata resolution behind a
		// corporate or CI proxy. Cargo respects these standard env vars for
		// HTTPS connections to the crates.io registry index.
		"HTTP_PROXY",
		"HTTPS_PROXY",
		"NO_PROXY",
		"http_proxy",
		"https_proxy",
		"no_proxy",
		"CARGO_HTTP_",
		// Offline mode signal forwarded from the host to the Rust plugin so
		// the plugin's own cargo metadata invocation can also honour offline mode.
		"COMMIT0_CARGO_OFFLINE",
	}

	var env []string
	var cargoHome, rustupHome string
	for _, kv := range os.Environ() {
		eqIdx := strings.Index(kv, "=")
		if eqIdx < 0 {
			continue
		}
		k := kv[:eqIdx]

		// Save the inherited CARGO_HOME / RUSTUP_HOME before stripping.
		if k == "CARGO_HOME" {
			cargoHome = kv[eqIdx+1:]
		}
		if k == "RUSTUP_HOME" {
			rustupHome = kv[eqIdx+1:]
		}

		if strip[k] {
			continue
		}
		allowed := false
		for _, pfx := range allowPrefixes {
			if k == pfx || strings.HasPrefix(k, pfx) {
				allowed = true
				break
			}
		}
		if allowed {
			env = append(env, kv)
		}
	}

	// Re-add inherited CARGO_HOME / RUSTUP_HOME (trusted — came from the parent shell).
	if cargoHome != "" {
		env = append(env, "CARGO_HOME="+cargoHome)
	}
	if rustupHome != "" {
		env = append(env, "RUSTUP_HOME="+rustupHome)
	}
	// Pin the toolchain to stable; overrides any rust-toolchain.toml in the repo.
	env = append(env, "RUSTUP_TOOLCHAIN=stable")

	return env
}

// listCargoDeps runs `cargo metadata --format-version 1` in moduleRoot,
// parses the resulting JSON, and returns a flat list of (name, version) pairs for
// every crate in the resolved closure.
//
// Security: cargo metadata does NOT execute build scripts (build.rs) or
// proc-macros, making it safe on untrusted repos (the same guarantee held by the
// Rust plugin's own cargo.LoadManifest call). The subprocess is run with a
// sanitized environment (see sanitizedCargoEnv) so a repo-local rust-toolchain.toml
// cannot hijack the toolchain and arbitrary env vars cannot influence the cargo
// invocation. RUSTUP_TOOLCHAIN=stable is always pinned.
//
// When offline is true (the user passed --offline), --offline is added to the
// cargo invocation so it reads only the already-fetched registry cache without
// hitting the network. When offline is false (the default), cargo fetches registry
// metadata as needed — this is required for fresh clones whose deps are not yet
// in the local cache. Cargo metadata only downloads index + crate metadata
// (not source tarballs and not build scripts), so online resolution is safe.
//
// Returns (deps, incomplete, err):
//   - deps: every crate present in the resolved packages[]; may be empty on
//     parse success with a trivial project.
//   - incomplete: true when cargo exited non-zero or the JSON was unparseable
//     (ClosureUnknown — the plugin will degrade, but we still need to mark the
//     host-side advisory query incomplete).
//   - err: non-nil when cargo is not on PATH or the process could not be started
//     (callers print a warning and propagate incomplete=true; they do NOT abort).
//
// Invariant: on any failure, incomplete is always true (unknown ≠ safe).
func listCargoDeps(ctx context.Context, moduleRoot string, offline bool) ([]cargoDep, bool, error) {
	args := []string{"metadata", "--format-version", "1", "--all-features"}
	if offline {
		args = append(args, "--offline")
	}
	cmd := exec.CommandContext(ctx, "cargo", args...)
	cmd.Dir = moduleRoot
	// Use a sanitized environment: pin RUSTUP_TOOLCHAIN=stable, strip
	// CARGO_HOME/RUSTUP_HOME override vectors, pass only an allowlisted set.
	cmd.Env = sanitizedCargoEnv()

	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, true, fmt.Errorf("cargo metadata: %w\n%s", err, exitErr.Stderr)
		}
		return nil, true, fmt.Errorf("cargo metadata: %w", err)
	}

	deps, incomplete, parseErr := parseCargoMetadataForDeps(out)
	if parseErr != nil {
		return nil, true, parseErr
	}
	return deps, incomplete, nil
}

// cargoMetadataMinimal is the minimal JSON shape of `cargo metadata --format-version 1`
// that listCargoDeps needs: just the flat packages[] list.
type cargoMetadataMinimal struct {
	Packages []cargoPackageMinimal `json:"packages"`
}

// cargoPackageMinimal holds only the name and version fields needed for advisory queries.
type cargoPackageMinimal struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// parseCargoMetadataForDeps parses the raw JSON output of `cargo metadata` and
// returns a flat (name, version) list for every crate in packages[].
//
// An empty packages list is treated as ClosureUnknown (incomplete=true) because
// a valid Cargo project always has at least one package. JSON parse errors also
// set incomplete=true and return a non-nil error.
func parseCargoMetadataForDeps(raw []byte) ([]cargoDep, bool, error) {
	var meta cargoMetadataMinimal
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil, true, fmt.Errorf("parse cargo metadata JSON: %w", err)
	}
	if len(meta.Packages) == 0 {
		// Cargo produced a valid JSON response but with no packages — treat as
		// partial/unknown (partiality invariant).
		return nil, true, nil
	}
	deps := make([]cargoDep, 0, len(meta.Packages))
	for _, p := range meta.Packages {
		if p.Name == "" || p.Version == "" {
			continue
		}
		deps = append(deps, cargoDep(p))
	}
	return deps, false, nil
}

// modDep is a resolved module dependency (path + version).
type modDep struct {
	Path    string
	Version string
}

// modPaths returns just the module paths from a dep list, for use with Refresh.
func modPaths(deps []modDep) []string {
	paths := make([]string, len(deps))
	for i, d := range deps {
		paths[i] = d.Path
	}
	return paths
}

// listModDeps uses `go list -m -json all` to enumerate module dependencies.
// It requires the module to be buildable (no broken replace directives).
// On failure it returns a clear error — callers must treat this as UNKNOWN,
// not as "no deps found" (Red Team #4: non-compiling → UNKNOWN).
func listModDeps(ctx context.Context, moduleRoot string) ([]modDep, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-m", "-json", "all")
	cmd.Dir = moduleRoot
	// Propagate GOPATH, GOMODCACHE etc. from the parent environment.
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod")

	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("go list -m all: %w\n%s", err, exitErr.Stderr)
		}
		return nil, fmt.Errorf("go list -m all: %w", err)
	}

	return parseGoListJSON(out), nil
}

// parseGoListJSON parses the concatenated JSON objects from `go list -m -json all`.
// Each module is a separate JSON object (not a JSON array) so we decode sequentially.
func parseGoListJSON(data []byte) []modDep {
	// `go list -m -json all` emits one JSON object per line-block, terminated by
	// newlines. We use a simple scanner: each top-level '{...}' block is one module.
	var deps []modDep
	s := string(data)
	for {
		start := strings.Index(s, "{")
		if start < 0 {
			break
		}
		end := findMatchingBrace(s, start)
		if end < 0 {
			break
		}
		block := s[start : end+1]
		s = s[end+1:]

		dep := parseModuleBlock(block)
		if dep.Path != "" && dep.Version != "" {
			deps = append(deps, dep)
		}
	}
	return deps
}

// findMatchingBrace returns the index of the closing '}' that matches the '{'
// at openIdx in s, counting depth. Returns -1 if not found.
func findMatchingBrace(s string, openIdx int) int {
	depth := 0
	for i := openIdx; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// parseModuleBlock extracts Path and Version from a single `go list -m -json` block.
// We parse manually to avoid importing encoding/json for a simple key extraction.
func parseModuleBlock(block string) modDep {
	return modDep{
		Path:    extractJSONStringField(block, "Path"),
		Version: extractJSONStringField(block, "Version"),
	}
}

// extractJSONStringField extracts a string JSON field value by key name.
func extractJSONStringField(s, key string) string {
	search := `"` + key + `"`
	idx := strings.Index(s, search)
	if idx < 0 {
		return ""
	}
	rest := s[idx+len(search):]
	// Find colon.
	colon := strings.Index(rest, ":")
	if colon < 0 {
		return ""
	}
	rest = rest[colon+1:]
	// Trim whitespace.
	rest = strings.TrimLeft(rest, " \t\r\n")
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	// Find closing quote (simple scan — values here are module paths and semver).
	rest = rest[1:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// parseSourceFlag validates and parses the --source comma list into a set of
// enabled canonical source names. Accepts both the short flag tokens (e.g. "osv")
// and the full canonical names (e.g. "osv.dev"). Returns an error when any
// token is unrecognised or the resulting set is empty.
func parseSourceFlag(flag string) (map[string]bool, error) {
	enabled := make(map[string]bool)
	for _, raw := range strings.Split(flag, ",") {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}
		canonical, ok := sourceAliases[token]
		if !ok {
			return nil, fmt.Errorf("unknown source %q: must be one of go-vuln-db, osv, ghsa, gitlab, nvd, nvd-cpe, epss", token)
		}
		enabled[canonical] = true
	}
	if len(enabled) == 0 {
		return nil, fmt.Errorf("at least one source must be enabled; got %q", flag)
	}
	return enabled, nil
}

// snapshotStalenessThreshold returns the age past which a pinned Go vuln DB
// snapshot is flagged stale. COMMIT0_SNAPSHOT_STALENESS overrides
// advisory.DefaultStalenessWarning with a Go duration string; an unset or
// unparseable value uses the production default, so there is no behavior change
// outside tests. It is a hermeticity seam: the E2E suite pins date-stamped corpus
// snapshots whose age would otherwise drift past the default 7-day threshold over
// calendar time, making the suite depend on wall-clock rather than its inputs.
func snapshotStalenessThreshold() time.Duration {
	if v := os.Getenv("COMMIT0_SNAPSHOT_STALENESS"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return advisory.DefaultStalenessWarning
}

// buildGHSASource constructs the GHSA source for the given user cache root. The
// offline OSV-format bundle under <cache>/commit0-analyzer/ghsa is the breadth
// floor; the live GraphQL layer is token-gated (GITHUB_TOKEN) and disabled in
// offline mode so --offline never touches the network. COMMIT0_GHSA_GRAPHQL_URL
// overrides the endpoint (test seam). A missing bundle directory makes Query a
// no-op (nil,nil), so attaching GHSA never converts "no advisory" into a failure.
func buildGHSASource(userCacheDir string, offline bool) advisory.Source {
	dir := filepath.Join(userCacheDir, "commit0-analyzer", "ghsa")
	if offline {
		// Offline: bundle floor only; never attempt the live GraphQL layer.
		return advisory.NewGHSASource(dir, advisory.WithGHSAGraphQLURL(""))
	}
	if override := os.Getenv("COMMIT0_GHSA_GRAPHQL_URL"); override != "" {
		return advisory.NewGHSASource(dir, advisory.WithGHSAGraphQLURL(override))
	}
	return advisory.NewGHSASource(dir)
}

// buildGitLabSource constructs the GitLab Advisory Database (gemnasium-db)
// source for the given user cache root. The extracted archive under
// <cache>/commit0-analyzer/gitlab is the offline floor; Query never touches the
// network (it reads the already-extracted cache), so offline mode needs no
// special handling here. COMMIT0_GITLAB_DB_URL overrides the gitlab.com base URL
// (test seam; also lets advanced users retarget the primary gemnasium-db host).
// A missing cache directory makes Query a no-op (nil,nil), so attaching GitLab
// never converts "no advisory" into a failure.
func buildGitLabSource(userCacheDir string) advisory.Source {
	dir := filepath.Join(userCacheDir, "commit0-analyzer", "gitlab")
	if override := os.Getenv("COMMIT0_GITLAB_DB_URL"); override != "" {
		return advisory.NewGitLabSource(dir, advisory.WithGitLabBaseURL(override))
	}
	return advisory.NewGitLabSource(dir)
}

// refreshGitLabArchive downloads and extracts the GitLab advisory archive once
// for the whole scan (gemnasium-db is a single archive covering every ecosystem,
// unlike the per-ecosystem OSV bundles). It returns incomplete=true when the
// source was requested but could not be made available, so the scan exits 3
// rather than passing false-clean (unknown ≠ safe). It never aborts: a refresh
// failure degrades to whatever cache already exists.
func refreshGitLabArchive(ctx context.Context, dir string, flags scanFlags) (incomplete bool) {
	if flags.offline || flags.dbSnapshot != "" {
		// Offline/snapshot: never fetch. A requested-but-empty cache is incomplete
		// only when the user explicitly selected gitlab; the default-on source
		// silently degrades to no advisories otherwise (backward compatible).
		if !gitlabCacheExists(dir) && flags.sourceExplicit {
			fmt.Fprintf(os.Stderr,
				"warning: GitLab advisory cache not populated at %s (run without --offline to fetch); "+
					"GitLab source skipped, scan marked incomplete\n", dir)
			return true
		}
		return false
	}

	var src *advisory.GitLabSource
	if override := os.Getenv("COMMIT0_GITLAB_DB_URL"); override != "" {
		src = advisory.NewGitLabSource(dir, advisory.WithGitLabBaseURL(override))
	} else {
		src = advisory.NewGitLabSource(dir)
	}
	src.ForceUpdate = flags.update

	if err := src.Refresh(ctx); err != nil {
		fmt.Fprintf(os.Stderr,
			"warning: GitLab advisory source refresh failed (%s): %v; scan marked incomplete\n",
			advisory.SourceGitLab, err)
		return true
	}
	return false
}

// gitlabCacheExists reports whether the GitLab archive has been extracted (its
// manifest is present) under dir.
func gitlabCacheExists(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, advisory.ManifestFilename))
	return err == nil && !info.IsDir()
}

// buildNVDCPESource constructs the opt-in NVD CPE-breadth source for the given
// user cache root. Online it uses the NVD API 2.0 endpoint (COMMIT0_NVD_API_URL
// override honored); offline it serves only the cached feed. A feed-load failure
// surfaces as a query error (unknown ≠ safe), never an empty clean result.
func buildNVDCPESource(userCacheDir string, offline bool) advisory.Source {
	dir := filepath.Join(userCacheDir, "commit0-analyzer", "nvd")
	if offline {
		return advisory.NewNVDCPESource(dir)
	}
	if override := os.Getenv("COMMIT0_NVD_API_URL"); override != "" {
		return advisory.NewNVDCPESource(dir, advisory.WithNVDBaseURL(override))
	}
	return advisory.NewNVDCPESource(dir, advisory.WithNVDBaseURL(nvdAPIDefaultURL))
}

// appendSecondarySources adds the GHSA source and the opt-in NVD-CPE breadth
// source to named, honoring --source selection and --offline. Both self-guard:
// an ecosystem they do not serve, or a missing bundle/cache (GHSA only), yields
// (nil,nil) rather than a failure, so attaching them is coverage-monotonic — it
// never removes an advisory the prior path surfaced and never turns "no advisory"
// into incomplete. The opt-in NVD-CPE source DOES error on a missing feed, which
// is the intended unknown ≠ safe behavior for an explicitly-requested source.
func appendSecondarySources(named []advisory.NamedSource, selected map[string]bool, userCacheDir string, offline bool) []advisory.NamedSource {
	if selected[advisory.SourceGHSA] {
		named = append(named, advisory.NamedSource{
			Name:  advisory.SourceGHSA,
			S:     buildGHSASource(userCacheDir, offline),
			Trust: trustGHSA,
		})
	}
	if selected[advisory.SourceGitLab] {
		named = append(named, advisory.NamedSource{
			Name:  advisory.SourceGitLab,
			S:     buildGitLabSource(userCacheDir),
			Trust: trustGitLab,
		})
	}
	if selected[advisory.SourceNVDCPE] {
		named = append(named, advisory.NamedSource{
			Name:  advisory.SourceNVDCPE,
			S:     buildNVDCPESource(userCacheDir, offline),
			Trust: trustNVDCPE,
		})
	}
	return named
}

// buildEnrichmentChain assembles the post-merge enrichment chain in a fixed,
// deterministic order: the local CWE normalizer, the CISA KEV catalog join, the
// opt-in NVD CVE-detail join, then the opt-in EPSS score join. Enrichment is
// prioritization metadata (KEV, EPSS, CWE weakness context, NVD CVE detail), NOT
// vulnerability coverage.
//
// CWE and KEV are always on: CWE is purely local, and KEV is a single small
// catalog. The NVD enricher (rate-limited to 5 req/30s anonymous) and the EPSS
// enricher (heavy daily feeds) are opt-in via --source nvd / --source epss, so a
// default scan never pays their latency. All network enrichers honor --offline
// (cached floor only). Test seams: KEV honors COMMIT0_KEV_URL, EPSS honors
// COMMIT0_EPSS_API_URL / COMMIT0_EPSS_CSV_URL, and NVD honors COMMIT0_NVD_API_URL; each
// falls back to its production endpoint when the seam is unset and online.
// A degraded enricher warns and is skipped (see runEnrichment) rather than
// changing the exit code, so a missing cache or network outage never marks the
// scan incomplete.
//
// The opt-in NVD *enricher* (CVE-keyed detail, structurally FP-safe) is distinct
// from the lower-confidence NVD-CPE breadth *source* (appendSecondarySources),
// which is gated separately behind --source nvd-cpe.
func buildEnrichmentChain(userCacheDir string, offline bool, selected map[string]bool) advisory.EnrichmentChain {
	kev := &advisory.KEVEnricher{
		CacheDir: filepath.Join(userCacheDir, "commit0-analyzer", "kev"),
		Offline:  offline,
	}
	if url := os.Getenv("COMMIT0_KEV_URL"); url != "" {
		kev.URL = url
	}
	chain := advisory.EnrichmentChain{
		advisory.CWEEnricher{},
		kev,
	}

	if selected[advisory.SourceNVD] {
		nvdDir := filepath.Join(userCacheDir, "commit0-analyzer", "nvd")
		switch {
		case offline:
			chain = append(chain, advisory.NewNVDEnricher(nvdDir))
		case os.Getenv("COMMIT0_NVD_API_URL") != "":
			chain = append(chain, advisory.NewNVDEnricher(nvdDir, advisory.WithNVDBaseURL(os.Getenv("COMMIT0_NVD_API_URL"))))
		default:
			chain = append(chain, advisory.NewNVDEnricher(nvdDir, advisory.WithNVDBaseURL(nvdAPIDefaultURL)))
		}
	}

	if selected[advisory.SourceEPSS] {
		epss := &advisory.EPSSEnricher{
			CacheDir: filepath.Join(userCacheDir, "commit0-analyzer", "epss"),
			Offline:  offline,
		}
		if api := os.Getenv("COMMIT0_EPSS_API_URL"); api != "" {
			epss.APIBaseURL = api
		}
		if csv := os.Getenv("COMMIT0_EPSS_CSV_URL"); csv != "" {
			epss.CSVURL = csv
		}
		chain = append(chain, epss)
	}
	return chain
}

// runEnrichment runs the post-merge enrichment chain over advs in place. A
// failed enricher is warned per failure (keeping whatever enrichment succeeded)
// and otherwise ignored: enrichment is prioritization metadata, not vulnerability
// coverage, so a degraded enricher must NEVER mark the scan incomplete or change
// the exit code. An empty chain or empty advisory slice is a silent no-op.
func runEnrichment(ctx context.Context, chain advisory.EnrichmentChain, advs []advisory.Advisory, pkgDesc string) {
	if len(chain) == 0 || len(advs) == 0 {
		return
	}
	if err := chain.Enrich(ctx, advs); err != nil {
		var enrIncomplete *advisory.EnrichmentIncompleteError
		if errors.As(err, &enrIncomplete) {
			for i, name := range enrIncomplete.FailedEnrichers {
				fmt.Fprintf(os.Stderr, "warning: advisory enricher %q failed for %s: %v\n",
					name, pkgDesc, enrIncomplete.Errors[i])
			}
		} else {
			fmt.Fprintf(os.Stderr, "warning: advisory enrichment failed for %s: %v\n", pkgDesc, err)
		}
	}
}

// osvCacheDirExists returns true when the per-ecosystem subdirectory inside
// osvRoot exists and is a directory. Used to detect an unpopulated OSV cache
// in offline mode so we can warn + mark incomplete rather than silently skip.
func osvCacheDirExists(osvRoot, ecosystem string) bool {
	info, err := os.Stat(filepath.Join(osvRoot, ecosystem))
	return err == nil && info.IsDir()
}

// buildPlugin compiles the go-reachability plugin into a temp directory.
// The binary is placed at a stable path within the OS temp dir to allow
// callers to cache it across repeated scan invocations in the same process.
func buildPlugin(ctx context.Context) (string, error) {
	tmpDir, err := os.MkdirTemp("", "commit0-analyzer-plugin-*")
	if err != nil {
		return "", fmt.Errorf("mktemp: %w", err)
	}
	binPath := filepath.Join(tmpDir, "go-reachability")

	const pluginPkg = "github.com/commit0-dev/commit0-analyzer/plugins/go-reachability"
	cmd := exec.CommandContext(ctx, "go", "build", "-o", binPath, pluginPkg)
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build %s: %w\n%s", pluginPkg, err, out)
	}
	return binPath, nil
}

// jsDistDir returns the absolute path to the JS plugin's dist directory,
// resolved relative to this source file's location in the repository tree.
// At runtime, the binary is compiled and the source layout is gone, so we
// resolve relative to the executable's location instead (for installed builds).
// Tests and local development use the repo-relative path.
func jsDistDir() string {
	// Prefer the repo-relative path for development and test.
	_, thisFile, _, ok := runtime.Caller(0)
	if ok {
		// This file is at internal/cli/scan.go; repo root is two dirs up.
		repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
		candidate := filepath.Join(repoRoot, "plugins", "js-reachability", "dist")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	// Fall back to a path adjacent to the running executable (installed build).
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), "plugins", "js-reachability", "dist")
}

// jsSidecarName returns the platform-specific napi sidecar filename, e.g.
// "parser.darwin-arm64.node". It mirrors the naming convention used by the
// oxc-binding package.
func jsSidecarName() string {
	return fmt.Sprintf("parser.%s-%s.node", runtime.GOOS, runtime.GOARCH)
}

// rustDistDir returns the absolute path to the Rust plugin's dist directory,
// resolved relative to this source file's location in the repository tree.
// At runtime (installed build), it falls back to a path adjacent to the
// running executable. Returns "" when neither location exists.
func rustDistDir() string {
	// Prefer the repo-relative path for development and test.
	_, thisFile, _, ok := runtime.Caller(0)
	if ok {
		// This file is at internal/cli/scan.go; repo root is two dirs up.
		repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
		candidate := filepath.Join(repoRoot, "plugins", "rust-reachability", "dist")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	// Fall back to a path adjacent to the running executable (installed build).
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), "plugins", "rust-reachability", "dist")
}

// buildRustPluginManifest constructs a Manifest for the rust-reachability plugin
// by locating its single-binary distribution under plugins/rust-reachability/dist/
// and computing a SHA-256 pin. The Rust plugin has no sidecar (unlike the JS plugin).
//
// When overrideBin is non-empty it is used as the plugin binary path directly
// (the override disables on-demand build).
// When overrideBin is empty and the dist binary is absent, the plugin is built
// on demand via `go build` — mirroring the Go plugin's buildPlugin(ctx) path.
// This enables zero-config: `commit0-analyzer scan <repo>` builds and runs all detected plugins.
// Returns (manifest, true) on success, or (nil, false) when the build fails or
// the binary cannot be located — callers treat this identically to the absent case.
func buildRustPluginManifest(ctx context.Context, overrideBin string) (*host.Manifest, bool) {
	var mainBin string

	if overrideBin != "" {
		mainBin = overrideBin
	} else {
		distDir := rustDistDir()
		if distDir == "" {
			return nil, false
		}
		mainBin = filepath.Join(distDir, "commit0-rust-reachability")

		// On-demand build: if the dist binary is absent, build it now.
		if _, err := os.Stat(mainBin); err != nil {
			const pluginPkg = "github.com/commit0-dev/commit0-analyzer/plugins/rust-reachability"
			if mkErr := os.MkdirAll(distDir, 0o755); mkErr != nil {
				fmt.Fprintf(os.Stderr,
					"warning: cannot create rust plugin dist dir %s: %v; rust plugin unavailable\n",
					distDir, mkErr)
				return nil, false
			}
			cmd := exec.CommandContext(ctx, "go", "build", "-o", mainBin, pluginPkg)
			cmd.Env = os.Environ()
			if out, buildErr := cmd.CombinedOutput(); buildErr != nil {
				fmt.Fprintf(os.Stderr,
					"warning: on-demand build of rust plugin failed: %v\n%s; rust plugin unavailable\n",
					buildErr, out)
				return nil, false
			}
		}
	}

	if _, err := os.Stat(mainBin); err != nil {
		// Binary not present even after build attempt: graceful skip.
		return nil, false
	}

	absMain, err := filepath.Abs(mainBin)
	if err != nil {
		// Should not happen for a file we just stat'd; treat as absent.
		return nil, false
	}

	hash, err := host.SHA256OfFile(absMain)
	if err != nil {
		// Cannot hash a file we know exists; treat as absent rather than crashing.
		return nil, false
	}

	return &host.Manifest{
		Name:      "rust-reachability",
		ExecPath:  absMain,
		Pillar:    "sca",
		Languages: []string{"rust"},
		SHA256:    hash,
	}, true
}

// pythonDistDir returns the absolute path to the Python plugin's dist directory,
// resolved relative to this source file's location in the repository tree.
// At runtime (installed build), it falls back to a path adjacent to the
// running executable. Returns "" when neither location exists.
func pythonDistDir() string {
	// Prefer the repo-relative path for development and test.
	_, thisFile, _, ok := runtime.Caller(0)
	if ok {
		// This file is at internal/cli/scan.go; repo root is two dirs up.
		repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
		candidate := filepath.Join(repoRoot, "plugins", "python-reachability", "dist")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	// Fall back to a path adjacent to the running executable (installed build).
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), "plugins", "python-reachability", "dist")
}

// buildPythonPluginManifest constructs a Manifest for the python-reachability plugin
// by locating its single-binary distribution under plugins/python-reachability/dist/
// and computing a SHA-256 pin. The Python plugin embeds its Python sidecar inside
// the Go binary (via embed.FS), so no separate sidecar file needs to be pinned.
//
// When overrideBin is non-empty it is used as the plugin binary path directly
// (the override disables on-demand build).
// When overrideBin is empty and the dist binary is absent, the plugin is built
// on demand via `go build` — mirroring the Go plugin's buildPlugin(ctx) path.
// Returns (manifest, true) on success, or (nil, false) when the build fails or
// the binary cannot be located — callers treat this identically to the absent case.
func buildPythonPluginManifest(ctx context.Context, overrideBin string) (*host.Manifest, bool) {
	var mainBin string

	if overrideBin != "" {
		mainBin = overrideBin
	} else {
		distDir := pythonDistDir()
		if distDir == "" {
			return nil, false
		}
		mainBin = filepath.Join(distDir, "commit0-python-reachability")

		// On-demand build: if the dist binary is absent, build it now.
		if _, err := os.Stat(mainBin); err != nil {
			const pluginPkg = "github.com/commit0-dev/commit0-analyzer/plugins/python-reachability"
			if mkErr := os.MkdirAll(distDir, 0o755); mkErr != nil {
				fmt.Fprintf(os.Stderr,
					"warning: cannot create python plugin dist dir %s: %v; python plugin unavailable\n",
					distDir, mkErr)
				return nil, false
			}
			cmd := exec.CommandContext(ctx, "go", "build", "-o", mainBin, pluginPkg)
			cmd.Env = os.Environ()
			if out, buildErr := cmd.CombinedOutput(); buildErr != nil {
				fmt.Fprintf(os.Stderr,
					"warning: on-demand build of python plugin failed: %v\n%s; python plugin unavailable\n",
					buildErr, out)
				return nil, false
			}
		}
	}

	if _, err := os.Stat(mainBin); err != nil {
		// Binary not present even after build attempt: graceful skip.
		return nil, false
	}

	absMain, err := filepath.Abs(mainBin)
	if err != nil {
		// Should not happen for a file we just stat'd; treat as absent.
		return nil, false
	}

	hash, err := host.SHA256OfFile(absMain)
	if err != nil {
		// Cannot hash a file we know exists; treat as absent rather than crashing.
		return nil, false
	}

	return &host.Manifest{
		Name:      "python-reachability",
		ExecPath:  absMain,
		Pillar:    "sca",
		Languages: []string{"python"},
		SHA256:    hash,
	}, true
}

// pythonDep is a resolved Python package dependency (name + version) extracted
// from the Python project's lockfile via the python-reachability plugin's
// --list-deps subcommand. Used to query PyPI OSV advisories before the plugin runs.
// DepType carries the dep classification from the Python plugin (runtime |
// optional-extra | dev | test | docs). It is used by the host to tag findings
// with properties["dep_type"] so the policy gate can apply dep-type aware gating.
type pythonDep struct {
	Ecosystem string `json:"ecosystem"` // always "PyPI"
	Name      string `json:"name"`
	Version   string `json:"version"`
	// DepType is the dependency classification emitted by the Python plugin's
	// --list-deps output: runtime | optional-extra | dev | test | docs.
	// Missing (empty string) is treated as runtime by the host (conservative default).
	DepType string `json:"dep_type,omitempty"`
}

// listPythonDepsOutput is the JSON shape emitted by the Python plugin's --list-deps mode.
type listPythonDepsOutput struct {
	Deps []pythonDep `json:"deps"`
	// Incomplete is true when the dep list could not be fully resolved.
	// This covers: no lockfile present, no venv present (manifest-only mode),
	// offline+unpinned (cannot resolve without network), or any parse error.
	// When true, the caller MUST set incomplete=true on the scan.
	Incomplete bool `json:"incomplete"`
	// IncompleteReason provides a human-readable explanation for the incomplete signal.
	IncompleteReason string `json:"incompleteReason,omitempty"`
}

// listPythonDeps execs the Python plugin binary in --list-deps mode and returns
// the resolved Python dependency list for the project rooted at moduleRoot.
// It also returns whether the project model is incomplete.
//
// The incomplete signal covers:
//   - No lockfile present (only pyproject.toml/requirements.txt): manifest-only mode,
//     no pinned versions available; dep resolution requires network or venv.
//   - No venv present: dist→import mapping unavailable, reachability not computable.
//   - offline+unpinned: cannot resolve without network access.
//
// Any of these forces incomplete=true so the scan exits 3, never 0 (false-clean).
// On any subprocess or parse failure it returns an error (never silently empty).
func listPythonDeps(ctx context.Context, pluginBin, moduleRoot string) ([]pythonDep, bool, error) {
	cmd := exec.CommandContext(ctx, pluginBin, "--list-deps", moduleRoot)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, false, fmt.Errorf("python plugin --list-deps: %w\n%s", err, exitErr.Stderr)
		}
		return nil, false, fmt.Errorf("python plugin --list-deps: %w", err)
	}

	var result listPythonDepsOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, false, fmt.Errorf("python plugin --list-deps: parse output: %w", err)
	}

	return result.Deps, result.Incomplete, nil
}

// buildJSPluginManifest constructs a Manifest for the js-reachability plugin
// by locating its two-file distribution (main binary + napi sidecar) under
// plugins/js-reachability/dist/ and computing SHA-256 pins for both files.
// When overrideBin is non-empty it is used as the main binary path directly
// (the dist directory is derived from its parent). Returns an error when the
// distribution has not been built yet.
func buildJSPluginManifest(overrideBin string) (*host.Manifest, error) {
	var mainBin string
	var distDir string

	if overrideBin != "" {
		mainBin = overrideBin
		distDir = filepath.Dir(overrideBin)
	} else {
		distDir = jsDistDir()
		if distDir == "" {
			return nil, fmt.Errorf("cannot locate js-reachability dist directory")
		}
		mainBin = filepath.Join(distDir, "commit0-js-reachability")
	}
	if _, err := os.Stat(mainBin); err != nil {
		return nil, fmt.Errorf("js-reachability plugin not built: %s not found (run 'make build-js-plugin'): %w", mainBin, err)
	}

	sidecarName := jsSidecarName()
	sidecarPath := filepath.Join(distDir, "oxc-binding", sidecarName)
	if _, err := os.Stat(sidecarPath); err != nil {
		return nil, fmt.Errorf("js-reachability napi sidecar not found: %s (run 'make build-js-plugin'): %w", sidecarPath, err)
	}

	mainHash, err := host.SHA256OfFile(mainBin)
	if err != nil {
		return nil, fmt.Errorf("hash js-reachability binary: %w", err)
	}

	sidecarHash, err := host.SHA256OfFile(sidecarPath)
	if err != nil {
		return nil, fmt.Errorf("hash js-reachability sidecar: %w", err)
	}

	return &host.Manifest{
		Name:      "js-reachability",
		ExecPath:  mainBin,
		Pillar:    "sca",
		Languages: []string{"js", "ts"},
		SHA256:    mainHash,
		AdditionalArtifacts: []host.ArtifactPin{
			{Path: sidecarPath, SHA256: sidecarHash},
		},
	}, nil
}
