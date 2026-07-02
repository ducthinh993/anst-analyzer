package cli

// ecosystem_pub.go — lockfile-static adapter for Pub (Dart/Flutter).
//
// OSV ecosystem: "Pub" (https://osv.dev/list?ecosystem=Pub)
// Maximum confidence: PACKAGE_REACHABLE (Pub OSV advisories carry no method-level data).
//
// Security invariants (ACE-safety):
//   - NEVER evaluate pubspec.yaml. Although pubspec.yaml is declarative YAML
//     and not itself executable, build hooks (hooks/build.dart) may run via
//     `dart pub get`. We avoid triggering that code path entirely.
//   - NEVER call `dart pub get` or any other pub subcommand on untrusted repos.
//     Doing so would execute build hooks (hooks/build.dart scripts), which
//     constitute arbitrary code execution (ACE) on an untrusted repo.
//   - Parse ONLY the static pubspec.lock (YAML, non-executable). pubspec.lock
//     records the fully-resolved transitive closure written by pub after a
//     successful dependency resolution.
//   - pubspec.yaml is listed as a DetectFiles entry so that Dart projects without
//     a committed lockfile are still detected, triggering a scan that returns
//     incomplete=true rather than silently skipping the Dart ecosystem
//     (unknown ≠ safe). But pubspec.yaml is NEVER opened or parsed for resolution.
//
// Lockfile resolution:
//   - pubspec.lock present → full resolved transitive closure → complete=true.
//   - pubspec.yaml only (no pubspec.lock) → cannot resolve without running
//     `dart pub get` (which may execute build hooks — ACE) → complete=false
//     → incomplete=true in the scan.
//   - Nothing found → complete=false.
//
// Dep-type classification from pubspec.lock:
//   - dependency: "direct main" → runtime  (direct production dependency)
//   - dependency: "transitive"  → runtime  (transitive production dependency)
//   - dependency: "direct dev"  → dev      (direct development-only dependency)
//   Any other value is treated as "runtime" (conservative: unknown ≠ dev).
//
// Version scheme:
//   - Dart/Flutter packages use Semantic Versioning 2.0.0. pubspec.lock always
//     records bare exact versions ("1.2.3", never "v1.2.3"). The OSV Pub records
//     also use bare versions. The shared pub_version.go comparator handles this.
//   - Parse failures in version comparison → VersionUndecidable → UNKNOWN +
//     incomplete=true (never silently treated as NotAffected).
//
// Positive-reachability framing:
//   - Dart advisory data via OSV carries only package + version range; no
//     method or symbol-level data is available. Maximum confidence is
//     PACKAGE_REACHABLE (the vulnerable package is present in the resolved
//     closure). SYMBOL_REACHABLE is never emitted.

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
)

func init() {
	RegisterEcosystemAdapter(EcosystemAdapter{
		Ecosystem: advisory.EcosystemPub,
		Language:  "dart",
		// DetectFiles: pubspec.lock is the primary lockfile (complete static closure).
		// pubspec.yaml is included so that Dart/Flutter projects without a committed
		// lockfile are still detected, triggering a scan that will return
		// incomplete=true rather than silently skipping the Dart ecosystem
		// (unknown ≠ safe). pubspec.yaml is intentionally NEVER parsed as a
		// resolution source (see ACE-safety notes in the file header).
		DetectFiles:   []string{"pubspec.lock", "pubspec.yaml"},
		MaxConfidence: ceilingPackage,
		ParseLockfile: parsePubspecLock,
		// HasPlugin graduates Pub to the plugin-backed path: the host keeps
		// parsing pubspec.lock (the closure source, ParseLockfile above) and passes
		// that closure to the reachability plugin, which can additionally prove
		// package-level NOT_REACHABLE (advisory package present in the closure but
		// provably never in the project's used-import closure) → VEX not_affected.
		// When the plugin binary is absent or fails to build, the host falls back
		// to the direct PACKAGE_REACHABLE finding (never a silent skip).
		HasPlugin: true,
		// PluginName pins the plugin base name so the manifest derives
		// plugins/pub-reachability/ and the binary commit0-pub-reachability
		// (distinct from Language "dart", which is the ecosystem's language tag).
		PluginName: "pub",
		// NormalizeName is nil: Pub package names on pub.dev are lowercase and
		// case-sensitive. The OSV Pub index records use the same canonical form
		// as the names stored in pubspec.lock. No normalization is required.
		NormalizeName: nil,
	})
}

// ── pubspec.lock YAML model ───────────────────────────────────────────────────

// pubspecLockFile is the Go model for pubspec.lock (Pub YAML lockfile).
//
// Structure (relevant fields):
//
//	packages:
//	  <name>:
//	    dependency: "direct main" | "direct dev" | transitive
//	    description:
//	      name: <name>
//	      ...
//	    source: hosted | git | path | sdk
//	    version: "1.2.3"
//	sdks:
//	  dart: ">=3.0.0 <4.0.0"
//
// The "packages" map holds every package in the transitive closure. The
// "dependency" field encodes how the package was introduced:
//   - "direct main"  — listed in pubspec.yaml dependencies section (production)
//   - "direct dev"   — listed in pubspec.yaml dev_dependencies section (dev-only)
//   - "transitive"   — pulled in transitively by a direct or transitive dep
//
// Only "direct dev" is explicitly dev-only; all others are treated as runtime
// (conservative: unknown ≠ dev).
type pubspecLockFile struct {
	Packages map[string]pubspecLockPkg `yaml:"packages"`
}

// pubspecLockPkg is a single package entry in pubspec.lock.
type pubspecLockPkg struct {
	// Dependency encodes dep-type as written by pub:
	//   "direct main"  → runtime
	//   "direct dev"   → dev
	//   "transitive"   → runtime
	//   (any other)    → runtime (conservative)
	Dependency string `yaml:"dependency"`
	// Source is the origin of the package: "hosted", "git", "path", or "sdk".
	// Only "hosted" packages have an OSV Pub advisory identity; "git", "path",
	// and "sdk" packages are skipped (no pub.dev registry identity).
	Source string `yaml:"source"`
	// Version is the pinned exact version string (e.g. "1.2.3").
	Version string `yaml:"version"`
}

// ── parsePubspecLock ──────────────────────────────────────────────────────────

// parsePubspecLock is the EcosystemAdapter.ParseLockfile implementation for Dart/Flutter.
//
// It reads pubspec.lock (YAML) and returns the fully-resolved dependency closure.
// Only "hosted" source packages are included; "git", "path", and "sdk" packages
// have no pub.dev registry identity and cannot match OSV Pub advisories.
//
// Dep-type classification:
//   - "direct dev"  → DepType "dev"
//   - "direct main" → DepType "runtime"
//   - "transitive"  → DepType "runtime"
//   - any other     → DepType "" (treated as runtime by mergeDepType; conservative)
//
// Contract:
//   - (nil, false, nil)     → pubspec.lock absent; caller marks scan incomplete.
//     A pubspec.yaml-only project cannot be resolved without running `dart pub get`
//     (which may execute build hooks — ACE); the caller must NOT run a build tool.
//   - (deps, true, nil)     → closure is complete; all hosted packages have
//     pinned versions. An empty closure (project has no hosted deps) is valid.
//   - (nil, false, err)     → I/O or YAML decode error; caller marks scan incomplete.
//
// NEVER returns a partial closure with complete=false (EcosystemAdapter invariant):
// a partial dep list would produce false NOT_REACHABLE for the missing portion,
// silently dropping real vulnerabilities.
func parsePubspecLock(root string) ([]ResolvedDep, bool, error) {
	lockPath := filepath.Join(root, "pubspec.lock")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No pubspec.lock: the Dart project has either never run `dart pub get`
			// or the lockfile was not committed. Resolving the transitive closure
			// requires running `dart pub get`, which may execute build hooks (ACE
			// risk on untrusted repos). Return incomplete rather than running an
			// untrusted tool.
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read pubspec.lock: %w", err)
	}

	var lock pubspecLockFile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		// Malformed pubspec.lock: cannot trust any partial parse result.
		// Return complete=false so the caller marks the scan incomplete.
		return nil, false, fmt.Errorf("parse pubspec.lock: %w", err)
	}

	if lock.Packages == nil {
		// A pubspec.lock with no "packages" key is valid only for a project with
		// zero dependencies; return an empty complete closure.
		return nil, true, nil
	}

	deps := make([]ResolvedDep, 0, len(lock.Packages))
	for name, pkg := range lock.Packages {
		if name == "" || pkg.Version == "" {
			// Degenerate entry (should not occur in machine-written lockfiles);
			// skip without failing the parse so the rest of the closure is intact.
			continue
		}

		// Skip non-hosted packages: "git", "path", and "sdk" packages have no
		// pub.dev registry identity and cannot match OSV Pub advisories.
		// Skipping them is safe (not false-clean): OSV Pub advisories are
		// exclusively for pub.dev-hosted packages.
		if pkg.Source != "hosted" {
			continue
		}

		deps = append(deps, ResolvedDep{
			Name:    name,
			Version: pkg.Version,
			DepType: pubDepType(pkg.Dependency),
		})
	}

	return deps, true, nil
}

// pubDepType maps the pubspec.lock "dependency" field to the ResolvedDep DepType.
//
// Mapping:
//   - "direct dev"  → "dev"     (explicitly development-only)
//   - "direct main" → "runtime" (explicit production dependency)
//   - "transitive"  → "runtime" (all transitive deps are runtime in pub's model)
//   - (any other)   → ""        (unknown; mergeDepType conservatively treats as runtime)
//
// Only "direct dev" is dev-only per the pubspec.lock format spec; treating
// any unrecognised value as "" (unknown → runtime) is conservative.
func pubDepType(dep string) string {
	switch dep {
	case "direct dev":
		return "dev"
	case "direct main", "transitive":
		return "runtime"
	default:
		// Unrecognised dependency type: conservative default (empty → runtime).
		return ""
	}
}
