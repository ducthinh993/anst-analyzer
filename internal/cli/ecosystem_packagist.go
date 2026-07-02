package cli

// ecosystem_packagist.go — lockfile-static adapter for Packagist (PHP/Composer).
//
// OSV ecosystem: "Packagist" (https://osv.dev/list?ecosystem=Packagist)
// Maximum confidence: PACKAGE_REACHABLE (Packagist OSV advisories carry no method-level data).
//
// Security invariants (ACE-safety):
//   - NEVER run composer install, composer update, or any composer subcommand.
//     composer.json may define scripts (post-install-cmd, post-update-cmd, etc.)
//     that execute arbitrary PHP/shell code on invocation — ACE on an untrusted repo.
//   - Parse ONLY the static composer.lock (pure JSON, non-executable).
//   - composer.json is listed as a DetectFiles entry so that PHP projects without
//     a committed lockfile are detected and marked incomplete (unknown ≠ safe),
//     but it is never parsed as a resolution source.
//
// Lockfile resolution:
//   - composer.lock present → full resolved transitive closure → complete=true.
//   - composer.json only (no composer.lock) → cannot resolve without running
//     composer install (ACE) → complete=false → incomplete=true in the scan.
//   - Nothing found → complete=false.
//
// Dep-type classification:
//   - "packages" array in composer.lock → "runtime"
//   - "packages-dev" array in composer.lock → "dev"
//   - This segmentation is clean and authoritative; no heuristics needed.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
)

func init() {
	RegisterEcosystemAdapter(EcosystemAdapter{
		Ecosystem: advisory.EcosystemPackagist,
		Language:  "php",
		// DetectFiles: composer.lock is the primary lockfile (full static closure).
		// composer.json is included so that manifest-only projects (no committed lockfile)
		// are still detected, triggering a scan that will return incomplete=true rather
		// than silently skipping the PHP ecosystem (unknown ≠ safe).
		DetectFiles:   []string{"composer.lock", "composer.json"},
		MaxConfidence: ceilingPackage,
		ParseLockfile: parseComposerLockfile,
		// NormalizeName is nil: Packagist enforces lowercase package names
		// (e.g. "vendor/package") and the OSV Packagist index records use the same
		// lowercase canonical form. Names from composer.lock are already lowercase.
		NormalizeName: nil,
	})
}

// ── composer.lock ────────────────────────────────────────────────────────────

// composerLockFile is the Go model for composer.lock (Composer JSON lockfile).
//
// Structure (relevant fields):
//
//	{
//	  "packages":     [ { "name": "vendor/pkg", "version": "1.2.3", ... }, ... ],
//	  "packages-dev": [ { "name": "vendor/dev-pkg", "version": "2.0.0", ... }, ... ]
//	}
//
// "packages" contains the runtime dependency closure; "packages-dev" contains
// the development/test-only dependency closure. Both are fully resolved
// transitive closures — no resolver run is needed to expand them.
type composerLockFile struct {
	Packages    []composerLockPkg `json:"packages"`
	PackagesDev []composerLockPkg `json:"packages-dev"`
}

type composerLockPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// parseComposerLockfile is the EcosystemAdapter.ParseLockfile implementation for PHP.
//
// It reads composer.lock and returns the full resolved dependency closure with
// authoritative dep-type classification from the lockfile structure.
//
// Contract:
//   - (nil, false, nil)         → composer.lock absent; caller may check composer.json
//     but MUST mark the scan incomplete (no tool run = cannot resolve transitives).
//   - (deps, true, nil)         → closure is complete; all packages have pinned versions.
//   - (nil, false, err)         → I/O or JSON decode error.
//
// NEVER returns a partial closure with complete=false (EcosystemAdapter invariant):
// a partial dep list would cause false NOT_REACHABLE for the missing transitive
// portion, silently dropping real vulnerabilities.
func parseComposerLockfile(root string) ([]ResolvedDep, bool, error) {
	lockPath := filepath.Join(root, "composer.lock")
	f, err := os.Open(lockPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No composer.lock means the PHP project is manifest-only.
			// Resolving the transitive closure requires `composer install`, which
			// executes composer scripts (ACE risk). Return incomplete rather than
			// running an untrusted tool.
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("open composer.lock: %w", err)
	}
	defer func() { _ = f.Close() }()

	var lock composerLockFile
	if err := json.NewDecoder(f).Decode(&lock); err != nil {
		// Malformed lockfile: cannot trust any partial parse result.
		// Return complete=false so the caller marks the scan incomplete.
		return nil, false, fmt.Errorf("decode composer.lock: %w", err)
	}

	var deps []ResolvedDep

	// Runtime packages — included in production deployments.
	for _, pkg := range lock.Packages {
		if pkg.Name == "" || pkg.Version == "" {
			// Incomplete entry: skip without error. The lockfile is still
			// considered complete for the packages that do have pinned versions;
			// incomplete entries are a degenerate edge case in machine-generated files.
			continue
		}
		deps = append(deps, ResolvedDep{
			Name:    pkg.Name,
			Version: pkg.Version,
			DepType: "runtime",
		})
	}

	// Dev packages — test runners, code generators, etc.
	for _, pkg := range lock.PackagesDev {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		deps = append(deps, ResolvedDep{
			Name:    pkg.Name,
			Version: pkg.Version,
			DepType: "dev",
		})
	}

	// An empty closure (no dependencies) with complete=true is valid — a project
	// with zero dependencies has no advisories to query.
	return deps, true, nil
}
