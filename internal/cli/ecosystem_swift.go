package cli

// ecosystem_swift.go — Lane-A lockfile-static adapter for SwiftURL (Swift Package Manager).
//
// OSV ecosystem: "SwiftURL" (https://osv.dev/list?ecosystem=SwiftURL)
// Maximum confidence: PACKAGE_REACHABLE (SwiftURL OSV advisories carry no method-level data).
//
// Security invariants (ACE-safety):
//   - NEVER evaluate Package.swift. Package.swift is executable Swift source code —
//     evaluating it constitutes arbitrary code execution (ACE) on an untrusted repo.
//   - NEVER call `swift`, `swift package resolve`, or any Swift build tool on an
//     untrusted repo.
//   - Parse ONLY the static Package.resolved (JSON, non-executable). Package.resolved
//     is written deterministically by `swift package resolve` and records the fully-
//     pinned transitive closure. It is safe to read as a static file.
//
// Package identity — git URL, not package name:
//   - SwiftURL OSV records use the git repository URL as the package identity in
//     affected[].package.name. The form is the bare URL with no scheme and no .git
//     suffix (e.g. "github.com/apple/swift-nio").
//   - Package.resolved records the git URL in the "repositoryURL" (v1) or "location"
//     (v2/v3) field.  These URLs typically carry "https://" scheme and a trailing
//     ".git" suffix.
//   - normalizeSwiftURL normalizes both forms to a comparable canonical form so
//     that advisory matching works correctly (see below).
//
// URL normalization (normalizeSwiftURL):
//   Applied to the lockfile URL before storing as dep.Name. The same form is
//   stored in OSV records, so NormalizeName on the adapter is nil (identity).
//
//   Transformations (in order):
//     1. Lowercase the entire URL (git hosting names are case-insensitive).
//     2. Strip git@ SSH prefix (git@github.com:owner/repo → github.com/owner/repo).
//     3. Strip https:// or http:// scheme prefix.
//     4. Strip trailing .git suffix.
//     5. Strip trailing / separator.
//
//   Example: "https://github.com/apple/swift-nio.git" → "github.com/apple/swift-nio"
//
// Package.resolved format versions:
//   - v1 ({"version":1}): top-level "object" → "pins" array; each pin has
//     "repositoryURL" and "state"."version".
//   - v2/v3 ({"version":2} or {"version":3}): top-level "pins" array; each pin
//     has "location" and "state"."version".
//   Both formats are parsed. A pin whose state.version is empty (branch/revision
//   pin with no concrete version) is skipped and sets complete=false — that pin's
//   version is undecidable, so the closure cannot be marked complete.
//
// Dep-type classification:
//   - Package.resolved does NOT distinguish test targets from product targets.
//     Recovering dep-type would require evaluating Package.swift (ACE risk).
//     Therefore all resolved deps are tagged "runtime" — the conservative default
//     (unknown ≠ dev: tagging a dev dep as runtime causes it to be checked against
//     advisories, NOT silently skipped).
//
// Positive-reachability framing:
//   - Swift's dynamic dispatch, @objc / Objective-C bridging, and Combine closures
//     make negative reachability (NOT_REACHABLE) unsound.
//   - Maximum confidence is PACKAGE_REACHABLE. SYMBOL_REACHABLE is never emitted.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
)

func init() {
	RegisterEcosystemAdapter(EcosystemAdapter{
		Ecosystem: advisory.EcosystemSwiftURL,
		Language:  "swift",
		// DetectFiles: Package.resolved is the only SwiftPM lockfile we parse.
		// Package.swift is INTENTIONALLY excluded: it is executable Swift source code
		// (ACE risk on untrusted repos). Detecting Package.resolved alone is sufficient
		// for zero-config auto-detection — projects that have never run `swift package
		// resolve` will not have a Package.resolved, so they are not falsely detected.
		DetectFiles:   []string{"Package.resolved"},
		MaxConfidence: ceilingPackage,
		ParseLockfile: parsePackageResolved,
		// NormalizeName is nil: normalizeSwiftURL is applied inside ParseLockfile so
		// dep.Name already holds the canonical OSV form (e.g. "github.com/apple/swift-nio").
		// No further transformation is needed at query time.
		NormalizeName: nil,
	})
}

// ── Package.resolved JSON models ─────────────────────────────────────────────

// packageResolvedFile is the top-level structure of Package.resolved for both
// format version 1 (object.pins) and versions 2/3 (pins).
//
// Format v1 example:
//
//	{
//	  "version": 1,
//	  "object": {
//	    "pins": [ { "package": "swift-nio", "repositoryURL": "...", "state": {...} } ]
//	  }
//	}
//
// Format v2/v3 example:
//
//	{
//	  "version": 2,
//	  "pins": [ { "identity": "swift-nio", "location": "...", "state": {...} } ]
//	}
type packageResolvedFile struct {
	Version int `json:"version"`
	// v2/v3: top-level "pins" array.
	Pins []packageResolvedPin `json:"pins"`
	// v1: "object" wrapper.
	Object *packageResolvedV1Object `json:"object"`
}

// packageResolvedV1Object is the "object" wrapper present in format version 1.
type packageResolvedV1Object struct {
	Pins []packageResolvedV1Pin `json:"pins"`
}

// packageResolvedPin is a single pin entry in format v2/v3.
type packageResolvedPin struct {
	// Identity is the short package name (e.g. "swift-nio") — not used for OSV matching.
	Identity string `json:"identity"`
	// Location is the git repository URL (e.g. "https://github.com/apple/swift-nio.git").
	Location string `json:"location"`
	// State holds the pinned version.
	State packageResolvedState `json:"state"`
}

// packageResolvedV1Pin is a single pin entry in format v1.
type packageResolvedV1Pin struct {
	// Package is the short package name — not used for OSV matching.
	Package string `json:"package"`
	// RepositoryURL is the git repository URL.
	RepositoryURL string `json:"repositoryURL"`
	// State holds the pinned version.
	State packageResolvedState `json:"state"`
}

// packageResolvedState holds the pinned state of a dependency.
// A concrete version pin has Version non-empty; branch/revision pins do not.
type packageResolvedState struct {
	// Version is the pinned SemVer tag (e.g. "2.41.0"). Empty for branch/revision pins.
	Version string `json:"version"`
	// Branch is the pinned branch name (non-empty for branch pins). Presence means
	// no concrete version — skip this pin and mark closure incomplete.
	Branch string `json:"branch"`
	// Revision is the git commit SHA. May be present alongside Version (tag + SHA)
	// or alone (revision-only pin, which is undecidable — skip and mark incomplete).
	Revision string `json:"revision"`
}

// ── parsePackageResolved ──────────────────────────────────────────────────────

// parsePackageResolved is the EcosystemAdapter.ParseLockfile implementation for Swift.
//
// It reads Package.resolved (static JSON) and returns the fully-pinned dependency
// closure. Both format v1 (object.pins with repositoryURL) and v2/v3 (top-level
// pins with location) are handled.
//
// URL normalization is applied to each pin's git URL so that dep.Name matches
// the canonical form used by OSV SwiftURL records (e.g. "github.com/apple/swift-nio").
//
// Contract:
//   - (nil, false, nil)      → Package.resolved absent; caller marks scan incomplete.
//   - (deps, true, nil)      → complete closure; all pins have concrete versions.
//   - (deps, false, nil)     → partial closure; at least one pin lacked a version
//     (branch/revision-only pin). The partial result is returned so the caller can
//     query advisories for the decidable portion, but incomplete=true is set so the
//     scan exits 3 (not 0 — unknown ≠ safe for the undecidable portion).
//   - (nil, false, err)      → I/O or JSON parse error; caller marks scan incomplete.
//
// NEVER returns (nil, true, nil) — that would be a false-clean empty closure.
func parsePackageResolved(root string) ([]ResolvedDep, bool, error) {
	lockPath := filepath.Join(root, "Package.resolved")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No Package.resolved: the Swift project either has no dependencies or
			// has not run `swift package resolve`. Resolving the closure requires
			// evaluating Package.swift (ACE risk). Return incomplete.
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read Package.resolved: %w", err)
	}

	var lock packageResolvedFile
	if err := json.Unmarshal(data, &lock); err != nil {
		// Malformed JSON: cannot trust any partial parse. Return complete=false.
		return nil, false, fmt.Errorf("parse Package.resolved: %w", err)
	}

	// Route to the correct format parser.
	switch lock.Version {
	case 1:
		return parsePackageResolvedV1(&lock)
	case 2, 3:
		return parsePackageResolvedV23(&lock)
	default:
		// Unknown format version: undecidable. Returning complete=false marks the
		// scan incomplete (unknown ≠ safe) rather than silently treating it as clean.
		return nil, false, fmt.Errorf(
			"unsupported Package.resolved format version %d; expected 1, 2, or 3", lock.Version)
	}
}

// parsePackageResolvedV1 parses format version 1 (object.pins with repositoryURL).
func parsePackageResolvedV1(lock *packageResolvedFile) ([]ResolvedDep, bool, error) {
	if lock.Object == nil {
		// Version 1 must have an "object" key. A missing object means either a
		// zero-dependency project or a malformed file. Return complete=true with an
		// empty closure (no deps to check) — this is safe because there is nothing
		// to miss.  A future version that adds a dep without re-running the resolver
		// cannot produce a stale Package.resolved without a rewrite of the file.
		return nil, true, nil
	}

	complete := true
	deps := make([]ResolvedDep, 0, len(lock.Object.Pins))
	for _, pin := range lock.Object.Pins {
		rawURL := pin.RepositoryURL
		if rawURL == "" {
			// No URL: cannot identify the package. Skip and mark incomplete.
			complete = false
			continue
		}
		version := pin.State.Version
		if version == "" {
			// Branch or revision-only pin: version is undecidable. Skip this pin
			// and mark the closure incomplete (unknown ≠ safe).
			complete = false
			continue
		}
		deps = append(deps, ResolvedDep{
			Name:    normalizeSwiftURL(rawURL),
			Version: version,
			// DepType is "runtime": Package.resolved does not encode dep-type.
			// Recovering it would require evaluating Package.swift (ACE risk).
			// "runtime" is the conservative default: unknown ≠ dev.
			DepType: "runtime",
		})
	}

	return deps, complete, nil
}

// parsePackageResolvedV23 parses format versions 2 and 3 (top-level pins with location).
func parsePackageResolvedV23(lock *packageResolvedFile) ([]ResolvedDep, bool, error) {
	complete := true
	deps := make([]ResolvedDep, 0, len(lock.Pins))
	for _, pin := range lock.Pins {
		rawURL := pin.Location
		if rawURL == "" {
			// No URL: cannot identify the package. Skip and mark incomplete.
			complete = false
			continue
		}
		version := pin.State.Version
		if version == "" {
			// Branch or revision-only pin: version is undecidable. Skip this pin
			// and mark the closure incomplete (unknown ≠ safe).
			complete = false
			continue
		}
		deps = append(deps, ResolvedDep{
			Name:    normalizeSwiftURL(rawURL),
			Version: version,
			// DepType is "runtime": Package.resolved does not encode dep-type.
			// See comment in parsePackageResolvedV1.
			DepType: "runtime",
		})
	}

	return deps, complete, nil
}

// normalizeSwiftURL converts a raw git repository URL from Package.resolved into
// the canonical form used by OSV SwiftURL package records.
//
// OSV SwiftURL records use the bare git host + path with no scheme, no .git
// suffix, and lowercase (e.g. "github.com/apple/swift-nio"). Package.resolved
// typically stores HTTPS URLs with a .git suffix (e.g.
// "https://github.com/apple/swift-nio.git"). SSH URLs (git@github.com:...) are
// also normalised.
//
// Transformations (applied in order):
//  1. Lowercase (git hosting names are case-insensitive; OSV uses lowercase).
//  2. Strip git@ SSH format: "git@host:owner/repo" → "host/owner/repo".
//  3. Strip https:// or http:// scheme prefix.
//  4. Strip trailing .git suffix.
//  5. Strip trailing / separator.
//
// An empty input is returned as-is (empty string does not match any OSV record).
func normalizeSwiftURL(rawURL string) string {
	s := strings.ToLower(strings.TrimSpace(rawURL))
	if s == "" {
		return ""
	}

	// Strip git@ SSH format: git@github.com:owner/repo → github.com/owner/repo.
	if strings.HasPrefix(s, "git@") {
		s = s[len("git@"):]
		// Replace the first colon (host:path separator) with a slash.
		if idx := strings.Index(s, ":"); idx >= 0 {
			s = s[:idx] + "/" + s[idx+1:]
		}
	} else {
		// Strip https:// or http:// scheme.
		for _, pfx := range []string{"https://", "http://"} {
			if strings.HasPrefix(s, pfx) {
				s = s[len(pfx):]
				break
			}
		}
	}

	// Strip trailing path separators before the .git suffix check, so that URLs
	// ending with ".git/" are handled correctly (e.g. "github.com/foo/bar.git/").
	s = strings.TrimRight(s, "/")
	// Strip trailing .git suffix.
	s = strings.TrimSuffix(s, ".git")
	// Strip any trailing path separator that was between host and .git (rare but defensive).
	s = strings.TrimRight(s, "/")

	return s
}
