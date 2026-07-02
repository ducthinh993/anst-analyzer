package cli

// ecosystem_rubygems.go — Lane-A lockfile-static adapter for RubyGems (Ruby/Bundler).
//
// OSV ecosystem: "RubyGems" (https://osv.dev/list?ecosystem=RubyGems)
// Maximum confidence: PACKAGE_REACHABLE (RubyGems OSV advisories carry no method-level data).
//
// Security invariants (ACE-safety):
//   - NEVER evaluate the Gemfile. The Gemfile is Ruby source code — it is
//     executed verbatim by Bundler at `bundle install` time.  Parsing it would
//     require evaluating arbitrary Ruby, which constitutes arbitrary code
//     execution (ACE) on an untrusted repo.
//   - Parse ONLY the static Gemfile.lock (plain text, non-executable).
//   - The Gemfile is listed as a DetectFiles entry so that Ruby projects without
//     a committed lockfile are detected and marked incomplete (unknown ≠ safe),
//     but it is NEVER opened or parsed as a resolution source.
//   - NEVER run `bundle install`, `bundle exec`, or any other Bundler subcommand.
//
// Lockfile resolution:
//   - Gemfile.lock present → full resolved transitive closure → complete=true.
//   - Gemfile only (no Gemfile.lock) → cannot resolve without running
//     `bundle install` (which evaluates the Gemfile — ACE) → complete=false
//     → incomplete=true in the scan.
//   - Nothing found → complete=false.
//
// Dep-type classification:
//   - Gemfile.lock's standard format (as written by Bundler) does NOT encode
//     group annotations (`:development`, `:test`) in the GEM/specs section.
//     Group membership is stored only in the Gemfile (which we must not parse).
//     Therefore all gems from the GEM/specs section are tagged "runtime" — the
//     conservative default per the mergeDepType contract (unknown ≠ dev).
//   - This is safe: tagging a dev gem as runtime causes it to be checked against
//     advisories (conservative), NOT to be silently skipped (dangerous).
//   - Per-group tagging is deferred to a future version that can safely infer
//     group membership (e.g., via a separate static-analysis pass on Gemfile
//     DSL patterns, not via eval).
//
// Positive-reachability framing:
//   - Ruby's metaprogramming primitives (send, const_get, method_missing,
//     Zeitwerk autoloading) make NEGATIVE reachability (NOT_REACHABLE) unsound.
//     Any call to .send("method_name") or require with a dynamic string can
//     invoke code that a static analysis would classify as unreachable.
//   - Therefore max confidence is PACKAGE_REACHABLE (the package is present
//     in the resolved closure); SYMBOL_REACHABLE is never emitted.

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
)

func init() {
	RegisterEcosystemAdapter(EcosystemAdapter{
		Ecosystem: advisory.EcosystemRubyGems,
		Language:  "ruby",
		// DetectFiles: Gemfile.lock is the primary lockfile (full static closure).
		// Gemfile is included so that manifest-only projects (no committed lockfile)
		// are still detected, triggering a scan that will return incomplete=true
		// rather than silently skipping the Ruby ecosystem (unknown ≠ safe).
		DetectFiles:   []string{"Gemfile.lock", "Gemfile"},
		MaxConfidence: ceilingPackage,
		ParseLockfile: parseGemfileLock,
		// NormalizeName is nil: RubyGems package names are case-sensitive and
		// are stored in the OSV index with the canonical casing from rubygems.org.
		// Names in Gemfile.lock use the same canonical form.
		NormalizeName: nil,
	})
}

// gemSpecRe matches a gem spec line in Gemfile.lock's GEM/specs section.
//
// Format: exactly 4 spaces of indentation, gem name, a space, version in parens.
// Examples:
//
//	    rails (7.0.4)
//	    net-http (0.3.2)
//	    google-protobuf (3.24.4)
//
// The version inside the parens may contain digits, dots, letters, and hyphens
// (pre-release: "1.2.3.rc1", "2.0.0.beta4", "1.0.0.pre.1"). Parentheses may
// also be absent in rare malformed lockfiles; those lines are silently skipped.
//
// The name character class ([a-zA-Z0-9_.-]+) covers all valid RubyGems package
// names: alphanumeric, underscores, hyphens, and dots (e.g. "net-http", "google-protobuf").
var gemSpecRe = regexp.MustCompile(`^    ([a-zA-Z0-9][a-zA-Z0-9._-]*) \(([^)]+)\)$`)

// parseGemfileLock is the EcosystemAdapter.ParseLockfile implementation for Ruby.
//
// It reads Gemfile.lock and returns the full resolved dependency closure from
// the GEM/specs section. All deps are tagged "runtime" because Gemfile.lock's
// standard format does not encode group (development/test) membership — see the
// dep-type classification note in the file header.
//
// Contract:
//   - (nil, false, nil)         → Gemfile.lock absent; caller may check Gemfile
//     but MUST mark the scan incomplete (no tool run = cannot resolve transitives).
//   - (deps, true, nil)         → closure is complete; all packages have pinned versions.
//   - (nil, false, err)         → I/O or parse error.
//
// NEVER returns a partial closure with complete=false (EcosystemAdapter invariant):
// a partial dep list would cause false NOT_REACHABLE for the missing transitive
// portion, silently dropping real vulnerabilities.
func parseGemfileLock(root string) ([]ResolvedDep, bool, error) {
	lockPath := filepath.Join(root, "Gemfile.lock")
	f, err := os.Open(lockPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No Gemfile.lock means the Ruby project is manifest-only.
			// Resolving the transitive closure requires `bundle install`,
			// which evaluates the Gemfile (ACE risk). Return incomplete rather
			// than running an untrusted tool.
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("open Gemfile.lock: %w", err)
	}
	defer func() { _ = f.Close() }()

	var deps []ResolvedDep
	// seen deduplicates (name, version): Bundler lists a gem once per resolved
	// platform, so the same gem@version appears multiple times.
	seen := make(map[string]bool)
	inGemSection := false
	inSpecs := false
	firstLine := true

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// Normalize line endings: bufio.ScanLines already strips trailing \n
		// (and \r\n via dropCR), but strip \r explicitly as defense-in-depth
		// against any future scanner customization or non-standard encodings.
		line = strings.TrimRight(line, "\r")

		// Strip UTF-8 BOM (0xEF 0xBB 0xBF) from the first line only.
		// A BOM-prefixed Gemfile.lock would corrupt the section header
		// ("\xEF\xBB\xBFGEM" ≠ "GEM"), silently producing an empty closure
		// with complete=true — a false-clean result (unknown ≠ safe).
		if firstLine {
			line = strings.TrimPrefix(line, "\xEF\xBB\xBF")
			firstLine = false
		}

		// Track which top-level section we are in.
		// Top-level section headers have no leading whitespace.
		if len(line) > 0 && line[0] != ' ' {
			trimmed := strings.TrimRight(line, " \t\r")
			switch trimmed {
			case "GEM", "GIT":
				// GIT-sourced gems carry real names and versions that can match
				// published OSV advisories. Silently dropping them (false-clean)
				// would violate the "unknown ≠ safe" invariant. Parse GIT specs
				// with the same logic as GEM specs.
				inGemSection = true
				inSpecs = false
			case "PLATFORMS", "DEPENDENCIES", "BUNDLED WITH", "PATH", "PLUGIN SOURCE":
				// PATH gems are local filesystem sources with no OSV index entry;
				// they are intentionally skipped.
				// Entering any other non-GEM section: exit GEM/specs context.
				inGemSection = false
				inSpecs = false
			}
			continue
		}

		if !inGemSection {
			continue
		}

		// Inside the GEM section, look for the "  specs:" sub-header.
		if strings.TrimSpace(line) == "specs:" {
			inSpecs = true
			continue
		}

		if !inSpecs {
			continue
		}

		// Spec lines: exactly 4-space indent → gem name + version.
		// Dependency sub-lines: 6+ space indent → constraints on the gem's own
		// dependencies; we skip those (we only need the gem name and version).
		m := gemSpecRe.FindStringSubmatch(line)
		if m == nil {
			// Not a gem spec line (e.g., a sub-dependency constraint line,
			// a blank line, or a remote: / source: header). Skip.
			continue
		}

		name := m[1]
		version := m[2]
		// Strip the platform suffix Bundler appends to a platform-specific gem
		// (e.g. "nokogiri (1.19.0-x86_64-linux-gnu)"). A Gem::Version never
		// contains "-" (pre-release segments use "."), so the platform is
		// everything from the first "-". Without this, every platform variant of
		// the same gem@version is treated as a distinct dependency and matches
		// the same advisories, multiplying the finding count (e.g. 9x for a gem
		// pinned in nine platform variants).
		if dash := strings.IndexByte(version, '-'); dash >= 0 {
			version = version[:dash]
		}
		if name == "" || version == "" {
			// Degenerate match: skip without failing.
			continue
		}

		// Deduplicate by (name, version): the platform variants collapse to one.
		key := name + "\x00" + version
		if seen[key] {
			continue
		}
		seen[key] = true

		deps = append(deps, ResolvedDep{
			Name:    name,
			Version: version,
			// All gems are tagged "runtime" because Gemfile.lock does not
			// encode group membership (development/test) — see file header.
			DepType: "runtime",
		})
	}

	if err := scanner.Err(); err != nil {
		// Scanner I/O error: cannot trust any partial result.
		return nil, false, fmt.Errorf("read Gemfile.lock: %w", err)
	}

	// An empty closure (no gems) with complete=true is valid — a project with
	// zero dependencies has no advisories to query.
	return deps, true, nil
}
