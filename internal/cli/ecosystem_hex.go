package cli

// ecosystem_hex.go — lockfile-static adapter for Hex (Elixir/Erlang).
//
// OSV ecosystem: "Hex" (https://osv.dev/list?ecosystem=Hex)
// Maximum confidence: PACKAGE_REACHABLE (Hex OSV advisories carry no method-level data).
//
// Security invariants (ACE-safety):
//   - NEVER evaluate mix.exs. mix.exs is Elixir source code — evaluating it is
//     arbitrary code execution (ACE) on an untrusted repo.
//   - NEVER evaluate rebar.config (Erlang source; same ACE risk).
//   - NEVER call mix, rebar3, or any build tool on untrusted repos.
//   - Parse ONLY the static mix.lock (Elixir term format) and rebar.lock
//     (Erlang term format). Both are deterministically machine-written files.
//
// Lockfile formats:
//   - mix.lock:   %{"pkg": {:hex, :pkg_atom, "version", "hash", [managers], [deps], "hexpm", "outer_hash"}, ...}
//   - rebar.lock: {[{"pkg",{pkg,"reg_name","version",...}}, ...], [1,0,0]}.
//
// Dep-type classification:
//   - mix.lock does NOT encode the :only scope ([:dev, :test]) from mix.exs.
//     The dep-type annotation (:only: [:dev, :test]) is declared in mix.exs,
//     which we must never read (ACE risk). Therefore all packages from mix.lock
//     are tagged "" (dep-type unknown) which the mergeDepType contract treats as
//     "runtime" — the conservative default (unknown ≠ dev).
//   - rebar.lock likewise does not encode dep-type; all packages are tagged "".
//   - This is a documented limitation. Tagging an actual dev dep as runtime causes
//     it to be checked against advisories (conservative), NOT silently skipped (dangerous).
//
// Positive-reachability framing:
//   - BEAM's dynamic dispatch (apply/3, GenServer callbacks, hot-code reloading,
//     Protocol dispatch) makes negative reachability (NOT_REACHABLE) unsound for
//     Elixir/Erlang.
//   - Maximum confidence is PACKAGE_REACHABLE (the vulnerable package is present in
//     the lockfile-resolved transitive closure). SYMBOL_REACHABLE is never emitted.
//
// Detection:
//   - mix.lock  → Elixir/Mix project with full resolved closure.
//   - rebar.lock → Erlang/Rebar3 project with full resolved closure.
//   - If neither lockfile is present → complete=false (no build-tool call is safe).

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
		Ecosystem: advisory.EcosystemHex,
		Language:  "elixir",
		// DetectFiles: mix.lock is the Elixir/Mix lockfile (complete transitive closure).
		// rebar.lock is the Erlang/Rebar3 lockfile (complete transitive closure).
		// mix.exs and rebar.config are INTENTIONALLY excluded: they are executable
		// Elixir/Erlang source code — detecting them without a lockfile would trigger
		// a scan that must return incomplete=true (cannot resolve without `mix deps.get`
		// or `rebar3 lock`), which is both correct and safe. However, since these
		// manifest-only projects cannot be resolved statically, excluding them from
		// DetectFiles avoids the misleading "detected but incomplete" pattern for projects
		// that simply haven't committed their lockfile yet.
		DetectFiles:   []string{"mix.lock", "rebar.lock"},
		MaxConfidence: ceilingPackage,
		ParseLockfile: parseHexLockfiles,
		// NormalizeName is nil: Hex package names are case-sensitive and match
		// the OSV Hex index exactly (e.g. "jason", "phoenix", "cowboy").
		NormalizeName: nil,
	})
}

// ── mix.lock parser ──────────────────────────────────────────────────────────

// mixLockHexEntryRe matches a Hex (hex.pm) package entry in mix.lock.
//
// mix.lock format (one entry per line, machine-written by mix):
//
//	%{"certifi": {:hex, :certifi, "2.9.0", "6f2a...", [:rebar3], [], "hexpm", "266..."},
//	  "castore": {:hex, :castore, "1.0.6", "ffc...", [:mix], [], "hexpm", "374..."},
//	  "git_dep": {:git, "https://github.com/owner/repo.git", "abcdef", [tag: "v1.0"]},
//	  "path_dep": {:path, "../my_dep", [env: :dev]},
//	}
//
// The opening %{ and the first entry appear on the SAME first line
// (%{"certifi": {:hex, ...}), so the regex must NOT be anchored at ^ — the
// entry starts at an arbitrary byte offset on that first line.  Subsequent
// lines are either continuation entries or the closing }.
//
// Only :hex entries are captured; :git and :path entries are intentionally skipped:
//   - :git entries have no Hex registry version → cannot match OSV Hex advisories.
//   - :path entries are local packages → no registry identity.
//
// Captured groups:
//
//	[1] = package name (the quoted map key, e.g. "certifi")
//	[2] = version string (e.g. "2.9.0")
var mixLockHexEntryRe = regexp.MustCompile(`"([^"]+)"\s*:\s*\{:hex,\s*:[^,]+,\s*"([^"]+)",`)

// parseMixLock reads mix.lock and returns the resolved Hex dependency closure.
//
// Contract:
//   - (nil, false, nil)      → mix.lock absent; caller marks scan incomplete.
//   - (deps, true, nil)      → complete closure; all :hex entries have pinned versions.
//   - (nil, false, err)      → I/O or read error.
//
// NEVER returns a partial closure with complete=false (EcosystemAdapter invariant):
// a partial dep list would produce false NOT_REACHABLE for the missing transitive
// portion, silently dropping real vulnerabilities.
//
// Dep-type: all deps are tagged "" (unknown, treated as runtime by mergeDepType).
// mix.lock does not encode the :only scope from mix.exs. See file header.
func parseMixLock(root string) ([]ResolvedDep, bool, error) {
	lockPath := filepath.Join(root, "mix.lock")
	f, err := os.Open(lockPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No mix.lock: resolving transitives requires `mix deps.get`, which
			// evaluates mix.exs (ACE risk). Return incomplete rather than running
			// an untrusted tool.
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("open mix.lock: %w", err)
	}
	defer func() { _ = f.Close() }()

	var deps []ResolvedDep
	hasMixLockMarker := false // set when we see the %{ map-open that every mix.lock starts with
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Strip Windows CRLF: bufio.ScanLines strips \n but not \r.
		line = strings.TrimRight(line, "\r")

		// Track the %{ map-open that every valid mix.lock must contain.
		// We intentionally check every line (not just the first) to be robust
		// against files with leading comments or non-standard whitespace.
		if strings.Contains(line, "%{") {
			hasMixLockMarker = true
		}

		m := mixLockHexEntryRe.FindStringSubmatch(line)
		if m == nil {
			// Not a :hex entry (map header, :git, :path, closing brace, blank line).
			continue
		}

		name := m[1]
		version := m[2]
		if name == "" || version == "" {
			// Degenerate regex match: skip without failing.
			continue
		}

		deps = append(deps, ResolvedDep{
			Name:    name,
			Version: version,
			// DepType is "" (unknown) because mix.lock does not encode the :only
			// scope from mix.exs. The mergeDepType contract treats "" as "runtime"
			// (conservative: unknown ≠ dev, so we check rather than skip).
			DepType: "",
		})
	}

	if err := scanner.Err(); err != nil {
		// Scanner I/O error: cannot trust any partial result.
		return nil, false, fmt.Errorf("read mix.lock: %w", err)
	}

	if len(deps) == 0 && !hasMixLockMarker {
		// File is present and readable but contains no recognisable %{ map-open
		// marker. This is either a corrupted file or an unrecognised format variant.
		// Per the 'unknown ≠ safe' invariant, returning complete=true here would
		// silently drop all Hex advisories for the project (false-clean). Return
		// complete=false so the caller marks the scan incomplete.
		// (Mirrors the parseRebarLock behaviour on zero-match content.)
		return nil, false, nil
	}

	// An empty closure (zero :hex deps) with complete=true is valid for a project
	// that has no Hex registry dependencies (e.g. only :git/:path deps, or a brand-
	// new project whose mix.lock is a bare %{}).
	return deps, true, nil
}

// ── rebar.lock parser ─────────────────────────────────────────────────────────

// rebarLockPkgRe matches a Hex (pkg) entry in rebar.lock.
//
// rebar.lock format (Erlang term, machine-written by rebar3):
// All string values are Erlang binary literals (<<"...">>), not plain atoms.
//
//	{[{<<"cowboy">>,{pkg,<<"cowboy">>,<<"2.10.0">>},0},
//	  {<<"ranch">>,{pkg,<<"ranch">>,<<"1.8.0">>},1},
//	  {<<"git_dep">>,{git,"https://github.com/owner/repo.git",{branch,"main"}},0}
//	 ],
//	 [1,0,0]}.
//
// Only {pkg,...} entries are captured; {git,...} entries are skipped (no Hex version).
//
// The file is read as a whole byte slice and matched with FindAllSubmatch because
// rebar3 may write multi-line entries. \s* handles optional whitespace/newlines between
// fields (RE2's \s matches \n).
//
// Captured groups:
//
//	[1] = dependency name (e.g. "cowboy") — binary literal in the outer tuple key
//	[2] = version string (e.g. "2.10.0")  — 2nd binary literal in the {pkg,...} tuple
var rebarLockPkgRe = regexp.MustCompile(`\{<<"([^"]+)">>,\s*\{pkg,\s*<<"[^"]*">>,\s*<<"([^"]+)">>`)

// parseRebarLock reads rebar.lock and returns the resolved Hex dependency closure.
//
// Contract:
//   - (nil, false, nil)      → rebar.lock absent; caller marks scan incomplete.
//   - (deps, true, nil)      → complete closure; all {pkg,...} entries have versions.
//   - (nil, false, err)      → I/O or read error.
//
// NEVER returns a partial closure with complete=false (EcosystemAdapter invariant).
//
// Dep-type: all deps are tagged "" (unknown, treated as runtime by mergeDepType).
// rebar.lock does not encode dep-type. See file header.
func parseRebarLock(root string) ([]ResolvedDep, bool, error) {
	lockPath := filepath.Join(root, "rebar.lock")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No rebar.lock: resolving transitives requires `rebar3 lock`, which
			// evaluates rebar.config (ACE risk). Return incomplete rather than
			// running an untrusted tool.
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read rebar.lock: %w", err)
	}

	// Match all {pkg,...} entries across the whole file (handles multi-line entries).
	matches := rebarLockPkgRe.FindAllSubmatch(data, -1)
	if matches == nil {
		// File is present and readable but contains no recognisable {pkg,...} entries.
		// This is either an empty lockfile (no Hex deps) or an unrecognised format
		// variant. Per the 'unknown ≠ safe' invariant, these cases are statically
		// indistinguishable; returning complete=true here would silently drop all
		// Hex advisories for the project (false-clean). Return complete=false so the
		// caller marks the scan incomplete.
		return nil, false, nil
	}

	deps := make([]ResolvedDep, 0, len(matches))
	for _, m := range matches {
		name := string(m[1])
		version := string(m[2])
		if name == "" || version == "" {
			continue
		}
		deps = append(deps, ResolvedDep{
			Name:    name,
			Version: version,
			// DepType is "" (unknown) because rebar.lock does not encode dep-type.
			// mergeDepType treats "" as "runtime" (conservative: unknown ≠ dev).
			DepType: "",
		})
	}

	return deps, true, nil
}

// ── combined lockfile entry point ─────────────────────────────────────────────

// parseHexLockfiles is the EcosystemAdapter.ParseLockfile implementation for Elixir/Erlang.
//
// It reads whichever of mix.lock and rebar.lock are present, merges the resulting
// closures, and returns complete=true iff at least one lockfile was successfully parsed.
//
// Merge rationale:
//   - A pure Elixir/Mix project has only mix.lock; mix.lock already contains the
//     full transitive closure including any rebar3 deps (mix pulls them in). In that
//     case, also scanning rebar.lock (if somehow present) may double-count a few deps;
//     this is conservative (more findings, not fewer) and harmless.
//   - A pure Erlang/Rebar3 project has only rebar.lock.
//   - A monorepo or umbrella app may have both; merging is correct behaviour.
//
// Contract:
//   - (nil, false, nil)   → no lockfile found; caller marks scan incomplete.
//   - (deps, true, nil)   → at least one lockfile parsed; deps is the merged closure.
//   - (nil, false, err)   → I/O or parse error in one of the lockfiles.
func parseHexLockfiles(root string) ([]ResolvedDep, bool, error) {
	var allDeps []ResolvedDep
	anyComplete := false

	mixDeps, mixComplete, mixErr := parseMixLock(root)
	if mixErr != nil {
		return nil, false, fmt.Errorf("mix.lock: %w", mixErr)
	}
	if mixComplete {
		allDeps = append(allDeps, mixDeps...)
		anyComplete = true
	}

	rebarDeps, rebarComplete, rebarErr := parseRebarLock(root)
	if rebarErr != nil {
		return nil, false, fmt.Errorf("rebar.lock: %w", rebarErr)
	}
	if rebarComplete {
		allDeps = append(allDeps, rebarDeps...)
		anyComplete = true
	}

	if !anyComplete {
		// Neither lockfile present → incomplete (cannot resolve without running a build tool).
		return nil, false, nil
	}

	return allDeps, true, nil
}
