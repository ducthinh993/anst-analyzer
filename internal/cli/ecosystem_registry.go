package cli

import (
	"strings"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
)

// ResolvedDep is a single dependency from a lockfile-static parse.
// It carries the minimum information needed for an OSV advisory query and
// dep-type segmentation (the dev_only gate).
type ResolvedDep struct {
	// Name is the ecosystem-specific package name (e.g. "org.springframework:spring-core").
	Name string
	// Version is the resolved version string from the lockfile.
	Version string
	// DepType is the dependency classification from the lockfile:
	// "runtime", "dev", "test", "optional", or "" (unknown, treated as runtime by the gate).
	// Dep-type segmentation is only possible when the lockfile explicitly records it;
	// if the format does not encode dep-type, tag all deps as "" (not as "runtime") so
	// the caller can log that segmentation was unavailable rather than silently assuming runtime.
	DepType string
}

// confidenceCeiling is the maximum reachability confidence an ecosystem can
// currently prove. It is a local capability tier so adapter files need not
// import the generated proto package; it is mapped to the wire-level
// commit0v1.Confidence only at the scan seam (ceilingToConfidence in scan.go).
type confidenceCeiling int

const (
	// ceilingPackage caps findings at PACKAGE_REACHABLE. Lockfile-static
	// ecosystems use this: advisory records carry no method/function-level data,
	// so the strongest provable statement is "the vulnerable package is present
	// in the resolved dependency closure".
	ceilingPackage confidenceCeiling = iota
	// ceilingSymbol permits SYMBOL_REACHABLE. Plugin-backed ecosystems use this:
	// a reachability plugin can trace a real call path into the vulnerable symbol.
	ceilingSymbol
)

// EcosystemAdapter describes one supported ecosystem in the single unified
// registry. It is the one taxonomy for detection, --language validation, and
// (for lockfile-static ecosystems) advisory resolution.
//
// Two capability tiers coexist in the same registry:
//   - Plugin-backed ecosystems (Go, JS/TS, Rust, Python) leave ParseLockfile
//     nil. Their dependency closure and call-graph reachability are produced by
//     a reachability plugin (dispatched in scan.go), so MaxConfidence is the
//     symbol ceiling. The registry entry carries only detection files and the
//     --language taxonomy; scan.go still owns their bespoke resolvers and plugin
//     dispatch — the registry is the single taxonomy, not (yet) the single dispatcher.
//   - Lockfile-static ecosystems (Maven, NuGet, Packagist, RubyGems, Hex, Pub,
//     SwiftURL, …) set ParseLockfile. The host parses the lockfile statically to
//     obtain the resolved closure, then queries advisories per dependency.
//     MaxConfidence is the package ceiling.
//
// Adding a lockfile ecosystem is one registry entry plus a version comparator;
// there are no per-language switches to update.
type EcosystemAdapter struct {
	// Ecosystem is the OSV ecosystem name (e.g. "Go", "npm", "Maven", "NuGet").
	// For lockfile-static ecosystems this value is passed to
	// OSVBundleSource.Refresh and used as the Package.Ecosystem when querying
	// advisories.
	Ecosystem string

	// Language is the --language flag value for this ecosystem (e.g. "java").
	// It must appear in orderedLanguages so users can select this ecosystem
	// explicitly and the --language error message can enumerate it.
	Language string

	// DetectFiles is a list of filenames; if ANY exists in the module root, this
	// ecosystem is considered present. Detection is zero-config: the ecosystem is
	// recognised automatically when `commit0-analyzer scan <path>` is invoked (no
	// --language flag needed). Entries beginning with "*." are treated as suffix
	// globs (e.g. "*.csproj" matches any non-directory file ending in ".csproj").
	//
	// For lockfile-static ecosystems, at least one entry must be a lockfile (not
	// only an executable manifest) to avoid the ACE risk of detecting a
	// manifest-only project and then running the build tool to resolve deps.
	DetectFiles []string

	// MaxConfidence is the proof ceiling this ecosystem supports today:
	// ceilingSymbol for plugin-backed ecosystems, ceilingPackage for
	// lockfile-static ones (advisory data carries no symbol information).
	MaxConfidence confidenceCeiling

	// ParseLockfile parses the lockfile(s) at root and returns the resolved dep
	// closure. It is set only for lockfile-static ecosystems; plugin-backed
	// ecosystems leave it nil (their resolvers are tool/plugin-backed and remain
	// in scan.go).
	//
	// Security invariants (ACE-safety — lockfile-static ecosystems only):
	//   - ParseLockfile MUST parse only the lockfile (or other static declarative
	//     artifacts). It MUST NOT evaluate the build manifest (Gemfile, mix.exs,
	//     Package.swift, conanfile.py, build.gradle[.kts] are executable code —
	//     running them on an untrusted repo is arbitrary code execution).
	//   - ParseLockfile MUST NOT run a build tool or its repo wrapper (mvn, gradle,
	//     ./mvnw, ./gradlew, dotnet restore, bundle install, mix deps.get, etc.)
	//     unless the tool is sandboxed (network-denied, dropped privileges, fixed-path
	//     toolchain). If a tool must run and cannot be sandboxed, return complete=false.
	//
	// Contract:
	//   - complete=true: closure is the fully-resolved transitive dep closure; the
	//     caller proceeds to query OSV for each dep. An empty closure with complete=true
	//     is valid (project has no dependencies).
	//   - complete=false: the closure could not be resolved (missing lockfile, parse
	//     error, or the resolver requires running a build tool). The caller MUST set
	//     incomplete=true and skip the OSV query for this ecosystem. NEVER return
	//     a partial closure with complete=false — that would produce false
	//     NOT_REACHABLE for the missing portion.
	//   - err non-nil implies complete=false. Return both for caller convenience
	//     (the caller checks complete first, then logs err if non-nil).
	ParseLockfile func(root string) (closure []ResolvedDep, complete bool, err error)

	// NormalizeName optionally transforms a package name from the lockfile before
	// it is passed to the OSV advisory query. This allows adapter-specific
	// normalization (e.g. case folding for case-insensitive registries).
	//
	// If nil, the name is used as-is (identity). Adapter authors MUST set this
	// only when the OSV index for the ecosystem uses a different canonical form
	// than the lockfile. Maven coordinates are case-sensitive and are preserved
	// in OSV records; do NOT set NormalizeName for Maven adapters. PyPI names
	// are case-insensitive; a future PyPI adapter would set NormalizeName to
	// strings.ToLower (or a PEP-503-compliant normalizer).
	NormalizeName func(name string) string
}

// ecosystems is the set of ecosystems in scope for a scan, keyed by --language
// value. Membership means "detected in the module root, or explicitly selected
// via --language". It is backed by a map so adding an ecosystem never touches a
// switch statement; deterministic output ordering is derived from
// orderedLanguages, NEVER from map iteration.
type ecosystems map[string]bool

// active reports whether lang is in scope for this scan.
func (e ecosystems) active(lang string) bool { return e[lang] }

// set marks lang as in scope.
func (e ecosystems) set(lang string) { e[lang] = true }

// clear removes lang from scope.
func (e ecosystems) clear(lang string) { delete(e, lang) }

// any reports whether at least one ecosystem is in scope.
func (e ecosystems) any() bool {
	for _, on := range e {
		if on {
			return true
		}
	}
	return false
}

// clone returns an independent copy of the set. Callers that derive a reduced
// set (e.g. unsupportedEco) MUST clone first: ecosystems is a map (reference
// type), so a plain assignment would alias and mutating the copy would corrupt
// the original.
func (e ecosystems) clone() ecosystems {
	out := make(ecosystems, len(e))
	for k, v := range e {
		out[k] = v
	}
	return out
}

// orderedLanguages is the canonical, deterministic ordering of every supported
// --language value. It is the single source of truth for user-visible ordering:
// the --language error enumeration (languageChoices) and the
// unsupported-ecosystem warning order (warnUnsupportedEcosystems). Ordering is
// NEVER derived from map or registry iteration.
var orderedLanguages = []string{
	"go", "js", "rust", "python",
	"java", "dotnet", "php", "ruby", "elixir", "dart", "swift",
}

// ecosystemRegistry is the global adapter registry. The plugin-backed ecosystems
// (Go, JS/TS, Rust, Python) are seeded here in the var literal; lockfile-static
// adapters append themselves at package init time from their own files
// (ecosystem_maven.go, ecosystem_nuget.go, …). Access is not synchronized: all
// writes happen during package initialization, all reads happen during scan.
//
// The seeded plugin-backed entries carry only detection files and taxonomy
// (ParseLockfile is nil); scan.go owns their resolvers and plugin dispatch.
var ecosystemRegistry = []EcosystemAdapter{
	{
		Ecosystem:     advisory.EcosystemGo,
		Language:      "go",
		DetectFiles:   []string{"go.mod"},
		MaxConfidence: ceilingSymbol,
	},
	{
		Ecosystem:     advisory.EcosystemNPM,
		Language:      "js",
		DetectFiles:   []string{"package.json"},
		MaxConfidence: ceilingSymbol,
	},
	{
		Ecosystem:     advisory.EcosystemCratesIO,
		Language:      "rust",
		DetectFiles:   []string{"Cargo.toml"},
		MaxConfidence: ceilingSymbol,
	},
	{
		Ecosystem:     advisory.EcosystemPyPI,
		Language:      "python",
		DetectFiles:   []string{"pyproject.toml", "requirements.txt"},
		MaxConfidence: ceilingSymbol,
	},
}

// RegisterEcosystemAdapter appends an adapter to the global registry.
// Must be called only from init() functions (before any concurrent use).
func RegisterEcosystemAdapter(a EcosystemAdapter) {
	ecosystemRegistry = append(ecosystemRegistry, a)
}

// EcosystemAdapters returns a snapshot of every registered adapter.
// The returned slice is a copy; modifications do not affect the registry.
func EcosystemAdapters() []EcosystemAdapter {
	out := make([]EcosystemAdapter, len(ecosystemRegistry))
	copy(out, ecosystemRegistry)
	return out
}

// lockfileAdapters returns the subset of registered adapters that resolve their
// dependency closure by static lockfile parsing (ParseLockfile != nil). This is
// the set the host runs directly: it parses the lockfile and queries advisories
// per dep. Plugin-backed ecosystems (ParseLockfile nil) are excluded — their
// closure and reachability come from a plugin dispatched in scan.go.
//
// Order is registry insertion order, which for the lockfile subset preserves the
// historical adapter ordering (finding accumulation order is unchanged).
func lockfileAdapters() []EcosystemAdapter {
	out := make([]EcosystemAdapter, 0, len(ecosystemRegistry))
	for _, a := range ecosystemRegistry {
		if a.ParseLockfile != nil {
			out = append(out, a)
		}
	}
	return out
}

// isKnownLanguage reports whether lang is a valid --language value. Validation
// is against orderedLanguages so it shares a single source of truth with the
// error enumeration and is independent of registry mutation.
func isKnownLanguage(lang string) bool {
	for _, l := range orderedLanguages {
		if l == lang {
			return true
		}
	}
	return false
}

// languageChoices renders the deterministic "auto|go|js|…" enumeration used in
// the --language error message. It is derived from orderedLanguages so the list
// never drifts from the set of accepted values.
func languageChoices() string {
	return "auto|" + strings.Join(orderedLanguages, "|")
}

// mergeDepType updates depTypeByAdvID for the given advisory ID.
//
// Conservative semantics (must be used by ALL resolve paths: Python, lockfile-static, etc.):
//   - "runtime" wins over any other type; once set to "runtime" it cannot be downgraded.
//   - An empty depType is treated as "runtime" (unknown dep-type must NOT default to
//     "dev" — that would cause the dev_only gate to suppress a runtime-reachable vuln,
//     a false-clean pass violating the "unknown ≠ safe" invariant).
//   - A non-runtime type is stored only when no prior entry exists for this advisory.
//     Subsequent non-runtime types do not overwrite the first (keeps deterministic output).
//
// The dep_type field populated here drives the dev_only policy gate. Any deviation
// from this function's semantics is a security-relevant correctness bug.
func mergeDepType(depTypeByAdvID map[string]string, advID, depType string) {
	existing, ok := depTypeByAdvID[advID]
	if ok && existing == "runtime" {
		return // already runtime; cannot be downgraded
	}
	dt := depType
	if dt == "" {
		dt = "runtime" // conservative: unknown dep-type defaults to runtime
	}
	if dt == "runtime" {
		depTypeByAdvID[advID] = "runtime"
	} else if !ok {
		// First non-runtime dep for this advisory; record it.
		depTypeByAdvID[advID] = dt
	}
	// dt != "runtime" && ok (e.g. a second "test" dep after an initial "dev"):
	// keep the initial value; do not overwrite with a possibly-different non-runtime type.
}
