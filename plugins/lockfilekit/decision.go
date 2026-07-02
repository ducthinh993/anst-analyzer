// Package lockfilekit is the shared Go toolkit every lockfile-ecosystem
// reachability plugin (Dart/pub, Elixir/hex, PHP/packagist, .NET/nuget,
// JVM/maven, …) imports. It centralizes the ONE soundness contract those
// plugins must all obey so no ecosystem can drift into a false NOT_REACHABLE.
//
// # What a lockfile-ecosystem plugin adds
//
// The host already resolves the lockfile closure and emits PACKAGE_REACHABLE
// (plus dev_only gating). A plugin's ONLY new value is source-level used-import
// NOT_REACHABLE: an advisory package that is present in the closure but provably
// never referenced in project source, with zero dynamism frontier. SYMBOL_REACHABLE
// is not built in v1 for any of these ecosystems (no advisory carries symbol data).
//
// # Soundness contract (the tier decision procedure)
//
// Given an advisory package X (resolved version present in the closure), the
// decision is NOT_REACHABLE ONLY when every one of these holds:
//   - the closure is complete (host said so),
//   - every project source file parsed cleanly,
//   - the project has NO dynamism frontier (reflection, eval, dynamic require,
//     DI-by-name scan, metaprogramming — anything that could load a package by
//     name without a resolvable static import),
//   - X's owned namespaces are known (the artifact was fetched/indexed), and
//   - none of X's owned namespaces appears in the project's used-token set.
//
// Any other state is UNKNOWN (never "safe") or PACKAGE_REACHABLE. This mirrors
// rust-reachability/internal/engine: NOT_REACHABLE only from a complete proof.
//
// # What each ecosystem plugin provides
//
//	usedTokens(root)     → (Set, parseIncomplete)   the identifiers referenced in source
//	frontier(root)       → Frontier                 the project's dynamism frontier
//	ownedNamespaces(dep) → (Set, mappingUnknown)    the namespaces a package owns
//
// Everything else — the walk, the fetch/cache, the decision — is shared here.
package lockfilekit

import (
	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// Set is a string set with the minimal operations the decision procedure needs.
type Set map[string]struct{}

// NewSet builds a Set from the given elements.
func NewSet(elems ...string) Set {
	s := make(Set, len(elems))
	for _, e := range elems {
		s[e] = struct{}{}
	}
	return s
}

// Add inserts an element.
func (s Set) Add(e string) { s[e] = struct{}{} }

// Has reports membership.
func (s Set) Has(e string) bool { _, ok := s[e]; return ok }

// Intersects reports whether s and other share at least one element. It scans
// the smaller set for efficiency.
func (s Set) Intersects(other Set) bool {
	small, large := s, other
	if len(large) < len(small) {
		small, large = large, small
	}
	for e := range small {
		if _, ok := large[e]; ok {
			return true
		}
	}
	return false
}

// Decision is the per-advisory input to Decide. It collects the facts the
// ecosystem plugin has gathered; Decide applies the shared soundness contract.
type Decision struct {
	// Advisory is the vulnerability being decided. Its Id/Module/Ecosystem are
	// copied onto the emitted Finding.
	Advisory *commit0v1.Advisory

	// Language is the finding's language tag (e.g. "dart", "php").
	Language string

	// Ecosystem is the finding's ecosystem tag.
	Ecosystem commit0v1.Ecosystem

	// ClosureIncomplete is the host's closure_incomplete signal: any adapter
	// returned a partial closure, so a missing transitive dep could be X.
	ClosureIncomplete bool

	// ParseIncomplete is true when any project source file failed to parse, so
	// the used-token set may be missing references to X.
	ParseIncomplete bool

	// Frontier is the project's dynamism frontier. When present, no package can
	// be proven unreachable (dynamic loading could reference X by name).
	Frontier Frontier

	// MappingUnknown is true when X's owned namespaces could not be determined
	// (artifact fetch failed, offline cache miss, or the ecosystem has no sound
	// name→namespace mapping at all).
	MappingUnknown bool

	// OwnedNamespaces is the set of namespaces/identifiers X owns.
	OwnedNamespaces Set

	// UsedTokens is the set of identifiers referenced anywhere in project source.
	UsedTokens Set
}

// Decide applies the shared tier decision procedure and returns exactly one
// Finding. NOT_REACHABLE is reachable ONLY through the final branch; every other
// branch is UNKNOWN (incomplete, carrying the synthetic partiality marker so the
// host exits 3) or PACKAGE_REACHABLE.
func Decide(d Decision) *commit0v1.Finding {
	switch {
	case d.ClosureIncomplete:
		return d.unknown("dependency closure is incomplete; a missing transitive dependency could reference this package")
	case d.ParseIncomplete:
		return d.unknown("a project source file failed to parse; the used-import set may be missing a reference to this package")
	case d.Frontier.Present():
		return d.unknown("project has a dynamism frontier (" + d.Frontier.Summary() + "); a package could be loaded by name without a static import")
	case d.MappingUnknown:
		return d.unknown("could not determine the namespaces this package owns (artifact unavailable or no sound name mapping)")
	case d.OwnedNamespaces.Intersects(d.UsedTokens):
		return d.finding(commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE, false,
			"package owns a namespace that is statically referenced in project source")
	default:
		return d.finding(commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE, false,
			"package present in closure but no static reference in project source (no dynamism frontier)")
	}
}

// unknown builds a CONFIDENCE_UNKNOWN finding carrying Incomplete=true and the
// wire-level synthetic partiality marker the host reads to exit 3.
func (d Decision) unknown(reason string) *commit0v1.Finding {
	f := d.finding(commit0v1.Confidence_CONFIDENCE_UNKNOWN, true, reason)
	f.Properties["synthetic"] = "true"
	return f
}

// finding constructs the base Finding shared by every tier.
func (d Decision) finding(conf commit0v1.Confidence, incomplete bool, reason string) *commit0v1.Finding {
	return &commit0v1.Finding{
		Advisory:   &commit0v1.AdvisoryRef{Id: d.Advisory.GetId()},
		Module:     d.Advisory.GetModule(),
		Confidence: conf,
		Incomplete: incomplete,
		Pillar:     "sca",
		Language:   d.Language,
		Ecosystem:  d.Ecosystem,
		Properties: map[string]string{"reason": reason},
	}
}
