// Package engine decides package-level reachability for the Dart/Pub plugin.
//
// # What it proves
//
// The host already resolves the pubspec.lock closure and emits PACKAGE_REACHABLE.
// This engine's only new value is NOT_REACHABLE: an advisory package that is in
// the closure but provably never referenced in the project's transitive
// used-import closure, with an empty dynamism frontier.
//
// # Soundness ordering (cardinal sin: a false NOT_REACHABLE)
//
//  1. Package statically referenced (directly or transitively) → PACKAGE_REACHABLE.
//     A positive static reference is definitive, so it wins over every
//     incompleteness/frontier condition (those only ever threaten NOT_REACHABLE).
//  2. Host closure incomplete → UNKNOWN. A missing transitive lockfile dep could
//     reference the package.
//  3. Dynamism frontier present (dart:mirrors, Isolate.spawnUri, build hook,
//     absent generated part) → UNKNOWN. A package could be loaded by name.
//  4. Source parse incomplete → UNKNOWN. A missed reference is possible.
//  5. Transitive walk incomplete (no package_config.json, or a dependency source
//     dir missing) → UNKNOWN. Unreachability is unproven.
//  6. Otherwise → NOT_REACHABLE, carrying the used-closure size as evidence.
//
// Mapping is the identity function (a `package:NAME/...` URI literally names its
// package), so there is no artifact download, no version lookup, and mapping is
// never unknown.
package engine

import (
	"fmt"
	"strconv"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// language is the finding language tag for every Dart finding.
const language = "dart"

// Analyzer decides reachability for one Dart project against a set of advisories.
type Analyzer struct {
	// Root is the absolute project directory to analyze.
	Root string

	// Advisories are the vulnerabilities to decide (the host has pre-matched them
	// to the pubspec.lock closure). Exactly one finding is emitted per advisory.
	Advisories []*commit0v1.Advisory

	// ClosureIncomplete is the host's closure_incomplete signal: some adapter
	// returned a partial closure, so no NOT_REACHABLE may be emitted.
	ClosureIncomplete bool
}

// Analyze computes the used-import closure once, then returns one finding per
// advisory. A silently dropped advisory would be the same cardinal sin as a false
// NOT_REACHABLE, so every advisory in Advisories yields exactly one finding.
func (a *Analyzer) Analyze() []*commit0v1.Finding {
	c := buildClosure(a.Root)
	findings := make([]*commit0v1.Finding, 0, len(a.Advisories))
	for _, adv := range a.Advisories {
		findings = append(findings, a.decide(adv, c))
	}
	return findings
}

// decide applies the soundness ordering to one advisory.
func (a *Analyzer) decide(adv *commit0v1.Advisory, c closure) *commit0v1.Finding {
	pkg := adv.GetModule()

	if c.Used.Has(pkg) {
		return newFinding(adv, commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE, false,
			"package is imported (directly or transitively) in the project's used-import closure")
	}

	switch {
	case a.ClosureIncomplete:
		return newUnknown(adv,
			"host dependency closure is incomplete; a missing transitive dependency could reference this package")
	case c.Frontier.Present():
		return newUnknown(adv,
			"project has a dynamism frontier ("+c.Frontier.Summary()+"); a package could be loaded by name without a static import")
	case c.ParseIncomplete:
		return newUnknown(adv,
			"a project source file could not be parsed (or a referenced part file is absent); the used-import set may be missing a reference")
	case c.TransitiveIncomplete:
		return newUnknown(adv,
			"the transitive used-import closure could not be completed (.dart_tool/package_config.json absent or a dependency source directory missing); "+
				"cannot prove the package unreferenced without running `dart pub get` (forbidden: build-hook ACE)")
	default:
		f := newFinding(adv, commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE, false,
			fmt.Sprintf("package absent from the used-import closure of %d package(s) rooted at project source; dynamism frontier clean", c.Size()))
		f.Properties["used_closure_size"] = strconv.Itoa(c.Size())
		return f
	}
}

// newFinding builds the base finding shared by every tier.
func newFinding(adv *commit0v1.Advisory, conf commit0v1.Confidence, incomplete bool, reason string) *commit0v1.Finding {
	return &commit0v1.Finding{
		Advisory:   &commit0v1.AdvisoryRef{Id: adv.GetId()},
		Module:     adv.GetModule(),
		Confidence: conf,
		Incomplete: incomplete,
		Pillar:     "sca",
		Language:   language,
		Ecosystem:  adv.GetEcosystem(),
		Properties: map[string]string{"reason": reason},
	}
}

// newUnknown builds a CONFIDENCE_UNKNOWN finding carrying the wire-level
// partiality markers (Incomplete=true and the synthetic property) the host reads
// to keep the scan from silently exiting clean.
func newUnknown(adv *commit0v1.Advisory, reason string) *commit0v1.Finding {
	f := newFinding(adv, commit0v1.Confidence_CONFIDENCE_UNKNOWN, true, reason)
	f.Properties["synthetic"] = "true"
	return f
}
