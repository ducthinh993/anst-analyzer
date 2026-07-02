package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// advisoryDep is one resolved dependency ready for an advisory query. The caller
// precomputes every name and descriptor field so the engine's stderr output
// stays byte-identical across ecosystems (the scan test suite asserts these
// warning strings verbatim).
type advisoryDep struct {
	// QueryName is the package name used in the advisory.Package lookup key.
	// Callers apply any ecosystem-specific normalization before constructing the
	// dep (npm/PyPI lowercase; Maven preserves case), matching the pre-refactor
	// per-block normalization exactly.
	QueryName string
	// Version is the resolved version string from the lockfile/module graph.
	Version string
	// Module is the module identifier stamped onto any finding synthesized by the
	// PerAdvisory hook (dep.Path for Go, dep.Name elsewhere). It is independent of
	// QueryName because the finding preserves the original (non-normalized) name.
	Module string
	// DepType is the lockfile dependency classification. It is folded via
	// mergeDepType only when DepTypeByAdv is non-nil (Python + lockfile adapters);
	// other ecosystems leave it empty and do not track dep types.
	DepType string
	// SourcesFailDesc is the subject printed in the SourcesIncompleteError warning
	// ("advisory source %q failed for <SourcesFailDesc>: ..."). For npm it carries
	// the "(workspace X)" suffix that the fatal-query/enrichment descriptor omits.
	SourcesFailDesc string
	// Desc is the subject for the fatal-query warning AND the enrichment
	// descriptor. In every pre-refactor block these two call sites used an
	// identical string, so a single field preserves both verbatim.
	Desc string
}

// advisoryResolution carries the shared, caller-owned bookkeeping and hooks that
// resolveDepAdvisories folds each dependency's advisories into. The accumulators
// are held by pointer/reference so the engine mutates the caller's existing scan
// state in place — incomplete propagation, source attribution, severity, risk,
// and dep-type maps are all threaded through unchanged.
type advisoryResolution struct {
	// Ecosystem is the advisory.Ecosystem* value for the advisory.Package lookup.
	Ecosystem string
	// Source is the merged multi-source queried once per dependency.
	Source *advisory.MultiSource
	// Enrich is the post-merge enrichment chain applied to each dep's advisories.
	Enrich advisory.EnrichmentChain

	// ProtoAdvs accumulates every resolved advisory (proto form) across all deps.
	ProtoAdvs *[]*commit0v1.Advisory
	// SourcesByID records merged source attribution per advisory ID.
	SourcesByID map[string][]string
	// AdvByID records the resolved+enriched advisory per ID (for risk/provenance).
	AdvByID map[string]*advisory.Advisory
	// SeverityByID records the CVSS-derived severity per advisory ID.
	SeverityByID map[string]advisory.Severity
	// DepTypeByAdv, when non-nil, folds each dep's DepType via mergeDepType so the
	// dev_only policy gate can segment findings. Nil disables dep-type tracking.
	DepTypeByAdv map[string]string
	// Incomplete is the scan-level "unknown ≠ safe" flag. The engine sets it true
	// on a failed source, a fatal query error, or an undecidable advisory version —
	// never silently dropping coverage.
	Incomplete *bool

	// PostEnrich runs after enrichment and before the fold, for precision-only
	// passes that mutate advisories in place (npm vulnerable-symbol resolution).
	// Nil skips it.
	PostEnrich func(advs []advisory.Advisory)
	// PerAdvisory runs once per resolved advisory during the fold, for per-block
	// finding synthesis (package-level UNKNOWN findings under
	// --skip-reachability-analysis, or the lockfile-adapter PACKAGE_REACHABLE/
	// UNKNOWN findings). Nil skips it. It receives a pointer into the dep's
	// advisory slice, matching the pre-refactor aliasing exactly.
	PerAdvisory func(dep advisoryDep, adv *advisory.Advisory)
}

// resolveDepAdvisories queries res.Source for each dep, applies enrichment, and
// folds the results into res's caller-owned bookkeeping. It is the single shared
// implementation of the per-dependency advisory-resolution loop that every scan
// path (Go, npm, crates.io, PyPI, and the lockfile-adapter registry) runs.
//
// Error taxonomy (preserved byte-for-byte from the pre-refactor blocks):
//   - *advisory.SourcesIncompleteError → warn per failed source, mark incomplete,
//     but still fold the advisories that succeeded (partial coverage is kept).
//   - *advisory.StalenessWarningError  → warn, fold staleWarn.Advisories.
//   - any other query error            → warn, mark incomplete, skip this dep.
//   - adv.Incomplete (undecidable version) → mark incomplete (unknown ≠ safe).
func resolveDepAdvisories(ctx context.Context, res advisoryResolution, deps []advisoryDep) {
	for _, dep := range deps {
		pkg := advisory.Package{Ecosystem: res.Ecosystem, Name: dep.QueryName}
		advs, queryErr := res.Source.Query(ctx, pkg, dep.Version)

		// A *SourcesIncompleteError means one or more sources failed for this dep.
		// Warn + mark incomplete, but still gate on the advisories that succeeded.
		var srcIncomplete *advisory.SourcesIncompleteError
		if queryErr != nil && errors.As(queryErr, &srcIncomplete) {
			for i, name := range srcIncomplete.FailedSources {
				fmt.Fprintf(os.Stderr, "warning: advisory source %q failed for %s: %v\n",
					name, dep.SourcesFailDesc, srcIncomplete.Errors[i])
			}
			*res.Incomplete = true
		} else if queryErr != nil {
			// A non-StalenessWarning, non-SourcesIncomplete error (e.g. cache corrupt).
			var staleWarn *advisory.StalenessWarningError
			if errors.As(queryErr, &staleWarn) {
				fmt.Fprintf(os.Stderr, "warning: %s\n", staleWarn.Warning)
				advs = staleWarn.Advisories
			} else {
				fmt.Fprintf(os.Stderr, "commit0-analyzer scan: advisory query %s: %v\n",
					dep.Desc, queryErr)
				*res.Incomplete = true
				continue
			}
		}

		// Post-merge enrichment (CWE+KEV default-on; NVD/EPSS opt-in via --source).
		// A failed enricher warns and degrades but never marks the scan incomplete —
		// enrichment is prioritization metadata, not vulnerability coverage.
		runEnrichment(ctx, res.Enrich, advs, dep.Desc)

		// Precision-only pass (npm vulnerable-symbol resolution) runs before the
		// fold so any SymbolLevel promotion is reflected in the proto advisory.
		if res.PostEnrich != nil {
			res.PostEnrich(advs)
		}

		for i := range advs {
			// Propagate advisory-level Incomplete: an undecidable version comparison
			// must surface as incomplete=true so the scan exits 3, not 0.
			if advs[i].Incomplete {
				*res.Incomplete = true
			}
			*res.ProtoAdvs = append(*res.ProtoAdvs, advs[i].ToProto())
			if advs[i].ID != "" {
				res.SourcesByID[advs[i].ID] = advs[i].Sources
				res.AdvByID[advs[i].ID] = &advs[i]
				if advs[i].Severity != advisory.SeverityUnspecified {
					res.SeverityByID[advs[i].ID] = advs[i].Severity
				}
				// Conservative dep-type fold: "runtime" wins; empty dep-type is
				// runtime (unknown ≠ safe). Only when the path tracks dep types.
				if res.DepTypeByAdv != nil {
					mergeDepType(res.DepTypeByAdv, advs[i].ID, dep.DepType)
				}
			}
			// Per-block finding synthesis (package-level UNKNOWN, or lockfile-adapter
			// PACKAGE_REACHABLE/UNKNOWN). Runs after the maps so pointers folded into
			// AdvByID are already stamped; the resulting finding order is preserved.
			if res.PerAdvisory != nil {
				res.PerAdvisory(dep, &advs[i])
			}
		}
	}
}
