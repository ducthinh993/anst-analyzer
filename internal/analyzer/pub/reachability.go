package pub

import (
	"context"

	"github.com/commit0-dev/commit0-analyzer/internal/analyzer"
	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// ecosystem is the OSV ecosystem name this analyzer owns. It matches
// advisory.EcosystemPub host-side, which is how the host routes only "Pub"
// advisories into Analyze — a non-Pub advisory never reaches the Dart engine.
const ecosystem = "Pub"

// Reachability adapts the used-import Analyzer engine to the in-process
// analyzer.Analyzer seam. It is stateless; each Analyze call builds a fresh
// engine over the request's module root.
type Reachability struct{}

// New returns the in-process Dart/Pub reachability analyzer.
func New() analyzer.Analyzer { return Reachability{} }

// Name is the analyzer identity, kept identical to the former subprocess plugin
// name so aggregated finding order and any downstream attribution are unchanged.
func (Reachability) Name() string { return "pub-reachability" }

// Ecosystems returns the single OSV ecosystem this analyzer owns.
func (Reachability) Ecosystems() []string { return []string{ecosystem} }

// Analyze runs the used-import reachability engine and returns one finding per
// advisory plus an incomplete flag derived from the findings' partiality markers.
// The engine's own soundness ordering (a positive static reference wins; any
// incompleteness or dynamism frontier forbids NOT_REACHABLE) is unchanged from
// the subprocess implementation, so findings are byte-identical.
func (Reachability) Analyze(_ context.Context, in analyzer.Input) ([]*commit0v1.Finding, bool, error) {
	eng := &Analyzer{
		Root:              in.ModuleRoot,
		Advisories:        in.Advisories,
		ClosureIncomplete: in.ClosureIncomplete,
	}
	findings := eng.Analyze()
	incomplete := false
	for _, f := range findings {
		if f.GetIncomplete() {
			incomplete = true
		}
	}
	return findings, incomplete, nil
}
