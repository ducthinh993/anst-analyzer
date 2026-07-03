// Package analyzer is the in-process reachability seam. It defines the Analyzer
// interface an in-tree language analyzer implements, the Input the host hands it
// (module root, resolved closure, and advisories PRE-FILTERED to the analyzer's
// owned ecosystems), an in-process transport (Run) that runs an analyzer with the
// same fail-closed crash semantics the subprocess host applies, and the
// transport-agnostic advisory routing (Owned/Partition) that guarantees no
// analyzer — in-process or subprocess — ever receives an advisory for an
// ecosystem it does not own.
//
// The gRPC/allowlist/SHA-pinning machinery in internal/host enforces a trust and
// runtime boundary that does not exist for in-tree, same-module, pure-Go
// analyzers. Those graduate to this seam: transport becomes a function call, the
// resolved closure becomes an argument instead of a wire message, and a crash is
// a recovered panic instead of a killed process. The subprocess transport remains
// for foreign-runtime or third-party analyzers where the trust boundary is real.
package analyzer

import (
	"context"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// Input is the analysis request the host hands an in-process Analyzer.
type Input struct {
	// ModuleRoot is the absolute project root to analyze.
	ModuleRoot string

	// Closure is the host-parsed resolved dependency closure (for lockfile
	// ecosystems). It is the same data the subprocess contract carries as
	// resolved_deps; in-process it is a function argument rather than a wire
	// message, so an analyzer never re-parses the lockfile.
	Closure []*commit0v1.ResolvedDependency

	// ClosureIncomplete is the host's signal that the closure is partial. A partial
	// closure forbids any NOT_REACHABLE verdict (unknown ≠ safe).
	ClosureIncomplete bool

	// Advisories are the vulnerabilities to decide, PRE-FILTERED to this analyzer's
	// owned ecosystems (see Owned). Exactly one finding is expected per advisory; a
	// silently dropped advisory is the same cardinal sin as a false NOT_REACHABLE.
	Advisories []*commit0v1.Advisory
}

// Analyzer is one in-tree, in-process reachability analyzer.
type Analyzer interface {
	// Name is the stable analyzer identity used for deterministic result ordering
	// and synthetic-finding attribution. It matches the historical plugin name so
	// aggregated finding order is unchanged after a subprocess→in-process move.
	Name() string

	// Ecosystems is the set of OSV ecosystem names this analyzer owns (e.g. "Pub").
	// The host routes only advisories for these ecosystems into Analyze.
	Ecosystems() []string

	// Analyze decides reachability for in.Advisories over in.ModuleRoot. It returns
	// one finding per advisory, an incomplete flag (true when any verdict was
	// undecidable), and an error only for an operational failure. The in-process
	// transport (Run) converts a panic, timeout, or returned error into synthetic
	// UNKNOWN findings, so Analyze itself never has to.
	Analyze(ctx context.Context, in Input) (findings []*commit0v1.Finding, incomplete bool, err error)
}
