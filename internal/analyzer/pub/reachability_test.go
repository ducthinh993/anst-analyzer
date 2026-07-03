package pub

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/commit0-dev/commit0-analyzer/internal/analyzer"
	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// TestReachability_InProcessDispatch runs the analyzer through the in-process
// transport (analyzer.Run) and proves it decides routed advisories end-to-end: a
// used package resolves to PACKAGE_REACHABLE and a provably-unused one to
// NOT_REACHABLE over a hermetic Dart fixture — the same verdicts the former
// subprocess plugin produced.
func TestReachability_InProcessDispatch(t *testing.T) {
	tmp := t.TempDir()
	root := projectRoot(t, tmp, "http") // project imports package:http
	dirHTTP := depDir(t, tmp, "http")
	dirEvil := depDir(t, tmp, "evil") // present in closure, never imported
	writePackageConfig(t, root, map[string]string{"app": root, "http": dirHTTP, "evil": dirEvil})

	a := New()
	require.Equal(t, "pub-reachability", a.Name())
	require.Equal(t, []string{"Pub"}, a.Ecosystems())

	res := analyzer.Run(context.Background(), a, analyzer.Input{
		ModuleRoot: root,
		Advisories: []*commit0v1.Advisory{adv("CVE-HTTP", "http"), adv("CVE-EVIL", "evil")},
	}, 0)
	require.NoError(t, res.Err)
	assert.False(t, res.Incomplete)

	byMod := make(map[string]*commit0v1.Finding)
	for _, f := range res.Findings {
		byMod[f.GetModule()] = f
	}
	require.Len(t, byMod, 2, "one finding per routed advisory")
	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE, byMod["http"].GetConfidence())
	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE, byMod["evil"].GetConfidence())
}

// TestReachability_ClosureIncompleteForbidsNotReachable proves the host's
// closure_incomplete signal flows through the seam: a partial closure forbids
// NOT_REACHABLE (the verdict widens to UNKNOWN, incomplete propagates).
func TestReachability_ClosureIncompleteForbidsNotReachable(t *testing.T) {
	tmp := t.TempDir()
	root := projectRoot(t, tmp, "http")
	dirHTTP := depDir(t, tmp, "http")
	dirEvil := depDir(t, tmp, "evil")
	writePackageConfig(t, root, map[string]string{"app": root, "http": dirHTTP, "evil": dirEvil})

	res := analyzer.Run(context.Background(), New(), analyzer.Input{
		ModuleRoot:        root,
		ClosureIncomplete: true,
		Advisories:        []*commit0v1.Advisory{adv("CVE-EVIL", "evil")},
	}, 0)
	require.NoError(t, res.Err)
	assert.True(t, res.Incomplete, "a partial closure must propagate incomplete")
	require.Len(t, res.Findings, 1)
	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_UNKNOWN, res.Findings[0].GetConfidence())
}
