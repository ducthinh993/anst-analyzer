package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/commit0-dev/commit0-analyzer/internal/advisory"
	"github.com/commit0-dev/commit0-analyzer/internal/analyzer"
	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// TestEcosystemsForLanguages_JSOwnsNpm proves the subprocess routing key: a JS
// plugin manifest (Languages ["js","ts"]) maps to exactly the npm ecosystem, so
// the host hands it only npm advisories. "ts" carries no distinct ecosystem.
func TestEcosystemsForLanguages_JSOwnsNpm(t *testing.T) {
	assert.Equal(t, []string{advisory.EcosystemNPM}, ecosystemsForLanguages([]string{"js", "ts"}))
	assert.Equal(t, []string{advisory.EcosystemGo}, ecosystemsForLanguages([]string{"go"}))
	assert.Equal(t, []string{advisory.EcosystemCratesIO}, ecosystemsForLanguages([]string{"rust"}))
	assert.Equal(t, []string{advisory.EcosystemPyPI}, ecosystemsForLanguages([]string{"python"}))
}

// TestRoutedRequest_JSSubprocessNeverSeesNonNpm is the #15 fix at the scan seam:
// given a polyglot advisory set, the request routed to the js-reachability
// subprocess plugin contains only npm advisories — a Go or Pub advisory never
// reaches the subprocess request.
func TestRoutedRequest_JSSubprocessNeverSeesNonNpm(t *testing.T) {
	advsByEco := map[string][]*commit0v1.Advisory{
		advisory.EcosystemNPM:      {{Id: "NPM-1", Module: "lodash"}, {Id: "NPM-2", Module: "axios"}},
		advisory.EcosystemGo:       {{Id: "GO-1", Module: "golang.org/x/net"}},
		advisory.EcosystemPub:      {{Id: "PUB-1", Module: "http"}},
		advisory.EcosystemCratesIO: {{Id: "RUST-1", Module: "tokio"}},
	}
	base := &commit0v1.AnalyzeRequest{ModuleRoot: "/proj"}

	// The js plugin manifest declares Languages ["js","ts"].
	jsEcos := ecosystemsForLanguages([]string{"js", "ts"})
	routed := routedRequest(base, analyzer.Owned(advsByEco, jsEcos))

	require.Len(t, routed.GetAdvisories(), 2, "only the two npm advisories reach the js subprocess")
	for _, a := range routed.GetAdvisories() {
		assert.Contains(t, []string{"lodash", "axios"}, a.GetModule(),
			"a non-npm advisory (%s) must never reach the js subprocess request", a.GetId())
	}
	// Base-request fields survive the per-plugin routing.
	assert.Equal(t, "/proj", routed.GetModuleRoot())
}

// TestAdvisoryRouting_NoOrphanAcrossTransports asserts the whole-scan invariant:
// every resolved advisory is either routed to some transport (subprocess plugin
// or in-process analyzer) or kept as unowned (its existing host-side direct
// finding). count(in) == count(routed) + count(unowned).
func TestAdvisoryRouting_NoOrphanAcrossTransports(t *testing.T) {
	advsByEco := map[string][]*commit0v1.Advisory{
		advisory.EcosystemNPM:   {{Id: "NPM-1"}, {Id: "NPM-2"}},
		advisory.EcosystemGo:    {{Id: "GO-1"}},
		advisory.EcosystemPub:   {{Id: "PUB-1"}, {Id: "PUB-2"}},
		advisory.EcosystemMaven: {{Id: "MVN-1"}}, // lockfile-static, no analyzer → unowned/direct
	}
	total := 0
	for _, advs := range advsByEco {
		total += len(advs)
	}

	// Owners: js→npm, go→Go subprocess; pub→Pub in-process. Maven has no
	// reachability transport (unowned → direct PACKAGE_REACHABLE finding).
	owned := map[string]bool{}
	for _, e := range ecosystemsForLanguages([]string{"js", "go"}) {
		owned[e] = true
	}
	owned[advisory.EcosystemPub] = true

	routed, unowned := analyzer.Partition(advsByEco, owned)
	assert.Equal(t, total, len(routed)+len(unowned),
		"no advisory orphaned: in == routed + unowned")
	assert.Len(t, unowned, 1, "the Maven advisory stays unowned (host-side direct finding), never dropped")
}

// TestPubAdapterGraduatedInProcess proves the pub adapter is wired to the
// in-process seam (not the subprocess HasPlugin path) and owns exactly the Pub
// ecosystem, so the Dart analyzer only ever receives Pub advisories.
func TestPubAdapterGraduatedInProcess(t *testing.T) {
	var pubAdapter *EcosystemAdapter
	for _, a := range EcosystemAdapters() {
		if a.Ecosystem == advisory.EcosystemPub {
			adapter := a
			pubAdapter = &adapter
			break
		}
	}
	require.NotNil(t, pubAdapter, "the Pub adapter must be registered")

	assert.NotNil(t, pubAdapter.Analyzer, "Pub must be graduated to the in-process analyzer seam")
	assert.False(t, pubAdapter.HasPlugin, "Pub must not use the subprocess plugin path any more")
	assert.NotNil(t, pubAdapter.ParseLockfile, "the analyzer's closure source (ParseLockfile) must remain")
	assert.Equal(t, ceilingPackage, pubAdapter.MaxConfidence, "the analyzer proves NOT_REACHABLE below the package tier, never SYMBOL above it")
	assert.Equal(t, []string{advisory.EcosystemPub}, pubAdapter.Analyzer.Ecosystems(),
		"the Dart analyzer owns exactly the Pub ecosystem")
}
