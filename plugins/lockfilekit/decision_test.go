package lockfilekit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// baseDecision returns a Decision that, unmodified, reaches the NOT_REACHABLE
// branch (complete closure, clean parse, no frontier, known mapping, no overlap).
// Each test perturbs exactly one field to isolate a branch.
func baseDecision() Decision {
	return Decision{
		Advisory:        &commit0v1.Advisory{Id: "CVE-TEST-1", Module: "pkg.example"},
		Language:        "java",
		Ecosystem:       commit0v1.Ecosystem_ECOSYSTEM_MAVEN,
		OwnedNamespaces: NewSet("pkg.example"),
		UsedTokens:      NewSet("other.thing"),
	}
}

func assertUnknownIncomplete(t *testing.T, f *commit0v1.Finding) {
	t.Helper()
	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_UNKNOWN, f.GetConfidence())
	assert.True(t, f.GetIncomplete(), "UNKNOWN findings must set Incomplete")
	assert.Equal(t, "true", f.GetProperties()["synthetic"],
		"UNKNOWN findings must carry the synthetic partiality marker so the host exits 3")
}

// Branch 1.
func TestDecide_ClosureIncomplete_Unknown(t *testing.T) {
	d := baseDecision()
	d.ClosureIncomplete = true
	// Even with a used-namespace overlap, an incomplete closure wins first.
	d.UsedTokens = NewSet("pkg.example")
	f := Decide(d)
	assertUnknownIncomplete(t, f)
	assert.Contains(t, f.GetProperties()["reason"], "closure is incomplete")
}

// Branch 2.
func TestDecide_ParseIncomplete_Unknown(t *testing.T) {
	d := baseDecision()
	d.ParseIncomplete = true
	f := Decide(d)
	assertUnknownIncomplete(t, f)
	assert.Contains(t, f.GetProperties()["reason"], "failed to parse")
}

// Branch 3: a dynamism frontier forbids NOT_REACHABLE even with no token overlap.
func TestDecide_Frontier_Unknown(t *testing.T) {
	d := baseDecision()
	d.Frontier.Add("reflection: Class.forName")
	f := Decide(d)
	assertUnknownIncomplete(t, f)
	assert.Contains(t, f.GetProperties()["reason"], "reflection: Class.forName",
		"the frontier reason must be surfaced so the user sees why it could not be proven clean")
}

// Branch 4.
func TestDecide_MappingUnknown_Unknown(t *testing.T) {
	d := baseDecision()
	d.MappingUnknown = true
	f := Decide(d)
	assertUnknownIncomplete(t, f)
	assert.Contains(t, f.GetProperties()["reason"], "namespaces")
}

// Branch 5.
func TestDecide_UsedNamespace_PackageReachable(t *testing.T) {
	d := baseDecision()
	d.UsedTokens = NewSet("pkg.example", "other.thing")
	f := Decide(d)
	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE, f.GetConfidence())
	assert.False(t, f.GetIncomplete(), "PACKAGE_REACHABLE is a complete verdict")
	assert.NotContains(t, f.GetProperties(), "synthetic")
}

// Branch 6: the ONLY path to NOT_REACHABLE.
func TestDecide_UnusedNoFrontier_NotReachable(t *testing.T) {
	d := baseDecision()
	f := Decide(d)
	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE, f.GetConfidence())
	assert.False(t, f.GetIncomplete())
	assert.NotContains(t, f.GetProperties(), "synthetic")
	assert.Contains(t, f.GetProperties()["reason"], "no static reference")
}

// The finding must copy the advisory identity and ecosystem/language tags.
func TestDecide_FindingIdentity(t *testing.T) {
	d := baseDecision()
	f := Decide(d)
	require.NotNil(t, f.GetAdvisory())
	assert.Equal(t, "CVE-TEST-1", f.GetAdvisory().GetId())
	assert.Equal(t, "pkg.example", f.GetModule())
	assert.Equal(t, "java", f.GetLanguage())
	assert.Equal(t, commit0v1.Ecosystem_ECOSYSTEM_MAVEN, f.GetEcosystem())
	assert.Equal(t, "sca", f.GetPillar())
}

func TestSet_Intersects(t *testing.T) {
	assert.True(t, NewSet("a", "b").Intersects(NewSet("b", "c")))
	assert.False(t, NewSet("a", "b").Intersects(NewSet("c", "d")))
	assert.False(t, NewSet().Intersects(NewSet("a")), "empty set intersects nothing")
}
