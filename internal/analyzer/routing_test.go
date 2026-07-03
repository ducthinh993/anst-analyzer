package analyzer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

func advisory(id string) *commit0v1.Advisory {
	return &commit0v1.Advisory{Id: id, Module: id + "-pkg"}
}

// byEcoFixture is a polyglot advisory set spread across three ecosystems.
func byEcoFixture() map[string][]*commit0v1.Advisory {
	return map[string][]*commit0v1.Advisory{
		"npm": {advisory("NPM-1"), advisory("NPM-2")},
		"Go":  {advisory("GO-1")},
		"Pub": {advisory("PUB-1"), advisory("PUB-2"), advisory("PUB-3")},
	}
}

// TestOwned_FiltersByEcosystem returns exactly the advisories for the requested
// ecosystems and nothing else.
func TestOwned_FiltersByEcosystem(t *testing.T) {
	got := Owned(byEcoFixture(), []string{"npm"})
	require.Len(t, got, 2)
	for _, a := range got {
		assert.Contains(t, a.GetId(), "NPM-", "npm-owned routing must only yield npm advisories")
	}
}

// TestOwned_NonNpmNeverRoutedToNpmOwner is the #15 fix at the routing primitive:
// a Go or Pub advisory can never reach a transport that owns only npm.
func TestOwned_NonNpmNeverRoutedToNpmOwner(t *testing.T) {
	got := Owned(byEcoFixture(), []string{"npm"})
	for _, a := range got {
		assert.NotContains(t, a.GetId(), "GO-", "a Go advisory must never route to the npm owner")
		assert.NotContains(t, a.GetId(), "PUB-", "a Pub advisory must never route to the npm owner")
	}
}

// TestOwned_PubOwnerNeverSeesNonPub proves the Dart/Pub analyzer only ever
// receives Pub advisories.
func TestOwned_PubOwnerNeverSeesNonPub(t *testing.T) {
	got := Owned(byEcoFixture(), []string{"Pub"})
	require.Len(t, got, 3)
	for _, a := range got {
		assert.Contains(t, a.GetId(), "PUB-", "the Pub analyzer must never see a non-Pub advisory")
	}
}

// TestOwned_UnknownEcosystemYieldsNone returns nothing (not a panic) for an
// ecosystem absent from the map.
func TestOwned_UnknownEcosystemYieldsNone(t *testing.T) {
	assert.Empty(t, Owned(byEcoFixture(), []string{"crates.io"}))
}

// TestPartition_NoOrphan is the load-bearing invariant: routing never drops or
// duplicates an advisory. count(in) == count(routed) + count(unowned).
func TestPartition_NoOrphan(t *testing.T) {
	byEco := byEcoFixture()
	total := 0
	for _, advs := range byEco {
		total += len(advs)
	}

	// npm + Go are owned; Pub is deliberately left unowned here.
	owned := map[string]bool{"npm": true, "Go": true}
	routed, unowned := Partition(byEco, owned)

	assert.Len(t, routed, 3, "npm(2) + Go(1) are routed")
	assert.Len(t, unowned, 3, "Pub(3) is unowned and kept, never dropped")
	assert.Equal(t, total, len(routed)+len(unowned),
		"no advisory may be orphaned: in == routed + unowned")
}

// TestPartition_AllOwned leaves nothing unowned when every ecosystem has an owner.
func TestPartition_AllOwned(t *testing.T) {
	byEco := byEcoFixture()
	owned := map[string]bool{"npm": true, "Go": true, "Pub": true}
	routed, unowned := Partition(byEco, owned)
	assert.Len(t, routed, 6)
	assert.Empty(t, unowned)
}
